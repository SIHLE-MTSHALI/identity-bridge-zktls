// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CrossChainCredentialReceiver} from "../src/CrossChainCredentialReceiver.sol";
import {PolicyManagerAdapter} from "../src/PolicyManagerAdapter.sol";
import {CredentialTypes} from "../src/libraries/CredentialTypes.sol";
import {PropagationPayload} from "../src/libraries/PropagationPayload.sol";
import {CredentialTestBase} from "./helpers/CredentialTestBase.sol";

/**
 * @title CrossChainPropagationTest
 * @notice Every cross-chain attack the engineering spec names: replay, wrong
 *         source, wrong sender, wrong schema, stale nonce, and freshness.
 * @dev The destination registry is a separate deployment, so anything it holds is
 *      genuinely a replica and the "local issuer" rule is exercised for real.
 */
contract CrossChainPropagationTest is CredentialTestBase {
    PolicyManagerAdapter internal destPolicy;
    PolicyManagerAdapter internal srcPolicy;

    function setUp() public override {
        super.setUp();
        destPolicy = new PolicyManagerAdapter(destRegistry, destSchemas, destProviders, destEmergency);
        srcPolicy = new PolicyManagerAdapter(sourceRegistry, sourceSchemas, sourceProviders, sourceEmergency);
    }

    /// @dev Issue on source with propagation to `dest`, returning the message index.
    function _issueAndPropagate(bytes32 subject, uint64 nonce) internal returns (bytes32 ccid, uint256 msgIndex) {
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;
        CredentialTypes.CredentialResult memory r = _resultWithDestinations(subject, nonce, dests);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);
        return (r.ccid, _sentCount() - 1);
    }

    // -----------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------

    function test_ReplicaIsAccepted() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccak256("order-1"));

        assertTrue(destRegistry.exists(ccid));
        assertEq(uint8(destRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));

        CredentialTypes.PropagationState memory p = destRegistry.getPropagationState(ccid);
        assertTrue(p.isReplica);
        assertEq(p.sourceChainSelector, SOURCE_SELECTOR);
        assertEq(p.lastSourceNonce, 1);
    }

    function test_ReplicaIsEvaluatedLocallyAfterPropagation() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccak256("order-1"));

        (bool allowed, bytes32 reason) = destPolicy.evaluate(ccid, _requirement());
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
    }

    function test_NoSubjectCommitmentOnTheWire() public {
        _issueAndPropagate(SUBJECT, 1);
        PropagationPayload.Message memory m = _decodeSent(0);

        // The payload must not carry the holder's subject commitment. Verify by
        // re-encoding and checking the field is absent from the fixed layout.
        bytes memory reencoded = PropagationPayload.encode(m);
        assertEq(reencoded.length, PropagationPayload.ENCODED_LENGTH);
        // 11 static words, and none of them is the subject commitment.
        assertFalse(containsWord(reencoded, SUBJECT));
    }

    // -----------------------------------------------------------------
    // Replay
    // -----------------------------------------------------------------

    function test_ReplayedOrderIdRejected() public {
        (, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccak256("order-1"));

        // Same order id, delivered again.
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainCredentialReceiver.ReplayedMessage.selector, keccak256("order-1"))
        );
        _deliver(idx, address(sourceBridge), keccak256("order-1"));
    }

    function test_ReplayedPayloadUnderNewOrderIdStillRejectedByNonce() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccab256Helper("order-1"));

        // Attacker replays the identical payload with a fresh order id. The nonce
        // check is what stops this, not the order id.
        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.NonceNotIncreasing.selector, ccid, 1, 1));
        _deliver(idx, address(sourceBridge), keccab256Helper("order-2"));
    }

    // -----------------------------------------------------------------
    // Wrong sender / wrong chain
    // -----------------------------------------------------------------

    function test_UntrustedSourceSenderRejected() public {
        (, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.UntrustedSourceSender.selector, outsider));
        _deliver(idx, outsider, keccak256("order-1"));
    }

    function test_DelegatedSourceSenderRejectedOnceDeauthorized() public {
        (, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        vm.prank(admin);
        destReceiver.setAllowedSourceSender(address(sourceBridge), false);

        vm.expectRevert(
            abi.encodeWithSelector(CrossChainCredentialReceiver.UntrustedSourceSender.selector, address(sourceBridge))
        );
        _deliver(idx, address(sourceBridge), keccak256("order-1"));
    }

    function test_UntrustedSourceChainRejected() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);

        // Rebuild the payload claiming a different source chain.
        PropagationPayload.Message memory m = _decodeSent(idx);
        m.sourceChainSelector = 999_999;
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);
        bytes memory forged = PropagationPayload.encode(m);

        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.UntrustedSourceChain.selector, 999_999));
        router.deliverRaw(address(destReceiver), address(sourceBridge), keccak256("order-x"), destSelector, forged);

        assertFalse(destRegistry.exists(ccid));
    }

    function test_SelfSourceChainRejected() public {
        PropagationPayload.Message memory m;
        m.ccid = keccak256("x");
        m.credentialType = CRED_TYPE;
        m.schemaVersion = SCHEMA_VERSION;
        m.providerId = PROVIDER_A;
        m.evidenceHash = EVIDENCE;
        m.issuedAt = uint64(block.timestamp);
        m.expiresAt = uint64(block.timestamp) + TTL;
        m.nonce = 1;
        m.status = CredentialTypes.CredentialStatus.Valid;
        m.sourceChainSelector = DEST_SELECTOR; // destination claiming to be the source
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);

        vm.expectRevert(
            abi.encodeWithSelector(CrossChainCredentialReceiver.UntrustedSourceChain.selector, DEST_SELECTOR)
        );
        router.deliverRaw(
            address(destReceiver),
            address(sourceBridge),
            keccak256("order-y"),
            destSelector,
            PropagationPayload.encode(m)
        );
    }

    // -----------------------------------------------------------------
    // Payload tampering
    // -----------------------------------------------------------------

    function test_BindingHashMismatchRejected() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        PropagationPayload.Message memory m = _decodeSent(idx);

        // Extend the expiry without recomputing the binding hash.
        m.expiresAt += 365 days;

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainCredentialReceiver.BindingHashMismatch.selector,
                m.bindingHash,
                PropagationPayload.recomputeBindingHash(m)
            )
        );
        router.deliverRaw(
            address(destReceiver),
            address(sourceBridge),
            keccak256("order-z"),
            destSelector,
            PropagationPayload.encode(m)
        );
        assertFalse(destRegistry.exists(ccid));
    }

    function test_StatusFlipToValidRejectedByBindingHash() public {
        // A revoked credential whose status is flipped in the payload to Valid
        // must not be accepted, even by a trusted sender and fresh order id.
        (bytes32 ccid, uint256 idx) = _issueAndRevoke();
        PropagationPayload.Message memory m = _decodeSent(idx);
        assertEq(uint8(m.status), uint8(CredentialTypes.CredentialStatus.Revoked));

        m.status = CredentialTypes.CredentialStatus.Valid; // no bindingHash recompute
        vm.expectRevert();
        router.deliverRaw(
            address(destReceiver),
            address(sourceBridge),
            keccak256("order-flip"),
            destSelector,
            PropagationPayload.encode(m)
        );
        (bool allowed,) = destPolicy.evaluate(ccid, _requirement());
        assertFalse(allowed);
    }

    function test_MalformedPayloadRejected() public {
        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.MalformedPayload.selector, 10));
        router.deliverRaw(
            address(destReceiver),
            address(sourceBridge),
            keccak256("order-bad"),
            destSelector,
            hex"00112233445566778899"
        );
    }

    function test_UnknownStatusRejected() public {
        // Build the payload as raw words so an out-of-range status can be expressed.
        // A typed enum conversion would panic in the test itself, which would not
        // prove anything about the receiver's validation.
        bytes memory forged = abi.encode(
            keccak256("y"),
            CRED_TYPE,
            uint256(SCHEMA_VERSION),
            PROVIDER_A,
            EVIDENCE,
            uint256(block.timestamp),
            uint256(block.timestamp) + TTL,
            uint256(1),
            uint256(99), // not a CredentialStatus member
            uint256(SOURCE_SELECTOR),
            bytes32(0)
        );
        assertEq(forged.length, PropagationPayload.ENCODED_LENGTH);

        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.UnknownStatus.selector, uint8(99)));
        router.deliverRaw(address(destReceiver), address(sourceBridge), keccak256("order-st"), destSelector, forged);
    }

    // -----------------------------------------------------------------
    // Schema / provider gating on the destination
    // -----------------------------------------------------------------

    function test_ReplicaOnUnsupportedSchemaRejected() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        vm.prank(admin);
        destSchemas.setSchemaActive(CRED_TYPE, SCHEMA_VERSION, false);

        vm.expectRevert(
            abi.encodeWithSelector(CrossChainCredentialReceiver.SchemaNotSupported.selector, CRED_TYPE, SCHEMA_VERSION)
        );
        _deliver(idx, address(sourceBridge), keccak256("order-1"));
        assertFalse(destRegistry.exists(ccid));
    }

    function test_ReplicaWithPausedProviderRejected() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        // Pausing on the destination must take effect independently of the source.
        vm.prank(admin);
        destProviders.setProviderStatus(PROVIDER_A, CredentialTypes.ProviderStatus.Paused);

        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.ProviderUnavailable.selector, PROVIDER_A));
        _deliver(idx, address(sourceBridge), keccak256("order-1"));
        assertFalse(destRegistry.exists(ccid));
    }

    // -----------------------------------------------------------------
    // Nonce monotonicity
    // -----------------------------------------------------------------

    function test_OutOfOrderNonceRejected() public {
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;

        // Two genuine source states with increasing nonces: issuance, then renewal.
        CredentialTypes.CredentialResult memory r5 = _resultWithDestinations(SUBJECT, 5, dests);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r5);
        uint256 idxOld = _sentCount() - 1;

        vm.warp(block.timestamp + 1 days);
        CredentialTypes.CredentialResult memory r7 = _resultWithDestinations(SUBJECT, 7, dests);
        vm.prank(workflow);
        sourceBridge.renewCredential(r7, dests);
        uint256 idxNew = _sentCount() - 1;

        // Deliver the NEWER state first. CCIP delivery is unordered, so out-of-order
        // arrival is a normal occurrence rather than an attack.
        _deliver(idxNew, address(sourceBridge), keccak256("o7"));
        assertEq(destReceiver.lastAcceptedNonce(r5.ccid), 7);

        // The older state must not overwrite the newer one.
        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.NonceNotIncreasing.selector, r5.ccid, 7, 5));
        _deliver(idxOld, address(sourceBridge), keccak256("o5"));
    }

    function test_HigherNonceAccepted() public {
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;

        CredentialTypes.CredentialResult memory r1 = _resultWithDestinations(SUBJECT, 1, dests);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r1);
        _deliver(_sentCount() - 1, address(sourceBridge), keccak256("o1"));

        vm.warp(block.timestamp + 1 days);
        CredentialTypes.CredentialResult memory r2 = _resultWithDestinations(SUBJECT, 2, dests);
        vm.prank(workflow);
        sourceBridge.renewCredential(r2, dests);
        _deliver(_sentCount() - 1, address(sourceBridge), keccak256("o2"));

        assertEq(destReceiver.lastAcceptedNonce(r1.ccid), 2);
    }

    // -----------------------------------------------------------------
    // Local issuer protection
    // -----------------------------------------------------------------

    function test_ReplicaCannotOverwriteLocalIssuance() public {
        // Issue the same credential directly on the destination chain first, so it
        // is local authority rather than a replica.
        bytes32 ccid = sourceResolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, SUBJECT);

        // Resolve the role id BEFORE pranking: reading it is an external call that
        // would otherwise consume the prank and leave grantRole unauthorized.
        bytes32 workflowRole = destBridge.WORKFLOW_SUBMITTER();
        vm.prank(admin);
        destBridge.grantRole(workflowRole, workflow);

        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory local = CredentialTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER_A,
            subjectCommitment: SUBJECT,
            evidenceHash: EVIDENCE,
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: 1,
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        destBridge.submitCredentialResult(local);

        assertFalse(destRegistry.getPropagationState(ccid).isReplica);

        // Now attempt to push the source chain's view of the same credential in.
        (, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        vm.expectRevert(abi.encodeWithSelector(CrossChainCredentialReceiver.LocalIssuerOverride.selector, ccid));
        _deliver(idx, address(sourceBridge), keccak256("order-1"));
    }

    // -----------------------------------------------------------------
    // Revocation propagation
    // -----------------------------------------------------------------

    function test_RevocationPropagatesToDestination() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccak256("o1"));
        (bool allowed, bytes32 reason) = destPolicy.evaluate(ccid, _requirement());
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);

        // Revoke on the source, which must re-propagate to the same destination.
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);

        PropagationPayload.Message memory m = _decodeSent(_sentCount() - 1);
        assertEq(uint8(m.status), uint8(CredentialTypes.CredentialStatus.Revoked));

        _deliver(_sentCount() - 1, address(sourceBridge), keccak256("o-revoke"));

        (bool allowed2, bytes32 reason2) = destPolicy.evaluate(ccid, _requirement());
        assertFalse(allowed2);
        assertEq(reason2, CredentialTypes.REASON_REVOKED);
    }

    // -----------------------------------------------------------------
    // Freshness
    // -----------------------------------------------------------------

    function test_StaleDestinationDenied() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        _deliver(idx, address(sourceBridge), keccak256("o1"));

        // Fresh immediately after propagation.
        (bool allowed, bytes32 reason) = destPolicy.evaluate(ccid, _requirementWithFreshness(1 days));
        assertTrue(allowed);

        // Move past the integrator's tolerance without re-propagating.
        vm.warp(block.timestamp + 2 days);
        (allowed, reason) = destPolicy.evaluate(ccid, _requirementWithFreshness(1 days));
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_STALE_DESTINATION);
    }

    function test_FreshnessNotAppliedToSourceChainRecords() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        // Advance past the freshness tolerance but stay inside the 30-day TTL, so
        // the only thing that could deny is a freshness rule.
        vm.warp(block.timestamp + 2 days);

        // The source of truth is never stale; only replicas are.
        (bool allowed, bytes32 reason) = srcPolicy.evaluate(ccid, _requirementWithFreshness(1 days));
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
    }

    // -----------------------------------------------------------------
    // Pause
    // -----------------------------------------------------------------

    function test_PausedDestinationRejectsPropagation() public {
        (bytes32 ccid, uint256 idx) = _issueAndPropagate(SUBJECT, 1);
        vm.prank(guardian);
        destEmergency.pause("incident");

        vm.expectRevert();
        _deliver(idx, address(sourceBridge), keccak256("o1"));
        assertFalse(destRegistry.exists(ccid));
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    function _issueAndRevoke() internal returns (bytes32 ccid, uint256 revokeIdx) {
        uint64[] memory dests = new uint64[](1);
        dests[0] = DEST_SELECTOR;
        CredentialTypes.CredentialResult memory r = _resultWithDestinations(SUBJECT, 1, dests);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);
        ccid = r.ccid;
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);
        revokeIdx = _sentCount() - 1;
    }

    function keccab256Helper(string memory s) internal pure returns (bytes32) {
        return keccak256(bytes(s));
    }

    /// @dev True if `needle` appears as a 32-byte word inside `haystack`.
    function containsWord(bytes memory haystack, bytes32 needle) internal pure returns (bool) {
        bytes32 target = needle;
        for (uint256 i = 0; i + 32 <= haystack.length; i += 32) {
            bytes32 word;
            assembly {
                word := mload(add(add(haystack, 0x20), i))
            }
            if (word == target) return true;
        }
        return false;
    }
}
