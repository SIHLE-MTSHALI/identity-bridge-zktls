// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PolicyManagerAdapter} from "../src/PolicyManagerAdapter.sol";
import {CredentialTypes} from "../src/libraries/CredentialTypes.sol";
import {CredentialTestBase} from "./helpers/CredentialTestBase.sol";

/**
 * @title PolicyManagerAdapterTest
 * @notice Every reason code the engineering spec requires, plus the precedence
 *         order between them.
 * @dev This suite is the executable form of the "unsafe defaults are hard"
 *      requirement: each non-`Valid` state must deny, and each denial must be
 *      explainable.
 */
contract PolicyManagerAdapterTest is CredentialTestBase {
    PolicyManagerAdapter internal policy;

    function setUp() public override {
        super.setUp();
        policy = new PolicyManagerAdapter(sourceRegistry, sourceSchemas, sourceProviders, sourceEmergency);
    }

    // -----------------------------------------------------------------
    // Allow
    // -----------------------------------------------------------------

    function test_ValidCredentialAllowed() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
        assertTrue(CredentialTypes.isAllow(reason));
    }

    // -----------------------------------------------------------------
    // Lifecycle denials - the nine required reason codes
    // -----------------------------------------------------------------

    function test_UnknownDenied() public {
        (bool allowed, bytes32 reason) = policy.evaluate(keccak256("nobody"), _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_UNKNOWN);
    }

    function test_ExpiredDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);
        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_EXPIRED);
    }

    function test_SuspendedDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.suspend(ccid, bytes32("review"), dests);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_SUSPENDED);
    }

    function test_RevokedDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_REVOKED);
    }

    function test_DisputedDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(holder);
        sourceBridge.dispute(ccid, bytes32("contested"), dests);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_DISPUTED);
    }

    function test_PendingDenied() public {
        // A Pending record models a verification that has started but not finished.
        bytes32 ccid = sourceResolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, SUBJECT);
        vm.prank(workflow);
        sourceBridge.beginVerification(ccid, CRED_TYPE, SCHEMA_VERSION, TTL);

        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Pending));
        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_PENDING);
    }

    function test_PendingResolvesToValid() public {
        bytes32 ccid = sourceResolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, SUBJECT);
        vm.prank(workflow);
        sourceBridge.beginVerification(ccid, CRED_TYPE, SCHEMA_VERSION, TTL);

        // Build the result BEFORE the prank: _result() performs an external call to
        // the resolver, which would otherwise consume the prank and run the
        // submission as the test contract.
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
    }

    function test_ProviderPausedDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, CredentialTypes.ProviderStatus.Paused);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_PROVIDER_PAUSED);
    }

    function test_ProviderRevokedDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, CredentialTypes.ProviderStatus.Revoked);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_PROVIDER_PAUSED);
    }

    function test_DeprecatedProviderStillBacksExistingCredentials() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, CredentialTypes.ProviderStatus.Deprecated);

        // A planned wind-down must not retroactively invalidate live holders,
        // but new issuance is still blocked (covered in the bridge suite).
        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
    }

    function test_DeprecatedSchemaDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(admin);
        sourceSchemas.setSchemaActive(CRED_TYPE, SCHEMA_VERSION, false);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_SCHEMA_UNSUPPORTED);
    }

    // -----------------------------------------------------------------
    // Requirement mismatches
    // -----------------------------------------------------------------

    function test_CredentialTypeMismatchDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        CredentialTypes.CredentialRequirement memory req = _requirement();
        req.credentialType = keccak256("some.other.type");

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, req);
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_CREDENTIAL_TYPE_MISMATCH);
    }

    function test_SchemaVersionMismatchDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        CredentialTypes.CredentialRequirement memory req = _requirement();
        req.schemaVersion = 99;

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, req);
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_SCHEMA_VERSION_UNSUPPORTED);
    }

    function test_UnacceptedProviderDenied() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        bytes32[] memory trusted = new bytes32[](1);
        trusted[0] = PROVIDER_B; // issuer used provider A
        CredentialTypes.CredentialRequirement memory req = _requirementWithProviders(trusted);

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, req);
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_PROVIDER_NOT_ACCEPTED);
    }

    function test_AcceptedProviderAllowed() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        bytes32[] memory trusted = new bytes32[](1);
        trusted[0] = PROVIDER_A;

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirementWithProviders(trusted));
        assertTrue(allowed);
        assertEq(reason, CredentialTypes.REASON_OK);
    }

    // -----------------------------------------------------------------
    // Precedence
    // -----------------------------------------------------------------

    function test_RevokedOutranksExpired() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);
        // Also past expiry: revocation must still be the reported reason.
        vm.warp(block.timestamp + TTL + 1);

        (, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertEq(reason, CredentialTypes.REASON_REVOKED);
    }

    function test_SystemPauseOutranksEverything() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.prank(guardian);
        sourceEmergency.pause("incident");

        (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_SYSTEM_PAUSED);
    }

    function test_PauseFailsClosedEvenForUnknownCredential() public {
        vm.prank(guardian);
        sourceEmergency.pause("incident");
        (bool allowed, bytes32 reason) = policy.evaluate(keccak256("nobody"), _requirement());
        assertFalse(allowed);
        assertEq(reason, CredentialTypes.REASON_SYSTEM_PAUSED);
    }

    // -----------------------------------------------------------------
    // Explainability
    // -----------------------------------------------------------------

    function test_DescribeReasonCoversEveryCode() public {
        assertEq(policy.describeReason(CredentialTypes.REASON_OK), "OK");
        assertEq(policy.describeReason(CredentialTypes.REASON_UNKNOWN), "UNKNOWN");
        assertEq(policy.describeReason(CredentialTypes.REASON_PENDING), "PENDING");
        assertEq(policy.describeReason(CredentialTypes.REASON_EXPIRED), "EXPIRED");
        assertEq(policy.describeReason(CredentialTypes.REASON_SUSPENDED), "SUSPENDED");
        assertEq(policy.describeReason(CredentialTypes.REASON_REVOKED), "REVOKED");
        assertEq(policy.describeReason(CredentialTypes.REASON_DISPUTED), "DISPUTED");
        assertEq(policy.describeReason(CredentialTypes.REASON_PROVIDER_PAUSED), "PROVIDER_PAUSED");
        assertEq(policy.describeReason(CredentialTypes.REASON_SCHEMA_UNSUPPORTED), "SCHEMA_UNSUPPORTED");
        assertEq(policy.describeReason(CredentialTypes.REASON_STALE_DESTINATION), "STALE_DESTINATION");
        // Unknown codes degrade gracefully instead of reverting, so a newer
        // contract cannot brick an older SDK's display path.
        assertEq(policy.describeReason(keccak256("FROM_THE_FUTURE")), "UNRECOGNIZED");
    }

    function test_EvaluateAndRecordEmitsOnAllowOnly() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.recordLogs();
        policy.evaluateAndRecord(ccid, _requirement());
        assertEq(vm.getRecordedLogs().length, 1);

        bytes32 revokedCcid = _issue(keccak256("other-subject"), 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.revoke(revokedCcid, bytes32("x"), dests);

        vm.recordLogs();
        policy.evaluateAndRecord(revokedCcid, _requirement());
        // Denials must not emit, or a prober could inflate a holder's public
        // denial history at will.
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_ExplainDefaultMatchesEvaluate() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        (bool a1, bytes32 r1) = policy.evaluate(ccid, _requirement());
        (bool a2, bytes32 r2) = policy.explainDefault(ccid, CRED_TYPE);
        assertEq(a1, a2);
        assertEq(r1, r2);
    }
}
