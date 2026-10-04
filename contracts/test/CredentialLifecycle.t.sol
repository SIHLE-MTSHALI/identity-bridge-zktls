// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialBridge} from "../src/CredentialBridge.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {CredentialTypes} from "../src/libraries/CredentialTypes.sol";
import {CredentialTestBase} from "./helpers/CredentialTestBase.sol";

/**
 * @title CredentialLifecycleTest
 * @notice Credential issue, renew, suspend, resume, dispute, revoke, expire, and query.
 * @dev Covers every state in the {CredentialStatus} enum and every transition the
 *      engineering spec requires, on the source chain.
 */
contract CredentialLifecycleTest is CredentialTestBase {
    // -----------------------------------------------------------------
    // Issue
    // -----------------------------------------------------------------

    function test_IssueStoresMinimalRecord() public {
        bytes32 ccid = _issue(SUBJECT, 1);

        assertTrue(sourceRegistry.exists(ccid));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
        assertEq(sourceRegistry.getRecord(ccid).credentialType, CRED_TYPE);
        assertEq(sourceRegistry.getRecord(ccid).providerId, PROVIDER_A);
        assertEq(sourceRegistry.getRecord(ccid).evidenceHash, EVIDENCE);
        assertEq(sourceRegistry.getRecord(ccid).schemaVersion, SCHEMA_VERSION);
        assertEq(sourceRegistry.getRecord(ccid).nonce, 1);
        assertEq(sourceRegistry.getRecord(ccid).expiresAt, uint64(block.timestamp) + TTL);
    }

    function test_IssueEmitsEvent() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.expectEmit(true, true, true, true);
        emit CredentialRegistry.CredentialIssued(
            r.ccid, CRED_TYPE, PROVIDER_A, SCHEMA_VERSION, r.issuedAt, r.expiresAt, 1
        );
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);
    }

    function test_ReissueSameNonceRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);

        // Same subject, same nonce -> same CCID -> already exists.
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_UnauthorizedSubmitterRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(CredentialBridge.NotAuthorized.selector, outsider));
        sourceBridge.submitCredentialResult(r);
    }

    function test_TamperedCcidRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        r.ccid = keccak256("not-the-real-ccid");
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_SubjectSwapRejected() public {
        // A CCID computed for Alice, submitted with Bob's subject commitment.
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        r.subjectCommitment = keccak256("subject-commitment-bob");
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_ExtendedTtlRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        r.expiresAt = r.issuedAt + TTL * 10; // workflow tries to grant a longer life
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_ZeroEvidenceHashRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        r.evidenceHash = bytes32(0);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_PausedProviderRejected() public {
        vm.prank(admin);
        sourceProviders.setProviderStatus(PROVIDER_A, CredentialTypes.ProviderStatus.Paused);
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_DeprecatedSchemaRejected() public {
        vm.prank(admin);
        sourceSchemas.setSchemaActive(CRED_TYPE, SCHEMA_VERSION, false);
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    function test_ExpiryInPastRejected() public {
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1);
        r.issuedAt = uint64(block.timestamp) - TTL - 1;
        r.expiresAt = r.issuedAt + TTL;
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.submitCredentialResult(r);
    }

    // -----------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------

    function test_LazyExpiryWithoutSweeper() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        assertTrue(sourceRegistry.isValid(ccid));

        vm.warp(block.timestamp + TTL);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Expired));
        assertFalse(sourceRegistry.isValid(ccid));
    }

    function test_SweeperMarksExpired() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);

        bytes32[] memory ccids = new bytes32[](1);
        ccids[0] = ccid;
        // The sweeper is writer-gated; in production this is a Chainlink
        // Automation upkeep. Here the bridge stands in for it.
        vm.prank(address(sourceBridge));
        uint256 n = sourceRegistry.expireDue(ccids);

        assertEq(n, 1);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Expired));
    }

    function test_SweeperIsIdempotent() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL);
        bytes32[] memory ccids = new bytes32[](1);
        ccids[0] = ccid;
        vm.startPrank(address(sourceBridge));
        sourceRegistry.expireDue(ccids);
        assertEq(sourceRegistry.expireDue(ccids), 0);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------
    // Renew
    // -----------------------------------------------------------------

    function test_RenewExtendsExpiry() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64 oldExpiry = sourceRegistry.getRecord(ccid).expiresAt;

        vm.warp(block.timestamp + 10 days);
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 2);
        uint64[] memory dests = new uint64[](0);
        vm.prank(workflow);
        sourceBridge.renewCredential(r, dests);

        assertGt(sourceRegistry.getRecord(ccid).expiresAt, oldExpiry);
        assertEq(sourceRegistry.getRecord(ccid).nonce, 2);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
    }

    function test_RenewRecoversExpiredCredential() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        vm.warp(block.timestamp + TTL + 1);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Expired));

        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 2);
        uint64[] memory dests = new uint64[](0);
        vm.prank(workflow);
        sourceBridge.renewCredential(r, dests);

        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
    }

    function test_RenewRevokedRejected() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("test"), dests);

        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 2);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.renewCredential(r, dests);
    }

    function test_RenewWithReplayedNonceRejected() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 1); // same nonce
        uint64[] memory dests = new uint64[](0);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.renewCredential(r, dests);
    }

    // -----------------------------------------------------------------
    // Suspend / resume / dispute
    // -----------------------------------------------------------------

    function test_SuspendAndResume() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(issuer);
        sourceBridge.suspend(ccid, bytes32("review"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Suspended));

        vm.prank(issuer);
        sourceBridge.resume(ccid, bytes32("cleared"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
    }

    function test_SuspendRequiresIssuer() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(outsider);
        vm.expectRevert();
        sourceBridge.suspend(ccid, bytes32("nope"), dests);
    }

    function test_DisputeDenies() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(holder);
        sourceBridge.dispute(ccid, bytes32("contested"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Disputed));
        assertFalse(sourceRegistry.isValid(ccid));
    }

    function test_DisputeResolvableByIssuer() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(holder);
        sourceBridge.dispute(ccid, bytes32("contested"), dests);
        vm.prank(issuer);
        sourceBridge.resume(ccid, bytes32("resolved"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
    }

    // -----------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------

    function test_RevokeByIssuer() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);

        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Revoked));
    }

    function test_RevokeRequiresAuthorityForIssuerOnlySchema() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        // Schema is IssuerOnly, so the holder cannot revoke.
        vm.prank(holder);
        vm.expectRevert();
        sourceBridge.revoke(ccid, bytes32("mine"), dests);
    }

    function test_HolderCanRevokeUnderHolderOrIssuerSchema() public {
        // Register a second schema permitting holder revocation.
        bytes32[] memory ps = new bytes32[](1);
        ps[0] = PROVIDER_A;
        vm.prank(admin);
        sourceSchemas.registerSchema(
            CRED_TYPE, 2, TTL, CredentialTypes.RevocationMode.HolderOrIssuer, ps, "https://example.invalid/s2"
        );

        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory r = CredentialTypes.CredentialResult({
            ccid: sourceResolver.compute(CRED_TYPE, 2, PROVIDER_A, SUBJECT),
            credentialType: CRED_TYPE,
            schemaVersion: 2,
            providerId: PROVIDER_A,
            subjectCommitment: SUBJECT,
            evidenceHash: EVIDENCE,
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: 1,
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);

        uint64[] memory dests = new uint64[](0);
        vm.prank(holder);
        sourceBridge.revoke(r.ccid, bytes32("self-revoked"), dests);
        assertEq(uint8(sourceRegistry.statusOf(r.ccid)), uint8(CredentialTypes.CredentialStatus.Revoked));
    }

    function test_GovernanceOnlySchemaExcludesIssuer() public {
        bytes32[] memory ps = new bytes32[](1);
        ps[0] = PROVIDER_A;
        vm.prank(admin);
        sourceSchemas.registerSchema(
            CRED_TYPE, 3, TTL, CredentialTypes.RevocationMode.GovernanceOnly, ps, "https://example.invalid/s3"
        );

        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory r = CredentialTypes.CredentialResult({
            ccid: sourceResolver.compute(CRED_TYPE, 3, PROVIDER_A, SUBJECT),
            credentialType: CRED_TYPE,
            schemaVersion: 3,
            providerId: PROVIDER_A,
            subjectCommitment: SUBJECT,
            evidenceHash: EVIDENCE,
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: 1,
            destinationChainSelectors: new uint64[](0)
        });
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);

        uint64[] memory dests = new uint64[](0);
        // Issuer alone cannot revoke a governance-controlled credential.
        vm.prank(issuer);
        vm.expectRevert();
        sourceBridge.revoke(r.ccid, bytes32("no"), dests);

        // Governance can.
        vm.prank(admin);
        sourceBridge.revoke(r.ccid, bytes32("gov"), dests);
        assertEq(uint8(sourceRegistry.statusOf(r.ccid)), uint8(CredentialTypes.CredentialStatus.Revoked));
    }

    function test_RevocationIsTerminal() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        uint64[] memory dests = new uint64[](0);
        vm.prank(issuer);
        sourceBridge.revoke(ccid, bytes32("fraud"), dests);

        // No path back to Valid: suspend, resume, and renew all fail.
        vm.prank(issuer);
        vm.expectRevert();
        sourceBridge.suspend(ccid, bytes32("x"), dests);

        vm.prank(issuer);
        vm.expectRevert();
        sourceBridge.resume(ccid, bytes32("x"), dests);

        CredentialTypes.CredentialResult memory r = _result(SUBJECT, 2);
        vm.prank(workflow);
        vm.expectRevert();
        sourceBridge.renewCredential(r, dests);

        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Revoked));
    }

    // -----------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------

    function test_UnknownCredentialIsNotValid() public {
        bytes32 ccid = keccak256("never-issued");
        assertFalse(sourceRegistry.exists(ccid));
        assertEq(uint8(sourceRegistry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Unknown));
        assertFalse(sourceRegistry.isValid(ccid));
    }

    function test_AgeOfTracksUpdates() public {
        bytes32 ccid = _issue(SUBJECT, 1);
        assertEq(sourceRegistry.ageOf(ccid), 0);
        vm.warp(block.timestamp + 5 days);
        assertEq(sourceRegistry.ageOf(ccid), 5 days);
    }
}
