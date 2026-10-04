// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Vm} from "forge-std/Vm.sol";

import {CCIDResolver} from "../../src/CCIDResolver.sol";
import {CredentialBridge} from "../../src/CredentialBridge.sol";
import {CredentialRegistry} from "../../src/CredentialRegistry.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {SchemaRegistry} from "../../src/SchemaRegistry.sol";
import {CredentialTypes} from "../../src/libraries/CredentialTypes.sol";

/**
 * @title CredentialLifecycleHandler
 * @notice Random action driver for the lifecycle invariant suite.
 *
 * @dev ## Why the bookkeeping lives here
 *
 *      Monotonicity properties ("expiry never decreases", "nonce never decreases")
 *      have to compare against the *previous* value, which means state. Keeping
 *      that state in the handler - not in the invariant function - is what makes
 *      the comparison sound: every path that can change the registry is a handler
 *      action, so the handler's record cannot miss an update.
 *
 *      Putting the comparison inside a `view` invariant would either be impossible
 *      or would mutate state during the check, both of which mislead the shrinker.
 *
 *      ## Why actions swallow reverts
 *
 *      Most random calls are invalid, and that is the point: the invariants must
 *      hold whether an action succeeds or reverts. Swallowing the revert keeps the
 *      fuzzer exploring valid action sequences instead of getting stuck on the
 *      first rejected call.
 */
contract CredentialLifecycleHandler {
    /// @dev Cheatcodes are used for time travel only. Every state-changing call
    ///      goes through a real contract role, so authorization is still exercised.
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    CredentialRegistry public immutable REGISTRY;
    CredentialBridge public immutable BRIDGE;
    ProviderRegistry public immutable PROVIDERS;
    SchemaRegistry public immutable SCHEMAS;
    CCIDResolver public immutable RESOLVER;
    EmergencyControls public immutable EMERGENCY;

    bytes32 public immutable CRED_TYPE;
    bytes32 public immutable PROVIDER;
    uint32 public immutable SCHEMA_VERSION;
    uint64 public immutable TTL;

    /// @notice Every CCID this handler has touched.
    bytes32[] public ccids;

    /// @notice Every subject salt this handler has used.
    bytes32[] public subjectSalts;

    /// @notice Highest expiry observed per CCID, for the monotonicity invariant.
    mapping(bytes32 => uint64) public highWaterExpiry;

    /// @notice Highest nonce observed per CCID, for the monotonicity invariant.
    mapping(bytes32 => uint64) public highWaterNonce;

    /// @notice True once a CCID was observed in `Revoked`.
    mapping(bytes32 => bool) public everRevoked;

    /// @notice True once a revoke actually succeeded.
    mapping(bytes32 => bool) public revokeSucceeded;

    /// @notice True once any action moved a credential out of `Valid`.
    mapping(bytes32 => bool) public everNonValid;

    uint256 public actionCount;

    constructor(
        CredentialRegistry registry,
        CredentialBridge bridge,
        ProviderRegistry providers,
        SchemaRegistry schemas,
        CCIDResolver resolver,
        EmergencyControls emergency,
        bytes32 credType,
        bytes32 provider,
        uint32 schemaVersion,
        uint64 ttl
    ) {
        REGISTRY = registry;
        BRIDGE = bridge;
        PROVIDERS = providers;
        SCHEMAS = schemas;
        RESOLVER = resolver;
        EMERGENCY = emergency;
        CRED_TYPE = credType;
        PROVIDER = provider;
        SCHEMA_VERSION = schemaVersion;
        TTL = ttl;
    }

    // -----------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------

    function warpRandom(uint32 secondsToAdvance) external {
        actionCount++;
        vm.warp(block.timestamp + secondsToAdvance);
    }

    function pauseRandom() external {
        actionCount++;
        if (!EMERGENCY.paused()) {
            try EMERGENCY.pause("fuzz") {} catch {}
        }
    }

    function unpauseRandom() external {
        actionCount++;
        if (EMERGENCY.paused()) {
            // Jump past the unpause delay so the two-step flow can complete.
            vm.warp(block.timestamp + EMERGENCY.UNPAUSE_DELAY() + 1);
            try EMERGENCY.scheduleUnpause("fuzz") {} catch {}
            try EMERGENCY.executeUnpause() {} catch {}
        }
    }

    function providerStatusRandom(uint8 next) external {
        actionCount++;
        if (next > uint8(CredentialTypes.ProviderStatus.Revoked)) return;
        try PROVIDERS.setProviderStatus(PROVIDER, CredentialTypes.ProviderStatus(next)) {} catch {}
    }

    function schemaActiveRandom(bool active) external {
        actionCount++;
        try SCHEMAS.setSchemaActive(CRED_TYPE, SCHEMA_VERSION, active) {} catch {}
    }

    /// @dev Issue for a fresh subject/nonce. Both are fuzzer-supplied, so the
    ///      fuzzer explores many distinct credentials.
    function issueRandom(bytes32 subjectSalt, uint64 nonce) external {
        actionCount++;
        _remember(subjectSalt);
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory r = CredentialTypes.CredentialResult({
            ccid: RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject),
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER,
            subjectCommitment: subject,
            evidenceHash: keccak256(abi.encode("evidence", subjectSalt, nonce)),
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: nonce,
            destinationChainSelectors: new uint64[](0)
        });
        try BRIDGE.submitCredentialResult(r) {
            _track(r.ccid);
        } catch {}
    }

    function beginPendingRandom(bytes32 subjectSalt) external {
        actionCount++;
        _remember(subjectSalt);
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);
        try BRIDGE.beginVerification(ccid, CRED_TYPE, SCHEMA_VERSION, TTL) {
            _track(ccid);
        } catch {}
    }

    function renewRandom(bytes32 subjectSalt, uint64 nonce) external {
        actionCount++;
        _remember(subjectSalt);
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);
        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory r = CredentialTypes.CredentialResult({
            ccid: ccid,
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER,
            subjectCommitment: subject,
            evidenceHash: keccak256(abi.encode("evidence", subjectSalt, nonce)),
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: nonce,
            destinationChainSelectors: new uint64[](0)
        });
        try BRIDGE.renewCredential(r, new uint64[](0)) {
            _track(ccid);
        } catch {}
    }

    // -----------------------------------------------------------------
    // Compound actions
    //
    // Single-action fuzzing almost never produces the sequences that matter.
    // `revoke` immediately followed by `resume` is the exact attack a revoked
    // credential faces - an attempt to resurrect it - and it is vanishingly
    // unlikely to be drawn by chance from random salts. Folding such sequences
    // into one action guarantees the invariant is actually tested.
    // -----------------------------------------------------------------

    /// @notice Revoke, then immediately attempt every way back to `Valid`.
    function revokeThenAttemptResurrection(uint256 raw) external {
        actionCount++;
        bytes32 subjectSalt = _pickSalt(raw);
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);

        try BRIDGE.revoke(ccid, keccak256("revoked"), new uint64[](0)) {
            revokeSucceeded[ccid] = true;
            everRevoked[ccid] = true;
        } catch {}
        _track(ccid);

        // Every one of these must fail for a revoked credential.
        try BRIDGE.resume(ccid, keccak256("resume"), new uint64[](0)) {} catch {}
        try BRIDGE.suspend(ccid, keccak256("suspend"), new uint64[](0)) {} catch {}
        try BRIDGE.dispute(ccid, keccak256("dispute"), new uint64[](0)) {} catch {}
        try BRIDGE.renewCredential(_result(subject, uint64(block.timestamp), 1000), new uint64[](0)) {} catch {}
        _track(ccid);
    }

    /// @notice Let a credential lapse, then try to extend it without re-verifying.
    function expireThenAttemptRenewal(uint256 raw, uint64 nonce) external {
        actionCount++;
        bytes32 subjectSalt = _pickSalt(raw);
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);

        vm.warp(block.timestamp + TTL + 1);
        _track(ccid);
        try BRIDGE.renewCredential(_result(subject, uint64(block.timestamp), nonce), new uint64[](0)) {} catch {}
        _track(ccid);
    }

    function suspendRandom(uint256 raw) external {
        actionCount++;
        _transition(_pickSalt(raw), "suspend");
    }

    function resumeRandom(uint256 raw) external {
        actionCount++;
        _transition(_pickSalt(raw), "resume");
    }

    function revokeRandom(uint256 raw) external {
        actionCount++;
        bytes32 subject = keccak256(abi.encode("subject", _pickSalt(raw)));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);
        try BRIDGE.revoke(ccid, keccak256("revoked"), new uint64[](0)) {
            revokeSucceeded[ccid] = true;
            everRevoked[ccid] = true;
        } catch {}
        _track(ccid);
    }

    function disputeRandom(uint256 raw) external {
        actionCount++;
        _transition(_pickSalt(raw), "dispute");
    }

    function _transition(bytes32 subjectSalt, string memory which) private {
        bytes32 subject = keccak256(abi.encode("subject", subjectSalt));
        bytes32 ccid = RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject);
        bytes memory tag = bytes(which);
        if (keccak256(tag) == keccak256("suspend")) {
            try BRIDGE.suspend(ccid, keccak256(tag), new uint64[](0)) {} catch {}
        } else if (keccak256(tag) == keccak256("resume")) {
            try BRIDGE.resume(ccid, keccak256(tag), new uint64[](0)) {} catch {}
        } else {
            try BRIDGE.dispute(ccid, keccak256(tag), new uint64[](0)) {} catch {}
        }
        _track(ccid);
    }

    function _result(bytes32 subject, uint64 issuedAt, uint64 nonce)
        private
        view
        returns (CredentialTypes.CredentialResult memory)
    {
        return CredentialTypes.CredentialResult({
            ccid: RESOLVER.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject),
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER,
            subjectCommitment: subject,
            evidenceHash: keccak256("evidence"),
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: nonce,
            destinationChainSelectors: new uint64[](0)
        });
    }

    // -----------------------------------------------------------------
    // Ghost-variable key selection
    // -----------------------------------------------------------------

    /// @dev Record a salt so later actions can target it.
    function _remember(bytes32 salt) private {
        for (uint256 i = 0; i < subjectSalts.length; ++i) {
            if (subjectSalts[i] == salt) return;
        }
        subjectSalts.push(salt);
    }

    /**
     * @dev Choose a salt, preferring one that has already produced a credential.
     *
     *      This is what makes the suite have teeth. With purely random salts the
     *      fuzzer spends its budget minting new credentials and almost never
     *      revisits an existing one, so lifecycle interactions - revoke then
     *      resume, expire then renew - simply do not occur and the invariants pass
     *      without ever being tested.
     */
    function _pickSalt(uint256 raw) private view returns (bytes32) {
        if (subjectSalts.length == 0) return keccak256(abi.encode("fresh", raw));
        return subjectSalts[raw % subjectSalts.length];
    }

    // -----------------------------------------------------------------
    // Bookkeeping
    // -----------------------------------------------------------------

    /// @dev Record the high-water marks for a CCID and note terminal states.
    function _track(bytes32 ccid) private {
        if (REGISTRY.getPropagationState(ccid).isReplica) return; // replicas unused here
        if (!REGISTRY.exists(ccid)) return;

        if (_indexOf(ccid) == type(uint256).max) ccids.push(ccid);

        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);
        if (r.expiresAt > highWaterExpiry[ccid]) highWaterExpiry[ccid] = r.expiresAt;
        if (r.nonce > highWaterNonce[ccid]) highWaterNonce[ccid] = r.nonce;
        if (r.status == CredentialTypes.CredentialStatus.Revoked) everRevoked[ccid] = true;
        if (r.status != CredentialTypes.CredentialStatus.Valid) everNonValid[ccid] = true;
    }

    function _indexOf(bytes32 ccid) private view returns (uint256) {
        for (uint256 i = 0; i < ccids.length; ++i) {
            if (ccids[i] == ccid) return i;
        }
        return type(uint256).max;
    }

    function credentialCount() external view returns (uint256) {
        return ccids.length;
    }

    function credentialAt(uint256 i) external view returns (bytes32) {
        return ccids[i];
    }
}
