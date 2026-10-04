// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialRegistry} from "./CredentialRegistry.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {SchemaRegistry} from "./SchemaRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";

/**
 * @title PolicyManagerAdapter
 * @notice Integrator-facing access check. Returns an allow/deny decision together
 *         with a reason code, so callers never have to guess why access failed.
 *
 * @dev ## Why this exists
 *
 *      A bare `registry.isValid(ccid)` is an unsafe integration surface. It is
 *      true for a credential whose provider has since been paused, and for a
 *      replica this chain last heard from weeks ago. Integrators reach for
 *      `isValid`, get `true`, and ship a gate that fails open during exactly the
 *      incidents it was meant to survive.
 *
 *      This adapter exists to make the safe path the easy one: one call that
 *      considers credential state, provider status, schema support, and
 *      destination freshness, and always explains itself.
 *
 *      ## Reason-code precedence
 *
 *      Checks run in a fixed order, and the first failure wins. The order is
 *      chosen so the returned code describes the most actionable problem:
 *
 *      1.  `SYSTEM_PAUSED`          - no decision is trustworthy while paused.
 *      2.  `UNKNOWN`                - no record. Distinguishable from every denial.
 *      3.  `PENDING`                - verification in flight; retry later.
 *      4.  `REVOKED`                - deliberate, permanent withdrawal. Reported
 *                                    ahead of expiry because it is the stronger
 *                                    and more deliberate signal.
 *      5.  `SUSPENDED`              - temporary, issuer-imposed block.
 *      6.  `DISPUTED`               - contested; deny until resolved.
 *      7.  `EXPIRED`                - lapsed, by sweeper or lazily.
 *      8.  `CREDENTIAL_TYPE_MISMATCH`
 *      9.  `SCHEMA_VERSION_UNSUPPORTED`
 *      10. `PROVIDER_NOT_ACCEPTED`  - this integrator does not trust that provider.
 *      11. `PROVIDER_PAUSED`        - provider status blocks issuance or attestation.
 *      12. `SCHEMA_UNSUPPORTED`     - schema deprecated or absent on this chain.
 *      13. `STALE_DESTINATION`      - replica older than the integrator tolerates.
 *      14. `OK`
 *
 *      `PROVIDER_NOT_ACCEPTED` (an integrator's own choice) is deliberately
 *      checked before `PROVIDER_PAUSED` (a system-wide condition), because an
 *      integrator should not have to wait out an unrelated provider incident to
 *      learn that they never trusted that provider.
 */
contract PolicyManagerAdapter {
    CredentialRegistry public immutable REGISTRY;
    SchemaRegistry public immutable SCHEMA_REGISTRY;
    ProviderRegistry public immutable PROVIDER_REGISTRY;
    EmergencyControls public immutable EMERGENCY;

    /// @notice Emitted on every allow. Denials are not emitted: they are on-chain
    ///         view calls, and emitting them would let an attacker inflate a
    ///         holder's public denial history by probing repeatedly.
    event AccessGranted(
        bytes32 indexed ccid, bytes32 indexed credentialType, address indexed caller, bytes32 reasonCode
    );

    constructor(
        CredentialRegistry registry,
        SchemaRegistry schemaRegistry,
        ProviderRegistry providerRegistry,
        EmergencyControls emergency
    ) {
        REGISTRY = registry;
        SCHEMA_REGISTRY = schemaRegistry;
        PROVIDER_REGISTRY = providerRegistry;
        EMERGENCY = emergency;
    }

    /**
     * @notice Evaluate a credential against an integrator's requirement.
     * @dev Matches the signature required by `ENGINEERING_SPEC.md` section 4.
     *      Pure and view: an integrator may call it off-chain via `eth_call`
     *      without any state change or event.
     * @param ccid Credential content identifier.
     * @param requirement The integrator's policy.
     * @return allowed True only when every check passes.
     * @return reasonCode A `CredentialTypes` reason code; `REASON_OK` iff allowed.
     */
    function evaluate(bytes32 ccid, CredentialTypes.CredentialRequirement calldata requirement)
        external
        view
        returns (bool allowed, bytes32 reasonCode)
    {
        // Copy once from calldata into memory so every caller shares one
        // implementation of the decision logic.
        CredentialTypes.CredentialRequirement memory req = requirement;
        return _evaluate(ccid, req);
    }

    /// @dev The single implementation of the decision. Every public entry point
    ///      funnels through here so the precedence order can never diverge between
    ///      the view and state-changing surfaces.
    function _evaluate(bytes32 ccid, CredentialTypes.CredentialRequirement memory requirement)
        private
        view
        returns (bool allowed, bytes32 reasonCode)
    {
        // 1. A paused system cannot produce a trustworthy decision. Failing closed
        //    here is deliberate: during an incident the safe answer is "no".
        if (EMERGENCY.isPaused()) return (false, CredentialTypes.REASON_SYSTEM_PAUSED);

        // 2. Presence and lifecycle state.
        CredentialTypes.CredentialStatus status = REGISTRY.statusOf(ccid);
        reasonCode = _statusReason(status);
        if (reasonCode != CredentialTypes.REASON_OK) return (false, reasonCode);

        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);

        // 3. Requirement matching.
        if (requirement.credentialType != bytes32(0) && r.credentialType != requirement.credentialType) {
            return (false, CredentialTypes.REASON_CREDENTIAL_TYPE_MISMATCH);
        }
        if (requirement.schemaVersion != 0 && r.schemaVersion != requirement.schemaVersion) {
            return (false, CredentialTypes.REASON_SCHEMA_VERSION_UNSUPPORTED);
        }

        // 4. Integrator's own provider allowlist, before any system condition.
        if (!_isProviderAccepted(requirement, r)) {
            return (false, CredentialTypes.REASON_PROVIDER_NOT_ACCEPTED);
        }

        // 5. Provider status. `Deprecated` still backs existing credentials so a
        //    planned wind-down does not retroactively invalidate live holders.
        if (!PROVIDER_REGISTRY.backsExistingCredentials(r.providerId)) {
            return (false, CredentialTypes.REASON_PROVIDER_PAUSED);
        }

        // 6. Schema must still be supported here. A replica of a schema this chain
        //    does not know about is not safely usable.
        if (!SCHEMA_REGISTRY.isSchemaSupported(r.credentialType, r.schemaVersion)) {
            return (false, CredentialTypes.REASON_SCHEMA_UNSUPPORTED);
        }

        // 7. Destination freshness, replicas only.
        if (requirement.requireFresh && REGISTRY.getPropagationState(ccid).isReplica) {
            uint64 maxAge = requirement.maxAgeSeconds == 0 ? 1 days : requirement.maxAgeSeconds;
            if (REGISTRY.ageOf(ccid) > maxAge) {
                return (false, CredentialTypes.REASON_STALE_DESTINATION);
            }
        }

        return (true, CredentialTypes.REASON_OK);
    }

    /**
     * @notice Evaluate and emit {AccessGranted} on success.
     * @dev The non-view entry point for integrators that want an audit trail of
     *      grants. Denials still revert-free and emit nothing; see {AccessGranted}.
     */
    function evaluateAndRecord(bytes32 ccid, CredentialTypes.CredentialRequirement calldata requirement)
        external
        returns (bool allowed, bytes32 reasonCode)
    {
        (allowed, reasonCode) = _evaluate(ccid, requirement);
        if (allowed) emit AccessGranted(ccid, REGISTRY.getRecord(ccid).credentialType, msg.sender, reasonCode);
    }

    /**
     * @notice Convenience wrapper: "is this credential currently valid?"
     * @dev Provided so the common case is one call, but it is deliberately named
     *      `explainDefault` rather than `isValid` to avoid the false confidence
     *      that a bare boolean invites. It still omits freshness, because a
     *      requirement must express an integrator's tolerance before it can be checked.
     */
    function explainDefault(bytes32 ccid, bytes32 credentialType)
        external
        view
        returns (bool allowed, bytes32 reasonCode)
    {
        CredentialTypes.CredentialRequirement memory req;
        req.credentialType = credentialType;
        req.schemaVersion = 0;
        req.maxAgeSeconds = 0;
        req.requireFresh = false;
        return _evaluate(ccid, req);
    }

    /// @notice Human-readable reason code, for events, CLI, and SDK display.
    function describeReason(bytes32 reasonCode) external pure returns (string memory) {
        return CredentialTypes.reasonToString(reasonCode);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /// @dev Maps a non-Valid status to its reason code, in precedence order.
    function _statusReason(CredentialTypes.CredentialStatus status) private pure returns (bytes32 reasonCode) {
        if (status == CredentialTypes.CredentialStatus.Valid) return CredentialTypes.REASON_OK;
        if (status == CredentialTypes.CredentialStatus.Unknown) return CredentialTypes.REASON_UNKNOWN;
        if (status == CredentialTypes.CredentialStatus.Pending) return CredentialTypes.REASON_PENDING;
        if (status == CredentialTypes.CredentialStatus.Revoked) return CredentialTypes.REASON_REVOKED;
        if (status == CredentialTypes.CredentialStatus.Suspended) return CredentialTypes.REASON_SUSPENDED;
        if (status == CredentialTypes.CredentialStatus.Disputed) return CredentialTypes.REASON_DISPUTED;
        return CredentialTypes.REASON_EXPIRED;
    }

    /**
     * @dev An empty allowlist means "any provider the schema accepts", which keeps
     *      simple integrations from having to enumerate providers.
     */
    function _isProviderAccepted(
        CredentialTypes.CredentialRequirement memory requirement,
        CredentialTypes.CredentialRecord memory r
    ) private view returns (bool) {
        if (requirement.acceptedProviders.length == 0) {
            return SCHEMA_REGISTRY.isProviderAccepted(r.credentialType, r.schemaVersion, r.providerId);
        }
        for (uint256 i = 0; i < requirement.acceptedProviders.length; ++i) {
            if (requirement.acceptedProviders[i] == r.providerId) return true;
        }
        return false;
    }
}
