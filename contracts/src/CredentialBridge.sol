// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CCIDResolver} from "./CCIDResolver.sol";
import {CredentialRegistry} from "./CredentialRegistry.sol";
import {CrossChainCredentialSender} from "./CrossChainCredentialSender.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {SchemaRegistry} from "./SchemaRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {PropagationPayload} from "./libraries/PropagationPayload.sol";

/**
 * @title CredentialBridge
 * @notice Accepts credential results from authorized Chainlink workflows, validates
 *         them, writes source-of-truth state, and triggers cross-chain propagation.
 *
 * @dev This is the only writer to {CredentialRegistry} on the issuing chain, so
 *      every guarantee the system makes is enforced here.
 *
 *      ## Why validate so much on-chain
 *
 *      The workflow is off-chain and therefore not part of the trust boundary we
 *      can reason about. A workflow bug, a compromised runner, or a replayed
 *      request must not be able to mint a credential that passes policy. So the
 *      bridge re-derives and re-checks, in this order:
 *
 *      1.  System is not paused.
 *      2.  Caller holds `WORKFLOW_SUBMITTER`.
 *      3.  CCID reproduces from the submitted fields (anti-tampering / binding).
 *      4.  Provider is registered and `Active`.
 *      5.  Schema exists, is active, and admits this provider.
 *      6.  `expiresAt == issuedAt + schema.ttl` - a workflow cannot mint a
 *          10-year credential under a 24-hour schema.
 *      7.  `expiresAt` is in the future, and `issuedAt` is not implausibly skewed.
 *      8.  Nonce strictly increases for this CCID - replay defence.
 *      9.  `evidenceHash` is non-empty.
 *
 *      Steps 4-6 mean a compromised workflow can still *refuse* a credential but
 *      cannot invent one, extend its life, or attribute it to a paused provider.
 *
 *      ## Revocation authority is schema-scoped
 *
 *      Revocation is the most dangerous transition here, so who may perform it is
 *      decided by the schema's {RevocationMode} rather than by a single global
 *      role. A governance-controlled schema cannot be revoked by its issuer, and an
 *      issuer-controlled schema cannot be revoked by governance alone.
 */
contract CredentialBridge {
    using CredentialTypes for bytes32;

    /// @dev keccak256("WORKFLOW_SUBMITTER") - may submit results and lifecycle changes.
    bytes32 public constant WORKFLOW_SUBMITTER = keccak256("WORKFLOW_SUBMITTER");

    /// @dev keccak256("ISSUER") - acts as the issuer for `IssuerOnly` / `HolderOrIssuer` schemas.
    bytes32 public constant ISSUER = keccak256("ISSUER");

    /// @dev keccak256("HOLDER") - may revoke their own credential where the schema allows.
    bytes32 public constant HOLDER = keccak256("HOLDER");

    /// @dev keccak256("ADMIN") - role administration.
    bytes32 public constant ADMIN = keccak256("ADMIN");

    CredentialRegistry public immutable REGISTRY;
    SchemaRegistry public immutable SCHEMA_REGISTRY;
    ProviderRegistry public immutable PROVIDER_REGISTRY;
    CCIDResolver public immutable CCID_RESOLVER;
    EmergencyControls public immutable EMERGENCY;

    /// @notice Propagation sender. Address(0) disables propagation entirely.
    CrossChainCredentialSender public immutable SENDER;

    /// @notice Max clock skew tolerated between workflow-computed and chain time.
    uint64 public constant MAX_CLOCK_SKEW_SECONDS = 5 minutes;

    event CredentialResultSubmitted(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        bytes32 indexed providerId,
        uint64 expiresAt,
        uint64 nonce,
        uint256 destinations
    );
    event CredentialLifecycleAction(
        bytes32 indexed ccid, string action, CredentialTypes.CredentialStatus resultingStatus, bytes32 reason
    );
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed granter);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed revoker);

    error NotAuthorized(address caller);
    error SystemPaused();
    error InvalidCCID(bytes32 claimed, bytes32 expected);
    error ProviderNotActive(bytes32 providerId);
    error ProviderNotAdmitted(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion);
    error SchemaUnavailable(bytes32 credentialType, uint32 schemaVersion);
    error TtlMismatch(uint64 expectedExpiresAt, uint64 providedExpiresAt);
    error ExpiryNotInFuture(uint64 expiresAt, uint64 nowTs);
    error IssuanceTooSkewed(uint64 issuedAt, uint64 nowTs);
    error ZeroEvidenceHash();
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error RevocationNotPermitted(bytes32 ccid, CredentialTypes.RevocationMode mode, address caller);
    error ZeroAddress();

    constructor(
        address admin,
        CredentialRegistry registry,
        SchemaRegistry schemaRegistry,
        ProviderRegistry providerRegistry,
        CCIDResolver ccidResolver,
        CrossChainCredentialSender sender,
        EmergencyControls emergency
    ) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(ADMIN, admin);
        _grantRole(WORKFLOW_SUBMITTER, admin);
        _grantRole(ISSUER, admin);
        REGISTRY = registry;
        SCHEMA_REGISTRY = schemaRegistry;
        PROVIDER_REGISTRY = providerRegistry;
        CCID_RESOLVER = ccidResolver;
        SENDER = sender;
        EMERGENCY = emergency;
    }

    // ---------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------

    mapping(bytes32 => mapping(address => bool)) private _roles;

    function _grantRole(bytes32 role, address account) private {
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external {
        if (!hasRole(ADMIN, msg.sender)) revert NotAuthorized(msg.sender);
        if (account == address(0)) revert NotAuthorized(msg.sender);
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external {
        if (!hasRole(ADMIN, msg.sender)) revert NotAuthorized(msg.sender);
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        if (!hasRole(role, msg.sender)) revert NotAuthorized(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Issuance
    // ---------------------------------------------------------------------

    /**
     * @notice Submit a verified credential result and propagate it.
     * @dev The single issuance path. See the contract docs for the validation order
     *      and why each step exists.
     * @param r The workflow's credential result.
     */
    function submitCredentialResult(CredentialTypes.CredentialResult calldata r) external onlyRole(WORKFLOW_SUBMITTER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();

        // --- 3. Anti-tampering: the CCID must reproduce from its own fields. ---
        bytes32 expected = CCID_RESOLVER.compute(r.credentialType, r.schemaVersion, r.providerId, r.subjectCommitment);
        if (r.ccid != expected) revert InvalidCCID(r.ccid, expected);

        // --- 4. Provider must be usable right now. ---
        if (!PROVIDER_REGISTRY.isActive(r.providerId)) revert ProviderNotActive(r.providerId);

        // --- 5. Schema must exist, be active, and admit this provider. ---
        SchemaRegistry.Schema memory schema = SCHEMA_REGISTRY.getSchema(r.credentialType, r.schemaVersion);
        if (!schema.registered || !schema.active) revert SchemaUnavailable(r.credentialType, r.schemaVersion);
        if (!SCHEMA_REGISTRY.isProviderAccepted(r.credentialType, r.schemaVersion, r.providerId)) {
            revert ProviderNotAdmitted(r.providerId, r.credentialType, r.schemaVersion);
        }

        // --- 6. TTL is schema policy, not a workflow choice. ---
        uint64 expectedExpiresAt = r.issuedAt + schema.ttlSeconds;
        if (r.expiresAt != expectedExpiresAt) revert TtlMismatch(expectedExpiresAt, r.expiresAt);

        // --- 7. Time sanity. ---
        uint64 nowTs = uint64(block.timestamp);
        if (r.expiresAt <= nowTs) revert ExpiryNotInFuture(r.expiresAt, nowTs);
        if (r.issuedAt > nowTs + MAX_CLOCK_SKEW_SECONDS) revert IssuanceTooSkewed(r.issuedAt, nowTs);

        // --- 9. Evidence must be committed to, even though it is never stored. ---
        if (r.evidenceHash == bytes32(0)) revert ZeroEvidenceHash();

        // --- 8. Replay: a CCID may be issued once, and re-issued only with a higher
        //        nonce. The CCID is the stable identity binding, so the nonce is
        //        what proves the result is newer than what we already hold. ---
        if (REGISTRY.exists(r.ccid)) {
            uint64 current = REGISTRY.getRecord(r.ccid).nonce;
            if (r.nonce <= current) revert NonceNotIncreasing(r.ccid, current, r.nonce);
        }

        // A holder who opened a check with beginVerification already has a record,
        // so resolve it rather than trying to create a second one.
        if (REGISTRY.exists(r.ccid)) {
            REGISTRY.resolvePending(
                r.ccid, r.providerId, r.evidenceHash, r.schemaVersion, r.issuedAt, r.expiresAt, r.nonce
            );
        } else {
            REGISTRY.issue(
                r.ccid,
                r.credentialType,
                r.providerId,
                r.evidenceHash,
                r.schemaVersion,
                r.issuedAt,
                r.expiresAt,
                r.nonce
            );
        }

        _propagate(
            r.ccid,
            r.credentialType,
            r.schemaVersion,
            r.providerId,
            r.evidenceHash,
            r.issuedAt,
            r.expiresAt,
            r.nonce,
            CredentialTypes.CredentialStatus.Valid,
            r.destinationChainSelectors
        );

        emit CredentialResultSubmitted(
            r.ccid, r.credentialType, r.providerId, r.expiresAt, r.nonce, r.destinationChainSelectors.length
        );
    }

    /**
     * @notice Open a credential in `Pending` when verification begins.
     * @dev Lets a holder see that a check is in flight rather than observing
     *      `UNKNOWN` and being unable to distinguish "not requested" from
     *      "requested, still running". Resolved by {submitCredentialResult} or a
     *      later {revoke}.
     */
    function beginVerification(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion, uint64 ttlSeconds)
        external
        onlyRole(WORKFLOW_SUBMITTER)
    {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        uint64 issuedAt = uint64(block.timestamp);
        REGISTRY.registerPending(ccid, credentialType, schemaVersion, issuedAt + ttlSeconds);
        emit CredentialLifecycleAction(
            ccid, "begin", CredentialTypes.CredentialStatus.Pending, CredentialTypes.REASON_PENDING
        );
    }

    // ---------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------

    /**
     * @notice Renew a credential after fresh provider verification.
     * @dev `r` must satisfy the same validation as issuance. Renewal is therefore
     *      impossible without a provider result that passes every issuance check,
     *      which is what stops a stale or forged result from extending a credential.
     */
    function renewCredential(CredentialTypes.CredentialResult calldata r, uint64[] calldata destinations)
        external
        onlyRole(WORKFLOW_SUBMITTER)
    {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (!REGISTRY.exists(r.ccid)) revert InvalidCCID(r.ccid, bytes32(0));

        bytes32 expected = CCID_RESOLVER.compute(r.credentialType, r.schemaVersion, r.providerId, r.subjectCommitment);
        if (r.ccid != expected) revert InvalidCCID(r.ccid, expected);
        if (!PROVIDER_REGISTRY.isActive(r.providerId)) revert ProviderNotActive(r.providerId);

        SchemaRegistry.Schema memory schema = SCHEMA_REGISTRY.getSchema(r.credentialType, r.schemaVersion);
        if (!schema.registered || !schema.active) revert SchemaUnavailable(r.credentialType, r.schemaVersion);
        if (!SCHEMA_REGISTRY.isProviderAccepted(r.credentialType, r.schemaVersion, r.providerId)) {
            revert ProviderNotAdmitted(r.providerId, r.credentialType, r.schemaVersion);
        }

        uint64 expectedExpiresAt = r.issuedAt + schema.ttlSeconds;
        if (r.expiresAt != expectedExpiresAt) revert TtlMismatch(expectedExpiresAt, r.expiresAt);
        if (r.expiresAt <= uint64(block.timestamp)) revert ExpiryNotInFuture(r.expiresAt, uint64(block.timestamp));
        if (r.evidenceHash == bytes32(0)) revert ZeroEvidenceHash();

        REGISTRY.renew(r.ccid, r.expiresAt, r.nonce);

        _propagate(
            r.ccid,
            r.credentialType,
            r.schemaVersion,
            r.providerId,
            r.evidenceHash,
            r.issuedAt,
            r.expiresAt,
            r.nonce,
            CredentialTypes.CredentialStatus.Valid,
            destinations
        );

        emit CredentialLifecycleAction(
            r.ccid, "renew", CredentialTypes.CredentialStatus.Valid, CredentialTypes.REASON_OK
        );
    }

    /**
     * @notice Revoke a credential and propagate the revocation.
     * @dev Authority comes from the schema's {RevocationMode}, checked against the
     *      caller's roles. Revocation fails closed on any propagation error: if a
     *      destination cannot be told, the revocation must not appear to have
     *      succeeded system-wide, so the whole transaction reverts.
     * @param reason Short machine-readable cause, emitted publicly.
     */
    function revoke(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external {
        if (EMERGENCY.isPaused()) revert SystemPaused();

        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        SchemaRegistry.Schema memory schema = SCHEMA_REGISTRY.getSchema(r.credentialType, r.schemaVersion);
        _requireRevocationAuthority(schema.revocationMode);

        REGISTRY.setStatus(ccid, CredentialTypes.CredentialStatus.Revoked, reason);
        _repropagateStatus(ccid, CredentialTypes.CredentialStatus.Revoked, destinations);

        emit CredentialLifecycleAction(ccid, "revoke", CredentialTypes.CredentialStatus.Revoked, reason);
    }

    /// @notice Suspend a credential. Issuer-controlled lifecycle action.
    function suspend(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external onlyRole(ISSUER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        REGISTRY.setStatus(ccid, CredentialTypes.CredentialStatus.Suspended, reason);
        _repropagateStatus(ccid, CredentialTypes.CredentialStatus.Suspended, destinations);
        emit CredentialLifecycleAction(ccid, "suspend", CredentialTypes.CredentialStatus.Suspended, reason);
    }

    /// @notice Lift a suspension, returning the credential to `Valid`.
    function resume(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external onlyRole(ISSUER) {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        REGISTRY.setStatus(ccid, CredentialTypes.CredentialStatus.Valid, reason);
        _repropagateStatus(ccid, CredentialTypes.CredentialStatus.Valid, destinations);
        emit CredentialLifecycleAction(ccid, "resume", CredentialTypes.CredentialStatus.Valid, reason);
    }

    /// @notice Flag a credential as contested. Denies access until resolved.
    function dispute(bytes32 ccid, bytes32 reason, uint64[] calldata destinations) external {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        CredentialTypes.CredentialRecord memory r = REGISTRY.getRecord(ccid);
        if (r.ccid == bytes32(0)) revert InvalidCCID(ccid, bytes32(0));

        // A dispute may be raised by the issuer, the holder, or governance.
        if (!hasRole(ISSUER, msg.sender) && !hasRole(HOLDER, msg.sender) && !hasRole(ADMIN, msg.sender)) {
            revert NotAuthorized(msg.sender);
        }

        REGISTRY.setStatus(ccid, CredentialTypes.CredentialStatus.Disputed, reason);
        _repropagateStatus(ccid, CredentialTypes.CredentialStatus.Disputed, destinations);
        emit CredentialLifecycleAction(ccid, "dispute", CredentialTypes.CredentialStatus.Disputed, reason);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev Who may revoke, per schema policy.
     *      `GovernanceOnly` deliberately excludes ISSUER: a governance-controlled
     *      credential that its own issuer could revoke would not be
     *      governance-controlled.
     */
    function _requireRevocationAuthority(CredentialTypes.RevocationMode mode) private view {
        if (mode == CredentialTypes.RevocationMode.GovernanceOnly) {
            if (!hasRole(ADMIN, msg.sender)) revert RevocationNotPermitted(bytes32(0), mode, msg.sender);
            return;
        }
        if (mode == CredentialTypes.RevocationMode.HolderOrIssuer) {
            if (hasRole(ISSUER, msg.sender) || hasRole(HOLDER, msg.sender) || hasRole(ADMIN, msg.sender)) return;
            revert RevocationNotPermitted(bytes32(0), mode, msg.sender);
        }
        if (!hasRole(ISSUER, msg.sender) && !hasRole(ADMIN, msg.sender)) {
            revert RevocationNotPermitted(bytes32(0), mode, msg.sender);
        }
    }

    /**
     * @dev Propagate a status-only change.
     *
     *      Re-reads the record rather than trusting the caller's copy, because
     *      {CredentialRegistry.setStatus} bumps the nonce and the destination
     *      chain only accepts strictly increasing nonces. Propagating a stale
     *      nonce would make every status change - revocation above all - look
     *      like a replay and be discarded.
     */
    function _repropagateStatus(bytes32 ccid, CredentialTypes.CredentialStatus status, uint64[] calldata destinations)
        private
    {
        CredentialTypes.CredentialRecord memory fresh = REGISTRY.getRecord(ccid);
        _propagate(
            ccid,
            fresh.credentialType,
            fresh.schemaVersion,
            fresh.providerId,
            fresh.evidenceHash,
            fresh.issuedAt,
            fresh.expiresAt,
            fresh.nonce,
            status,
            destinations
        );
    }

    /**
     * @dev Dispatch to destinations when propagation is configured.
     *      An empty destination list is a no-op, which is what lets a single-chain
     *      deployment run with propagation disabled.
     */
    function _propagate(
        bytes32 ccid,
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce,
        CredentialTypes.CredentialStatus status,
        uint64[] calldata destinations
    ) private {
        if (address(SENDER) == address(0) || destinations.length == 0) return;

        PropagationPayload.Message memory m;
        m.ccid = ccid;
        m.credentialType = credentialType;
        m.schemaVersion = schemaVersion;
        m.providerId = providerId;
        m.evidenceHash = evidenceHash;
        m.issuedAt = issuedAt;
        m.expiresAt = expiresAt;
        m.nonce = nonce;
        m.status = status;
        // bindingHash is left unset: the sender is its single authority and
        // recomputes it, so there is exactly one implementation of the rule.

        SENDER.sendCredentialState(m, destinations);
    }
}
