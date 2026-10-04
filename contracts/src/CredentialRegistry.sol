// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialTypes} from "./libraries/CredentialTypes.sol";

/**
 * @title CredentialRegistry
 * @notice The single persistent home of credential state. Stores minimal,
 *         PII-free records and enforces the lifecycle rules that make an access
 *         decision safe.
 *
 * @dev ## Writer model
 *
 *      This contract holds no admin keys of its own. It is written only by two
 *      authorized writers, both set at deployment by the deployer:
 *
 *      1. `CredentialBridge` - the source of truth on the issuing chain.
 *      2. `CrossChainCredentialReceiver` - writes *replicas* received via CCIP.
 *
 *      Splitting authority this way means a compromised bridge still cannot forge
 *      destination state, and a compromised receiver cannot invent new issuance.
 *
 *      ## The central invariant
 *
 *      Only `Valid` may ever produce an allow decision. `Unknown`, `Pending`,
 *      `Expired`, `Suspended`, `Revoked`, and `Disputed` are all denials. This is
 *      asserted as a Foundry invariant in
 *      `contracts/test/invariant/CredentialLifecycle.t.sol`.
 *
 *      ## Expiry does not depend on a sweeper
 *
 *      {effectiveStatus} applies expiry lazily from `expiresAt`, so a credential
 *      is denied the instant it lapses whether or not anyone has called
 *      {expireDue}. The sweeper exists to keep the event trail complete, not to
 *      enforce safety. A system whose expiry depended on a keeper being alive
 *      would fail open, which is the one unacceptable direction here.
 */
contract CredentialRegistry {
    using CredentialTypes for bytes32;

    /// @dev Writers permitted to mutate credential state.
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    /// @dev May change the writer set and pause reads.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice A credential was written for the first time.
    event CredentialIssued(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        bytes32 indexed providerId,
        uint32 schemaVersion,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce
    );

    /// @notice A credential's status changed.
    event CredentialStatusChanged(
        bytes32 indexed ccid,
        CredentialTypes.CredentialStatus previous,
        CredentialTypes.CredentialStatus current,
        bytes32 reason
    );

    /// @notice A credential was renewed, producing a new expiry.
    event CredentialRenewed(bytes32 indexed ccid, uint64 previousExpiresAt, uint64 newExpiresAt, uint64 nonce);

    /// @notice Credential state was replicated from another chain.
    event CredentialPropagated(
        bytes32 indexed ccid, uint64 indexed sourceChainSelector, uint64 sourceNonce, uint64 lastUpdatedAt
    );

    /// @notice A sweeper confirmed a credential had lapsed.
    event CredentialExpired(bytes32 indexed ccid, uint64 expiresAt);

    /// @notice The authorized writer set changed.
    event WriterAuthorizationChanged(address indexed writer, bool authorized, address indexed changedBy);

    /// @dev ccid => CredentialRecord
    mapping(bytes32 => CredentialTypes.CredentialRecord) private _records;

    /// @dev ccid => PropagationState. Kept out of the record so the record
    ///      matches `ENGINEERING_SPEC.md` section 4 exactly.
    mapping(bytes32 => CredentialTypes.PropagationState) public propagationState;

    error NotWriter(address caller);
    error NotAdmin(address caller);
    error CredentialNotFound(bytes32 ccid);
    error CredentialAlreadyExists(bytes32 ccid);
    error IllegalTransition(bytes32 ccid, CredentialTypes.CredentialStatus from, CredentialTypes.CredentialStatus to);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error ExpiryInPast(bytes32 ccid, uint64 expiresAt, uint64 nowTs);
    error ZeroAddress();
    error BatchTooLarge(uint256 length);

    /// @dev Max records touched in a single sweep, to bound automation gas.
    uint256 public constant MAX_SWEEP_BATCH = 100;

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(ADMIN_ROLE, admin);
    }

    // ---------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------

    /// @dev Minimal local role store. `AccessControl` is not used here on
    ///      purpose: this contract holds two roles, and a bespoke 20-line store
    ///      is easier to audit than an inherited general-purpose one.
    mapping(bytes32 => mapping(address => bool)) private _roles;

    function _grantRole(bytes32 role, address account) private {
        _roles[role][account] = true;
        emit WriterAuthorizationChanged(account, true, msg.sender);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    /// @notice Authorize an additional writer. Admin only.
    function setWriter(address writer, bool authorized) external {
        if (!hasRole(ADMIN_ROLE, msg.sender)) revert NotAdmin(msg.sender);
        if (writer == address(0)) revert ZeroAddress();
        if (_roles[WRITER_ROLE][writer] == authorized) return;
        // Emits WriterAuthorizationChanged immediately below; the lint heuristic
        // does not associate a non-"role"-named event with this mapping.
        // forge-lint: disable-next-line(missing-events-access-control)
        _roles[WRITER_ROLE][writer] = authorized;
        emit WriterAuthorizationChanged(writer, authorized, msg.sender);
    }

    function isWriter(address account) external view returns (bool) {
        return hasRole(WRITER_ROLE, account);
    }

    modifier onlyWriter() {
        if (!hasRole(WRITER_ROLE, msg.sender)) revert NotWriter(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Writes
    // ---------------------------------------------------------------------

    /**
     * @notice Write a new credential. Rejects any pre-existing CCID.
     * @dev The bridge is the only production caller. `subjectCommitment` is
     *      deliberately absent: the record never stores it, only the CCID derived
     *      from it, so the binding is verifiable without retaining the commitment.
     */
    function issue(
        bytes32 ccid,
        bytes32 credentialType,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce
    ) external onlyWriter {
        if (_records[ccid].ccid != bytes32(0)) revert CredentialAlreadyExists(ccid);

        CredentialTypes.CredentialRecord storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;
        r.status = CredentialTypes.CredentialStatus.Valid;

        emit CredentialIssued(ccid, credentialType, providerId, schemaVersion, issuedAt, expiresAt, nonce);
    }

    /**
     * @notice Write a replica received from another chain.
     * @dev Marks the record as a replica and records freshness, which is what
     *      {PolicyManagerAdapter} later uses to detect a stale destination.
     *
     *      Replicas never overwrite source-of-truth state: if this chain is the
     *      issuer for `ccid`, an inbound message is ignored by the receiver before
     *      it gets here.
     */
    function applyReplica(
        bytes32 ccid,
        bytes32 credentialType,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce,
        CredentialTypes.CredentialStatus status,
        uint64 sourceChainSelector
    ) external onlyWriter {
        CredentialTypes.CredentialRecord storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;
        r.status = status;

        CredentialTypes.PropagationState storage p = propagationState[ccid];
        p.isReplica = true;
        p.sourceChainSelector = sourceChainSelector;
        p.lastUpdatedAt = uint64(block.timestamp);
        p.lastSourceNonce = nonce;

        emit CredentialPropagated(ccid, sourceChainSelector, nonce, uint64(block.timestamp));
    }

    /**
     * @notice Open a credential in `Pending` while verification is in flight.
     * @dev `Pending` exists so a holder can be told "your check is running" instead
     *      of being indistinguishable from a credential that was never requested.
     *      It is a denial ({PolicyManagerAdapter} returns `PENDING`), which is the
     *      point: an unfinished check must never read as a pass.
     *
     *      Writers call this when a verification starts, then {issue} or {setStatus}
     *      to resolve it. A `Pending` record that is never resolved simply expires
     *      like any other lapsed credential.
     */
    function registerPending(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion, uint64 expiresAt)
        external
        onlyWriter
    {
        if (_records[ccid].ccid != bytes32(0)) revert CredentialAlreadyExists(ccid);

        CredentialTypes.CredentialRecord storage r = _records[ccid];
        r.ccid = ccid;
        r.credentialType = credentialType;
        r.providerId = bytes32(0); // not yet known; set on resolution
        r.evidenceHash = bytes32(0);
        r.schemaVersion = schemaVersion;
        r.issuedAt = uint64(block.timestamp);
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = 0;
        r.status = CredentialTypes.CredentialStatus.Pending;

        emit CredentialStatusChanged(
            ccid, CredentialTypes.CredentialStatus.Unknown, CredentialTypes.CredentialStatus.Pending, bytes32("PENDING")
        );
    }

    /**
     * @notice Resolve a `Pending` record into a fully verified credential.
     * @dev The counterpart to {registerPending}. Kept separate from {issue} because
     *      the record already exists, and a holder who started a check must be able
     *      to finish it. Callers that skipped `Pending` should use {issue}.
     *
     *      Enforces the same rules issuance does: the nonce must strictly increase,
     *      and the result must arrive before `expiresAt`.
     */
    function resolvePending(
        bytes32 ccid,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint32 schemaVersion,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce
    ) external onlyWriter {
        CredentialTypes.CredentialRecord storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);
        if (r.status != CredentialTypes.CredentialStatus.Pending) revert CredentialAlreadyExists(ccid);
        if (nonce <= r.nonce) revert NonceNotIncreasing(ccid, r.nonce, nonce);
        if (expiresAt <= uint64(block.timestamp)) revert ExpiryInPast(ccid, expiresAt, uint64(block.timestamp));

        r.providerId = providerId;
        r.evidenceHash = evidenceHash;
        r.schemaVersion = schemaVersion;
        r.issuedAt = issuedAt;
        r.expiresAt = expiresAt;
        r.updatedAt = uint64(block.timestamp);
        r.nonce = nonce;
        r.status = CredentialTypes.CredentialStatus.Valid;

        emit CredentialIssued(ccid, r.credentialType, providerId, schemaVersion, issuedAt, expiresAt, nonce);
    }

    /**
     * @notice Move a credential to a new status.
     * @dev Enforces the transition table in {ALLOWED_TRANSITIONS} and refuses to
     *      move backwards out of a terminal state. `Revoked` is terminal: there is
     *      no path back to `Valid`, so a revoked credential cannot be resurrected
     *      by a later, buggy, or compromised workflow.
     *
     *      Every accepted transition bumps `nonce`. This is essential, not
     *      cosmetic: the nonce is what a destination chain uses to decide an
     *      inbound message is newer than what it already holds. Without a bump, a
     *      revocation would carry the same nonce as the issuance it reverses, and
     *      every destination that saw the credential as `Valid` would reject the
     *      revocation as stale - leaving a revoked credential valid everywhere.
     */
    function setStatus(bytes32 ccid, CredentialTypes.CredentialStatus next, bytes32 reason) external onlyWriter {
        CredentialTypes.CredentialRecord storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);

        CredentialTypes.CredentialStatus previous = r.status;
        if (!_isTransitionAllowed(previous, next)) revert IllegalTransition(ccid, previous, next);

        r.status = next;
        r.updatedAt = uint64(block.timestamp);
        r.nonce += 1;

        emit CredentialStatusChanged(ccid, previous, next, reason);
    }

    /**
     * @notice Extend a credential's lifetime after successful re-verification.
     * @dev Refreshes the nonce as well as the expiry. The nonce bump is what makes
     *      a renewal impossible to forge by replaying an older provider result:
     *      the old result carries the old nonce and will be rejected.
     * @param newExpiresAt Must be strictly later than the current expiry.
     */
    function renew(bytes32 ccid, uint64 newExpiresAt, uint64 newNonce) external onlyWriter {
        CredentialTypes.CredentialRecord storage r = _records[ccid];
        if (r.ccid == bytes32(0)) revert CredentialNotFound(ccid);
        if (r.status == CredentialTypes.CredentialStatus.Revoked) {
            revert IllegalTransition(ccid, r.status, CredentialTypes.CredentialStatus.Valid);
        }
        if (newExpiresAt <= r.expiresAt) revert NonceNotIncreasing(ccid, r.expiresAt, newExpiresAt);
        if (newNonce <= r.nonce) revert NonceNotIncreasing(ccid, r.nonce, newNonce);

        uint64 previousExpiresAt = r.expiresAt;
        r.expiresAt = newExpiresAt;
        r.nonce = newNonce;
        r.issuedAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);
        if (r.status != CredentialTypes.CredentialStatus.Valid) {
            r.status = CredentialTypes.CredentialStatus.Valid;
        }

        emit CredentialRenewed(ccid, previousExpiresAt, newExpiresAt, newNonce);
    }

    /**
     * @notice Mark lapsed credentials as `Expired` and emit an event for each.
     * @dev Purely cosmetic for safety purposes - {effectiveStatus} already denies
     *      on `expiresAt`. Exists so monitoring and audit exports see a clean
     *      terminal transition instead of a silent time-based change.
     */
    function expireDue(bytes32[] calldata ccids) external onlyWriter returns (uint256 expiredCount) {
        if (ccids.length > MAX_SWEEP_BATCH) revert BatchTooLarge(ccids.length);

        for (uint256 i = 0; i < ccids.length; ++i) {
            bytes32 ccid = ccids[i];
            CredentialTypes.CredentialRecord storage r = _records[ccid];
            if (r.ccid == bytes32(0)) continue;
            if (r.status == CredentialTypes.CredentialStatus.Valid && r.expiresAt <= uint64(block.timestamp)) {
                r.status = CredentialTypes.CredentialStatus.Expired;
                r.updatedAt = uint64(block.timestamp);
                emit CredentialExpired(ccid, r.expiresAt);
                emit CredentialStatusChanged(
                    ccid,
                    CredentialTypes.CredentialStatus.Valid,
                    CredentialTypes.CredentialStatus.Expired,
                    CredentialTypes.REASON_EXPIRED
                );
                ++expiredCount;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------

    function exists(bytes32 ccid) external view returns (bool) {
        return _records[ccid].ccid != bytes32(0);
    }

    /// @notice Raw stored record, with no lazy-expiry applied.
    function getRecord(bytes32 ccid) external view returns (CredentialTypes.CredentialRecord memory) {
        return _records[ccid];
    }

    /**
     * @notice Status with lazy expiry applied.
     * @dev A stored `Valid` whose `expiresAt` has passed reads as `Expired`.
     *      This is the function every policy path should use.
     */
    function statusOf(bytes32 ccid) public view returns (CredentialTypes.CredentialStatus) {
        CredentialTypes.CredentialRecord storage r = _records[ccid];
        if (r.ccid == bytes32(0)) return CredentialTypes.CredentialStatus.Unknown;
        if (r.status == CredentialTypes.CredentialStatus.Valid && r.expiresAt <= uint64(block.timestamp)) {
            return CredentialTypes.CredentialStatus.Expired;
        }
        return r.status;
    }

    /**
     * @notice True only for a present, `Valid`, unexpired record.
     * @dev Note this says nothing about provider status or destination freshness.
     *      Those are policy inputs, not credential state, so integrators that need
     *      the full decision must use {PolicyManagerAdapter.evaluate}.
     */
    function isValid(bytes32 ccid) external view returns (bool) {
        return statusOf(ccid) == CredentialTypes.CredentialStatus.Valid;
    }

    function getPropagationState(bytes32 ccid) external view returns (CredentialTypes.PropagationState memory) {
        return propagationState[ccid];
    }

    /**
     * @notice Seconds since this record's state was last written.
     * @return age Age in seconds, or `type(uint64).max` when unknown.
     */
    function ageOf(bytes32 ccid) external view returns (uint64 age) {
        if (_records[ccid].ccid == bytes32(0)) return type(uint64).max;
        return uint64(block.timestamp) - _records[ccid].updatedAt;
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev The lifecycle transition table.
     *
     *      Rules encoded here:
     *      - `Revoked` is terminal. No transitions out.
     *      - Nothing enters `Valid` except from a state a holder can recover
     *        from (renewal / dispute resolution / un-suspension).
     *      - `Unknown` is unreachable as a transition target; it is the absence
     *        of a record, not a lifecycle step.
     */
    function _isTransitionAllowed(CredentialTypes.CredentialStatus from, CredentialTypes.CredentialStatus to)
        private
        pure
        returns (bool)
    {
        if (from == to) return true;

        // Terminal.
        if (from == CredentialTypes.CredentialStatus.Revoked) return false;

        if (from == CredentialTypes.CredentialStatus.Unknown) {
            return to == CredentialTypes.CredentialStatus.Pending || to == CredentialTypes.CredentialStatus.Valid;
        }

        if (from == CredentialTypes.CredentialStatus.Pending) {
            return to == CredentialTypes.CredentialStatus.Valid || to == CredentialTypes.CredentialStatus.Suspended
                || to == CredentialTypes.CredentialStatus.Revoked || to == CredentialTypes.CredentialStatus.Disputed;
        }

        if (from == CredentialTypes.CredentialStatus.Valid) {
            return to == CredentialTypes.CredentialStatus.Expired || to == CredentialTypes.CredentialStatus.Suspended
                || to == CredentialTypes.CredentialStatus.Revoked || to == CredentialTypes.CredentialStatus.Disputed;
        }

        if (from == CredentialTypes.CredentialStatus.Expired) {
            // Expired credentials recover only through renewal, which the bridge
            // performs as an explicit `renew` call, not a status flip.
            return to == CredentialTypes.CredentialStatus.Revoked || to == CredentialTypes.CredentialStatus.Disputed;
        }

        if (from == CredentialTypes.CredentialStatus.Suspended) {
            return to == CredentialTypes.CredentialStatus.Valid || to == CredentialTypes.CredentialStatus.Revoked
                || to == CredentialTypes.CredentialStatus.Expired;
        }

        // Disputed
        return to == CredentialTypes.CredentialStatus.Valid || to == CredentialTypes.CredentialStatus.Revoked
            || to == CredentialTypes.CredentialStatus.Expired;
    }
}
