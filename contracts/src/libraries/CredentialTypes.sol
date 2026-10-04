// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title CredentialTypes
 * @notice Shared enums, structs, and reason codes for the Identity Bridge zkTLS credential system.
 * @dev This file is the single source of truth for on-chain credential vocabulary.
 *
 *      PRIVACY INVARIANT
 *      -----------------
 *      `CredentialRecord` is the complete persistent surface for a credential's
 *      identity. It deliberately contains no name, email, phone, address,
 *      document, account handle, TLS transcript, proof, or provider report.
 *
 *      Every field is either a 32-byte hash, an enum, or a timestamp. The
 *      credential is bound to a holder by `ccid`, which is a salted,
 *      domain-separated hash computed off-chain from a subject commitment
 *      (see {CCIDResolver}). It is one-way, so possession of on-chain state does
 *      not reveal who the holder is.
 *
 *      The `PII` free-storage property is enforced mechanically, not just by
 *      convention: `contracts/test/invariant/NoPIIStorage.t.sol` walks every
 *      storage slot of the deployed system and asserts that no slot decodes to a
 *      human-readable string. Adding a `string` or `bytes` field to this struct
 *      will fail that test.
 */
library CredentialTypes {
    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    /**
     * @notice Lifecycle state of a credential.
     * @dev `Valid` is the ONLY status from which {PolicyManagerAdapter} will
     *      return `allowed == true`. Every other value is a denial. This is the
     *      central safety property of the system and is asserted as a Foundry
     *      invariant.
     */
    enum CredentialStatus {
        Unknown,
        Pending,
        Valid,
        Expired,
        Suspended,
        Revoked,
        Disputed
    }

    /**
     * @notice Operational state of a provider adapter.
     * @dev `Deprecated` means "still valid for existing credentials, but no new
     *      issuance". `Paused` and `Revoked` additionally deny access checks.
     */
    enum ProviderStatus {
        Unknown,
        Active,
        Paused,
        Deprecated,
        Revoked
    }

    /**
     * @notice Who may revoke a credential issued under a given schema.
     * @dev Enforced by {CredentialBridge}; revocation is the most dangerous
     *      transition in the system so it is schema-scoped rather than global.
     */
    enum RevocationMode {
        IssuerOnly,
        HolderOrIssuer,
        GovernanceOnly
    }

    // ---------------------------------------------------------------------
    // Records
    // ---------------------------------------------------------------------

    /**
     * @notice Minimal credential state. Mirrors `ENGINEERING_SPEC.md` section 4.
     * @param ccid Content identifier binding the credential to its holder.
     * @param credentialType Schema family this credential belongs to.
     * @param providerId Adapter that produced the underlying verification.
     * @param evidenceHash Commitment to the provider evidence. Hash only; the
     *        evidence itself never reaches chain state.
     * @param schemaVersion Version of the schema policy applied at issuance.
     * @param issuedAt Issuance timestamp (seconds).
     * @param expiresAt Expiry timestamp (seconds). Enforced even if no sweeper runs.
     * @param updatedAt Last mutation timestamp (seconds).
     * @param nonce Per-credential monotonic counter binding each result to a
     *        single use, preventing replay of an old provider result.
     * @param status Lifecycle state.
     */
    struct CredentialRecord {
        bytes32 ccid;
        bytes32 credentialType;
        bytes32 providerId;
        bytes32 evidenceHash;
        uint32 schemaVersion;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 updatedAt;
        uint64 nonce;
        CredentialStatus status;
    }

    /**
     * @notice A credential result as submitted by an authorized Chainlink workflow.
     * @dev `ccid` is redundant with the other fields by design: {CredentialBridge}
     *      recomputes it and rejects the result on mismatch, so a workflow cannot
     *      bind a valid provider result to the wrong subject commitment.
     *
     *      Note the absence of any holder field. The subject enters only as a
     *      pre-hashed commitment, so the bridge can verify binding without ever
     *      seeing or storing the underlying identity.
     */
    struct CredentialResult {
        bytes32 ccid;
        bytes32 credentialType;
        uint32 schemaVersion;
        bytes32 providerId;
        bytes32 subjectCommitment;
        bytes32 evidenceHash;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 nonce;
        uint64[] destinationChainSelectors;
    }

    /**
     * @notice Cross-chain replication metadata.
     * @dev Kept out of {CredentialRecord} so that struct matches the engineering
     *      spec exactly while destination freshness remains first-class.
     * @param isReplica True when this chain learned of the credential via CCIP
     *        rather than being the source of truth.
     * @param sourceChainSelector CCIP selector of the chain that sent the state.
     * @param lastUpdatedAt Timestamp of the last accepted propagation.
     * @param lastSourceNonce Highest source nonce accepted, for replay defence.
     */
    struct PropagationState {
        bool isReplica;
        uint64 sourceChainSelector;
        uint64 lastUpdatedAt;
        uint64 lastSourceNonce;
    }

    /**
     * @notice An integrator's access requirement, evaluated by {PolicyManagerAdapter}.
     * @param credentialType Required schema family.
     * @param schemaVersion Required schema version (0 = any supported version).
     * @param acceptedProviders Providers this integrator trusts; empty means "any
     *        provider the schema accepts".
     * @param maxAgeSeconds Maximum acceptable replica age. Only meaningful when
     *        the record arrived via propagation.
     * @param requireFresh Reject replicas whose propagated state is older than
     *        `maxAgeSeconds`. A source-of-truth record is never rejected for age
     *        beyond `expiresAt`.
     */
    struct CredentialRequirement {
        bytes32 credentialType;
        uint32 schemaVersion;
        bytes32[] acceptedProviders;
        uint64 maxAgeSeconds;
        bool requireFresh;
    }

    // ---------------------------------------------------------------------
    // Reason codes
    // ---------------------------------------------------------------------

    /// @notice Access granted.
    bytes32 internal constant REASON_OK = keccak256("OK");

    /// @notice No record exists for this CCID.
    bytes32 internal constant REASON_UNKNOWN = keccak256("UNKNOWN");

    /// @notice Verification started but has not completed.
    bytes32 internal constant REASON_PENDING = keccak256("PENDING");

    /// @notice Past `expiresAt`, or explicitly expired.
    bytes32 internal constant REASON_EXPIRED = keccak256("EXPIRED");

    /// @notice Temporarily blocked by the issuer.
    bytes32 internal constant REASON_SUSPENDED = keccak256("SUSPENDED");

    /// @notice Permanently withdrawn.
    bytes32 internal constant REASON_REVOKED = keccak256("REVOKED");

    /// @notice Under dispute; treated as a denial until resolved.
    bytes32 internal constant REASON_DISPUTED = keccak256("DISPUTED");

    /// @notice Issuing or attesting provider is not currently Active.
    bytes32 internal constant REASON_PROVIDER_PAUSED = keccak256("PROVIDER_PAUSED");

    /// @notice Schema is unknown or deprecated on this chain.
    bytes32 internal constant REASON_SCHEMA_UNSUPPORTED = keccak256("SCHEMA_UNSUPPORTED");

    /// @notice Replicated state is older than the integrator will accept.
    bytes32 internal constant REASON_STALE_DESTINATION = keccak256("STALE_DESTINATION");

    // --- Additional codes (the spec requires the nine above, not only those) ---

    /// @notice Credential type does not match the requirement.
    bytes32 internal constant REASON_CREDENTIAL_TYPE_MISMATCH = keccak256("CREDENTIAL_TYPE_MISMATCH");

    /// @notice Schema version does not match the requirement.
    bytes32 internal constant REASON_SCHEMA_VERSION_UNSUPPORTED = keccak256("SCHEMA_VERSION_UNSUPPORTED");

    /// @notice Provider is not in the integrator's accepted set.
    bytes32 internal constant REASON_PROVIDER_NOT_ACCEPTED = keccak256("PROVIDER_NOT_ACCEPTED");

    /// @notice System is paused; no decision can be trusted.
    bytes32 internal constant REASON_SYSTEM_PAUSED = keccak256("SYSTEM_PAUSED");

    /**
     * @notice True when `code` denotes an allow decision.
     * @dev Only {REASON_OK} allows. There is no path by which a non-`Valid`
     *      credential, a paused provider, or stale replica state can produce
     *      `true`, which is the "unsafe defaults are hard" requirement.
     */
    function isAllow(bytes32 code) internal pure returns (bool) {
        return code == REASON_OK;
    }

    /**
     * @notice Human-readable form of a reason code, for events, logs, and SDKs.
     * @dev Provided so tooling never has to hardcode the mapping. Unknown values
     *      render as `UNRECOGNIZED` rather than reverting, so a newer contract
     *      cannot brick an older SDK's logging path.
     */
    function reasonToString(bytes32 code) internal pure returns (string memory) {
        bytes32[13] memory codes = [
            REASON_OK,
            REASON_UNKNOWN,
            REASON_PENDING,
            REASON_EXPIRED,
            REASON_SUSPENDED,
            REASON_REVOKED,
            REASON_DISPUTED,
            REASON_PROVIDER_PAUSED,
            REASON_SCHEMA_UNSUPPORTED,
            REASON_STALE_DESTINATION,
            REASON_CREDENTIAL_TYPE_MISMATCH,
            REASON_SCHEMA_VERSION_UNSUPPORTED,
            REASON_PROVIDER_NOT_ACCEPTED
        ];
        string[13] memory names = [
            "OK",
            "UNKNOWN",
            "PENDING",
            "EXPIRED",
            "SUSPENDED",
            "REVOKED",
            "DISPUTED",
            "PROVIDER_PAUSED",
            "SCHEMA_UNSUPPORTED",
            "STALE_DESTINATION",
            "CREDENTIAL_TYPE_MISMATCH",
            "SCHEMA_VERSION_UNSUPPORTED",
            "PROVIDER_NOT_ACCEPTED"
        ];
        for (uint256 i = 0; i < codes.length; ++i) {
            if (codes[i] == code) return names[i];
        }
        return "UNRECOGNIZED";
    }
}
