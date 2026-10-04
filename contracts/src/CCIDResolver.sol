// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title CCIDResolver
 * @notice Derives and verifies credential content identifiers (CCIDs).
 *
 * @dev ## What a CCID is
 *
 *      A CCID is a credential's **identity binding**: "this proof of this attribute,
 *      produced by this provider, under this schema, belongs to this holder". It is
 *      deliberately *not* a version counter.
 *
 *      Renewal and re-issuance therefore yield the **same** CCID with a higher
 *      nonce. That matters for more than tidiness: a CCID is the key integrators
 *      and holders store, and it is the value propagated across chains. If renewal
 *      produced a new one, every renewal would strand the holder's previous
 *      credential on every destination chain as a dangling, still-`Valid` record -
 *      the credential would look alive forever because nothing can ever revoke it
 *      by its new name.
 *
 *      The replay counter is `nonce`, which lives on the record and must strictly
 *      increase. Keeping the two concerns separate is what makes both correct.
 *
 * @dev ## Why this contract exists
 *
 *      `ENGINEERING_SPEC.md` lists `CCIDResolver.sol` in the target tree but
 *      assigns it no responsibilities. Rather than ship an empty file, this
 *      implementation gives it the one job the rest of the system actually
 *      needs: **proving that a credential is bound to the subject it claims**,
 *      without ever seeing the subject.
 *
 *      ## The problem it solves
 *
 *      A workflow submits a credential result naming a holder. If the CCID were
 *      simply an opaque identifier the workflow chose, a compromised or buggy
 *      workflow could attach a genuine provider result to the wrong holder. The
 *      bridge would have no way to notice, because it would only be comparing
 *      one opaque value with another.
 *
 *      So the CCID is not opaque: it is a deterministic, domain-separated hash
 *      over every field that defines the credential's identity. {CredentialBridge}
 *      recomputes it from the submitted fields and rejects any mismatch. Tampering
 *      with the subject, provider, or schema changes the expected CCID, so the
 *      result is rejected.
 *
 *      ## Privacy model
 *
 *      The holder enters the hash only as `subjectCommitment`, which the workflow
 *      computes **off-chain** as a salted commitment to the verified identity
 *      (for example `keccak256(salt || verifiedAttribute)`). Because the salt never
 *      reaches the chain, the commitment is not reversible and not correlatable
 *      across issuers that choose different salts.
 *
 *      This contract cannot and does not compute commitments from raw identity
 *      data. There is deliberately no function that accepts a name, email, or
 *      document: the sensitive boundary is off-chain by construction, not by policy.
 */
contract CCIDResolver {
    /// @notice Domain separator, versioned so future CCID rules cannot collide with these.
    bytes32 public constant DOMAIN = keccak256("identity-bridge-zktls/CCID/v1");

    /// @notice Emitted whenever a CCID is successfully derived, for off-chain indexing.
    event CCIDDerived(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 indexed providerId);

    /**
     * @notice Deterministically derive the CCID for a credential.
     * @dev Field order is part of the protocol. Changing it changes every CCID,
     *      so the order below is frozen alongside `DOMAIN`.
     *
     *      `nonce` is intentionally absent - see the contract docs.
     * @param credentialType Schema family of the credential.
     * @param schemaVersion Schema version the result was evaluated against.
     * @param providerId Adapter that produced the verification.
     * @param subjectCommitment Salted, one-way commitment to the verified holder.
     *        Must not be a raw identifier.
     * @return ccid The derived content identifier, stable across renewals.
     */
    function compute(bytes32 credentialType, uint32 schemaVersion, bytes32 providerId, bytes32 subjectCommitment)
        public
        pure
        returns (bytes32 ccid)
    {
        // abi.encode with explicit uint256 widening: pack() would silently
        // truncate the uint32 and let two distinct inputs collide.
        ccid = keccak256(abi.encode(DOMAIN, credentialType, uint256(schemaVersion), providerId, subjectCommitment));
    }

    /**
     * @notice Derive and emit in one call, for use inside transactions that mint a CCID.
     * @dev Kept separate from {compute} so that pure derivation stays free of
     *      side effects and is trivially reproducible off-chain.
     */
    function derive(bytes32 credentialType, uint32 schemaVersion, bytes32 providerId, bytes32 subjectCommitment)
        external
        returns (bytes32 ccid)
    {
        ccid = compute(credentialType, schemaVersion, providerId, subjectCommitment);
        emit CCIDDerived(ccid, credentialType, providerId);
    }

    /**
     * @notice Check a claimed CCID against the fields it must be derived from.
     * @dev This is the anti-tampering primitive. A result whose `ccid` does not
     *      reproduce from its own fields is rejected by {CredentialBridge}.
     * @return ok True when `ccid` is the correct derivation.
     */
    function verify(
        bytes32 ccid,
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        bytes32 subjectCommitment
    ) external pure returns (bool ok) {
        ok = ccid == compute(credentialType, schemaVersion, providerId, subjectCommitment);
    }

    /**
     * @notice Structural validation of the parts that go into a CCID.
     * @dev Cheap guard against empty or zero-value fields reaching storage. A zero
     *      `subjectCommitment` would make the credential unbound, which is worse
     *      than not having issued it at all.
     */
    function validateParts(bytes32 credentialType, bytes32 providerId, bytes32 subjectCommitment)
        external
        pure
        returns (bool ok)
    {
        ok = credentialType != bytes32(0) && providerId != bytes32(0) && subjectCommitment != bytes32(0);
    }
}
