// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialTypes} from "./CredentialTypes.sol";

/**
 * @title PropagationPayload
 * @notice The single definition of the cross-chain credential message, shared by
 *         {CrossChainCredentialSender} and {CrossChainCredentialReceiver}.
 *
 * @dev ## Why this library exists
 *
 *      Sender and receiver must agree byte-for-byte on the wire format. When that
 *      format lives in two contracts it drifts: a field is added on one side and
 *      the other silently mis-decodes, or `abi.decode` reverts deep inside a
 *      callback where the failure is hard to attribute. Defining it once removes
 *      that entire failure mode.
 *
 *      ## What is deliberately absent
 *
 *      `subjectCommitment` is NOT in the payload. The destination never needs it:
 *      the CCID already binds the credential to its holder, and shipping the
 *      commitment would publish a second, correlatable value per holder on every
 *      destination chain for no functional gain.
 *
 *      ## Integrity: `bindingHash`
 *
 *      The receiver cannot re-derive the CCID, because doing so would require
 *      `subjectCommitment` - which is exactly what we refuse to transmit. So
 *      integrity is established differently: the sender commits to the message
 *      contents with {bindingHash}, and the receiver recomputes it and rejects any
 *      mismatch.
 *
 *      Together with the router check, the sender allowlist, and strictly
 *      increasing nonces, that gives the destination three independent facts:
 *      the message came through CCIP, from a permitted sender, and describes
 *      exactly the CCID and state it claims to. None of them requires the
 *      destination to hold any holder-identifying material.
 */
library PropagationPayload {
    /// @notice Domain separator for the binding hash. Versioned independently of
    ///         the CCID domain because this covers message framing, not identity.
    bytes32 internal constant PAYLOAD_DOMAIN = keccak256("identity-bridge-zktls/propagation/v1");

    /// @notice The decoded propagation message.
    struct Message {
        bytes32 ccid;
        bytes32 credentialType;
        uint32 schemaVersion;
        bytes32 providerId;
        bytes32 evidenceHash;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 nonce;
        CredentialTypes.CredentialStatus status;
        uint64 sourceChainSelector;
        bytes32 bindingHash;
    }

    /**
     * @notice Commit to a message's contents.
     * @dev Covers every field that carries meaning, plus the domain. The sender
     *      stores the result in {Message.bindingHash}; the receiver recomputes it.
     */
    function computeBindingHash(
        bytes32 ccid,
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce,
        CredentialTypes.CredentialStatus status,
        uint64 sourceChainSelector
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PAYLOAD_DOMAIN,
                ccid,
                credentialType,
                uint256(schemaVersion),
                providerId,
                evidenceHash,
                issuedAt,
                expiresAt,
                nonce,
                uint8(status),
                sourceChainSelector
            )
        );
    }

    /// @notice Recompute a received message's binding hash for comparison.
    function recomputeBindingHash(Message memory m) internal pure returns (bytes32) {
        return computeBindingHash(
            m.ccid,
            m.credentialType,
            m.schemaVersion,
            m.providerId,
            m.evidenceHash,
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            m.status,
            m.sourceChainSelector
        );
    }

    /// @notice ABI-encode a message for CCIP transport.
    function encode(Message memory m) internal pure returns (bytes memory) {
        return abi.encode(
            m.ccid,
            m.credentialType,
            m.schemaVersion,
            m.providerId,
            m.evidenceHash,
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            uint8(m.status),
            m.sourceChainSelector,
            m.bindingHash
        );
    }

    /// @notice Encoded length of a message: 11 static 32-byte words.
    uint256 internal constant ENCODED_LENGTH = 352;

    /**
     * @notice Why a payload failed to decode.
     * @dev Distinguished rather than collapsed into a boolean so the receiver can
     *      report `MalformedPayload` for a bad length and `UnknownStatus` for an
     *      out-of-range enum. Those are different operational problems - a
     *      truncated message suggests a version mismatch, an unknown status
     *      suggests a sender bug - and operators act on them differently.
     */
    enum DecodeError {
        None,
        BadLength,
        NumericOverflow,
        UnknownStatus
    }

    /**
     * @notice ABI-decode and structurally validate a message.
     * @dev Takes `bytes memory` rather than `calldata` so one implementation
     *      serves the receiver (calldata) and off-chain/test callers (memory).
     *
     *      Returns a zeroed message plus a reason instead of reverting, so the
     *      caller can raise a precisely named error. A truncated payload
     *      surfaces as a named error rather than an opaque ABI revert from deep
     *      inside a CCIP callback, where attribution is difficult.
     *
     *      The length guard is what makes the single tuple decode safe: `abi.decode`
     *      of an all-static tuple requires an exact byte length, and a longer
     *      buffer would otherwise be silently accepted with trailing junk.
     */
    function decode(bytes memory data) internal pure returns (Message memory m, DecodeError err) {
        if (data.length != ENCODED_LENGTH) return (m, DecodeError.BadLength);

        uint256 schemaVersionRaw;
        uint256 issuedAtRaw;
        uint256 expiresAtRaw;
        uint256 nonceRaw;
        uint256 statusRaw;
        uint256 sourceChainRaw;

        (
            m.ccid,
            m.credentialType,
            schemaVersionRaw,
            m.providerId,
            m.evidenceHash,
            issuedAtRaw,
            expiresAtRaw,
            nonceRaw,
            statusRaw,
            sourceChainRaw,
            m.bindingHash
        ) =
            abi.decode(
                data,
                (bytes32, bytes32, uint256, bytes32, bytes32, uint256, uint256, uint256, uint256, uint256, bytes32)
            );

        // The status range check MUST precede the enum conversion: Solidity panics
        // on an out-of-range enum conversion, which would turn malformed input into
        // an unhandled panic rather than a named, actionable error.
        if (statusRaw > uint256(CredentialTypes.CredentialStatus.Disputed)) {
            return (m, DecodeError.UnknownStatus);
        }

        // Narrowing is bounded explicitly, so a maliciously wide word cannot wrap
        // into a small plausible value.
        if (schemaVersionRaw > type(uint32).max) return (m, DecodeError.NumericOverflow);
        if (issuedAtRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (expiresAtRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (nonceRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);
        if (sourceChainRaw > type(uint64).max) return (m, DecodeError.NumericOverflow);

        m.schemaVersion = uint32(schemaVersionRaw);
        m.issuedAt = uint64(issuedAtRaw);
        m.expiresAt = uint64(expiresAtRaw);
        m.nonce = uint64(nonceRaw);
        m.status = CredentialTypes.CredentialStatus(uint8(statusRaw));
        m.sourceChainSelector = uint64(sourceChainRaw);

        err = DecodeError.None;
    }

    /// @notice True when the payload's declared status is a legal enum member.
    function isKnownStatus(Message memory m) internal pure returns (bool) {
        return uint256(m.status) <= uint256(CredentialTypes.CredentialStatus.Disputed);
    }
}
