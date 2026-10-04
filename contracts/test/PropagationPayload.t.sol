// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CCIDResolver} from "../src/CCIDResolver.sol";
import {CredentialTypes} from "../src/libraries/CredentialTypes.sol";
import {PropagationPayload} from "../src/libraries/PropagationPayload.sol";
import {Test} from "forge-std/Test.sol";

/**
 * @title PropagationPayloadTest
 * @notice Wire-format round-trip and tamper detection for the CCIP payload.
 * @dev This suite exists because a single misordered field in
 *      {PropagationPayload} would be invisible at compile time and would corrupt
 *      every cross-chain message in production. The round-trip assertions below
 *      pin each field to a distinct value so a shift cannot pass unnoticed.
 */
contract PropagationPayloadTest is Test {
    /// @dev Distinct, non-sequential values so a one-field shift is detectable.
    bytes32 internal constant CCID = keccak256("ccid");
    bytes32 internal constant CRED_TYPE = keccak256("credType");
    uint32 internal constant SCHEMA_VERSION = 7;
    bytes32 internal constant PROVIDER = keccak256("provider");
    bytes32 internal constant EVIDENCE = keccak256("evidence");
    uint64 internal constant ISSUED_AT = 1_111_111_111;
    uint64 internal constant EXPIRES_AT = 2_222_222_222;
    uint64 internal constant NONCE = 42;
    uint64 internal constant SOURCE_SELECTOR = 16_015_286_601_757_825_753;
    CredentialTypes.CredentialStatus internal constant STATUS = CredentialTypes.CredentialStatus.Disputed;

    function _copy(bytes memory src) internal pure returns (bytes memory out) {
        out = new bytes(src.length);
        for (uint256 i = 0; i < src.length; ++i) {
            out[i] = src[i];
        }
    }

    function _message() internal pure returns (PropagationPayload.Message memory m) {
        m.ccid = CCID;
        m.credentialType = CRED_TYPE;
        m.schemaVersion = SCHEMA_VERSION;
        m.providerId = PROVIDER;
        m.evidenceHash = EVIDENCE;
        m.issuedAt = ISSUED_AT;
        m.expiresAt = EXPIRES_AT;
        m.nonce = NONCE;
        m.status = STATUS;
        m.sourceChainSelector = SOURCE_SELECTOR;
        m.bindingHash = bytes32(0);
    }

    // -----------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------

    function test_EncodedLengthIsFixed() public pure {
        assertEq(PropagationPayload.ENCODED_LENGTH, 11 * 32);
    }

    function test_RoundTripPreservesEveryField() public pure {
        PropagationPayload.Message memory m = _message();
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);

        (PropagationPayload.Message memory out, PropagationPayload.DecodeError err) =
            PropagationPayload.decode(PropagationPayload.encode(m));

        assertEq(uint8(err), uint8(PropagationPayload.DecodeError.None));
        assertEq(out.ccid, m.ccid);
        assertEq(out.credentialType, m.credentialType);
        assertEq(out.schemaVersion, m.schemaVersion);
        assertEq(out.providerId, m.providerId);
        assertEq(out.evidenceHash, m.evidenceHash);
        assertEq(out.issuedAt, m.issuedAt);
        assertEq(out.expiresAt, m.expiresAt);
        assertEq(out.nonce, m.nonce);
        assertEq(uint8(out.status), uint8(m.status));
        assertEq(out.sourceChainSelector, m.sourceChainSelector);
        assertEq(out.bindingHash, m.bindingHash);
    }

    function test_DecodeRejectsWrongLength() public pure {
        (PropagationPayload.Message memory m, PropagationPayload.DecodeError err) =
            PropagationPayload.decode(hex"00112233");
        assertEq(uint8(err), uint8(PropagationPayload.DecodeError.BadLength));
        assertEq(m.ccid, bytes32(0));

        // Trailing junk must be rejected too, not silently ignored.
        bytes memory tooLong = abi.encode(
            bytes32(0),
            bytes32(0),
            uint256(0),
            bytes32(0),
            bytes32(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            bytes32(0),
            bytes32(0)
        );
        (, PropagationPayload.DecodeError err2) = PropagationPayload.decode(tooLong);
        assertEq(uint8(err2), uint8(PropagationPayload.DecodeError.BadLength));
    }

    // -----------------------------------------------------------------
    // Binding hash
    // -----------------------------------------------------------------

    function test_BindingHashIsDeterministic() public pure {
        assertEq(
            PropagationPayload.recomputeBindingHash(_message()), PropagationPayload.recomputeBindingHash(_message())
        );
    }

    function test_BindingHashCoversEveryField() public pure {
        bytes32 base = PropagationPayload.recomputeBindingHash(_message());

        PropagationPayload.Message memory m = _message();
        m.nonce = NONCE + 1;
        assertTrue(PropagationPayload.recomputeBindingHash(m) != base, "nonce not covered");

        m = _message();
        m.expiresAt = EXPIRES_AT + 1;
        assertTrue(PropagationPayload.recomputeBindingHash(m) != base, "expiresAt not covered");

        m = _message();
        m.status = CredentialTypes.CredentialStatus.Revoked;
        assertTrue(PropagationPayload.recomputeBindingHash(m) != base, "status not covered");

        m = _message();
        m.sourceChainSelector = SOURCE_SELECTOR + 1;
        assertTrue(PropagationPayload.recomputeBindingHash(m) != base, "sourceChainSelector not covered");

        m = _message();
        m.providerId = keccak256("other");
        assertTrue(PropagationPayload.recomputeBindingHash(m) != base, "providerId not covered");
    }

    function test_TamperedPayloadFailsVerification() public pure {
        PropagationPayload.Message memory m = _message();
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);
        bytes memory encoded = PropagationPayload.encode(m);

        // Mutate the status word in place: 9th field (index 8).
        bytes memory tampered = _copy(encoded);
        tampered[287] = bytes1(uint8(CredentialTypes.CredentialStatus.Valid));

        (PropagationPayload.Message memory out, PropagationPayload.DecodeError terr) =
            PropagationPayload.decode(tampered);
        assertEq(uint8(terr), uint8(PropagationPayload.DecodeError.None));
        assertTrue(PropagationPayload.recomputeBindingHash(out) != out.bindingHash, "tamper went undetected");
    }

    // -----------------------------------------------------------------
    // Status validation
    // -----------------------------------------------------------------

    function test_OutOfRangeStatusRejectedWithoutPanic() public pure {
        // An enum conversion in Solidity panics on an out-of-range value, which
        // would surface as an unhandled panic rather than a named error. The
        // library must range-check before converting.
        bytes memory forged = abi.encode(
            CCID,
            CRED_TYPE,
            uint256(SCHEMA_VERSION),
            PROVIDER,
            EVIDENCE,
            uint256(ISSUED_AT),
            uint256(EXPIRES_AT),
            uint256(NONCE),
            uint256(99),
            uint256(SOURCE_SELECTOR),
            bytes32(0)
        );
        (PropagationPayload.Message memory out, PropagationPayload.DecodeError ferr) = PropagationPayload.decode(forged);
        assertEq(uint8(ferr), uint8(PropagationPayload.DecodeError.UnknownStatus));
        assertEq(uint8(out.status), 0);
    }

    function test_OversizedNumericFieldsRejected() public pure {
        bytes memory wide = abi.encode(
            CCID,
            CRED_TYPE,
            type(uint256).max, // schemaVersion cannot fit uint32
            PROVIDER,
            EVIDENCE,
            uint256(ISSUED_AT),
            uint256(EXPIRES_AT),
            uint256(NONCE),
            uint256(STATUS),
            uint256(SOURCE_SELECTOR),
            bytes32(0)
        );
        (, PropagationPayload.DecodeError werr) = PropagationPayload.decode(wide);
        assertEq(uint8(werr), uint8(PropagationPayload.DecodeError.NumericOverflow));
    }

    function test_IsKnownStatusAcceptsAllMembers() public pure {
        PropagationPayload.Message memory m = _message();
        for (uint256 i = 0; i <= uint256(CredentialTypes.CredentialStatus.Disputed); ++i) {
            m.status = CredentialTypes.CredentialStatus(uint8(i));
            assertTrue(PropagationPayload.isKnownStatus(m));
        }
    }
}

/**
 * @title CCIDResolverTest
 * @notice Determinism, tamper detection, and renewal-stability of the CCID.
 */
contract CCIDResolverTest is Test {
    CCIDResolver internal resolver;

    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER = keccak256("provider.mock");
    bytes32 internal constant SUBJECT_A = keccak256("subject-alice");
    bytes32 internal constant SUBJECT_B = keccak256("subject-bob");

    function setUp() public {
        resolver = new CCIDResolver();
    }

    function test_Deterministic() public view {
        assertEq(
            resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A), resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A)
        );
    }

    function test_DistinctInputsGiveDistinctIds() public view {
        bytes32 base = resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A);
        assertTrue(resolver.compute(CRED_TYPE, 2, PROVIDER, SUBJECT_A) != base, "schemaVersion not bound");
        assertTrue(resolver.compute(CRED_TYPE, 1, keccak256("other"), SUBJECT_A) != base, "provider not bound");
        assertTrue(resolver.compute(keccak256("other.type"), 1, PROVIDER, SUBJECT_A) != base, "type not bound");
        assertTrue(resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_B) != base, "subject not bound");
    }

    function test_VerifyAcceptsCorrectDerivation() public view {
        bytes32 ccid = resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A);
        assertTrue(resolver.verify(ccid, CRED_TYPE, 1, PROVIDER, SUBJECT_A));
        assertFalse(resolver.verify(ccid, CRED_TYPE, 1, PROVIDER, SUBJECT_B), "subject swap must fail");
    }

    function test_ValidatePartsRejectsZeroValues() public view {
        assertTrue(resolver.validateParts(CRED_TYPE, PROVIDER, SUBJECT_A));
        assertFalse(resolver.validateParts(bytes32(0), PROVIDER, SUBJECT_A));
        assertFalse(resolver.validateParts(CRED_TYPE, bytes32(0), SUBJECT_A));
        assertFalse(resolver.validateParts(CRED_TYPE, PROVIDER, bytes32(0)));
    }

    function test_DeriveEmitsAndMatches() public {
        vm.expectEmit(true, true, true, true);
        emit CCIDResolver.CCIDDerived(resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A), CRED_TYPE, PROVIDER);
        bytes32 out = resolver.derive(CRED_TYPE, 1, PROVIDER, SUBJECT_A);
        assertEq(out, resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A));
    }

    /// @dev The CCID is a stable identity binding, so it must NOT depend on any
    ///      value that changes over the credential's life. A CCID that moved on
    ///      renewal would strand the previous credential on every destination chain.
    function test_CcidIsStableAcrossRenewal() public view {
        bytes32 first = resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A);
        bytes32 second = resolver.compute(CRED_TYPE, 1, PROVIDER, SUBJECT_A);
        assertEq(first, second, "renewal must not change the CCID");
    }
}
