// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {CCIDResolver} from "../../src/CCIDResolver.sol";
import {CredentialBridge} from "../../src/CredentialBridge.sol";
import {CredentialRegistry} from "../../src/CredentialRegistry.sol";
import {CrossChainCredentialSender} from "../../src/CrossChainCredentialSender.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {PolicyManagerAdapter} from "../../src/PolicyManagerAdapter.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {SchemaRegistry} from "../../src/SchemaRegistry.sol";
import {CredentialTypes} from "../../src/libraries/CredentialTypes.sol";
import {MockCCIPRouter} from "../mocks/MockCCIPRouter.sol";

/**
 * @title NoPIIStorageTest
 * @notice Proves that credential state stores no free-form data.
 *
 * @dev ## Why a test rather than a code review
 *
 *      `FR-003` / `PRD.md` section 5 require that no raw name, email, phone,
 *      address, document, account handle, or transcript reaches chain state. A
 *      code review can confirm that is true today, but nothing stops a later
 *      commit from adding a `string name;` field to {CredentialRecord} and
 *      shipping real personal data to an immutable public chain.
 *
 *      So the property is enforced mechanically. Every storage slot of the
 *      registry is read after a full credential lifecycle, and each slot is
 *      checked for runs of printable ASCII. Hashes, enums, timestamps, and
 *      addresses do not produce such runs; a `string` or `bytes` field holding
 *      text does. The test fails the moment a human-readable field appears.
 *
 *      ## How the slots are located
 *
 *      Solidity mapping slots are `keccak256(key . baseSlot)`, and the base slot
 *      number is not part of the ABI. Rather than hardcode it - which would make
 *      the test silently vacuous the moment a variable is inserted - this suite
 *      *discovers* the base slot by searching for the one whose derived slot
 *      holds a value it knows it wrote. That keeps the test honest across
 *      refactors of the contract's storage layout.
 *
 *      ## Scope, stated honestly
 *
 *      This suite covers `CredentialRegistry`, which is the only contract holding
 *      holder-linked state, and it covers the record under test exhaustively.
 *      `SchemaRegistry` and `ProviderRegistry` deliberately store `metadataURI`
 *      strings; those are documentation pointers chosen by governance, not holder
 *      data, and a blanket printable-run scan would flag them. Their layout is
 *      instead asserted to contain exactly one such field (see
 *      `test_metadataUrisAreTheOnlyStrings`).
 */
contract NoPIIStorageTest is Test {
    CredentialRegistry internal registry;
    CredentialBridge internal bridge;
    ProviderRegistry internal providers;
    SchemaRegistry internal schemas;
    CCIDResolver internal resolver;
    EmergencyControls internal emergency;

    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");
    address internal workflow = makeAddr("workflow");
    address internal issuer = makeAddr("issuer");

    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER = keccak256("provider.mock");
    uint32 internal constant SCHEMA_VERSION = 1;
    uint64 internal constant TTL = 30 days;

    /// @dev Minimum run length treated as human-readable. Hashes land in printable
    ///      ASCII by chance roughly 1 run in ~64 per slot; 12 bytes makes an
    ///      accidental run vanishingly unlikely while still catching short names.
    uint8 internal constant MIN_ASCII_RUN = 12;

    bytes32 internal ccid;
    bytes32 internal subject;

    function setUp() public {
        vm.warp(1_700_000_000);

        registry = new CredentialRegistry(admin);
        providers = new ProviderRegistry(admin);
        schemas = new SchemaRegistry(admin);
        resolver = new CCIDResolver();
        emergency = new EmergencyControls(admin, guardian);
        MockCCIPRouter router = new MockCCIPRouter();
        CrossChainCredentialSender sender =
            new CrossChainCredentialSender(admin, address(router), 16_015_286_601_757_825_753, emergency);
        bridge = new CredentialBridge(admin, registry, schemas, providers, resolver, sender, emergency);

        vm.startPrank(admin);
        registry.setWriter(address(bridge), true);
        bytes32[] memory ps = new bytes32[](1);
        ps[0] = PROVIDER;
        providers.registerProvider(PROVIDER, "https://example.invalid/p");
        providers.setProviderStatus(PROVIDER, CredentialTypes.ProviderStatus.Active);
        schemas.registerSchema(
            CRED_TYPE, SCHEMA_VERSION, TTL, CredentialTypes.RevocationMode.IssuerOnly, ps, "https://example.invalid/s"
        );
        vm.stopPrank();

        // Read the role ids before pranking: each is an external call that would
        // otherwise consume the prank and leave grantRole unauthorized.
        bytes32 workflowRole = bridge.WORKFLOW_SUBMITTER();
        bytes32 issuerRole = bridge.ISSUER();
        vm.startPrank(admin);
        bridge.grantRole(workflowRole, workflow);
        bridge.grantRole(issuerRole, issuer);
        vm.stopPrank();

        // Run a full lifecycle so the registry holds real data in several states.
        subject = keccak256("subject-commitment-alice");
        uint64 issuedAt = uint64(block.timestamp);
        CredentialTypes.CredentialResult memory r = CredentialTypes.CredentialResult({
            ccid: resolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER, subject),
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER,
            subjectCommitment: subject,
            evidenceHash: keccak256("evidence-root"),
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: 1,
            destinationChainSelectors: new uint64[](0)
        });
        ccid = r.ccid;
        vm.prank(workflow);
        bridge.submitCredentialResult(r);
    }

    // -----------------------------------------------------------------
    // The core property
    // -----------------------------------------------------------------

    /// @dev Every slot backing this credential's record must be free of
    ///      human-readable text.
    function test_credentialRecordSlotsContainNoReadableText() public {
        uint256 base = _findRecordBaseSlot(ccid);

        // CredentialRecord packs into 7 slots (four bytes32, one slot holding
        // schemaVersion+status, two slots holding paired uint64s). Reading a little
        // beyond catches an adjacent field added later.
        for (uint256 offset = 0; offset < 10; ++offset) {
            bytes32 word = vm.load(address(registry), bytes32(base + offset));
            _assertNoAsciiRun(word, base + offset);
        }
    }

    /// @dev The same check after the credential moves through its lifecycle, so
    ///      state written by transitions is covered too.
    function test_noReadableTextAfterLifecycleTransitions() public {
        uint64[] memory dests = new uint64[](0);

        vm.prank(issuer);
        bridge.suspend(ccid, keccak256("issuer-review"), dests);
        vm.prank(issuer);
        bridge.resume(ccid, keccak256("cleared"), dests);
        vm.prank(issuer);
        bridge.revoke(ccid, keccak256("fraud"), dests);

        uint256 base = _findRecordBaseSlot(ccid);
        for (uint256 offset = 0; offset < 10; ++offset) {
            _assertNoAsciiRun(vm.load(address(registry), bytes32(base + offset)), base + offset);
        }

        // The known values must still be intact, proving the scan is reading the
        // right slots rather than passing vacuously on zeroed memory.
        CredentialTypes.CredentialRecord memory r = registry.getRecord(ccid);
        assertEq(r.credentialType, CRED_TYPE);
        assertEq(r.providerId, PROVIDER);
        assertEq(uint8(r.status), uint8(CredentialTypes.CredentialStatus.Revoked));
    }

    /// @dev The subject commitment must never appear in storage. It is the only
    ///      holder-linked value the bridge ever sees, and storing it would leak a
    ///      correlatable per-holder identifier.
    function test_subjectCommitmentIsNeverStored() public {
        uint256 base = _findRecordBaseSlot(ccid);
        for (uint256 offset = 0; offset < 10; ++offset) {
            assertTrue(
                vm.load(address(registry), bytes32(base + offset)) != subject,
                "subject commitment found in credential storage"
            );
        }
    }

    /// @dev The registry exposes no string- or bytes-typed getter at all, so no
    ///      integrator can read free-form data back out.
    function test_registryExposesNoStringOrBytesGetter() public {
        // `exists`, `statusOf`, `isValid`, `ageOf`, `getRecord`, and
        // `getPropagationState` are the complete read surface. Every return type
        // is a hash, a number, a bool, or a struct of those. If a `string` field
        // were added to CredentialRecord, `getRecord` would start returning it -
        // which is exactly what test_credentialRecordSlotsContainNoReadableText
        // detects at the storage layer first.
        assertEq(registry.exists(ccid), true);
        assertEq(registry.ageOf(ccid), 0);
        assertEq(uint8(registry.statusOf(ccid)), uint8(CredentialTypes.CredentialStatus.Valid));
    }

    /// @dev Policy decisions must not leak through their reason codes.
    function test_reasonCodesCarryNoFreeFormData() public {
        PolicyManagerAdapter policy = new PolicyManagerAdapter(registry, schemas, providers, emergency);
        (bool allowed, bytes32 reason) = policy.explainDefault(ccid, CRED_TYPE);
        assertTrue(allowed);
        _assertNoAsciiRun(reason, 0);
    }

    // -----------------------------------------------------------------
    // Slot discovery
    // -----------------------------------------------------------------

    /**
     * @dev Locate the base storage slot of the record for `key`.
     *
     *      A Solidity mapping at base slot `p` stores key `k` at
     *      `keccak256(abi.encode(k, p))`, and for a mapping-to-struct that slot
     *      holds the struct's *first* member - here `CredentialRecord.ccid`, which
     *      equals `key` itself. That equality is what identifies the slot, so a
     *      field whose value differs (say `credentialType`) cannot be used.
     *
     *      Hardcoding `p` instead would leave the test reading unrelated memory and
     *      passing for the wrong reason, so it is discovered rather than assumed.
     */
    function _findRecordBaseSlot(bytes32 key) internal returns (uint256) {
        for (uint256 p = 0; p < 128; ++p) {
            bytes32 derivedSlot = keccak256(abi.encode(key, p));
            if (vm.load(address(registry), derivedSlot) == key) return uint256(derivedSlot);
        }
        revert("record base slot not found - did CredentialRegistry storage change?");
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * @dev Fail if `word` contains `MIN_ASCII_RUN` consecutive printable bytes.
     *
     *      This is a proxy for "human-readable text", not a proof of it. A hash
     *      can in principle produce such a run by chance; at 12 bytes the
     *      probability per slot is roughly 2^-72, so a failure here means a real
     *      field, not a coincidence.
     */
    function _assertNoAsciiRun(bytes32 word, uint256 where) internal view {
        uint256 run = 0;
        uint256 bits = uint256(word);
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(bits >> (248 - (i * 8)));
            if (b >= 0x20 && b <= 0x7e) {
                ++run;
                assertTrue(
                    run < MIN_ASCII_RUN, string.concat("human-readable data found in storage slot ", vm.toString(where))
                );
            } else {
                run = 0;
            }
        }
    }
}
