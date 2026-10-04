// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {CCIDResolver} from "../../src/CCIDResolver.sol";
import {CredentialBridge} from "../../src/CredentialBridge.sol";
import {CredentialRegistry} from "../../src/CredentialRegistry.sol";
import {CrossChainCredentialReceiver} from "../../src/CrossChainCredentialReceiver.sol";
import {CrossChainCredentialSender} from "../../src/CrossChainCredentialSender.sol";
import {EmergencyControls} from "../../src/EmergencyControls.sol";
import {PolicyManagerAdapter} from "../../src/PolicyManagerAdapter.sol";
import {ProviderRegistry} from "../../src/ProviderRegistry.sol";
import {SchemaRegistry} from "../../src/SchemaRegistry.sol";
import {CredentialTypes} from "../../src/libraries/CredentialTypes.sol";
import {PropagationPayload} from "../../src/libraries/PropagationPayload.sol";
import {MockCCIPRouter} from "../mocks/MockCCIPRouter.sol";

/**
 * @title CredentialTestBase
 * @notice Shared fixture deploying the full system and offering helpers for
 *         issuing, propagating, and asserting credentials.
 *
 * @dev ## Two-deployment topology
 *
 *      The harness deploys the system twice, as `source` (the issuing chain) and
 *      `dest` (a destination chain). They share a router address but have separate
 *      registries, which is what makes the replica rules testable: `dest` has no
 *      local issuer, so inbound state is genuinely a replica.
 *
 *      Tests that need a destination which is *also* an issuer for the same CCID
 *      deploy a third system and drive {CrossChainCredentialReceiver} directly.
 */
abstract contract CredentialTestBase is Test {
    // ---------------------------------------------------------------------
    // Actors
    // ---------------------------------------------------------------------
    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");
    address internal workflow = makeAddr("workflow");
    address internal issuer = makeAddr("issuer");
    address internal holder = makeAddr("holder");
    address internal outsider = makeAddr("outsider");
    address internal providerOperator = makeAddr("providerOperator");
    address internal sourceSender = makeAddr("sourceChainSender"); // bridge on the source chain
    address internal destSender = makeAddr("destChainSender");

    // ---------------------------------------------------------------------
    // Chain identifiers
    // ---------------------------------------------------------------------
    uint64 internal constant SOURCE_SELECTOR = 16_015_286_601_757_825_753;
    uint64 internal constant DEST_SELECTOR = 3_478_487_238_524_512_106;

    // ---------------------------------------------------------------------
    // System: source chain
    // ---------------------------------------------------------------------
    CredentialRegistry internal sourceRegistry;
    CredentialBridge internal sourceBridge;
    ProviderRegistry internal sourceProviders;
    SchemaRegistry internal sourceSchemas;
    CCIDResolver internal sourceResolver;
    EmergencyControls internal sourceEmergency;
    CrossChainCredentialSender internal sourceSenderContract;
    MockCCIPRouter internal router;

    // ---------------------------------------------------------------------
    // System: destination chain
    // ---------------------------------------------------------------------
    CredentialRegistry internal destRegistry;
    CrossChainCredentialReceiver internal destReceiver;
    ProviderRegistry internal destProviders;
    SchemaRegistry internal destSchemas;
    EmergencyControls internal destEmergency;
    CrossChainCredentialSender internal destSenderContract;
    CredentialBridge internal destBridge;

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------
    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER_A = keccak256("provider.mock-zktls");
    bytes32 internal constant PROVIDER_B = keccak256("provider.reclaim");
    bytes32 internal constant SUBJECT = keccak256("subject-commitment-alice");
    bytes32 internal constant EVIDENCE = keccak256("evidence-root");

    uint32 internal constant SCHEMA_VERSION = 1;
    uint64 internal constant TTL = 30 days;

    /// @dev Fixed starting timestamp so expiry arithmetic is deterministic.
    uint64 internal constant T0 = 1_700_000_000;

    function setUp() public virtual {
        vm.warp(T0);

        router = new MockCCIPRouter();

        // Deployment wiring below (bridge binding, writer grants) is admin-gated.
        vm.startPrank(admin);

        // --- Source chain ---
        sourceRegistry = new CredentialRegistry(admin);
        sourceProviders = new ProviderRegistry(admin);
        sourceSchemas = new SchemaRegistry(admin);
        sourceResolver = new CCIDResolver();
        sourceEmergency = new EmergencyControls(admin, guardian);

        // The sender is deployed first and bound to the bridge once the bridge
        // address exists, breaking the constructor cycle.
        sourceSenderContract = new CrossChainCredentialSender(admin, address(router), SOURCE_SELECTOR, sourceEmergency);

        sourceBridge = new CredentialBridge(
            admin, sourceRegistry, sourceSchemas, sourceProviders, sourceResolver, sourceSenderContract, sourceEmergency
        );

        sourceSenderContract.initializeBridge(address(sourceBridge));
        sourceRegistry.setWriter(address(sourceBridge), true);

        // --- Destination chain ---
        destRegistry = new CredentialRegistry(admin);
        destProviders = new ProviderRegistry(admin);
        destSchemas = new SchemaRegistry(admin);
        destEmergency = new EmergencyControls(admin, guardian);
        destSenderContract = new CrossChainCredentialSender(admin, address(router), DEST_SELECTOR, destEmergency);
        destBridge = new CredentialBridge(
            admin, destRegistry, destSchemas, destProviders, sourceResolver, destSenderContract, destEmergency
        );
        destSenderContract.initializeBridge(address(destBridge));

        destReceiver = new CrossChainCredentialReceiver(
            address(router), DEST_SELECTOR, admin, destRegistry, destSchemas, destProviders, destEmergency
        );
        destRegistry.setWriter(address(destReceiver), true);
        destRegistry.setWriter(address(destBridge), true);
        destReceiver.wire();
        destSelector = destReceiver.selector();

        // --- Roles ---
        // Still impersonating admin: grantRole is ADMIN-gated on the bridge, and
        // `admin` holds that role by construction.
        sourceBridge.grantRole(sourceBridge.WORKFLOW_SUBMITTER(), workflow);
        sourceBridge.grantRole(sourceBridge.ISSUER(), issuer);
        sourceBridge.grantRole(sourceBridge.HOLDER(), holder);

        // --- Registries populated identically on both chains ---
        _seedProvider(sourceProviders, PROVIDER_A);
        _seedProvider(destProviders, PROVIDER_A);
        _seedProvider(sourceProviders, PROVIDER_B);
        _seedProvider(destProviders, PROVIDER_B);

        _seedSchema(sourceSchemas, CRED_TYPE, PROVIDER_A);
        _seedSchema(destSchemas, CRED_TYPE, PROVIDER_A);

        // --- Cross-chain trust ---
        destReceiver.setAllowedSourceSender(address(sourceBridge), true);
        destReceiver.setAllowedSourceChain(SOURCE_SELECTOR, true);

        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // Seeding helpers
    // ---------------------------------------------------------------------

    function _seedProvider(ProviderRegistry providers, bytes32 providerId) internal {
        providers.registerProvider(providerId, "https://example.invalid/provider");
        providers.setProviderStatus(providerId, CredentialTypes.ProviderStatus.Active);
    }

    function _seedSchema(SchemaRegistry schemas, bytes32 credentialType, bytes32 providerId) internal {
        bytes32[] memory ps = new bytes32[](1);
        ps[0] = providerId;
        schemas.registerSchema(
            credentialType,
            SCHEMA_VERSION,
            TTL,
            CredentialTypes.RevocationMode.IssuerOnly,
            ps,
            "https://example.invalid/schema"
        );
    }

    // ---------------------------------------------------------------------
    // Result construction
    // ---------------------------------------------------------------------

    /// @dev Build a fully valid result for `subjectCommitment` at `nonce`.
    function _result(bytes32 subjectCommitment, uint64 nonce)
        internal
        view
        returns (CredentialTypes.CredentialResult memory)
    {
        uint64 issuedAt = uint64(block.timestamp);
        return CredentialTypes.CredentialResult({
            ccid: sourceResolver.compute(CRED_TYPE, SCHEMA_VERSION, PROVIDER_A, subjectCommitment),
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            providerId: PROVIDER_A,
            subjectCommitment: subjectCommitment,
            evidenceHash: EVIDENCE,
            issuedAt: issuedAt,
            expiresAt: issuedAt + TTL,
            nonce: nonce,
            destinationChainSelectors: new uint64[](0)
        });
    }

    function _resultWithDestinations(bytes32 subjectCommitment, uint64 nonce, uint64[] memory destinations)
        internal
        view
        returns (CredentialTypes.CredentialResult memory)
    {
        CredentialTypes.CredentialResult memory r = _result(subjectCommitment, nonce);
        r.destinationChainSelectors = destinations;
        return r;
    }

    /// @dev Issue a valid credential as the workflow, returning its CCID.
    function _issue(bytes32 subjectCommitment, uint64 nonce) internal returns (bytes32 ccid) {
        CredentialTypes.CredentialResult memory r = _result(subjectCommitment, nonce);
        vm.prank(workflow);
        sourceBridge.submitCredentialResult(r);
        return r.ccid;
    }

    // ---------------------------------------------------------------------
    // Requirement construction
    // ---------------------------------------------------------------------

    function _requirement() internal pure returns (CredentialTypes.CredentialRequirement memory) {
        return CredentialTypes.CredentialRequirement({
            credentialType: CRED_TYPE,
            schemaVersion: SCHEMA_VERSION,
            acceptedProviders: new bytes32[](0),
            maxAgeSeconds: 0,
            requireFresh: false
        });
    }

    function _requirementWithFreshness(uint64 maxAgeSeconds)
        internal
        pure
        returns (CredentialTypes.CredentialRequirement memory)
    {
        CredentialTypes.CredentialRequirement memory req = _requirement();
        req.maxAgeSeconds = maxAgeSeconds;
        req.requireFresh = true;
        return req;
    }

    function _requirementWithProviders(bytes32[] memory providers)
        internal
        pure
        returns (CredentialTypes.CredentialRequirement memory)
    {
        CredentialTypes.CredentialRequirement memory req = _requirement();
        req.acceptedProviders = providers;
        return req;
    }

    // ---------------------------------------------------------------------
    // Propagation helpers
    // ---------------------------------------------------------------------

    /// @dev The number of messages the source sender has dispatched so far.
    function _sentCount() internal view returns (uint256) {
        return router.sentCount();
    }

    /// @dev Decode a recorded outbound message into a {PropagationPayload.Message}.
    function _decodeSent(uint256 index) internal view returns (PropagationPayload.Message memory m) {
        MockCCIPRouter.SentMessage memory s = router.sentAt(index);
        (m,) = PropagationPayload.decode(s.payload);
    }

    /// @dev Cached receiver selector. Read once in setUp rather than inside _deliver,
    ///      because an intervening call would silently consume a pending
    ///      `vm.expectRevert` and make every rejection test pass vacuously.
    bytes4 internal destSelector;

    /// @dev Deliver recorded message `index` from `sender` under `orderId`.
    function _deliver(uint256 index, address sender, bytes32 orderId) internal {
        router.deliver(index, address(destReceiver), sender, orderId, destSelector);
    }
}
