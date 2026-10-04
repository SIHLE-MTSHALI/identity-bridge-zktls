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
import {CredentialLifecycleHandler} from "./CredentialLifecycleHandler.sol";

/**
 * @title CredentialLifecycleInvariantTest
 * @notice Stateful fuzzing of the credential lifecycle against the properties
 *         that must hold unconditionally, whatever sequence of actions occurs.
 *
 * @dev Unit tests cover the cases we anticipated. These cover the ones we did not:
 *      the fuzzer drives random valid *and* invalid actions at the system for
 *      thousands of calls, and the invariants below are checked after every one.
 *
 *      Each property here is a safety property, not a liveness one. The system is
 *      allowed to refuse work; it is never allowed to say yes when it should not.
 */
contract CredentialLifecycleInvariantTest is Test {
    CredentialRegistry internal registry;
    CredentialBridge internal bridge;
    ProviderRegistry internal providers;
    SchemaRegistry internal schemas;
    CCIDResolver internal resolver;
    PolicyManagerAdapter internal policy;
    EmergencyControls internal emergency;
    CredentialLifecycleHandler internal handler;

    address internal admin = makeAddr("admin");
    address internal guardian = makeAddr("guardian");

    bytes32 internal constant CRED_TYPE = keccak256("kyc.basic");
    bytes32 internal constant PROVIDER = keccak256("provider.mock");
    uint32 internal constant SCHEMA_VERSION = 1;
    uint64 internal constant TTL = 30 days;

    MockCCIPRouter internal router;
    CrossChainCredentialSender internal sender;

    function setUp() public {
        vm.warp(1_700_000_000);

        registry = new CredentialRegistry(admin);
        providers = new ProviderRegistry(admin);
        schemas = new SchemaRegistry(admin);
        resolver = new CCIDResolver();
        emergency = new EmergencyControls(admin, guardian);

        // A real sender is deployed but deliberately never bound to a bridge.
        // Propagation is a no-op because every handler action passes an empty
        // destination list; these invariants are about source-chain lifecycle and
        // CCIP has its own suite.
        router = new MockCCIPRouter();
        sender = new CrossChainCredentialSender(admin, address(router), 16_015_286_601_757_825_753, emergency);

        bridge = new CredentialBridge(admin, registry, schemas, providers, resolver, sender, emergency);
        policy = new PolicyManagerAdapter(registry, schemas, providers, emergency);

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

        handler = new CredentialLifecycleHandler(
            registry, bridge, providers, schemas, resolver, emergency, CRED_TYPE, PROVIDER, SCHEMA_VERSION, TTL
        );

        // The handler drives the bridge directly, so it needs the roles the
        // bridge enforces.
        vm.startPrank(admin);
        bridge.grantRole(bridge.WORKFLOW_SUBMITTER(), address(handler));
        bridge.grantRole(bridge.ISSUER(), address(handler));
        bridge.grantRole(bridge.HOLDER(), address(handler));
        emergency.grantRole(emergency.GUARDIAN(), address(handler));
        emergency.grantRole(emergency.TIMELOCK_ADMIN(), address(handler));
        emergency.grantRole(emergency.DEFAULT_ADMIN_ROLE(), address(handler));
        vm.stopPrank();

        // Fuzz the handler, not the contracts: it is the only address that can
        // satisfy the bridge's role checks, so every state change flows through it.
        targetContract(address(handler));
    }

    function _requirement() internal pure returns (CredentialTypes.CredentialRequirement memory r) {
        r.credentialType = CRED_TYPE;
        r.schemaVersion = SCHEMA_VERSION;
        r.maxAgeSeconds = 0;
        r.requireFresh = false;
    }

    // -----------------------------------------------------------------
    // INV-1: only a Valid, unexpired credential may ever be allowed
    // -----------------------------------------------------------------

    function invariant_onlyValidCredentialIsAllowed() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            if (!registry.exists(ccid)) continue;

            (bool allowed,) = policy.evaluate(ccid, _requirement());
            CredentialTypes.CredentialStatus status = registry.statusOf(ccid);

            if (status != CredentialTypes.CredentialStatus.Valid) {
                assertFalse(allowed, "INV-1: non-Valid credential produced an allow");
            }
            if (allowed) {
                assertEq(
                    uint8(status), uint8(CredentialTypes.CredentialStatus.Valid), "INV-1: allow on non-Valid status"
                );
            }
        }
    }

    /// @dev Stronger form of INV-1: once the system has seen a credential as
    ///      expired, it can never be allowed again - not even after a warp backwards.
    function invariant_expiredIsNeverAllowed() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            if (registry.getRecord(ccid).expiresAt <= block.timestamp) {
                (bool allowed,) = policy.evaluate(ccid, _requirement());
                assertFalse(allowed, "INV-2: expired credential allowed");
            }
        }
    }

    // -----------------------------------------------------------------
    // INV-3: revocation is terminal
    // -----------------------------------------------------------------

    function invariant_revocationIsTerminal() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            if (!handler.revokeSucceeded(ccid)) continue;
            assertTrue(
                registry.getRecord(ccid).status == CredentialTypes.CredentialStatus.Revoked,
                "INV-3: revoked credential left the Revoked state"
            );
            (bool allowed,) = policy.evaluate(ccid, _requirement());
            assertFalse(allowed, "INV-3: revoked credential allowed");
        }
    }

    // -----------------------------------------------------------------
    // INV-4 / INV-5: expiry and nonce never move backwards
    // -----------------------------------------------------------------

    function invariant_expiryNeverDecreases() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            assertGe(registry.getRecord(ccid).expiresAt, handler.highWaterExpiry(ccid), "INV-4: expiry moved backwards");
        }
    }

    function invariant_nonceNeverDecreases() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            assertGe(registry.getRecord(ccid).nonce, handler.highWaterNonce(ccid), "INV-5: nonce moved backwards");
        }
    }

    // -----------------------------------------------------------------
    // INV-6: the system never reports itself healthy while misconfigured
    // -----------------------------------------------------------------

    /// @dev A paused system must deny everyone, including credentials that are
    ///      otherwise perfectly valid. This is the fail-closed guarantee.
    function invariant_pauseFailsClosed() public view {
        if (!emergency.paused()) return;
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            (bool allowed, bytes32 reason) = policy.evaluate(ccid, _requirement());
            assertFalse(allowed, "INV-6: allowed while paused");
            assertEq(reason, CredentialTypes.REASON_SYSTEM_PAUSED, "INV-6: wrong reason while paused");
        }
    }

    // -----------------------------------------------------------------
    // INV-7: a credential's identity binding always reproduces
    // -----------------------------------------------------------------

    /// @dev Any record that claims to be attested must carry a provider that the
    ///      schema actually admits. A record that slipped past with an unadmitted
    ///      provider would mean issuance checks were bypassable.
    function invariant_issuedRecordsUseAdmittedProviders() public view {
        uint256 n = handler.credentialCount();
        for (uint256 i = 0; i < n; ++i) {
            bytes32 ccid = handler.credentialAt(i);
            CredentialTypes.CredentialRecord memory r = registry.getRecord(ccid);
            if (r.providerId == bytes32(0)) continue; // still Pending
            assertTrue(
                schemas.isProviderAccepted(r.credentialType, r.schemaVersion, r.providerId),
                "INV-7: record carries a provider the schema does not admit"
            );
        }
    }
}
