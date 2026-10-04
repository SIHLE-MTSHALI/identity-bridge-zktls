// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {CCIDResolver} from "../src/CCIDResolver.sol";
import {CredentialBridge} from "../src/CredentialBridge.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";
import {CrossChainCredentialReceiver} from "../src/CrossChainCredentialReceiver.sol";
import {CrossChainCredentialSender} from "../src/CrossChainCredentialSender.sol";
import {EmergencyControls} from "../src/EmergencyControls.sol";
import {PolicyManagerAdapter} from "../src/PolicyManagerAdapter.sol";
import {ProviderRegistry} from "../src/ProviderRegistry.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";

/**
 * @title Deploy
 * @notice Deploys the full credential system and wires it together.
 *
 * @dev ## Ordering, and why it is awkward
 *
 *      There is a genuine cycle: the sender needs the bridge's address, and the
 *      bridge needs the sender's address. Rather than hide that with CREATE2
 *      gymnastics, the cycle is broken explicitly:
 *
 *        1. Deploy the sender unbound.
 *        2. Deploy the bridge pointing at it.
 *        3. Bind the sender to the bridge, once, permanently.
 *
 *      An unbound sender accepts no calls at all, so the intermediate state is
 *      safe rather than merely inconvenient.
 *
 *      The receiver has a mirror-image problem - it must be a registry writer
 *      before it will accept anything - resolved by {CrossChainCredentialReceiver.wire}.
 *      A receiver left unwired refuses every message instead of silently dropping it.
 *
 *      ## Secrets
 *
 *      Reads deployment parameters from the environment. Never accepts a private
 *      key as an argument: keys come from `PRIVATE_KEY` via forge's keystore or
 *      environment, and this script refuses to run without one rather than
 *      defaulting to anything.
 */
contract Deploy is Script {
    struct Deployment {
        CredentialRegistry registry;
        CredentialBridge bridge;
        ProviderRegistry providers;
        SchemaRegistry schemas;
        CCIDResolver resolver;
        PolicyManagerAdapter policy;
        CrossChainCredentialSender sender;
        EmergencyControls emergency;
    }

    function run() external returns (Deployment memory d) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.envOr("ADMIN_ADDRESS", vm.addr(pk));
        address guardian = vm.envOr("GUARDIAN_ADDRESS", admin);
        address ccipRouter = vm.envAddress("CCIP_ROUTER");
        uint64 sourceSelector = uint64(vm.envUint("SOURCE_CHAIN_SELECTOR"));

        vm.startBroadcast(pk);

        d.emergency = new EmergencyControls(admin, guardian);
        d.registry = new CredentialRegistry(admin);
        d.providers = new ProviderRegistry(admin);
        d.schemas = new SchemaRegistry(admin);
        d.resolver = new CCIDResolver();

        d.sender = new CrossChainCredentialSender(admin, ccipRouter, sourceSelector, d.emergency);
        d.bridge = new CredentialBridge(admin, d.registry, d.schemas, d.providers, d.resolver, d.sender, d.emergency);

        // Break the cycle: the sender now learns its bridge, permanently.
        d.sender.initializeBridge(address(d.bridge));

        d.registry.setWriter(address(d.bridge), true);

        d.policy = new PolicyManagerAdapter(d.registry, d.schemas, d.providers, d.emergency);

        vm.stopBroadcast();

        _log("CredentialRegistry", address(d.registry));
        _log("CredentialBridge", address(d.bridge));
        _log("ProviderRegistry", address(d.providers));
        _log("SchemaRegistry", address(d.schemas));
        _log("CCIDResolver", address(d.resolver));
        _log("PolicyManagerAdapter", address(d.policy));
        _log("CrossChainCredentialSender", address(d.sender));
        _log("EmergencyControls", address(d.emergency));
    }

    /**
     * @notice Deploy the destination-side contracts for a chain that receives state.
     * @dev Run once per destination chain. Registers the source chain's sender and
     *      selector, which is what makes {CrossChainCredentialReceiver} accept it.
     */
    function deployDestination() external returns (CrossChainCredentialReceiver receiver) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.envOr("ADMIN_ADDRESS", vm.addr(pk));
        address guardian = vm.envOr("GUARDIAN_ADDRESS", admin);
        address ccipRouter = vm.envAddress("CCIP_ROUTER");
        uint64 destSelector = uint64(vm.envUint("DESTINATION_CHAIN_SELECTOR"));
        address sourceSender = vm.envAddress("ALLOWED_SOURCE_SENDER");
        uint64 sourceSelector = uint64(vm.envUint("SOURCE_CHAIN_SELECTOR"));

        CredentialRegistry registry = new CredentialRegistry(admin);
        ProviderRegistry providers = new ProviderRegistry(admin);
        SchemaRegistry schemas = new SchemaRegistry(admin);
        EmergencyControls emergency = new EmergencyControls(admin, guardian);

        vm.startBroadcast(pk);
        receiver =
            new CrossChainCredentialReceiver(ccipRouter, destSelector, admin, registry, schemas, providers, emergency);
        registry.setWriter(address(receiver), true);
        receiver.wire();

        // Trust configuration. Both must be set or propagation silently does nothing.
        receiver.setAllowedSourceSender(sourceSender, true);
        receiver.setAllowedSourceChain(sourceSelector, true);
        vm.stopBroadcast();

        console.log("CrossChainCredentialReceiver:", address(receiver));
        console.log("  registry:", address(registry));
        console.log("  providerRegistry:", address(providers));
        console.log("  schemaRegistry:", address(schemas));
        console.log("  emergencyControls:", address(emergency));
        console.log("  allowedSourceSender:", sourceSender);
        console.log("  allowedSourceChainSelector:", sourceSelector);
    }

    function _log(string memory label, address addr) private pure {
        console.log(string.concat(label, ": ", vm.toString(addr)));
    }
}
