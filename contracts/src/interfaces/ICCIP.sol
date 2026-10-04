// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title ICCIPRouter
 * @notice Minimal, faithful subset of the Chainlink CCIP v2 router interface.
 *
 * @dev ## Why these are declared locally instead of vendored
 *
 *      The production system calls the real Chainlink CCIP router. This repository
 *      declares the subset it depends on rather than vendoring the upstream
 *      `chainlink-contracts` package, for two reasons:
 *
 *      1.  The repo must build for any reviewer with `forge` and `forge-std`
 *          alone. A vendored dependency tree makes `forge build` fail on network
 *          access and pins the repo to one upstream release.
 *      2.  The surface is genuinely tiny - two types and one function - so the
 *          security-relevant part stays readable in-repo instead of behind a
 *          transitive dependency.
 *
 *      The signatures and message shape below match CCIP v2 exactly, so swapping in
 *      the real router is a deployment-time address change. See
 *      `docs/architecture.md`, "Swapping in the real CCIP router".
 */
interface ICCIPRouter {
    /// @notice A message from an EVM chain to any chain. Field order is protocol-defined.
    struct EVM2AnyMessage {
        bytes receiver; // abi-encoded receiver address on the destination
        bytes data; // abi-encoded payload for the destination receiver
        uint64 destChainSelector; // CCIP chain selector of the destination
    }

    /// @notice Send a message. Returns the CCIP message id.
    function send(EVM2AnyMessage calldata message) external returns (bytes32 messageId);
}

/**
 * @title ICCIPReceiver
 * @notice Minimal, faithful subset of the Chainlink CCIP receiver interface.
 * @dev `ccipMessageCallback` is called by the router only, and must validate
 *      `msg.sender` before trusting any field in the payload. The `selector`
 *      argument identifies which receiver function the router is invoking.
 */
interface ICCIPReceiver {
    /**
     * @notice Callback invoked by the CCIP router on delivery.
     * @param orderId Unique message id; used here as a replay key.
     * @param sender The source-chain sender address as reported by CCIP.
     * @param receivedSelector The receiver function selector CCIP is invoking.
     * @param data The abi-encoded payload.
     * @return The function selector CCIP expects echoed back.
     */
    function ccipMessageCallback(bytes32 orderId, address sender, bytes4 receivedSelector, bytes calldata data)
        external
        returns (bytes4);
}
