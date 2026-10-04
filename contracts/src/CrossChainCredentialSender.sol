// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EmergencyControls} from "./EmergencyControls.sol";
import {ICCIPRouter} from "./interfaces/ICCIP.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {PropagationPayload} from "./libraries/PropagationPayload.sol";

/**
 * @title CrossChainCredentialSender
 * @notice Encodes and dispatches credential state to destination chains over CCIP.
 *
 * @dev ## The deployment cycle
 *
 *      The sender must know its bridge, and the bridge must hold the sender, so the
 *      two cannot both take the other as a constructor argument. The sender is
 *      therefore deployed first and bound once via {initializeBridge}.
 *
 *      That is safe because the binding is one-way and permanent: `bridge` starts
 *      unset, only the deployer may set it, and only once. After that the sender
 *      accepts calls from that one address forever. Until it is set, the sender
 *      simply cannot be called by anyone, which is the safe default - an
 *      unbound sender propagates nothing rather than propagating to the wrong
 *      caller.
 *
 * @dev ## Propagation is fail-closed
 *
 *      Every state change a destination could care about goes out through
 *      {sendCredentialState}: issue, renew, suspend, dispute, expire, and revoke.
 *      There is no separate fast path for revocation, because a channel that only
 *      sometimes exists is precisely how a revoked credential ends up still looking
 *      valid somewhere.
 *
 *      Revocation latency is therefore bounded only by CCIP delivery, and
 *      `docs/operations-runbook.md` treats revocation lag as an alertable metric
 *      rather than something this contract can solve on its own.
 */
contract CrossChainCredentialSender {
    /// @notice The deployer. May perform the one-time bridge binding and nothing else.
    address public immutable ADMIN;

    /// @notice The CCIP router.
    ICCIPRouter public immutable ROUTER;

    /// @notice This chain's CCIP selector, embedded in every payload.
    uint64 public immutable SOURCE_CHAIN_SELECTOR;

    EmergencyControls public immutable EMERGENCY;

    /// @notice The bridge authorized to dispatch. Zero until {initializeBridge}.
    address public bridge;

    /// @notice True once {bridge} has been set. Prevents rebinding.
    bool public bridgeInitialized;

    /// @notice Emitted when credential state is dispatched to a destination chain.
    event CredentialSent(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        uint64 indexed destinationChainSelector,
        uint64 nonce,
        bytes32 ccipMessageId,
        CredentialTypes.CredentialStatus status
    );

    /// @dev ccid => highest nonce dispatched. Replay/staleness bookkeeping.
    mapping(bytes32 => uint64) public lastSentNonce;

    /// @dev ccid => destination selector => true once ever dispatched.
    mapping(bytes32 => mapping(uint64 => bool)) public sentTo;

    /// @notice Emitted when the one-time bridge binding is performed.
    event BridgeInitialized(address indexed bridge);

    error NotBridge(address caller);
    error NotAdmin(address caller);
    error BridgeAlreadyInitialized(address existing);
    error SystemPaused();
    error NoDestinations();
    error TooManyDestinations(uint256 length);
    error SelfDestination(uint64 destinationChainSelector);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error UnknownStatus(uint8 status);
    error RouterNotConfigured();

    /// @dev Bounded per call so one result cannot exceed block gas.
    uint256 public constant MAX_DESTINATIONS = 10;

    constructor(address admin, address router, uint64 sourceChainSelector, EmergencyControls emergency) {
        if (admin == address(0) || router == address(0)) revert RouterNotConfigured();
        ADMIN = admin;
        ROUTER = ICCIPRouter(router);
        SOURCE_CHAIN_SELECTOR = sourceChainSelector;
        EMERGENCY = emergency;
    }

    /**
     * @notice Bind this sender to its bridge. Callable exactly once, by the deployer.
     * @dev Breaks the bridge/sender constructor cycle. Permanent by design: a
     *      rebindable sender would let a compromised deployer role redirect
     *      credential propagation at any moment.
     */
    function initializeBridge(address bridge_) external {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        if (bridgeInitialized) revert BridgeAlreadyInitialized(bridge);
        if (bridge_ == address(0)) revert RouterNotConfigured();
        bridge = bridge_;
        bridgeInitialized = true;
        emit BridgeInitialized(bridge_);
    }

    /**
     * @notice Propagate a credential's current state to the given destinations.
     * @dev The bridge calls this after any state change. Revocation included.
     *      Takes the message struct rather than nine positional parameters: it
     *      keeps the call within the EVM stack limit, and it means the wire format
     *      has exactly one definition ({PropagationPayload.Message}) instead of a
     *      signature and an encoding that must agree.
     * @param m Credential state to propagate. `bindingHash` is ignored on input
     *        and recomputed here, so the sender is the single authority on it.
     * @param destinations Destination chain selectors.
     */
    function sendCredentialState(PropagationPayload.Message memory m, uint64[] calldata destinations)
        external
        returns (uint256 sentCount)
    {
        if (msg.sender != bridge) revert NotBridge(msg.sender);
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (destinations.length == 0) revert NoDestinations();
        if (destinations.length > MAX_DESTINATIONS) revert TooManyDestinations(destinations.length);
        if (m.nonce <= lastSentNonce[m.ccid]) {
            revert NonceNotIncreasing(m.ccid, lastSentNonce[m.ccid], m.nonce);
        }
        if (!PropagationPayload.isKnownStatus(m)) revert UnknownStatus(uint8(m.status));

        // This contract is the sole authority on the source chain selector. The
        // caller does not supply it - a caller that could would be able to forge
        // messages claiming to originate from another chain.
        m.sourceChainSelector = SOURCE_CHAIN_SELECTOR;

        for (uint256 i = 0; i < destinations.length; ++i) {
            if (destinations[i] == SOURCE_CHAIN_SELECTOR) revert SelfDestination(destinations[i]);
        }

        // The sender is authoritative for the binding hash; the receiver
        // recomputes and rejects any mismatch.
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);
        bytes memory payload = PropagationPayload.encode(m);

        // Recorded before dispatch: a partially failed batch must not be
        // retryable with the same nonce, or a destination could be skipped
        // silently while the retry appears to succeed.
        lastSentNonce[m.ccid] = m.nonce;

        for (uint256 i = 0; i < destinations.length; ++i) {
            uint64 dest = destinations[i];
            bytes32 messageId = ROUTER.send(
                ICCIPRouter.EVM2AnyMessage({
                    receiver: abi.encode(address(this)), data: payload, destChainSelector: dest
                })
            );
            sentTo[m.ccid][dest] = true;
            emit CredentialSent(m.ccid, m.credentialType, dest, m.nonce, messageId, m.status);
            ++sentCount;
        }
    }

    /// @notice Highest nonce dispatched for a credential.
    function getLastSentNonce(bytes32 ccid) external view returns (uint64) {
        return lastSentNonce[ccid];
    }

    /// @notice Whether a credential has ever been dispatched to a destination.
    function hasSentTo(bytes32 ccid, uint64 destinationChainSelector) external view returns (bool) {
        return sentTo[ccid][destinationChainSelector];
    }

    /// @notice Build the payload this sender would emit. Exposed so tests and
    ///         off-chain tooling share one definition rather than re-deriving it.
    function encodePayload(
        bytes32 ccid,
        bytes32 credentialType,
        uint32 schemaVersion,
        bytes32 providerId,
        bytes32 evidenceHash,
        uint64 issuedAt,
        uint64 expiresAt,
        uint64 nonce,
        CredentialTypes.CredentialStatus status
    ) external view returns (bytes memory) {
        PropagationPayload.Message memory m;
        m.ccid = ccid;
        m.credentialType = credentialType;
        m.schemaVersion = schemaVersion;
        m.providerId = providerId;
        m.evidenceHash = evidenceHash;
        m.issuedAt = issuedAt;
        m.expiresAt = expiresAt;
        m.nonce = nonce;
        m.status = status;
        m.sourceChainSelector = SOURCE_CHAIN_SELECTOR;
        m.bindingHash = PropagationPayload.recomputeBindingHash(m);
        return PropagationPayload.encode(m);
    }
}
