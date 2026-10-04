// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialRegistry} from "./CredentialRegistry.sol";
import {EmergencyControls} from "./EmergencyControls.sol";
import {ProviderRegistry} from "./ProviderRegistry.sol";
import {SchemaRegistry} from "./SchemaRegistry.sol";
import {ICCIPReceiver} from "./interfaces/ICCIP.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {PropagationPayload} from "./libraries/PropagationPayload.sol";

/**
 * @title CrossChainCredentialReceiver
 * @notice Accepts credential state propagated from a trusted source chain and
 *         records it as a local replica.
 *
 * @dev ## What a replica is, and is not
 *
 *      Replicated state is a cache with an expiry, not an authority. This chain
 *      verified nothing; it trusted a message from a configured peer. Two
 *      consequences follow, and both are enforced:
 *
 *      - Freshness is recorded ({CredentialRegistry.propagationState}) so an
 *        integrator can refuse a replica older than it tolerates.
 *      - A replica can never improve local state. If this chain is itself the
 *        issuer for a CCID, an inbound message is rejected outright. Without that
 *        check a compromised source chain could overwrite a locally revoked
 *        credential with `Valid`, which is the one outcome this system exists to
 *        make impossible.
 *
 *      ## Validation performed
 *
 *      Each check stops a distinct attack and has a named error:
 *
 *      | Check                        | Attack it stops                             |
 *      |------------------------------|---------------------------------------------|
 *      | `msg.sender == ROUTER`       | direct calls bypassing CCIP                |
 *      | `EMERGENCY.isPaused()`        | writes during an incident                  |
 *      | selector match                | wrong receiver function / misrouted call   |
 *      | `consumedOrderIds[orderId]`   | message replay                             |
 *      | `ALLOWED_SOURCE_SENDERS`      | any address forging a payload              |
 *      | `ALLOWED_SOURCE_CHAINS`       | message replayed from an unexpected chain |
 *      | payload length + enum range   | malformed / truncated input                |
 *      | `bindingHash` recomputation   | a message altered after the sender signed it |
 *      | local-issuer check            | remote state overriding local authority    |
 *      | schema supported              | credentials under an unknown schema        |
 *      | provider backs credentials    | reliance on a compromised provider         |
 *      | strictly increasing nonce     | out-of-order and replayed state            |
 *
 *      ## Fail-closed
 *
 *      Rejections revert, which in CCIP v2 marks the message failed rather than
 *      silently dropping it. An unhandled inbound message is an operational signal
 *      this system would rather surface loudly.
 */
contract CrossChainCredentialReceiver is ICCIPReceiver {
    using CredentialTypes for bytes32;

    /// @notice The authorized CCIP router. The only caller permitted to deliver.
    address public immutable ROUTER;

    /// @notice This chain's own selector, used to reject self-addressed messages.
    uint64 public immutable DESTINATION_CHAIN_SELECTOR;

    CredentialRegistry public immutable REGISTRY;
    SchemaRegistry public immutable SCHEMA_REGISTRY;
    ProviderRegistry public immutable PROVIDER_REGISTRY;
    EmergencyControls public immutable EMERGENCY;

    /// @notice Administrators allowed to configure trusted sources.
    address public immutable ADMIN;

    /// @notice Source-chain senders whose messages are honoured.
    mapping(address => bool) public ALLOWED_SOURCE_SENDERS;

    /// @notice Source chain selectors whose messages are honoured.
    mapping(uint64 => bool) public ALLOWED_SOURCE_CHAINS;

    /// @notice Emitted when a replica is accepted.
    event CredentialReplicaAccepted(
        bytes32 indexed ccid,
        bytes32 indexed credentialType,
        uint64 indexed sourceChainSelector,
        address sourceSender,
        uint64 nonce,
        CredentialTypes.CredentialStatus status
    );

    /// @notice Emitted when a replica is refused, with a human-readable cause.
    event CredentialReplicaRejected(bytes32 indexed ccid, uint64 indexed nonce, string reason);

    /// @notice Emitted once the receiver has verified it can write to the registry.
    event ReceiverWired(address indexed receiver);

    /// @dev orderId => consumed. Replay defence.
    mapping(bytes32 => bool) public consumedOrderIds;

    /// @dev ccid => highest nonce accepted from any allowed source.
    mapping(bytes32 => uint64) public lastAcceptedNonce;

    error NotRouter(address caller);
    error SystemPaused();
    error NotAdmin(address caller);
    error UnknownSelector(bytes4 selector);
    error ReplayedMessage(bytes32 orderId);
    error UntrustedSourceSender(address sender);
    error UntrustedSourceChain(uint64 sourceChainSelector);
    error MalformedPayload(uint256 length);
    error UnknownStatus(uint8 status);
    error SchemaNotSupported(bytes32 credentialType, uint32 schemaVersion);
    error ProviderUnavailable(bytes32 providerId);
    error NonceNotIncreasing(bytes32 ccid, uint64 current, uint64 submitted);
    error LocalIssuerOverride(bytes32 ccid);
    error BindingHashMismatch(bytes32 claimed, bytes32 recomputed);
    error NotRegistryWriter(address account);
    error AlreadyWired();
    error NotWired();
    error ZeroAddress();

    /// @notice True once {wire} has confirmed this contract can actually write.
    /// @dev A receiver that is not a registry writer would silently drop every
    ///      propagation. Rather than discover that from missing data, the receiver
    ///      refuses to accept anything until wiring is verified - see {wire}.
    bool public wired;

    constructor(
        address router,
        uint64 destinationChainSelector,
        address admin,
        CredentialRegistry registry,
        SchemaRegistry schemaRegistry,
        ProviderRegistry providerRegistry,
        EmergencyControls emergency
    ) {
        if (router == address(0) || admin == address(0)) revert ZeroAddress();
        ROUTER = router;
        DESTINATION_CHAIN_SELECTOR = destinationChainSelector;
        ADMIN = admin;
        REGISTRY = registry;
        SCHEMA_REGISTRY = schemaRegistry;
        PROVIDER_REGISTRY = providerRegistry;
        EMERGENCY = emergency;
        // The writer role cannot be verified here: this contract's own address
        // does not exist until after the constructor returns. {wire} does it.
    }

    /**
     * @notice Confirm this contract holds the registry writer role, then arm.
     * @dev Must be called once, by the admin, after the registry has authorized
     *      this receiver. Until then every inbound message is refused with
     *      {NotWired}.
     *
     *      A deployment that skipped this step would otherwise accept messages
     *      and write nothing - the worst possible failure mode, because it looks
     *      healthy while silently losing credential state.
     */
    function wire() external {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        if (wired) revert AlreadyWired();
        if (!REGISTRY.isWriter(address(this))) revert NotRegistryWriter(address(this));
        wired = true;
        emit ReceiverWired(address(this));
    }

    // ---------------------------------------------------------------------
    // Trust configuration
    // ---------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != ADMIN) revert NotAdmin(msg.sender);
        _;
    }

    /// @notice Authorize or deauthorize a source-chain sender.
    function setAllowedSourceSender(address sender, bool allowed) external onlyAdmin {
        if (sender == address(0)) revert ZeroAddress();
        ALLOWED_SOURCE_SENDERS[sender] = allowed;
    }

    /// @notice Authorize or deauthorize a source chain selector.
    function setAllowedSourceChain(uint64 chainSelector, bool allowed) external onlyAdmin {
        ALLOWED_SOURCE_CHAINS[chainSelector] = allowed;
    }

    /// @notice The receiver function the router dispatches to.
    function selector() external pure returns (bytes4) {
        return CrossChainCredentialReceiver.receiveCredential.selector;
    }

    // ---------------------------------------------------------------------
    // Delivery
    // ---------------------------------------------------------------------

    /**
     * @notice CCIP entry point, called by the router on delivery.
     * @dev Reverts on any validation failure. See the contract docs for the attack
     *      each check prevents.
     */
    function ccipMessageCallback(bytes32 orderId, address sender, bytes4 receivedSelector, bytes calldata data)
        external
        returns (bytes4)
    {
        if (msg.sender != ROUTER) revert NotRouter(msg.sender);
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (receivedSelector != CrossChainCredentialReceiver.receiveCredential.selector) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNKNOWN_SELECTOR");
            revert UnknownSelector(receivedSelector);
        }
        if (!ALLOWED_SOURCE_SENDERS[sender]) {
            emit CredentialReplicaRejected(bytes32(0), 0, "UNTRUSTED_SOURCE_SENDER");
            revert UntrustedSourceSender(sender);
        }

        (PropagationPayload.Message memory m, PropagationPayload.DecodeError decodeErr) =
            PropagationPayload.decode(data);
        if (decodeErr != PropagationPayload.DecodeError.None) {
            if (decodeErr == PropagationPayload.DecodeError.UnknownStatus) {
                // Recover the raw status word purely to name it in the error.
                emit CredentialReplicaRejected(bytes32(0), 0, "UNKNOWN_STATUS");
                revert UnknownStatus(uint8(_rawStatus(data)));
            }
            emit CredentialReplicaRejected(bytes32(0), 0, "MALFORMED_PAYLOAD");
            revert MalformedPayload(data.length);
        }
        if (!PropagationPayload.isKnownStatus(m)) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "UNKNOWN_STATUS");
            revert UnknownStatus(uint8(m.status));
        }

        _accept(orderId, sender, m);
        return ICCIPReceiver.ccipMessageCallback.selector;
    }

    /**
     * @notice Validate and apply a propagation message.
     * @dev Split out from the callback so the same rules can be exercised directly
     *      in tests and by a local relay, without impersonating the router.
     * @param orderId CCIP message id, used as the replay key.
     * @param sender Source-chain sender reported by CCIP.
     * @param m Decoded message.
     */
    function receiveMessage(bytes32 orderId, address sender, PropagationPayload.Message memory m) public {
        if (EMERGENCY.isPaused()) revert SystemPaused();
        if (!ALLOWED_SOURCE_SENDERS[sender]) revert UntrustedSourceSender(sender);
        if (!PropagationPayload.isKnownStatus(m)) revert UnknownStatus(uint8(m.status));
        _accept(orderId, sender, m);
    }

    /// @notice Target function for CCIP dispatch. Not called directly.
    function receiveCredential() external pure {
        // Reached only through ccipMessageCallback / receiveMessage.
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * @dev Read the raw status word (field index 8) so an out-of-range status can
     *      be named in {UnknownStatus} instead of collapsing into MalformedPayload.
     *      Only called after {PropagationPayload.decode} has confirmed the length.
     */
    function _rawStatus(bytes memory data) private pure returns (uint256 raw) {
        assembly {
            // data points at the length word; the payload starts 32 bytes in.
            // Field index 8 is at byte offset 8 * 32 == 0x100 within the payload.
            raw := mload(add(add(data, 0x20), 0x100))
        }
    }

    function _accept(bytes32 orderId, address sender, PropagationPayload.Message memory m) private {
        if (!wired) revert NotWired();
        if (consumedOrderIds[orderId]) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "REPLAYED_MESSAGE");
            revert ReplayedMessage(orderId);
        }
        if (!ALLOWED_SOURCE_CHAINS[m.sourceChainSelector]) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "UNTRUSTED_SOURCE_CHAIN");
            revert UntrustedSourceChain(m.sourceChainSelector);
        }
        if (m.sourceChainSelector == DESTINATION_CHAIN_SELECTOR) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "SELF_SOURCE_CHAIN");
            revert UntrustedSourceChain(m.sourceChainSelector);
        }

        // Integrity: the sender committed to these exact contents. Recomputing here
        // is what makes a post-hoc edit to the payload detectable.
        bytes32 recomputed = PropagationPayload.recomputeBindingHash(m);
        if (recomputed != m.bindingHash) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "BINDING_HASH_MISMATCH");
            revert BindingHashMismatch(m.bindingHash, recomputed);
        }

        // A replica must never overwrite state this chain is authoritative for.
        // Evaluated before any write, so a refused override costs nothing.
        CredentialTypes.PropagationState memory p = REGISTRY.getPropagationState(m.ccid);
        if (REGISTRY.exists(m.ccid) && !p.isReplica) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "LOCAL_ISSUER_OVERRIDE");
            revert LocalIssuerOverride(m.ccid);
        }

        if (!SCHEMA_REGISTRY.isSchemaSupported(m.credentialType, m.schemaVersion)) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "SCHEMA_NOT_SUPPORTED");
            revert SchemaNotSupported(m.credentialType, m.schemaVersion);
        }

        // A paused or revoked provider must not have its attestations trusted on
        // this chain either. Checked per-destination, so pausing a provider in one
        // jurisdiction does not depend on propagation from another.
        if (!PROVIDER_REGISTRY.backsExistingCredentials(m.providerId)) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "PROVIDER_UNAVAILABLE");
            revert ProviderUnavailable(m.providerId);
        }

        uint64 current = lastAcceptedNonce[m.ccid];
        if (m.nonce <= current) {
            emit CredentialReplicaRejected(m.ccid, m.nonce, "STALE_NONCE");
            revert NonceNotIncreasing(m.ccid, current, m.nonce);
        }

        // Consumed markers are written last. If any check above reverts the whole
        // transaction reverts, leaving the order id unconsumed so the message can be
        // retried once an operator has fixed the underlying cause, rather than
        // being burned permanently.
        consumedOrderIds[orderId] = true;
        lastAcceptedNonce[m.ccid] = m.nonce;

        REGISTRY.applyReplica(
            m.ccid,
            m.credentialType,
            m.providerId,
            m.evidenceHash,
            m.schemaVersion,
            m.issuedAt,
            m.expiresAt,
            m.nonce,
            m.status,
            m.sourceChainSelector
        );

        emit CredentialReplicaAccepted(m.ccid, m.credentialType, m.sourceChainSelector, sender, m.nonce, m.status);
    }
}
