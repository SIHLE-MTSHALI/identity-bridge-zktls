// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ProviderRegistry
 * @notice Registry of zkTLS / compliance provider adapters, their supported
 *         schemas, and their operational health.
 *
 * @dev Providers are the system's trust boundary. A provider is trusted only for
 *      the schema versions it is admitted to, and only while its status is
 *      `Active`. Every other status degrades safely:
 *
 *      - `Paused`     - denies new issuance and denies policy checks.
 *      - `Deprecated` - denies new issuance, but existing credentials keep their
 *                       validity. This is the "wind down" state.
 *      - `Revoked`    - the adapter's attestations are no longer trusted at all;
 *                       policy checks deny immediately.
 *
 *      The distinction between `Deprecated` and `Revoked` is the difference
 *      between a planned migration and a compromise response, and it is why
 *      health metadata is tracked here rather than in the credential record.
 */
contract ProviderRegistry is AccessControl {
    using CredentialTypes for bytes32;

    /// @dev keccak256("PROVIDER_ADMIN") - may register providers and change status.
    bytes32 public constant PROVIDER_ADMIN = keccak256("PROVIDER_ADMIN");

    /// @dev keccak256("PROVIDER_OPERATOR") - may submit heartbeats and failure reports.
    bytes32 public constant PROVIDER_OPERATOR = keccak256("PROVIDER_OPERATOR");

    /// @notice A registered provider adapter.
    /// @param providerId Stable identifier, usually keccak256 of a human-readable tag.
    /// @param status Operational state.
    /// @param metadataURI Adapter documentation and proof-format pointer.
    /// @param registered Exists as a distinct flag so deprecation is reversible.
    /// @param lastHeartbeat Timestamp of the most recent operator heartbeat.
    /// @param failureCount Consecutive reported failures, for alerting.
    /// @param registeredAt First-registration timestamp.
    /// @param updatedAt Last change timestamp.
    struct Provider {
        bytes32 providerId;
        CredentialTypes.ProviderStatus status;
        string metadataURI;
        bool registered;
        uint64 lastHeartbeat;
        uint64 failureCount;
        uint64 registeredAt;
        uint64 updatedAt;
    }

    event ProviderRegistered(bytes32 indexed providerId, string metadataURI);
    event ProviderStatusChanged(
        bytes32 indexed providerId, CredentialTypes.ProviderStatus previous, CredentialTypes.ProviderStatus current
    );
    event ProviderSchemaSupportSet(
        bytes32 indexed providerId, bytes32 indexed credentialType, uint32 schemaVersion, bool supported
    );
    event ProviderHeartbeat(bytes32 indexed providerId, uint64 timestamp);
    event ProviderFailureReported(bytes32 indexed providerId, uint64 consecutiveFailures);
    event ProviderMetadataUpdated(bytes32 indexed providerId, string metadataURI);

    /// @dev providerId => Provider
    mapping(bytes32 => Provider) private _providers;

    /// @dev providerId => credentialType => schemaVersion => supported
    mapping(bytes32 => mapping(bytes32 => mapping(uint32 => bool))) private _schemaSupport;

    error NotProviderAdmin(address caller);
    error NotProviderOperator(address caller);
    error ProviderAlreadyRegistered(bytes32 providerId);
    error ProviderNotRegistered(bytes32 providerId);
    error InvalidProviderStatus();
    error EmptyProviderId();
    error MetadataUriTooLong(uint256 length);
    error StaleHeartbeat(uint64 lastHeartbeat, uint64 nowTs);
    error NotStaleHeartbeat(uint64 lastHeartbeat, uint64 nowTs);

    /// @dev Max URI length; adapter documentation lives off-chain.
    uint256 public constant MAX_METADATA_URI_LENGTH = 512;

    /// @dev A heartbeat older than this is considered stale by {isProviderHealthy}.
    uint64 public constant HEARTBEAT_STALENESS_SECONDS = 7 days;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROVIDER_ADMIN, admin);
    }

    modifier onlyProviderAdmin() {
        if (!hasRole(PROVIDER_ADMIN, msg.sender)) revert NotProviderAdmin(msg.sender);
        _;
    }

    modifier onlyProviderOperator() {
        if (!hasRole(PROVIDER_OPERATOR, msg.sender)) revert NotProviderOperator(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    /// @notice Register a provider adapter in `Paused` state.
    /// @dev New providers start paused on purpose: an adapter must be reviewed
    ///      and explicitly activated before it can influence any decision.
    function registerProvider(bytes32 providerId, string calldata metadataURI) external onlyProviderAdmin {
        if (providerId == bytes32(0)) revert EmptyProviderId();
        if (_providers[providerId].registered) revert ProviderAlreadyRegistered(providerId);
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) revert MetadataUriTooLong(bytes(metadataURI).length);

        Provider storage p = _providers[providerId];
        p.providerId = providerId;
        p.status = CredentialTypes.ProviderStatus.Paused;
        p.metadataURI = metadataURI;
        p.registered = true;
        p.registeredAt = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);

        emit ProviderRegistered(providerId, metadataURI);
        emit ProviderStatusChanged(
            providerId, CredentialTypes.ProviderStatus.Unknown, CredentialTypes.ProviderStatus.Paused
        );
    }

    /**
     * @notice Change a provider's operational status.
     * @dev Any transition is permitted, including backwards. An operator may need
     *      to re-activate a provider that was paused during an incident, and the
     *      event trail is what makes that auditable rather than silent.
     */
    function setProviderStatus(bytes32 providerId, CredentialTypes.ProviderStatus status) external onlyProviderAdmin {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);
        if (uint256(status) > uint256(CredentialTypes.ProviderStatus.Revoked)) revert InvalidProviderStatus();

        CredentialTypes.ProviderStatus previous = _providers[providerId].status;
        _providers[providerId].status = status;
        _providers[providerId].updatedAt = uint64(block.timestamp);

        // Re-activation clears the failure counter: an operator bringing a
        // provider back should not inherit an unbounded stale alert.
        if (status == CredentialTypes.ProviderStatus.Active) {
            _providers[providerId].failureCount = 0;
        }

        emit ProviderStatusChanged(providerId, previous, status);
    }

    /// @notice Declare whether a provider may attest a given schema version.
    function setSchemaSupport(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion, bool supported)
        external
        onlyProviderAdmin
    {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);
        _schemaSupport[providerId][credentialType][schemaVersion] = supported;
        _providers[providerId].updatedAt = uint64(block.timestamp);
        emit ProviderSchemaSupportSet(providerId, credentialType, schemaVersion, supported);
    }

    /// @notice Update the adapter documentation pointer.
    function setMetadataURI(bytes32 providerId, string calldata metadataURI) external onlyProviderAdmin {
        if (!_providers[providerId].registered) revert ProviderNotRegistered(providerId);
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) revert MetadataUriTooLong(bytes(metadataURI).length);
        _providers[providerId].metadataURI = metadataURI;
        _providers[providerId].updatedAt = uint64(block.timestamp);
        emit ProviderMetadataUpdated(providerId, metadataURI);
    }

    // ---------------------------------------------------------------------
    // Health reporting
    // ---------------------------------------------------------------------

    /**
     * @notice Record a successful liveness check.
     * @dev Enforces monotonicity: a heartbeat older than the stored one is
     *      rejected so an out-of-order report cannot mask a stall.
     */
    function heartbeat(bytes32 providerId) external onlyProviderOperator {
        Provider storage p = _providers[providerId];
        if (!p.registered) revert ProviderNotRegistered(providerId);
        if (p.lastHeartbeat != 0 && uint64(block.timestamp) < p.lastHeartbeat) {
            revert StaleHeartbeat(p.lastHeartbeat, uint64(block.timestamp));
        }
        p.lastHeartbeat = uint64(block.timestamp);
        p.updatedAt = uint64(block.timestamp);
        emit ProviderHeartbeat(providerId, uint64(block.timestamp));
    }

    /// @notice Record an adapter failure. Increments the consecutive-failure counter.
    function reportFailure(bytes32 providerId) external onlyProviderOperator {
        Provider storage p = _providers[providerId];
        if (!p.registered) revert ProviderNotRegistered(providerId);
        p.failureCount += 1;
        p.updatedAt = uint64(block.timestamp);
        emit ProviderFailureReported(providerId, p.failureCount);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getProvider(bytes32 providerId) external view returns (Provider memory) {
        return _providers[providerId];
    }

    /// @notice True when the provider is registered and `Active`.
    /// @dev The single gate used by both issuance and policy evaluation, so the
    ///      two can never disagree about whether a provider is usable.
    function isActive(bytes32 providerId) external view returns (bool) {
        Provider storage p = _providers[providerId];
        return p.registered && p.status == CredentialTypes.ProviderStatus.Active;
    }

    /// @notice True when the provider may still back existing credentials.
    /// @dev `Deprecated` returns true: wind-down must not retroactively invalidate
    ///      credentials that integrators already reasoned about.
    function backsExistingCredentials(bytes32 providerId) external view returns (bool) {
        Provider storage p = _providers[providerId];
        if (!p.registered) return false;
        return
            p.status == CredentialTypes.ProviderStatus.Active || p.status == CredentialTypes.ProviderStatus.Deprecated;
    }

    function supportsSchema(bytes32 providerId, bytes32 credentialType, uint32 schemaVersion)
        external
        view
        returns (bool)
    {
        return _schemaSupport[providerId][credentialType][schemaVersion];
    }

    /**
     * @notice Liveness assessment used by monitoring, not by access control.
     * @dev A stale heartbeat does NOT deny access. Denying on liveness would let a
     *      missed heartbeat become a denial-of-service against every holder, so
     *      health is surfaced to operators and left out of the policy path.
     */
    function isProviderHealthy(bytes32 providerId) external view returns (bool healthy) {
        Provider storage p = _providers[providerId];
        if (!p.registered) return false;
        if (p.status != CredentialTypes.ProviderStatus.Active) return false;
        if (p.failureCount != 0) return false;
        if (p.lastHeartbeat == 0) return false;
        healthy = (uint64(block.timestamp) - p.lastHeartbeat) <= HEARTBEAT_STALENESS_SECONDS;
    }

    /// @notice Seconds since the last heartbeat, or `type(uint64).max` if never seen.
    function heartbeatAge(bytes32 providerId) external view returns (uint64) {
        uint64 last = _providers[providerId].lastHeartbeat;
        if (last == 0) return type(uint64).max;
        return uint64(block.timestamp) - last;
    }

    /// @notice Reject a heartbeat claim that is not actually stale. Used by tests and probes.
    function requireStaleHeartbeat(bytes32 providerId) external view {
        uint64 last = _providers[providerId].lastHeartbeat;
        if (last == 0 || (uint64(block.timestamp) - last) <= HEARTBEAT_STALENESS_SECONDS) {
            revert NotStaleHeartbeat(last, uint64(block.timestamp));
        }
    }
}
