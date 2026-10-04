// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SchemaRegistry
 * @notice Authoritative registry of credential schemas: what a credential means,
 *         how long it may live, which providers may attest it, and who may revoke it.
 *
 * @dev A schema is the contract between an issuer and every integrator. Integrators
 *      read schemas to know what a credential proves; the bridge reads them to decide
 *      TTL, provider admissibility, and revocation authority.
 *
 *      Deprecation is one-way on purpose. `deprecate` stops new issuance for a
 *      version but leaves existing credentials readable, so an integrator's
 *      historical decisions stay explainable. Schemas are never deleted.
 */
contract SchemaRegistry is AccessControl {
    using CredentialTypes for bytes32;

    /// @dev keccak256("SCHEMA_ADMIN") - may register, activate, and deprecate schemas.
    bytes32 public constant SCHEMA_ADMIN = keccak256("SCHEMA_ADMIN");

    /// @notice A registered credential schema.
    /// @param credentialType Schema family.
    /// @param schemaVersion Version within the family.
    /// @param ttlSeconds Canonical lifetime. The bridge rejects results that deviate.
    /// @param revocationMode Who may revoke credentials issued under this schema.
    /// @param active False once deprecated. Blocks new issuance, not existing reads.
    /// @param registered Exists as a distinct flag so a deprecation is reversible.
    /// @param metadataURI Documentation pointer. A URI, never inline sensitive data.
    /// @param createdAt Registration timestamp.
    /// @param updatedAt Last metadata change timestamp.
    struct Schema {
        bytes32 credentialType;
        uint32 schemaVersion;
        uint64 ttlSeconds;
        CredentialTypes.RevocationMode revocationMode;
        bool active;
        bool registered;
        string metadataURI;
        uint64 createdAt;
        uint64 updatedAt;
        bytes32[] acceptedProviderList;
    }

    /// @notice emitted when a new schema version is registered.
    event SchemaRegistered(
        bytes32 indexed credentialType,
        uint32 indexed schemaVersion,
        uint64 ttlSeconds,
        CredentialTypes.RevocationMode revocationMode,
        string metadataURI
    );

    /// @notice emitted when a schema is activated or deprecated.
    event SchemaStatusChanged(bytes32 indexed credentialType, uint32 indexed schemaVersion, bool active);

    /// @notice emitted when a provider is admitted to or removed from a schema.
    event SchemaProviderSet(
        bytes32 indexed credentialType, uint32 indexed schemaVersion, bytes32 indexed providerId, bool accepted
    );

    /// @notice emitted when a schema's metadata URI is updated.
    event SchemaMetadataUpdated(bytes32 indexed credentialType, uint32 indexed schemaVersion, string metadataURI);

    /// @dev credentialType => schemaVersion => Schema
    mapping(bytes32 => mapping(uint32 => Schema)) private _schemas;

    /// @dev credentialType => schemaVersion => providerId => accepted
    mapping(bytes32 => mapping(uint32 => mapping(bytes32 => bool))) private _acceptedProviders;

    /// @dev Marks the latest registered version per type, so callers can follow a moving target.
    mapping(bytes32 => uint32) public latestVersion;

    error NotSchemaAdmin(address caller);
    error SchemaAlreadyRegistered(bytes32 credentialType, uint32 schemaVersion);
    error SchemaNotRegistered(bytes32 credentialType, uint32 schemaVersion);
    error SchemaVersionMustIncrease(bytes32 credentialType, uint32 registered, uint32 attempted);
    error InvalidTtl(uint256 ttlSeconds);
    error InvalidRevocationMode();
    error EmptyCredentialType();
    error ProviderListTooLarge(uint256 length);
    error MetadataUriTooLong(uint256 length);

    /// @dev Max accepted providers per schema; bounds loop cost on registration.
    uint256 public constant MAX_PROVIDERS_PER_SCHEMA = 32;

    /// @dev Max URI length, to keep metadata off-chain rather than bloating state.
    uint256 public constant MAX_METADATA_URI_LENGTH = 512;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SCHEMA_ADMIN, admin);
    }

    modifier onlySchemaAdmin() {
        if (!hasRole(SCHEMA_ADMIN, msg.sender)) revert NotSchemaAdmin(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    /**
     * @notice Register a new schema version with its initial accepted-provider set.
     * @dev Versions must strictly increase per credential type so that
     *      {latestVersion} is unambiguous and version comparison is meaningful.
     */
    function registerSchema(
        bytes32 credentialType,
        uint32 schemaVersion,
        uint64 ttlSeconds,
        CredentialTypes.RevocationMode revocationMode,
        bytes32[] calldata initialProviders,
        string calldata metadataURI
    ) external onlySchemaAdmin {
        if (credentialType == bytes32(0)) revert EmptyCredentialType();
        if (_schemas[credentialType][schemaVersion].registered) {
            revert SchemaAlreadyRegistered(credentialType, schemaVersion);
        }
        if (schemaVersion <= latestVersion[credentialType]) {
            revert SchemaVersionMustIncrease(credentialType, latestVersion[credentialType], schemaVersion);
        }
        if (ttlSeconds == 0 || ttlSeconds > type(uint64).max / 2) revert InvalidTtl(ttlSeconds);
        if (uint256(revocationMode) > uint256(CredentialTypes.RevocationMode.GovernanceOnly)) {
            revert InvalidRevocationMode();
        }
        if (initialProviders.length > MAX_PROVIDERS_PER_SCHEMA) {
            revert ProviderListTooLarge(initialProviders.length);
        }
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) {
            revert MetadataUriTooLong(bytes(metadataURI).length);
        }

        // Assign field-by-field rather than as a struct literal: a literal would
        // have to construct the acceptedProviderList array inline.
        Schema storage s = _schemas[credentialType][schemaVersion];
        s.credentialType = credentialType;
        s.schemaVersion = schemaVersion;
        s.ttlSeconds = ttlSeconds;
        s.revocationMode = revocationMode;
        s.active = true;
        s.registered = true;
        s.metadataURI = metadataURI;
        s.createdAt = uint64(block.timestamp);
        s.updatedAt = uint64(block.timestamp);

        for (uint256 i = 0; i < initialProviders.length; ++i) {
            bytes32 providerId = initialProviders[i];
            if (_acceptedProviders[credentialType][schemaVersion][providerId]) continue;
            _acceptedProviders[credentialType][schemaVersion][providerId] = true;
            s.acceptedProviderList.push(providerId);
            emit SchemaProviderSet(credentialType, schemaVersion, providerId, true);
        }

        latestVersion[credentialType] = schemaVersion;
        emit SchemaRegistered(credentialType, schemaVersion, ttlSeconds, revocationMode, metadataURI);
    }

    /**
     * @notice Activate or deprecate a schema version.
     * @dev Deprecating blocks new issuance. It does not alter existing records,
     *      so already-issued credentials keep their original semantics.
     */
    function setSchemaActive(bytes32 credentialType, uint32 schemaVersion, bool active) external onlySchemaAdmin {
        if (!_schemas[credentialType][schemaVersion].registered) {
            revert SchemaNotRegistered(credentialType, schemaVersion);
        }
        _schemas[credentialType][schemaVersion].active = active;
        _schemas[credentialType][schemaVersion].updatedAt = uint64(block.timestamp);
        emit SchemaStatusChanged(credentialType, schemaVersion, active);
    }

    /// @notice Update the documentation pointer for a schema.
    function setMetadataURI(bytes32 credentialType, uint32 schemaVersion, string calldata metadataURI)
        external
        onlySchemaAdmin
    {
        if (!_schemas[credentialType][schemaVersion].registered) {
            revert SchemaNotRegistered(credentialType, schemaVersion);
        }
        if (bytes(metadataURI).length > MAX_METADATA_URI_LENGTH) {
            revert MetadataUriTooLong(bytes(metadataURI).length);
        }
        _schemas[credentialType][schemaVersion].metadataURI = metadataURI;
        _schemas[credentialType][schemaVersion].updatedAt = uint64(block.timestamp);
        emit SchemaMetadataUpdated(credentialType, schemaVersion, metadataURI);
    }

    /**
     * @notice Admit or remove a provider for a schema.
     * @dev Removal also prunes the stored list so {acceptedProviders} cannot
     *      report a provider that is no longer accepted.
     */
    function setProviderAcceptance(bytes32 credentialType, uint32 schemaVersion, bytes32 providerId, bool accepted)
        external
        onlySchemaAdmin
    {
        Schema storage s = _schemas[credentialType][schemaVersion];
        if (!s.registered) revert SchemaNotRegistered(credentialType, schemaVersion);
        if (accepted) {
            if (_acceptedProviders[credentialType][schemaVersion][providerId]) return;
            if (s.acceptedProviderList.length >= MAX_PROVIDERS_PER_SCHEMA) {
                revert ProviderListTooLarge(s.acceptedProviderList.length + 1);
            }
            _acceptedProviders[credentialType][schemaVersion][providerId] = true;
            s.acceptedProviderList.push(providerId);
        } else {
            if (!_acceptedProviders[credentialType][schemaVersion][providerId]) return;
            delete _acceptedProviders[credentialType][schemaVersion][providerId];
            _removeFromProviderList(s.acceptedProviderList, providerId);
        }
        s.updatedAt = uint64(block.timestamp);
        emit SchemaProviderSet(credentialType, schemaVersion, providerId, accepted);
    }

    /// @dev Swap-and-pop removal. The list is governance-managed and short, so an
    ///      order-preserving removal is not worth the gas.
    function _removeFromProviderList(bytes32[] storage list, bytes32 providerId) private {
        for (uint256 i = 0; i < list.length; ++i) {
            if (list[i] == providerId) {
                list[i] = list[list.length - 1];
                list.pop();
                return;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getSchema(bytes32 credentialType, uint32 schemaVersion) external view returns (Schema memory) {
        return _schemas[credentialType][schemaVersion];
    }

    /// @notice True when the schema exists and is not deprecated.
    function isSchemaSupported(bytes32 credentialType, uint32 schemaVersion) external view returns (bool) {
        Schema storage s = _schemas[credentialType][schemaVersion];
        return s.registered && s.active;
    }

    function isProviderAccepted(bytes32 credentialType, uint32 schemaVersion, bytes32 providerId)
        external
        view
        returns (bool)
    {
        if (!_schemas[credentialType][schemaVersion].registered) return false;
        return _acceptedProviders[credentialType][schemaVersion][providerId];
    }

    /**
     * @notice Enumerate the providers accepted for a schema version.
     * @dev Bounded by `MAX_PROVIDERS_PER_SCHEMA`, so the loop is safe in a view
     *      function. O(1) acceptance checks use {isProviderAccepted} instead.
     */
    function acceptedProviders(bytes32 credentialType, uint32 schemaVersion)
        external
        view
        returns (bytes32[] memory providers)
    {
        Schema storage s = _schemas[credentialType][schemaVersion];
        if (!s.registered) return new bytes32[](0);
        return s.acceptedProviderList;
    }

    /// @notice Number of providers currently accepted for a schema version.
    function acceptedProviderCount(bytes32 credentialType, uint32 schemaVersion) external view returns (uint256) {
        return _schemas[credentialType][schemaVersion].acceptedProviderList.length;
    }
}
