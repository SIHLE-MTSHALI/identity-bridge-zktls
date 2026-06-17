# Identity Bridge zkTLS Engineering Specification

**Status:** Implementation-ready MVP build contract  
**Last reviewed:** 2026-06-17  
**Canonical product document:** `PRD.md`  
**Audience:** engineering team building the first complete MVP without further product consultation

## 1. Build Contract

This document turns the PRD into an executable engineering handoff. Engineers should be able to build the MVP described here without asking for product decisions. If this file conflicts with `PRD.md`, treat `PRD.md` as the product intent and this file as the implementation contract; update both in the same PR.

Escalate only for real provider contracts, production identity data, legal/compliance claims, secrets, or mainnet deployment. Do not escalate for MVP credential types, state model, contract names, test scope, or default policy values; those are fixed below.

## 2. Fixed MVP Decisions

| Topic | MVP decision |
| --- | --- |
| First credential type | `GITHUB_ACCOUNT_MIN_AGE_180D` |
| Second credential type | `GITHUB_REPO_CONTRIBUTOR` for a configured repository |
| First provider path | `MockZkTlsProvider` with deterministic fixtures |
| First real-provider adapter | Reclaim-style adapter interface, implemented behind a feature flag when testnet tooling is available |
| Identity binding | `ccid = keccak256(abi.encode(wallet, recoverySalt, version))` for MVP |
| Credential storage | Store status, expiry, schema version, provider ID, evidence hash, and revocation nonce only |
| Raw data policy | No raw PII, raw TLS transcript, account handle, document, provider response, or raw proof on-chain or in events |
| Source chain | Local simulator first; Sepolia for public testnet target if supported at implementation time |
| Destination chain | Local simulator first; Avalanche Fuji for public testnet target if supported at implementation time |
| Propagation | CCIP message carries credential state update and nonce |
| Default TTL | 30 days in production config; 5 minutes in tests |
| Governance | Timelocked schema/provider changes; local tests use deterministic admin accounts |

Open questions in `PRD.md` are future production questions. They do not block this MVP.

## 3. Target Architecture

```text
contracts/
  src/
    CredentialRegistry.sol
    CredentialBridge.sol
    ProviderRegistry.sol
    CCIDResolver.sol
    PolicyManagerAdapter.sol
    CrossChainCredentialReceiver.sol
    EmergencyControls.sol
  test/
  script/
workflows/
  src/
    credential-verify.ts
    adapters/mock-zktls.ts
    adapters/reclaim.ts
    submit-credential.ts
  test/
packages/sdk/
  src/
    credentialStatus.ts
    policyClient.ts
    generated ABIs
apps/portal/
  src/
    holder status, credential request, renewal, revoke, and integrator demo views
docs/
  architecture.md
  privacy-model.md
  runbook.md
  threat-model.md
```

Use Foundry for contracts, TypeScript for CRE-style workflows and SDK code, and Chainlink Local for CCIP tests.

## 4. Credential Model

Required enums:

```solidity
enum CredentialStatus { Unknown, Pending, Valid, Expired, Revoked, Disputed }
enum ProviderStatus { Unknown, Active, Paused, Deprecated, Revoked }
```

Required credential key:

```solidity
bytes32 credentialKey = keccak256(abi.encode(ccid, credentialType, schemaVersion));
```

Required credential record:

```solidity
struct CredentialRecord {
    bytes32 ccid;
    bytes32 credentialType;
    bytes32 providerId;
    bytes32 evidenceHash;
    uint32 schemaVersion;
    uint64 issuedAt;
    uint64 expiresAt;
    uint64 updatedAt;
    uint64 nonce;
    CredentialStatus status;
}
```

Status handling rules:

- `Unknown`, `Pending`, `Expired`, `Revoked`, and `Disputed` must never pass access checks.
- `Valid` passes only when `block.timestamp <= expiresAt` and provider/schema are still accepted by the policy.
- Expiry can be lazy: view functions may report `Expired` even before an on-chain state transition occurs.
- Revocation increments nonce and must propagate cross-chain.

## 5. Contract Modules

### `ProviderRegistry`

Responsibilities:

- Register provider ID, adapter metadata URI, supported schema versions, and status.
- Pause or deprecate a provider without deleting history.
- Emit provider lifecycle events.

Required functions:

```solidity
function registerProvider(bytes32 providerId, string calldata metadataURI, uint32[] calldata schemaVersions) external;
function setProviderStatus(bytes32 providerId, ProviderStatus status) external;
function isProviderAccepted(bytes32 providerId, uint32 schemaVersion) external view returns (bool);
```

### `CredentialRegistry`

Responsibilities:

- Store credential records.
- Expose safe query helpers.
- Enforce status transitions.
- Prevent raw proof or PII storage.

Required functions:

```solidity
function getCredential(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion) external view returns (CredentialRecord memory);
function getStatus(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion) external view returns (CredentialStatus status, uint64 expiresAt, uint64 updatedAt);
function hasValidCredential(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion) external view returns (bool);
function revokeCredential(bytes32 ccid, bytes32 credentialType, uint32 schemaVersion, bytes32 reasonCode) external;
```

Required events:

```solidity
event CredentialIssued(bytes32 indexed ccid, bytes32 indexed credentialType, bytes32 indexed providerId, uint32 schemaVersion, uint64 expiresAt, bytes32 evidenceHash);
event CredentialRenewed(bytes32 indexed ccid, bytes32 indexed credentialType, uint32 schemaVersion, uint64 expiresAt, uint64 nonce);
event CredentialRevoked(bytes32 indexed ccid, bytes32 indexed credentialType, uint32 schemaVersion, uint64 nonce, bytes32 reasonCode);
event CredentialStatusChanged(bytes32 indexed ccid, bytes32 indexed credentialType, uint32 schemaVersion, CredentialStatus status, uint64 nonce);
```

### `CredentialBridge`

Responsibilities:

- Accept authorized workflow results.
- Validate provider, schema, TTL, nonce, and evidence hash.
- Update source registry.
- Initiate CCIP propagation.

Required workflow result:

```solidity
struct CredentialResult {
    bytes32 ccid;
    bytes32 credentialType;
    bytes32 providerId;
    bytes32 evidenceHash;
    uint32 schemaVersion;
    uint64 issuedAt;
    uint64 expiresAt;
    uint64 nonce;
    CredentialStatus status;
}
```

### `CrossChainCredentialReceiver`

Must validate router, source chain selector, source sender, payload type, schema version, nonce ordering, and provider acceptance. Stale nonce messages must be ignored and emitted as rejected.

### `PolicyManagerAdapter`

Required helper:

```solidity
function evaluate(bytes32 ccid, CredentialRequirement calldata requirement) external view returns (bool allowed, bytes32 reasonCode);
```

Reason codes must distinguish `UNKNOWN`, `PENDING`, `EXPIRED`, `REVOKED`, `DISPUTED`, `PROVIDER_PAUSED`, `SCHEMA_UNSUPPORTED`, and `STALE_DESTINATION`.

## 6. CRE Workflow Specification

### Workflow: `credential-verify`

Trigger:

- User request from portal or integrator demo.
- Manual trigger in tests.

Inputs:

```json
{
  "wallet": "0x...",
  "recoverySaltHash": "bytes32",
  "credentialType": "GITHUB_ACCOUNT_MIN_AGE_180D",
  "schemaVersion": 1,
  "providerId": "mock-zktls",
  "proofBundleRef": "fixture://github-account-age-valid"
}
```

Algorithm:

1. Load provider adapter by `providerId`.
2. Validate schema support and credential type.
3. Verify proof fixture or provider proof.
4. Compute `ccid` from wallet, recovery salt hash, and version.
5. Compute `evidenceHash` from normalized proof result, not raw transcript.
6. Emit `CredentialResult` with status `Valid` or `Disputed`; invalid proofs do not issue a credential.
7. Submit result to `CredentialBridge`.

Outputs:

```json
{
  "ccid": "bytes32",
  "credentialType": "bytes32",
  "providerId": "bytes32",
  "schemaVersion": 1,
  "status": "Valid",
  "issuedAt": 1710000000,
  "expiresAt": 1712592000,
  "nonce": 1,
  "evidenceHash": "bytes32"
}
```

Failure behavior:

- Invalid proof: no credential issue; return `INVALID_PROOF` reason.
- Unsupported schema: no credential issue; return `SCHEMA_UNSUPPORTED` reason.
- Provider timeout: mark request `Pending` in off-chain request log only; do not issue on-chain credential.
- Workflow submission failure: retry with same nonce and evidence hash.

## 7. CCIP Rules

Credential propagation payload:

```solidity
struct CredentialMessageV1 {
    bytes32 ccid;
    bytes32 credentialType;
    bytes32 providerId;
    bytes32 evidenceHash;
    uint32 schemaVersion;
    uint64 expiresAt;
    uint64 updatedAt;
    uint64 nonce;
    CredentialStatus status;
}
```

Receivers must reject:

- Unknown router.
- Unknown source chain selector.
- Unknown source sender.
- Unsupported payload type.
- Schema version not supported locally.
- Nonce less than or equal to current nonce.
- Credential update for a paused provider unless the update is revocation.

## 8. SDK and Portal Requirements

SDK must expose:

```ts
type CredentialState = 'unknown' | 'pending' | 'valid' | 'expired' | 'revoked' | 'disputed';
async function getCredentialStatus(ccid: string, credentialType: string): Promise<CredentialStatusResult>;
async function hasValidCredential(ccid: string, requirement: CredentialRequirement): Promise<boolean>;
```

Portal required views:

- Start credential request.
- Credential status and expiry.
- Renewal flow.
- Revocation request.
- Destination chain propagation status.
- Integrator demo that handles all statuses distinctly.

## 9. Test Plan

Required local commands once implementation exists:

```bash
forge fmt --check
forge test -vvv
forge test --match-path 'contracts/test/invariant/*' -vvv
pnpm --dir workflows test
pnpm --dir packages/sdk test
pnpm --dir apps/portal test
pnpm --dir apps/portal build
```

Required tests:

- Valid mock proof issues credential.
- Invalid proof does not issue credential.
- Raw account handle, transcript, proof, and PII are never emitted or stored.
- Expired credential fails `hasValidCredential`.
- Revoked credential fails and propagates revocation.
- Disputed credential fails access checks.
- Paused provider blocks new issuance.
- Unsupported schema rejected.
- Wrong CCIP router/source/sender rejected.
- Stale nonce ignored.
- Destination state exposes last-updated timestamp.
- SDK handles every credential state safely.

## 10. Implementation Milestones

1. Scaffold Foundry contracts, test harness, roles, and pause controls.
2. Implement `ProviderRegistry` and schema support tests.
3. Implement `CredentialRegistry` and status transition tests.
4. Implement `CredentialBridge` with authorized workflow submitter.
5. Implement CCIP sender/receiver using Chainlink Local simulator.
6. Implement `CCIDResolver` and recovery-salt MVP behavior.
7. Implement TypeScript mock provider workflow and fixtures.
8. Implement SDK query helpers and status-safe examples.
9. Implement minimal portal and integrator demo.
10. Add deployment scripts, `.env.example`, privacy model, and runbook.

## 11. Deployment and Configuration

Required config keys:

```text
SOURCE_CHAIN_SELECTOR=
DESTINATION_CHAIN_SELECTOR=
CCIP_ROUTER=
LINK_TOKEN=
CREDENTIAL_BRIDGE=
WORKFLOW_SUBMITTER=
PROVIDER_ADMIN=
SCHEMA_ADMIN=
EMERGENCY_GUARDIAN=
DEFAULT_TTL_SECONDS=
```

Never commit provider credentials, private keys, raw proofs, transcripts, account handles, or PII.

## 12. Definition of Done

The MVP is engineering-complete when:

- Mock zkTLS credential issue, renew, revoke, expire, and propagation flows pass locally.
- Source and destination registries agree after a CCIP propagation test.
- SDK and portal demonstrate safe handling of valid, expired, revoked, unknown, pending, and disputed states.
- No raw proof or PII appears in events, storage structs, fixtures intended for public repo use, or logs.
- Docs include setup, deploy, test, privacy, security, and recovery instructions.
