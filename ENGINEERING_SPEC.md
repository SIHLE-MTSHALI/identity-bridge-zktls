# Identity Bridge zkTLS Engineering Specification

**Status:** Full production engineering specification  
**Last reviewed:** 2026-06-17  
**Canonical product document:** `PRD.md`  
**Audience:** engineering team building the complete product through production release gates

## 1. Build Contract

This document defines the production engineering target for a privacy-preserving credential bridge that can support real providers, real integrators, and cross-chain credential state after security, privacy, and legal readiness gates are satisfied.

Engineers should not need product clarification for architecture, credential lifecycle, contract responsibilities, workflow shape, reason codes, tests, or release gates. Escalate only for real provider agreements, legal/compliance claims, production identity data, secrets, or mainnet deployment.

## 2. Product Delivery Model

| Release gate | Purpose | Required outcome |
| --- | --- | --- |
| Production Foundation | Build the complete architecture locally | Contracts, workflows, provider fixtures, SDK, portal, and tests prove the full system shape |
| Public Testnet Pilot | Prove cross-chain credential state safely | Testnet registries, CCIP propagation, monitoring, no real identity data |
| Provider-Backed Pilot | Connect reviewed real provider path | Privacy/legal review, provider adapter, revocation drills, incident runbooks |
| Production Network | Operate practical credential infrastructure | Multiple schemas, providers, chains, integrators, monitoring, and support processes |

## 3. Target Repository Architecture

```text
contracts/
  src/
    CredentialRegistry.sol
    CredentialBridge.sol
    ProviderRegistry.sol
    SchemaRegistry.sol
    CCIDResolver.sol
    PolicyManagerAdapter.sol
    CrossChainCredentialSender.sol
    CrossChainCredentialReceiver.sol
    EmergencyControls.sol
  test/
  script/
workflows/
  src/
    credential-verify.ts
    credential-renew.ts
    credential-revoke.ts
    adapters/mock-zktls.ts
    adapters/reclaim.ts
    adapters/tlsnotary.ts
  test/
packages/sdk/
  src/
    credentialStatus.ts
    policyClient.ts
    providerClient.ts
apps/portal/
  src/
    holder, integrator, provider, schema-admin, and audit views
docs/
  architecture.md
  privacy-model.md
  provider-adapter-guide.md
  operations-runbook.md
  incident-response.md
  threat-model.md
```

## 4. Required Contract System

### `SchemaRegistry`

Must register credential type, schema version, TTL, accepted providers, revocation mode, and policy metadata.

### `ProviderRegistry`

Must register provider ID, metadata URI, supported schema versions, status, pause/deprecation/revocation state, and health metadata.

### `CredentialRegistry`

Must store only minimal credential state:

```solidity
enum CredentialStatus { Unknown, Pending, Valid, Expired, Suspended, Revoked, Disputed }

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

Required invariant: unknown, pending, expired, suspended, revoked, and disputed credentials must never pass policy checks.

### `CredentialBridge`

Must accept authorized Chainlink workflow results, validate provider/schema/TTL/nonce/evidence, update source state, and trigger propagation.

### `CrossChainCredentialSender` and `CrossChainCredentialReceiver`

Must validate CCIP router, source chain, source sender, payload type, schema version, nonce, provider state, and destination freshness.

### `PolicyManagerAdapter`

Must provide safe reason-coded decisions:

```solidity
function evaluate(bytes32 ccid, CredentialRequirement calldata requirement) external view returns (bool allowed, bytes32 reasonCode);
```

Required reason codes include `UNKNOWN`, `PENDING`, `EXPIRED`, `SUSPENDED`, `REVOKED`, `DISPUTED`, `PROVIDER_PAUSED`, `SCHEMA_UNSUPPORTED`, and `STALE_DESTINATION`.

## 5. Chainlink Workflow System

### Workflow: `credential-verify`

Responsibilities:

1. Load provider adapter and schema policy.
2. Validate proof or provider result.
3. Compute CCID and evidence hash without exposing raw proof material.
4. Submit credential result.
5. Trigger CCIP propagation when destination chains are configured.

### Workflow: `credential-renew`

Must renew only after fresh provider verification. Expiring credentials should be visible before they fail access checks.

### Workflow: `credential-revoke`

Must propagate revocations across all configured chains and make revoked state fail immediately on the source chain.

Workflow logs must never contain raw PII, raw proof, raw TLS transcript, account handle, document, email, phone, or provider report.

## 6. Portal and SDK Requirements

Portal views:

- Holder credential request, status, expiry, renewal, revocation, and propagation view.
- Integrator policy builder and access-check simulator.
- Provider adapter status and schema compatibility.
- Audit view for credential lifecycle and provider/schema changes.

SDK requirements:

```ts
async function getCredentialStatus(ccid: string, credentialType: string): Promise<CredentialStatusResult>;
async function hasValidCredential(ccid: string, requirement: CredentialRequirement): Promise<boolean>;
async function explainCredentialDecision(ccid: string, requirement: CredentialRequirement): Promise<PolicyDecision>;
```

## 7. Testing and Verification

Required checks once implementation exists:

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

- Credential issue, renew, suspend, revoke, expire, dispute, and query.
- Invalid proof and unsupported provider rejection.
- Provider pause and schema deprecation behavior.
- CCIP replay, stale nonce, wrong source, wrong sender, and wrong schema rejection.
- Destination freshness and local policy checks.
- No raw sensitive data in storage, events, logs, fixtures, or SDK outputs.
- SDK safe handling of every status.

## 8. Production Operations Requirements

Before real provider or identity data:

- Privacy review and data flow map.
- Provider agreement and adapter review.
- Threat model and external security review.
- Key management and timelock runbook.
- Monitoring for provider status, credential volume, failed propagation, stale destination state, and revocation lag.
- Incident response process for provider compromise, schema bug, privacy leak, and false credential issuance.

## 9. Configuration

```text
SOURCE_CHAIN_SELECTOR=
DESTINATION_CHAIN_SELECTORS=
CCIP_ROUTER=
LINK_TOKEN=
WORKFLOW_SUBMITTER=
PROVIDER_ADMIN=
SCHEMA_ADMIN=
EMERGENCY_GUARDIAN=
DEFAULT_TTL_SECONDS=
PROVIDER_CONFIG_URI=
PRIVACY_POLICY_URI=
```

Never commit provider credentials, private keys, raw proofs, transcripts, account handles, documents, or PII.

## 10. Definition of Done for Full Product

The product is not complete until:

- The complete credential lifecycle works on source and destination chains.
- Multiple credential schemas and provider adapters are supported or cleanly pluggable.
- SDK and portal guide integrators away from unsafe status handling.
- Privacy tests prove sensitive data exclusion.
- Monitoring, runbooks, and incident response exist.
- Legal/compliance claims are reviewed separately before any regulated use case is marketed.
