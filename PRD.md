# Identity Bridge zkTLS PRD

**Status:** Product design ready for implementation  
**Last reviewed:** 2026-06-17  
**Primary audience:** protocol integrators, privacy engineers, compliance teams, smart contract engineers, Chainlink reviewers  
**Public-readiness goal:** define a credible privacy-preserving credential bridge without overstating deployment, regulatory, or cryptographic guarantees.

## 1. Product Vision

Identity Bridge zkTLS turns verified web2 attributes into privacy-preserving on-chain credentials. A user proves an attribute through a supported zkTLS provider. Chainlink CRE orchestrates verification. Confidential compute isolates sensitive proof material. The protocol stores only a credential result bound to a Chainlink ACE cross-chain identity and propagates that result to supported chains through CCIP.

The product goal is simple: prove eligibility without publishing identity data.

## 2. Problem

DeFi, DAO, RWA, and marketplace protocols need identity and eligibility signals, but current approaches create unacceptable tradeoffs:

- On-chain KYC leaks sensitive data or permanent identifiers.
- Centralized identity APIs create single points of failure and vendor lock-in.
- zkTLS providers have fragmented SDKs, proof formats, and verification contracts.
- Credentials verified on one chain or app rarely transfer cleanly to another.
- Credential expiry, revocation, and renewal are often afterthoughts.

Identity Bridge zkTLS provides a common product and developer interface for these proofs while keeping private data outside public chain state.

## 3. Target Users

| Persona | Job to be done | Success condition |
| --- | --- | --- |
| DeFi protocol developer | Gate access based on verified attributes | Can call one contract function and receive a boolean |
| User | Prove an attribute without exposing raw account or identity data | Completes verification and receives a portable credential |
| RWA issuer | Enforce compliance rules without storing investor PII on-chain | Can evaluate policy from credential status and freshness |
| DAO operator | Reduce sybil risk while preserving voter privacy | Can define credential-gated proposals or voting rules |
| zkTLS provider | Make proofs usable across more protocols | Can implement one adapter and reach multiple chains |

## 4. Product Principles

- Boolean-first privacy: only the minimum result needed by an application should be exposed.
- Provider neutrality: Reclaim, TLSNotary, and future providers should plug into the same adapter pattern.
- No permanent PII on-chain: do not store raw identifiers, raw proofs, names, documents, account handles, or API responses.
- Clear expiry: every credential must have a TTL and renewal path.
- Local reads: applications should query credential state on their own chain after CCIP propagation.
- Revocation is a first-class product feature, not an admin workaround.

## 5. Scope

### MVP Scope

- Credential type registry with schemas, provider mappings, thresholds, TTLs, and revocation policy.
- Provider adapter interface for zkTLS proof verification workflows.
- CRE workflow for proof intake, provider routing, validation, and result submission.
- Confidential compute boundary for raw proof handling where available.
- Credential registry contract storing credential hash, CCID, status, expiry, issuer/provider, and revocation state.
- CCIP propagation of credential status to destination chain registries.
- Simple integration SDK examples for Solidity and TypeScript.
- Public documentation for privacy model, trust boundaries, and limitations.

### Non-Goals for MVP

- Becoming a KYC provider.
- Storing user documents, account handles, raw TLS transcripts, or legal identity data.
- Supporting every zkTLS provider on day one.
- Proving unique humanity as a standalone identity product.
- Making legal claims of GDPR, CCPA, MiCA, or securities-law compliance without external counsel review.

## 6. User Journeys

### Credential Holder Journey

1. User selects a credential type requested by a protocol.
2. User chooses a supported zkTLS provider.
3. User completes provider-specific proof generation.
4. CRE workflow validates the proof and computes the credential result.
5. The on-chain registry stores a credential hash and status bound to the user's CCID.
6. CCIP propagates the credential to selected chains.
7. User can view status, expiry, supported chains, and revocation controls.

### Integrator Journey

1. Integrator reviews credential schemas and trust assumptions.
2. Integrator configures accepted credential types, minimum freshness, and destination chains.
3. Integrator calls `hasCredential(ccid, credentialId)` or an equivalent policy helper.
4. Integrator handles false, expired, revoked, and unknown states distinctly.
5. Integrator monitors registry events for changes and revocations.

## 7. Functional Requirements

| ID | Requirement | Priority | Acceptance criteria |
| --- | --- | --- | --- |
| FR-001 | Register credential schemas | P0 | Admin can define type, parameters, TTL, provider set, and revocation mode |
| FR-002 | Bind credentials to CCID | P0 | Credential state is keyed by CCID and credential ID, not only wallet address |
| FR-003 | Verify zkTLS proof through adapter | P0 | Provider-specific proof path returns deterministic valid/invalid result |
| FR-004 | Store minimal credential state | P0 | Registry stores no raw PII, raw proof, account handle, or transcript |
| FR-005 | Query credential status | P0 | Integrators can distinguish valid, expired, revoked, unknown, and pending |
| FR-006 | Propagate via CCIP | P0 | Destination registry accepts only validated messages from authorized source |
| FR-007 | Support expiry and renewal | P0 | Expired credentials fail access checks until renewed |
| FR-008 | Support revocation | P0 | Authorized revocation changes state and propagates to destination chains |
| FR-009 | Support provider addition | P1 | New provider can be registered without changing core registry storage layout |
| FR-010 | Provide SDK examples | P1 | Solidity and TypeScript examples compile and show expected status handling |
| FR-011 | Emit audit events | P0 | Issue, renew, revoke, expire, propagate, and provider changes emit indexed events |

## 8. Chainlink Architecture

- CRE coordinates proof verification workflows and provider adapter execution.
- Confidential compute is the intended boundary for raw proof material and provider response handling where supported.
- ACE provides the cross-chain identity concept used to decouple credentials from a single wallet address.
- CCIP propagates credential status updates to supported destination chains.
- Automation monitors credential expiry and schedules renewal reminders or expiration state updates.

Design constraints:

- No CRE workflow should log raw proof material or PII.
- CCIP receivers must validate router, source chain, source sender, message type, nonce, and credential schema version.
- Destination registries must treat propagated credentials as eventually consistent and expose last-updated timestamps.
- Integrators must be able to opt into strict freshness windows.

## 9. Smart Contract Architecture

| Contract | Responsibility |
| --- | --- |
| `CredentialRegistry` | Stores credential status, expiry, issuer, schema version, and revocation state |
| `CredentialBridge` | Receives CRE verification results and initiates CCIP propagation |
| `ProviderRegistry` | Manages supported zkTLS providers and schema compatibility |
| `CCIDResolver` | Maps wallets or account abstractions to CCIDs and recovery state |
| `PolicyManagerAdapter` | Helper for integrators to evaluate credential requirements |
| `CrossChainCredentialReceiver` | Receives and validates CCIP credential updates |
| `EmergencyControls` | Pauses issue, renew, revoke, or propagation actions independently |

## 10. Credential State Model

Suggested status enum:

- `UNKNOWN`: no credential exists.
- `PENDING`: verification started but not finalized.
- `VALID`: credential accepted and within TTL.
- `EXPIRED`: credential passed TTL and must be renewed.
- `REVOKED`: credential was explicitly revoked and cannot be used.
- `DISPUTED`: credential is under review due to provider or abuse signal.

Applications must not treat unknown, expired, revoked, or disputed as equivalent. The SDK should make unsafe defaults hard.

## 11. UX and Developer Experience

The project should expose three surfaces:

- User portal: prove credential, view status, renew, revoke, export proof receipt.
- Integrator docs: contract addresses, supported credentials, query examples, status handling, threat model.
- Provider docs: adapter interface, schema registration, test vectors, privacy requirements.

Public docs must state what the system does not prove. Example: a GitHub-stars credential proves that a supported provider attested to a threshold at a time; it does not prove user quality, legal identity, or future behavior.

## 12. Security and Privacy Requirements

| Risk | Mitigation |
| --- | --- |
| PII leakage | Raw proof material stays off-chain; no raw identifiers in storage or events |
| Provider compromise | Provider allowlist, per-provider pause, schema versioning, short TTLs |
| Credential replay | Bind proof result to CCID, chain ID, schema, nonce, and expiry |
| Cross-chain spoofing | Validate CCIP router, source chain, source sender, schema version, and nonce |
| Stale credentials | TTL enforcement and freshness checks in policy helpers |
| Governance abuse | Timelocked provider/schema changes and public events |
| Integrator misuse | SDK exposes safe status handling and warnings for stale destination state |

## 13. Verification Plan

Required checks before testnet launch:

- Unit tests for credential issue, query, expiry, renew, revoke, and provider changes.
- Fuzz tests for credential hashes, schema parameters, TTL boundaries, and status transitions.
- Invariant tests: no raw PII fields, revoked never returns valid, expired never returns valid, destination updates are monotonic by nonce.
- CCIP local simulator tests for propagation, replay attempts, wrong source, wrong schema, and stale messages.
- CRE simulation tests for valid proof, invalid proof, malformed proof, unsupported provider, provider timeout, and no-log privacy assertions.
- Static analysis with no unresolved high or critical findings.

## 14. Launch Criteria

The project is ready for public testnet when:

- At least two credential types and one zkTLS provider are implemented end to end.
- One source chain and two destination chains can issue and propagate credential status.
- Integrator example contract demonstrates valid, expired, revoked, and unknown handling.
- Privacy documentation is complete and avoids legal overclaims.
- Security review confirms no raw proof or PII is emitted, stored, or committed.

## 15. Success Metrics

| Metric | Target |
| --- | --- |
| Credential query latency | Local chain read under normal RPC latency |
| Cross-chain propagation visibility | 100% of messages tracked by message ID and status |
| Raw PII in on-chain state/events | 0 tolerated |
| Revocation propagation test coverage | Source and destination chains covered |
| Integrator time to first query | Under 15 minutes from docs |

## 16. Open Questions

- Which zkTLS provider should be first for MVP based on available testnet tooling?
- What credential schemas are most compelling for launch: GitHub, KYC-provider status, employment, DAO membership, or exchange account standing?
- How should CCID recovery work when a user loses all wallets associated with an identity?
- What legal review is required before marketing the system for RWA or KYC use cases?
- Should revocation be issuer-controlled, user-controlled, governance-controlled, or schema-specific?

## 17. References

- Chainlink CRE: https://docs.chain.link/cre
- Chainlink CRE TypeScript WASM runtime: https://docs.chain.link/cre/concepts/typescript-wasm-runtime
- Chainlink CCIP: https://docs.chain.link/ccip
- Chainlink Automation: https://docs.chain.link/chainlink-automation
