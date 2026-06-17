# Identity Bridge zkTLS PRD

**Status:** Full production product specification  
**Last reviewed:** 2026-06-17  
**Primary audience:** protocol integrators, privacy engineers, compliance teams, smart contract engineers, Chainlink reviewers  
**Product ambition:** build practical privacy-preserving credential infrastructure that lets users prove useful web2 or compliance attributes across chains without exposing raw identity data.

## 1. Product Thesis

Identity Bridge zkTLS turns verified off-chain attributes into portable, privacy-preserving on-chain credentials. Users prove attributes through supported zkTLS or compliance providers. Chainlink workflows coordinate verification, confidential processing boundaries protect sensitive proof material where available, and CCIP propagates credential state across chains.

The target is not a demo. The target is a production-grade identity and eligibility layer that DeFi protocols, DAOs, marketplaces, and RWA issuers can integrate when they need durable, revocable, minimally revealing credentials.

## 2. Real-World Problem

Protocols increasingly need identity and eligibility signals, but common approaches either leak sensitive data, depend on one centralized API, force repeated verification across apps, or create credentials that are hard to revoke and hard to use across chains.

The product must solve for:

1. Attribute verification without public PII exposure.
2. Provider-neutral credential issuance.
3. Clear credential expiry, renewal, revocation, and dispute states.
4. Cross-chain credential portability through local readable state.
5. Safe integration defaults that prevent protocols from treating stale or unknown credentials as valid.

## 3. Product Principles

- Minimal disclosure: expose only the credential state required by an application.
- Provider neutrality: adapters can support Reclaim-style, TLSNotary-style, KYC/KYB, and future proof providers.
- No raw PII on public chain state or public logs.
- Every credential has a lifecycle: issue, active, renew, expire, suspend, revoke, dispute.
- Cross-chain state is eventually consistent and must expose freshness.
- Legal and compliance claims require separate review; the product provides infrastructure, not legal guarantees.

## 4. Full Product Scope

### Core Production Capabilities

- Credential schema registry with type, version, TTL, accepted providers, policy metadata, and revocation rules.
- Provider registry with adapter metadata, schema compatibility, status, pause, deprecation, and revocation.
- Chainlink workflow orchestration for proof intake, provider routing, validation, result construction, and submission.
- Confidential processing boundary for raw proof/provider material where supported.
- Credential registry storing only minimal status, expiry, provider ID, schema version, evidence hash, nonce, and CCID binding.
- CCIP propagation of credential state to destination chain registries.
- Policy adapter for safe integrator checks with reason codes.
- Holder portal for request, status, renewal, revocation, and propagation visibility.
- Integrator SDK and examples for Solidity and TypeScript.
- Privacy model, provider onboarding guide, threat model, and incident response plan.

### Scale and Ecosystem Capabilities

- Multiple credential classes: account ownership, account age, contribution history, proof of uniqueness, accreditation status, jurisdiction class, DAO membership, partner-specific eligibility.
- Multi-provider redundancy and provider-specific risk controls.
- Credential recovery and account abstraction support.
- Issuer-controlled, user-controlled, and governance-controlled revocation modes by schema.
- Analytics for credential freshness, propagation state, provider health, and integrator usage.

## 5. Explicit Boundaries

The product must not store raw documents, legal names, account handles, raw TLS transcripts, raw proofs, provider reports, tax identifiers, phone numbers, or email addresses in public chain state or events.

The product must not claim GDPR, CCPA, MiCA, securities-law, KYC, or AML compliance without qualified legal review and jurisdiction-specific documentation.

## 6. User Journeys

### Credential Holder

1. User selects a credential requested by an application.
2. User chooses a supported provider.
3. User completes proof generation off-chain.
4. Chainlink workflow validates the proof and emits a minimal credential result.
5. Registry stores credential state bound to the user's CCID.
6. Credential state propagates to selected chains.
7. User can renew, revoke, or inspect freshness and destination status.

### Protocol Integrator

1. Integrator reviews supported credential schemas and trust assumptions.
2. Integrator configures accepted credential type, schema version, provider set, and freshness policy.
3. Integrator calls a policy adapter or registry view.
4. Integrator handles `valid`, `expired`, `revoked`, `unknown`, `pending`, and `disputed` distinctly.
5. Integrator monitors credential update and revocation events.

### Provider

1. Provider implements the adapter contract/interface and test vectors.
2. Provider documents proof format, freshness, privacy assumptions, and failure modes.
3. Governance or schema admin approves provider support.
4. Provider health and status remain visible to integrators.

## 7. Functional Requirements

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| FR-001 | Credential schema registry | Schemas define type, version, TTL, accepted providers, and revocation mode |
| FR-002 | Provider adapter model | New providers can be added without changing core credential storage |
| FR-003 | Minimal storage | Registry stores no raw PII, proof, transcript, account handle, or provider report |
| FR-004 | Credential lifecycle | Issue, renew, expire, suspend, revoke, dispute, and propagation states are explicit |
| FR-005 | Safe policy checks | Integrators receive reason-coded allow/deny decisions |
| FR-006 | CCID binding | Credentials bind to a cross-chain identity concept, not only one wallet address |
| FR-007 | CCIP propagation | Destination registries validate source and expose freshness |
| FR-008 | Provider risk controls | Provider pause/deprecation/revocation affects new issuance and policy decisions |
| FR-009 | Privacy audits | Tests and docs prove raw sensitive data is not stored or emitted |
| FR-010 | Developer experience | SDK examples compile and demonstrate safe status handling |

## 8. Chainlink Architecture

- Chainlink CRE coordinates proof workflows, provider adapters, consensus where needed, and result submission.
- Confidential compute is the preferred boundary for sensitive proof/provider processing where supported.
- CCIP propagates credential state to destination chains.
- Automation supports expiry checks, renewal notifications, revocation propagation, and provider health tasks.

Design constraints:

- Workflows must never log raw proof material or PII.
- CCIP receivers must validate router, source chain, source sender, payload type, schema version, and nonce.
- Destination state must expose last update time and source chain.
- SDKs must make unsafe defaults hard.

## 9. Security and Privacy Requirements

| Risk | Required mitigation |
| --- | --- |
| PII leakage | No raw sensitive fields in storage, events, logs, fixtures, or docs |
| Provider compromise | Provider pause, short TTLs, schema versioning, revocation, and monitoring |
| Credential replay | Bind result to CCID, schema, nonce, chain context, provider, and expiry |
| Stale destination state | Freshness timestamps and strict policy checks |
| Integrator misuse | Reason-coded policy adapter and SDK warnings |
| Governance abuse | Timelocked schema/provider changes and public events |
| Legal overclaim | Clear docs separating infrastructure from legal compliance |

## 10. Production Readiness Gates

### Gate 1: Production Foundation

- Core contracts, workflows, SDK, portal, and tests are implemented.
- At least two credential schemas and one fixture-backed provider work end to end.
- Privacy tests prove raw sensitive data is not stored or emitted.

### Gate 2: Public Testnet Pilot

- Source and destination testnet registries propagate credential state.
- Integrator example handles all credential states safely.
- Monitoring, runbooks, and provider health checks exist.

### Gate 3: Provider-Backed Pilot

- At least one real provider adapter is reviewed and tested.
- Legal/privacy review is complete for the supported credential class.
- Revocation, renewal, incident response, and provider-pause drills are complete.

### Gate 4: Production Network

- Multiple credential schemas, providers, chains, and integrators are supported.
- Credential lifecycle, analytics, support, and audit exports are operational.
- Security review and ongoing monitoring are in place.

## 11. Success Metrics

| Metric | Target |
| --- | --- |
| Raw PII in chain state/events/logs | 0 tolerated |
| Revoked or expired credential allowed | 0 tolerated |
| Stale destination state presented as valid | 0 tolerated |
| Provider pause propagation | Visible to integrators and holders |
| Integrator time to first safe check | Under 20 minutes from docs |
| Credential lifecycle auditability | Issue, renew, revoke, expire, and propagate events visible |

## 12. Documentation Requirements

Before public release, the repository must include architecture, privacy model, provider adapter guide, SDK guide, deployment guide, operations runbook, incident response plan, threat model, and audit readiness checklist.

## 13. References

- Chainlink CRE: https://docs.chain.link/cre
- Chainlink CRE TypeScript WASM runtime: https://docs.chain.link/cre/concepts/typescript-wasm-runtime
- Chainlink CCIP: https://docs.chain.link/ccip
- Chainlink Automation: https://docs.chain.link/chainlink-automation
