# Security Policy

## Project Status

Identity Bridge zkTLS is a pre-release Chainlink blueprint. It is not audited, not deployed for production use, and must not be used to process real identity, compliance, or credential data.

No paid bug bounty is active yet. Do not infer reward eligibility unless a future version of this file links to an official bounty program.

## Reporting a Security Issue

Do not open a public issue with exploit details, private keys, API keys, raw proofs, TLS transcripts, account handles, PII, or proof-of-concept code.

Preferred reporting path before public launch:

1. Use GitHub private vulnerability reporting if it is enabled for this repository.
2. If private reporting is not enabled, open a minimal public issue saying only that a private security report is available and ask the maintainer to enable a private channel.
3. Do not disclose technical details publicly until the issue is acknowledged and a disclosure plan is agreed.

Maintainer response targets are best-effort during pre-release: acknowledge within 7 days and provide an initial severity assessment when enough detail is available.

## Supported Versions

| Version | Supported |
| --- | --- |
| Public releases | None yet |
| `main` and active PR branches | Best-effort review only |

## In Scope

- Credential schema registry, provider mappings, TTLs, renewal, and revocation policy.
- zkTLS provider adapter boundaries and proof verification assumptions.
- CRE proof intake, provider routing, validation, and result submission.
- Confidential-compute boundaries for raw proof material.
- Credential registry storage, status transitions, expiry, and revocation state.
- CCID binding, wallet recovery assumptions, and credential propagation through CCIP.
- Integrator helper behavior for valid, expired, revoked, unknown, pending, and disputed states.

## Out of Scope

- Social engineering, phishing, or physical attacks.
- Vulnerabilities requiring access to maintainer devices or accounts.
- Findings against third-party zkTLS providers unless they create an integration-specific failure in this repository.
- Legal compliance opinions or regulatory classifications.
- Findings against hypothetical production deployments that do not exist.
- Reward requests when no bounty program has been announced.

## High-Risk Areas

| Risk | Expected mitigation direction |
| --- | --- |
| PII or raw proof leakage | No raw identifiers, documents, transcripts, provider responses, or proofs in chain state, events, logs, or commits |
| Provider compromise | Provider allowlist, per-provider pause, schema versioning, TTLs, and revocation path |
| Credential replay | Bind proof result to CCID, schema, nonce, chain context, and expiry |
| Cross-chain spoofing | Validate CCIP router, source chain, source sender, schema version, nonce, and message type |
| Stale credentials | TTL enforcement, freshness checks, and explicit status handling |
| Integrator misuse | SDKs must distinguish false, expired, revoked, unknown, pending, and disputed states |
| Governance abuse | Timelocked provider/schema changes and public events |

## Secure Development Rules

- Never commit secrets, private keys, API keys, access tokens, raw proofs, raw TLS transcripts, provider responses, account handles, or PII.
- Use placeholders in `.env.example` files only.
- Before public launch, verify repository remotes, config, docs, and history do not contain embedded credentials.
- Treat provider responses, user-supplied proof material, adapter payloads, and CCIP messages as attacker-controlled.
- Add tests for invalid proofs, replay, stale nonce, unsupported provider, revoked provider, expired credentials, wrong CCIP sender, and destination freshness.
- Keep audit, bounty, provider partnership, and legal-compliance claims out of docs until they are true and linked.

## Audit Status

No external audit has been completed. Any future audit report should be linked here with date, scope, commit hash, and unresolved findings.

## Disclosure Policy

Coordinated disclosure is preferred. Public disclosure should wait until a fix is available or a mutually agreed disclosure date is reached, unless there is active exploitation or user safety risk that requires faster notice.