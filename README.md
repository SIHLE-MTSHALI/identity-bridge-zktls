# Identity Bridge zkTLS

Privacy-preserving credential infrastructure for proving web2 attributes on-chain without publishing the underlying identity data.

## Status

This repository is in product and architecture design. The canonical product specification is [PRD.md](./PRD.md). Implementation work should follow the PRD requirements, privacy constraints, verification plan, and launch criteria before any production claims are made.

## Why It Exists

Protocols increasingly need identity and eligibility signals: KYC status, accreditation, social reputation, employment, account ownership, or other web2 attributes. Most approaches either leak sensitive data, rely on centralized APIs, or force users to re-verify separately for every app and chain.

Identity Bridge zkTLS defines a Chainlink-native credential bridge where users prove an attribute through a supported zkTLS provider, verification is orchestrated through CRE, sensitive proof handling stays off public chain state, and applications receive only the credential status they need.

## Product Shape

1. A protocol requests a credential such as KYC status, GitHub threshold, employment status, or custom provider claim.
2. The user generates a proof with a supported zkTLS provider.
3. Chainlink CRE routes the proof through the appropriate adapter.
4. Confidential compute is used as the privacy boundary where supported.
5. The registry stores only minimal credential status bound to a cross-chain identity.
6. CCIP propagates credential status to destination chains.
7. Integrators query local credential state and handle valid, expired, revoked, disputed, unknown, and pending states explicitly.

## Core Design Goals

- No raw PII, raw TLS transcript, account handle, document, or provider report in on-chain state or events.
- Provider-neutral adapter pattern.
- Credential expiry, renewal, and revocation as first-class product flows.
- Local reads for integrators after CCIP propagation.
- Clear developer docs that explain what a credential proves and what it does not prove.

## Planned Architecture

| Layer | Responsibility |
| --- | --- |
| Credential registry | Credential status, expiry, schema version, revocation state |
| Provider registry | Supported zkTLS providers and schema compatibility |
| CRE workflow | Proof routing, validation, result submission |
| Confidential compute | Sensitive proof/provider-response boundary where available |
| CCIP sender/receiver | Cross-chain credential propagation |
| Policy adapter | Safe helper for integrator access checks |

## Documentation

- [PRD.md](./PRD.md) - canonical product requirements, workflows, architecture, privacy model, risks, verification, and launch criteria.
- [ENGINEERING_SPEC.md](./ENGINEERING_SPEC.md) - implementation-ready build contract with MVP decisions, contract surfaces, workflow I/O, tests, milestones, and definition of done.
- [PRODUCT_REQUIREMENTS_DOC.md](./PRODUCT_REQUIREMENTS_DOC.md) - compatibility pointer to the canonical PRD.

## Implementation Notes

The first implementation should support a small number of credential schemas and at least one zkTLS provider end to end before expanding. Legal or compliance claims must be reviewed separately; this repository should describe architecture and trust assumptions, not promise regulatory compliance.

## Security and Privacy Posture

The system is security-sensitive because it handles identity-adjacent proofs. Before public testnet, the repository should include proof-handling tests, no-log privacy checks, CCIP replay tests, revocation tests, static analysis, and documentation proving raw PII cannot enter storage or events.

## Chainlink References

- CRE: https://docs.chain.link/cre
- CRE TypeScript WASM runtime: https://docs.chain.link/cre/concepts/typescript-wasm-runtime
- CCIP: https://docs.chain.link/ccip
- Automation: https://docs.chain.link/chainlink-automation

## License

MIT. See [LICENSE](./LICENSE).
