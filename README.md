# Identity Bridge zkTLS

Privacy-preserving credential infrastructure: prove something about yourself once,
then let applications check a *status* rather than receive your *data*.

A credential here answers "is this KYC check current?" — never "what is this
person's name?". Integrators get an allow/deny decision with a reason code, so
they can act on the difference between a revoked credential and a week-old copy.

> **Status: implemented core, pre-release.** The contracts, workflow logic, and SDK
> below are built and tested. There is **no external audit, no deployed
> environment, and no real provider integration**. See [What is and is not
> built](#what-is-and-is-not-built) before drawing conclusions, and
> [Legal boundary](#legal-boundary) before any regulated use.

## The problem this solves

Protocols need identity and eligibility signals. The usual approaches either leak
the underlying data, hard-depend on one centralized API, force re-verification per
application, or produce credentials that are hard to revoke and impossible to use
across chains.

This system takes a narrower position: **applications should receive a decision,
not the evidence.** The holder proves an attribute through a zkTLS-style provider;
what reaches the chain is a salted commitment and a lifecycle status.

## How it works

```
holder                Chainlink CRE workflow              contracts              integrator
  |                          |                              |                        |
  |  proof (off-chain)       |                              |                        |
  |------------------------->|                              |                        |
  |                    provider adapter                      |                        |
  |                    validates proof                       |                        |
  |                    commits: CCID + evidence hash         |                        |
  |                          |--- submitCredentialResult -->|                        |
  |                          |                              |  CredentialBridge      |
  |                          |                              |  re-derives CCID,      |
  |                          |                              |  re-checks policy      |
  |                          |                              |        |               |
  |                          |<--------- CCIP replica -------------------------- |
  |                          |                              |        |               |
  |                          |                              |  evaluate(ccid, req) ->|  allow / deny
  |                          |                              |  + reason code         |  + reason
```

Raw proof material never leaves the workflow. What reaches the chain is a hash.

## Quick start

Requires [Foundry](https://getfoundry.sh) and Node 20+.

```bash
pnpm install
forge install                 # if lib/ is missing
pnpm run verify               # fmt, build, privacy check, all tests
```

Individual gates:

```bash
forge fmt --check
forge build
forge test -vvv
forge test --match-path 'contracts/test/invariant/*' -vvv
pnpm --dir packages/sdk test
pnpm --dir workflows test
node scripts/check-no-dynamic-storage.mjs
```

## Using the SDK

```ts
import { createPublicClient, http } from "viem";
import { explainCredentialDecision, withFreshness, anyVersion, shouldRetry } from "@identity-bridge/sdk";

const decision = await explainCredentialDecision(client, policyAdapter, ccid, withFreshness(anyVersion(KYC_TYPE)));

if (decision.allowed) {
  // ...
} else if (decision.reasonName === "EXPIRED") {
  // Ask the holder to renew. Do NOT retry.
} else if (shouldRetry(decision.reasonName)) {
  // Pending or a stale replica: worth another look shortly.
} else {
  // Escalate: paused provider, dispute, schema withdrawn, system paused.
}
```

**Branch on `decision.allowed`, never on `record.status === "Valid"`.** A `Valid`
status means the credential is live *here*. It says nothing about a provider that
was paused since, a schema this chain no longer supports, or a replica that is a
week stale. `evaluate` considers all of that; the status does not.

## Reason codes

Every decision carries a reason, and the reason is the point — "denied" is not
actionable.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `OK` | Allowed | Proceed |
| `PENDING` | Verification in flight | Retry shortly |
| `UNKNOWN` | No credential exists | Start verification |
| `EXPIRED` | Past `expiresAt` | Holder renews |
| `REVOKED` | Permanently withdrawn | Holder re-verifies; do not retry |
| `SUSPENDED` | Temporarily blocked by issuer | Escalate to issuer |
| `DISPUTED` | Contested | Escalate; deny until resolved |
| `PROVIDER_PAUSED` | Provider not `Active` | Escalate to operator |
| `SCHEMA_UNSUPPORTED` | Schema deprecated or unknown here | Escalate |
| `STALE_DESTINATION` | Replica older than tolerated | Retry after propagation |
| `CREDENTIAL_TYPE_MISMATCH` | Wrong credential type | Fix your requirement |
| `SCHEMA_VERSION_UNSUPPORTED` | Wrong version | Fix your requirement |
| `PROVIDER_NOT_ACCEPTED` | Provider not in your allowlist | Fix your requirement |
| `SYSTEM_PAUSED` | System paused; all decisions denied | Escalate immediately |

Precedence is fixed and documented on `PolicyManagerAdapter`. One consequence worth
knowing: `REVOKED` outranks `EXPIRED`, because revocation is the more deliberate
signal.

## Design commitments, and how each is enforced

These are not aspirations. Each has a test that fails if the property is broken,
and each was verified by deliberately breaking the property and confirming the
test caught it.

| Commitment | Enforced by |
| --- | --- |
| Only `Valid` ever yields `allowed == true` | `invariant_onlyValidCredentialIsAllowed` |
| `Revoked` is terminal | `invariant_revocationIsTerminal` |
| Expiry and nonce never move backwards | `invariant_expiryNeverDecreases`, `invariant_nonceNeverDecreases` |
| A paused system denies everyone | `invariant_pauseFailsClosed` |
| No readable text in credential storage | `NoPIIStorage.t.sol` + `scripts/check-no-dynamic-storage.mjs` |
| A `string` field cannot be added to a record | `scripts/check-no-dynamic-storage.mjs` (walks the compiled layout) |
| Raw material cannot reach a workflow log | `safeLog` throws; `privacy.test.ts` |
| Replay, wrong sender, wrong chain, wrong schema rejected | `CrossChainPropagation.t.sol` |
| Workflow CCID matches the on-chain CCID | `ccid-parity.test.ts`, against contract-generated vectors |

Two of these deserve a note, because they were the ones most likely to be
vacuous:

- **The privacy storage test alone was not enough.** An unused `string` field
  occupies no storage, so a runtime scan passed even with `string legalName` added
  to `CredentialRecord`. The layout checker closes that gap by inspecting the
  compiled storage layout instead of runtime values.
- **The invariant suite initially had no teeth.** With purely random inputs the
  fuzzer minted new credentials and rarely revisited an existing one, so
  `revoke → resume` was essentially never exercised and the terminality invariant
  passed regardless. Adding a ghost-variable key pool and compound actions made it
  catch a deliberately introduced `Revoked → Valid` transition.

## What is and is not built

**Built and tested:**

- 9 contracts: credential registry, bridge, provider registry, schema registry, CCID
  resolver, policy adapter, CCIP sender/receiver, emergency controls.
- Full credential lifecycle: issue, renew, suspend, resume, dispute, revoke, expire,
  query — with lazy expiry that does not depend on a keeper being alive.
- Cross-chain propagation with replay, wrong-sender, wrong-chain, wrong-schema,
  stale-nonce, and payload-tamper defences.
- 3 CRE workflows with 3 provider adapters, and a runtime privacy guard on logs.
- Typed SDK with reason-code decoding and retry-category helpers.
- 193 tests: 94 Foundry (incl. 7 stateful invariants), 26 SDK, 73 workflow.

**Not built:**

- `apps/portal` — the React portal in the spec's tree does not exist. The views are
  specified; the UI is not written.
- Real provider integrations. `reclaim.ts` and `tlsnotary.ts` define the boundary,
  the failure semantics, and the privacy handling, and throw rather than pretend to
  be live. Supplying a transport is all that is missing.
- A CCIP testnet deployment. The router is exercised through a mock that
  reproduces the properties the receiver depends on; the real router's guarantees
  are treated as a trusted external dependency in the threat model.
- Auditing, key management, and operational runbooks that have been *exercised* as
  opposed to merely written.

## Documentation

| Document | Contents |
| --- | --- |
| [PRD.md](./PRD.md) | Canonical product requirements (FR-001 … FR-010) |
| [ENGINEERING_SPEC.md](./ENGINEERING_SPEC.md) | Build contract, contract surfaces, verification plan |
| [docs/architecture.md](./docs/architecture.md) | Components, trust boundaries, deployment cycle |
| [docs/privacy-model.md](./docs/privacy-model.md) | What is stored, what is not, and what is proved |
| [docs/threat-model.md](./docs/threat-model.md) | Assets, adversaries, and what each control does *not* cover |
| [docs/provider-adapter-guide.md](./docs/provider-adapter-guide.md) | Writing and reviewing an adapter |
| [docs/operations-runbook.md](./docs/operations-runbook.md) | Provider outage, stale propagation, revocation lag |
| [docs/incident-response.md](./docs/incident-response.md) | Triage paths and disclosure |
| [docs/audit-readiness.md](./docs/audit-readiness.md) | What an auditor will ask, and the current gaps |

## Repository layout

```
contracts/src/        9 contracts + 2 libraries + CCIP interfaces
contracts/test/       unit suites, mocks, invariants, privacy storage test
contracts/script/     deploy + CCID vector generation
workflows/src/        credential-verify / -renew / -revoke + 3 adapters
packages/sdk/         typed client for integrators
scripts/              storage-layout privacy check, CCID vector generation
```

## Security

Report privately via GitHub Security Advisories. Do not open a public issue with
exploit detail, keys, proofs, or personal data. See [SECURITY.md](./SECURITY.md).

## Legal boundary

This repository is infrastructure. It does not provide legal advice and makes no
claim of GDPR, CCPA, MiCA, KYC, AML, or securities-law compliance. Credential status
says nothing about whether any particular use of it is lawful. Qualified counsel
must review any regulated use before it is marketed.

## Chainlink references

- CRE: https://docs.chain.link/cre
- CCIP: https://docs.chain.link/ccip
- Automation: https://docs.chain.link/chainlink-automation

## License

MIT. See [LICENSE](./LICENSE).