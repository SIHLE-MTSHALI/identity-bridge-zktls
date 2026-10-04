# Incident Response

## Severity

| Sev | Meaning | Response |
| --- | --- | --- |
| **S1** | revoked credential accepted somewhere; identity data on chain; admin compromise | page immediately, pause, notify |
| **S2** | provider compromise; propagation stalled; revocation lag > 1h | page during business hours |
| **S3** | provider outage; stale replicas; schema withdrawn | ticket, same business day |
| **S4** | cosmetic; documentation drift | backlog |

S1 triggers `pause()` before diagnosis. Stopping first and investigating second is
the right order: a pause is instant, reversible, and destroys no evidence, while an
active leak continues while you read logs.

## Triage

```bash
# Is anything allowed that should not be?
cast call <POLICY_ADAPTER> "evaluate(bytes32,(bytes32,uint32,bytes32[],uint64,bool))" ...

# What is the system doing right now?
cast call <EMERGENCY> "paused()(bool)" <CHAIN>     # expect false
cast call <REGISTRY> "statusOf(bytes32)" <CCID> <CHAIN>

# Provider state - distinguishes outage from compromise
cast call <PROVIDERS> "getProvider(bytes32)" <PROVIDER_ID> <CHAIN>
cast call <PROVIDERS> "isProviderHealthy(bytes32)" <PROVIDER_ID> <CHAIN>

# Propagation state
cast call <REGISTRY> "getPropagationState(bytes32)" <CCID> <CHAIN>
cast call <RECEIVER> "lastAcceptedNonce(bytes32)" <CCID> <CHAIN>
```

Then ask, in order:

1. Is any non-`Valid` credential currently allowed? If yes, S1. Pause.
2. Did a status change happen that nobody authorised? If yes, key compromise. S1.
3. Did a credential get issued that should not exist? S1 if it confers access.
4. Is revocation propagating? If `carriedOver` is non-empty, S2 minimum.

## Disclosure

Coordinated disclosure is preferred. Public disclosure waits until a fix is
available or a date is agreed — **except** where delay increases harm:

| Situation | Disclose |
| --- | --- |
| Identity data on public chain | immediately, to affected holders |
| Live exploit granting access | immediately |
| Provider compromise | after revocation is confirmed on all chains |
| Policy bug, no exposure | after fix |
| Documentation overclaim | immediately, before anyone relies on it |

Data that reached chain state is permanent. There is no redaction path. The only
remedy is notifying affected holders so they can change whatever the leaked data
was used to obtain.

## Roles

| Role | During an incident |
| --- | --- |
| Incident lead | declares severity, owns the timeline |
| Operator | executes pause, status changes, revocations |
| Communications | holder and partner notification |
| Privacy | owns anything touching raw material |
| Scribe | timestamps decisions in the incident log |

One person should hold incident lead. "Everyone is doing everything" reliably means
no one verifies that a revocation reached all chains.

## Post-incident

Within 14 days:

1. Timeline, with the moment the system stopped being correct — not when it was
   noticed. These differ, and the gap is the real finding.
2. **Which checks would have caught this earlier?** If the answer is "none", the
   priority output is a new test, not a new document.
3. Update [threat-model.md](./threat-model.md). An incident that fits no documented
   adversary is a gap in the model.
4. Update [operations-runbook.md](./operations-runbook.md) if a step was missing or
   wrong. A runbook written from theory rather than experience is a guess.
5. Be honest about what is still broken.

## What this document does not cover

- A breach of a **provider's** systems. That is the provider's incident; our
  obligation is to pause, revoke, and notify.
- **Legal or regulatory notification.** Determined by counsel with jurisdiction
  context. This repository gives infrastructure, not legal advice, and no part of
  incident response should be read as a regulatory playbook.
- **Social engineering and key theft** targeting operators. Standard hygiene; not
  addressed here.

## Pre-incident preparation

- [ ] Private reporting channel enabled
- [ ] Guardian and operator contacts current and tested
- [ ] Pause and unpause rehearsed on a testnet deployment
- [ ] Monitoring live (§ standing alerts in the operations runbook)
- [ ] Holder notification template drafted
- [ ] Roles split across addresses, behind governance
- [ ] `pnpm run verify` green on `main`