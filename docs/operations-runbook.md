# Operations Runbook

Every runbook here has been written from the code's actual behaviour. None has been
exercised against a live deployment, because there is no live deployment — see
[audit-readiness.md](./audit-readiness.md).

## Standing alerts

| Signal | Source | Threshold | Severity |
| --- | --- | --- | --- |
| Revocation propagation lag | `CredentialSent` vs `CredentialReplicaAccepted` | > 15 min | **page** |
| Revocation carried over | `credential-revoke` outcome | any | **page** |
| Provider not healthy | `ProviderRegistry.isProviderHealthy` | > 1 interval | warn |
| Provider paused / revoked | `ProviderStatusChanged` | any non-planned | **page** |
| Destination replica stale | `PropagationState.lastUpdatedAt` | > 24h | warn |
| `SYSTEM_PAUSED` decisions | policy adapter | any | warn (expected during incident) |
| Receiver not wired | `ReceiverWired` absent after deploy | any | **page** |
| Unexpected writer | `WriterAuthorizationChanged` | any unapproved | **page** |

Revocation lag is the one to page on. It is the only metric whose failure mode is a
credential that is still valid where it should not be.

## Provider outage

**Symptom:** `provider_unreachable` from an adapter; `PROVIDER_PAUSED` if an operator
paused the provider; workflow retries.

**What the system does:** nothing automatically, and that is correct. Access decisions
deny rather than fail open, so holders are denied while the provider is down. Nothing
auto-revokes — an outage is not evidence a credential is bad.

**Do:**

1. Confirm it is an outage, not a compromise. Check `ProviderStatusChanged` history.
   A status change nobody made is an incident, not an outage.
2. Do **not** pause the provider to "stop issuance" unless you also believe the
   provider is compromised. Pausing denies every existing holder immediately and is
   not a queue-control mechanism.
3. If compromised: pause, then revoke credentials from that provider
   (`CredentialBridge.revoke` per credential). There is no bulk revoke — plan for
   iterating. An emergency bulk path is a known gap.
4. If merely unavailable: wait. Holders with unexpired credentials keep access.
   Communicate the expected duration; do not promise a re-verification that will not
   happen.
5. After recovery, verify the failure counter cleared:
   `isActive(providerId)` for issuance, `backsExistingCredentials(providerId)` for
   existing holders. They differ by design.

**Do not:** extend TTLs to paper over an outage. It extends exposure to whatever
caused the outage.

## False or compromised credential

**Symptom:** a credential was issued that should not have been, or a provider
confirmed a false attestation.

1. Pause the provider — this stops new issuance immediately.
2. Revoke the affected credentials. `revoke` re-propagates to all configured
   destinations; **check `carriedOver`** — that list is the set of chains still
   showing the credential as valid.
3. For each chain in `carriedOver`: confirm trust configuration, then retry
   propagation. If the chain cannot be reached, the credential genuinely remains
   valid there — record it as a known exposure with a chain list, not as "handled".
4. Investigate whether the CCID binding holds: re-derive the CCID from the recorded
   fields and confirm it matches. A mismatch means the issue is in the bridge, not the
   provider.

**Note:** revocation is terminal and cannot be undone. Confirm you have the right
CCIDs before broadcasting; there is no recall.

## Stale destination state

**Symptom:** integrators report `STALE_DESTINATION`.

1. Check the destination's `lastUpdatedAt` and `lastSourceNonce` per CCID.
2. If the source nonce advanced but the destination did not, propagation is stuck —
   check router availability and the destination's `ALLOWED_SOURCE_CHAINS`.
3. If they match, the source did not propagate. Check `credential-revoke` /
   `credential-renew` outcomes for a `carriedOver`.
4. Integrators can raise `maxAgeSeconds` as a mitigation. Raising it accepts a longer
   window of stale belief — treat it as a documented, time-boxed decision, not a fix.

A replica that is never refreshed does not fail safe on its own. Freshness only
protects integrators who set `requireFresh`. Confirm your integrators do.

## Privacy incident

**Symptom:** raw proof material, a transcript, or identity data observed in a
workflow log, an event, or storage.

1. **Contain first.** `pause()` is immediate and needs no delay. If the leak is in
   logs, pausing stops new log lines while you scope it.
2. Preserve the evidence — logs, events, the offending run id — before rotating
   anything. Do not delete logs; that destroys the audit trail you need.
3. Identify the sink. See the decision table in
   [privacy-model.md](./privacy-model.md#known-limits).
4. If data reached **chain state**, it is permanent. Assume compromise of every
   identity in the leaked batch and notify affected holders. There is no redaction
   mechanism on a public chain; that is why the storage-layout check is a CI gate.
5. If data reached **workflow logs only**, the exposure is to whoever can read those
   logs. Rotate any credential that appears in them.
6. Fix the source. If `safeLog` was bypassed, that is a code defect — add a test that
   asserts the guard rejects that shape.

## Emergency pause

`pause()` — guardian only, immediate, no delay.
`cancelUnpause()` — timelock admin only, stops a scheduled resume.
`scheduleUnpause(reason)` → `executeUnpause()` after 24h.

Pausing does not hide state. Reads stay available so holders, integrators, and
auditors keep seeing what is true. It stops new decisions, not history.

Pausing fails closed: `evaluate` returns `SYSTEM_PAUSED` and `allowed == false` for
everyone, including valid credentials. During an incident that is the safe direction.

Resuming is deliberately slow. If someone is pressuring you to resume mid-incident,
that pressure is itself information.

## Key rotation

| Key | Rotation | Notes |
| --- | --- | --- |
| `WORKFLOW_SUBMITTER` | planned | grant the new address, redeploy workflows, revoke the old |
| `PROVIDER_ADMIN` / `SCHEMA_ADMIN` | planned | must not overlap, or two admins coexist |
| `EMERGENCY_GUARDIAN` | **urgent** | `pause` needs no delay; losing it costs the fastest response |
| `TIMELOCK_ADMIN` | planned | controls resume |
| `ADMIN` | planned, timelocked | highest blast radius |
| CCIP router | n/a | immutable; a change is a redeploy |

**Losing `WORKFLOW_SUBMITTER`** means issuance stops. Nothing is at risk except
availability — a compromised workflow cannot mint credentials (see
[threat-model.md](./threat-model.md#a2--compromised-workflow)). This asymmetry is
intentional and is why rotation is not urgent.

**Losing `GUARDIAN`** removes the ability to pause instantly. Rotate urgently.

No multisig or timelock contract is wired in these tests. Production deployment must
place these roles behind governance — noted as a gap in
[audit-readiness.md](./audit-readiness.md).

## Deployment checklist

- [ ] `PRIVATE_KEY` from a keystore, not an env var
- [ ] roles split across addresses — not everything on the deployer
- [ ] `SOURCE_CHAIN_SELECTOR` verified; a wrong value makes every destination reject
- [ ] `ALLOWED_SOURCE_SENDER` is the source `CredentialBridge`
- [ ] `receiver.wire()` called
- [ ] no fixture-marked provider registered
- [ ] `forge inspect <c> storage-layout` reviewed for dynamic members
- [ ] monitoring and alerts live **before** the first credential is issued
- [ ] incident contacts and escalation path agreed