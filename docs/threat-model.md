# Threat Model

Written to be useful to an attacker who has read it. A threat model that only
describes what the system defends against is marketing.

## Assets

| Asset | Why it matters | Worst outcome |
| --- | --- | --- |
| Credential status integrity | gates access to real value | revoked credential accepted |
| Holder privacy | irreversible once public | identity data on chain forever |
| Revocation reach | trust in the whole model | one chain silently still valid |
| Provider admission | trust root for attestations | unvetted provider issues credentials |
| Schema policy | defines what a credential means | policy silently weakened |
| Upgrade/admin keys | can change everything | total compromise |

## Adversaries

| # | Adversary | Capability |
| --- | --- | --- |
| A1 | Attacker, no privileges | can call any public function, send arbitrary CCIP-looking data |
| A2 | Compromised workflow runner | holds `WORKFLOW_SUBMITTER`; can submit arbitrary results |
| A3 | Compromised provider | returns valid attestations for things that are not true |
| A4 | Compromised source-chain bridge | controls outbound CCIP messages |
| A5 | Compromised CCIP router | delivers and attributes messages |
| A6 | Compromised admin key | holds `ADMIN` on any registry or the bridge |
| A7 | Malicious integrator | writes unsafe integration code |
| A8 | Watcher | reads public state and correlates |

## Controls, by adversary

### A1 — unprivileged attacker

| Threat | Control | Test |
| --- | --- | --- |
| Forge a credential | `CredentialBridge` is the only writer; requires `WORKFLOW_SUBMITTER` | `test_UnauthorizedSubmitterRejected` |
| Bind a valid result to the wrong holder | CCID is re-derived from submitted fields | `test_SubjectSwapRejected`, `test_TamperedCcidRejected` |
| Mint a long-lived credential | `expiresAt` must equal `issuedAt + schema.ttl` | `test_ExtendedTtlRejected` |
| Replay an old result | nonce must strictly increase | `test_ReissueSameNonceRejected`, `test_RenewWithReplayedNonceRejected` |
| Resurrect a revoked credential | `Revoked` is terminal in the transition table | `test_RevocationIsTerminal`, `invariant_revocationIsTerminal` |
| Read private data | no dynamic storage on the PII-sensitive contracts | `check-no-dynamic-storage.mjs` |

### A2 — compromised workflow

The workflow is **not** in the trust boundary. It can refuse to issue, but it
cannot forge, extend, or misattribute:

- CCID must reproduce from its own fields.
- Provider must be `Active` right now.
- Schema must be active and must admit that provider.
- `expiresAt` is computed from schema TTL, not chosen by the workflow.
- `expiresAt` must be in the future; `issuedAt` cannot be implausibly future-dated.
- `evidenceHash` must be non-zero.
- Nonce must strictly increase.

A compromised workflow's worst outcome is **denial of service** — refusing to issue.
It cannot mint a credential that passes policy. Note the limit: it *can* refuse
indefinitely, and no on-chain mechanism can prevent that. Recovery is to rotate the
`WORKFLOW_SUBMITTER` role.

### A3 — compromised provider

Controls: short TTLs, per-provider pause, revocation, `Deprecated` for wind-down,
schema-scoped provider admission, provider pause checked **per destination** so
pausing in one jurisdiction does not depend on propagation from another.

A paused or revoked provider denies policy checks immediately. `Deprecated` still
backs existing credentials — a planned migration must not retroactively invalidate
holders.

Not covered: a provider that returns *wrong but well-formed* attestations while
`Active`. Only the provider's own key compromise or an external audit finds that.

### A4 — compromised source bridge

The destination holds an allowlist of source senders, so a compromised bridge can
only write through chains that trusted it. It cannot forge messages from other
senders.

It **can** send valid-looking messages for credentials it should not, and nothing
downstream detects that on its own — the destination trusts its configured peer.
Mitigation is operational: rotate the allowlist, pause the system. This is a
single point of trust by design, and `docs/audit-readiness.md` flags it as the
hardest question an auditor will ask.

### A5 — compromised CCIP router

**The router is a fully trusted component.** It provides `msg.sender` attribution
and message ordering. A compromised router can attribute a message to an allowed
sender.

Bounded by:

- `bindingHash` is computed by the *sender*, not the router, so the router cannot
  alter payload contents without detection.
- Nonces are monotonic per CCID, so replay and reordering are handled.

Not covered: the router lying about *which* sender a message came from. Closing
that requires the sender to sign payloads and the receiver to verify signatures,
which is a real design change and is listed in `audit-readiness.md` rather than
claimed as solved.

### A6 — compromised admin key

`ADMIN` can: grant/revoke roles, change schema/provider registration, authorise
registry writers, schedule an unpause.

`ADMIN` **cannot** mint a credential (needs `WORKFLOW_SUBMITTER` plus a valid
result), and cannot revoke a `GovernanceOnly` credential it does not govern without
the governance role.

Highest-impact compromise is authorising a rogue writer on `CredentialRegistry`,
which would allow arbitrary status writes. Mitigation: the writer set is small,
should be timelocked, and every change emits `WriterAuthorizationChanged`.

Unpause is deliberately timelocked (`UNPAUSE_DELAY`, 24h) while pause is immediate.
Stopping is cheap and reversible; resuming is the risky direction, and during an
unresolved incident it is exactly when pressure to resume is highest.

### A7 — malicious or careless integrator

This is the most likely real-world failure, and the least glamorous.

`registry.isValid(ccid)` is an unsafe integration surface: it is `true` for a
credential whose provider has since been paused, and for a stale replica.
Integrators reach for it, get `true`, and ship a gate that fails open during the
incidents it was built to survive.

Mitigations:

- `PolicyManagerAdapter.evaluate` returns `(allowed, reasonCode)`.
- The SDK's rule is "branch on `allowed`, never on status".
- `categorize()` maps each reason to an action class, and `shouldRetry()` refuses to
  retry non-retryable reasons — so a revoked credential cannot become an infinite
  retry loop, and a `PENDING` one is not treated as fatal.
- `apps/portal` would carry an integrator simulator; **it is not built**, so this
  control is currently documentation plus SDK ergonomics.

### A8 — watcher

Can correlate issuance timing and CCID stability. See
[privacy-model.md](./privacy-model.md#known-limits) — this is inherent to public
state, not a defect to be engineered away.

## Cross-chain replay and spoofing

| Attack | Control | Test |
| --- | --- | --- |
| Direct call bypassing CCIP | `msg.sender == ROUTER` | `NotRouter` |
| Replayed message | consumed `orderId` **and** monotonic nonce | `test_ReplayedOrderIdRejected`, `test_ReplayedPayloadUnderNewOrderIdStillRejectedByNonce` |
| Forged sender | allowlist | `test_UntrustedSourceSenderRejected` |
| Message from an unexpected chain | chain-selector allowlist + self-chain rejection | `test_UntrustedSourceChainRejected`, `test_SelfSourceChainRejected` |
| Payload altered in transit | `bindingHash` recomputation | `test_BindingHashMismatchRejected` |
| Revocation flipped to `Valid` | `bindingHash` | `test_StatusFlipToValidRejectedByBindingHash` |
| Out-of-order delivery | strictly increasing nonce | `test_OutOfOrderNonceRejected` |
| Remote state overwriting local authority | local-issuer check | `test_ReplicaCannotOverwriteLocalIssuance` |
| Truncated / malformed payload | exact length guard + typed decode errors | `test_MalformedPayloadRejected`, `test_UnknownStatusRejected` |

### The bug that this table would not have predicted

`CrossChainCredentialSender` originally deduplicated per destination
(`if (sentTo[ccid][dest]) continue`). That silently meant a credential already
propagated once could **never be propagated again** — so a revocation could never
reach a chain that had already seen the credential as `Valid`. The revocation would
succeed on the source chain and everywhere the credential had never been, and fail
silently everywhere it mattered.

Replay defence was moved entirely to the receiver (strictly increasing nonce), and
the comment in the sender says why. `test_RevocationPropagatesToDestination`
regression-tests it.

A second, related bug: `CredentialRegistry.setStatus` did not bump the nonce, so a
revocation carried the same nonce as the issuance it reversed and every destination
discarded it as stale. Status transitions now bump the nonce, and the bridge re-reads
the record after the transition rather than propagating a stale copy.

## What is explicitly out of scope

- The CCIP router's own correctness (§A5).
- Confidential compute guarantees. `docs/architecture.md` treats the workflow
  runtime as the sensitive boundary; where confidential compute is available it
  strengthens that, but the model does not depend on it.
- Provider-internal compromise that leaves no on-chain trace.
- Governance capture of the *process*, as opposed to a key. A captured governance
  can deprecate a schema or revoke a provider legitimately, by design.
- Economic attacks on the integrator's own application.

## Residual risk, ranked

1. **Router sender-attribution is trusted** (A5). Highest-impact unmitigated path.
2. **Workflow denial of service** (A2). Unpreventable by design; needs key rotation
   to recover.
3. **Integrator misuse** (A7). Most likely in practice; mitigated by ergonomics and
   docs, not by contract guarantees.
4. **Single source-of-truth per credential** (A4). Cross-chain trust is a
   configuration decision, not a cryptographic one.
5. **Provider integrity while `Active`** (A3). Bounded by TTL, not prevented.