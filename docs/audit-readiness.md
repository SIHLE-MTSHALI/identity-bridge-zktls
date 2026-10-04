# Audit Readiness

An honest inventory of what an auditor will find. Written to be useful to a
reviewer, including one who concludes "not ready yet".

**No external audit has been performed.** No statement in this repository should be
read as implying otherwise.

## Verified

Each of these has a check that fails if the property breaks, and — for the two most
important — was verified by deliberately breaking the property.

| Property | Enforced by | Mutation-verified |
| --- | --- | --- |
| Only `Valid` yields `allowed == true` | `invariant_onlyValidCredentialIsAllowed` | yes |
| `Revoked` is terminal | `invariant_revocationIsTerminal` | **yes** — `Revoked → Valid` was caught |
| Expiry never decreases | `invariant_expiryNeverDecreases` | yes |
| Nonce never decreases | `invariant_nonceNeverDecreases` | yes |
| Paused system denies everyone | `invariant_pauseFailsClosed` | yes |
| Issued records use admitted providers | `invariant_issuedRecordsUseAdmittedProviders` | yes |
| No readable text in credential storage | `NoPIIStorage.t.sol` | partial — see below |
| No dynamic storage member possible | `check-no-dynamic-storage.mjs` | **yes** — `string legalName` was caught |
| Raw material cannot reach logs | `safeLog` | yes |
| Replay / wrong sender / wrong chain / wrong schema | `CrossChainPropagation.t.sol` | — |
| CCIP binding hash detects tampering | `CrossChainPropagation.t.sol` | — |
| Workflow CCID equals on-chain CCID | `ccid-parity.test.ts` | — (external vectors) |

### Two verification findings worth recording

Both were cases where a check passed while proving nothing.

**The privacy storage test had a blind spot.** An *unused* `string` field occupies
no storage, so adding `string legalName` to `CredentialRecord` and never writing it
left every storage slot clean and the test green. The compiled-layout checker closes
this by inspecting types rather than runtime values. A reviewer should treat
"passing runtime scan" as necessary and not sufficient.

**The invariant suite initially had no teeth.** With purely random fuzz inputs the
handler minted new credentials and rarely revisited an existing one, so
`revoke → resume` was essentially never exercised and the terminality invariant
passed regardless of the code. Adding a ghost-variable key pool and compound
actions (`revokeThenAttemptResurrection`) made it catch a deliberately introduced
`Revoked → Valid` transition. **Test suites should be mutation-tested.** A green
invariant suite that has never been shown to fail proves nothing.

## Known gaps, ranked by what an auditor would weight them

### 1. The CCIP router is a fully trusted component

A compromised router can attribute a message to an allowed sender. `bindingHash`
stops payload *alteration*, and nonces stop replay and reordering, but neither
establishes provenance.

Remediation: have the sender sign payloads and the receiver verify. A real design
change, not a configuration one.

### 2. Single source of truth per credential

Cross-chain trust is a configured allowlist. A compromised source bridge can write
through any chain that trusted it, and a compromised destination can lie about what
it holds. This is inherent to a replication design; the honest framing is that
integrators are choosing to trust the issuer.

### 3. Workflow denial of service

A compromised or stuck workflow can halt issuance indefinitely. No on-chain
mechanism prevents it. Recovery is rotating `WORKFLOW_SUBMITTER`. Bounded impact:
availability only, because a compromised workflow cannot forge a credential.

### 4. Provider integrity while `Active`

A provider returning *wrong but well-formed* attestations is not detectable on
chain. Bounded by TTL, not prevented.

### 5. No governance contracts wired in

Roles are plain addresses. Production deployment must place `ADMIN`,
`SCHEMA_ADMIN`, `PROVIDER_ADMIN`, `TIMELOCK_ADMIN`, and `EMERGENCY_GUARDIAN` behind
a multisig and/or timelock. The pause/unpause asymmetry (immediate pause, 24h
delayed resume) is built into `EmergencyControls`, but nothing enforces who holds the
roles.

### 6. No bulk revocation

Revocation is per-credential. A provider compromise requiring mass revocation means
iterating one transaction per credential. At any realistic scale that is operationally
untenable during the incident where it matters most. **This is the gap most likely
to matter in a real provider compromise.**

### 7. `apps/portal` does not exist

The spec lists holder, integrator, provider, schema-admin, and audit views. None are
built. The integrator simulator in particular was meant to be a control against
integrator misuse (A7 in the threat model); without it, that control is documentation
and SDK ergonomics only.

### 8. No live provider integration

`reclaim.ts` and `tlsnotary.ts` are documented boundaries with tested failure
semantics. Supplying a transport is all that is missing, but no real provider has
been reviewed, which `Gate 3` of the PRD requires.

### 9. No testnet deployment

Cross-chain behaviour is tested against `MockCCIPRouter`, which reproduces the
properties the receiver depends on (router identity, message ids, sender
attribution) but not the real router's guarantees. `fail_on_revert = false` in the
invariant config means a revert during fuzzing is tolerated — deliberate, since the
handler issues mostly-invalid calls, but it does mean handler-side reverts are not
themselves failures.

### 10. Foundry lint suppressions

Six rules are suppressed in `foundry.toml` with written justifications
(`unsafe-typecast`, `calls-loop`, `reentrancy-events`, `block-timestamp`,
`require-revert-in-loop`, `empty-block`). Each is a claim a reviewer should check
independently rather than accept.

### 11. Oracle and price dependencies

None exist — the system does not read prices. Listed so its absence is not read as
an oversight.

## Coverage

| Area | State |
| --- | --- |
| Access-control matrix | Partial — bespoke role stores, no test proving role *separation* |
| Reentrancy | Argued structurally; no adversarial test |
| Gas limits | Unbounded loops: `expireDue` (bounded 100), sender fan-out (bounded 10), `acceptedProviders` (bounded 32) |
| Integer overflow | Solidity 0.8 checked arithmetic; `via_ir` enabled |
| Signature replay | No on-chain signatures exist — see gap 1 |
| Upgradeability | **None.** Contracts are immutable, not upgradeable. A bug requires redeployment. |
| Oracle dependencies | None |
| Flash loans | Not applicable — no value held |

The upgradeability choice is deliberate for a credential system: a mutable
`CredentialRegistry` is a mutable privacy boundary. It also means a bug discovered
post-deployment is a migration, not a patch.

## Suggested scope for a first audit

1. `PolicyManagerAdapter._evaluate` — the whole security argument reduces to this
   function and its ordering.
2. `CredentialRegistry.setStatus` + the transition table — terminality, nonce
   monotonicity, and lazy expiry.
3. `CrossChainCredentialReceiver._accept` — every cross-chain check in one place.
4. `CredentialBridge.submitCredentialResult` — whether the re-validation genuinely
   defends against a compromised workflow.
5. The privacy guard: `check-no-dynamic-storage.mjs` traversal correctness, and
   `safeLog` key matching against real provider response shapes.

## Verifying this repository yourself

```bash
pnpm run verify
```

Expect: `forge fmt --check` clean, `forge build` clean, `forge lint` clean,
`check-no-dynamic-storage` clean, 94 Foundry tests, 26 SDK tests, 73 workflow tests.

To confirm the invariants have teeth, break one and watch it fail:

```solidity
// CredentialRegistry._isTransitionAllowed
if (from == CredentialTypes.CredentialStatus.Revoked) return to == CredentialTypes.CredentialStatus.Valid;
```

`invariant_revocationIsTerminal` should fail with `INV-3`. Revert afterwards.

To confirm the privacy check has teeth, add `string legalName;` to
`CredentialRecord` and run `node scripts/check-no-dynamic-storage.mjs`. It should
report `_records{value}.legalName (string)` and exit 1.