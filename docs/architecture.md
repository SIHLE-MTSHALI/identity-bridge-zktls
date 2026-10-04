# Architecture

## Components

| Contract | Responsibility | Trust level |
| --- | --- | --- |
| `CredentialRegistry` | minimal credential state, lifecycle transitions, replica freshness | holds no keys; two authorized writers |
| `CredentialBridge` | validates workflow results, writes source of truth, triggers propagation | `WORKFLOW_SUBMITTER`, `ISSUER`, `HOLDER`, `ADMIN` |
| `ProviderRegistry` | provider admission, status, schema support, health | `PROVIDER_ADMIN`, `PROVIDER_OPERATOR` |
| `SchemaRegistry` | credential types, versions, TTL, revocation mode, admitted providers | `SCHEMA_ADMIN` |
| `CCIDResolver` | derives and verifies the holder binding | pure; no state |
| `PolicyManagerAdapter` | the integrator-facing decision, with reason codes | view-only |
| `CrossChainCredentialSender` | encodes and dispatches state over CCIP | one-time-bound bridge |
| `CrossChainCredentialReceiver` | validates and records replicas | `ROUTER` + allowlists |
| `EmergencyControls` | system-wide pause, timelocked unpause | `GUARDIAN`, `TIMELOCK_ADMIN` |

## Why the registry holds no keys

`CredentialRegistry` is written by exactly two addresses: the `CredentialBridge`
(source of truth) and the `CrossChainCredentialReceiver` (replicas). Splitting
authority this way means a compromised bridge cannot forge destination state, and a
compromised receiver cannot invent issuance.

It uses a bespoke 20-line role store rather than OpenZeppelin `AccessControl`. Two
roles do not justify a general-purpose authorisation system, and the smaller surface
is easier to audit.

## Deployment cycle: a real circular dependency

The sender needs the bridge's address; the bridge needs the sender's address.
Neither can take the other as a constructor argument. The sender is therefore
deployed unbound and bound once:

```
1. deploy EmergencyControls
2. deploy CredentialRegistry, ProviderRegistry, SchemaRegistry, CCIDResolver
3. deploy CrossChainCredentialSender        (unbound — accepts no calls)
4. deploy CredentialBridge                 (points at the sender)
5. sender.initializeBridge(bridge)         (once, permanent, deployer only)
6. registry.setWriter(bridge, true)
7. deploy PolicyManagerAdapter
```

An unbound sender accepts calls from nobody, so the intermediate state is safe
rather than merely inconvenient. `initializeBridge` is one-way and deployer-only: a
rebindable sender would let a compromised deployer role redirect credential
propagation at will.

### The mirror-image problem on destinations

The receiver must be a registry writer before it accepts anything, and its own
address does not exist during its constructor. So construction cannot verify it.

`CrossChainCredentialReceiver` starts `wired == false` and refuses every message
with `NotWired` until `wire()` confirms the writer role. A deployment that skipped
this would otherwise accept messages and write nothing — the worst failure mode,
because it looks healthy while silently losing credential state.

Order on each destination: deploy → `setWriter(receiver)` → `wire()` →
`setAllowedSourceSender` → `setAllowedSourceChain`.

## Why the CCIP interfaces are local

`contracts/src/interfaces/ICCIP.sol` declares the two types and one function this
system uses, with signatures matching CCIP v2 exactly. The upstream
`chainlink-contracts` package is not vendored:

1. A reviewer should be able to `forge build` with `forge-std` alone. A vendored
   dependency tree makes the build depend on network access and pins the repo to
   one upstream release.
2. The security-relevant surface is three declarations. Keeping it in-repo means
   the thing an auditor reads is the thing that runs.

Swapping in the real router is a deployment-time address change.

### Wire format

Defined once, in `libraries/PropagationPayload.sol`, used by both sender and
receiver. 11 static 32-byte words:

| # | Field |
| --- | --- |
| 0 | `ccid` |
| 1 | `credentialType` |
| 2 | `schemaVersion` |
| 3 | `providerId` |
| 4 | `evidenceHash` |
| 5 | `issuedAt` |
| 6 | `expiresAt` |
| 7 | `nonce` |
| 8 | `status` |
| 9 | `sourceChainSelector` |
| 10 | `bindingHash` |

`subjectCommitment` is absent by design — see
[privacy-model.md](./privacy-model.md#cross-chain-payloads).

`decode` returns a `DecodeError` rather than a boolean so the receiver can
distinguish a bad length (`MalformedPayload`, suggests a version mismatch) from an
out-of-range status (`UnknownStatus`, suggests a sender bug). Operators act on
those differently.

## Why `via_ir` is on

Several functions legitimately touch more values than the legacy codegen allows on
the stack — the 11-field ABI decode, the bridge's validation sequence. The IR
pipeline is required, not cosmetic, and produces smaller bytecode as a side benefit.
The cost is compile time.

## Expiry does not depend on a keeper

`statusOf` applies expiry lazily from `expiresAt`. A credential is denied the instant
it lapses, whether or not `expireDue` has run.

A system whose expiry depended on a keeper being alive fails **open** the moment
that keeper stalls — the one unacceptable direction here. `expireDue` exists to keep
the event trail and audit exports complete, not to enforce safety.

## Revocation propagation

Every state change goes out through one function: issue, renew, suspend, resume,
dispute, expire, revoke. There is no separate revocation channel, because a channel
that only sometimes exists is precisely how a revoked credential ends up looking
valid somewhere.

Two things this depends on, both of which were bugs first:

- **No per-destination deduplication.** An earlier version skipped destinations it had
  already sent to, which silently made revocation impossible for any chain that had
  already seen the credential as `Valid`.
- **`setStatus` bumps the nonce.** A revocation that carries the same nonce as the
  issuance it reverses is discarded by every destination as stale.

Revocation latency is therefore bounded only by CCIP delivery, and
[operations-runbook.md](./operations-runbook.md) treats lag as an alertable metric.

## Decision precedence

`PolicyManagerAdapter` evaluates in a fixed order, first failure wins:

```
SYSTEM_PAUSED → UNKNOWN → PENDING → REVOKED → SUSPENDED → DISPUTED
→ EXPIRED → CREDENTIAL_TYPE_MISMATCH → SCHEMA_VERSION_UNSUPPORTED
→ PROVIDER_NOT_ACCEPTED → PROVIDER_PAUSED → SCHEMA_UNSUPPORTED
→ STALE_DESTINATION → OK
```

Two orderings worth explaining:

- **`REVOKED` before `EXPIRED`** — revocation is the more deliberate signal. A revoked
  credential that has also expired is reported as revoked.
- **`PROVIDER_NOT_ACCEPTED` before `PROVIDER_PAUSED`** — the first is the
  integrator's own policy choice; the second is a system-wide condition. An
  integrator should not have to wait out an unrelated provider incident to learn
  they never trusted that provider.

All entry points funnel through one internal `_evaluate`, so the order cannot diverge
between the view and state-changing surfaces.

## CCID

`CCIDResolver.compute(DOMAIN, credentialType, uint256(schemaVersion), providerId, subjectCommitment)`.

**The nonce is deliberately not part of the CCID.** A CCID is an identity binding,
not a version counter. If renewal produced a new CCID, every renewal would strand
the previous credential on every destination chain as a dangling, still-`Valid`
record — unreachable by any revocation, because nothing knows its new name. The
replay counter is `nonce`, which lives on the record and must strictly increase.

Parity between the Solidity and TypeScript derivations is not assumed:
`scripts/generate-ccid-vectors.mjs` runs the on-chain resolver and
`workflows/test/ccid-parity.test.ts` asserts the workflow reproduces every vector,
including zero and `uint32` max edge cases. CI fails if the committed vectors are
stale.

## Verification

```bash
forge fmt --check
forge build --sizes
forge lint
forge test -vvv
forge test --match-path 'contracts/test/invariant/*' -vvv
node scripts/check-no-dynamic-storage.mjs
pnpm run typecheck
pnpm --dir packages/sdk test
pnpm --dir workflows test
```

`pnpm run verify` runs the lot.

## Lint configuration

`foundry.toml` suppresses six lint rules with written justifications, because each
fires on a deliberate pattern: `unsafe-typecast` (every timestamp is narrowed to
`uint64` because the spec's storage schema fixes those widths), `calls-loop` (CCIP
fan-out, bounded by `MAX_DESTINATIONS`), `reentrancy-events` (every external callee
is an immutable address, and nonces are committed before the call),
`block-timestamp` (TTL logic is inherently time-based, with tolerances orders of
magnitude larger than validator influence), `require-revert-in-loop` (destination
validation, rejecting the batch rather than partially sending), `empty-block`
(`receiveCredential` is an intentional CCIP dispatch target).

`lint_on_build` is off so a real compiler error is not buried in ~60 advisories.
`forge lint` is a separate CI step. The suppressions are not free: they are a claim
a reviewer should check.