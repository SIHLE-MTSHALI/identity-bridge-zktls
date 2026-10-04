# Privacy Model

What leaves the holder's device, what reaches the chain, and what is proved about
each. Written to be checkable: every claim here maps to a test or a script.

## The single sentence

**The holder proves a fact; the chain stores that a proof happened and what its
current status is. The fact itself, and anything that identifies the person who
holds it, never reaches chain state, events, logs, or fixtures.**

## Data flow

| Stage | Data present | Boundary |
| --- | --- | --- |
| Holder's browser | raw proof, account handle, document | user device |
| Provider | raw proof, verified attribute | provider infrastructure |
| Workflow runtime | raw proof in, commitments out | confidential compute where available |
| Chainlink logs | **hashes only** | enforced by `safeLog` |
| On-chain state | CCID, provider id, evidence hash, timestamps, status | immutable public state |
| CCIP payload | the above, plus source chain and nonce | public transit |

The transition that matters is workflow runtime → chain. Everything upstream of it
is off-chain and revocable by its own terms. Everything downstream is permanent.

## What is stored on chain

`CredentialRecord` is the entire persistent surface for a credential's identity:

| Field | Type | Why it is safe |
| --- | --- | --- |
| `ccid` | `bytes32` | domain-separated hash; one-way, salted upstream |
| `credentialType` | `bytes32` | `keccak256("kyc.basic")` — a label, not data |
| `providerId` | `bytes32` | identifies an adapter, not a person |
| `evidenceHash` | `bytes32` | commitment; evidence lives off-chain |
| `schemaVersion` | `uint32` | integer |
| `issuedAt` / `expiresAt` / `updatedAt` | `uint64` | timestamps |
| `nonce` | `uint64` | monotonic counter |
| `status` | enum | 7 values |

Every field is a hash, an integer, or an enum. No field can hold free-form text.

### How that is enforced, not just asserted

Two independent checks, because each catches what the other misses:

1. **Runtime storage scan** — `contracts/test/invariant/NoPIIStorage.t.sol`
   reads every storage slot backing a credential after a full lifecycle and fails
   on any run of 12+ printable ASCII bytes. Hashes produce such a run by chance
   with probability roughly 2⁻⁷² per slot, so a failure means a real field.

   The test *discovers* the record's base slot rather than hardcoding it, by
   searching for the mapping slot that holds the value it knows it wrote. A
   hardcoded slot would leave the test reading unrelated memory and passing for
   the wrong reason.

2. **Compiled layout check** — `scripts/check-no-dynamic-storage.mjs`
   walks `forge inspect <contract> storage-layout`, following the type graph
   through `members`, `value`, and `base` so a `string` hidden inside a struct
   inside a mapping is still found.

   This exists because the runtime scan has a real blind spot: **an unused `string`
   field occupies no storage.** Adding `string legalName` to `CredentialRecord` and
   never writing it leaves every storage slot clean, and the runtime test passes.
   This was confirmed by mutation, not assumed — see the README.

Both checks were verified by deliberately breaking them and confirming the failure.

## What is deliberately *not* stored

Not in storage, not in events, not in workflow logs, not in fixtures, not in this
repository:

- names, aliases, handles
- email addresses, phone numbers
- documents, uploads, scans
- raw proofs, zkTLS payloads
- TLS transcripts, certificates, notarisation evidence
- provider API responses or internal case identifiers
- birth dates, tax identifiers, government IDs
- any salt used to compute a commitment

### Why the subject commitment is not stored either

The workflow computes `subjectCommitment = keccak256(domain ‖ salt ‖ evidence)`. The
salt never leaves the workflow, so the commitment is:

- **non-reversible** — recovering the input requires the salt
- **non-correlatable** — two issuers choosing different salts produce unlinkable
  commitments for the same person
- **non-enumerable** — a fresh 32-byte salt per commitment

The chain stores the *CCID*, which is derived from the commitment. The commitment
itself is discarded once the CCID exists; `test_subjectCommitmentIsNeverStored`
asserts it is absent from every slot.

## Logs

Chainlink CRE workflow logs are operational records that persist and are often
publicly observable. A single `console.log` of a provider response body converts an
off-chain boundary into an on-chain disclosure, and it is easy to write during an
incident.

So logging is guarded, not advised:

- `safeLog(sink, level, message, context)` is the only sanctioned emitter.
- It calls `assertRedacted`, which walks the context and throws
  `RawMaterialInLogError` listing offending keys.
- Nothing reaches the sink when it throws. `test/privacy.test.ts` asserts this.

Key matching uses two strategies, because a single strategy fails:

- **substring** for unambiguous tokens — `proof`, `transcript`, `passport`, `email`,
  `phone`, `ssn`, `taxid`, `dateOfBirth`, `privateKey`, `apiKey`, `apiResponse`.
  Needed because `tlsNotaryTranscript` and `rawProofHex` are compound names that
  exact matching waves through.
- **exact** for ambiguous words — `name`, `address`, `report`, `token`, `seed`,
  `salt`, `document`.

`credential` is deliberately *not* a substring token. An earlier version included
it and immediately flagged `credentialType` — this entire system is about
credentials. Over-matching is not a safe default: a guard that fires on legitimate
fields gets disabled, and the real leaks get through.

## Cross-chain payloads

`PropagationPayload.Message` is 11 static words. It carries credential state, never
credential material. Notably absent: `subjectCommitment`. The destination already has
the CCID, which is the binding it needs; shipping the commitment would publish a
second correlatable value per holder on every destination chain for no gain.

Integrity does **not** rest on the destination re-deriving the CCID — it cannot,
since it never receives the commitment. Instead:

1. The sender computes `bindingHash` over every meaningful field.
2. The receiver recomputes it and rejects any mismatch.
3. Alongside the router check, the sender allowlist, and strictly increasing nonces,
   the destination learns three independent facts: the message came through CCIP,
   from a permitted sender, and describes exactly the CCID and state it claims.

## Roles and their privacy implications

`ADMIN` grants/revokes roles and authorises registry writers. It cannot mint
credentials: issuance additionally requires `WORKFLOW_SUBMITTER`, and the bridge
re-derives the CCID and re-checks provider, schema, TTL, and nonce.

Revocation authority is schema-scoped. A `GovernanceOnly` credential cannot be
revoked by its issuer, and a `HolderOrIssuer` credential can be revoked by the
holder — so a compromised issuer cannot unilaterally extend its reach.

## Known limits

Stated plainly, because a privacy model that lists only strengths is not a model:

1. **Correlation by timing.** Issuance transactions are public. An observer can see
   that *some* credential of a given type was issued at time *t*. The system does
   not and cannot hide transaction timing; that is a property of public chains.
   Mitigation is access-pattern design, not cryptography.
2. **Provider is a trusted party.** A compromised provider can issue a credential it
   should not. Mitigated by pausing, revoking, and short TTLs — which bound the blast
   radius but do not prevent it.
3. **A CCID is a stable pseudonym.** For a given `(type, version, provider)`, the
   same holder always produces the same CCID, by design — that is what makes a
   credential renewable. It is therefore correlatable *within that tuple* by anyone
   watching public state. This is a deliberate trade: the alternative is a new
   identity per re-verification, which breaks revocation.
4. **`ProviderRegistry` and `SchemaRegistry` store a `metadataURI` string.** These are
   governance-chosen documentation pointers, not holder data. The layout checker
   allowlists exactly that one field per contract and fails on a second.
5. **Workflow logs before the guard existed.** Any historical run predating
   `safeLog` is outside this model's assurance. There are no such runs; there are no
   production runs.

## Verification

```bash
node scripts/check-no-dynamic-storage.mjs     # compiled layout
forge test --match-path 'contracts/test/invariant/NoPIIStorage.t.sol' -vvv
pnpm --dir workflows test                      # log guard
```