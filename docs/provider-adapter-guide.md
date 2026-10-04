# Provider Adapter Guide

How to write one, how to review one, and what an adapter must never do.

## The contract

```ts
interface ProviderAdapter {
  readonly providerId: string;
  readonly supportedCredentialTypes: readonly string[];
  readonly supportedSchemaVersions: readonly number[];
  supports(credentialType: string, schemaVersion: number): boolean;
  verify(input: AdapterInput): Promise<AdapterResult>;
}
```

`AdapterInput.raw` is typed `RawProof`, an opaque branded type. The branding exists
so a payload cannot be passed around as a plain value and serialized into a result
by accident.

## Rules

### 1. Raw material enters and does not leave

`AdapterInput.raw` is the only place raw proof material appears. `AdapterResult`
contains no field capable of holding it — the type does not permit it.

An adapter that needs to *return* evidence returns a salted commitment
(`evidenceCommitment`), never the evidence.

### 2. Distinguish "no" from "cannot tell"

This is the rule most likely to be broken, and the most consequential.

```ts
// Wrong: an outage becomes a denial.
return { ok: true, verification: { verified: false, ... } };

// Right: the caller can retry.
return { ok: false, failure: "provider_unreachable", detail: "..." };
```

Collapsing these means a ten-minute provider outage denies every applicant, and the
denials are indistinguishable from genuine rejections. The next response is
"verification is broken, shut it down", and now nobody can verify anything.

A thrown transport error is **always** `provider_unreachable`. Never map it to
`verified: false`.

### 3. Trust the provider's schema claim, but check it

If the provider attests a different `credentialType` than requested, return
`subject_mismatch`. Trusting the provider's answer over the request is how a
credential gets issued under a schema nobody checked — and the workflow enforces
this again at the boundary, because a compromised adapter is a supported adversary.

### 4. Never log raw material

Use `safeLog` from `../privacy.js`. It throws rather than emit, and nothing reaches
the sink when it does. Do not reach for `console.log` — that is the entire failure
mode this module exists to prevent.

### 5. Fresh salt per commitment

```ts
commit(vendor.evidenceLabel, input.credentialType);  // fresh random salt
```

Reusing a salt lets anyone holding two commitments detect that they describe the
same subject. That is exactly the correlation the privacy model forbids.

Add every scoping dimension to the **domain separator**, not the material. The
TLSNotary adapter folds the origin into the domain, so the same attribute attested
on two origins yields two unlinkable commitments.

### 6. Check `supports()` before touching the transport

Fail fast. A test asserts the transport is never called for an unsupported schema —
call it anyway and you have made a network round trip on a request that could never
succeed.

## Fixture adapters

`mock-zktls` takes its outcome from the proof envelope, so a test can drive any
branch. Use it for denial paths, not just the happy one — the denial paths are where
the interesting bugs live.

It exports `FIXTURE_MARKER`, and every evidence label it produces contains it.
**A deployment script must refuse to register any provider whose evidence label
carries that marker.** An adapter that accepts any proof and can be told to verify
is catastrophic in production.

## Reference implementations

`reclaim.ts` and `tlsnotary.ts` are **documented boundaries, not live
integrations**. They define the surface, the failure semantics, and the privacy
handling, and they throw `ReclaimTransportNotConfiguredError` /
`TlsNotaryTransportNotConfiguredError` when no transport is supplied.

This is deliberate. A half-written vendor client is worse than an honest boundary:
it looks integrated, cannot be verified, and someone will ship it.

Failing with a *distinct* error rather than `provider_unreachable` matters — a
misconfigured adapter must not be mistaken for a vendor outage during an incident.

To make one live, implement the transport seam:

```ts
interface ReclaimTransport {
  verify(claim: ReclaimClaim, signal?: AbortSignal): Promise<ReclaimVerification>;
}
```

Nothing else in the adapter needs to change.

## Review checklist

Before a provider is admitted to a schema:

- [ ] `verify` cannot return raw material in any code path
- [ ] transport failures map to `provider_unreachable`, never `verified: false`
- [ ] an unknown status or schema returns a typed failure, not a throw
- [ ] the commitment salt is freshly generated per credential
- [ ] scoping dimensions (origin, tenant) are in the domain separator
- [ ] `supports()` is checked before any I/O
- [ ] no `console.log`, `console.error`, or raw `JSON.stringify` of provider output
- [ ] timeouts are explicit; a hung request must not hang the workflow
- [ ] every `AdapterFailure` case is covered by a test
- [ ] the adapter is not fixture-marked
- [ ] an owner is named for key rotation and incident response