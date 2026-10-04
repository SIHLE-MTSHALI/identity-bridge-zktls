/**
 * @file credential-renew
 *
 * Chainlink CRE workflow: renew an expiring credential.
 *
 * Implements the `credential-renew` requirement: renew **only after fresh provider
 * verification**, and make impending expiry visible before it causes a denial.
 *
 * ## Why renewal is not just "extend the expiry"
 *
 * The tempting implementation is to bump `expiresAt` when the clock approaches it.
 * That would let a credential live forever on the strength of one old proof, and
 * revocation would become cosmetic - the credential would be permanently renewable
 * by whoever holds it.
 *
 * So renewal runs the full verification path again. A renewal that has not been
 * re-verified is not a renewal; it is an extension granted on stale evidence, and
 * this workflow has no code path that produces one.
 *
 * ## Renewal window
 *
 * {findRenewable} reports credentials approaching expiry *before* they fail, so a
 * holder can be prompted while access still works. A system that only notices at
 * expiry has already denied the user.
 */

import { safeLog, type LogSink } from "./privacy.js";
import type { ProviderAdapter } from "./adapters/types.js";
import { credentialVerify, type SchemaPolicy, type VerifyOutcome } from "./credential-verify.js";
import { rawProof, type RawProof } from "./adapters/types.js";

/** A credential approaching expiry. */
export interface RenewalCandidate {
  ccid: string;
  credentialType: string;
  schemaVersion: number;
  providerId: string;
  /** Seconds until expiry. Zero or negative means already expired. */
  secondsRemaining: bigint;
}

/** A request to renew one credential. */
export interface RenewRequest {
  readonly ccid: string;
  readonly credentialType: string;
  readonly schemaVersion: number;
  readonly providerId: string;
  /** Fresh proof. The old one is not reused, by design. */
  readonly raw: RawProof;
  readonly requestId: string;
  readonly destinationChainSelectors?: readonly bigint[];
}

/** Outcome of a renewal attempt. */
export type RenewOutcome =
  | { kind: "renewed"; ccid: string; expiresAt: bigint; propagationTargets: number }
  | { kind: "not_renewable"; reason: string }
  /** Verification failed. Carries the underlying outcome so the caller can react correctly. */
  | { kind: "renewal_failed"; cause: VerifyOutcome };

export interface RenewDeps {
  readonly registry: ReadonlyMap<string, SchemaPolicy>;
  readonly adapters: ReadonlyMap<string, ProviderAdapter>;
  readonly readNonce: (ccid: string) => Promise<bigint>;
  readonly readIssuedAt: (ccid: string) => Promise<bigint | null>;
  readonly log?: LogSink;
  readonly now?: () => bigint;
}

/**
 * Find credentials that should be renewed soon.
 *
 * `renewWindowSeconds` is deliberately a positive window: a credential is listed
 * while it is *still valid*, so the holder gets a prompt before any denial.
 */
export function findRenewable(
  candidates: readonly RenewalCandidate[],
  renewWindowSeconds: bigint,
): RenewalCandidate[] {
  if (renewWindowSeconds < 0n) throw new RangeError("renewWindowSeconds must be non-negative");
  return candidates
    .filter((c) => c.secondsRemaining <= renewWindowSeconds)
    // bigint subtraction, so the ordering is exact rather than losing precision
    // through Number conversion on a 64-bit timestamp difference.
    .sort((a, b) => (a.secondsRemaining < b.secondsRemaining ? -1 : a.secondsRemaining > b.secondsRemaining ? 1 : 0));
}

/**
 * Renew a credential, but only after fresh verification.
 *
 * Delegates to {credentialVerify} rather than reimplementing verification, so the
 * issuance and renewal paths cannot drift apart - the exact drift that would let a
 * bypass appear in one and not the other.
 */
export async function credentialRenew(request: RenewRequest, deps: RenewDeps): Promise<RenewOutcome> {
  const log = deps.log ?? (() => {});

  // A renewal is an issuance with the same identity binding. Delegating keeps every
  // issuance check - provider active, schema admitted, TTL from policy, CCID
  // binding, nonce monotonicity - applied identically.
  const outcome = await credentialVerify(
    {
      credentialType: request.credentialType,
      schemaVersion: request.schemaVersion,
      providerId: request.providerId,
      raw: request.raw,
      requestId: request.requestId,
      ...(request.destinationChainSelectors ? { destinationChainSelectors: request.destinationChainSelectors } : {}),
    },
    deps,
  );

  if (outcome.kind === "issued") {
    safeLog(log, "info", "credential renewed", {
      ccid: request.ccid,
      credentialType: request.credentialType,
      providerId: request.providerId,
      expiresAt: outcome.expiresAt.toString(),
    });
    return {
      kind: "renewed",
      ccid: request.ccid,
      expiresAt: outcome.expiresAt,
      propagationTargets: outcome.propagationTargets,
    };
  }

  // A failed renewal is *not* a revocation and must not be presented as one. The
  // caller keeps whatever access it already had, which may still be valid for a
  // while; silently treating a provider outage as "no longer eligible" is the
  // behaviour this distinction exists to prevent.
  safeLog(log, "warn", "renewal did not complete", {
    ccid: request.ccid,
    requestId: request.requestId,
    outcomeKind: outcome.kind,
  });

  return { kind: "renewal_failed", cause: outcome };
}

export { rawProof };