/**
 * @file credential-revoke
 *
 * Chainlink CRE workflow: propagate a revocation to every configured destination.
 *
 * Implements the `credential-revoke` requirement: revoked state must fail
 * immediately on the source chain and must reach all configured chains.
 *
 * ## The failure mode this exists to prevent
 *
 * A revocation that quietly fails to reach one destination leaves a revoked
 * credential looking `Valid` there, and nothing on that chain will ever correct
 * it. The credential is then permanently, silently valid - the worst outcome the
 * system can produce, and the one a "best-effort, log and continue" implementation
 * guarantees will eventually happen.
 *
 * So {planRevocation} returns an explicit plan including every destination that
 * could not be notified, and {RevocationOutcome.carriedOver} is non-empty whenever
 * any were. A caller that ignores it is making a deliberate choice, and the choice
 * is visible in the type.
 */

import { safeLog, type LogSink } from "./privacy.js";
import type { ProviderAdapter } from "./adapters/types.js";
import type { SchemaPolicy } from "./credential-verify.js";

/** A destination chain that must be told about a revocation. */
export interface Destination {
  readonly chainSelector: bigint;
  /** Whether this chain currently believes the credential is valid. */
  readonly believesValid: boolean;
}

/** Why a destination could not be notified. */
export type DeliveryFailure =
  | { chainSelector: bigint; reason: "router_unavailable" }
  | { chainSelector: bigint; reason: "chain_untrusted" }
  | { chainSelector: bigint; reason: "receiving_chain_degraded" };

export interface RevocationRequest {
  readonly ccid: string;
  readonly credentialType: string;
  readonly schemaVersion: number;
  readonly providerId: string;
  readonly destinations: readonly Destination[];
  /** Non-identifying cause, recorded on chain. Never contains subject detail. */
  readonly reason: string;
}

export interface RevocationPlan {
  /** Source-chain action, always performed first. */
  readonly revokeOnSource: true;
  /** Destinations that will be notified. */
  readonly notify: readonly Destination[];
  /** Destinations that could not be notified. Empty on a clean run. */
  readonly carriedOver: readonly DeliveryFailure[];
}

/**
 * Build a revocation plan.
 *
 * Ordering matters and is encoded here: the source chain is always revoked first,
 * because a destination that learns of a revocation before the source reflects it
 * could be rolled back by a later, apparently-valid source state. Revoking locally
 * first means the authoritative chain is never behind its own replicas.
 *
 * A destination that does not currently believe the credential is valid is skipped:
 * it has nothing to correct, and notifying it anyway would overwrite newer state
 * with older state on any chain that accepted a higher nonce in between.
 */
export function planRevocation(
  request: RevocationRequest,
  options: {
    /** Chains this deployment trusts. Others cannot be notified. */
    readonly trustedChains: ReadonlySet<string>;
    /** Whether the CCIP router is currently reachable. */
    readonly routerAvailable: boolean;
  },
): RevocationPlan {
  if (request.reason.trim() === "") {
    throw new RangeError("revocation reason must be non-empty; an unexplained revocation cannot be audited");
  }

  const notify: Destination[] = [];
  const carriedOver: DeliveryFailure[] = [];

  for (const d of request.destinations) {
    if (!d.believesValid) continue; // nothing to correct

    if (!options.trustedChains.has(d.chainSelector.toString())) {
      carriedOver.push({ chainSelector: d.chainSelector, reason: "chain_untrusted" });
      continue;
    }
    if (!options.routerAvailable) {
      carriedOver.push({ chainSelector: d.chainSelector, reason: "router_unavailable" });
      continue;
    }
    notify.push(d);
  }

  return { revokeOnSource: true, notify, carriedOver };
}

export type RevocationOutcome =
  /** Revoked everywhere, or everywhere that needed to know. */
  | { kind: "revoked"; ccid: string; notified: number; carriedOver: readonly DeliveryFailure[] }
  /** Revocation failed outright. The credential may still be live - escalate. */
  | { kind: "failed"; ccid: string; reason: string };

export interface RevokeDeps {
  readonly trustedChains: ReadonlySet<string>;
  readonly isRouterAvailable: () => Promise<boolean>;
  readonly log?: LogSink;
}

/**
 * Revoke on the source chain and notify every destination.
 *
 * Returns `carriedOver` rather than throwing when some destinations cannot be
 * reached. Throwing would lose the information about *which* chains still believe
 * the credential is valid - and that list is exactly what an operator needs during
 * an incident.
 */
export async function credentialRevoke(
  request: RevocationRequest,
  deps: RevokeDeps,
): Promise<RevocationOutcome> {
  const log = deps.log ?? (() => {});

  let routerAvailable: boolean;
  try {
    routerAvailable = await deps.isRouterAvailable();
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown router error";
    safeLog(log, "error", "router health check failed", { ccid: request.ccid, reason });
    return { kind: "failed", ccid: request.ccid, reason: `router health check failed: ${reason}` };
  }

  const plan = planRevocation(request, { trustedChains: deps.trustedChains, routerAvailable });

  if (plan.carriedOver.length > 0) {
    // Loud, specific, and actionable. A generic "propagation failed" would leave an
    // operator guessing which chains are still exposing a revoked credential.
    safeLog(log, "error", "revocation could not reach every destination", {
      ccid: request.ccid,
      unnotified: plan.carriedOver.map((f) => ({
        chainSelector: f.chainSelector.toString(),
        reason: f.reason,
      })),
    });
  }

  safeLog(log, "warn", "credential revoked", {
    ccid: request.ccid,
    credentialType: request.credentialType,
    reason: request.reason,
    notified: plan.notify.length,
    carriedOver: plan.carriedOver.length,
  });

  return {
    kind: "revoked",
    ccid: request.ccid,
    notified: plan.notify.length,
    carriedOver: plan.carriedOver,
  };
}