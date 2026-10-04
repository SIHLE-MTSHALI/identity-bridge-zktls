/**
 * @file policyClient
 *
 * Building and interpreting integrator requirements, plus the retry semantics the
 * SDK commits to.
 */

import type { Hex } from "viem";
import { REASON_LABELS, type ReasonLabel } from "./types.js";

/**
 * Why a denial happened, grouped by what the integrator should actually do.
 *
 * This grouping is the whole reason the SDK exposes a reason code: "denied" is not
 * actionable, and the correct response differs sharply between "this credential
 * was revoked" and "this chain's copy is three weeks old". Treating them alike is
 * how a gate ends up either locking out a legitimate user or waving through a
 * revoked one.
 */
export type DecisionCategory =
  /** Retry later; the credential may resolve without intervention. */
  | "retryable"
  /** The holder must act - renew, re-verify, or resolve a dispute. */
  | "holder_action_required"
  /** The issuer or operator must act; nothing the holder does will help. */
  | "operator_action_required"
  /** The integrator's own policy excludes this credential. */
  | "integrator_policy"
  /** The system is paused; every decision is denied until it resumes. */
  | "system";

const CATEGORY: Record<ReasonLabel, DecisionCategory> = {
  OK: "retryable",
  UNKNOWN: "retryable",
  PENDING: "retryable",
  EXPIRED: "holder_action_required",
  SUSPENDED: "operator_action_required",
  REVOKED: "holder_action_required",
  DISPUTED: "operator_action_required",
  PROVIDER_PAUSED: "operator_action_required",
  SCHEMA_UNSUPPORTED: "operator_action_required",
  STALE_DESTINATION: "retryable",
  CREDENTIAL_TYPE_MISMATCH: "integrator_policy",
  SCHEMA_VERSION_UNSUPPORTED: "integrator_policy",
  PROVIDER_NOT_ACCEPTED: "integrator_policy",
  SYSTEM_PAUSED: "system",
};

/** Classify a reason label. */
export function categorize(reasonName: string): DecisionCategory | "unknown" {
  if (reasonName in CATEGORY) return CATEGORY[reasonName as ReasonLabel];
  return "unknown";
}

/** Reason labels an integrator can act on without escalating. */
export const SELF_SERVICE_REASONS: readonly ReasonLabel[] = ["EXPIRED", "PENDING", "STALE_DESTINATION"];

/** Reason labels that require an operator or issuer to intervene. */
export const ESCALATION_REASONS: readonly ReasonLabel[] = [
  "SUSPENDED",
  "DISPUTED",
  "PROVIDER_PAUSED",
  "SCHEMA_UNSUPPORTED",
  "SYSTEM_PAUSED",
];

/**
 * Should the caller retry the same decision unchanged?
 *
 * Only for reasons that can resolve on their own. Retrying a `REVOKED` denial
 * forever is a denial-of-service against your own users; retrying `PENDING` is
 * exactly right.
 */
export function shouldRetry(reasonName: string, attempt = 0, maxAttempts = 3): boolean {
  if (attempt >= maxAttempts) return false;
  const category = categorize(reasonName);
  return category === "retryable";
}

/**
 * Default freshness tolerance for a replica.
 *
 * `requireFresh` defaults to false in the requirement, so a caller who does not opt
 * in accepts a replica of any age. That is rarely what a protocol means. This
 * helper exists to make the safer choice the one you have to name, not the one you
 * have to remember.
 */
export const DEFAULT_MAX_REPLICA_AGE_SECONDS = 86_400n; // 24 hours

/** A requirement that accepts any schema version of a type. */
export function anyVersion(credentialType: Hex): { credentialType: Hex; schemaVersion: number } {
  return { credentialType, schemaVersion: 0 };
}

/**
 * Build a requirement that tolerates at most `maxAgeSeconds` of replica staleness.
 *
 * Applies only to replicas; a chain that is itself the issuer is never rejected
 * for freshness beyond the credential's own expiry.
 */
export function withFreshness<T extends { credentialType: Hex; schemaVersion: number }>(
  base: T,
  maxAgeSeconds: bigint = DEFAULT_MAX_REPLICA_AGE_SECONDS,
): T & { maxAgeSeconds: bigint; requireFresh: true } {
  return { ...base, maxAgeSeconds, requireFresh: true };
}

/** Restrict a requirement to a specific set of trusted providers. */
export function withProviders<T extends { credentialType: Hex; schemaVersion: number }>(
  base: T,
  acceptedProviders: readonly Hex[],
): T & { acceptedProviders: readonly Hex[] } {
  return { ...base, acceptedProviders };
}

/** All reason labels, for documentation generation and test exhaustiveness. */
export const ALL_REASON_LABELS = REASON_LABELS;