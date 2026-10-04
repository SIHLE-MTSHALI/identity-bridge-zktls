import type { Address, PublicClient, Hex } from "viem";
import { decide, toRecord, toPropagationState, type CredentialRecord, type CredentialRequirement, type PolicyDecision, type PropagationState } from "./decode.js";
import { credentialStatusName, type CredentialStatusName } from "./types.js";

/**
 * @file credentialStatus
 *
 * Read-side credential queries.
 *
 * Every function here is safe to call against an untrusted chain: it performs no
 * signing and makes no assumption that what it returns is favourable.
 */

/** Minimal contract surface the client needs. Keeps the SDK dependency-light. */
export interface CredentialRegistryLike {
  address: Address;
  abi: readonly unknown[];
}

/** A credential's current state, as the SDK reports it. */
export interface CredentialStatusResult {
  ccid: Hex;
  credentialType: Hex;
  exists: boolean;
  status: number;
  statusName: CredentialStatusName;
  record: CredentialRecord | null;
  propagation: PropagationState | null;
  /**
   * True when this chain holds a replica rather than being the issuer.
   *
   * Integrators should almost always set `requireFresh` when acting on a replica;
   * a replica is a cached belief about another chain, not a local fact.
   */
  isReplica: boolean;
  /** Seconds since the record was last written. `null` when absent. */
  ageSeconds: bigint | null;
}

/**
 * Read a credential's status.
 *
 * Note what this does *not* tell you: whether the provider is paused, whether the
 * schema is still supported here, or whether a replica is stale. Those are policy
 * inputs, so use {@link hasValidCredential} or `explainCredentialDecision` to make
 * an access decision. This function is for display.
 */
export async function getCredentialStatus(
  client: PublicClient,
  registry: CredentialRegistryLike,
  ccid: Hex,
  credentialType: Hex,
): Promise<CredentialStatusResult> {
  const [exists, status, raw, propagation, age] = await Promise.all([
    client.readContract({ address: registry.address, abi: registry.abi, functionName: "exists", args: [ccid] }),
    client.readContract({ address: registry.address, abi: registry.abi, functionName: "statusOf", args: [ccid] }),
    client.readContract({ address: registry.address, abi: registry.abi, functionName: "getRecord", args: [ccid] }),
    client.readContract({ address: registry.address, abi: registry.abi, functionName: "getPropagationState", args: [ccid] }),
    client.readContract({ address: registry.address, abi: registry.abi, functionName: "ageOf", args: [ccid] }),
  ]);

  const statusNumber = Number(status);
  const prop = toPropagationState(propagation as readonly unknown[]);

  return {
    ccid,
    credentialType,
    exists: Boolean(exists),
    status: statusNumber,
    statusName: credentialStatusName(statusNumber),
    record: Boolean(exists) ? toRecord(raw as readonly unknown[]) : null,
    propagation: Boolean(exists) ? prop : null,
    isReplica: Boolean(exists) && prop.isReplica,
    ageSeconds: Boolean(exists) ? (age as bigint) : null,
  };
}

/**
 * Does this credential satisfy `requirement`?
 *
 * A thin wrapper that discards the reason. Prefer
 * {@link explainCredentialDecision} unless the reason is genuinely uninteresting,
 * because "no" without a reason is rarely actionable.
 */
export async function hasValidCredential(
  client: PublicClient,
  policy: CredentialRegistryLike,
  ccid: Hex,
  requirement: CredentialRequirement,
): Promise<boolean> {
  const decision = await explainCredentialDecision(client, policy, ccid, requirement);
  return decision.allowed;
}

/**
 * Evaluate a credential and explain the outcome.
 *
 * This is the function integrators should call. It returns both the decision and
 * a human-readable reason, and it never silently coerces a denial into a retryable
 * state.
 */
export async function explainCredentialDecision(
  client: PublicClient,
  policy: CredentialRegistryLike,
  ccid: Hex,
  requirement: CredentialRequirement,
): Promise<PolicyDecision> {
  const [allowed, reason] = (await client.readContract({
    address: policy.address,
    abi: policy.abi,
    functionName: "evaluate",
    args: [ccid, toRequirementArg(requirement)],
  })) as readonly [boolean, Hex];

  return decide(allowed, reason);
}

/** Shape a requirement for ABI encoding, defaulting every optional field. */
export function toRequirementArg(req: CredentialRequirement): readonly [Hex, number, readonly Hex[], bigint, boolean] {
  return [req.credentialType, req.schemaVersion, req.acceptedProviders ?? [], req.maxAgeSeconds ?? 0n, req.requireFresh ?? false];
}