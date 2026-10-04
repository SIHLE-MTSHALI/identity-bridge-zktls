import { toHex, keccak256, type Address, type Hex } from "viem";
import {
  CREDENTIAL_STATUS_NAMES,
  credentialStatusName,
  providerStatusName,
  REASON_LABELS,
  type CredentialStatusName,
  type ProviderStatusName,
  type ReasonLabel,
} from "./types.js";

/**
 * @file reason codes
 *
 * Reason codes are `keccak256("UPPERCASE_LABEL")` on-chain. Deriving them here
 * from the same label list keeps the SDK and the contract in agreement without
 * duplicating 14 opaque 32-byte literals that nobody can review.
 */

/** Compute the on-chain bytes32 for a reason label. */
export function reasonCode(label: ReasonLabel): Hex {
  return keccak256(toHex(label));
}

const BY_CODE = new Map<Hex, ReasonLabel>(REASON_LABELS.map((l) => [reasonCode(l), l]));

/**
 * Resolve a bytes32 reason code to its label.
 *
 * Returns `"UNRECOGNIZED"` rather than throwing for an unknown code. A newer
 * contract may introduce reasons this SDK predates, and an integrator's logging
 * path should degrade rather than crash in the middle of an incident.
 */
export function reasonLabel(code: Hex): ReasonLabel | "UNRECOGNIZED" {
  return BY_CODE.get(code.toLowerCase() as Hex) ?? "UNRECOGNIZED";
}

/**
 * Reason codes are received from `PolicyManagerAdapter.evaluate`, never submitted,
 * so the SDK derives them for display and never ABI-encodes one. There is
 * deliberately no `encodeReasonCode` helper: nothing in the protocol sends a
 * reason code on-chain, and an encoding helper would only invite callers to think
 * otherwise.
 */

/**
 * A decoded credential record.
 *
 * Every field is a hash, a number, or an enum by construction - see
 * `docs/privacy-model.md`. There is deliberately no field that could hold a name,
 * email, or document, so this type cannot be used to accidentally move personal
 * data off-chain.
 */
export interface CredentialRecord {
  ccid: Hex;
  credentialType: Hex;
  providerId: Hex;
  evidenceHash: Hex;
  schemaVersion: number;
  issuedAt: bigint;
  expiresAt: bigint;
  updatedAt: bigint;
  nonce: bigint;
  status: number;
}

/** Replica metadata. Present only for state learned via CCIP. */
export interface PropagationState {
  isReplica: boolean;
  sourceChainSelector: bigint;
  lastUpdatedAt: bigint;
  lastSourceNonce: bigint;
}

/** A registered credential schema. */
export interface SchemaInfo {
  credentialType: Hex;
  schemaVersion: number;
  ttlSeconds: bigint;
  revocationMode: number;
  active: boolean;
  registered: boolean;
  metadataURI: string;
  createdAt: bigint;
  updatedAt: bigint;
}

/** A registered provider adapter. */
export interface ProviderInfo {
  providerId: Hex;
  status: number;
  metadataURI: string;
  registered: boolean;
  lastHeartbeat: bigint;
  failureCount: bigint;
  registeredAt: bigint;
  updatedAt: bigint;
}

/** An integrator's access requirement. Mirrors `CredentialRequirement`. */
export interface CredentialRequirement {
  /** Required schema family. Zero means "any". */
  credentialType: Hex;
  /** Required schema version. Zero means "any supported version". */
  schemaVersion: number;
  /** Trusted providers. Empty means "any provider the schema admits". */
  acceptedProviders?: readonly Hex[];
  /** Maximum tolerated replica age. Only applied when `requireFresh` is set. */
  maxAgeSeconds?: bigint;
  /** Reject replicas older than `maxAgeSeconds`. Source records are exempt. */
  requireFresh?: boolean;
}

/**
 * The result of an access check.
 *
 * `allowed` is authoritative and `reason` exists so a denial can be acted on.
 *
 * Note there is no `status` field. A policy decision is not the same thing as a
 * credential status: `Revoked` and a paused provider both deny, but they need
 * different responses, and the reason code is what distinguishes them. Call
 * {@link getCredentialStatus} when the lifecycle state itself is what you need.
 */
export interface PolicyDecision {
  allowed: boolean;
  reason: Hex;
  reasonName: ReasonLabel | "UNRECOGNIZED";
}

export function decide(allowed: boolean, reason: Hex): PolicyDecision {
  return { allowed, reason, reasonName: reasonLabel(reason) };
}

/** Convert a raw contract record tuple into a typed record. */
export function toRecord(raw: readonly unknown[]): CredentialRecord {
  return {
    ccid: raw[0] as Hex,
    credentialType: raw[1] as Hex,
    providerId: raw[2] as Hex,
    evidenceHash: raw[3] as Hex,
    schemaVersion: Number(raw[4]),
    issuedAt: raw[5] as bigint,
    expiresAt: raw[6] as bigint,
    updatedAt: raw[7] as bigint,
    nonce: raw[8] as bigint,
    status: Number(raw[9]),
  };
}

export function toPropagationState(raw: readonly unknown[]): PropagationState {
  return {
    isReplica: Boolean(raw[0]),
    sourceChainSelector: raw[1] as bigint,
    lastUpdatedAt: raw[2] as bigint,
    lastSourceNonce: raw[3] as bigint,
  };
}

export function toSchema(raw: readonly unknown[]): SchemaInfo {
  return {
    credentialType: raw[0] as Hex,
    schemaVersion: Number(raw[1]),
    ttlSeconds: raw[2] as bigint,
    revocationMode: Number(raw[3]),
    active: Boolean(raw[4]),
    registered: Boolean(raw[5]),
    metadataURI: String(raw[6]),
    createdAt: raw[7] as bigint,
    updatedAt: raw[8] as bigint,
  };
}

export function toProvider(raw: readonly unknown[]): ProviderInfo {
  return {
    providerId: raw[0] as Hex,
    status: Number(raw[1]),
    metadataURI: String(raw[2]),
    registered: Boolean(raw[3]),
    lastHeartbeat: raw[4] as bigint,
    failureCount: raw[5] as bigint,
    registeredAt: raw[6] as bigint,
    updatedAt: raw[7] as bigint,
  };
}

export { credentialStatusName, providerStatusName, CREDENTIAL_STATUS_NAMES };
export type { Address, CredentialStatusName, ProviderStatusName };