/**
 * @file adapters
 *
 * Provider adapter contract.
 *
 * ## Shape of an adapter
 *
 * An adapter turns an opaque proof into a minimal verification outcome. It is
 * deliberately narrow: {verify} returns booleans and a commitment, never the
 * underlying material. That is what lets the rest of the system stay ignorant of
 * what a "proof" is, and it is what makes a new provider a drop-in change rather
 * than a core edit (`FR-002`).
 *
 * ## The sensitive boundary
 *
 * Raw proof material enters an adapter and must not leave it. Adapters receive
 * material in `input` and are expected to return only {AdapterVerification}. The
 * `raw` field on the input is explicitly typed as opaque so an adapter cannot
 * accidentally serialize it into a result.
 *
 * ## Failure modes are part of the contract
 *
 * A provider that is unavailable must say so ({ProviderUnavailable}) rather than
 * return `verified: false`. The distinction matters operationally: "this person
 * failed KYC" and "we could not reach the KYC provider" demand completely
 * different responses, and collapsing them is how an outage silently denies every
 * applicant.
 */

import type { Commitment } from "../privacy.js";

/** Opaque proof material. Never log, never serialize, never persist. */
export type RawProof = { readonly __brand: "RawProof"; readonly bytes: Uint8Array };

/** Wrap raw material so it cannot be passed around by accident as a plain value. */
export function rawProof(bytes: Uint8Array): RawProof {
  return { __brand: "RawProof", bytes };
}

/** What an adapter is asked. */
export interface AdapterInput {
  /** Opaque provider proof. */
  raw: RawProof;
  /** Schema family being verified. */
  credentialType: string;
  /** Schema version the result will be issued under. */
  schemaVersion: number;
  /** Workflow request identifier, for correlation. Must not identify the subject. */
  requestId: string;
  /** Injectable clock, so tests are deterministic. */
  now: number;
}

/** What an adapter returns. Contains no raw material, by construction. */
export interface AdapterVerification {
  /** True only when the provider affirmatively attested the attribute. */
  verified: boolean;
  /** Schema family the provider actually verified against. */
  credentialType: string;
  /** Non-identifying label for the evidence, e.g. `"reclaim.email-proof"`. */
  evidenceLabel: string;
  /** Commitment to the evidence, salted so it is not correlatable. */
  evidenceCommitment: Commitment;
  /** Provider's own timestamp, when available. */
  observedAt?: number;
}

/** Why an adapter could not reach a verdict. Distinct from a negative verdict. */
export type AdapterFailure =
  | "provider_unreachable"
  | "proof_malformed"
  | "proof_expired"
  | "schema_unsupported"
  | "subject_mismatch"
  | "provider_error";

/** Result of an adapter call. Exactly one of verification/failure is set. */
export type AdapterResult =
  | { ok: true; verification: AdapterVerification }
  | { ok: false; failure: AdapterFailure; detail: string };

/** A provider adapter. */
export interface ProviderAdapter {
  /** Stable identifier, matching the on-chain `providerId`. */
  readonly providerId: string;
  /** Schema families this adapter can attest. */
  readonly supportedCredentialTypes: readonly string[];
  /** Schema versions this adapter supports. */
  readonly supportedSchemaVersions: readonly number[];
  /** Whether the adapter can attest a given schema. */
  supports(credentialType: string, schemaVersion: number): boolean;
  /** Verify an opaque proof. Must not throw for expected failures. */
  verify(input: AdapterInput): Promise<AdapterResult>;
}

/** Convenience constructor for an unsupported-schema failure. */
export function unsupportedSchema(adapter: ProviderAdapter, credentialType: string, schemaVersion: number): AdapterResult {
  return {
    ok: false,
    failure: "schema_unsupported",
    detail: `${adapter.providerId} does not support ${credentialType}@v${schemaVersion}`,
  };
}