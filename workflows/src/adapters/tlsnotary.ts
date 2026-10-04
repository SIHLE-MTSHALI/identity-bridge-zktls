/**
 * @file tlsnotary
 *
 * Adapter boundary for a TLSNotary-style provider.
 *
 * ## Status: documented boundary, not a live integration
 *
 * Same posture as `reclaim.ts`: the privacy and failure-handling logic is
 * specified and tested, but no vendor client is included. See that file for why.
 *
 * ## The distinction from Reclaim that matters
 *
 * TLSNotary-style providers attest *a web origin and a statement about it*, rather
 * than a claim about an account. That has a concrete consequence here: the
 * verified attribute is scoped to an origin, so the same adapter serving two
 * origins produces two different commitments.
 *
 * The origin is folded into the commitment's domain separator for exactly that
 * reason. If it were not, a holder who attested the same attribute on two origins
 * would present two commitments that could be linked.
 *
 * @see ./reclaim.ts for the shared reasoning.
 */

import { commit, type Commitment } from "../privacy.js";
import { unsupportedSchema, type AdapterInput, type AdapterResult, type ProviderAdapter } from "./types.js";

/** A statement a TLS notary observed on an origin. */
export interface TlsNotaryStatement {
  /** Origin the statement was observed on, e.g. `"example.gov"`. */
  readonly origin: string;
  /** Non-identifying statement label, e.g. `"kyc.cleared"`. */
  readonly label: string;
}

/** Transport seam. See {ReclaimTransportNotConfiguredError} semantics. */
export interface TlsNotaryTransport {
  evaluate(statement: TlsNotaryStatement, raw: Uint8Array, signal?: AbortSignal): Promise<TlsNotaryVerdict>;
}

export interface TlsNotaryVerdict {
  readonly valid: boolean;
  readonly observedAt: number;
  /** Non-empty when the statement could not be established. */
  readonly reason?: string;
}

/** Raised when no transport is configured. */
export class TlsNotaryTransportNotConfiguredError extends Error {
  constructor() {
    super(
      "TlsNotaryTransport not configured. This adapter is a documented boundary, not a live " +
        "integration. Supply a transport, or use the mock-zktls fixture adapter for testing.",
    );
    this.name = "TlsNotaryTransportNotConfiguredError";
  }
}

/**
 * Encode a statement request for transport.
 *
 * Split out so tests can assert what the adapter hands to a transport without
 * running one.
 */
export function encodeStatementRequest(
  credentialType: string,
  origin: string,
  label: string,
): TlsNotaryStatement {
  return { origin, label: label === "" ? credentialType : label };
}

export function tlsNotaryAdapter(options: {
  providerId?: string;
  supportedCredentialTypes?: readonly string[];
  supportedSchemaVersions?: readonly number[];
  transport?: TlsNotaryTransport;
  /** Origin this adapter is scoped to. Part of the commitment domain. */
  origin?: string;
  /** Statement label. Part of the commitment domain. */
  statementLabel?: string;
} = {}): ProviderAdapter {
  const providerId = options?.providerId ?? "provider.tlsnotary";
  const supportedCredentialTypes = options?.supportedCredentialTypes ?? ["kyc.basic", "employment.status"];
  const supportedSchemaVersions = options?.supportedSchemaVersions ?? [1];
  const transport = options?.transport;
  const origin = options?.origin ?? "example.invalid";
  const statementLabel = options?.statementLabel ?? "";

  return {
    providerId,
    supportedCredentialTypes,
    supportedSchemaVersions,

    supports(credentialType: string, schemaVersion: number): boolean {
      return supportedCredentialTypes.includes(credentialType) && supportedSchemaVersions.includes(schemaVersion);
    },

    async verify(input: AdapterInput): Promise<AdapterResult> {
      if (!this.supports(input.credentialType, input.schemaVersion)) {
        return unsupportedSchema(this, input.credentialType, input.schemaVersion);
      }

      if (transport === undefined) {
        throw new TlsNotaryTransportNotConfiguredError();
      }

      const statement = encodeStatementRequest(input.credentialType, origin, statementLabel);

      let verdict: TlsNotaryVerdict;
      try {
        verdict = await transport.evaluate(statement, input.raw.bytes);
      } catch (err) {
        return {
          ok: false,
          failure: "provider_unreachable",
          detail: err instanceof Error ? err.message : "unknown transport error",
        };
      }

      // Origin is part of the domain separator, so the same attribute attested on
      // two origins yields two unlinkable commitments.
      const evidenceCommitment: Commitment = commit(`${statement.origin}|${statement.label}`, input.credentialType);

      return {
        ok: true,
        verification: {
          verified: verdict.valid,
          credentialType: input.credentialType,
          evidenceLabel: `tlsnotary.${statement.origin}.${statement.label || input.credentialType}`,
          evidenceCommitment,
          observedAt: verdict.observedAt ?? input.now,
        },
      };
    },
  };
}