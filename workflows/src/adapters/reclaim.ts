/**
 * @file reclaim
 *
 * Adapter boundary for a Reclaim-style zkTLS provider.
 *
 * ## Status: not implemented, on purpose
 *
 * This file defines the integration surface and its failure handling, but performs
 * **no network call**. That is a deliberate choice rather than an omission:
 *
 * - A live call would need an API key and network access, neither of which belongs
 *   in a test suite or in a public repository's verification path.
 * - The parts of this adapter that actually carry risk - what is logged, what is
 *   returned, how a provider outage is distinguished from a negative result - are
 *   fully specified and tested here, independently of any vendor SDK.
 * - A half-written vendor client is worse than an honest boundary: it looks
 *   integrated and cannot be verified.
 *
 * `Gate 3` of the PRD requires a reviewed real provider adapter before any pilot.
 * That review has not happened, so this adapter throws rather than pretending.
 *
 * ## What a real implementation must preserve
 *
 * 1. {ReclaimTransport.verify} is the only place a vendor payload is touched.
 * 2. Raw material never leaves {ReclaimTransport.verify}.
 * 3. A transport failure yields `provider_unreachable`, never `verified: false`.
 * 4. The commitment is always freshly salted per credential.
 */

import { commit, type Commitment } from "../privacy.js";
import { unsupportedSchema, type AdapterInput, type AdapterResult, type ProviderAdapter } from "./types.js";

/** The vendor payload, as this adapter needs it. Opaque by design. */
export interface ReclaimClaim {
  readonly raw: Uint8Array;
  /** Non-identifying claim label, e.g. `"EmailAddress"`. */
  readonly claimLabel: string;
}

/**
 * Transport seam.
 *
 * Separating this from the adapter means the privacy and failure-handling logic can
 * be tested with a fake, and a real client can be dropped in without touching the
 * parts that matter.
 */
export interface ReclaimTransport {
  verify(claim: ReclaimClaim, signal?: AbortSignal): Promise<ReclaimVerification>;
}

/** What the vendor says, before this adapter reduces it. */
export interface ReclaimVerification {
  /** Vendor's affirmative/negative verdict. */
  readonly valid: boolean;
  /** Vendor timestamp, seconds. */
  readonly observedAt: number;
  /** Vendor evidence label. Must contain no subject detail. */
  readonly evidenceLabel: string;
  /** Non-empty when the vendor rejected the claim. */
  readonly reason?: string;
}

/**
 * Error raised when a real Reclaim transport has not been supplied.
 *
 * Failing loudly is the point. An adapter that returned `provider_unreachable`
 * here would be indistinguishable from a genuine outage, and operators would burn
 * incident time chasing a vendor problem that does not exist.
 */
export class ReclaimTransportNotConfiguredError extends Error {
  constructor() {
    super(
      "ReclaimTransport not configured. This adapter is a documented boundary, not a live " +
        "integration. Supply a transport, or use the mock-zktls fixture adapter for testing.",
    );
    this.name = "ReclaimTransportNotConfiguredError";
  }
}

export function reclaimAdapter(options: {
  providerId?: string;
  supportedCredentialTypes?: readonly string[];
  supportedSchemaVersions?: readonly number[];
  transport?: ReclaimTransport;
} = {}): ProviderAdapter {
  const providerId = options?.providerId ?? "provider.reclaim";
  const supportedCredentialTypes = options?.supportedCredentialTypes ?? ["kyc.basic"];
  const supportedSchemaVersions = options?.supportedSchemaVersions ?? [1];
  const transport = options?.transport;

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
        // Unambiguous and distinguishable from a vendor outage.
        throw new ReclaimTransportNotConfiguredError();
      }

      const claim: ReclaimClaim = {
        raw: input.raw.bytes,
        claimLabel: input.credentialType,
      };

      let vendor: ReclaimVerification;
      try {
        vendor = await transport.verify(claim);
      } catch (err) {
        // A thrown transport error is an availability problem, never a verdict.
        // Returning `provider_unreachable` is what lets the workflow decide to
        // retry rather than deny.
        return {
          ok: false,
          failure: "provider_unreachable",
          detail: err instanceof Error ? err.message : "unknown transport error",
        };
      }

      // Fresh salt per credential: reusing one would let anyone holding two
      // commitments detect that they describe the same subject.
      const evidenceCommitment: Commitment = commit(vendor.evidenceLabel, input.credentialType);

      return {
        ok: true,
        verification: {
          verified: vendor.valid,
          credentialType: input.credentialType,
          evidenceLabel: vendor.evidenceLabel,
          evidenceCommitment,
          observedAt: vendor.observedAt ?? input.now,
        },
      };
    },
  };
}