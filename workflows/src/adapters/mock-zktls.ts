/**
 * @file mock-zktls
 *
 * Fixture adapter used by tests and by the local development harness.
 *
 * ## Why this exists
 *
 * `Gate 1` of the PRD requires "at least two credential schemas and one
 * fixture-backed provider work end to end". A fixture adapter is the only way to
 * test issuance, expiry, revocation, and propagation without a live provider -
 * and, more importantly, it lets a test *choose* the outcome, so the denial paths
 * get the same coverage as the happy path.
 *
 * ## What it must never become
 *
 * This adapter must never be registered as `Active` on a production deployment.
 * It accepts any proof and can be told to verify or fail by its input, which is
 * useful in a test and catastrophic in production. {FIXTURE_MARKER} exists so
 * tooling can refuse a deployment that registers it.
 */

import { commitDeterministic, type Commitment } from "../privacy.js";
import { unsupportedSchema, type AdapterInput, type AdapterResult, type ProviderAdapter } from "./types.js";

/** Marker a deployment script can assert against before registering this adapter. */
export const FIXTURE_MARKER = "fixture-only-mock-zktls";

/**
 * Fixture proof envelope.
 *
 * Carries an explicit outcome so a test can drive any branch deterministically.
 * A real proof would be an opaque blob; the shape here exists only because this
 * adapter must be scriptable.
 */
export interface FixtureProof {
  readonly outcome: "verified" | "rejected" | "malformed" | "expired" | "unreachable" | "subject_mismatch";
  /** Salt for the deterministic evidence commitment. Hex. */
  readonly saltHex: string;
  /** Non-identifying evidence description. Never contains subject detail. */
  readonly evidence?: string;
  /** Credential type the fixture claims, to exercise schema-mismatch handling. */
  readonly credentialType?: string;
}

/** Parse the fixture envelope from raw bytes. */
function parseFixture(bytes: Uint8Array): FixtureProof | null {
  try {
    const text = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(text) as Partial<FixtureProof>;
    if (typeof parsed.outcome !== "string") return null;
    const saltHex = typeof parsed.saltHex === "string" && /^[0-9a-f]{64}$/i.test(parsed.saltHex)
      ? parsed.saltHex
      : "00".repeat(32);
    // Conditional spread rather than an explicit undefined: under
    // exactOptionalPropertyTypes, assigning undefined to an optional field is an
    // error, and omitting the key is the correct representation of "not present".
    return {
      outcome: parsed.outcome as FixtureProof["outcome"],
      saltHex,
      evidence: typeof parsed.evidence === "string" ? parsed.evidence : "fixture-evidence",
      ...(typeof parsed.credentialType === "string" ? { credentialType: parsed.credentialType } : {}),
    };
  } catch {
    return null;
  }
}

/** Encode a fixture proof. Test helper, not used on any real path. */
export function encodeFixture(proof: FixtureProof): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(proof));
}

export function mockZkTlsAdapter(options?: {
  providerId?: string;
  supportedCredentialTypes?: readonly string[];
  supportedSchemaVersions?: readonly number[];
}): ProviderAdapter {
  const providerId = options?.providerId ?? "provider.mock-zktls";
  const supportedCredentialTypes = options?.supportedCredentialTypes ?? ["kyc.basic", "accreditation.investor"];
  const supportedSchemaVersions = options?.supportedSchemaVersions ?? [1];

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

      const fixture = parseFixture(input.raw.bytes);
      if (fixture === null) {
        return { ok: false, failure: "proof_malformed", detail: "fixture envelope could not be parsed" };
      }

      // A fixture may deliberately claim a different schema, to prove the workflow
      // checks what the provider says rather than what it asked for.
      if (fixture.credentialType !== undefined && fixture.credentialType !== input.credentialType) {
        return {
          ok: false,
          failure: "subject_mismatch",
          detail: `fixture claims ${fixture.credentialType}, workflow asked for ${input.credentialType}`,
        };
      }

      // Commitment is salted and domain-separated by evidence label. The salt is a
      // fixed test value so commitments are reproducible across runs.
      const evidenceCommitment: Commitment = commitDeterministic(
        `${fixture.evidence ?? "fixture-evidence"}|${input.requestId}`,
        fixture.saltHex,
      );

      switch (fixture.outcome) {
        case "verified":
          return {
            ok: true,
            verification: {
              verified: true,
              credentialType: input.credentialType,
              evidenceLabel: `${FIXTURE_MARKER}.verified`,
              evidenceCommitment,
              observedAt: input.now,
            },
          };
        case "rejected":
          // An affirmative negative. Distinct from an outage on purpose.
          return {
            ok: true,
            verification: {
              verified: false,
              credentialType: input.credentialType,
              evidenceLabel: `${FIXTURE_MARKER}.rejected`,
              evidenceCommitment,
              observedAt: input.now,
            },
          };
        case "expired":
          return { ok: false, failure: "proof_expired", detail: "fixture proof past its validity window" };
        case "unreachable":
          return { ok: false, failure: "provider_unreachable", detail: "fixture simulates provider outage" };
        case "subject_mismatch":
          return { ok: false, failure: "subject_mismatch", detail: "fixture simulates a subject mismatch" };
        case "malformed":
        default:
          return { ok: false, failure: "proof_malformed", detail: "fixture simulates a malformed proof" };
      }
    },
  };
}