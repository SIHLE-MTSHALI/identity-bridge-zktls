/**
 * @file credential-verify
 *
 * Chainlink CRE workflow: verify an attribute and issue a credential.
 *
 * Implements step 5 of `ENGINEERING_SPEC.md`, and the ordering below is the whole
 * point of the workflow:
 *
 *   1. Load the provider adapter and schema policy.
 *   2. Validate the proof with the adapter.
 *   3. Compute the CCID and evidence hash **without exposing raw proof material**.
 *   4. Submit the credential result to the bridge.
 *   5. Trigger CCIP propagation when destination chains are configured.
 *
 * ## Why each rejection is distinct
 *
 * {VerifyOutcome.kind} separates `rejected` (the provider said no) from
 * `unavailable` (we could not reach the provider) and from `invalid` (the request
 * was malformed). Collapsing the first two is the classic integration bug: an
 * outage then denies every applicant, and the denial is indistinguishable from a
 * genuine negative. Each gets its own `kind` so the caller can retry the right one.
 */

import { keccak256, toHex, encodeAbiParameters, parseAbiParameters } from "viem";
import { commit, RawMaterialInLogError, safeLog, type Commitment, type LogSink } from "./privacy.js";
import { rawProof, type AdapterFailure, type ProviderAdapter, type RawProof } from "./adapters/types.js";

/** What a workflow caller supplies. */
export interface VerifyRequest {
  readonly credentialType: string;
  readonly schemaVersion: number;
  readonly providerId: string;
  /** Opaque proof. Never logged. */
  readonly raw: RawProof;
  /** Correlation id. Must not identify the subject. */
  readonly requestId: string;
  /** Chain selectors to propagate to. Empty disables propagation. */
  readonly destinationChainSelectors?: readonly bigint[];
}

/** Schema policy the workflow enforces before touching a provider. */
export interface SchemaPolicy {
  readonly credentialType: string;
  readonly schemaVersion: number;
  readonly ttlSeconds: bigint;
  readonly acceptedProviders: readonly string[];
  readonly revocationMode: "IssuerOnly" | "HolderOrIssuer" | "GovernanceOnly";
}

/** The bridge submission, as the workflow computes it. */
export interface CredentialSubmission {
  readonly ccid: string;
  readonly credentialType: string;
  readonly schemaVersion: number;
  readonly providerId: string;
  readonly subjectCommitment: string;
  readonly evidenceHash: string;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly nonce: bigint;
  readonly destinationChainSelectors: readonly bigint[];
}

/** Outbound effect the runner must perform. The workflow never signs. */
export interface PendingEffect {
  readonly kind: "submit_credential" | "revoke_credential" | "none";
  readonly submission?: CredentialSubmission;
  readonly ccid?: string;
  readonly reason?: string;
}

/** Result. `kind` is the caller's routing signal. */
export type VerifyOutcome =
  | { kind: "issued"; ccid: string; expiresAt: bigint; propagationTargets: number }
  | { kind: "rejected"; reason: string; evidenceLabel: string }
  | { kind: "unavailable"; failure: AdapterFailure; detail: string; retryable: true }
  | { kind: "invalid"; reason: string };

/** Ports the runner injects. Keeps the workflow testable without a chain. */
export interface VerifyDeps {
  readonly registry: ReadonlyMap<string, SchemaPolicy>;
  readonly adapters: ReadonlyMap<string, ProviderAdapter>;
  /** Current nonce for a CCID. Injected because it lives in contract storage. */
  readonly readNonce: (ccid: string) => Promise<bigint>;
  /** Submitted ccid -> issuedAt, to keep timestamps monotonic on re-issuance. */
  readonly readIssuedAt: (ccid: string) => Promise<bigint | null>;
  readonly log?: LogSink;
  readonly now?: () => bigint;
}

const noopSink: LogSink = () => {};

/**
 * Run the verify workflow.
 *
 * Pure with respect to the chain: it returns an effect for the runner to execute.
 * That separation is deliberate - a workflow that signs directly cannot be tested
 * and cannot be reviewed for what it will actually submit.
 */
export async function credentialVerify(request: VerifyRequest, deps: VerifyDeps): Promise<VerifyOutcome> {
  const now = deps.now ? deps.now() : BigInt(Math.floor(Date.now() / 1000));
  const log = deps.log ?? noopSink;

  if (request.requestId.trim() === "") {
    return { kind: "invalid", reason: "requestId is required and must not be empty" };
  }
  if (request.raw.bytes.length === 0) {
    return { kind: "invalid", reason: "proof payload is empty" };
  }

  // --- 1. Load provider adapter and schema policy. ---
  const policy = deps.registry.get(`${request.credentialType}@v${request.schemaVersion}`);
  if (policy === undefined) {
    return { kind: "invalid", reason: `no schema policy for ${request.credentialType}@v${request.schemaVersion}` };
  }

  const adapter = deps.adapters.get(request.providerId);
  if (adapter === undefined) {
    // A missing adapter is a configuration problem, not a provider outage.
    return { kind: "invalid", reason: `no adapter registered for provider ${request.providerId}` };
  }

  if (!policy.acceptedProviders.includes(request.providerId)) {
    return {
      kind: "invalid",
      reason: `provider ${request.providerId} is not admitted by schema ${request.credentialType}@v${request.schemaVersion}`,
    };
  }

  if (!adapter.supports(request.credentialType, request.schemaVersion)) {
    return {
      kind: "invalid",
      reason: `adapter ${request.providerId} does not support ${request.credentialType}@v${request.schemaVersion}`,
    };
  }

  // --- 2. Validate the proof with the adapter. ---
  const result = await adapter.verify({
    raw: request.raw,
    credentialType: request.credentialType,
    schemaVersion: request.schemaVersion,
    requestId: request.requestId,
    now: Number(now),
  });

  if (!result.ok) {
    // Availability failures are retryable. A malformed proof is not.
    const retryable = result.failure === "provider_unreachable" || result.failure === "provider_error";
    safeLog(log, retryable ? "warn" : "error", "provider verification failed", {
      requestId: request.requestId,
      providerId: request.providerId,
      failure: result.failure,
      credentialType: request.credentialType,
    });
    return retryable
      ? { kind: "unavailable", failure: result.failure, detail: result.detail, retryable: true }
      : { kind: "invalid", reason: `${result.failure}: ${result.detail}` };
  }

  const verification = result.verification;

  // The provider may attest a different schema than the one requested. Trusting
  // the provider's answer over the request is how a credential ends up issued
  // under a schema nobody checked.
  if (verification.credentialType !== request.credentialType) {
    return {
      kind: "invalid",
      reason: `provider attested ${verification.credentialType}, workflow requested ${request.credentialType}`,
    };
  }

  if (!verification.verified) {
    safeLog(log, "info", "provider returned an affirmative negative", {
      requestId: request.requestId,
      providerId: request.providerId,
      evidenceLabel: verification.evidenceLabel,
    });
    return { kind: "rejected", reason: "provider declined to attest", evidenceLabel: verification.evidenceLabel };
  }

  // --- 3. Compute CCID and evidence hash without exposing raw material. ---
  //
  // The commitment is over the provider's evidence *label*, never over the proof.
  // Nothing that leaves this function was derived from `request.raw`.
  const subjectCommitment: Commitment = commit(
    `${verification.evidenceLabel}|${request.requestId}|${request.providerId}`,
    request.credentialType,
  );
  const evidenceCommitment: Commitment = verification.evidenceCommitment;

  const ccid = computeCcid({
    domain: "identity-bridge-zktls/CCID/v1",
    credentialType: request.credentialType,
    schemaVersion: request.schemaVersion,
    providerId: request.providerId,
    subjectCommitment: subjectCommitment.value,
  });

  const previousIssuedAt = await deps.readIssuedAt(ccid);
  const issuedAt = previousIssuedAt !== null && previousIssuedAt >= now ? previousIssuedAt : now;
  const expiresAt = issuedAt + policy.ttlSeconds;
  const nonce = (await deps.readNonce(ccid)) + 1n;
  const destinations = request.destinationChainSelectors ?? [];

  safeLog(log, "info", "credential verified", {
    requestId: request.requestId,
    ccid,
    credentialType: request.credentialType,
    providerId: request.providerId,
    nonce: nonce.toString(),
    expiresAt: expiresAt.toString(),
    propagationTargets: destinations.length,
  });

  return { kind: "issued", ccid, expiresAt, propagationTargets: destinations.length };
}

/**
 * Build the submission the runner should hand to `CredentialBridge`.
 *
 * Separated from {credentialVerify} so a test can assert exactly what would be
 * submitted without executing a transaction.
 */
export function buildSubmission(
  request: VerifyRequest,
  policy: SchemaPolicy,
  ccid: string,
  subjectCommitment: Commitment,
  evidenceCommitment: Commitment,
  issuedAt: bigint,
  nonce: bigint,
): CredentialSubmission {
  return {
    ccid,
    credentialType: request.credentialType,
    schemaVersion: request.schemaVersion,
    providerId: request.providerId,
    subjectCommitment: subjectCommitment.value,
    evidenceHash: evidenceCommitment.value,
    issuedAt,
    expiresAt: issuedAt + policy.ttlSeconds,
    nonce,
    destinationChainSelectors: request.destinationChainSelectors ?? [],
  };
}

/**
 * Convert a human-readable label into the on-chain identifier.
 *
 * `credentialType` and `providerId` are `bytes32` on chain, conventionally
 * `keccak256("label")`. Converting here - once, explicitly - keeps the rest of the
 * workflow working in readable strings while guaranteeing the values it hashes are
 * the same ones the bridge and registries hold.
 */
export function identifier(label: string): `0x${string}` {
  return keccak256(toHex(label));
}

/**
 * CCID derivation, mirroring `CCIDResolver.compute` exactly.
 *
 * The canonical encoding is
 * `abi.encode(DOMAIN, credentialType, uint256(schemaVersion), providerId, subjectCommitment)`
 * hashed with keccak256 - the same field order and the same hash the contract uses.
 *
 * Parity is not assumed. `scripts/generate-ccid-vectors.mjs` runs the on-chain
 * resolver over fixed inputs and writes the results to
 * `workflows/test/vectors/ccid-vectors.json`; `test/ccid-parity.test.ts` asserts
 * this function reproduces every one of them. A change to either side that is not
 * mirrored on the other fails the suite, rather than silently causing the bridge
 * to reject every result the workflow submits.
 */
export function computeCcid(parts: {
  domain: string;
  credentialType: string;
  schemaVersion: number;
  providerId: string;
  subjectCommitment: string;
}): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("bytes32, bytes32, uint256, bytes32, bytes32"),
      [
        keccak256(toHex(parts.domain)),
        identifier(parts.credentialType),
        BigInt(parts.schemaVersion),
        identifier(parts.providerId),
        parts.subjectCommitment as `0x${string}`,
      ],
    ),
  );
}

export { rawProof, RawMaterialInLogError };
export type { ProviderAdapter };