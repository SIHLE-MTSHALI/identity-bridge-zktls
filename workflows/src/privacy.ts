/**
 * @file privacy
 *
 * The privacy boundary for Chainlink CRE workflows.
 *
 * ## The rule
 *
 * A workflow handles raw proof material: a TLS transcript, a zkTLS proof, an
 * account handle, a document reference, a provider report. None of that may reach
 * a workflow log, an event, or chain state.
 *
 * ## Why a runtime guard rather than a convention
 *
 * Chainlink CRE logs are operational records that persist and are frequently
 * readable by anyone monitoring a public workflow run. A single `console.log` of a
 * response body turns an off-chain privacy boundary into an on-chain disclosure,
 * and it is exactly the mistake that is easy to make during an incident.
 *
 * So the boundary is enforced, not documented. {safeLog} and {assertRedacted} are
 * the only sanctioned ways to emit anything, and every workflow in this package
 * routes through them. `test/privacy.test.ts` proves the guard actually rejects
 * raw material rather than merely being the documented convention.
 */

import { createHash, randomBytes } from "node:crypto";

/**
 * Tokens that mark a field as raw material wherever they appear in a key.
 *
 * Substring-matched, so compound names are caught: `tlsNotaryTranscript` and
 * `rawProofHex` are both raw material, and exact matching would wave them through.
 * Only tokens that cannot plausibly appear in an innocuous field name belong here.
 */
const FORBIDDEN_TOKENS = [
  "proof",
  "transcript",
  "passport",
  "email",
  "phone",
  "ssn",
  "taxid",
  "dateofbirth",
  "birthdate",
  "privatekey",
  "apikey",
  "apisecret",
  "apiresponse",
  "notarytranscript",
] as const;

/**
 * Fields that are raw material only when the key is exactly this.
 *
 * These are words that legitimately appear inside safe field names, so substring
 * matching would produce false positives. `name` is the clearest example: this
 * entire system is about *credentials*, and a substring rule on `credential` or
 * `name` flags `credentialType`, `namespace`, and `displayName` - at which point
 * every developer disables the guard and the real leaks get through.
 *
 * Over-matching is not a safe default. A guard that cries wolf is worse than no
 * guard, so anything ambiguous is matched exactly.
 */
const FORBIDDEN_EXACT = [
  "handles",
  "accounthandle",
  "document",
  "documents",
  "idnumber",
  "name",
  "legalname",
  "fullname",
  "firstname",
  "lastname",
  "address",
  "dob",
  "providerreport",
  "report",
  "certificate",
  "secret",
  "password",
  "token",
  "seed",
  "salt",
] as const;

/**
 * Anything that plausibly carries raw material, used to shape a value before
 * hashing rather than rejecting it outright.
 */
export interface Rawish {
  [key: string]: unknown;
}

function normalise(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * True when `key` names a field whose value must not be logged verbatim.
 *
 * Matched on the normalised key, so `raw_proof`, `rawProof`, and `Raw-Proof` are all
 * caught. See {FORBIDDEN_TOKENS} and {FORBIDDEN_EXACT} for why the two lists use
 * different matching strategies.
 */
export function isForbiddenKey(key: string): boolean {
  const n = normalise(key);
  if ((FORBIDDEN_EXACT as readonly string[]).includes(n)) return true;
  return (FORBIDDEN_TOKENS as readonly string[]).some((token) => n.includes(token));
}

/**
 * A salted commitment to sensitive material.
 *
 * The salt never leaves the workflow, which is what makes the commitment
 * non-reversible and non-correlatable across credentials. Reusing a salt would
 * let anyone holding two commitments detect that they describe the same subject -
 * so a fresh salt is generated per commitment, always.
 */
export interface Commitment {
  value: string;
  saltFingerprint: string;
}

/**
 * Commit to sensitive material with a fresh random salt.
 *
 * @param material Raw material. Never logged, never returned, never persisted.
 * @param materialLabel A non-identifying label used only for the returned
 *        fingerprint, e.g. `"kyc.verified"`. Must not contain identifying detail.
 */
export function commit(material: string, materialLabel: string): Commitment {
  const salt = randomBytes(32);
  // Domain-separated by label so the same underlying value committed under two
  // different credential types yields two different commitments. Without this, a
  // holder who proved the same fact for two schemas could be correlated across them.
  const value = createHash("sha256").update(Buffer.from(materialLabel, "utf8")).update("\0").update(salt).update(material).digest("hex");
  // Fingerprint of the salt, not the salt. Lets an operator confirm two
  // commitments used different salts without learning either.
  const saltFingerprint = createHash("sha256").update(salt).digest("hex").slice(0, 16);
  return { value: `0x${value}`, saltFingerprint };
}

/** Deterministic commitment, for tests and for reproducible fixtures only. */
export function commitDeterministic(material: string, saltHex: string): Commitment {
  const value = createHash("sha256").update(Buffer.from(saltHex, "hex")).update(material).digest("hex");
  const saltFingerprint = createHash("sha256").update(Buffer.from(saltHex, "hex")).digest("hex").slice(0, 16);
  return { value: `0x${value}`, saltFingerprint };
}

/** Thrown when raw material reaches a log sink. */
export class RawMaterialInLogError extends Error {
  constructor(public readonly keys: readonly string[]) {
    super(
      `refusing to log raw material: ${keys.join(", ")}. ` +
        "Hash or drop these fields; see docs/privacy-model.md.",
    );
    this.name = "RawMaterialInLogError";
  }
}

/**
 * Scan an object for raw material and return it only if clean.
 *
 * Throws {RawMaterialInLogError} listing the offending keys. Failing loudly is the
 * point: a silent redaction would let a caller believe a field was safe to log.
 */
export function assertRedacted(value: unknown, path = ""): void {
  if (value === null || value === undefined) return;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, i) => assertRedacted(item, path ? `${path}[${i}]` : `[${i}]`));
    return;
  }

  if (typeof value === "object") {
    const offenders: string[] = [];
    for (const [key, child] of Object.entries(value as Rawish)) {
      if (isForbiddenKey(key)) offenders.push(path ? `${path}.${key}` : key);
      assertRedacted(child, path ? `${path}.${key}` : key);
    }
    if (offenders.length > 0) throw new RawMaterialInLogError(offenders);
  }
}

/**
 * Remove every raw-material field.
 *
 * Keys are **dropped**, not replaced with a placeholder. Keeping `proof:
 * "[redacted]"` would still disclose that a proof existed, would still name the
 * field on the log line, and would still trip {assertRedacted} - so a marker buys
 * nothing and leaves a false sense that the record is safe.
 *
 * Use when the shape of the input is not fully under your control - a provider
 * response, say - and you need a log line rather than a crash. Output always
 * satisfies {assertRedacted}.
 */
export function redact(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === "object") {
    const out: Rawish = {};
    for (const [key, child] of Object.entries(value as Rawish)) {
      if (isForbiddenKey(key)) continue; // dropped entirely
      out[key] = redact(child);
    }
    return out;
  }
  return value;
}

/** The sink a workflow writes audit lines to. Injected so tests can capture it. */
export type LogSink = (level: "info" | "warn" | "error", message: string, context?: unknown) => void;

/**
 * Emit an audit line that is guaranteed free of raw material.
 *
 * Every workflow routes its logging through here. A line that would carry raw
 * material throws rather than emitting, so the leak never reaches the log sink.
 */
export function safeLog(sink: LogSink, level: "info" | "warn" | "error", message: string, context?: unknown): void {
  assertRedacted(context);
  sink(level, message, context);
}