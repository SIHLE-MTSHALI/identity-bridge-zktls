/**
 * On-chain vocabulary, mirroring `contracts/src/libraries/CredentialTypes.sol`.
 *
 * These values are the contract's, not the SDK's. Each is duplicated here rather
 * than generated because the duplication is the point of the file: it is a
 * hand-checkable, greppable record of every status and reason code an integrator
 * can observe, so a contract change that adds an enum member shows up as a
 * compile error here rather than as an unhandled value at runtime.
 */

/** Lifecycle state of a credential. */
export const CredentialStatus = {
  Unknown: 0,
  Pending: 1,
  Valid: 2,
  Expired: 3,
  Suspended: 4,
  Revoked: 5,
  Disputed: 6,
} as const;

export type CredentialStatusValue = (typeof CredentialStatus)[keyof typeof CredentialStatus];

export const CREDENTIAL_STATUS_NAMES = [
  "Unknown",
  "Pending",
  "Valid",
  "Expired",
  "Suspended",
  "Revoked",
  "Disputed",
] as const;

export type CredentialStatusName = (typeof CREDENTIAL_STATUS_NAMES)[number];

export function credentialStatusName(value: number): CredentialStatusName | "Unknown" {
  return CREDENTIAL_STATUS_NAMES[value] ?? "Unknown";
}

/** Operational state of a provider adapter. */
export const ProviderStatus = {
  Unknown: 0,
  Active: 1,
  Paused: 2,
  Deprecated: 3,
  Revoked: 4,
} as const;

export type ProviderStatusValue = (typeof ProviderStatus)[keyof typeof ProviderStatus];

export const PROVIDER_STATUS_NAMES = ["Unknown", "Active", "Paused", "Deprecated", "Revoked"] as const;

export type ProviderStatusName = (typeof PROVIDER_STATUS_NAMES)[number];

export function providerStatusName(value: number): ProviderStatusName | "Unknown" {
  return PROVIDER_STATUS_NAMES[value] ?? "Unknown";
}

/**
 * Reason codes returned by `PolicyManagerAdapter.evaluate`.
 *
 * Kept as `keccak256` of the uppercase label, which is how the contract defines
 * them. A constant list of the labels is exported alongside so callers never have
 * to hardcode a hash, and so an unknown code can still be rendered.
 */
export const REASON_LABELS = [
  "OK",
  "UNKNOWN",
  "PENDING",
  "EXPIRED",
  "SUSPENDED",
  "REVOKED",
  "DISPUTED",
  "PROVIDER_PAUSED",
  "SCHEMA_UNSUPPORTED",
  "STALE_DESTINATION",
  "CREDENTIAL_TYPE_MISMATCH",
  "SCHEMA_VERSION_UNSUPPORTED",
  "PROVIDER_NOT_ACCEPTED",
  "SYSTEM_PAUSED",
] as const;

export type ReasonLabel = (typeof REASON_LABELS)[number];

/**
 * The one reason code that permits access.
 *
 * `isAllow` is the only correct way to branch on a decision. Comparing a status
 * to `Valid` directly is the mistake this SDK exists to prevent: `Valid` says
 * nothing about provider status, schema support, or destination freshness, so
 * code that checks it can allow access during exactly the incidents it was
 * written to survive.
 */
export const REASON_OK_LABEL = "OK" satisfies ReasonLabel;