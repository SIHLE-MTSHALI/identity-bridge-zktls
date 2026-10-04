/**
 * @file index
 *
 * Public surface of the Identity Bridge zkTLS SDK.
 *
 * ## Start here
 *
 * ```ts
 * import { createPublicClient, http } from "viem";
 * import { explainCredentialDecision, withFreshness, anyVersion } from "@identity-bridge/sdk";
 *
 * const decision = await explainCredentialDecision(client, policyAdapter, ccid, withFreshness(anyVersion(KYC_TYPE)));
 *
 * if (decision.allowed) {
 *   // ...
 * } else if (decision.reasonName === "EXPIRED") {
 *   // Ask the holder to renew. Do not retry.
 * }
 * ```
 *
 * ## The rule this SDK exists to enforce
 *
 * Branch on `decision.allowed`, never on `record.status === "Valid"`.
 *
 * A `Valid` status means the credential is live on this chain. It says nothing
 * about whether the provider has since been paused, whether the schema is still
 * supported here, or whether this chain's copy is a week out of date. Code that
 * checks status directly fails open during exactly the incidents it was written to
 * survive. `evaluate` considers all of it and returns a reason so you can act on
 * the difference.
 */

export {
  CredentialStatus,
  CREDENTIAL_STATUS_NAMES,
  ProviderStatus,
  PROVIDER_STATUS_NAMES,
  REASON_LABELS,
  REASON_OK_LABEL,
  credentialStatusName,
  providerStatusName,
} from "./types.js";
export type {
  CredentialStatusName,
  CredentialStatusValue,
  ProviderStatusName,
  ProviderStatusValue,
  ReasonLabel,
} from "./types.js";

export {
  reasonCode,
  reasonLabel,
  toRecord,
  toPropagationState,
  toSchema,
  toProvider,
  decide,
} from "./decode.js";
export type {
  CredentialRecord,
  CredentialRequirement,
  PolicyDecision,
  PropagationState,
  SchemaInfo,
  ProviderInfo,
} from "./decode.js";

export {
  getCredentialStatus,
  hasValidCredential,
  explainCredentialDecision,
  toRequirementArg,
} from "./credentialStatus.js";
export type { CredentialRegistryLike, CredentialStatusResult } from "./credentialStatus.js";

export {
  getProviderStatus,
  backsExistingCredentials,
  isProviderUsableForIssuance,
  isProviderHealthy,
  acceptedProvidersForSchema,
  reportHeartbeat,
} from "./providerClient.js";
export type { ProviderRegistryLike, ProviderStatusResult } from "./providerClient.js";

export {
  categorize,
  shouldRetry,
  anyVersion,
  withFreshness,
  withProviders,
  DEFAULT_MAX_REPLICA_AGE_SECONDS,
  SELF_SERVICE_REASONS,
  ESCALATION_REASONS,
  ALL_REASON_LABELS,
} from "./policyClient.js";
export type { DecisionCategory } from "./policyClient.js";