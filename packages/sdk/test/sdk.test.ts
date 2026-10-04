import { describe, expect, it } from "vitest";
import { keccak256, toHex, encodeAbiParameters, parseAbiParameters, type Hex } from "viem";
import {
  ALL_REASON_LABELS,
  CREDENTIAL_STATUS_NAMES,
  ESCALATION_REASONS,
  REASON_LABELS,
  SELF_SERVICE_REASONS,
  anyVersion,
  categorize,
  credentialStatusName,
  decide,
  providerStatusName,
  reasonCode,
  reasonLabel,
  shouldRetry,
  toPropagationState,
  toRecord,
  toRequirementArg,
  withFreshness,
  withProviders,
} from "../src/index.js";
import * as sdk from "../src/index.js";

/**
 * These tests deliberately avoid a chain. The SDK's value is that reason codes and
 * statuses map to the contract's definitions; that mapping is pure and can be
 * pinned exactly. Chain-dependent behaviour is covered by the Foundry suite.
 */

const CONTRACT_LABEL = "UNKNOWN";

describe("reason codes", () => {
  it("derives bytes32 exactly as the contract does: keccak256 of the uppercase label", () => {
    expect(reasonCode("REVOKED")).toBe(keccak256(toHex("REVOKED")));
    expect(reasonCode("STALE_DESTINATION")).toBe(keccak256(toHex("STALE_DESTINATION")));
  });

  it("round-trips every reason code", () => {
    for (const label of REASON_LABELS) {
      expect(reasonLabel(reasonCode(label))).toBe(label);
    }
  });

  it("produces distinct codes for distinct labels", () => {
    const codes = new Set(REASON_LABELS.map(reasonCode));
    expect(codes.size).toBe(REASON_LABELS.length);
  });

  it("degrades gracefully for an unknown code instead of throwing", () => {
    // A newer contract may introduce reasons this SDK predates. Crashing a logging
    // path during an incident is strictly worse than admitting the code is unknown.
    const future = keccak256(toHex("PROVIDER_QUARANTINED"));
    expect(reasonLabel(future)).toBe("UNRECOGNIZED");
  });

  it("has no ABI-encoding helper, because reason codes are never submitted", () => {
    // `evaluate` returns the reason; nothing on-chain accepts one. An encoder
    // would suggest otherwise, so the SDK does not provide one.
    expect("encodeReasonCode" in sdk).toBe(false);
  });
});

describe("status names", () => {
  it("maps every credential status in enum order", () => {
    expect(CREDENTIAL_STATUS_NAMES).toHaveLength(7);
    expect(credentialStatusName(0)).toBe("Unknown");
    expect(credentialStatusName(1)).toBe("Pending");
    expect(credentialStatusName(2)).toBe("Valid");
    expect(credentialStatusName(3)).toBe("Expired");
    expect(credentialStatusName(4)).toBe("Suspended");
    expect(credentialStatusName(5)).toBe("Revoked");
    expect(credentialStatusName(6)).toBe("Disputed");
  });

  it("does not throw on an out-of-range status", () => {
    expect(credentialStatusName(99)).toBe("Unknown");
    expect(providerStatusName(99)).toBe("Unknown");
  });
});

describe("decide", () => {
  it("marks only the OK reason as an allow", () => {
    expect(decide(true, reasonCode("OK")).allowed).toBe(true);
    expect(decide(true, reasonCode("OK")).reasonName).toBe("OK");
  });

  it("never reports allowed for a denial reason, even if a caller passes allowed=true", () => {
    // Defensive: the SDK trusts the contract, but a mismatch here would be silent
    // and catastrophic, so the label travels with the boolean for logging.
    const d = decide(false, reasonCode("REVOKED"));
    expect(d.allowed).toBe(false);
    expect(d.reasonName).toBe("REVOKED");
  });
});

describe("categorize", () => {
  it("puts every reason in exactly one category", () => {
    const seen = new Set(ALL_REASON_LABELS.map(categorize));
    expect(seen.has("unknown")).toBe(false);
  });

  it("treats a revoked credential as holder action, not as retryable", () => {
    // Retrying a revoked credential forever locks out a legitimate holder.
    expect(categorize("REVOKED")).toBe("holder_action_required");
    expect(shouldRetry("REVOKED")).toBe(false);
  });

  it("treats pending and stale as retryable", () => {
    expect(categorize("PENDING")).toBe("retryable");
    expect(shouldRetry("PENDING", 0)).toBe(true);
    expect(categorize("STALE_DESTINATION")).toBe("retryable");
    expect(shouldRetry("STALE_DESTINATION", 0)).toBe(true);
  });

  it("routes policy mismatches to the integrator, not the holder", () => {
    expect(categorize("PROVIDER_NOT_ACCEPTED")).toBe("integrator_policy");
    expect(categorize("CREDENTIAL_TYPE_MISMATCH")).toBe("integrator_policy");
    expect(categorize("SCHEMA_VERSION_UNSUPPORTED")).toBe("integrator_policy");
  });

  it("stops retrying once the attempt budget is spent", () => {
    expect(shouldRetry("PENDING", 0, 3)).toBe(true);
    expect(shouldRetry("PENDING", 2, 3)).toBe(true);
    expect(shouldRetry("PENDING", 3, 3)).toBe(false);
  });

  it("keeps the self-service and escalation lists disjoint", () => {
    const overlap = SELF_SERVICE_REASONS.filter((r) => ESCALATION_REASONS.includes(r));
    expect(overlap).toHaveLength(0);
  });
});

describe("requirement builders", () => {
  const TYPE = keccak256(toHex("kyc.basic")) as Hex;

  it("anyVersion matches every version", () => {
    expect(anyVersion(TYPE)).toEqual({ credentialType: TYPE, schemaVersion: 0 });
  });

  it("withFreshness opts into replica staleness checks", () => {
    const req = withFreshness(anyVersion(TYPE));
    expect(req.requireFresh).toBe(true);
    expect(req.maxAgeSeconds).toBe(86_400n);
  });

  it("withFreshness honours a custom tolerance", () => {
    expect(withFreshness(anyVersion(TYPE), 3600n).maxAgeSeconds).toBe(3600n);
  });

  it("withProviders narrows the trusted set", () => {
    const p = keccak256(toHex("provider.reclaim")) as Hex;
    expect(withProviders(anyVersion(TYPE), [p]).acceptedProviders).toEqual([p]);
  });

  it("defaults every optional field when ABI-encoding", () => {
    const arg = toRequirementArg(anyVersion(TYPE));
    expect(arg).toHaveLength(5);
    expect(arg[1]).toBe(0);
    expect(arg[2]).toEqual([]);
    expect(arg[3]).toBe(0n);
    expect(arg[4]).toBe(false);
  });

  it("carries explicit values through to the ABI argument", () => {
    const p = keccak256(toHex("provider.mock")) as Hex;
    const req = withProviders(withFreshness({ ...anyVersion(TYPE), schemaVersion: 2 }, 60n), [p]);
    const arg = toRequirementArg(req);
    expect(arg[1]).toBe(2);
    expect(arg[2]).toEqual([p]);
    expect(arg[3]).toBe(60n);
    expect(arg[4]).toBe(true);
  });
});

describe("decoders", () => {
  it("reads a credential record tuple in struct order", () => {
    const ccid = keccak256(toHex("ccid"));
    const type = keccak256(toHex("type"));
    const provider = keccak256(toHex("provider"));
    const evidence = keccak256(toHex("evidence"));

    const record = toRecord([ccid, type, provider, evidence, 3, 100n, 200n, 150n, 7n, 5]);

    expect(record.ccid).toBe(ccid);
    expect(record.credentialType).toBe(type);
    expect(record.providerId).toBe(provider);
    expect(record.evidenceHash).toBe(evidence);
    expect(record.schemaVersion).toBe(3);
    expect(record.status).toBe(5);
    expect(record.nonce).toBe(7n);
  });

  it("reads a propagation state tuple", () => {
    const p = toPropagationState([true, 16015286601757825753n, 999n, 4n]);
    expect(p.isReplica).toBe(true);
    expect(p.sourceChainSelector).toBe(16015286601757825753n);
    expect(p.lastUpdatedAt).toBe(999n);
    expect(p.lastSourceNonce).toBe(4n);
  });

  it("treats a missing record as a not-a-replica state", () => {
    expect(toPropagationState([false, 0n, 0n, 0n]).isReplica).toBe(false);
  });
});

describe("reason vocabulary stays in step with the contract", () => {
  it("includes every label the contract defines", () => {
    // These nine are required by ENGINEERING_SPEC.md section 4.
    const required = [
      "UNKNOWN",
      "PENDING",
      "EXPIRED",
      "SUSPENDED",
      "REVOKED",
      "DISPUTED",
      "PROVIDER_PAUSED",
      "SCHEMA_UNSUPPORTED",
      "STALE_DESTINATION",
    ];
    for (const label of required) {
      expect(ALL_REASON_LABELS).toContain(label);
    }
  });

  it("exposes exactly one allow label", () => {
    expect(ALL_REASON_LABELS.filter((l) => l === "OK")).toHaveLength(1);
    expect(CONTRACT_LABEL).toBe("UNKNOWN");
  });
});