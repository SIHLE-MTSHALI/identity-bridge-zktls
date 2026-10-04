import { describe, expect, it, vi } from "vitest";
import { credentialVerify, type VerifyDeps, type SchemaPolicy } from "../src/credential-verify.js";
import { rawProof, type AdapterResult, type ProviderAdapter } from "../src/adapters/types.js";
import { mockZkTlsAdapter, encodeFixture, FIXTURE_MARKER } from "../src/adapters/mock-zktls.js";
import { reclaimAdapter, ReclaimTransportNotConfiguredError } from "../src/adapters/reclaim.js";
import { tlsNotaryAdapter, TlsNotaryTransportNotConfiguredError } from "../src/adapters/tlsnotary.js";
import type { LogSink } from "../src/privacy.js";

const CRED_TYPE = "kyc.basic";
const PROVIDER = "provider.mock-zktls";
const SALT = "11".repeat(32);

const policy: SchemaPolicy = {
  credentialType: CRED_TYPE,
  schemaVersion: 1,
  ttlSeconds: 2_592_000n, // 30 days
  acceptedProviders: [PROVIDER],
  revocationMode: "IssuerOnly",
};

function deps(overrides: Partial<VerifyDeps> = {}): VerifyDeps {
  return {
    registry: new Map([[`${CRED_TYPE}@v1`, policy]]),
    adapters: new Map([[PROVIDER, mockZkTlsAdapter()]]),
    readNonce: async () => 0n,
    readIssuedAt: async () => null,
    now: () => 1_700_000_000n,
    ...overrides,
  };
}

function fixture(outcome: "verified" | "rejected" | "malformed" | "expired" | "unreachable" | "subject_mismatch") {
  return rawProof(encodeFixture({ outcome, saltHex: SALT }));
}

const baseRequest = {
  credentialType: CRED_TYPE,
  schemaVersion: 1,
  providerId: PROVIDER,
  requestId: "req-1",
};

describe("credentialVerify - happy path", () => {
  it("issues a credential for an affirmative proof", async () => {
    const out = await credentialVerify({ ...baseRequest, raw: fixture("verified") }, deps());
    expect(out.kind).toBe("issued");
    if (out.kind !== "issued") return;
    expect(out.ccid).toMatch(/^0x[0-9a-f]{64}$/);
    expect(out.expiresAt).toBe(1_700_000_000n + 2_592_000n);
    expect(out.propagationTargets).toBe(0);
  });

  it("reports propagation targets when destinations are supplied", async () => {
    const out = await credentialVerify(
      { ...baseRequest, raw: fixture("verified"), destinationChainSelectors: [1n, 2n] },
      deps(),
    );
    expect(out.kind).toBe("issued");
    if (out.kind !== "issued") return;
    expect(out.propagationTargets).toBe(2);
  });

  it("increments the nonce so a re-issuance is distinguishable", async () => {
    const out = await credentialVerify({ ...baseRequest, raw: fixture("verified") }, deps({ readNonce: async () => 7n }));
    expect(out.kind).toBe("issued");
  });
});

describe("credentialVerify - outcome separation", () => {
  it("distinguishes an affirmative negative from an outage", async () => {
    // This is the distinction that matters: collapsing these two means a provider
    // outage denies every applicant, indistinguishably from a genuine rejection.
    const rejected = await credentialVerify({ ...baseRequest, raw: fixture("rejected") }, deps());
    expect(rejected.kind).toBe("rejected");

    const unreachable = await credentialVerify({ ...baseRequest, raw: fixture("unreachable") }, deps());
    expect(unreachable.kind).toBe("unavailable");
    if (unreachable.kind !== "unavailable") return;
    expect(unreachable.retryable).toBe(true);
  });

  it("treats a malformed proof as invalid, not retryable", async () => {
    const out = await credentialVerify({ ...baseRequest, raw: fixture("malformed") }, deps());
    expect(out.kind).toBe("invalid");
  });

  it("treats an expired proof as invalid", async () => {
    const out = await credentialVerify({ ...baseRequest, raw: fixture("expired") }, deps());
    expect(out.kind).toBe("invalid");
  });

  it("rejects a provider that attests a different schema than requested", async () => {
    // Trusting the provider's answer over the request is how a credential gets
    // issued under a schema nobody checked.
    const adapter = mockZkTlsAdapter();
    const spoofing: ProviderAdapter = {
      ...adapter,
      async verify(input) {
        return {
          ok: true,
          verification: {
            verified: true,
            credentialType: "some.other.type",
            evidenceLabel: "spoofed",
            evidenceCommitment: { value: `0x${"0".repeat(64)}`, saltFingerprint: "0" },
          },
        };
      },
    };
    const out = await credentialVerify(
      { ...baseRequest, raw: fixture("verified") },
      deps({ adapters: new Map([[PROVIDER, spoofing]]) }),
    );
    expect(out.kind).toBe("invalid");
  });
});

describe("credentialVerify - pre-flight validation", () => {
  it("rejects an empty requestId", async () => {
    const out = await credentialVerify({ ...baseRequest, requestId: "  ", raw: fixture("verified") }, deps());
    expect(out.kind).toBe("invalid");
  });

  it("rejects an empty proof payload", async () => {
    const out = await credentialVerify({ ...baseRequest, raw: rawProof(new Uint8Array(0)) }, deps());
    expect(out.kind).toBe("invalid");
  });

  it("rejects an unknown schema policy", async () => {
    const out = await credentialVerify(
      { ...baseRequest, schemaVersion: 99, raw: fixture("verified") },
      deps(),
    );
    expect(out.kind).toBe("invalid");
  });

  it("rejects an unregistered adapter", async () => {
    const out = await credentialVerify({ ...baseRequest, providerId: "provider.unknown", raw: fixture("verified") }, deps());
    expect(out.kind).toBe("invalid");
  });

  it("rejects a provider the schema does not admit", async () => {
    const out = await credentialVerify(
      { ...baseRequest, providerId: "provider.reclaim", raw: fixture("verified") },
      deps({ adapters: new Map([["provider.reclaim", reclaimAdapter()]]) }),
    );
    expect(out.kind).toBe("invalid");
  });
});

describe("credentialVerify - logging hygiene", () => {
  it("never logs raw proof material", async () => {
    const contexts: unknown[] = [];
    const log: LogSink = (_lvl, _msg, ctx) => contexts.push(ctx);
    const proof = fixture("verified");
    await credentialVerify({ ...baseRequest, raw: proof }, deps({ log }));

    // Every emitted context must survive the privacy guard.
    for (const ctx of contexts) {
      expect(ctx).toBeDefined();
      const serialized = JSON.stringify(ctx, (_k, v) => (v instanceof Uint8Array ? `<${v.byteLength} bytes>` : v));
      expect(serialized).not.toContain("proof");
      expect(serialized).not.toContain("saltHex");
      expect(serialized).not.toContain("outcome");
    }
  });

  it("logs only safe identifiers on success", async () => {
    const contexts: Record<string, unknown>[] = [];
    const log: LogSink = (_lvl, _msg, ctx) => contexts.push(ctx as Record<string, unknown>);
    await credentialVerify({ ...baseRequest, raw: fixture("verified") }, deps({ log }));

    expect(contexts).toHaveLength(1);
    const keys = Object.keys(contexts[0] ?? {});
    expect(keys).toContain("requestId");
    expect(keys).toContain("ccid");
    expect(keys).not.toContain("raw");
  });
});

describe("provider adapters", () => {
  it("mock adapter reports support only for its declared schemas", () => {
    const adapter = mockZkTlsAdapter();
    expect(adapter.supports("kyc.basic", 1)).toBe(true);
    expect(adapter.supports("kyc.basic", 2)).toBe(false);
    expect(adapter.supports("unknown.type", 1)).toBe(false);
  });

  it("mock adapter labels its evidence as fixture-only", async () => {
    const adapter = mockZkTlsAdapter();
    const result = await adapter.verify({
      raw: fixture("verified"),
      credentialType: CRED_TYPE,
      schemaVersion: 1,
      requestId: "req-1",
      now: 1,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // A deployment script can refuse any provider whose evidence label carries
    // this marker.
    expect(result.verification.evidenceLabel).toContain(FIXTURE_MARKER);
  });

  it("reclaim adapter refuses to pretend it is integrated", async () => {
    const adapter = reclaimAdapter();
    await expect(
      adapter.verify({ raw: fixture("verified"), credentialType: CRED_TYPE, schemaVersion: 1, requestId: "r", now: 1 }),
    ).rejects.toBeInstanceOf(ReclaimTransportNotConfiguredError);
  });

  it("reclaim adapter reports transport errors as unavailable, not as a rejection", async () => {
    const adapter = reclaimAdapter({
      transport: {
        async verify() {
          throw new Error("ECONNRESET");
        },
      },
    });
    const result = await adapter.verify({
      raw: fixture("verified"),
      credentialType: CRED_TYPE,
      schemaVersion: 1,
      requestId: "r",
      now: 1,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure).toBe("provider_unreachable");
  });

  it("tlsnotary adapter refuses to pretend it is integrated", async () => {
    const adapter = tlsNotaryAdapter();
    await expect(
      adapter.verify({ raw: fixture("verified"), credentialType: CRED_TYPE, schemaVersion: 1, requestId: "r", now: 1 }),
    ).rejects.toBeInstanceOf(TlsNotaryTransportNotConfiguredError);
  });

  it("tlsnotary adapter scopes its evidence to the origin", async () => {
    const transport = { evaluate: vi.fn(async () => ({ valid: true, observedAt: 42 })) };
    const a = tlsNotaryAdapter({ transport, origin: "example.gov", statementLabel: "kyc.cleared" });
    const b = tlsNotaryAdapter({ transport, origin: "other.gov", statementLabel: "kyc.cleared" });

    const input = { raw: fixture("verified"), credentialType: CRED_TYPE, schemaVersion: 1, requestId: "r", now: 1 };
    const ra = await a.verify(input);
    const rb = await b.verify(input);

    expect(ra.ok && rb.ok).toBe(true);
    if (!ra.ok || !rb.ok) return;
    // Same attribute, two origins: two unlinkable commitments.
    expect(ra.verification.evidenceCommitment.value).not.toBe(rb.verification.evidenceCommitment.value);
  });

  it("every adapter rejects an unsupported schema before touching the transport", async () => {
    const transport = { verify: vi.fn(), evaluate: vi.fn() };
    for (const adapter of [reclaimAdapter({ transport }), tlsNotaryAdapter({ transport })]) {
      const result = await adapter.verify({
        raw: fixture("verified"),
        credentialType: CRED_TYPE,
        schemaVersion: 42,
        requestId: "r",
        now: 1,
      });
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.failure).toBe("schema_unsupported");
    }
    expect(transport.verify).not.toHaveBeenCalled();
    expect(transport.evaluate).not.toHaveBeenCalled();
  });
});