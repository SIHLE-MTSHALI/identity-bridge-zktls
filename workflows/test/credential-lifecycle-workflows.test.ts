import { describe, expect, it } from "vitest";
import { credentialRenew, findRenewable, type RenewDeps, type RenewalCandidate } from "../src/credential-renew.js";
import { credentialRevoke, planRevocation, type RevocationRequest } from "../src/credential-revoke.js";
import { rawProof } from "../src/adapters/types.js";
import { mockZkTlsAdapter, encodeFixture } from "../src/adapters/mock-zktls.js";
import type { SchemaPolicy } from "../src/credential-verify.js";
import type { LogSink } from "../src/privacy.js";

const CRED_TYPE = "kyc.basic";
const PROVIDER = "provider.mock-zktls";
const SALT = "11".repeat(32);

const policy: SchemaPolicy = {
  credentialType: CRED_TYPE,
  schemaVersion: 1,
  ttlSeconds: 2_592_000n,
  acceptedProviders: [PROVIDER],
  revocationMode: "IssuerOnly",
};

function renewDeps(overrides: Partial<RenewDeps> = {}): RenewDeps {
  return {
    registry: new Map([[`${CRED_TYPE}@v1`, policy]]),
    adapters: new Map([[PROVIDER, mockZkTlsAdapter()]]),
    readNonce: async () => 4n,
    readIssuedAt: async () => null,
    now: () => 1_700_000_000n,
    ...overrides,
  };
}

const proof = (outcome: "verified" | "rejected" | "unreachable" | "malformed") =>
  rawProof(encodeFixture({ outcome, saltHex: SALT }));

describe("findRenewable", () => {
  const candidates: RenewalCandidate[] = [
    { ccid: "0xa", credentialType: CRED_TYPE, schemaVersion: 1, providerId: PROVIDER, secondsRemaining: 100n },
    { ccid: "0xb", credentialType: CRED_TYPE, schemaVersion: 1, providerId: PROVIDER, secondsRemaining: 10_000n },
    { ccid: "0xc", credentialType: CRED_TYPE, schemaVersion: 1, providerId: PROVIDER, secondsRemaining: -5n },
  ];

  it("lists credentials inside the window, most urgent first", () => {
    // 0xc is already past expiry (-5s) so it is the most urgent, then 0xa (100s).
    const out = findRenewable(candidates, 1_000n);
    expect(out.map((c) => c.ccid)).toEqual(["0xc", "0xa"]);
  });

  it("includes already-expired credentials so they are not forgotten", () => {
    // A credential that has already lapsed still needs attention; dropping it here
    // would strand it until something else noticed.
    expect(findRenewable(candidates, 1_000n).map((c) => c.ccid)).toContain("0xc");
  });

  it("excludes credentials comfortably outside the window", () => {
    expect(findRenewable(candidates, 100n).map((c) => c.ccid)).not.toContain("0xb");
  });

  it("rejects a negative window rather than silently matching nothing", () => {
    expect(() => findRenewable(candidates, -1n)).toThrow(RangeError);
  });
});

describe("credentialRenew", () => {
  const base = {
    ccid: "0xdead",
    credentialType: CRED_TYPE,
    schemaVersion: 1,
    providerId: PROVIDER,
    requestId: "renew-1",
  };

  it("renews only after a fresh affirmative proof", async () => {
    const out = await credentialRenew({ ...base, raw: proof("verified") }, renewDeps());
    expect(out.kind).toBe("renewed");
    if (out.kind !== "renewed") return;
    expect(out.expiresAt).toBe(1_700_000_000n + 2_592_000n);
  });

  it("does not renew on an affirmative negative", async () => {
    const out = await credentialRenew({ ...base, raw: proof("rejected") }, renewDeps());
    expect(out.kind).toBe("renewal_failed");
  });

  it("reports a provider outage as a failure, not as a revocation", async () => {
    // A failed renewal must not be presented as ineligibility: the caller may still
    // have valid access for some time, and turning an outage into a denial is the
    // behaviour this distinction prevents.
    const out = await credentialRenew({ ...base, raw: proof("unreachable") }, renewDeps());
    expect(out.kind).toBe("renewal_failed");
    if (out.kind !== "renewal_failed") return;
    expect(out.cause.kind).toBe("unavailable");
  });

  it("carries the underlying cause through so the caller can distinguish retry from give-up", async () => {
    const out = await credentialRenew({ ...base, raw: proof("malformed") }, renewDeps());
    if (out.kind !== "renewal_failed") throw new Error("expected renewal_failed");
    expect(out.cause.kind).toBe("invalid");
  });

  it("applies the same issuance checks as first issuance", async () => {
    // Delegating to credentialVerify is what guarantees renewal cannot be a bypass.
    const out = await credentialRenew(
      { ...base, raw: proof("verified"), providerId: "provider.unregistered" },
      renewDeps(),
    );
    expect(out.kind).toBe("renewal_failed");
  });

  it("never logs raw material while renewing", async () => {
    const contexts: unknown[] = [];
    const log: LogSink = (_l, _m, c) => contexts.push(c);
    await credentialRenew({ ...base, raw: proof("verified") }, renewDeps({ log }));
    for (const ctx of contexts) {
      expect(JSON.stringify(ctx)).not.toContain("saltHex");
      expect(JSON.stringify(ctx)).not.toContain("outcome");
    }
  });
});

describe("planRevocation", () => {
  const request: RevocationRequest = {
    ccid: "0xfeed",
    credentialType: CRED_TYPE,
    schemaVersion: 1,
    providerId: PROVIDER,
    reason: "provider reported compromise",
    destinations: [
      { chainSelector: 100n, believesValid: true },
      { chainSelector: 200n, believesValid: true },
      { chainSelector: 300n, believesValid: false },
    ],
  };

  const trusted = new Set(["100", "200"]);

  it("always revokes on the source chain first", () => {
    const plan = planRevocation(request, { trustedChains: trusted, routerAvailable: true });
    expect(plan.revokeOnSource).toBe(true);
  });

  it("skips destinations that do not believe the credential is valid", () => {
    // Nothing to correct, and notifying anyway risks overwriting newer state.
    const plan = planRevocation(request, { trustedChains: trusted, routerAvailable: true });
    expect(plan.notify.map((d) => d.chainSelector)).toEqual([100n, 200n]);
  });

  it("reports an untrusted chain rather than silently dropping it", () => {
    const plan = planRevocation(request, { trustedChains: new Set(["100"]), routerAvailable: true });
    expect(plan.carriedOver).toEqual([{ chainSelector: 200n, reason: "chain_untrusted" }]);
  });

  it("reports every destination when the router is down", () => {
    // This is the case that must never be swallowed: those chains keep showing the
    // credential as valid, and an operator has to know which ones.
    const plan = planRevocation(request, { trustedChains: trusted, routerAvailable: false });
    expect(plan.notify).toHaveLength(0);
    expect(plan.carriedOver).toHaveLength(2);
    expect(plan.carriedOver.every((f) => f.reason === "router_unavailable")).toBe(true);
  });

  it("refuses an empty reason, because an unexplained revocation cannot be audited", () => {
    expect(() =>
      planRevocation({ ...request, reason: "   " }, { trustedChains: trusted, routerAvailable: true }),
    ).toThrow(RangeError);
  });
});

describe("credentialRevoke", () => {
  const request: RevocationRequest = {
    ccid: "0xfeed",
    credentialType: CRED_TYPE,
    schemaVersion: 1,
    providerId: PROVIDER,
    reason: "fraud",
    destinations: [{ chainSelector: 100n, believesValid: true }],
  };

  it("reports a clean revocation with nothing carried over", async () => {
    const out = await credentialRevoke(request, {
      trustedChains: new Set(["100"]),
      isRouterAvailable: async () => true,
    });
    expect(out.kind).toBe("revoked");
    if (out.kind !== "revoked") return;
    expect(out.notified).toBe(1);
    expect(out.carriedOver).toHaveLength(0);
  });

  it("surfaces unnotified destinations instead of failing silently", async () => {
    const out = await credentialRevoke(request, {
      trustedChains: new Set(["100"]),
      isRouterAvailable: async () => false,
    });
    if (out.kind !== "revoked") throw new Error("expected revoked");
    expect(out.notified).toBe(0);
    expect(out.carriedOver).toHaveLength(1);
  });

  it("fails loudly when the router health check itself throws", async () => {
    const out = await credentialRevoke(request, {
      trustedChains: new Set(["100"]),
      isRouterAvailable: async () => {
        throw new Error("RPC down");
      },
    });
    expect(out.kind).toBe("failed");
  });

  it("logs which chains were not notified, so an incident has a concrete list", async () => {
    const contexts: Record<string, unknown>[] = [];
    const out = await credentialRevoke(
      { ...request, destinations: [{ chainSelector: 100n, believesValid: true }, { chainSelector: 900n, believesValid: true }] },
      {
        trustedChains: new Set(["100"]),
        isRouterAvailable: async () => true,
        log: (_l, _m, c) => contexts.push(c as Record<string, unknown>),
      },
    );
    if (out.kind !== "revoked") throw new Error("expected revoked");
    expect(out.carriedOver.map((f) => f.chainSelector)).toEqual([900n]);
    expect(contexts.some((c) => JSON.stringify(c).includes("chain_untrusted"))).toBe(true);
  });
});