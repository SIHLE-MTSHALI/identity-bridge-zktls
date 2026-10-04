import { describe, expect, it } from "vitest";
import {
  RawMaterialInLogError,
  assertRedacted,
  commit,
  commitDeterministic,
  isForbiddenKey,
  redact,
  safeLog,
  type LogSink,
} from "../src/privacy.js";

/**
 * The privacy guard is only worth having if it actually rejects raw material.
 * These tests are written adversarially: each case is a shape that a naive
 * key-substring check would miss.
 */

describe("forbidden key detection", () => {
  it("catches raw-material fields regardless of casing or separators", () => {
    for (const key of ["proof", "rawProof", "raw_proof", "RAW-PROOF", "tlsNotaryTranscript", "accountHandle", "legalName", "phoneNumber", "providerReport", "apiKey"]) {
      expect(isForbiddenKey(key), `${key} should be forbidden`).toBe(true);
    }
  });

  it("does not fire on innocuous field names", () => {
    // Over-matching trains people to ignore the guard, which is worse than not
    // having one. These are all legitimate fields a workflow logs.
    for (const key of ["ccid", "requestId", "providerId", "credentialType", "schemaVersion", "expiresAt", "nonce", "status"]) {
      expect(isForbiddenKey(key), `${key} should be allowed`).toBe(false);
    }
  });
});

describe("assertRedacted", () => {
  it("accepts a log context containing only safe fields", () => {
    expect(() =>
      assertRedacted({
        requestId: "req-1",
        ccid: "0xabc",
        providerId: "provider.mock-zktls",
        credentialType: "kyc.basic",
        schemaVersion: 1,
        nonce: "2",
      }),
    ).not.toThrow();
  });

  it("rejects raw proof material at the top level", () => {
    expect(() => assertRedacted({ requestId: "req-1", proof: "deadbeef" })).toThrow(RawMaterialInLogError);
  });

  it("rejects raw material nested several levels deep", () => {
    // A naive implementation checking only top-level keys would pass this.
    expect(() =>
      assertRedacted({
        requestId: "req-1",
        result: {
          verification: {
            provider: { telemetry: { tlsNotaryTranscript: "-----BEGIN CERTIFICATE-----" } },
          },
        },
      }),
    ).toThrow(RawMaterialInLogError);
  });

  it("rejects raw material inside arrays", () => {
    expect(() => assertRedacted({ steps: [{ ok: true }, { document: "passport-scan.png" }] })).toThrow(RawMaterialInLogError);
  });

  it("names every offending key in the error", () => {
    try {
      assertRedacted({ proof: "a", email: "b", ok: 1 });
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RawMaterialInLogError);
      expect((err as RawMaterialInLogError).keys).toContain("proof");
      expect((err as RawMaterialInLogError).keys).toContain("email");
    }
  });

  it("tolerates null, undefined, and empty structures", () => {
    expect(() => assertRedacted(null)).not.toThrow();
    expect(() => assertRedacted(undefined)).not.toThrow();
    expect(() => assertRedacted({})).not.toThrow();
    expect(() => assertRedacted([])).not.toThrow();
  });
});

describe("safeLog", () => {
  it("emits a clean context", () => {
    const seen: unknown[] = [];
    const sink: LogSink = (_lvl, _msg, ctx) => seen.push(ctx);
    safeLog(sink, "info", "hello", { requestId: "req-1" });
    expect(seen).toHaveLength(1);
  });

  it("refuses to emit raw material", () => {
    // The critical property: nothing reaches the sink.
    const seen: unknown[] = [];
    const sink: LogSink = (_lvl, _msg, ctx) => seen.push(ctx);
    expect(() => safeLog(sink, "error", "oops", { transcript: "raw bytes" })).toThrow(RawMaterialInLogError);
    expect(seen).toHaveLength(0);
  });

  it("emits when no context is supplied", () => {
    const seen: unknown[] = [];
    const sink: LogSink = (_lvl, _msg, ctx) => seen.push(ctx);
    safeLog(sink, "warn", "no context");
    expect(seen).toEqual([undefined]);
  });
});

describe("redact", () => {
  it("drops forbidden keys entirely and preserves the rest", () => {
    const out = redact({
      requestId: "req-1",
      proof: "secret-proof-bytes",
      nested: { email: "a@b.c", ccid: "0xabc" },
    }) as Record<string, unknown>;

    expect(out.requestId).toBe("req-1");
    // Dropped, not replaced: a "[redacted]" marker would still disclose that a
    // proof existed and would still trip the guard.
    expect("proof" in out).toBe(false);
    const nested = out.nested as Record<string, unknown>;
    expect("email" in nested).toBe(false);
    expect(nested.ccid).toBe("0xabc");
  });

  it("produces output that passes assertRedacted", () => {
    const cleaned = redact({ proof: "x", report: "y", name: "z", ccid: "0x1" });
    expect(() => assertRedacted(cleaned)).not.toThrow();
  });

  it("never leaves a forbidden key anywhere in a deep structure", () => {
    const cleaned = redact({
      a: { b: [{ proof: "p", ok: 1 }, { c: { transcript: "t", ccid: "0x2" } }] },
    });
    expect(JSON.stringify(cleaned)).not.toContain("proof");
    expect(JSON.stringify(cleaned)).not.toContain("transcript");
  });
});

describe("commit", () => {
  it("produces a 0x-prefixed 32-byte commitment", () => {
    const c = commit("some-evidence", "kyc.basic");
    expect(c.value).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("never returns the raw material", () => {
    const c = commit("alice@example.com", "kyc.basic");
    expect(c.value).not.toContain("alice");
  });

  it("uses a fresh salt each call, so the same input yields different commitments", () => {
    // Reusing a salt would let anyone holding two commitments detect that they
    // describe the same subject, which is the correlation the privacy model forbids.
    const a = commit("same-evidence", "kyc.basic");
    const b = commit("same-evidence", "kyc.basic");
    expect(a.value).not.toBe(b.value);
    expect(a.saltFingerprint).not.toBe(b.saltFingerprint);
  });

  it("is domain-separated by credential type", () => {
    const a = commitDeterministic("evidence", "11".repeat(32));
    const b = commitDeterministic("evidence", "22".repeat(32));
    expect(a.value).not.toBe(b.value);
  });

  it("is deterministic for a fixed salt, so fixtures stay reproducible", () => {
    const salt = "ab".repeat(32);
    expect(commitDeterministic("evidence", salt).value).toBe(commitDeterministic("evidence", salt).value);
  });
});