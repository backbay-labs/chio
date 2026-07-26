/**
 * Canonical JSON conformance tests.
 *
 * These tests verify that the TypeScript canonical JSON implementation
 * produces byte-identical output to the Rust kernel's canonical_json_bytes.
 * The expected values are derived from the Rust chio-core-types crate.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { canonicalJsonString, canonicalJsonBytes } from "../src/canonical.js";

function sha256Hex(input: Uint8Array | string): string {
  return createHash("sha256").update(input).digest("hex");
}

describe("canonical JSON (RFC 8785 conformance)", () => {
  it("sorts object keys lexicographically", () => {
    const result = canonicalJsonString({ z: 1, a: 2, m: 3 });
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("produces no whitespace", () => {
    const result = canonicalJsonString({ hello: "world", items: [1, 2, 3] });
    expect(result).not.toContain(" ");
    expect(result).not.toContain("\n");
    expect(result).not.toContain("\t");
  });

  it("handles nested objects with sorted keys", () => {
    const result = canonicalJsonString({
      outer: { z: true, a: false },
      first: 1,
    });
    expect(result).toBe('{"first":1,"outer":{"a":false,"z":true}}');
  });

  it("handles null", () => {
    expect(canonicalJsonString(null)).toBe("null");
  });

  it("handles booleans", () => {
    expect(canonicalJsonString(true)).toBe("true");
    expect(canonicalJsonString(false)).toBe("false");
  });

  it("handles numbers", () => {
    expect(canonicalJsonString(42)).toBe("42");
    expect(canonicalJsonString(3.14)).toBe("3.14");
    expect(canonicalJsonString(0)).toBe("0");
    expect(canonicalJsonString(-1)).toBe("-1");
  });

  it("handles strings with escaping", () => {
    expect(canonicalJsonString("hello")).toBe('"hello"');
    expect(canonicalJsonString('say "hi"')).toBe('"say \\"hi\\""');
    expect(canonicalJsonString("line\nbreak")).toBe('"line\\nbreak"');
  });

  it("emits DEL and C1 controls without non-RFC escapes", () => {
    expect(canonicalJsonString("\u007f\u009f")).toBe('"\u007f\u009f"');
    expect(canonicalJsonString({ "\u007f\u009f": "\u007f\u009f" })).toBe(
      '{"\u007f\u009f":"\u007f\u009f"}',
    );
  });

  it("handles arrays", () => {
    expect(canonicalJsonString([1, 2, 3])).toBe("[1,2,3]");
    expect(canonicalJsonString([])).toBe("[]");
    expect(canonicalJsonString(["a", "b"])).toBe('["a","b"]');
  });

  it("handles empty objects", () => {
    expect(canonicalJsonString({})).toBe("{}");
  });

  it("skips undefined values (matches Rust serde skip_serializing_if)", () => {
    const result = canonicalJsonString({
      a: 1,
      b: undefined,
      c: 3,
    });
    expect(result).toBe('{"a":1,"c":3}');
  });

  it("throws on non-finite numbers", () => {
    expect(() => canonicalJsonString(Infinity)).toThrow();
    expect(() => canonicalJsonString(NaN)).toThrow();
    expect(() => canonicalJsonString(-Infinity)).toThrow();
  });

  it("produces deterministic bytes", () => {
    const bytes1 = canonicalJsonBytes({ key: "value" });
    const bytes2 = canonicalJsonBytes({ key: "value" });
    expect(sha256Hex(bytes1)).toBe(sha256Hex(bytes2));
  });

  // -- Chio-specific type conformance --

  it("produces correct canonical JSON for CallerIdentity", () => {
    const identity = {
      agent_id: undefined,
      auth_method: { method: "bearer", token_hash: "abc123" },
      subject: "bearer:abc1",
      tenant: undefined,
      verified: false,
    };
    const result = canonicalJsonString(identity);
    // Keys sorted: auth_method, subject, verified (undefined skipped)
    expect(result).toBe(
      '{"auth_method":{"method":"bearer","token_hash":"abc123"},"subject":"bearer:abc1","verified":false}',
    );
  });

  it("produces correct canonical JSON for Verdict Allow", () => {
    const verdict = { verdict: "allow" };
    expect(canonicalJsonString(verdict)).toBe('{"verdict":"allow"}');
  });

  it("produces correct canonical JSON for Verdict Deny", () => {
    const verdict = {
      guard: "CapabilityGuard",
      http_status: 403,
      reason: "no capability",
      verdict: "deny",
    };
    expect(canonicalJsonString(verdict)).toBe(
      '{"guard":"CapabilityGuard","http_status":403,"reason":"no capability","verdict":"deny"}',
    );
  });

  it("produces deterministic content hash for request binding", () => {
    // Mirrors the Rust RequestContentBinding struct
    const binding = {
      body_hash: null,
      method: "GET",
      path: "/pets/42",
      query: {},
      route_pattern: "/pets/{petId}",
    };
    const canonical = canonicalJsonString(binding);
    const hash = sha256Hex(canonical);

    // Verify determinism
    const hash2 = sha256Hex(canonicalJsonString(binding));
    expect(hash).toBe(hash2);
    expect(hash).toHaveLength(64);
  });

  it("content hash changes when query parameters differ", () => {
    const binding1 = {
      body_hash: null,
      method: "GET",
      path: "/pets",
      query: {},
      route_pattern: "/pets",
    };
    const binding2 = {
      body_hash: null,
      method: "GET",
      path: "/pets",
      query: { limit: "10" },
      route_pattern: "/pets",
    };

    const hash1 = sha256Hex(canonicalJsonString(binding1));
    const hash2 = sha256Hex(canonicalJsonString(binding2));
    expect(hash1).not.toBe(hash2);
  });

  it("content hash changes when method differs", () => {
    const binding1 = {
      body_hash: null,
      method: "GET",
      path: "/pets",
      query: {},
      route_pattern: "/pets",
    };
    const binding2 = {
      body_hash: null,
      method: "POST",
      path: "/pets",
      query: {},
      route_pattern: "/pets",
    };

    const hash1 = sha256Hex(canonicalJsonString(binding1));
    const hash2 = sha256Hex(canonicalJsonString(binding2));
    expect(hash1).not.toBe(hash2);
  });
});
