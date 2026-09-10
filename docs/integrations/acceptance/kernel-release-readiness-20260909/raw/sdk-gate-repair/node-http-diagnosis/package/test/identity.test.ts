import { describe, it, expect } from "vitest";
import { defaultIdentityExtractor, sha256Hex } from "../src/identity.js";

describe("sha256Hex", () => {
  it("produces a 64-character hex string", () => {
    const hash = sha256Hex("hello");
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    expect(sha256Hex("test")).toBe(sha256Hex("test"));
  });
});

describe("defaultIdentityExtractor", () => {
  it("extracts bearer token identity", () => {
    const identity = defaultIdentityExtractor({
      authorization: "Bearer mytoken123",
    });
    expect(identity.subject).toMatch(/^bearer:/);
    expect(identity.auth_method.method).toBe("bearer");
    expect(identity.verified).toBe(false);
    if (identity.auth_method.method === "bearer") {
      expect(identity.auth_method.token_hash).toBe(sha256Hex("mytoken123"));
    }
  });

  it("extracts API key identity from x-api-key", () => {
    const identity = defaultIdentityExtractor({
      "x-api-key": "sk-test-123",
    });
    expect(identity.subject).toMatch(/^apikey:/);
    expect(identity.auth_method.method).toBe("api_key");
    if (identity.auth_method.method === "api_key") {
      expect(identity.auth_method.key_hash).toBe(sha256Hex("sk-test-123"));
    }
  });

  it("extracts cookie identity", () => {
    const identity = defaultIdentityExtractor({
      cookie: "session=abc123; other=xyz",
    });
    expect(identity.subject).toMatch(/^cookie:/);
    expect(identity.auth_method.method).toBe("cookie");
    if (identity.auth_method.method === "cookie") {
      expect(identity.auth_method.cookie_name).toBe("session");
      expect(identity.auth_method.cookie_hash).toBe(sha256Hex("abc123"));
    }
  });

  it("returns anonymous when no auth headers present", () => {
    const identity = defaultIdentityExtractor({});
    expect(identity.subject).toBe("anonymous");
    expect(identity.auth_method.method).toBe("anonymous");
    expect(identity.verified).toBe(false);
  });

  it("prefers bearer over api key", () => {
    const identity = defaultIdentityExtractor({
      authorization: "Bearer token",
      "x-api-key": "key",
    });
    expect(identity.auth_method.method).toBe("bearer");
  });

  it("handles case-insensitive headers", () => {
    const identity = defaultIdentityExtractor({
      Authorization: "Bearer mytoken",
    });
    expect(identity.auth_method.method).toBe("bearer");
  });

  it("handles array header values", () => {
    const identity = defaultIdentityExtractor({
      authorization: ["Bearer mytoken"],
    });
    expect(identity.auth_method.method).toBe("bearer");
  });
});
