import { describe, it, expect } from "vitest";
import {
  isAllowed,
  isAuthoritativeVerification,
  isAuthorizedHttpReceipt,
  isDenied,
  isMethodSafe,
} from "../src/types.js";
import type { HttpReceipt, Verdict, VerifyReceiptResponse } from "../src/types.js";

describe("isMethodSafe", () => {
  it("returns true for safe methods", () => {
    expect(isMethodSafe("GET")).toBe(true);
    expect(isMethodSafe("HEAD")).toBe(true);
    expect(isMethodSafe("OPTIONS")).toBe(true);
  });

  it("returns false for side-effect methods", () => {
    expect(isMethodSafe("POST")).toBe(false);
    expect(isMethodSafe("PUT")).toBe(false);
    expect(isMethodSafe("PATCH")).toBe(false);
    expect(isMethodSafe("DELETE")).toBe(false);
  });
});

describe("verdict helpers", () => {
  it("isAllowed returns true for allow verdict", () => {
    const v: Verdict = { verdict: "allow" };
    expect(isAllowed(v)).toBe(true);
    expect(isDenied(v)).toBe(false);
  });

  it("isDenied returns true for deny verdict", () => {
    const v: Verdict = {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    };
    expect(isDenied(v)).toBe(true);
    expect(isAllowed(v)).toBe(false);
  });

  it("isDenied narrows type to access reason and guard", () => {
    const v: Verdict = {
      verdict: "deny",
      reason: "rate limited",
      guard: "RateGuard",
      http_status: 429,
    };
    if (isDenied(v)) {
      expect(v.reason).toBe("rate limited");
      expect(v.guard).toBe("RateGuard");
      expect(v.http_status).toBe(429);
    }
  });

  it("handles cancel verdict", () => {
    const v: Verdict = { verdict: "cancel", reason: "timeout" };
    expect(isAllowed(v)).toBe(false);
    expect(isDenied(v)).toBe(false);
  });

  it("handles incomplete verdict", () => {
    const v: Verdict = { verdict: "incomplete", reason: "pending" };
    expect(isAllowed(v)).toBe(false);
    expect(isDenied(v)).toBe(false);
  });
});

describe("receipt authority helpers", () => {
  const baseReceipt = {
    id: "rcpt-1",
    request_id: "req-1",
    route_pattern: "/tool",
    method: "POST",
    caller_identity_hash: "a".repeat(64),
    verdict: { verdict: "allow" },
    evidence: [],
    response_status: 200,
    timestamp: 1_700_000_000,
    content_hash: "b".repeat(64),
    policy_hash: "c".repeat(64),
    kernel_key: "d".repeat(64),
    signature: "e".repeat(128),
  } as unknown as HttpReceipt;

  it("does not authorize bare allow receipts without structural semantics", () => {
    expect(isAuthorizedHttpReceipt(baseReceipt)).toBe(false);
  });

  it("authorizes only mediated prevent allow receipts", () => {
    expect(isAuthorizedHttpReceipt({
      ...baseReceipt,
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
    })).toBe(true);
  });

  it("requires full verifier authority fields", () => {
    const receipt = {
      ...baseReceipt,
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
    } as HttpReceipt;
    const report: VerifyReceiptResponse = {
      signature_valid: true,
      signer_trusted: true,
      receipt_id_valid: true,
      parameter_hash_valid: true,
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      trust_level: "mediated",
      result: "allow",
      authorized: true,
      signer_key_hex: "d".repeat(64),
      ok: true,
    };
    expect(isAuthoritativeVerification(report, receipt)).toBe(true);
    expect(isAuthoritativeVerification({
      ...report,
      signer_trusted: false,
    }, receipt)).toBe(false);
  });
});
