/**
 * Receipt verification utilities for conformance tests.
 *
 * These functions mirror the Rust kernel's receipt verification logic
 * and can be used to validate that receipts produced by the TS SDK
 * match the expected format.
 */

import { createHash } from "node:crypto";
import type { HttpReceipt, Verdict, GuardEvidence } from "@chio-protocol/node-http";
import { canonicalJsonString } from "./canonical.js";
import type { Receipt_Record } from "./_generated/index.js";

export interface ReceiptAuthorityResult {
  signature_valid: boolean;
  signer_trusted: boolean;
  receipt_id_valid: boolean;
  parameter_hash_valid: boolean;
  receipt_kind: string;
  boundary_class: string;
  trust_level: string;
  result: string;
  authorized: boolean;
  ok: boolean;
}

/**
 * Verify that a receipt has all required fields and valid structure.
 */
export function validateReceiptStructure(receipt: HttpReceipt): string[] {
  const errors: string[] = [];

  if (typeof receipt.id !== "string" || receipt.id.length === 0) {
    errors.push("receipt.id must be a non-empty string");
  }
  if (!isLowerHex64(receipt.id)) {
    errors.push("receipt.id must be a 64-character lowercase hex content-addressed id");
  }

  if (typeof receipt.request_id !== "string" || receipt.request_id.length === 0) {
    errors.push("receipt.request_id must be a non-empty string");
  }

  if (typeof receipt.route_pattern !== "string") {
    errors.push("receipt.route_pattern must be a string");
  }

  const validMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  if (!validMethods.includes(receipt.method)) {
    errors.push(`receipt.method must be one of ${validMethods.join(", ")}`);
  }

  if (!isLowerHex64(receipt.caller_identity_hash)) {
    errors.push("receipt.caller_identity_hash must be a 64-character hex string");
  }

  if (!isValidVerdict(receipt.verdict)) {
    errors.push("receipt.verdict must be a valid Verdict");
  }

  const semanticErrors = validateReceiptSemantics(receipt);
  errors.push(...semanticErrors);

  if (!Array.isArray(receipt.evidence)) {
    errors.push("receipt.evidence must be an array");
  } else {
    for (const [i, ev] of receipt.evidence.entries()) {
      if (typeof ev.guard_name !== "string") {
        errors.push(`receipt.evidence[${i}].guard_name must be a string`);
      }
      if (typeof ev.verdict !== "boolean") {
        errors.push(`receipt.evidence[${i}].verdict must be a boolean`);
      }
    }
  }

  if (typeof receipt.response_status !== "number" || receipt.response_status < 100 || receipt.response_status > 599) {
    errors.push("receipt.response_status must be a valid HTTP status code");
  }

  if (typeof receipt.timestamp !== "number" || receipt.timestamp <= 0) {
    errors.push("receipt.timestamp must be a positive number");
  }

  if (!isLowerHex64(receipt.content_hash)) {
    errors.push("receipt.content_hash must be a 64-character hex string");
  }

  if (typeof receipt.policy_hash !== "string" || receipt.policy_hash.length === 0) {
    errors.push("receipt.policy_hash must be a non-empty string");
  }

  if (typeof receipt.kernel_key !== "string" || receipt.kernel_key.length === 0) {
    errors.push("receipt.kernel_key must be a non-empty string");
  }

  if (typeof receipt.signature !== "string" || receipt.signature.length === 0) {
    errors.push("receipt.signature must be a non-empty string");
  }

  return errors;
}

export function validateChioReceiptRecordStructure(receipt: Receipt_Record.ChioReceiptRecord): string[] {
  const errors: string[] = [];
  if (!isLowerHex64(receipt.id)) {
    errors.push("receipt.id must be a 64-character lowercase hex content-addressed id");
  }
  if (!isLowerHex64(receipt.action.parameter_hash)) {
    errors.push("receipt.action.parameter_hash must be a 64-character lowercase hex string");
  }
  if (!isLowerHex64(receipt.content_hash)) {
    errors.push("receipt.content_hash must be a 64-character lowercase hex string");
  }
  if (typeof receipt.signature !== "string" || receipt.signature.length === 0) {
    errors.push("receipt.signature must be a non-empty string");
  }
  errors.push(...validateChioReceiptRecordSemantics(receipt));
  return errors;
}

export function receiptAuthorityAllows(
  receipt: HttpReceipt,
  verification: ReceiptAuthorityResult,
): boolean {
  return verification.ok
    && verification.authorized
    && verification.signature_valid
    && verification.signer_trusted
    && verification.receipt_id_valid
    && verification.parameter_hash_valid
    && verification.receipt_kind === "mediated_decision"
    && verification.boundary_class === "prevent"
    && verification.trust_level === "mediated"
    && verification.result === "allow"
    && isLowerHex64(receipt.id)
    && typeof receipt.signature === "string"
    && receipt.signature.length > 0
    && isLowerHex64(receipt.content_hash)
    && isHttpReceiptAuthorizedBySemantics(receipt);
}

/**
 * Verify that the content hash in a receipt matches the expected
 * canonical JSON representation of the request content binding.
 */
export function verifyContentHash(
  receipt: HttpReceipt,
  expectedMethod: string,
  expectedRoutePattern: string,
  expectedPath: string,
  expectedQuery: Record<string, string>,
  expectedBodyHash: string | null,
): boolean {
  const binding = {
    body_hash: expectedBodyHash,
    method: expectedMethod,
    path: expectedPath,
    query: expectedQuery,
    route_pattern: expectedRoutePattern,
  };

  const canonical = canonicalJsonString(binding);
  const hash = createHash("sha256").update(canonical, "utf-8").digest("hex");
  return hash === receipt.content_hash;
}

/**
 * Check that a receipt verdict matches expected values.
 */
export function assertVerdictMatch(
  actual: Verdict,
  expected: {
    verdict: "allow" | "deny" | "cancel" | "incomplete";
    reason?: string;
    guard?: string;
    http_status?: number;
  },
): string[] {
  const errors: string[] = [];

  if (actual.verdict !== expected.verdict) {
    errors.push(`expected verdict "${expected.verdict}", got "${actual.verdict}"`);
    return errors;
  }

  if (expected.verdict === "deny" && actual.verdict === "deny") {
    if (expected.reason != null && actual.reason !== expected.reason) {
      errors.push(`expected deny reason "${expected.reason}", got "${actual.reason}"`);
    }
    if (expected.guard != null && actual.guard !== expected.guard) {
      errors.push(`expected deny guard "${expected.guard}", got "${actual.guard}"`);
    }
    if (expected.http_status != null && actual.http_status !== expected.http_status) {
      errors.push(`expected deny http_status ${expected.http_status}, got ${actual.http_status}`);
    }
  }

  return errors;
}

function isValidVerdict(v: Verdict): boolean {
  if (v.verdict === "allow") return true;
  if (v.verdict === "deny") return typeof v.reason === "string" && typeof v.guard === "string";
  if (v.verdict === "cancel") return typeof v.reason === "string";
  if (v.verdict === "incomplete") return typeof v.reason === "string";
  return false;
}

function isHttpReceiptAuthorizedBySemantics(receipt: HttpReceipt): boolean {
  return receipt.receipt_kind === "mediated_decision"
    && receipt.boundary_class === "prevent"
    && receipt.observation_outcome == null
    && receipt.trust_level === "mediated"
    && receipt.verdict.verdict === "allow";
}

function isLowerHex64(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function validateReceiptSemantics(receipt: HttpReceipt): string[] {
  const errors: string[] = [];
  if (receipt.receipt_kind !== "mediated_decision"
    && receipt.receipt_kind !== "trace_observation"
    && receipt.receipt_kind !== "advisory_evaluation") {
    errors.push("receipt.receipt_kind must be a current v1 receipt kind");
  }
  if (receipt.boundary_class !== "prevent"
    && receipt.boundary_class !== "detect_only"
    && receipt.boundary_class !== "advisory_only") {
    errors.push("receipt.boundary_class must be a runtime boundary class");
  }
  if (receipt.tool_origin !== "caller_executed"
    && receipt.tool_origin !== "host_executed_provider_reported"
    && receipt.tool_origin !== "host_executed_unmediated") {
    errors.push("receipt.tool_origin must be a current v1 tool origin");
  }
  if (receipt.redaction_mode !== "none"
    && receipt.redaction_mode !== "summary"
    && receipt.redaction_mode !== "redacted") {
    errors.push("receipt.redaction_mode must be a current v1 redaction mode");
  }
  if (receipt.trust_level !== "mediated"
    && receipt.trust_level !== "verified"
    && receipt.trust_level !== "advisory") {
    errors.push("receipt.trust_level must be a current v1 trust level");
  }

  if (receipt.receipt_kind === "mediated_decision") {
    if (receipt.boundary_class !== "prevent") {
      errors.push("mediated_decision receipts must use boundary_class prevent");
    }
    if (receipt.trust_level !== "mediated") {
      errors.push("mediated_decision receipts must use trust_level mediated");
    }
    if (receipt.observation_outcome != null) {
      errors.push("mediated_decision receipts must omit observation_outcome");
    }
  } else if (receipt.receipt_kind === "trace_observation") {
    if (receipt.boundary_class !== "detect_only") {
      errors.push("trace_observation receipts must use boundary_class detect_only");
    }
    if (receipt.trust_level !== "verified") {
      errors.push("trace_observation receipts must use trust_level verified");
    }
    if (receipt.observation_outcome == null) {
      errors.push("trace_observation receipts must include observation_outcome");
    }
  } else if (receipt.receipt_kind === "advisory_evaluation") {
    if (receipt.boundary_class !== "advisory_only") {
      errors.push("advisory_evaluation receipts must use boundary_class advisory_only");
    }
    if (receipt.trust_level !== "advisory") {
      errors.push("advisory_evaluation receipts must use trust_level advisory");
    }
    if (receipt.observation_outcome == null) {
      errors.push("advisory_evaluation receipts must include observation_outcome");
    }
  }
  return errors;
}

function validateChioReceiptRecordSemantics(
  receipt: Receipt_Record.ChioReceiptRecord,
): string[] {
  const errors: string[] = [];
  if (receipt.receipt_kind === "mediated_decision") {
    if (receipt.decision == null) {
      errors.push("mediated_decision receipts must include decision");
    }
    if (receipt.boundary_class !== "prevent") {
      errors.push("mediated_decision receipts must use boundary_class prevent");
    }
    if (receipt.trust_level !== "mediated") {
      errors.push("mediated_decision receipts must use trust_level mediated");
    }
    if (receipt.observation_outcome != null) {
      errors.push("mediated_decision receipts must omit observation_outcome");
    }
    return errors;
  }

  if (receipt.receipt_kind === "trace_observation") {
    if (receipt.decision != null) {
      errors.push("trace_observation receipts must omit decision");
    }
    if (receipt.boundary_class !== "detect_only") {
      errors.push("trace_observation receipts must use boundary_class detect_only");
    }
    if (receipt.trust_level !== "verified") {
      errors.push("trace_observation receipts must use trust_level verified");
    }
    if (receipt.observation_outcome == null) {
      errors.push("trace_observation receipts must include observation_outcome");
    }
    return errors;
  }

  if (receipt.receipt_kind === "advisory_evaluation") {
    if (receipt.decision != null) {
      errors.push("advisory_evaluation receipts must omit decision");
    }
    if (receipt.boundary_class !== "advisory_only") {
      errors.push("advisory_evaluation receipts must use boundary_class advisory_only");
    }
    if (receipt.trust_level !== "advisory") {
      errors.push("advisory_evaluation receipts must use trust_level advisory");
    }
    if (receipt.observation_outcome == null) {
      errors.push("advisory_evaluation receipts must include observation_outcome");
    }
    return errors;
  }

  errors.push("receipt_kind must be a current v1 receipt kind");
  return errors;
}
