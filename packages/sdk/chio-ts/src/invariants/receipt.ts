import { canonicalizeJson, canonicalizeJsonString } from "./json.ts";
import { publicKeyHexMatches, sha256Hex, verifyChioSignature } from "./crypto.ts";
import { ChioInvariantError, parseJsonText } from "./errors.ts";

function safeVerifyReceiptSignature(
  signedBytes: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    return verifyChioSignature(signedBytes, signature, publicKey);
  } catch (error) {
    if (error instanceof ChioInvariantError) {
      // Fail-closed: receipts signed with unsupported algorithms or malformed
      // keys/signatures verify as false rather than propagating an exception.
      return false;
    }
    throw error;
  }
}

export type ReceiptDecisionKind = "allow" | "deny" | "cancelled" | "incomplete" | "none";

export interface ToolCallAction {
  parameters: unknown;
  parameter_hash: string;
}

export interface ChioReceipt {
  id: string;
  timestamp: number;
  capability_id: string;
  tool_server: string;
  tool_name: string;
  action: ToolCallAction;
  decision?: {
    verdict: ReceiptDecisionKind;
    reason?: string;
    guard?: string;
  };
  receipt_kind: string;
  boundary_class: string;
  observation_outcome?: string;
  tool_origin: string;
  redaction_mode: string;
  actor_chain?: Array<{
    actor_id: string;
    actor_kind?: string;
  }>;
  content_hash: string;
  policy_hash: string;
  evidence?: Array<{
    guard_name: string;
    verdict: boolean;
    details?: string;
  }>;
  metadata?: unknown;
  trust_level: "mediated" | "verified" | "advisory" | string;
  tenant_id?: string;
  kernel_key: string;
  algorithm?: unknown;
  signature: string;
}

export interface ReceiptVerification {
  signature_valid: boolean;
  parameter_hash_valid: boolean;
  receipt_id_valid: boolean;
  decision: ReceiptDecisionKind;
  receipt_kind: string;
  boundary_class: string;
  trust_level: string;
  result: string;
  authorized: boolean;
  signer_key_hex: string;
  signer_trusted: boolean;
  ok: boolean;
}

export function parseReceiptJson(input: string): ChioReceipt {
  return parseJsonText(input);
}

export function receiptBody(receipt: ChioReceipt): Omit<ChioReceipt, "algorithm" | "signature"> {
  const { signature: _signature, algorithm: _algorithm, ...body } = receipt;
  return body;
}

export function receiptBodyCanonicalJson(receipt: ChioReceipt): string {
  return canonicalizeJson(receiptBody(receipt));
}

function receiptIdInput(receipt: ChioReceipt): Record<string, unknown> {
  const input: Record<string, unknown> = {
    action: receipt.action,
    capability_id: receipt.capability_id,
    content_hash: receipt.content_hash,
    receipt_kind: receipt.receipt_kind,
    boundary_class: receipt.boundary_class,
    tool_origin: receipt.tool_origin,
    redaction_mode: receipt.redaction_mode,
    kernel_key: receipt.kernel_key,
    policy_hash: receipt.policy_hash,
    timestamp: receipt.timestamp,
    tool_name: receipt.tool_name,
    tool_server: receipt.tool_server,
  };
  if (receipt.evidence !== undefined && receipt.evidence.length > 0) {
    input.evidence = receipt.evidence;
  }
  if (receipt.decision !== undefined) {
    input.decision = receipt.decision;
  }
  if (receipt.observation_outcome !== undefined) {
    input.observation_outcome = receipt.observation_outcome;
  }
  if (receipt.actor_chain !== undefined && receipt.actor_chain.length > 0) {
    input.actor_chain = receipt.actor_chain;
  }
  if (receipt.metadata !== undefined && receipt.metadata !== null) {
    input.metadata = receipt.metadata;
  }
  input.trust_level = receipt.trust_level;
  if (receipt.tenant_id !== undefined) {
    input.tenant_id = receipt.tenant_id;
  }
  return input;
}

function contentAddressedReceiptId(receipt: ChioReceipt): string {
  return sha256Hex(canonicalizeJson(receiptIdInput(receipt)));
}

export function receiptSigningBodyCanonicalJson(receipt: ChioReceipt): string {
  return canonicalizeJson({
    id: receipt.id,
    body: receiptIdInput(receipt),
  });
}

function receiptSemantics(receipt: ChioReceipt): { receipt_kind: string; boundary_class: string } {
  return { receipt_kind: receipt.receipt_kind, boundary_class: receipt.boundary_class };
}

function resultLabel(receiptKind: string, boundaryClass: string, decision: ReceiptDecisionKind): string {
  if (receiptKind === "mediated_decision" && boundaryClass === "prevent" && decision === "allow") {
    return "Authorized";
  }
  if (receiptKind === "trace_observation") {
    return "Observed";
  }
  if (receiptKind === "advisory_evaluation") {
    return "Advisory";
  }
  switch (decision) {
    case "allow":
      return "Allowed";
    case "deny":
      return "Denied";
    case "cancelled":
      return "Cancelled";
    case "incomplete":
      return "Incomplete";
    case "none":
      return "Invalid";
  }
}

function validObservationOutcome(value: string | undefined): boolean {
  return value === "observed" || value === "evaluated" || value === "dropped";
}

function semanticallySignable(receipt: ChioReceipt, decision: ReceiptDecisionKind): boolean {
  if (receipt.receipt_kind === "mediated_decision") {
    return (
      receipt.boundary_class === "prevent" &&
      receipt.trust_level === "mediated" &&
      decision !== "none" &&
      receipt.observation_outcome === undefined
    );
  }
  if (receipt.receipt_kind === "trace_observation") {
    return (
      receipt.boundary_class === "detect_only" &&
      receipt.trust_level === "verified" &&
      decision === "none" &&
      validObservationOutcome(receipt.observation_outcome)
    );
  }
  if (receipt.receipt_kind === "advisory_evaluation") {
    return (
      receipt.boundary_class === "advisory_only" &&
      receipt.trust_level === "advisory" &&
      decision === "none" &&
      validObservationOutcome(receipt.observation_outcome)
    );
  }
  return false;
}

export function verifyReceipt(receipt: ChioReceipt, trustedSigners: string[] = []): ReceiptVerification {
  const signingBodyCanonicalJson = receiptSigningBodyCanonicalJson(receipt);
  const parameterCanonicalJson = canonicalizeJson(receipt.action.parameters);
  const decision = receipt.decision?.verdict ?? "none";
  const semantics = receiptSemantics(receipt);
  const semanticAuthorized =
    semantics.receipt_kind === "mediated_decision" && semantics.boundary_class === "prevent" && decision === "allow";
  const signerTrusted =
    trustedSigners.length > 0 && trustedSigners.some((signer) => publicKeyHexMatches(signer, receipt.kernel_key));
  const receiptIdValid = receipt.id === contentAddressedReceiptId(receipt);
  const signatureValid =
    receiptIdValid &&
    semanticallySignable(receipt, decision) &&
    safeVerifyReceiptSignature(signingBodyCanonicalJson, receipt.signature, receipt.kernel_key);
  const parameterHashValid = receipt.action.parameter_hash === sha256Hex(parameterCanonicalJson);
  const authorized = semanticAuthorized && signatureValid && parameterHashValid && receiptIdValid && signerTrusted;

  return {
    signature_valid: signatureValid,
    parameter_hash_valid: parameterHashValid,
    receipt_id_valid: receiptIdValid,
    decision,
    receipt_kind: semantics.receipt_kind,
    boundary_class: semantics.boundary_class,
    trust_level: receipt.trust_level,
    result: resultLabel(semantics.receipt_kind, semantics.boundary_class, decision),
    authorized,
    signer_key_hex: receipt.kernel_key,
    signer_trusted: signerTrusted,
    ok: signatureValid && parameterHashValid && receiptIdValid && signerTrusted,
  };
}

export function verifyReceiptWithTrustedSigners(
  receipt: ChioReceipt,
  trustedSigners: string[],
): ReceiptVerification {
  return verifyReceipt(receipt, trustedSigners);
}

export function verifyReceiptJson(input: string): ReceiptVerification {
  return verifyReceipt(parseReceiptJson(input));
}

export { canonicalizeJsonString };
