// Synthetic sidecar fixtures only. These do not establish real-kernel acceptance.
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import type { HttpReceipt, Verdict, VerifyReceiptResponse } from "@chio-protocol/node-http";
import { canonicalJsonString } from "../../src/canonical.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signerHex = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJsonString(value)).digest("hex");
}

export function createMockReceipt(
  chioReq: { request_id: string; method: string; route_pattern: string; path: string; query: Record<string, string>; caller: { subject: string } },
  mode: "allow" | "deny",
): HttpReceipt {
  const verdict: Verdict =
    mode === "allow"
      ? { verdict: "allow" }
      : {
          verdict: "deny",
          reason: "side-effect route requires a capability token",
          guard: "CapabilityGuard",
          http_status: 403,
        };

  const binding = {
    body_hash: null,
    method: chioReq.method,
    path: chioReq.path,
    query: chioReq.query,
    route_pattern: chioReq.route_pattern,
  };
  const contentHash = createHash("sha256")
    .update(canonicalJsonString(binding))
    .digest("hex");

  const callerHash = createHash("sha256")
    .update(canonicalJsonString({ auth_method: { method: "anonymous" }, subject: chioReq.caller.subject, verified: false }))
    .digest("hex");

  const body: Omit<HttpReceipt, "id" | "signature"> = {
    request_id: chioReq.request_id,
    route_pattern: chioReq.route_pattern,
    method: chioReq.method as "GET",
    caller_identity_hash: callerHash,
    verdict,
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    trust_level: "mediated",
    evidence: [
      {
        guard_name: mode === "allow" ? "DefaultPolicyGuard" : "CapabilityGuard",
        verdict: mode === "allow",
        details: mode === "allow" ? "safe method, session-scoped allow" : "no capability token",
      },
    ],
    response_status: mode === "allow" ? 200 : 403,
    timestamp: Math.floor(Date.now() / 1000),
    content_hash: contentHash,
    policy_hash: createHash("sha256").update("test-policy").digest("hex"),
    kernel_key: signerHex,
  };
  const signedBody = { id: hash(body), ...body };
  return {
    ...signedBody,
    signature: sign(null, Buffer.from(canonicalJsonString(signedBody)), privateKey).toString("hex"),
  };
}

export function verifyMockReceipt(receipt: HttpReceipt): VerifyReceiptResponse {
  const { signature, ...body } = receipt;
  const { id, ...idInput } = body;
  const signatureValid = verify(null, Buffer.from(canonicalJsonString(body)), publicKey, Buffer.from(signature, "hex"));
  const signerTrusted = receipt.kernel_key === signerHex;
  const receiptIdValid = id === hash(idInput);
  const authorized = signatureValid && signerTrusted && receiptIdValid
    && receipt.receipt_kind === "mediated_decision"
    && receipt.boundary_class === "prevent"
    && receipt.trust_level === "mediated"
    && receipt.verdict.verdict === "allow";
  return {
    signature_valid: signatureValid,
    signer_trusted: signerTrusted,
    receipt_id_valid: receiptIdValid,
    parameter_hash_valid: signatureValid && receiptIdValid,
    receipt_kind: receipt.receipt_kind,
    boundary_class: receipt.boundary_class,
    trust_level: receipt.trust_level,
    result: authorized ? "allow" : "deny",
    authorized,
    signer_key_hex: signerHex,
    ok: authorized,
  };
}
