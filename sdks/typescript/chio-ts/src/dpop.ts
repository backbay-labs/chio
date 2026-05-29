import { randomBytes } from "node:crypto";

import { DpopSignError } from "./errors.ts";
import { signEd25519Message, sha256Hex } from "./invariants/crypto.ts";
import { canonicalizeJson } from "./invariants/json.ts";

/**
 * The schema identifier for DPoP proofs. Must match chio-kernel's DPOP_SCHEMA constant.
 */
export const DPOP_SCHEMA = "chio.dpop_proof.v1";

/**
 * The body of a DPoP proof. Field names use snake_case to match Rust/serde serialization.
 * Field order in canonical JSON is alphabetical (RFC 8785), which also matches serde's default.
 *
 * Fields (alphabetical order as they appear in canonical JSON):
 *   action_hash, agent_key, capability_id, issued_at, nonce, schema, tool_name, tool_server
 */
export interface DpopProofBody {
  action_hash: string;
  agent_key: string;
  capability_id: string;
  issued_at: number;
  nonce: string;
  schema: string;
  tool_name: string;
  tool_server: string;
}

/**
 * A signed DPoP proof. The signature is Ed25519 over the canonical JSON of the body.
 */
export interface DpopProof {
  body: DpopProofBody;
  signature: string;
}

/**
 * Parameters for signDpopProof.
 */
export interface SignDpopProofParams {
  capabilityId: string;
  toolServer: string;
  toolName: string;
  actionArgs: unknown;
  agentSeedHex: string;
  nonce?: string;
  issuedAt?: number;
}

/**
 * Sign a DPoP proof for a Chio tool invocation.
 *
 * The proof body is serialized as RFC 8785 canonical JSON before signing,
 * ensuring compatibility with chio-kernel's verify_dpop_proof.
 *
 * @throws DpopSignError if the agentSeedHex is invalid or signing fails.
 */
export function signDpopProof(params: SignDpopProofParams): DpopProof {
  const {
    capabilityId,
    toolServer,
    toolName,
    actionArgs,
    agentSeedHex,
    nonce = randomBytes(16).toString("hex"),
    issuedAt = Math.floor(Date.now() / 1000),
  } = params;

  try {
    // Compute action_hash: SHA-256 hex of canonical JSON of actionArgs
    const actionHash = sha256Hex(canonicalizeJson(actionArgs));

    // Derive agent public key from seed
    const { public_key_hex: agentKey, signature_hex: _unused } = signEd25519Message(
      "derive_key",
      agentSeedHex,
    );

    // Build body with fields in alphabetical order (matches canonical JSON and Rust serde)
    const body: DpopProofBody = {
      action_hash: actionHash,
      agent_key: agentKey,
      capability_id: capabilityId,
      issued_at: issuedAt,
      nonce,
      schema: DPOP_SCHEMA,
      tool_name: toolName,
      tool_server: toolServer,
    };

    // Sign canonical JSON of body
    const bodyCanonical = canonicalizeJson(body);
    const { signature_hex } = signEd25519Message(Buffer.from(bodyCanonical, "utf8"), agentSeedHex);

    return { body, signature: signature_hex };
  } catch (cause) {
    if (cause instanceof DpopSignError) {
      throw cause;
    }
    throw new DpopSignError("failed to sign DPoP proof", { cause });
  }
}
