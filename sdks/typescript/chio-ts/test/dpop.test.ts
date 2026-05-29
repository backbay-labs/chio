import test from "node:test";
import assert from "node:assert/strict";

import { signDpopProof, DPOP_SCHEMA } from "../src/dpop.ts";
import { DpopSignError } from "../src/errors.ts";
import { verifyEd25519Signature } from "../src/invariants/crypto.ts";
import { canonicalizeJson } from "../src/invariants/json.ts";
import { sha256Hex } from "../src/invariants/crypto.ts";

// A valid 32-byte Ed25519 seed in hex (deterministic for tests)
const SEED_HEX = "a".repeat(64);

const BASE_PARAMS = {
  capabilityId: "cap-001",
  toolServer: "tool.example.com",
  toolName: "read_file",
  actionArgs: { path: "/tmp/test.txt" },
  agentSeedHex: SEED_HEX,
};

test("signDpopProof returns body and signature with correct DpopProofBody field names", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  assert.ok(proof.body, "proof must have a body");
  assert.ok(typeof proof.signature === "string", "proof must have a signature string");

  // Verify exact field names (snake_case, matching Rust DpopProofBody)
  assert.ok("schema" in proof.body);
  assert.ok("capability_id" in proof.body);
  assert.ok("tool_server" in proof.body);
  assert.ok("tool_name" in proof.body);
  assert.ok("action_hash" in proof.body);
  assert.ok("nonce" in proof.body);
  assert.ok("issued_at" in proof.body);
  assert.ok("agent_key" in proof.body);
});

test("body.schema equals chio.dpop_proof.v1", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  assert.equal(proof.body.schema, "chio.dpop_proof.v1");
  assert.equal(proof.body.schema, DPOP_SCHEMA);
});

test("body fields are correctly populated from params", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  assert.equal(proof.body.capability_id, "cap-001");
  assert.equal(proof.body.tool_server, "tool.example.com");
  assert.equal(proof.body.tool_name, "read_file");
});

test("body.action_hash is SHA-256 hex of canonical JSON of actionArgs", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  const expected = sha256Hex(canonicalizeJson(BASE_PARAMS.actionArgs));
  assert.equal(proof.body.action_hash, expected);
});

test("body.agent_key is the Ed25519 public key derived from the seed", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  // The public key should be a 64-char hex string (32 bytes)
  assert.equal(proof.body.agent_key.length, 64);
  assert.ok(/^[0-9a-f]+$/.test(proof.body.agent_key), "agent_key must be lowercase hex");
});

test("signature verifies against canonical JSON of body using verifyEd25519Signature", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  const bodyCanonical = canonicalizeJson(proof.body);
  const valid = verifyEd25519Signature(bodyCanonical, proof.body.agent_key, proof.signature);
  assert.equal(valid, true, "signature must verify against canonical JSON of body");
});

test("canonical JSON of body has fields in alphabetical order (matching Rust serde)", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  const bodyCanonical = canonicalizeJson(proof.body);
  // The first key should be "action_hash" (alphabetically first among the fields)
  assert.ok(
    bodyCanonical.startsWith('{"action_hash"'),
    `canonical JSON must start with action_hash, got: ${bodyCanonical.slice(0, 30)}`,
  );
});

test("auto-generated nonce is 32 hex chars when not provided", () => {
  const proof = signDpopProof({ ...BASE_PARAMS });
  assert.equal(proof.body.nonce.length, 32, "auto-nonce must be 32 hex chars (16 bytes)");
  assert.ok(/^[0-9a-f]+$/.test(proof.body.nonce), "nonce must be lowercase hex");
});

test("provided nonce is used as-is", () => {
  const nonce = "deadbeefcafe1234deadbeefcafe1234";
  const proof = signDpopProof({ ...BASE_PARAMS, nonce });
  assert.equal(proof.body.nonce, nonce);
});

test("auto-generated issued_at is close to current Unix seconds when not provided", () => {
  const before = Math.floor(Date.now() / 1000);
  const proof = signDpopProof({ ...BASE_PARAMS });
  const after = Math.floor(Date.now() / 1000);
  assert.ok(
    proof.body.issued_at >= before && proof.body.issued_at <= after + 1,
    `issued_at ${proof.body.issued_at} should be between ${before} and ${after + 1}`,
  );
});

test("provided issued_at is used as-is", () => {
  const issuedAt = 1700000000;
  const proof = signDpopProof({ ...BASE_PARAMS, issuedAt });
  assert.equal(proof.body.issued_at, issuedAt);
});

test("invalid seed hex throws DpopSignError", () => {
  assert.throws(
    () => signDpopProof({ ...BASE_PARAMS, agentSeedHex: "not-valid-hex" }),
    (err: unknown) => err instanceof DpopSignError,
  );
});

test("two proofs with same params but no provided nonce have different nonces", () => {
  const proof1 = signDpopProof({ ...BASE_PARAMS });
  const proof2 = signDpopProof({ ...BASE_PARAMS });
  // With random nonces these should differ (astronomically unlikely to collide)
  assert.notEqual(proof1.body.nonce, proof2.body.nonce);
});
