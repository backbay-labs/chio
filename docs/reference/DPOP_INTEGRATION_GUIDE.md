# Chio DPoP Integration Guide

DPoP (Demonstration of Proof-of-Possession) is Chio's optional sender-constrained invocation profile. When a `ToolGrant` carries `dpop_required: Some(true)`, the kernel requires the agent to attach a fresh cryptographic proof with every invocation. The proof binds the call to the agent's keypair, the specific capability token, the target tool, and the exact arguments. Grants without `dpop_required: Some(true)` remain compatibility paths and should not be described as universally sender-constrained.

## When DPoP Is Required

The `dpop_required` field on `ToolGrant` controls enforcement:

```rust
pub struct ToolGrant {
    // ...
    pub dpop_required: Option<bool>,
}
```

`Some(true)` requires a valid DPoP proof. `None` and `Some(false)` both disable DPoP for that grant. When the kernel encounters a request against a DPoP-required grant and no proof is supplied (or the proof fails verification), the invocation is denied.

## Proof Format

A DPoP proof is a Chio-native structure using Ed25519 and RFC 8785 canonical
JSON. It is not a JWT.

### DpopProofBody

```rust
pub struct DpopProofBody {
    pub schema: String,        // "chio.dpop_proof.v1" (compatibility schema alias accepted)
    pub capability_id: String, // token ID of the capability being used
    pub tool_server: String,   // server_id of the target tool server
    pub tool_name: String,     // name of the tool being called
    pub action_hash: String,   // SHA-256 hex of canonical JSON of tool arguments
    pub nonce: String,         // caller-chosen random string
    pub issued_at: u64,        // Unix seconds when the proof was created
    pub agent_key: PublicKey,  // hex-encoded Ed25519 public key of the signer
}
```

### DpopProof

```rust
pub struct DpopProof {
    pub body: DpopProofBody,
    pub signature: Signature,  // Ed25519 over canonical_json_bytes(&body)
}
```

The `signature` covers the canonical JSON (RFC 8785) of `body`. The field order in canonical JSON is alphabetical, which matches Rust's default serde serialization.

## Field Binding

Each proof is bound to a single invocation by four fields:

- `capability_id` must match the token ID in the request.
- `tool_server` must match the `server_id` of the target tool server.
- `tool_name` must match the tool being called.
- `action_hash` must equal the SHA-256 hex of the canonical JSON of the tool arguments. This prevents an adversary from reusing a proof with different arguments.

## Verification Steps

`verify_dpop_proof` in `chio-kernel` enforces six steps in order. The first failure returns an error and the invocation is denied.

1. Schema check: `body.schema` must equal the current Chio DPoP schema or a
   compatibility alias accepted by the verifier.
2. Sender constraint: `body.agent_key` must equal `capability.subject` (the public key the token was issued to).
3. Binding fields: `capability_id`, `tool_server`, `tool_name`, and `action_hash` must all match the kernel's expected values.
4. Freshness: `body.issued_at + proof_ttl_secs >= now` (proof not expired) and `body.issued_at <= now + max_clock_skew_secs` (proof not future-dated beyond tolerance).
5. Signature: Ed25519 verification of `signature` over canonical JSON of `body` using `agent_key`.
6. Nonce replay: the `(nonce, capability_id)` pair must not have been seen within the TTL window.

## DpopConfig

```rust
pub struct DpopConfig {
    pub proof_ttl_secs: u64,          // default: 300
    pub max_clock_skew_secs: u64,     // default: 30
    pub nonce_store_capacity: usize,  // default: 8192
}
```

`proof_ttl_secs` is how long a proof remains valid after `issued_at`. The default is 5 minutes. `max_clock_skew_secs` is how far in the future a proof's `issued_at` may be while still passing (to accommodate slight clock differences between client and server). The default is 30 seconds.

`nonce_store_capacity` limits the in-memory nonce replay cache. Nonces are keyed by `(nonce, capability_id)`. Expired entries are reclaimed, but live replay markers are never evicted. When all slots are live, the store denies new reservations fail-closed. Capacity should be set above the expected peak rate of concurrent calls times the full signed validity window, including tolerated future clock skew.

The durable `SqliteExecutionNonceStore` applies the same deny-at-cap policy to
retained execution-nonce rows. `open` uses
`DEFAULT_EXECUTION_NONCE_STORE_CAPACITY`; `open_with_capacity` configures a
different kernel-global limit. Its prune, duplicate check, live-row count, and
insert execute in one write transaction, so pressure cannot evict a live marker
or admit a row above the configured bound.

### External payment authorization

DPoP alone does not authorize an external payment rail call. Its built-in nonce
store is process-scoped, so a fresh proof could be accepted again after a
kernel restart. Before calling `PaymentAdapter::authorize`, the kernel requires
a freshly reserved execution nonce or governed approval marker. Deployments
that need payment replay protection across restart must install the durable
store for that credential path, such as `SqliteExecutionNonceStore` or
`SqliteGovernedApprovalReplayStore`.

These capacities are availability boundaries, not tenant quotas. The replay
store contracts do not carry an authenticated principal or tenant identity, and
opaque nonce IDs must not be parsed to invent one. Multi-tenant deployments
that need independent pressure domains must use a dedicated kernel and replay
store per tenant, or enforce authenticated per-tenant rate limits before calls
reach a shared kernel. A shared store still preserves replay correctness under
pressure by denying new reservations, but one tenant can consume the shared
availability budget.

## Generating Proofs (Rust)

```rust
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

let body = DpopProofBody {
    schema: DPOP_SCHEMA.to_string(),
    capability_id: token.id.clone(),
    tool_server: "filesystem".to_string(),
    tool_name: "read_file".to_string(),
    action_hash: sha256_hex_of_canonical_args(&args),
    nonce: random_hex_16(),
    issued_at: unix_now_secs(),
    agent_key: agent_keypair.public_key(),
};

let proof = DpopProof::sign(body, &agent_keypair)?;
```

Attach `proof` to the `ToolCallRequest.dpop_proof` field before sending.

## Generating Proofs (TypeScript SDK)

See `docs/SDK_TYPESCRIPT_REFERENCE.md` for the `signDpopProof` function. The
TypeScript implementation emits Chio schema identifiers. Verifiers reject legacy
pre-Chio proof schemas instead of treating them as aliases.
