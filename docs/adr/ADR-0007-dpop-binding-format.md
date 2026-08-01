# ADR-0007: DPoP Binding Format

- Status: Accepted
- Decision owner: protocol and enforcement lanes

## Context

Chio capability tokens are Bearer-style credentials: any holder can present
them. This creates a stolen-token risk: if an agent's token is captured in
transit or on disk, an attacker can replay it until expiry.

The standard mitigation is Demonstration of Proof-of-Possession (DPoP), where
the holder proves they control the private key corresponding to the subject
field in the token. RFC 9449 defines DPoP for HTTP, binding proofs to HTTP
method and URI. Chio does not use HTTP for agent-to-kernel communication (it
uses an anonymous pipe or Unix domain socket), so RFC 9449's HTTP-shaped
binding fields are not applicable.

## Decision

Chio implements its own DPoP format, `chio.dpop_proof.v1`, designed for the
Chio wire protocol rather than HTTP.

### Proof Body (8 fields)

```rust
pub struct DpopProofBody {
    pub schema:        String,    // "chio.dpop_proof.v1" (forward-compat guard)
    pub capability_id: String,    // ID of the capability token being used
    pub tool_server:   String,    // server_id of the target tool server
    pub tool_name:     String,    // Name of the tool being called
    pub action_hash:   String,    // SHA-256 hex of the serialized tool arguments
    pub nonce:         String,    // Caller-chosen random string (replay prevention)
    pub issued_at:     u64,       // Unix seconds when the proof was created
    pub agent_key:     PublicKey, // Hex-encoded Ed25519 public key of the signer
}
```

The proof body is serialized to canonical JSON (RFC 8785) and signed with
Ed25519. The signature covers all 8 fields; none are mutable after signing.

### Verification Steps (in order)

1. **Schema check** -- `schema` must equal `"chio.dpop_proof.v1"`. Unknown
   schema strings are rejected to allow future protocol evolution.
2. **Sender constraint** -- `agent_key` must equal `capability.subject`. This
   binds the proof to the key the CA authorized.
3. **Binding fields** -- `capability_id`, `tool_server`, `tool_name`, and
   `action_hash` must all match the actual invocation context. A stolen proof
   cannot be replayed for a different tool or different arguments.
4. **Freshness** -- `issued_at + proof_ttl_secs >= now` and
   `issued_at <= now + max_clock_skew_secs`. Default TTL is 300 seconds.
   Default clock skew tolerance is 30 seconds.
5. **Signature** -- Ed25519 signature over canonical JSON of the proof body.
6. **Nonce replay** -- the `(nonce, capability_id)` pair must not have been
   consumed during the proof's signed validity window. The process-scoped
   store retains each live marker through that full horizon.

All six steps must pass. The first failure returns an error; the Kernel denies
fail-closed.

### Signed-Horizon Nonce Store

The nonce store uses an in-memory `LruCache` internally, keyed by
`(nonce, capability_id)`, but live markers are never evicted. Direct
verification calls `check_and_insert_through`; kernel dispatch calls the
owner-qualified `reserve_for_dispatch_through` path. Both retain a marker
through the inclusive `issued_at + proof_ttl_secs` horizon. Expired markers
are reclaimed, while exhaustion of the default 8192-entry capacity denies new
proofs fail-closed. Deployments must size the store for peak proof volume over
the full validity window, including tolerated future clock skew.

The current DPoP nonce store is process-scoped. Restarting the Kernel clears
its markers, so this implementation does not provide restart-durable replay
protection for a proof whose signed validity window is still open.

### DPoP Opt-In

DPoP is optional per grant. `ToolGrant::dpop_required: Option<bool>` controls
whether the Kernel requires a proof for invocations under that grant. `None`
and `Some(false)` both mean DPoP is not required. `Some(true)` means the
Kernel will reject any invocation that does not include a valid proof.

## Why Not RFC 9449

RFC 9449 binds proofs to HTTP method, URI, and optional access token hash.
These fields are HTTP-specific and meaningless in Chio's pipe/UDS transport.
Chio binds proofs to `capability_id`, `tool_server`, `tool_name`, and
`action_hash`, which provide equivalent or stronger binding for the Chio
invocation model.

## Consequences

### Positive

- Prevents stolen-token replay without requiring mTLS on the agent-kernel
  channel (typically a local pipe or UDS that is not TCP).
- Binding to `action_hash` means a proof cannot be replayed for a different
  set of arguments, even with the same token.
- Schema versioning (`chio.dpop_proof.v1`) allows the format to evolve without
  breaking existing verifiers.

### Negative

- Agents must generate an Ed25519 keypair per session and sign a proof for
  every invocation where `dpop_required = true`. This adds latency for
  CPU-constrained agents.
- The in-memory nonce store is lost on Kernel restart. Brief restart windows
  allow a narrow replay opportunity if a proof was issued just before restart.
  The remaining signed DPoP validity window bounds the attack window.

## Required Follow-up

- Provide reference DPoP proof construction in SDK clients (Rust, TypeScript,
  Python).
- Document the nonce store restart caveat in operator security guidance.
