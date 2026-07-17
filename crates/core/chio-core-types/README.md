# chio-core-types

chio-core-types defines the canonical Chio protocol wire types: capability
tokens, signed receipts, RFC 8785 canonical JSON, cryptographic signing,
Merkle proofs, and session boundaries. It is pure data and cryptography with
no I/O and no runtime state, and it has no internal `chio-*` dependencies,
which puts it at the base of the Chio dependency graph.

The crate is `no_std + alloc` by source: `--no-default-features` compiles
every module against `core` and `alloc` only, which is what lets
`chio-kernel-core` cross-compile to `wasm32-unknown-unknown` and other
embedded targets. `chio-core` re-exports this crate's public API alongside
the economic and trust domain crates under one `chio_core::*` path; depend on
`chio-core-types` directly when you need the wire types without that broader
facade.

## Responsibilities

- Define capability tokens, scopes, delegation and attenuation algebra, and
  governed-execution metadata (`capability`).
- Define signed receipts and the kind/boundary/decision compatibility rules
  that govern them (`receipt`).
- Implement RFC 8785 canonical JSON serialization, the byte-stable substrate
  every signature in Chio is computed over (`canonical`).
- Implement Ed25519 signing and verification behind the `SigningBackend`
  trait, with optional FIPS P-256/P-384 (`fips`) and post-quantum ML-DSA-65
  hybrid (`pq`) backends (`crypto`, `pq`).
- Implement SHA-256 hashing and an RFC 6962 Merkle tree for receipt-log
  inclusion proofs (`hashing`, `merkle`).
- Define session-scoped identifiers, transport auth contexts, and the
  normalized operations the edge translates transport frames into
  (`session`).
- Define signed tool-server manifests, agent/kernel wire messages, and
  pre-flight plan-evaluation DTOs (`manifest`, `message`, `plan`).
- Maintain the fail-closed registry of known signed-artifact schema IDs
  (`signed_artifact`).
- Define runtime attestation evidence, verifier-family classification, and
  workload identity normalization (`runtime_attestation`,
  `capability::runtime_attestation`, `capability::trust_policy`,
  `capability::workload_identity`).

## Public API

Flattened to the crate root via `pub use`:

- `canonical` - `canonical_json_bytes`, `canonical_json_string` (plus strict
  `_from_str` I-JSON variants), `canonicalize`, `CanonicalBytes`.
- `crypto` - `Keypair`, `PublicKey`, `Signature`, `SigningAlgorithm`, the
  `SigningBackend` trait, `Ed25519Backend`, `sha256_hex`;
  `HybridBackend`/`MlDsa65Backend` under `pq`, `P256Backend`/`P384Backend`
  under `fips`.
- `hashing`, `merkle` - `Hash`, `sha256`; `MerkleTree`, `MerkleProof`,
  `leaf_hash`, `node_hash`.
- `session` - `SessionId`, `RequestId`, `SessionAnchor`, `SessionAuthContext`,
  `SessionOperation`, and the rest of the normalized-operation surface.
- `manifest` - `ToolManifest`, `ToolDefinition`, `ToolAnnotations`,
  `ToolPricing`, `PricingModel`.
- `message` - `AgentMessage`, `KernelMessage`, `ToolCallResult`,
  `ToolCallError`.
- `plan` - `PlanEvaluationRequest`/`PlanEvaluationResponse`,
  `PlannedToolCall`, `StepVerdict`.
- `signed_artifact` - `validate_signed_artifact_schema`,
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, `built_in_signed_artifact_registry`.
- `runtime_attestation` - `AttestationVerifierFamily`,
  `verifier_family_for_attestation_schema`, the attestation schema constants.
- `oracle`, `loaded_weights`, `delegation_receipt`, `error` -
  `OracleConversionEvidence`; `LoadedWeights`; `DelegationReceipt`,
  `ScopeAttenuation`; `Error`, `Result`.
- `AgentId`, `ServerId`, `CapabilityId` - opaque `String` identifier aliases.

Namespaced, not flattened (import through the submodule path):

- `capability::token` - `CapabilityToken`, `CapabilityTokenBody`.
- `capability::scope` - `ChioScope`, `ToolGrant`, `Operation`, `Constraint`.
- `capability::attenuation` - `DelegationLink`, `Attenuation`, `delegate()`.
- `capability::governance` - `GovernedTransactionIntent`,
  `GovernedApprovalToken`, `CallChainContinuationToken`.
- `receipt::body` - `ChioReceipt`, `ChioReceiptBody`, `chio_receipt_id`.
- `receipt::signing` - `ReceiptSigningHandle` (WYSIWYS signing),
  `BbsReceiptSignature`.
- `receipt::kinds`, `receipt::decision` - `ReceiptKind`, `BoundaryClass`,
  `TrustLevel`, `Decision`, `ToolCallAction`.

## Usage

```rust
use chio_core_types::Keypair;
use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};

let issuer = Keypair::generate();
let subject = Keypair::generate();

let body = CapabilityTokenBody {
    id: "cap-001".into(),
    issuer: issuer.public_key(),
    subject: subject.public_key(),
    scope: ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-files".into(),
            tool_name: "read_file".into(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    },
    issued_at: 1_700_000_000,
    expires_at: 1_700_003_600,
    delegation_chain: vec![],
};

let token = CapabilityToken::sign(body, &issuer)?;
assert!(token.verify_signature()?);
```

## Feature flags

| Flag | Effect |
|------|--------|
| `std` (default) | Enables `std`-backed `thiserror::Error` derives and the `std` feature on every dependency. |
| `fips` | Enables `P256Backend` / `P384Backend` (NIST P-256/P-384 ECDSA via `aws-lc-rs`, FIPS 140-3 validated). Implies `std`. |
| `pq` | Enables the `pq` module, `MlDsa65Backend`, and `HybridBackend` (classical plus ML-DSA-65 hybrid signing) via `fips204`. |
| `delegation` | No-op. The recursive-delegation wire primitive is always compiled in; kept for downstream manifests that enable it by name. The Cargo feature `delegation_v2` is retained as a backward-compat alias of this flag. |

## Testing

```bash
cargo test -p chio-core-types
cargo test -p chio-core-types --features fips
cargo test -p chio-core-types --features pq
cargo build -p chio-core-types --no-default-features
cargo build -p chio-core-types --no-default-features --target wasm32-unknown-unknown
```

The integration-test harness itself needs `std`, so `tests/no_std_build.rs`
proves the public API stays reachable through `core`/`alloc` imports instead
of actually running under `--no-default-features`; the two build commands
above exercise that path directly.

## See also

- `chio-core` - facade that re-exports this crate's public API under
  `chio_core::*` alongside the economic and trust domain crates.
- `chio-kernel-core` - depends on `chio-core-types` directly
  (`default-features = false`, forwarding `std`) so kernel evaluation and
  receipt signing stay portable.
- `chio-spec-codegen` - generates the quarantined
  `src/_generated/chio_wire_v1.rs` bindings, not currently declared as a
  module from `lib.rs`.
