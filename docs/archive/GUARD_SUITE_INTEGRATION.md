# Guard Suite Integration Plan

How to port shared code from the upstream guard suite into Chio and restructure the dependency
relationship so that the guard product depends on Chio, not the other way around.

## 1. Architecture: Protocol vs Product

Chio is HTTP. The guard product is nginx.

Chio defines the protocol layer: capability tokens, delegation chains, receipts,
guards, and canonical serialization. It is a minimal reference implementation
suitable for standards submissions (IETF, W3C, OpenSSF). It ships zero
application-layer opinions about fleet management, SIEM, or threat intelligence.

The guard product is the batteries-included production deployment. It adds a policy
engine, 13 guards, SIEM exporters, a control console, fleet enrollment, posture
management, compliance templates, threat intel feeds, and desktop agents. It is
the commercial product built on top of the protocol.

Why the separation matters:

- **Standards submissions.** Chio must be vendor-neutral. Standards bodies will
  not adopt a spec that requires a specific product. The reference
  implementation must be self-contained.
- **Ecosystem adoption.** Third parties should be able to build their own
  "powered by Chio" products without pulling in the guard product's application code,
  SIEM integrations, or fleet management.
- **Vendor neutrality.** Chio's crypto primitives (Ed25519, SHA-256, canonical
  JSON RFC 8785, RFC 6962 Merkle trees) are standard, auditable, and
  reproducible across languages. They belong in chio-core, not behind a
  product-specific namespace.

## 2. Dependency Direction

The target dependency graph. Arrows point from consumer to dependency.

```
chio-core (types, crypto, merkle, canonical JSON)
  ^
  |-- chio-kernel (capability validation, guard pipeline, receipt signing)
  |     ^
  |     |-- chio-guards (7 protocol-level guards)
  |     |-- chio-policy (policy compiler, resolver, evaluator)
  |     |-- chio-mcp-adapter, chio-cli, chio-conformance
  |     |
  |     |-- Guard product (imports chio-core + chio-kernel as workspace deps)
  |           |-- adds: 6 application-layer guards (Jailbreak, PromptInjection,
  |           |         ComputerUse, InputInjectionCapability,
  |           |         RemoteDesktopSideChannel, SpiderSense)
  |           |-- adds: broker-specific HTTP adapters around shared Chio DPoP
  |           |-- adds: SIEM exporters (Splunk, Elastic, Datadog, Sumo Logic,
  |           |         Webhooks, Alerting)
  |           |-- adds: control console, fleet management, posture commands
  |           |-- adds: compliance templates, threat intel, marketplace
  |           |-- adds: async guard runtime (circuit breakers, caching, retry)
  |           |-- adds: telemetry bridges (Tetragon, Hubble, auditd, k8s-audit,
  |                     Darwin)
```

Today both projects maintain parallel implementations of the same crypto
primitives:

| Concept            | Chio module            | Upstream module         |
|--------------------|------------------------|----------------------------|
| Ed25519 signing    | `chio_core::crypto`    | `hush_core::signing`       |
| SHA-256 hashing    | `chio_core::hashing`   | `hush_core::hashing`       |
| Canonical JSON     | `chio_core::canonical` | `hush_core::canonical`     |
| Merkle trees       | `chio_core::merkle`    | `hush_core::merkle`        |
| Receipts           | `chio_core::receipt`   | `hush_core::receipt`       |
| Capability tokens  | `chio_core::capability`| `hush_multi_agent::token`  |

After integration, chio-core is the single canonical source for all of these.

## 3. What to Port Into Chio, and What Must Still Be Built Natively

### 3.1 DPoP Proof-of-Possession Binding

**Source (upstream guard suite):**
- `crates/services/the upstream guard suite-brokerd/src/capability.rs` -- `validate_dpop_binding()` (lines 233-324)
- `crates/libs/the upstream guard suite-broker-protocol/src/lib.rs` -- `binding_proof_message()`, `ProofBindingMode`, `ProofBinding`, `BindingProof` types

**Target (Chio):**
- `crates/chio-kernel/src/dpop.rs` (new module)
- Re-export from `chio_kernel::dpop`

**What to port:**
- `validate_dpop_binding()` -- verifies that a DPoP proof matches the key thumbprint bound into the capability, checks timestamp freshness, and validates the Ed25519 signature over a domain-separated message.
- `binding_proof_message()` -- use the broker's canonical message builder as a reference pattern, not as-is. Its current fields are HTTP-specific: `capability_id || method || url || body_sha256? || issued_at || nonce`.
- `ProofBindingMode` enum (`Loopback`, `Dpop`, `Mtls`) -- extensible binding modes.
- `ProofBinding` struct -- the binding constraint embedded in a capability token (mode + key_thumbprint + binding_sha256).
- `BindingProof` struct -- the proof the agent sends at invocation time (public_key + signature + issued_at + nonce).

**Adaptations needed:**
- Replace `BrokerCapability` references with `chio_core::CapabilityToken`. Chio's `CapabilityToken` already has a `subject: PublicKey` field that serves as the sender constraint. DPoP extends this with ephemeral proof freshness.
- Replace HTTP-request-shaped proof binding inputs (`method`, `url`, `body_sha256`) with a Chio invocation binding such as `capability_id`, `tool_server`, `tool_name`, canonical action/content hash, and optional request/session context.
- Replace `hush_core::{PublicKey, Signature}` with `chio_core::crypto::{PublicKey, Signature}`.
- Replace `hush_core::sha256_hex` with `chio_core::hashing::sha256_hex`.
- Replace `ApiError` returns with `chio_kernel::KernelError` variants.
- Remove `chrono` dependency -- use `u64` Unix timestamps to match Chio's existing convention.
- Add a `DpopConfig` struct with `proof_ttl_secs: u64` (default 60) and `max_clock_skew_secs: u64` (default 5).
- Add a replay-prevention store keyed by proof thumbprint + nonce (or equivalent). The upstream current source checks freshness but does not persist or reject nonce reuse.
- Keep SDK proof generation helpers in scope; porting only the verifier is not enough.

**Effort:** ~1-2 weeks (including replay protection, tests, and integration with the kernel's capability validation path).

### 3.2 Receipt Query API

**Source (upstream guard suite):**
- `crates/services/control-api/src/routes/receipts.rs` -- `ReceiptStore`, `StoredReceipt`, pagination, chain queries, batch verification

**Target (Chio):**
- `crates/chio-kernel/src/receipt_query.rs` (new module) -- query types and trait
- `crates/chio-kernel/src/receipt_store.rs` -- extend existing `SqliteReceiptStore` with query methods

**What to port:**
- **Pagination:** offset/limit list queries with tenant-scoped isolation. The upstream `list()` and `chain()` methods (lines 138-187 of `receipts.rs`) are useful references for paging and ordering.
- **Payload-size validation:** `MAX_RECEIPTS_PER_TENANT`, `MAX_RECEIPT_PAYLOAD_BYTES`, and `validate_payload_size()`.
- **Verification pattern:** signature verification over canonical receipt JSON.

**Adaptations needed:**
- Replace the guard product's `StoredReceipt` with Chio's `ChioReceipt` (already defined in `chio_core::receipt`).
- Replace `hush_core::receipt::{SignedReceipt, VerificationResult, PublicKeySet}` with `chio_core::receipt::ChioReceipt` (which embeds `kernel_key` and `signature`).
- Replace Axum route handlers with a trait-based query API (`ReceiptQueryStore`) that can be consumed by chio-cli or any HTTP framework.
- Do not treat the guard product's `(tenant_id, policy_name)` chain index as a Chio lineage model. In Chio, tool-receipt queries should remain keyed by capability/tool/time/decision and child-request queries by session/request lineage; agent-level joins come later via the capability lineage index.
- Add SQLite FTS or LIKE queries for receipt search (tool name, decision, timestamp range).

**Effort:** ~1 week.

### 3.3 Rate Limit / Velocity Guard

**Source (upstream guard suite):**
- `crates/libs/the upstream guard suite/src/async_guards/rate_limit.rs` -- `TokenBucket` struct (68 lines)

**Target (Chio):**
- `crates/chio-guards/src/velocity.rs` (new guard module)
- Register in `crates/chio-guards/src/lib.rs`

**What to port:**
- `TokenBucket` struct -- token-bucket rate limiter with fractional rates (e.g., 4 requests per 60 seconds), burst capacity, and refill math.
- `refill_locked()` -- computes elapsed time and adds tokens up to capacity.

**What not to port directly:**
- `acquire()` -- async waiting semantics are useful for service-internal throttling, but Chio guards should normally deny immediately rather than block a kernel evaluation path.

**Adaptations needed:**
- Wrap `TokenBucket` in a `VelocityGuard` that implements `chio_kernel::Guard`.
- The guard's `evaluate()` method uses `std::sync::Mutex` (not `tokio::Mutex`) since `chio_kernel::Guard::evaluate()` is synchronous. Use `try_acquire()` that returns `Verdict::Deny` immediately when the bucket is empty rather than blocking.
- Add per-agent and per-grant rate tracking: e.g. `HashMap<(AgentId, grant_index), TokenBucket>` or an equivalent keyed structure. Per-agent buckets alone do not cover grant-scoped spend windows.
- Capture `GuardEvidence` with `tokens_remaining`, `rate_per_sec`, `burst`, and `wait_estimate_ms`.
- Add `VelocityConfig` with `rate_per_interval`, `interval_secs`, `burst`, and `per_agent: bool`.
- For monetary velocity limits, derive debits from Chio budget/cost metadata rather than the guard product token bucket alone.

**Effort:** ~4-5 days.

### 3.4 SIEM Exporters

**Source (upstream guard suite):**
- `crates/services/hushd/src/siem/exporters/splunk.rs` -- Splunk HEC exporter
- `crates/services/hushd/src/siem/exporters/elastic.rs` -- Elasticsearch bulk API exporter
- `crates/services/hushd/src/siem/exporters/datadog.rs` -- Datadog agent exporter
- `crates/services/hushd/src/siem/exporters/sumo_logic.rs` -- Sumo Logic HTTP source exporter
- `crates/services/hushd/src/siem/exporters/webhooks.rs` -- Generic webhook exporter
- `crates/services/hushd/src/siem/exporters/alerting.rs` -- Alert rule engine
- `crates/services/hushd/src/siem/exporter.rs` -- `Exporter` trait, `ExporterConfig`, `RetryConfig`, `RateLimitConfig`
- `crates/services/hushd/src/siem/manager.rs` -- `ExporterManager`, `ExporterHandle`, `ExporterHealth`
- `crates/services/hushd/src/siem/dlq.rs` -- `DeadLetterQueue`, `DeadLetterEntry`
- `crates/services/hushd/src/siem/ratelimit.rs` -- `ExportRateLimiter`
- `crates/services/hushd/src/siem/filter.rs` -- `EventFilter`
- `crates/services/hushd/src/siem/types.rs` -- `SecurityEvent`

**Target (Chio):**
- New `crates/chio-siem/` crate with the following modules:
  - `src/lib.rs` -- crate root, re-exports
  - `src/exporter.rs` -- `Exporter` trait, `ExporterConfig`, `RetryConfig`
  - `src/exporters/splunk.rs`, `elastic.rs`, `datadog.rs`, `sumo_logic.rs`, `webhooks.rs`, `alerting.rs`
  - `src/manager.rs` -- `ExporterManager` for fan-out to multiple exporters
  - `src/dlq.rs` -- dead letter queue
  - `src/ratelimit.rs` -- per-exporter rate limiting
  - `src/filter.rs` -- event filtering
  - `src/event.rs` -- `SecurityEvent` type, built from `ChioReceipt`

**Adaptations needed:**
- Replace `SecurityEvent` with a Chio-native `ReceiptEvent` that wraps `ChioReceipt` plus routing metadata (exporter name, schema format, tenant context).
- Replace `hush_core` types in the event payload with `chio_core` types.
- Support schema formats: ECS, CEF, OCSF, Native (matching the guard product's `SchemaFormat` enum).
- The `Exporter` trait's `export_batch()` method should accept `Vec<ReceiptEvent>` and return `ExportResult`.
- Batch processing: configurable `batch_size` (default 100) and `flush_interval_ms` (default 5000).
- Retry with exponential backoff: `max_retries`, `initial_backoff_ms`, `max_backoff_ms`, `backoff_multiplier`.
- Dead letter queue: filesystem-backed, size-capped, with structured `DeadLetterEntry` records.
- Make the crate optional behind a `siem` feature flag in chio-cli.

**Effort:** ~2 weeks.

### 3.5 Checkpoint Statement Pattern (Merkle Wiring)

**Source (upstream guard suite):**
- `crates/libs/spine/src/checkpoint.rs` -- `checkpoint_statement()`, `checkpoint_hash()`, `checkpoint_witness_message()`, `sign_checkpoint_statement()`, `verify_witness_signature()`

**Target (Chio):**
- `crates/chio-kernel/src/checkpoint.rs` (new module)
- Extend `crates/chio-kernel/src/receipt_store.rs` (`SqliteReceiptStore`)

**What to port:**
- `checkpoint_statement()` -- builds an unsigned checkpoint JSON object containing `log_id`, `checkpoint_seq`, `prev_checkpoint_hash`, `merkle_root`, `tree_size`, and `issued_at`.
- `checkpoint_hash()` -- computes SHA-256 over the canonical JSON of a checkpoint statement.
- `checkpoint_witness_message()` -- useful as a domain-separation pattern if Chio later adds witness co-signatures.
- `sign_checkpoint_statement()` / `verify_witness_signature()` -- useful reference for checkpoint signature envelopes.

**Adaptations needed:**
- Do not port Merkle tree construction itself. Chio already has `chio_core::merkle::MerkleTree`; this work is about checkpoint schema, hashing, persistence, and verification.
- Replace `hush_core::{canonicalize_json, sha256, Hash, Keypair, PublicKey, Signature}` with `chio_core::{canonicalize, sha256, Hash, Keypair, PublicKey, Signature}`.
- Change the domain separation tag from `"AegisNetCheckpointHashV1"` to `"ChioCheckpointHashV1"`.
- Change the schema identifier from `"aegis.spine.checkpoint_statement.v1"` to `"chio.checkpoint_statement.v1"`.
- Wire into `SqliteReceiptStore`: after every N receipts (configurable), build a `MerkleTree` from the batch, call `checkpoint_statement()`, sign it with the kernel's keypair, and store the checkpoint row.
- Add a `checkpoints` table to the SQLite schema: `(seq, checkpoint_seq, merkle_root, tree_size, checkpoint_hash, statement_json, signature_json)`.
- Expose `SqliteReceiptStore::latest_checkpoint()`, `SqliteReceiptStore::verify_checkpoint()`, and inclusion-proof query methods.
- Treat witness co-signatures as optional future work. Q2 only requires kernel-signed checkpoints so Merkle commitment becomes externally verifiable.

**Effort:** ~1 week.

### 3.6 Capability Lineage Index (Chio-Native Companion Work)

**Source (upstream guard suite):**
- No direct equivalent. The guard product does not currently provide the capability snapshot index Chio needs for agent-centric joins.

**Target (Chio):**
- `crates/chio-kernel/src/capability_index.rs` (new module) or equivalent persistence integrated with the authority/store layer

**Why it matters:**
- Agent-centric receipt queries, local reputation, and per-grant budget attribution all depend on a deterministic join from `receipt.capability_id` to capability subject, issuer, grants, and delegation metadata.

**What must be built natively:**
- Persist issued capability snapshots keyed by `capability_id`
- Record subject, issuer, grants, and delegation metadata needed for joins
- Provide a deterministic join path from receipts to the matched grant context
- Make the index queryable without replaying issuance logs

**Phase:** Q3 2026 native Chio work. This is a prerequisite for reputation and agent-level analytics, and it is not supplied by any direct upstream code port.

## 4. What the Guard Product Should Import From Chio

Once chio-core becomes the canonical source of truth, the guard product should add
`chio-core` and `chio-kernel` as workspace dependencies and replace its internal
implementations.

| Upstream module                | Replaced by                  | Notes                                                    |
|-----------------------------------|------------------------------|----------------------------------------------------------|
| `hush_core::signing`              | `chio_core::crypto`          | `Keypair`, `PublicKey`, `Signature`, `Signer` trait       |
| `hush_core::hashing`             | `chio_core::hashing`         | `sha256()`, `sha256_hex()`, `Hash` type                  |
| `hush_core::canonical`           | `chio_core::canonical`       | `canonicalize()`, `canonical_json_bytes()`                |
| `hush_core::merkle`              | `chio_core::merkle`          | `MerkleTree`, `MerkleProof`                              |
| `hush_core::receipt`             | `chio_core::receipt`         | `ChioReceipt` replaces `SignedReceipt`; `Decision` replaces `Verdict` |
| `hush_multi_agent::token`        | `chio_core::capability`      | `CapabilityToken` replaces `DelegationClaims`; `DelegationLink` replaces `chn` chains |
| `hush_multi_agent::revocation`   | `chio_kernel::revocation_store` | `SqliteRevocationStore` with the same bloom + SQLite pattern |

Additional imports the guard product should make:

- `chio_kernel::Guard` trait replaces the upstream `guards::Guard` trait. The upstream `GuardResult` maps to `chio_kernel::Verdict` + `chio_core::GuardEvidence`.
- `chio_kernel::CapabilityAuthority` replaces ad-hoc token issuance in `hush_multi_agent`.
- `chio_core::ToolManifest` replaces any internal tool discovery schemas.

The guard product should re-export selected Chio types under its own namespace for
backwards compatibility during the transition, while keeping adapters for
incompatible wire formats:

```rust
// In the upstream guard suite/crates/libs/hush-core/src/lib.rs (transitional)
pub use chio_core::crypto::{Keypair, PublicKey, Signature};
pub use chio_core::hashing::{sha256, sha256_hex, Hash};
pub use chio_core::canonical::canonicalize as canonicalize_json;
pub use chio_core::merkle::{MerkleTree, MerkleProof};
```

## 5. Migration Sequence

### Phase 1: Port shared code into Chio (Q2 2026)

Target: Chio gains the shared building blocks from Sections 3.1-3.5, with full
test coverage and no runtime dependency on the guard product. The capability lineage
index in Section 3.6 remains native Q3 work.

| Week | Deliverable                         | Owner | Validation                                         |
|------|-------------------------------------|-------|-----------------------------------------------------|
| 1-2  | DPoP proof-of-possession module     | --    | Unit tests; replay/nonce rejection tests; integration test with chio-cli |
| 2-3  | Receipt query API + SQLite indexes  | --    | Query tests; chio-cli `receipt list` subcommand      |
| 3    | Velocity guard in chio-guards       | --    | Guard pipeline tests; conformance test               |
| 4-5  | Checkpoint statement pattern        | --    | Checkpoint sign/verify tests; Merkle batch test      |
| 5-6  | Integration test: full receipt flow | --    | End-to-end: issue cap, invoke tool, sign receipt, verify checkpoint |

### Phase 2: Add chio-core as a workspace dependency in the guard product + SIEM (Q3 2026)

**SIEM exporter porting** (moved from Phase 1 to align with Strategic Roadmap Q3 placement):

| Week | Deliverable                         | Owner | Validation                                         |
|------|-------------------------------------|-------|-----------------------------------------------------|
| 1-2  | chio-siem crate (6 exporters)       | --    | Mock SIEM endpoint tests; DLQ round-trip test        |

**the guard product dependency restructure:**

Target: the upstream `Cargo.toml` workspace members include `chio-core` and
`chio-kernel` as path or git dependencies.

Steps:
1. Add `chio-core` and `chio-kernel` to the guard product workspace `[dependencies]`.
2. Create a `hush-core` compatibility shim with selective re-exports and
   adapter types. Do not use a blanket `pub use chio_core::*`; preserve the
   module structure while adapting incompatible types and wire formats.
3. Run the full upstream test suite. Fix type mismatches (e.g., `Verdict` vs
   `Decision`, `SignedReceipt` vs `ChioReceipt`).
4. Update the upstream CI pipeline to build both workspaces.

Risk mitigation: use a feature flag `chio-backend` (default off) during this
phase. The upstream CI runs tests with both `chio-backend` on and off.

### Phase 3: Replace hush-core internals with chio-core re-exports (Q3-Q4 2026)

Target: `hush-core` becomes a thin facade over chio-core. No duplicated crypto
code remains.

Steps:
1. Remove `hush_core::signing` implementation; replace with `pub use chio_core::crypto::*`.
2. Remove `hush_core::hashing` implementation; replace with `pub use chio_core::hashing::*`.
3. Remove `hush_core::canonical` implementation; replace with `pub use chio_core::canonical::*`.
4. Remove `hush_core::merkle` implementation; replace with `pub use chio_core::merkle::*`.
5. Keep `hush_core::tpm` (TPM-sealed key support is upstream-specific).
6. Keep `hush_core::duration` (human duration parsing is application-level).
7. Remove `hush_core::receipt` implementation; replace with adapter types that
   convert between `ChioReceipt` and the upstream `SignedReceipt` wire format.

### Phase 4: Guard product fully depends on chio-core + chio-kernel (Q4 2026)

Target: `hush-core` is deprecated as the source of shared primitives. All
The guard product crates import directly from `chio_core` and `chio_kernel` for
shared protocol types. Only upstream-specific helpers or compatibility
adapters remain in `hush-core` (or a successor compat crate).

Steps:
1. Replace all `use hush_core::` with `use chio_core::` across the upstream
   workspace (`hushd`, `control-api`, `guard-brokerd`, all bridges).
2. Replace `hush_multi_agent::token::DelegationClaims` with
   `chio_core::capability::CapabilityToken`. Write a migration for any
   persisted delegation tokens.
3. Replace the upstream `Guard` trait with `chio_kernel::Guard`. Adapt
   the async guard runtime to wrap synchronous Chio guards with
   `tokio::task::spawn_blocking`.
4. Move the remaining upstream-specific `hush-core` modules (`tpm`,
   duration parsing, wire-format adapters) into a small compatibility crate or
   leave them as the only surviving `hush-core` modules.
5. Delete `hush-multi-agent` crate (delegation logic now in chio-core/chio-kernel).
6. Update upstream documentation and SDK references.

## 6. What Stays in the Guard Product Only

The following components are application-layer concerns that do not belong in a
protocol specification. They remain exclusively in the guard product.

### Application-Layer Guards

| Guard                          | Source file                                                        | Why it stays                                      |
|--------------------------------|--------------------------------------------------------------------|---------------------------------------------------|
| `JailbreakGuard`               | the upstream `guards/jailbreak.rs`                 | ML-based detection, model-specific heuristics      |
| `PromptInjectionGuard`         | the upstream `guards/prompt_injection.rs`          | NLP pipeline, vendor-specific scoring              |
| `ComputerUseGuard`             | the upstream `guards/computer_use.rs`              | CUA-specific policy (screenshot, click, type)      |
| `InputInjectionCapabilityGuard`| the upstream `guards/input_injection_capability.rs` | Desktop input event filtering                      |
| `RemoteDesktopSideChannelGuard`| the upstream `guards/remote_desktop_side_channel.rs`| RDP/VNC side-channel detection                     |
| `SpiderSense`                  | the upstream `spider_sense.rs`                     | Behavioral anomaly scoring                         |
| `CustomGuardRegistry`          | the upstream `guards/custom.rs`                    | User-defined guard loading via WASM/plugin         |

### Async Guard Runtime

| Component          | Source file                                                    | Why it stays                          |
|--------------------|----------------------------------------------------------------|---------------------------------------|
| `AsyncGuardRuntime`| the upstream `async_guards/runtime.rs`         | Tokio-specific orchestration          |
| Circuit breakers   | the upstream `async_guards/circuit_breaker.rs` | Production resilience pattern         |
| Guard caching      | the upstream `async_guards/cache.rs`           | Result memoization                    |
| Guard retry        | the upstream `async_guards/retry.rs`           | Retry with backoff for external calls |
| Threat intel feed  | the upstream `async_guards/threat_intel/` modules      | External threat feed integration      |

### Fleet Management and Control Plane

- Control API (`crates/services/control-api/`) -- tenant management, agent enrollment, policy CRUD, delegation graph visualization, compliance checks, billing, hunt queries, response actions, case management
- Posture commands (`crates/libs/the upstream guard suite/src/posture.rs`) -- agent health posture, compliance scoring
- RBAC (`crates/services/hushd/src/rbac/`) -- role-based access control for the control plane itself
- Policy engine cache (`crates/services/hushd/src/policy_engine_cache.rs`)
- Certification webhooks (`crates/services/hushd/src/certification_webhooks.rs`)

### Telemetry Bridges

| Bridge                  | Source directory                              |
|-------------------------|-----------------------------------------------|
| Tetragon bridge         | `crates/bridges/tetragon-bridge/`             |
| Hubble bridge           | `crates/bridges/hubble-bridge/`               |
| auditd bridge           | `crates/bridges/auditd-bridge/`               |
| k8s-audit bridge        | `crates/bridges/k8s-audit-bridge/`            |
| Darwin telemetry bridge | `crates/bridges/darwin-telemetry-bridge/`      |

### Other Product-Specific Components

- Desktop/agent apps (`apps/`)
- WASM guard runtime (`crates/libs/hush-wasm/`)
- Guard SDK and macros (`crates/libs/the upstream guard suite-guard-sdk/`, `crates/libs/the upstream guard suite-guard-sdk-macros/`)
- OCSF event schema (`crates/libs/the upstream guard suite-ocsf/`)
- Policy event types (`crates/libs/the upstream guard suite-policy-event/`)
- Spine NATS transport (`crates/libs/spine/src/nats_transport.rs`)
- Spine marketplace facts (`crates/libs/spine/src/marketplace_spine.rs`, `marketplace_facts.rs`)
- Threat intelligence correlations (`crates/libs/hunt-correlate/`, `hunt-query/`, `hunt-scan/`)
- Registry service (`crates/services/the upstream guard suite-registry/`)
- EAS anchor service (`crates/services/eas-anchor/`)
- Logos Z3 solver integration (`crates/libs/logos-z3/`)
- Output sanitizer (`crates/libs/the upstream guard suite/src/output_sanitizer.rs`)
- Watermarking (`crates/libs/the upstream guard suite/src/watermarking.rs`)
- Marketplace feed (`crates/libs/the upstream guard suite/src/marketplace_feed.rs`)
- Instruction hierarchy (`crates/libs/the upstream guard suite/src/instruction_hierarchy.rs`)

## 7. Type Mapping Reference

Quick reference for developers porting code between the two projects.

| Upstream type                          | Chio equivalent                              |
|-------------------------------------------|----------------------------------------------|
| `hush_core::Keypair`                      | `chio_core::crypto::Keypair`                 |
| `hush_core::PublicKey`                    | `chio_core::crypto::PublicKey`               |
| `hush_core::Signature`                    | `chio_core::crypto::Signature`               |
| `hush_core::Hash`                         | `chio_core::hashing::Hash`                   |
| `hush_core::sha256()`                     | `chio_core::hashing::sha256()`               |
| `hush_core::sha256_hex()`                | `chio_core::hashing::sha256_hex()`           |
| `hush_core::canonicalize_json()`         | `chio_core::canonical::canonicalize()`       |
| `hush_core::MerkleTree`                  | `chio_core::merkle::MerkleTree`              |
| `hush_core::MerkleProof`                 | `chio_core::merkle::MerkleProof`             |
| `hush_core::SignedReceipt`               | `chio_core::receipt::ChioReceipt`            |
| `hush_core::Verdict`                     | `chio_core::receipt::Decision`               |
| `hush_core::Receipt`                     | `chio_core::receipt::ChioReceiptBody`        |
| `hush_multi_agent::DelegationClaims`     | `chio_core::capability::CapabilityToken`     |
| `hush_multi_agent::AgentCapability`      | `chio_core::capability::ChioScope`           |
| `hush_multi_agent::AgentId`             | `chio_core::AgentId` (`String`)              |
| the upstream `guards::Guard` (trait)     | `chio_kernel::Guard` (trait)                 |
| the upstream `guards::GuardResult`       | `chio_kernel::Verdict` + `chio_core::GuardEvidence` |
| the upstream `guards::GuardAction`       | `chio_kernel::GuardContext`                  |
| the upstream `guards::GuardContext`      | `chio_kernel::GuardContext` (different shape) |
| the upstream `guards::Severity`          | No direct equivalent; map to `GuardEvidence::details` |

## 8. Risk Register

| Risk                                  | Impact | Mitigation                                                        |
|---------------------------------------|--------|-------------------------------------------------------------------|
| Type divergence during parallel dev   | High   | Freeze chio-core public API before Phase 2; semver guarantees     |
| upstream test suite regression     | High   | Feature flag (`chio-backend`) with dual CI runs                   |
| Canonical JSON output differs         | Critical | Property-based fuzz tests comparing `hush_core::canonicalize_json` vs `chio_core::canonicalize` output on 10k random JSON values |
| Merkle tree compatibility             | Critical | Cross-validate tree roots: same leaves must produce same root in both implementations before deleting hush-core version |
| Ed25519 signature compatibility       | Critical | Sign with hush-core, verify with chio-core (and vice versa) in CI |
| Performance regression in guard eval  | Medium | Benchmark `Guard::evaluate()` latency before and after migration  |
| DPoP replay protection missing from source port | High   | Treat broker DPoP code as verifier source material only; add a Chio-specific proof message and nonce replay store before claiming completion |
| Capability lineage index assumed to come from the guard product | High   | Build the capability snapshot/index natively in Chio; do not couple agent analytics or reputation work to the guard product control-api indexes |
| SIEM exporter API surface too large   | Medium | Put chio-siem behind a feature flag; keep chio-core/chio-kernel lean |
| Breaking changes in chio-core affect guard product releases | Medium | Pin chio-core version in the guard product; bump deliberately          |
