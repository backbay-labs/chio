# chio-kernel

`chio-kernel` is the Chio runtime kernel: the trusted computing base (TCB) of
the protocol. It sits between the untrusted agent and sandboxed tool servers
as the sole trusted mediator, validating capability tokens, running a guard
pipeline, dispatching tool calls, and signing a receipt for every decision.
The agent never learns the kernel's PID, address, or signing key.

Use `chio-kernel` for Rust-level embedding of Chio enforcement. For the
supported operator path, start with `chio-cli`.

## Responsibilities

- Validate capability tokens: signature, time bounds, revocation (including
  delegation-chain ancestors), delegated-scope lineage, grant matching, and
  DPoP proof-of-possession.
- Evaluate the registered `Guard` pipeline before forwarding a call; any guard
  deny or error fails the call closed.
- Admit governed transactions: HITL approval tokens, runtime-attestation
  tier, metered billing, call-chain proofs, autonomy bonds.
- Dispatch validated calls to registered `ToolServerConnection` tool servers
  under a per-server wall-clock budget.
- Sign and durably persist a receipt for every outcome (allow, deny,
  cancelled, incomplete), recomputing the content hash before signing
  (WYSIWYS).
- Build and verify Merkle checkpoints over the receipt log, including
  continuity and equivocation checks.
- Track sessions, in-flight and nested (sampling/elicitation) requests, and
  hold-based monetary/invocation budget accounting.
- Enforce the emergency-stop kill switch and shed load under a configurable
  RSS soft ceiling.

## Public API

Primary entrypoint:

- `ChioKernel` / `KernelConfig` construct and configure the kernel.
  `ChioKernel::evaluate_tool_call` (async) is the core mediation call;
  `evaluate_plan` previews a multi-step plan without mutating budget or
  receipt state.

Traits a host implements:

| Trait | Role |
|---|---|
| `Guard` | pre-dispatch policy check |
| `ToolServerConnection` | dispatch target |
| `ReceiptStore`, `BudgetStore`, `RevocationStore`, `CapabilityAuthority` | durable persistence and trust roots |
| `PostInvocationHook`, `RuntimeAdmissionHook` | post-dispatch and pre-dispatch product-specific gates |
| `PaymentAdapter` | payment-rail authorization (`X402PaymentAdapter`, `AcpPaymentAdapter` ship as references) |
| `ApprovalStore`, `ApprovalChannel` | HITL approval persistence and delivery (`WebhookChannel`, `RecordingChannel` ship as references) |
| `MemoryProvenanceStore`, `FederationArtifactStore`, `ExecutionNonceStore` | optional durable backing for memory provenance, federation artifacts, and nonce replay |
| `ToolEvaluator` | replace the four-phase evaluation pipeline itself (default `BlockingToolEvaluator` bridges to the sync path) |

Standalone surfaces:

- `checkpoint` - Merkle checkpoints over the receipt log (`build_checkpoint`,
  `verify_checkpoint_continuity`, `ReceiptInclusionProof`).
- `dpop` - DPoP proof-of-possession verification.
- `execution_nonce` - single-use nonces closing the TOCTOU gap between an
  allow decision and dispatch.
- `evidence_export` - signed evidence bundles for external audit.
- `compliance_score`, `compliance_certificate` - weighted compliance scoring
  and signed compliance certificates.
- `receipt_query`, `receipt_analytics`, `operator_report` -
  read-scope-bounded receipt queries and reporting.
- `settlement_observer` - post-signing settlement hook invocation.

Also re-exports the economic and governance artifact types from
`chio_core::{credit, governance, listing, market, open_market, underwriting}`
at the crate root, so an embedder does not need a direct `chio-core`
dependency for governed-transaction workflows.

## Feature flags

| Flag | Effect |
|------|--------|
| `delegation` (default) | Consults the installed recursive-delegation `RevocationView` snapshot on every delegated dispatch, denying if any chain link is revoked. Also enables `chio-core-types/delegation`. |
| `pq` | Enables the hybrid signing path: constructs a PQ (ML-DSA-65) `HybridBackend` from an operator-supplied seed, gated by the boot-time self-quote check in `boot.rs`. Enables `chio-core-types/pq` and `chio-core/pq`. |
| `otel` | Pulls in `opentelemetry-semantic-conventions` for the GenAI tool-call span attribute contract in `otel.rs`. |
| `dhat-heap` | Enables heap-profiling instrumentation for the `dispatch_allow_dhat` bench. |
| `tokio-console-smoke` | Enables `tokio/tracing` for the `tokio_console_smoke` integration test. |

## Testing

`cargo test -p chio-kernel`

- Hybrid/PQ tests (`hybrid_receipt_sign`, `compliance_certificate_hybrid`,
  `pq_key_load_after_self_quote`, `canonical_bytes_hybrid`) require
  `--features pq`.
- `tokio_console_smoke` requires `--features tokio-console-smoke`.
- `cargo bench -p chio-kernel` runs the criterion benchmark suite (capability
  verification, guard pipeline, dispatch, receipt signing/append);
  `dispatch_allow_dhat` requires the `dhat-heap` feature.
- Dev-dependencies also cover a property-based replay-invariance suite
  (`tests/replay_proptest.rs`) and loom-based concurrency checks.

## See also

- `chio-kernel-core` - portable verifier primitives (`RevocationView`, budget
  registry, receipt-signing handle) this crate builds on.
- `chio-store-sqlite` - durable `ReceiptStore` / `BudgetStore` backend for
  production deployments.
- `chio-cli` - the supported operator entrypoint.
- `chio-guards`, `chio-wasm-guards`, `chio-external-guards`,
  `chio-data-guards` - `Guard` implementations that plug into this kernel.
- `chio-mcp-edge`, `chio-a2a-edge`, `chio-acp-edge` and other protocol edge
  crates - implement `ToolServerConnection` to bring an external protocol
  under kernel mediation.
