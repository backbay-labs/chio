# chio-kernel architecture

## Overview

`chio-kernel` is the trusted computing base (TCB) of the Chio protocol: the
sole trusted mediator between the untrusted agent and sandboxed tool servers.
Every tool call passes through capability validation, a guard pipeline, and
receipt signing; the agent never learns the kernel's PID, address, or signing
key. The crate is trait-heavy by design: storage (`ReceiptStore`,
`BudgetStore`, `RevocationStore`, `CapabilityAuthority`), transport
(`ToolServerConnection`), and policy (`Guard`, `PostInvocationHook`,
`RuntimeAdmissionHook`) are consumer-supplied implementations of kernel-owned
traits, so the kernel enforces the protocol without committing to a storage
engine or a specific tool-hosting model. Portable verifier primitives
(revocation views, budget registry, receipt-signing handles) live one layer
down in `chio-kernel-core`; this crate is the hosted enforcement layer built
on top of them.

## Module map

### Kernel core (`src/kernel/`)

| Path | Responsibility |
|------|----------------|
| `kernel/kernel_struct.rs` | `ChioKernel` struct, `KernelConfig`, `MemoryBudgetConfig`, `HotPathDeadlineConfig`, the RSS soft-ceiling sampler. |
| `kernel/construction.rs` | Builder/setter surface, store attachment, emergency stop, the TCB lock-poison gate. |
| `kernel/validation.rs` | Capability issuance/revocation, delegation-chain lineage validation, budget charge/reconcile helpers. |
| `kernel/governed_validation.rs` | Governed-transaction admission: approval tokens, runtime attestation, metered billing, call-chain proofs, autonomy bonds. |
| `kernel/delegation.rs` (feature `delegation`) | Recursive-delegation `RevocationView` consultation. |
| `kernel/dispatch.rs` | Guard-pipeline execution, runtime admission hook, tool dispatch, deadline enforcement. |
| `kernel/evaluator.rs` | `ToolEvaluator` trait and the default `BlockingToolEvaluator`. |
| `kernel/evaluation/*.rs` | Async, sync-bridge, and nested-flow tool-call and plan evaluation pipelines. |
| `kernel/responses/*.rs` | Allow/deny/terminal response construction, receipt signing and persistence, the post-invocation pipeline. |
| `kernel/session_ops.rs` | Session-scoped operation dispatch, filesystem-root enforcement. |
| `kernel/kernel_scopes.rs` | Request-scoped tenant and federation-admission tagging. |
| `kernel/kernel_drop_guard.rs` | Cancellation/drop unwind for in-flight evaluations. |
| `kernel/signing_task.rs` | Off-critical-path mpsc-backed receipt signing. |
| `kernel/settlement_observer.rs` | Post-signing settlement hook invocation. |
| `kernel/receipt_writer_watchdog.rs` | Receipt-writer liveness publication for the pre-dispatch readiness gate. |
| `kernel/error.rs` | `KernelError`, `StructuredErrorReport`, `HotPathStage`. |

### Capability and trust

| Path | Responsibility |
|------|----------------|
| `authority.rs` | `CapabilityAuthority` trait, `LocalCapabilityAuthority`. |
| `capability_lineage.rs` | Capability-issuance snapshot schema for delegation-chain audit. |
| `custody.rs` | `PasskeyCapabilityVerifier`, hardware-backed capability verification. |
| `dpop.rs` | DPoP proof-of-possession verification. |
| `execution_nonce.rs` | Single-use execution nonces closing the evaluate-to-dispatch TOCTOU gap. |
| `weights_binding.rs` | Binds a provider's loaded model weights to a signed `ModelCard` and requested scope. |
| `revocation_runtime.rs` / `revocation_store.rs` | `RevocationStore` trait / error and record types. |
| `boot.rs` | Self-quote-gated hybrid/PQ signing key load. |

### Guard, approval, and compliance

| Path | Responsibility |
|------|----------------|
| `approval.rs` / `approval_channels.rs` | HITL approval model, `ApprovalGuard`, webhook/recording delivery channels. |
| `post_invocation.rs` | Post-dispatch hook pipeline (allow/block/redact/escalate). |
| `compliance_score.rs` / `compliance_certificate.rs` | Weighted compliance scoring, signed compliance certificates. |

### Receipts and evidence

| Path | Responsibility |
|------|----------------|
| `receipt_store.rs` | `ReceiptStore` durable persistence contract, retention, writer liveness. |
| `receipt_support/*.rs` | Receipt body assembly, crypto floor, WYSIWYS signing. |
| `checkpoint.rs` | Merkle checkpoints over the receipt log. |
| `receipt_query.rs` / `receipt_analytics.rs` | Read-scope-bounded receipt queries and aggregate analytics. |
| `evidence_export.rs` | Signed evidence bundles for external audit. |
| `memory_provenance.rs` | Hash-chained agent-memory action provenance log. |
| `cost_attribution.rs` | Delegation-chain cost attribution reports. |
| `operator_report/*.rs` | Operator-facing reporting: budget utilization, settlement/metered-billing reconciliation, behavioral anomaly scoring, OAuth authorization context. |

### Runtime, transport, and economics

| Path | Responsibility |
|------|----------------|
| `runtime.rs` | `ToolServerConnection` dispatch contract, streaming types, `Verdict`. |
| `transport.rs` | Length-prefixed canonical-JSON framing between kernel and agent. |
| `session.rs` | Session lifecycle, in-flight/subscription/terminal registries. |
| `budget_store.rs`, `budget_store/in_memory.rs` | `BudgetStore` trait, hold-based accounting, `InMemoryBudgetStore`. |
| `payment.rs` | `PaymentAdapter`, `X402PaymentAdapter` and `AcpPaymentAdapter` references. |
| `federation_artifact_store.rs` | Bilateral co-sign artifact cache (`DualSignedReceipt`, `DsseEnvelope`). |
| `request_matching.rs` | Capability-scope grant matching, DPoP-required determination. |
| `provider_verdict.rs` | Conversion shim to/from the `chio-tool-call-fabric` provider vocabulary. |
| `otel.rs` (feature `otel`) | GenAI OTel span attribute contract. |
| `observability/*.rs` | Prometheus metrics endpoint. |

## Request lifecycle

Ordered steps of one `ChioKernel::evaluate_tool_call`:

1. Emergency-stop and RSS-shed check (a single atomic read, before any other
   work); a tripped switch denies immediately.
2. Receipt-version negotiation: a trust-boundary admission check that fails
   closed through a dedicated deny path.
3. Capability validation: signature, time bounds, subject match, revocation
   of the capability and every delegation-chain ancestor, delegation-chain
   lineage re-derivation against stored snapshots.
4. Grant matching against the capability's scope, DPoP proof verification
   when the matched grant requires it.
5. Governed-transaction admission when the grant carries governed
   constraints: approval token, runtime-attestation tier, metered billing,
   call-chain proof, autonomy bond.
6. Guard pipeline: every registered `Guard::evaluate` runs sequentially and
   fails closed on deny or error, optionally offloaded under a wall-clock
   budget so a hung guard cannot pin an async worker.
7. Optional `RuntimeAdmissionHook` for product-specific gates.
8. Budget admission: invocation and monetary holds through `BudgetStore`,
   optional `PaymentAdapter` authorization.
9. Execution-nonce mint, closing the TOCTOU gap before handoff to the tool
   server.
10. Dispatch to the registered `ToolServerConnection` under a per-server
    budget; streamed output is bounded by byte and chunk caps as it
    accumulates.
11. Post-invocation hook pipeline over the tool output
    (allow/block/redact/escalate).
12. Receipt signing (WYSIWYS: the content hash is recomputed from the
    canonical preimage and signing is refused on mismatch) and durable
    append to the `ReceiptStore`, the in-process mirror log, optional
    federation co-sign, and settlement-hook invocation.

Every path, allow, deny, cancelled, or incomplete, converges on step 12:
exactly one signed, persisted receipt per call. Nested tool calls issued from
inside a running call (sampling, elicitation) run the same
capability-through-guard gate under
`kernel/evaluation/nested_flow_evaluation.rs` before their own child receipt
is recorded.

## Invariants and failure modes

- Fail-closed throughout: guard errors, hook errors, a poisoned TCB lock (for
  example `budget_registry`), a missing or unhealthy receipt-store writer,
  RSS overload, and hot-path deadline expiry all deny rather than proceed.
- WYSIWYS: the signing boundary always recomputes the content hash from the
  canonical preimage and refuses to sign on mismatch.
- The emergency stop denies every evaluate call before capability or guard
  checks run.
- Every decision produces exactly one signed, durably persisted receipt; a
  `ReceiptStore` append failure fails the call closed rather than returning
  an unpersisted allow.
- Delegated capabilities re-derive full lineage against stored snapshots and,
  under the default `delegation` feature, consult the recursive-delegation
  `RevocationView` in addition to the unconditional per-row `RevocationStore`
  lookup.
- Budget holds are single-use: an authorize is closed by exactly one of
  reverse, release, or reconcile; mutations are idempotent by event id,
  fenced by a monotonic lease epoch, and use checked arithmetic.
- Checkpoints are strictly sequential and hash-chained; gapped or
  equivocating checkpoints are rejected, not merged.
- Tenant and read-scope for every report and receipt query come only from
  the authenticated session, never from a caller-supplied request field.
- `allow_ephemeral_receipt_log` and `allow_ephemeral_revocation_store`
  default to `false`; without durable stores, call-chain proof resolution
  and revocation durability across a restart do not hold.

## Dependencies

- `chio-kernel-core` - portable verifier primitives this crate calls into:
  `RevocationView`, `InMemoryBudgetRegistry`, the receipt-signing handle.
- `chio-core` / `chio-core-types` - protocol types (capability, receipt,
  session, crypto); `chio-core` re-exports `chio-core-types`.
- `chio-supervisor` - `HealthFlag` backing the TCB lock-poison gate.
- `chio-bounded` - `Ring`, `BoundedMap`, `SizeGauge` bounded structures for
  receipt mirrors and federation caches.
- `chio-federation` - bilateral co-signing, DSSE envelopes, treaty and peer
  trust establishment.
- `chio-settle` - `SettlementHook` invoked strictly post-signing.
- `chio-custody-hw` (`passkey`, `sqlite-store` features re-enabled over the
  workspace default) - hardware-backed capability verification.
- `chio-weights` - model-weights identity for `weights_binding`.
- `chio-tool-call-fabric` - provider-agnostic verdict vocabulary consumed by
  `provider_verdict`.
- `chio-credit`, `chio-underwriting` - economic and trust artifact types
  re-exported at the crate root.
- `chio-appraisal` - verified runtime-attestation records consumed by
  governed-transaction admission.
- `chio-metrics-spec` - Prometheus metric family definitions rendered by
  `observability/metrics.rs`.
- `chio-log-redact` - the `redacted!` macro for log fields that must not leak
  request content.
- `chio-link` (path dependency, `default-features = false`) - price-oracle
  conversion only; the workspace default `web3` feature (alloy on-chain
  transport) is left off.
- `tokio` - async runtime; the crate also supports a synchronous bridge
  (`block_in_place`, or a direct `futures::executor::block_on` outside any
  runtime) for non-async hosts.

## Extension points

Consumers extend the kernel by implementing its traits rather than
subclassing:

- `Guard` - pre-dispatch policy check (implemented by `chio-guards`,
  `chio-wasm-guards`, `chio-external-guards`, `chio-data-guards`).
- `ToolServerConnection` - dispatch target (implemented by protocol edge
  crates: `chio-mcp-edge`, `chio-a2a-edge`, `chio-acp-edge`, and others).
- `ReceiptStore`, `BudgetStore`, `RevocationStore`, `CapabilityAuthority`,
  `ExecutionNonceStore`, `MemoryProvenanceStore`, `FederationArtifactStore` -
  durable persistence, implemented by `chio-store-sqlite` and similar
  crates.
- `PostInvocationHook`, `RuntimeAdmissionHook`, `PaymentAdapter`,
  `ApprovalChannel` / `ApprovalStore` - product-specific policy, runtime,
  payment, and HITL integration points.
- `ToolEvaluator` - replace the four-phase evaluation pipeline itself.
