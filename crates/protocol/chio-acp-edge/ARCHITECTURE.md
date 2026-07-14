# chio-acp-edge architecture

## Overview

`chio-acp-edge` is an untrusted edge component: it speaks ACP JSON-RPC to an
external editor or IDE client on one side and drives the Chio kernel through
`chio-cross-protocol`'s `CrossProtocolOrchestrator` on the other, so the
kernel remains the sole point of capability and guard evaluation. It is a
projector, not a proxy: it turns Chio's own `ToolManifest`s into an outward
ACP capability surface, the reverse of `chio-acp-proxy`, which sits in front
of a third-party ACP agent and enforces Chio checks on that agent's own
calls. The crate root is assembled from focused source fragments merged with
`include!` into one module scope (`lib.rs` declares the sequence); item
visibility resolves as if the fragments were written inline.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate doc, imports, and the `include!` sequence. Declares the public `metrics` module and the feature-gated `fuzz` module. |
| `src/error.rs` | `AcpEdgeError` and receipt-write error accounting for bridge failures. |
| `src/config.rs` | `AcpEdgeConfig`: permission default and fallback ACP category. |
| `src/types.rs` | ACP wire types (`AcpCapability`, `AcpCategory`, `PermissionRequest`/`PermissionDecision`, `AcpInvocationResult`, `AcpInvocationTask`/`AcpTaskStatus`, `AcpJsonRpcResponse`) and `AcpKernelExecutionContext`. |
| `src/bridge.rs` | `AcpCapabilityBridge` (the `CapabilityBridge` impl), ACP category inference, `BridgeFidelity` evaluation, the authoritative target registry, and orchestrated-request execution. |
| `src/conversion.rs` | Kernel-output-to-`Value` projection and every `chio` metadata envelope (authoritative, compatibility, permission-preview, pending/cancelled task). |
| `src/edge.rs` | `ChioAcpEdge`: capability publication, permission evaluation, invocation, and deferred-task lifecycle. `ChioAcpEdgeCompatibility`, its passthrough wrapper. |
| `src/jsonrpc.rs` | JSON-RPC envelope parsing and parameter extraction shared by the authoritative and passthrough dispatchers. |
| `src/metrics.rs` | This crate's `ReceiptWriteCounters` instance and Prometheus rendering, built on `chio-edge-metrics`. |
| `src/fuzz.rs` | `fuzz` feature only: a deterministic kernel/edge/capability fixture plus `fuzz_acp_envelope_decode`, the libFuzzer entry point. |
| `src/tests/all.rs`, `src/tests/nonce_preflight.rs` | Unit tests, merged into the crate root under `#[cfg(test)]` (`include!` and `#[path]` respectively). |

## Capability construction

`ChioAcpEdge::new` runs once per manifest set:

1. Validate every `ToolManifest` with `chio_manifest::validate_manifest`; any
   failure rejects construction.
2. For each tool, resolve its target protocol against the authoritative
   registry (an unsupported `x-chio-target-protocol` value also rejects
   construction), infer its `AcpCategory`, and evaluate `BridgeFidelity`.
3. A tool name reachable through more than one distinct `server_id` is
   withheld from discovery: its fidelity becomes `Unsupported` with a
   collision reason, and any capability or binding already recorded for that
   name is removed. Re-declaring the identical `server_id`/tool pair across
   manifests is not a collision.
4. Only tools whose fidelity is not `Unsupported` get an `AcpCapability` and
   a `CapabilityBinding`; the rest stay queryable through `bridge_fidelity`
   but are absent from `capabilities()` and cannot be invoked.

## Request lifecycle

- **Permission preview** (`evaluate_permission[_with_kernel]`,
  `session/request_permission`): validates the execution context and the
  capability's signature, expiry, and subject, checks the request against the
  capability scope, and consults the kernel's stateless DPoP verifier
  (`verify_dpop_for_permission_preview`) when the matched grant requires
  sender binding. Preview never touches the kernel's DPoP nonce store.
- **Blocking invoke** (`invoke`, `invoke_with_mcp_target`, `tool/invoke`):
  builds a `CrossProtocolExecutionRequest` from the capability binding and
  execution context, runs it through `CrossProtocolOrchestrator::execute`
  against `AcpCapabilityBridge`, and converts the resulting
  `OrchestratedToolCall` into an `AcpInvocationResult` carrying kernel receipt
  metadata, on both allow and deny.
- **Deferred stream** (`tool/stream` then `tool/resume`, optionally
  `tool/cancel`): `tool/stream` allocates a `DeferredAcpTask` without
  executing it. `tool/resume` executes the stored request exactly once and
  serves the cached terminal result on every later resume. `tool/cancel`
  marks a still-working task cancelled without ever dispatching it, and is
  idempotent once cancelled. Every lifecycle call is owner-checked against
  `AcpKernelExecutionContext.agent_id`.
- **Compatibility passthrough** (`compatibility()`,
  `cfg(any(test, feature = "compatibility-surface"))`): calls a raw
  `ToolServerConnection` directly through
  `chio_cross_protocol::sync_bridge_shared::block_on_tool_server_invoke`,
  bypassing the kernel. Metadata always marks these responses
  `compatibilityOnly: true` / `authoritative: false`.

## Invariants and failure modes

- Manifest validation is the single gate before ACP discovery; an invalid
  manifest fails `ChioAcpEdge::new` outright.
- `params.capabilityId`, `params.taskId`, and
  `AcpKernelExecutionContext.agent_id` are rejected if missing, non-string,
  empty, whitespace-padded, or containing control characters, before any
  lookup, binding, or kernel dispatch runs; none are trimmed or rewritten on
  the caller's behalf.
- A JSON-RPC request for a known method with non-object `params` fails
  `-32602` before dispatch; an unknown method returns `-32601`.
- Every deferred kernel request executes at most once. The
  `MAX_DEFERRED_ACP_TASKS` (1024) capacity gate counts only tasks still in
  `Working` status after TTL pruning (`DEFERRED_ACP_TASK_TTL_MILLIS`, 5
  minutes); completed, failed, and cancelled tasks are retained but exempt
  from the cap, so terminal-task retention is bounded by the TTL sweep, not
  by count.
- Permission preview and kernel invoke agree on DPoP policy (TTL, skew, store
  presence) without preview consuming a nonce invoke will later spend.
- Authoritative-path metadata is always `authoritative: true`; compatibility-
  path metadata is always `authoritative: false`. The two are never conflated
  in one response.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

`chio-cross-protocol` supplies the `CapabilityBridge` trait,
`CrossProtocolOrchestrator`, `TargetProtocolRegistry`, `BridgeFidelity`,
`DiscoveryProtocol`, the runtime-lifecycle contract, and the
`sync_bridge_shared` passthrough helper shared with `chio-a2a-edge`.
`chio-kernel` is the dispatch and DPoP-preview authority (`ChioKernel`,
`ToolServerConnection`, `dpop`). `chio-manifest` supplies
`ToolDefinition`/`ToolManifest`/`validate_manifest`. `chio-mcp-edge` supplies
`McpTargetExecutor`, registered alongside `OpenAiTargetExecutor` as the two
non-native target executors. `chio-edge-metrics` backs the receipt-write
counters. The `chio-core` dependency is aliased to `chio-core-types`
(`chio_core::capability::*`, `session::OperationTerminalState`).
`async-trait` is a direct dependency but is exercised only by this crate's own
test-fixture `ToolServerConnection` mocks.

## Extension points

`AcpEdgeConfig` is the only consumer-supplied configuration:
`require_permission` (force permission gating even for side-effect-free
tools) and `default_category` (fallback `AcpCategory` for tools
`infer_acp_category` cannot classify by name).
