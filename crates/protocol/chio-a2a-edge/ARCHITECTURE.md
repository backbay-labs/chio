# chio-a2a-edge architecture

## Overview

`chio-a2a-edge` speaks A2A JSON-RPC to an external caller and routes every
authoritative call through `chio-kernel`'s orchestration path, which
evaluates and receipt-signs it. It is the reverse of `chio-a2a-adapter`
(speaks A2A to a remote upstream agent), mirroring the `chio-mcp-adapter`
(wraps an upstream MCP server) / `chio-mcp-edge` (MCP hosting runtime) split.
The crate has no HTTP server dependency: it builds JSON-RPC responses and
Agent Card JSON for a caller to serve over whatever transport it chooses.
`lib.rs` merges most of the crate into one crate-root scope via `include!`
rather than nested `pub mod` declarations; `metrics` and `otel` are ordinary
submodules instead.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate-root facade. Composes `error`, `config`, `types`, `bridge`, `conversion`, `edge`, `jsonrpc`, and the test modules into one scope via `include!`; declares `metrics` and (feature-gated) `otel` as real submodules. |
| `src/error.rs` | `A2aEdgeError` and the receipt-write error-accounting helpers called from bridge orchestration. |
| `src/config.rs` | `A2aEdgeConfig` and its construction-time Agent Card field validation. |
| `src/types.rs` | A2A wire types (`AgentCard`, `SendMessageRequest`, `A2aMessage`, `A2aPart`, `TaskResponse`, `TaskStatus`, `A2aJsonRpcResponse`) and `A2aKernelExecutionContext`. |
| `src/bridge.rs` | `A2aCapabilityBridge` (`CapabilityBridge` impl), bridge-fidelity evaluation, skill-candidate construction, and the authoritative target-protocol registry and orchestrated execution call. |
| `src/conversion.rs` | Message-to-argument extraction, kernel-output-to-A2A-part projection, and the Chio metadata envelope builders (pending, cancelled, passthrough, authoritative annotation). |
| `src/edge.rs` | `ChioA2aEdge`: construction, Agent Card, skill resolution, the `message/send` / `message/stream` / JSON-RPC handlers, deferred task lifecycle, and the `ChioA2aEdgeCompatibility` passthrough wrapper. |
| `src/jsonrpc.rs` | JSON-RPC envelope parsing and params validation shared by the authoritative and compatibility dispatchers. |
| `src/metrics.rs` | This edge's `chio_receipt_write_total` counters, independent of every other edge's counters, plus Prometheus rendering. |
| `src/otel.rs` | A2A-specific GenAI tool-call span helper built on `chio-kernel`'s OTel primitives (`feature = "otel"`). |

## Skill publication and dispatch

1. `ChioA2aEdge::new` validates the Agent Card config, then runs every
   `ToolManifest` through `chio_manifest::validate_manifest` before building
   any skill.
2. `build_skill_candidate` resolves each tool's target protocol (native,
   MCP, or OpenAI-compatible), evaluates `BridgeFidelity`, and assigns a
   skill id: server-qualified on tool-name collision across manifests,
   ordinal-suffixed when multiple manifests expose the same
   server-qualified id. Only candidates whose fidelity is
   `published_by_default()` enter the Agent Card skill list; gated
   candidates stay queryable through `bridge_fidelity()`.
3. `handle_send_message` (and JSON-RPC `message/send`) resolves the skill
   binding, extracts arguments from the message parts, and calls
   `CrossProtocolOrchestrator::execute` with `A2aCapabilityBridge`.
   `task_response_from_orchestrated` maps the verdict to a `TaskResponse`
   (`Allow`+completed to `Completed`, `Allow`+incomplete such as an
   execution-nonce preflight retry to `Working`, `Deny`/`PendingApproval` to
   `Failed`) and records the verdict to the receipt-write counters.
4. `handle_stream_message` (and JSON-RPC `message/stream`) allocates a task
   id and stores a `Working` `DeferredA2aTask` without calling the kernel.
   `task/get` executes the stored request exactly once, persists the
   terminal `TaskResponse`, and returns it on every later poll. `task/cancel`
   moves a `Working` task to `Cancelled` (idempotent once cancelled) and
   rejects cancelling any other terminal status.
5. The compatibility surface (`ChioA2aEdgeCompatibility`, gated by
   `cfg(test)` or `feature = "compatibility-surface"`) skips the kernel
   entirely, invokes `dyn ToolServerConnection::invoke` directly, and tags
   the result with explicit `authoritative: false` metadata.

## Invariants and failure modes

- `A2aEdgeConfig` fields (name, version, endpoint URL, protocol binding)
  must be non-empty and free of leading or trailing whitespace; violations
  fail construction with `A2aEdgeError::InvalidRequest` instead of being
  trimmed.
- Every manifest passed to `ChioA2aEdge::new` must pass
  `chio_manifest::validate_manifest` before any skill is built from it.
- A skill id that collides across manifests and is looked up unqualified
  resolves to an explicit "ambiguous, use one of" error instead of silently
  picking a candidate.
- `agent_id` on `A2aKernelExecutionContext`, and the `taskId` /
  `metadata.chio.targetSkillId` JSON-RPC params, must be non-empty,
  unpadded, and (for `agent_id` and `taskId`) free of control characters
  before any skill resolution, kernel dispatch, or task-state mutation.
- The JSON-RPC boundary rejects a non-object `params` for a known method
  with `-32602`, an unknown method with `-32601`, and a malformed envelope
  (`jsonrpc != "2.0"`, missing `method`, or a non-string/number/null `id`)
  with `-32600`, all before message parsing or task lookup.
- `message.parts` must be non-empty with at most one `data` part, itself a
  JSON object.
- Deferred tasks are capped at `MAX_DEFERRED_A2A_TASKS` (1024) concurrently
  `Working` tasks and expire `DEFERRED_A2A_TASK_TTL_MILLIS` (5 minutes) after
  creation; pruning runs before every stream, get, and cancel operation.
  Terminal tasks do not count against the cap but are still pruned once
  their TTL elapses.
- `task/get` and `task/cancel` reject a task whose `owner_agent_id` does not
  match the calling `agent_id`.
- The receipt-write error counter increments only for `BridgeError::Kernel`
  orchestration failures, not other bridge errors such as an unregistered
  target protocol; the passthrough surface never records a verdict or
  receipt-write outcome at all. `render_a2a_edge_metrics_prometheus` appends
  receipt-writer liveness gauges after the outcome counters, so a wedged or
  dead writer is visible on the same scrape.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

`chio-core` is aliased to `chio-core-types` (path dependency) and supplies
capability, governance, session, and model-metadata types (`CapabilityToken`,
`GovernedTransactionIntent`, `GovernedApprovalToken`, `OperationTerminalState`,
`ModelMetadata`). `chio-cross-protocol` is the primary architectural
dependency: it supplies the `CapabilityBridge` trait, the target-protocol
registry, `CrossProtocolOrchestrator`, `BridgeFidelity`, the
runtime-lifecycle contract, and the sync bridge behind the compatibility
surface. `chio-kernel` supplies `ChioKernel`, `Verdict`, `ToolCallOutput`,
`ToolServerConnection`, and the DPoP / execution-nonce types carried on
`A2aKernelExecutionContext`. `chio-manifest` supplies `ToolDefinition`,
`ToolManifest`, and `validate_manifest`. `chio-mcp-edge` supplies
`McpTargetExecutor`, one of the two registered target executors (the other,
`OpenAiTargetExecutor`, comes from `chio-cross-protocol` itself).
`chio-edge-metrics` supplies the counter and Prometheus-render primitives
this crate's `metrics` module wraps into an independent counter instance.
`serde` / `serde_json` back every wire type; `thiserror` derives
`A2aEdgeError`.
