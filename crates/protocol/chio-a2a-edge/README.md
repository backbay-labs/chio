# chio-a2a-edge

Edge crate that exposes Chio-governed tools as A2A (Agent-to-Agent) skills to
external clients. It builds an A2A Agent Card and dispatches `message/send`,
`message/stream`, `task/get`, and `task/cancel` through the Chio kernel, which
evaluates each call and signs a receipt into the response metadata. This is
the inbound counterpart to `chio-a2a-adapter`, which consumes a remote A2A
agent instead of hosting one; the split mirrors `chio-mcp-adapter` (wraps an
upstream MCP server) and `chio-mcp-edge` (the MCP hosting runtime).

## Responsibilities

- Turn a set of Chio `ToolManifest`s into an A2A Agent Card: resolve each
  tool's target protocol, evaluate `BridgeFidelity`, assign collision-safe
  skill ids, and publish only skills whose fidelity resolves to
  publish-by-default.
- Route blocking `message/send` and the deferred `message/stream` /
  `task/get` / `task/cancel` lifecycle through `chio-kernel` via
  `chio-cross-protocol`'s `CrossProtocolOrchestrator`, mapping kernel
  verdicts to A2A `TaskResponse`s.
- Bound and prune the deferred task table by capacity and TTL, and restrict
  polling or cancelling a task to its owning `agent_id`.
- Parse and validate the inbound JSON-RPC envelope, method params, and
  identifier fields before any skill resolution or kernel dispatch runs.
- Provide an explicit, feature-gated non-authoritative passthrough
  (`ChioA2aEdgeCompatibility`) that bypasses the kernel for bounded
  migration and tests.
- Record per-outcome receipt-write counters and render them as Prometheus
  text (`metrics` module).

## Public API

- `ChioA2aEdge::new(config: A2aEdgeConfig, manifests: Vec<ToolManifest>)` -
  construct the edge; validates the Agent Card config and every manifest.
- `ChioA2aEdge::{agent_card, agent_card_json, skill_ids, skill,
  bridge_fidelity}` - Agent Card and skill-catalog introspection.
- `ChioA2aEdge::{handle_send_message, handle_stream_message, handle_jsonrpc}` -
  kernel-mediated blocking send, deferred stream start, and raw JSON-RPC
  dispatch (returns an `A2aJsonRpcResponse`).
- `ChioA2aEdge::compatibility()` -> `ChioA2aEdgeCompatibility` - opt-in
  passthrough surface (`cfg(test)` or `feature = "compatibility-surface"`).
- `A2aEdgeConfig`, `A2aEdgeError`, `A2aKernelExecutionContext` - Agent Card
  config, error type, and per-call kernel execution context.
- Wire types: `AgentCard`, `A2aSkillEntry`, `SendMessageRequest`,
  `A2aMessage`, `A2aPart`, `TaskResponse`, `TaskStatus`,
  `A2aJsonRpcResponse`.
- `metrics::{render_a2a_edge_metrics_prometheus, receipt_write_total,
  receipt_write_outcome_for_verdict, CHIO_RECEIPT_WRITE_TOTAL,
  RECEIPT_WRITE_OUTCOME_*}` - receipt-write metrics.
- `otel::a2a_tool_call_span` (`feature = "otel"`) - GenAI tool-call span
  helper.

## Feature flags

| Flag | Effect |
|------|--------|
| `compatibility-surface` | Compiles `ChioA2aEdge::compatibility()` and the passthrough handlers outside test builds. |
| `otel` | Enables the `otel` module and its GenAI span helpers (`chio-kernel/otel`, `chio-mcp-edge/otel`). |

## Testing

`cargo test -p chio-a2a-edge`

## See also

- `chio-a2a-adapter` - the reverse direction: mediates calls to a remote A2A agent instead of hosting Chio tools as one.
- `chio-cross-protocol` - supplies the `CapabilityBridge` trait, orchestrator, target-protocol registry, and fidelity/lifecycle contracts this crate implements against.
- `chio-kernel` - mediates every authoritative skill invocation and signs receipts.
- `chio-mcp-edge` - registered as a cross-protocol target executor; also the MCP hosting runtime that pairs with `chio-mcp-adapter` the way this crate pairs with `chio-a2a-adapter`.
