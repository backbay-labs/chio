# chio-mcp-edge architecture

## Overview

`chio-mcp-edge` hosts a Chio-governed kernel as an MCP server. `ChioMcpEdge`
owns the JSON-RPC 2.0 method surface, MCP session and task lifecycle, and
nested-flow mediation (sampling, roots, elicitation); every tool call,
resource read, prompt fetch, and completion is dispatched through
`chio_kernel::ChioKernel`, so authorization, guard evaluation, and receipt
signing stay in the kernel rather than the edge. The crate also owns
`McpTransport` and the wire-shape types (`McpToolInfo`, `McpToolResult`,
`McpServerCapabilities`, `AdapterError`) that `chio-mcp-adapter` implements on
the client-adapting side. The edge is an untrusted boundary: JSON-RPC input is
attacker-controlled, and malformed or unauthorized input fails closed to a
JSON-RPC error (or an `isError: true` tool result, for authorization) before
it reaches kernel state.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public surface: `McpToolInfo`, `McpToolResult`, `McpServerCapabilities`, `AdapterError`, the `McpTransport` trait, and re-exports of `runtime`/`metrics`/`otel`/`fuzz`. |
| `src/runtime.rs` | `ChioMcpEdge` and `McpEdgeConfig` fields and construction, the `handle_jsonrpc` / `serve_stdio` / `serve_message_channels` entry points, and the inbound loop that drives them. Declares the `runtime/` module tree. |
| `src/runtime/requests.rs` | Method dispatch table (`handle_request`) and handlers for `initialize`, `ping`, `tools/list`, `resources/*`, `prompts/*`, `completion/complete`, `logging/setLevel`, and the `notifications/initialized` / `notifications/roots/list_changed` state transitions. |
| `src/runtime/tool_calls.rs` | `tools/call` preparation and evaluation, the bridge-only `execute_bridge_mcp_tool_call[_async]` helpers, `McpTargetExecutor`, and kernel-response-to-MCP-result projection. |
| `src/runtime/tasks.rs` | `EdgeTask` state machine, `tasks/list\|get\|cancel\|result` handlers, deferred-task capacity and TTL pruning, background task pumping. |
| `src/runtime/nested_flow.rs` | `EdgeNestedFlowClient` (reader/writer) and `QueuedEdgeNestedFlowClient` (channel), the two `chio_kernel::NestedFlowClient` implementations that mediate roots, sampling, and elicitation requests back to the MCP client. |
| `src/runtime/runtime_flow.rs` | Host-facing `create_message`, roots refresh, blocking and channel client-request round trips, tool-server/upstream-notification forwarding, and small state accessors. |
| `src/runtime/discovery.rs` | `McpExposedTool`, manifest validation and projection into MCP tool listings (`build_exposed_tool_bindings`, `manifest_tool_to_mcp_tool`), annotation and latency-hint translation. |
| `src/runtime/protocol.rs` (+ `protocol/`) | JSON-RPC envelope parsing and known-method params gates, capability selection, cancellation and task-cancel matching, `_meta` parsing (execution nonce, governed intent, model metadata, progress token, related task), pagination, response construction, and tool-result value shaping. |
| `src/runtime/framing.rs` | Bounded newline-delimited stdio JSON-RPC frame decoding, shared by the stdio pump and the fuzz entry point. |
| `src/runtime/jsonrpc.rs` (+ `errors.rs`) | Structured Chio protocol-error payload construction and MCP protocol-version negotiation. |
| `src/runtime/state.rs` | `EdgeState` (session lifecycle), `EdgeAction`, `LogLevel`. |
| `src/runtime/receipts.rs` | Receipt-write error metric recording for kernel-error paths. |
| `src/metrics.rs` | MCP edge receipt-write counters and Prometheus rendering, built on `chio-edge-metrics`. |
| `src/otel.rs` (`otel` feature) | MCP-flavored GenAI tool-call span builder re-exporting `chio_kernel::otel`. |
| `src/fuzz.rs` (`fuzz` feature) | libFuzzer entry point driving decode-then-`handle_jsonrpc` dispatch. |

## Session lifecycle and dispatch

1. `ChioMcpEdge::new` validates every `ToolManifest` (`chio_manifest::validate_manifest`), projects its tools into `McpExposedTool` listings, and starts in `EdgeState::Uninitialized`.
2. `initialize` negotiates an exact-match protocol version, opens a kernel session, and stores peer capabilities, moving to `WaitingForInitialized`; `notifications/initialized` activates the session and moves to `Ready`. Every other stateful method requires `Ready`.
3. Two ways to drive the edge: `handle_jsonrpc` takes one message and returns an optional response, for embedders that own their own event loop (in-process hosting, tests); `serve_stdio` / `serve_message_channels` each spawn a reader thread publishing to an inbound channel plus a parallel cancellation side channel, then run a blocking inbound loop that dispatches, flushes queued notifications, drains deferred client messages, and services background tasks on a fixed poll interval.
4. `tools/call` resolves a capability against the requested tool and arguments, then either evaluates inline or, if the caller passed a `task` object, creates a bounded, TTL-limited `EdgeTask` and returns immediately; `tasks/result` (or the background pump) evaluates a pending task exactly once and records its terminal outcome.
5. When a tool call needs client input (sampling, roots, elicitation), the kernel calls back through a `NestedFlowClient` built for the active transport. The nested client tags its outgoing request with the owning task's `_meta`, blocks for the matching response, and defers any other in-flight client message so it can still be answered once the nested flow unwinds. `notifications/cancelled` and request-shaped `tasks/cancel` route through a separate cancellation side channel so a parent cancellation can interrupt a blocked nested request.
6. Kernel responses are projected to MCP results by `kernel_response_to_tool_result`: streamed output becomes either `notifications/chio/tool_call_chunk` notifications (if the peer negotiated `chioToolStreaming`) or a collapsed single result; every terminal tool-call outcome records a `chio_receipt_write_total` counter.

## Invariants and failure modes

- Protocol negotiation is exact-match: `initialize.params.protocolVersion`, if present, must equal `"2025-11-25"` (`MCP_PROTOCOL_VERSION`) or the request fails with a structured Chio protocol error; omitting it accepts the server's version.
- `initialize` runs once per edge instance; every other stateful method fails with `-32002` until `initialize` then `notifications/initialized` have both completed.
- A centralized params gate runs before dispatch: missing params on a known method normalize to `{}`, but non-object params on a known request method fail with `-32602` before session, discovery, or kernel state is touched; a matching notification gate keeps a malformed `notifications/initialized` from advancing session state.
- Manifest admission is fail-closed: `chio_manifest::validate_manifest` runs on every manifest before any tool is exposed, duplicate tool names across manifests are rejected, and non-object `inputSchema`/`outputSchema` are rejected.
- `parse_protocol_identifier` rejects empty, padded, or control-character `taskId`, prompt names, resource URIs, and completion argument names before they reach task maps or capability selection; completion argument *values* are exempt, including an empty prefix.
- Stdio framing is bounded at `MAX_STDIO_MCP_FRAME_BYTES` (1 MiB); EOF before a newline on a non-empty frame is a parse error, and an oversized frame discards its remainder so the next frame still parses.
- Deferred tasks are bounded at `MAX_DEFERRED_MCP_TASKS` (1024); a full task table prunes terminal tasks before rejecting new ones. Task TTL defaults to 5 minutes and is capped at 60 minutes. Background task start is delayed for `StreamableHttp` sessions and immediate for `InProcess`/`Stdio` sessions.
- An unauthorized `tools/call` returns a normal JSON-RPC *result* containing an MCP tool result with `isError: true`, not a JSON-RPC error object, so the calling model sees a tool failure rather than a protocol fault.
- Every terminal tool-call outcome (allow, deny, pending-approval, error) records `chio_receipt_write_total`; `RequestCancelled` and `UrlElicitationsRequired` kernel errors are excluded from the error counter because they are expected control flow.
- `value_to_tool_result` sets `isError: false` only when an MCP-shaped success value omits it; an explicit `isError` or existing `content` from the kernel is preserved. `chio-mcp-adapter` matches this same rule on the wrapping side.
- The `fuzz` feature never reaches production builds: `arbitrary` is optional and gated by `fuzz`, and `src/fuzz.rs` is `#[cfg(feature = "fuzz")]`.

## Dependencies

- `chio-kernel` - the governed runtime this edge hosts: sessions, capability and guard evaluation, receipts, `NestedFlowClient`/`NestedFlowBridge`, tool-call request and response types.
- `chio-core` (Cargo alias for the `chio-core-types` package, not the `chio-core` facade crate) - `CapabilityToken`, session and session-operation types, receipt `Decision`, capability scope and governance types.
- `chio-manifest` - `ToolManifest`, `ToolDefinition`, `ManifestError`, `validate_manifest`; the admission gate for every tool this crate exposes.
- `chio-cross-protocol` - `DiscoveryProtocol`, `TargetProtocolExecutor`, cross-protocol request/execution types; `McpTargetExecutor` implements the executor trait so `chio-a2a-edge` and `chio-acp-edge` can route into MCP targets.
- `chio-edge-metrics` - shared receipt-write counter and Prometheus-rendering logic; this crate owns one independent counter instance.
- `chrono` (`clock` feature) - task timestamps (`iso8601_now`, `unix_now_millis`).
- `tokio` - the async kernel call path and the current-thread/multi-thread runtime bridging in `execute_bridge_mcp_tool_call`.
- `serde` / `serde_json` - the wire format; most dispatch works directly on `serde_json::Value` rather than a typed JSON-RPC model.
- `thiserror` - `AdapterError`.

## Extension points

`McpTransport` is the trait a caller implements to represent an upstream MCP
connection (`chio-mcp-adapter::StdioMcpTransport` is the production
implementation). `chio-mcp-edge` itself never calls the tool/resource/prompt
methods on an attached transport: `attach_upstream_transport` only wires
`drain_notifications()` into `forward_upstream_notifications`, so an edge can
re-emit an upstream server's own `resources/list_changed`-style notifications
to its downstream MCP session. Routing an upstream tool call through the
kernel is a separate concern, handled by whoever adapts that transport into a
`ToolServerConnection` (`chio-mcp-adapter`).
