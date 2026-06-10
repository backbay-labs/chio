# chio-mcp-edge architecture note

## Boundaries

- `lib.rs` owns the public crate surface, shared MCP data contracts, metrics exports, and optional fuzz/otel feature gates.
- `runtime.rs` owns `ChioMcpEdge` construction, session lifecycle, request and notification dispatch, provider/resource/prompt/completion handlers, runtime event forwarding, root refresh, nested-flow client requests, and inbound loop control.
- `runtime/errors.rs` owns structured Chio protocol error argument data.
- `runtime/jsonrpc.rs` owns JSON-RPC protocol error construction and MCP protocol-version negotiation.
- `runtime/state.rs` owns edge lifecycle state, pending runtime actions, and logging level parsing.
- `runtime/tasks.rs` owns MCP task views, task lifecycle state transitions, task request handlers, deferred-task retention, and background task pumping.
- `runtime/tool_calls.rs` owns bridge-only MCP tool-call execution helpers, `McpTargetExecutor`, tool-call request preparation, kernel tool-call execution, MCP result projection, and URL elicitation persistence.
- `runtime/receipts.rs` owns receipt-write error metric tracking.
- `runtime/protocol.rs` owns JSON-RPC envelope parsing, response and notification shaping, task/result metadata, pagination, cancellation matching, capability selection, and wire helpers.
- `runtime/discovery.rs` owns MCP outward discovery projection and cross-manifest exposed-name binding.
- `runtime/framing.rs` owns bounded newline-delimited stdio frame decoding.
- `runtime/nested_flow.rs` owns server-to-client nested-flow client implementations for sampling, roots, elicitation, progress, and cancellation mediation.
- `metrics.rs` owns MCP edge receipt-write counters and Prometheus rendering through the workspace metrics registry.

## Inbound Boundary Gates

- `runtime/discovery.rs` validates every `ToolManifest` with `chio_manifest::validate_manifest` before discovery projection or exposed-name indexing, keeping cross-manifest duplicate exposed-name checks local. Manifest validation is the single canonical envelope gate.
- A centralized known-request-method params gate runs before dispatch. Missing params normalize to `{}` for compatibility; non-object params for known MCP request methods fail with `-32602` before session state, discovery, or kernel operation paths observe coerced empty params. A matching known-notification params gate guards notification dispatch, so a malformed `notifications/initialized` cannot advance a session into the ready state; missing notification params still normalize to `{}`.
- A shared protocol identifier parser rejects empty, padded, and control-character strings for `taskId` and `completion/complete` target identifiers (prompt names, resource URIs, argument names) before they reach task maps, capability selection, or providers. Completion argument values stay caller-provided prefixes, including an empty prefix.
- Stdio frame decoding is bounded newline-delimited JSON-RPC through `runtime/framing.rs`, shared by stdio pumps, blocking nested-flow reads, and the fuzz entrypoint. Truncated, delimiterless, invalid-UTF-8, invalid-JSON, and oversized frames are rejected before runtime dispatch.

## Cancellation Side Channel

The runtime pumps inbound client messages through the main JSON-RPC dispatcher
and a side channel that lets nested-flow clients notice parent cancellation while
a child request is in flight. `notifications/cancelled` is the
notification-shaped cancellation primitive. `tasks/cancel` is request-shaped:
it enters the cancellation side channel only when it is a well-formed JSON-RPC
request with a scalar `id`, and otherwise passes through the main dispatcher,
which returns the task view or a JSON-RPC error. Deferred request handling during
nested flows is preserved so an in-flight client request can still be answered
after the child flow unwinds.

## Constraints

- Preserve public API compatibility for `ChioMcpEdge`, `McpEdgeConfig`, `McpExposedTool`, bridge execution helpers, shared transport contracts, metrics exports, and feature-gated fuzz/otel modules.
- Preserve exact-match MCP protocol negotiation, ready-state gating, JSON-RPC error codes, task ownership metadata, cancellation behavior, URL elicitation handling, progress notifications, and receipt-write metrics semantics.
- Preserve canonical tool-call authorization through the kernel and do not bypass capability, guard, receipt, session, budget, revocation, approval, or runtime-assurance paths.
- Preserve MCP wire compatibility for `initialize`, `tools/list`, `tools/call`, resources, prompts, completion, logging, tasks, and notification replay.
- Keep the fuzz feature off by default and free of production-only dependencies.

## Dependents

- `chio-mcp-adapter`, `chio-mcp-remote`, `chio-hosted-mcp`, and `examples/hello-mcp` construct or re-export `ChioMcpEdge`.
- `spec/WIRE_PROTOCOL.md` defines ready-state and hosted MCP version-negotiation behavior.
- `spec/schemas/chio-wire/v1/jsonrpc` and `spec/schemas/chio-http/v1/stream-frame.schema.json` mirror the JSON-RPC and stream notification shapes emitted by this crate.
- `docs/architecture/CHIO_RUNTIME_BOUNDARIES.md` records the `runtime.rs` versus `runtime/protocol.rs` ownership split.
- `docs/protocols/EDGE-CRATE-SYMMETRY.md` treats `manifest_tool_to_mcp_tool` as the reference outward-edge discovery projection.
