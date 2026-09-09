# chio-mcp-edge

`chio-mcp-edge` hosts a Chio-governed kernel as an MCP (Model Context
Protocol) server. `ChioMcpEdge` implements the MCP JSON-RPC method surface
over stdio or an in-process channel and dispatches every call through
`chio_kernel::ChioKernel`, so capability checks, guard evaluation, and receipt
signing stay in the kernel rather than the edge.

The crate also owns the wire contracts shared with `chio-mcp-adapter`:
`McpTransport`, `McpToolInfo`, `McpToolResult`, `McpServerCapabilities`, and
`AdapterError`. `chio-mcp-adapter` implements `McpTransport` to adapt an
existing upstream MCP server into a governed Chio tool server. This crate does
the reverse: it hosts Chio's own tools as an MCP server.

## Responsibilities

- Implement the MCP JSON-RPC 2.0 method surface: `initialize`, `tools/list`,
  `tools/call`, `tasks/*`, `resources/*`, `prompts/*`, `completion/complete`,
  `logging/setLevel`, and the `notifications/initialized` /
  `notifications/roots/list_changed` / `notifications/cancelled` handshake.
- Project validated `chio_manifest::ToolManifest`s into MCP tool listings,
  translating side-effect and latency hints into MCP annotations.
- Run the MCP task lifecycle: bounded, TTL-limited deferred tasks with
  background pumping, cancellation, and status notifications.
- Mediate server-to-client nested flows (sampling, roots, elicitation) over
  both a blocking reader/writer transport and a channel-based transport, with
  a cancellation side channel independent of the main JSON-RPC dispatcher.
- Project kernel tool-call responses into MCP results, including collapsed or
  chunk-streamed output, and record `chio_receipt_write_total` metrics at the
  kernel boundary.
- Provide `McpTargetExecutor`, the default MCP-target executor for
  `chio-cross-protocol` cross-protocol tool-call bridging.

## Public API

- `ChioMcpEdge`, `McpEdgeConfig`, `McpExposedTool` - the hosting runtime, its
  configuration, and the tool shape it advertises over MCP.
- Entry points: `ChioMcpEdge::{new, handle_jsonrpc, serve_stdio,
  serve_message_channels, drain_runtime_notifications, restore_ready_session,
  attach_upstream_transport}`.
- Host-driven hooks: `notify_resource_updated`, `notify_resources_list_changed`,
  `notify_tools_list_changed`, `notify_prompts_list_changed`,
  `notify_elicitation_completed`, and `create_message` (sampling within an
  existing operation context, over a reader/writer transport).
- `McpTransport`, `McpToolInfo`, `McpToolResult`, `McpServerCapabilities`,
  `AdapterError` - shared MCP wire contracts, implemented by
  `chio-mcp-adapter`.
- `execute_bridge_mcp_tool_call`, `execute_bridge_mcp_tool_call_async`,
  `BridgeMcpToolCall`, `BridgeMcpToolCallRequest`, `McpTargetExecutor` -
  bridge-only tool-call execution that projects a kernel response into an MCP
  result without running the JSON-RPC loop.
- `metrics::{receipt_write_total, render_mcp_edge_metrics_prometheus,
  CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_*}` - receipt-write counters
  and Prometheus exposition.

## Usage

```rust
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig};
use serde_json::json;

// kernel, agent_id, capabilities, and manifests are built the usual way
// with chio-kernel, chio-core, and chio-manifest.
let mut edge = ChioMcpEdge::new(McpEdgeConfig::default(), kernel, agent_id, capabilities, manifests)?;

edge.handle_jsonrpc(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }));
edge.handle_jsonrpc(json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }));
let response = edge.handle_jsonrpc(json!({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": { "name": "echo_json", "arguments": { "city": "Boston" } }
}));
```

Use `serve_stdio` or `serve_message_channels` instead of `handle_jsonrpc` to
run a full inbound loop (background tasks, deferred nested-flow messages,
queued notifications) over stdio or an in-process channel.

## Feature flags

| Flag | Effect |
|------|--------|
| `otel` | Enables `otel`, MCP-flavored GenAI tool-call span helpers built on `chio-kernel/otel`. |
| `fuzz` | Exposes `fuzz`, the libFuzzer entry point for the stdio decode-then-`handle_jsonrpc` dispatch pipeline. Off by default; pulls in `arbitrary`. Enabled only by the standalone `fuzz` workspace. |

## Testing

`cargo test -p chio-mcp-edge`

## See also

- `chio-mcp-adapter` - adapts an existing upstream MCP server into a governed
  Chio tool server, implementing this crate's `McpTransport` contract.
- `chio-kernel` - the governed runtime this edge hosts and dispatches into.
- `chio-manifest` - tool manifest types and validation this crate projects
  into MCP tool listings.
- `chio-a2a-edge`, `chio-acp-edge` - route cross-protocol tool calls into MCP
  targets through `McpTargetExecutor`.
- `chio-openapi-mcp-bridge` - projects OpenAPI operations into this crate's
  `McpToolInfo`.
# Execution evidence extension

The MCP initialize response advertises
`capabilities.experimental["io.chio/execution-evidence"].version = "1"`.
For tool calls that produce a kernel response, the edge adds
`result._meta.chioEvidence`:

```json
{
  "schema": "chio.mcp.execution-evidence.v1",
  "requestId": "caller-stable-operation-id",
  "receipt": {},
  "outputKind": "value",
  "output": {},
  "terminalState": "completed"
}
```

`receipt` is the full signed kernel receipt. `output` is the original JSON
value returned by the kernel, before MCP wrapping, and its RFC 8785 canonical
bytes are the preimage of the receipt's `content_hash`. The normal MCP result
may add content blocks or `isError`; hash the evidence output, not that result.
Upstream tools cannot override the reserved `chioEvidence` metadata.

Clients must pin the expected kernel signer through trusted configuration,
verify the receipt signature and content-addressed ID, and bind the signed
capability ID, attribution subject, server, tool, action parameter hash and
`metadata.receipt_context.request_id` to the intended operation. Supply
`params._meta.chioRequestId` for every operation and preserve it across retries.
The JSON-RPC ID is only a transport correlation ID. The envelope's `requestId`
and `terminalState` are diagnostic projections, not additional signed claims.
Use the receipt's signed decision and any durable admission state for claims.

`outputKind: "none"` supplies no execution result, including an authorization
preflight or a denied call. It cannot establish executed success, even if the
receipt says Allow. Version 1 supplies a value preimage only for completed
Allow responses. Streams carry `outputKind: "stream"` and null evidence output;
their existing chunk receipt protocol must be verified separately. Suppressed
outputs are never re-exposed through evidence.

Errors before kernel evaluation, cancelled transport responses, and failed
receipt persistence may have no evidence. Treat missing, unsupported, malformed
or untrusted evidence as unresolved, not as proof of no effect or permission to
retry a consequential operation. This extension does not provide OS isolation
or make a client-side authorization check a resource enforcement boundary.

The authenticated, ready session also supports `chio/execution-context`, as
advertised by the extension's `contextMethod`. It returns the public subject
key, assigned capability IDs, and evidence version. This read-only response
lets an operator pin the authority assigned to an established session before
any tool call. It is session diagnostics over the authenticated transport,
not a signed authorization token. Clients must retain that session, compare
its context to the operator-pinned caller and capability before dispatch, and
still verify the signed invocation receipt. Losing or replacing a session
must not silently mint a fresh authority or reset a budget.
