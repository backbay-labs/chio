# chio-mcp-edge architecture note

## Boundaries

- `lib.rs` owns the public crate surface, shared MCP data contracts, metrics exports, and optional fuzz/otel feature gates.
- `runtime.rs` owns the `ChioMcpEdge` state machine, session lifecycle, task orchestration, kernel dispatch, runtime event forwarding, and inbound loop control.
- `runtime/protocol.rs` owns JSON-RPC envelope parsing, response and notification shaping, task/result metadata, pagination, cancellation matching, capability selection, and wire helpers.
- `runtime/nested_flow.rs` owns server-to-client nested-flow client implementations for sampling, roots, elicitation, progress, and cancellation mediation.
- `metrics.rs` owns MCP edge receipt-write counters and Prometheus rendering through the workspace metrics registry.

## Pain Points

- `runtime/discovery.rs` now validates every manifest through
  `chio_manifest::validate_manifest` before projection, keeping the manifest
  envelope gate canonical.
- The JSON-RPC `params` shape gate is now centralized for known request
  methods. The cancellation side channel is the next raw inbound-message
  boundary because it classifies messages before normal dispatch.
- `tasks/cancel` is request-shaped because it returns a task view. It must not
  be accepted as a notification-shaped cancellation signal while nested client
  work is in flight.

## Constraints

- Preserve public API compatibility for `ChioMcpEdge`, `McpEdgeConfig`, `McpExposedTool`, bridge execution helpers, shared transport contracts, metrics exports, and feature-gated fuzz/otel modules.
- Preserve exact-match MCP protocol negotiation, ready-state gating, JSON-RPC error codes, task ownership metadata, cancellation behavior, URL elicitation handling, progress notifications, and receipt-write metrics semantics.
- Preserve canonical tool-call authorization through the kernel and do not bypass capability, guard, receipt, session, budget, revocation, approval, or runtime-assurance paths.
- Preserve MCP wire compatibility for `initialize`, `tools/list`, `tools/call`, resources, prompts, completion, logging, tasks, and notification replay.
- Keep this slice scoped to `chio-mcp-edge` unless dependent tests prove a transitive change is required.

## Dependents

- `chio-mcp-adapter`, `chio-mcp-remote`, `chio-hosted-mcp`, and `examples/hello-mcp` construct or re-export `ChioMcpEdge`.
- `spec/WIRE_PROTOCOL.md` defines ready-state and hosted MCP version-negotiation behavior.
- `spec/schemas/chio-wire/v1/jsonrpc` and `spec/schemas/chio-http/v1/stream-frame.schema.json` mirror the JSON-RPC and stream notification shapes emitted by this crate.
- `docs/architecture/CHIO_RUNTIME_BOUNDARIES.md` records the current `runtime.rs` versus `runtime/protocol.rs` ownership split.
- `docs/protocols/EDGE-CRATE-SYMMETRY.md` treats `manifest_tool_to_mcp_tool` as the reference outward-edge discovery projection.

## Completed Baseline

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before
discovery projection or exposed-name indexing, while keeping cross-manifest
duplicate exposed-name checks in `runtime/discovery.rs`. This is architectural
because it makes manifest validation the single canonical envelope gate and
leaves the MCP discovery module responsible only for outward projection and
cross-manifest exposure rules.

## Completed Params Gate

Add one centralized known-request-method params-object gate before dispatch.
Missing params still normalize to `{}` for compatibility, but non-object params
for known MCP request methods fail closed with `-32602` before session state,
discovery, or kernel operation paths can observe coerced empty params.

## Task Cancellation Side-Channel Slice

### Current Boundary

The runtime pumps inbound client messages through the main JSON-RPC dispatcher
and a side channel used by nested-flow clients to notice parent cancellation
while a child request is in flight. `notifications/cancelled` is notification
shaped. `tasks/cancel` is request shaped and should still pass through the main
dispatcher so the edge can return the task view or a JSON-RPC error.

### Pain Point

Before this slice, `pump_client_messages`, `pump_channel_messages`, and
`task_cancel_matches_related_task` classified `tasks/cancel` by method alone. A
notification-shaped `tasks/cancel` with no `id` could therefore enter the
cancellation side channel even though the main dispatcher would treat it as a
notification and ignore it.

### Security And API Constraints

- Preserve normal request-shaped `tasks/cancel` behavior and response payloads.
- Preserve `notifications/cancelled` as the notification-shaped cancellation
  primitive.
- Preserve deferred request handling during nested flows so an in-flight client
  request can still be answered after the child flow unwinds.
- Keep this slice inside `chio-mcp-edge`; no public API change is intended.

### Affected Dependents

`chio-mcp-remote`, `chio-hosted-mcp`, and channel-based embedders depend on the
same runtime loop and should observe no API change. The compatibility proof is
crate-local: request-shaped `tasks/cancel` remains in the side channel, while
notification-shaped `tasks/cancel` does not cancel nested work or produce hidden
state transitions.

### Completed Improvement

Centralize cancellation-side-channel classification so `notifications/cancelled`
remains notification shaped, but `tasks/cancel` is treated as a cancellation
signal only when it is a well-formed JSON-RPC request with a scalar `id`.

## Inbound Stdio Framing Slice

### Current Boundary

`runtime/protocol.rs` owns JSON-RPC envelope parsing and the blocking stdio
pump that feeds `ChioMcpEdge`. `fuzz.rs` owns the feature-gated decode then
dispatch fuzz entrypoint.

### Pain Point

The edge accepts client JSON-RPC over newline-delimited stdio, but both
`pump_client_messages` and `read_jsonrpc_line` call `BufRead::read_line`
directly. That leaves the edge without an explicit byte ceiling and accepts a
non-empty EOF as a complete frame even when the client never sent the newline
delimiter.

### Security And API Constraints

- Preserve public APIs and all JSON-RPC method behavior.
- Preserve notification, task, cancellation, and nested-flow side-channel
  semantics after a complete frame is decoded.
- Reject truncated, delimiterless, invalid UTF-8, invalid JSON, and oversized
  stdio frames before runtime dispatch.
- Keep the fuzz feature off by default and free of production-only dependencies.

### Affected Dependents

`chio-mcp-adapter`, `chio-mcp-remote`, `chio-hosted-mcp`, and
`examples/hello-mcp` depend on the MCP edge runtime. They should see no API
change. The focused proof is crate-local stdio framing tests plus fuzz-feature
tests that prove the fuzz decoder exercises the same boundary.

### Planned Improvement

Extract bounded newline-delimited JSON-RPC frame decoding into
`runtime/framing.rs`, route stdio pumps and blocking nested-flow reads through
it, and make the fuzz entrypoint use the same decoder.

## Known Notification Params Gate Slice

### Current Boundary

`runtime/protocol.rs` parses JSON-RPC envelopes and validates object-shaped
params for known MCP request methods. `runtime.rs` then dispatches request
methods or notification methods into lifecycle and runtime state handling.

### Pain Point

Known request methods already fail closed when `params` is present but not an
object. Known notification methods do not. A malformed
`notifications/initialized` notification can therefore advance an initialized
session into the ready state even though the inbound lifecycle frame does not
match the MCP object params shape.

### Security And API Constraints

- Preserve notification semantics: notification-shaped inputs still do not
  receive JSON-RPC responses.
- Preserve missing `params` compatibility by normalizing it to `{}`.
- Preserve ready-state gating for `tools/list`, `tools/call`, resource, prompt,
  completion, logging, and task methods.
- Preserve request-shaped `tasks/cancel` behavior and cancellation-side-channel
  ordering.
- Keep this slice inside `chio-mcp-edge`; no public API change is intended.

### Affected Dependents

`chio-mcp-remote`, `chio-hosted-mcp`, and stdio/channel embedders all drive the
same runtime dispatcher. They should observe no API change for well-formed MCP
notifications. The compatibility proof is crate-local: malformed known
notifications are ignored without state transitions, while well-formed
`notifications/initialized` still enters the ready state.

### Completed Improvement

Added one shared known-notification params gate in `runtime/protocol.rs`, routed
all direct and transport-backed JSON-RPC notification dispatch through it, and
made the cancellation side channel reject malformed
`notifications/cancelled` params before nested-flow cancellation matching.

## Protocol Identifier Admission Slice

### Current Boundary

`runtime/protocol.rs` admits JSON-RPC params for task lookups and
`completion/complete` targets before those values reach task maps, capability
selection, prompt providers, and resource providers.

### Pain Point

The existing admission logic checks only that `taskId`, completion prompt
names, completion resource URIs, and completion argument names are strings.
Empty, padded, or control-character-bearing identifiers therefore pass the edge
boundary and are treated as ordinary lookup keys or provider arguments.

### Security And API Constraints

- Preserve generated task IDs and normal `tasks/get`, `tasks/result`, and
  `tasks/cancel` behavior.
- Preserve completion argument values exactly, including an empty prefix, since
  completion callers can ask for all candidates.
- Preserve JSON-RPC `-32602` error classification for malformed params.
- Keep this slice inside `chio-mcp-edge`; no public API change is intended.

### Affected Dependents

`chio-mcp-remote`, `chio-hosted-mcp`, and channel or stdio embedders share the
same parser and should observe no change for well-formed identifiers. The
compatibility proof is crate-local parser and runtime coverage plus dependent
edge checks.

### Completed Improvement

Added a shared protocol identifier parser that rejects empty, padded, and control
character strings, then routed task ID and completion target identifier parsing
through it while leaving completion argument values as caller-provided prefixes.
