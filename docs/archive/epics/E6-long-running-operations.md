# E6: Long-Running Operations

## Status

In progress.

Preconditions already in place:

- session IDs, request IDs, progress tokens, and cancellable flags exist in the session substrate
- in-flight request tracking exists in the kernel
- nested-flow lineage now works for wrapped stdio MCP servers

Shipped so far:

- MCP edge request contexts now parse `_meta.progressToken`
- wrapped nested `roots/list` and `sampling/createMessage` flows emit `notifications/progress`
- active nested client requests now honor `notifications/cancelled` and fail closed
- active parent `tools/call` requests can now be cancelled while nested client work is in flight
- cancellation now lands as an explicit denied runtime outcome instead of a generic transport failure
- tool requests now record explicit `Completed`, `Cancelled`, and `Incomplete` terminal states in session history
- tool receipts now carry explicit cancelled and incomplete decisions instead of flattening those outcomes into generic deny receipts
- wrapped tool-stream termination can now land as an incomplete, receipted outcome instead of an untyped tool-server failure
- the native Chio stdio wire can now emit `tool_call_chunk` frames before a terminal streamed tool response
- the native Chio stdio wire now distinguishes `stream_complete`, `incomplete`, and `cancelled` final tool statuses
- receipts now carry content hashes for all outcomes plus chunk-hash metadata for streamed tool output
- the kernel now enforces streamed tool duration and total-byte limits and converts limit breaches into incomplete outcomes
- wrapped stdio `tools/call` requests can now be cancelled while an upstream tool request is in flight even when no nested client callback is active
- the session subscription registry now tracks typed resource subjects instead of raw placeholders
- the MCP edge now implements `resources/subscribe` and `resources/unsubscribe`
- the MCP edge can now emit `notifications/resources/updated` only for subscribed URIs
- the MCP edge can now emit `notifications/resources/list_changed` when the host enables that feature
- wrapped stdio MCP servers can now forward `notifications/resources/updated` and `notifications/resources/list_changed` during active `tools/call` execution and while the outer client is otherwise idle
- wrapped stdio MCP servers can now forward `notifications/tools/list_changed` and `notifications/prompts/list_changed` during active requests and while the outer client is otherwise idle
- the MCP edge now has a capability-negotiated experimental stream bridge for native Chio streamed tool output via `notifications/chio/tool_call_chunk`
- the stdio edge now proves chunk notifications are emitted before the final `tools/call` result when that extension is negotiated
- the MCP edge now supports a first standard task slice for server-side `tools/call`: task-augmented invocation plus `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel`
- `tools/list` now advertises `execution.taskSupport: "optional"` and `tasks/result` reuses the stream bridge for native streamed tools
- idle stdio MCP sessions can now advance queued tool tasks to completion without waiting for `tasks/result`
- the edge can now emit optional `notifications/tasks/status` with full task objects when task status changes
- task-associated nested sampling requests, progress notifications, and log notifications now carry standard `io.modelcontextprotocol/related-task` metadata
- the wrapped stdio bridge now supports task-augmented `sampling/createMessage`, including `tasks/list|get|result|cancel` for nested client-side sampling work
- the wrapped stdio bridge now supports form-mode `elicitation/create`, including task-augmented nested client-side elicitation work via `tasks/list|get|result|cancel`
- the direct edge and wrapped stdio path now support URL-mode `elicitation/create`
- accepted URL-mode elicitation IDs now live in edge-owned pending state instead of request-local scratch state
- wrapped stdio servers can now forward `notifications/elicitation/complete` during active work and idle periods, and the edge filters those notifications to previously-brokered elicitation IDs
- end-to-end coverage exists in `crates/chio-cli/tests/mcp_serve.rs`
  - unit coverage exists in `crates/chio-mcp-adapter/src/edge.rs` for subscription/update fanout

Still missing:

- richer stream ownership rules beyond the current wrapped stdio path
- broader fully concurrent ownership across transports beyond the current stdio-local executors
- URL elicitation required-error brokerage
- durable async completion sources for native direct tool servers outside an active invocation

## Suggested issue title

`E6: implement progress, cancellation, and long-running operation semantics`

## Problem

Chio can now cover the major MCP request surfaces on the stdio edge, but it still behaves like a single-shot protocol.

That breaks down for:

- long-running tools
- streaming responses
- cancellable work
- resource subscriptions and change notifications
- reliable operator visibility into in-flight work

## Outcome

By the end of E6:

- progress is first-class and tied to live request IDs
- cancellation is explicit, race-aware, and fail-closed
- streams have terminal ownership rules
- partial or cancelled work has auditable terminal state

## Scope

In scope:

- progress token handling
- cancellation request handling
- stream lifecycle and terminal state
- receipt semantics for incomplete or cancelled work
- subscription bookkeeping needed for dynamic updates

Out of scope:

- HTTP transport and auth
- persistent receipt storage
- trust-plane services

## Primary files and areas

- `crates/chio-core/src/session.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-kernel/src/lib.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-mcp-adapter/src/transport.rs`

## Task breakdown

### `T6.1` Progress

- shipped first slice for MCP edge parsing and nested-flow progress emission
- remaining work: normalize progress events across more session operations and long-running streams

### `T6.2` Cancellation

- shipped first slice for nested client-request cancellation on the MCP edge
- shipped second slice for parent `tools/call` cancellation during nested client work
- shipped third slice for wrapped top-level `tools/call` cancellation while an upstream tool request is in flight outside nested callback windows
- remaining work: explicit race semantics and broader ownership beyond the wrapped stdio path

### `T6.3` Streams and partial outcomes

- shipped first slice:
  - tool requests now record explicit `Completed`, `Cancelled`, and `Incomplete` terminal states
  - incomplete and cancelled tool receipts are now signed and appended like other audited decisions
  - wrapped MCP subprocess termination during a live tool call now maps to an incomplete tool outcome
- shipped second slice:
  - the native Chio stdio wire now emits `tool_call_chunk` frames before terminal completion
  - terminal tool responses on the native wire now distinguish `stream_complete`, `incomplete`, and `cancelled`
- shipped third slice:
  - receipts now carry content hashes for all outcomes plus chunk-hash metadata for streamed output
  - the kernel now enforces stream duration and total-byte limits and preserves truncated partial output on incomplete limit breaches
- shipped fourth slice:
  - the MCP edge now advertises and honors an opt-in `capabilities.experimental.chioToolStreaming.toolCallChunkNotifications` extension
  - negotiated clients receive `notifications/chio/tool_call_chunk` before the final `tools/call` response
  - non-negotiated clients still receive a collapsed final tool result
- shipped fifth slice:
  - the MCP edge now accepts task-augmented `tools/call` requests and returns `CreateTaskResult`
  - the edge now serves `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel`
  - `tasks/result` blocks until terminal completion and reuses the chunk-notification bridge for native streamed tool output
- shipped sixth slice:
  - idle stdio MCP sessions can now advance queued tool tasks to completion without waiting for `tasks/result`
  - the edge can now emit optional `notifications/tasks/status` on completion and cancellation
  - task-associated nested sampling requests plus progress/logging notifications now carry standard related-task metadata
- shipped seventh slice:
  - the wrapped stdio transport now advertises client-side sampling task support to upstream servers
  - task-augmented upstream `sampling/createMessage` requests now return `CreateTaskResult`
  - the bridge now serves `tasks/list|get|result|cancel` for nested client-side sampling tasks and can advance them during idle polling
- shipped eighth slice:
  - the wrapped stdio transport now advertises form-mode client-side elicitation support to upstream servers
  - task-augmented upstream `elicitation/create` requests now return `CreateTaskResult`
  - the bridge now serves `tasks/list|get|result|cancel` for nested client-side elicitation tasks and can advance them during idle polling
  - direct edge and wrapped stdio nested-flow clients now share typed `elicitation/create` request/result handling, and the edge now treats `elicitation: {}` as form-mode support during capability negotiation
- shipped ninth slice:
  - the direct edge and wrapped stdio path now broker URL-mode `elicitation/create`
  - accepted URL-mode elicitation IDs now live in edge-owned pending state instead of request-local scratch state
  - wrapped stdio servers can now forward `notifications/elicitation/complete` during active work and idle periods
  - completion notifications are emitted only for previously-brokered elicitation IDs, with related-task metadata preserved when available
- shipped tenth slice:
  - wrapped MCP `-32042` URL-required errors now survive adapter and kernel boundaries as structured outcomes instead of flattening into tool-error text
  - direct/native tool servers can now return the same structured URL-required outcome through the kernel and edge
  - native direct tool servers can now emit late async events through a kernel-drained event source, including URL elicitation completion and catalog/resource notifications
- shipped eleventh slice:
  - nested child requests now produce signed child-request receipts with parent lineage, operation kind, terminal state, and an outcome hash
  - child-request cancellation now records a real cancelled terminal state instead of collapsing back to completed session history
  - both the outer edge task runner and wrapped nested-task runtime now advance multiple queued tasks per idle tick in bounded batches instead of exactly one
- shipped twelfth slice:
  - queued outer-edge tool tasks now make progress on normal stdio request turns, not only on idle poll timeouts
  - wrapped stdio nested client tasks now also make progress while the upstream server continues sending nonterminal messages, rather than depending on timeout-only servicing
  - end-to-end regression coverage now proves both outer-edge and wrapped nested tasks can complete under sustained traffic
- remaining work:
  - extend explicit terminal ownership beyond the current wrapped stdio tool-request path
  - move from fair serviced single-loop execution to broader concurrent ownership semantics across transports

### `T6.4` Subscriptions and updates

- shipped first slice:
  - replaced the placeholder subscription registry with typed resource subjects
  - added edge-level resource subscribe/unsubscribe flows
  - added edge-managed list-changed and resource-updated notification fanout
- shipped second slice:
  - bridged wrapped-server `notifications/resources/*` through the stdio adapted transport during active `tools/call` execution
- shipped third slice:
  - added an event-driven stdio edge loop plus background upstream notification queue
  - forwarded wrapped-server `notifications/resources/*` while the outer MCP client is idle
- shipped fourth slice:
  - forwarded wrapped-server `notifications/tools/list_changed` and `notifications/prompts/list_changed` during active requests and while idle
- remaining work:
  - decide whether subscriptions should become first-class normalized session operations
  - extend the same model to richer non-resource change surfaces when they are added

## Dependencies

- depends on E1 session foundation
- depends on E3 MCP tool edge parity
- depends on E4 resources/prompts/completion/logging
- depends on E5 nested-flow substrate

## Risks

- bolting progress and cancellation onto the edge without a real state machine
- sending progress for requests that are no longer live
- ambiguous cancellation races leading to inconsistent receipts

## Mitigations

- keep progress and cancellation session-scoped
- make terminal state single-owner and explicit
- test race boundaries before adding richer transports

## Acceptance criteria

- progress notifications reference only live in-flight requests
- nested cancellable requests can already be interrupted and fail closed
- partial or cancelled work reaches a terminal audited state
- resource subscriptions and update notifications work on the MCP edge, including the wrapped subprocess path when the upstream server can actually source those events
- wrapped tool/prompt catalog change notifications survive the wrapped subprocess path during active work and idle periods
- native `chio run` sessions can now emit chunked tool frames before a terminal streamed response
- negotiated MCP-edge clients can now receive multi-event streamed tool chunks for native Chio-backed tools
- task-augmented server-side `tools/call` requests are now retrievable via `tasks/get` and `tasks/result`
- idle stdio task execution can now complete and surface `notifications/tasks/status` without requiring a `tasks/result` waiter
- nested task-associated sampling/progress/logging messages carry standard related-task metadata
- wrapped stdio servers can now use task-augmented `sampling/createMessage` and resolve it through `tasks/get` and `tasks/result`
- wrapped stdio servers can now use task-augmented form-mode `elicitation/create` and resolve it through `tasks/get` and `tasks/result`
- wrapped stdio servers can now broker URL-mode `elicitation/create` and later emit `notifications/elicitation/complete` without a follow-up client request
- wrapped and direct tool servers can now surface standard `-32042` URL-required outcomes with structured elicitation data
- native direct tool servers can now emit late async completion/change events without an active invocation-local bridge
- nested child requests now produce signed receipts with parent lineage and correct cancelled/incomplete terminal states
- bounded idle batching now advances multiple queued edge and nested tasks per tick instead of exactly one

## Definition of done

- progress merged and tested
- cancellation merged and tested
- first stream and terminal-state slice for tool requests merged and tested
- subscription/update flows merged
- receipt behavior for incomplete work is implemented, not just documented
- the MCP edge exposes a tested opt-in bridge for multi-event native streamed tool output
- the MCP edge exposes a tested first slice of standard task-augmented `tools/call`
- the MCP edge exposes tested idle background task progression plus optional `notifications/tasks/status`
- the wrapped stdio bridge exposes tested task-augmented `sampling/createMessage` support
- the wrapped stdio bridge exposes tested task-augmented form-mode `elicitation/create` support
- the wrapped stdio bridge exposes tested URL-mode `elicitation/create` plus `notifications/elicitation/complete` forwarding
- the edge exposes tested `-32042` URL-required error brokerage for wrapped and direct tool servers
- the kernel and edge expose a tested async event path for native direct tool servers
- the kernel exposes tested signed child-request receipts for nested roots/sampling/elicitation flows
- the edge and wrapped nested-task runtime expose tested bounded multi-task idle progression
