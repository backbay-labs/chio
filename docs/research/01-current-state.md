# Current State

## Executive Summary

ARC is currently strongest as a security kernel and weakest as a complete application protocol.

The codebase already has:

- a coherent capability model
- a kernel that mediates tool execution
- useful guard implementations
- signed receipts for allow and deny decisions
- an MCP adapter that can wrap existing MCP tools
- a richer policy model in `arc-policy` that is ahead of the main CLI path

The codebase does not yet have:

- a full session protocol comparable to MCP
- fully concurrent long-running ownership across transports
- production trust infrastructure for remote deployments

The implication is straightforward: the project is credible, but it is still a protocol slice, not a complete replacement surface.

## What Already Works Well

### 1. Security model

The core bet is sound:

- explicit capability tokens instead of ambient authority
- a mediation kernel instead of direct agent-to-server access
- fail-closed guard execution
- signed receipts for decisions

That is stronger than vanilla MCP's default trust model.

Relevant code:

- [capability.rs](../../crates/chio-core-types/src/capability.rs)
- [lib.rs](../../crates/chio-kernel/src/lib.rs)
- [integration.rs](../../crates/chio-guards/tests/integration.rs)
- [full_flow.rs](../../tests/e2e/tests/full_flow.rs)

### 2. Clean crate boundaries

The workspace decomposition is sensible:

- `arc-core` for portable protocol data types
- `arc-kernel` for enforcement
- `arc-guards` for policy enforcement units
- `arc-manifest` for signed tool metadata
- `arc-mcp-adapter` for migration
- `arc-policy` for the future policy plane

This is a good foundation for a layered runtime.

### 3. Real migration instinct

The existence of `arc-mcp-adapter` is strategically important. It shows the project already understands that adoption will not happen via a flag day rewrite.

Relevant code:

- [crates/arc-mcp-adapter/src/lib.rs](../../crates/chio-mcp-adapter/src/lib.rs)
- [crates/arc-mcp-adapter/src/transport.rs](../../crates/chio-mcp-adapter/src/transport.rs)

### 4. The policy future is already partly built

`arc-policy` is more mature than the current CLI ARC YAML policy path. It already contains:

- a richer HushSpec schema
- validation
- inheritance and merge
- compilation into a guard pipeline
- detection and receipt helpers

Relevant code:

- [crates/arc-policy/src/lib.rs](../../crates/chio-policy/src/lib.rs)
- [crates/arc-policy/src/compiler.rs](../../crates/chio-policy/src/compiler.rs)
- [crates/arc-policy/src/models.rs](../../crates/chio-policy/src/models.rs)

## What Is Structurally Missing

### 1. No full session model

The current agent/kernel messages only cover:

- tool call request
- capability listing
- heartbeat
- tool call response
- capability revoked

Relevant code:

- [crates/arc-core/src/message.rs](../../crates/chio-core-types/src/message.rs)

That is too small to replace MCP, which is a session protocol with lifecycle, negotiated capabilities, notifications, and multiple primitives.

### 2. Custom transport instead of interoperable edge

ARC currently speaks a custom length-prefixed canonical JSON framing layer.

Relevant code:

- [crates/arc-kernel/src/transport.rs](../../crates/chio-kernel/src/transport.rs)

That may be fine internally, but it is not enough externally if the goal is ecosystem replacement. MCP clients and servers expect JSON-RPC session semantics.

### 3. MCP coverage is no longer tool-only, but it is still incomplete

The adapter supports:

- `tools/list`
- `tools/call`
- `tasks/list`
- `tasks/get`
- `tasks/result`
- `tasks/cancel`
- `resources/list`
- `resources/read`
- `resources/subscribe`
- `resources/unsubscribe`
- `resources/templates/list`
- `prompts/list`
- `prompts/get`
- `completion/complete`
- `logging/setLevel`
- nested client callbacks for `roots/list`, `sampling/createMessage`, and both form-mode and URL-mode `elicitation/create`

It still does not present:

- resumable Streamable HTTP GET/SSE hosting
- root-aware enforcement on top of the negotiated roots surface

Relevant code:

- [crates/arc-mcp-adapter/src/lib.rs](../../crates/chio-mcp-adapter/src/lib.rs)

### 4. Runtime is still behind the draft spec

The gap is smaller than it used to be, but it is still real.

The shipped runtime now exposes a first streaming surface on the native ARC transport: the kernel can emit chunk frames and explicit streamed terminal statuses for `arc run` agents. Streamed receipts now carry chunk-hash metadata and the kernel enforces basic stream duration and total-byte limits.

The MCP edge now closes the immediate gap with an opt-in experimental bridge: negotiated clients can receive `notifications/arc/tool_call_chunk` before the final `tools/call` result for native ARC-backed streamed tools.

It also now exposes a first standard task slice for server-side tool execution: task-augmented `tools/call`, `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel`. Queued work no longer depends only on idle polls: the outer stdio edge and wrapped nested-task runtime now both service bounded background work on ordinary request/notification turns, so tasks can still complete under sustained client or upstream traffic. The edge can emit optional `notifications/tasks/status`, and task-associated nested sampling/progress/logging messages now carry standard related-task metadata. The wrapped stdio bridge now supports task-augmented `sampling/createMessage`, form-mode `elicitation/create`, and URL-mode `elicitation/create` for upstream servers. Accepted URL-mode elicitations now live in edge-owned pending state and wrapped stdio servers can later emit `notifications/elicitation/complete` during active work or idle periods. Wrapped and direct tool servers can now also surface standard `-32042` URL-required outcomes with structured elicitation data, and native direct tool servers now have a kernel-drained async event source for late completion/change notifications. Nested child requests now produce signed receipts with parent lineage, operation kind, terminal state, and an outcome hash, and child cancellation no longer collapses back to completed terminal history.

The runtime now also has a first remote MCP edge slice: `arc mcp serve-http` exposes authenticated Streamable HTTP session admission with `MCP-Session-Id` issuance, per-session remote edge workers, POST-based JSON request handling with SSE responses, stricter `Accept` and `Content-Type` enforcement, and remote nested sampling round-trips through follow-up POSTed JSON-RPC responses. Session IDs are now only surfaced after a successful `initialize` response rather than being preallocated at transport admission time. Session state also carries a normalized transport-auth context, so HTTP bearer admission is recorded separately from later capability authorization. That auth path is no longer static-token-only: the remote edge now supports either bootstrap static bearer admission or Ed25519-signed JWT bearer admission with normalized OAuth-style `iss` / `sub` / `aud` / scope capture, and follow-up requests must remain consistent with the authenticated session identity. In JWT mode the edge now also serves protected-resource metadata at the standard well-known paths, returns `WWW-Authenticate` challenges pointing clients at the metadata document and current scope hints, and can serve colocated OAuth authorization-server metadata at the issuer’s RFC 8414 well-known path when explicit authorization/token endpoints are configured. Admin APIs can also be separated onto their own bearer via `--admin-token`. The honest remaining gaps on the remote side are resumability, standalone GET SSE streams, actual token-exchange / hosted authorization-server flows, and broader hosted-runtime ownership beyond one wrapped subprocess per remote session.

The trust plane is no longer only embedded local SQLite either. `arc-kernel` now ships SQLite receipt, revocation, authority, and budget backends, while `arc-cli` also ships an HA trust-control service in `arc trust serve`. That service now centralizes capability issuance, authority status/rotation, revocation query/control, durable tool/child receipt ingestion/query, and shared invocation-budget accounting, and every runtime path can use it through `--control-url` and `--control-token`. The control client now accepts a comma-separated endpoint list and will fail over across nodes. In clustered mode, trust-control nodes advertise themselves, deterministically elect the current write leader, forward writes there, and repair-sync authority snapshots, revocations, receipts, and budget usage in the background. Hosted HTTP admin APIs proxy to the control service when configured, so receipts, revocations, budgets, and authority status are no longer tied to whichever node happened to execute the request. Authority rotation remains intentionally future-session-only rather than a hot-swap of already running sessions, but trusted key history plus shared-SQLite or control-plane authority snapshots keep already-issued capabilities valid while new sessions converge on the new issuer across nodes without restart.

The remote auth surface also crossed the “real hosted auth server” threshold. `arc mcp serve-http` can now either verify external JWTs or act as its own OAuth authorization server with `GET/POST /oauth/authorize`, `POST /oauth/token`, and `GET /oauth/jwks.json`. The hosted server supports authorization code with `S256` PKCE and `urn:ietf:params:oauth:grant-type:token-exchange`, publishes protected-resource and authorization-server metadata, and enforces scope plus audience/resource binding on the resource-server side.

The honest remaining work is no longer basic HA or token exchange. It is deeper production hardening: resumability and standalone GET/SSE streams on the remote edge, broader hosted-runtime ownership than one subprocess per remote session, richer key hierarchy and attestation policy, dynamic user federation or external IdP integration, and stronger replicated-control semantics than today’s deterministic leader plus repair loop.

Relevant local design doc:

- [spec/PROTOCOL.md](../../spec/PROTOCOL.md)

Examples:

- native stream frames now exist and the runtime now signs streamed receipt metadata with chunk counts, chunk hashes, and total bytes
- the MCP edge can now either emit negotiated chunk notifications or degrade native streamed tool output into one final structured result
- the MCP edge can now return `CreateTaskResult` for task-augmented `tools/call` requests and resolve them through `tasks/result`
- stdio MCP task execution now progresses under sustained traffic on both the outer edge and wrapped nested-task runtime, not only during idle gaps
- remote MCP clients can now initialize over Streamable HTTP, reuse `MCP-Session-Id`, and drive nested sampling over POST plus SSE
- wrapped stdio servers can now issue task-augmented `sampling/createMessage` requests and resolve them through `tasks/get` and `tasks/result`
- wrapped stdio servers can now issue task-augmented form-mode `elicitation/create` requests and resolve them through `tasks/get` and `tasks/result`
- wrapped stdio servers can now broker URL-mode `elicitation/create` and later emit `notifications/elicitation/complete`
- direct and wrapped tool servers can now surface standard `-32042` URL-required outcomes, and native direct tool servers can emit late async completion/change events
- nested child requests now have signed receipts with parent lineage and correct cancelled/incomplete terminal states
- bidirectional tool callbacks are no longer the main blocker; broader concurrent ownership is now the larger workflow gap

### 5. Policy split-brain

The runtime split is mostly closed now.

The repo still has two authoring formats:

- a simple ARC YAML path used by the CLI
- a more ambitious HushSpec path in `arc-policy`

The important change is that both now compile into the same loaded runtime policy path. The remaining issue is product convergence and ergonomics, not a fake compile-then-discard execution path.

Relevant code:

- [crates/chio-control-plane/src/policy.rs](../../crates/chio-control-plane/src/policy.rs)
- [crates/arc-policy/src/compiler.rs](../../crates/chio-policy/src/compiler.rs)

This is still a maturity issue, but it is no longer a runtime integrity problem.

## Current Positioning

ARC today is best understood as:

- a secure agent tool execution kernel
- a capability and receipt protocol core
- a partial MCP hardening layer

ARC today is not yet:

- a complete developer-facing replacement for MCP clients and servers
- a full remote transport protocol with interoperable session semantics
- a finished platform for rich agent workflows

## Immediate Takeaway

The project does not need a new idea.

It needs completion of the protocol envelope around the idea it already has.
