# E7: Trust Plane and Remote Runtime

## Status

Core shipped.

Slice A is now partially shipped:

- `chio mcp serve-http` exposes a first authenticated remote MCP edge over Streamable HTTP
- remote sessions are isolated per `MCP-Session-Id`
- multiple remote sessions can coexist concurrently
- remote `tools/list`, `tools/call`, tasks, and nested sampling flows now work through the HTTP edge
- transport admission now enforces JSON request bodies plus `Accept: application/json, text/event-stream`
- session IDs are only surfaced after a successful `initialize` response
- normalized session auth context is now attached to kernel session state, separate from capability authorization

Slice C is now partially shipped too:

- `chio-kernel` has a SQLite receipt backend for signed tool and child-request receipts
- the CLI now exposes that through `--receipt-db`
- the CLI/runtime paths now also expose durable revocation through `--revocation-db`
- `chio-kernel` also has a SQLite revocation backend and a pluggable capability-authority interface with a local implementation
- the CLI now has a first local operator-facing trust control surface via `chio trust revoke` and `chio trust status`
- the hosted HTTP runtime now has remote trust-admin surfaces for receipt queries, arbitrary capability revocation, per-session trust revocation, and authority status/rotation
- restart-proof kernel tests now validate durable revocation enforcement and durable receipt persistence

The distributed-control rewrite is now shipped as the next E7 slice:

- `chio trust serve` now exposes a shared authenticated trust-control service over HTTP
- the service centralizes capability issuance, authority status/rotation, revocation query/control, and durable tool/child receipt ingestion and query
- `run`, `check`, `mcp serve`, and `mcp serve-http` can all now use that service through `--control-url` and `--control-token`
- hosted HTTP admin APIs now proxy to the control service when configured instead of reading only local SQLite files
- authority verification now uses trusted key history instead of only the current key, so future-session rotation does not invalidate existing capabilities
- remote authority clients now refresh trusted-key state on a short TTL so rotated issuers propagate across nodes without process restart
- distributed tests now prove centralized receipts, cross-node revocation enforcement, and future-session authority rotation across hosted nodes

The main remaining E7 work is no longer “is there a shared control plane at all?” It is deeper hardening beyond the shipped baseline: resumable remote transports, broader hosted-runtime ownership, richer key lifecycle policy, and stronger federation/integration around the hosted auth server.

This is now the dominant blocker for a true MCP replacement story.

Preconditions already in place:

- stdio MCP edge parity is materially strong across tools, resources, prompts, completion, logging, roots, sampling, elicitation, tasks, cancellation, and background notifications
- canonical runtime policy loading exists
- explicit receipts exist for tool outcomes and nested child requests

What is still missing:

- hardened remote hosting beyond the current POST/SSE slice, including resumability and standalone GET/SSE streams
- broader hosted-runtime ownership instead of one wrapped subprocess per remote session
- richer deployment-grade identity binding between manifests, sessions, and server keys
- stronger key hierarchy, attestation, and multi-region replication semantics on the trust plane
- richer external identity-provider and federation support around the hosted authorization server

## Suggested issue title

`E7: implement authenticated remote runtime and trust services`

## Problem

Chio can now look convincing as a local or wrapped stdio MCP replacement, but it is not yet credible as a remote deployment target.

That blocks:

- hosted MCP-compatible Chio servers
- authenticated remote sessions
- durable audit and revocation guarantees
- production adoption beyond local subprocess mediation

## Outcome

By the end of E7:

- Chio can host an authenticated remote MCP edge
- session authentication and action authorization are cleanly separated
- revocation and receipt durability survive process restarts
- remote sessions preserve the same kernel enforcement guarantees as local ones

## Scope

In scope:

- remote MCP edge transport
- session authentication and auth context plumbing
- multi-client hosting model
- persistent receipt store
- service-backed revocation and capability authority interfaces
- identity binding between manifests, sessions, and keys

Out of scope:

- cross-language compatibility publishing
- native authoring SDK ergonomics
- release-candidate performance tuning

## Primary files and areas

- new remote edge crate or modules
- `crates/chio-mcp-adapter`
- `crates/chio-kernel`
- `crates/chio-core`
- trust-service crates if added
- `docs`

## Sequencing note

The first slice inside E7 should front-load remote HTTP/auth, not wait for the entire trust plane to be perfect.

Reason:

- remote hosting is now the clearest product gap versus mature MCP runtimes
- it unlocks real deployment and interop work for E8
- trust services can then harden that runtime instead of being designed in a vacuum

## Proposed implementation slices

### Slice A: remote MCP edge

Requirements:

- streamable HTTP or equivalent MCP-compatible remote edge
- per-session state keyed outside a single stdio loop
- explicit lifecycle ownership for reconnect, stale session handling, and shutdown

Responsibilities:

- keep the current normalized kernel/session model
- avoid coupling remote hosting to a single transport-specific state machine

### Slice B: session auth

Requirements:

- authenticated session establishment
- auth context attached to session state
- clear separation between transport/session auth and capability-based action auth

Responsibilities:

- support local development mode first
- leave room for OAuth or other protected-server models later

Current status:

- normalized `SessionAuthContext` types now exist
- MCP edge initialization now stamps configured auth context onto kernel sessions
- the remote HTTP edge now records both static-bearer and signed JWT bearer session admission separately from capability authorization
- JWT admission now normalizes OAuth-style session identity and supports separate admin-token protection for remote control APIs
- JWT mode now serves protected-resource metadata and `WWW-Authenticate` discovery challenges for clients
- colocated JWT issuers can now also expose OAuth authorization-server metadata from the hosted edge when explicit authorization/token endpoints are configured
- the remaining work in this slice is richer external auth integration and federation, not the base plumbing

### Slice C: durable trust plane

Requirements:

- persistent receipt store
- persistent revocation backend
- capability authority interface with local implementation first
- key rotation scaffolding

Responsibilities:

- preserve current receipt signatures and hashes
- make durability verifiable by tests, not just by docs

Current status:

- SQLite receipt persistence is shipped in `chio-kernel`
- receipt durability is validated through kernel and CLI tests
- SQLite revocation persistence plus local and shared-SQLite pluggable capability authorities are now shipped in the kernel
- deployment wiring for those local stores now reaches `run`, `check`, `mcp serve`, and `mcp serve-http`
- the CLI now exposes the first local trust administration surface via `chio trust`
- `--authority-seed-file` now pins issuance identity across runtime restarts and hosted sessions
- `--authority-db` now allows future-session authority rotation to propagate across hosted nodes that share the same SQLite backend
- the hosted HTTP runtime now exposes remote trust administration for receipt queries, arbitrary revocation query/control, per-session trust revocation, and authority status/rotation
- `chio trust serve` now exposes a shared HTTP trust-control service that centralizes capability issuance, authority status/rotation, revocation query/control, and durable receipt ingestion/query
- all CLI/runtime paths can now use that service through `--control-url` and `--control-token`
- hosted admin APIs now proxy to that service when configured
- authority rotation is currently scoped to future sessions only, but trusted key history is now preserved so already-issued capabilities remain valid after rotation
- the remaining work is richer key lifecycle policy, stronger replicated-control semantics than the current deterministic leader plus repair-sync cluster, and broader control state beyond the current shared invocation budgets

## Task breakdown

### `T7.1` Remote MCP edge

- implement remote JSON-RPC hosting compatible with the MCP edge surface already shipped on stdio
- support multiple concurrent sessions
- define session lifecycle and stale-session handling

### `T7.2` Auth context plumbing

- introduce normalized session auth context types
- bind session identity to edge/session state
- keep action authorization separate and kernel-driven

### `T7.3` Persistent receipt backend

- add a SQLite receipt store first
- preserve append-only semantics at the application layer
- support later verification and ops queries

### `T7.4` Revocation and capability authority

- define issuance/revocation interfaces
- provide local service-backed implementations first
- add key rotation scaffolding and manifest identity binding

## Reference patterns

Useful references to study, not copy blindly:

- RMCP streamable HTTP transport slices
- RMCP transport-hardening tests for stale sessions and reserved headers
- MCP authorization model for protected HTTP transports

Chio should copy the shape of the solution where it helps, but keep its own kernel-mediated authority and receipt model.

## Dependencies

- depends on E3 MCP tool edge parity
- depends on E4 resources/prompts/completion/logging
- depends on E5 nested flows
- depends on E6 long-running operation semantics

## Risks

- smearing session auth and capability auth together
- rebuilding remote runtime logic separately from the current edge/session substrate
- making the receipt store mutable in ways that weaken auditability

## Mitigations

- normalize auth context once and pass it through session state
- reuse the existing kernel/session operation path under the remote edge
- keep receipt persistence append-only by design

## Acceptance criteria

- a remote MCP client can initialize, call tools, use nested flows, and retrieve task results through Chio
- multiple sessions can coexist without corrupting in-flight ownership
- authenticated remote sessions preserve capability checks and receipt issuance
- revocation and receipts survive process restart
- manifest and session identity bindings are explicit enough to support later attestation work

## Definition of done

- remote edge implementation merged
- auth context types and session plumbing merged
- SQLite receipt backend merged
- initial revocation and capability authority services merged
- HA control cluster, shared budgets, and hosted auth-server implementation merged
- remote and distributed acceptance tests added and passing
