# E10: Remote Runtime Hardening

## Status

Complete.

The hosted runtime now has:

- an explicit reconnect contract for `ready` sessions
- standalone GET `/mcp` SSE with bounded retained-notification replay
- an opt-in shared wrapped-host owner via `--shared-hosted-owner`
- deterministic session lifecycle cleanup with idle expiry, drain grace, and tombstone retention
- admin diagnostics at `/admin/sessions` plus per-session trust details for active and terminal sessions
- tunable lifecycle controls via `CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS`, `CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS`, and `CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS`

The conservative deployment default is still one wrapped subprocess per session, but the hosted runtime now also has an opt-in shared owner path. The remaining work in adjacent epics is broader async/concurrency normalization rather than an open E10 lifecycle gap.

## Suggested issue title

`E10: harden the remote MCP runtime for reconnects, resumability, and hosted ownership`

## Problem

Chio now ships a credible remote MCP edge over authenticated Streamable HTTP.

That is a major milestone, but it is not yet deployment-hard.

The remaining gaps are:

- resumability
- standalone GET/SSE streams
- reconnect, stale-session cleanup, and shutdown ownership rules
- broader hosted-runtime ownership than one wrapped subprocess per remote session

Without those, Chio remains convincing for controlled demos and harnesses but still weaker than a production-grade hosted runtime should be.

The first hardening slice should freeze one explicit reconnect contract before adding new stream surfaces:

- `initialize` is the only way to allocate a new remote session id
- a session id is reusable only while the hosted runtime still considers that session `ready`
- reconnect or reattach attempts must preserve the original authenticated session identity
- `draining`, `deleted`, `expired`, and `closed` sessions are terminal and require a fresh `initialize`
- standalone GET/SSE replay belongs to the next slice, not to the initial lifecycle contract

## Outcome

By the end of E10:

- remote sessions support a defined reconnect and resume model
- GET-based SSE support exists where the compatibility surface expects it
- stale-session, drain, and shutdown rules are explicit and test-covered
- operators can inspect active and terminal session lifecycle state through admin diagnostics
- hosted runtime ownership is broader and more scalable than a one-subprocess-per-session default

## Scope

In scope:

- Streamable HTTP resumability
- standalone GET/SSE stream handling
- remote session leases, expiry, reconnect, and drain rules
- hosted worker ownership model
- remote operator observability for session lifecycle, reconnect state, and terminal tombstones

Out of scope:

- new identity-provider federation models
- consensus trust-plane design
- SDK ergonomics outside what is needed for hosted runtime operability

## Primary files and areas

- `crates/chio-mcp-remote/src/remote_mcp/`
- `crates/chio-mcp-adapter/src/transport.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-core/src/session.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-cli/tests/mcp_serve_http.rs`
- `crates/chio-conformance/tests/`
- `docs/HA_CONTROL_AUTH_PLAN.md`

## Proposed implementation slices

### Slice A: remote resume contract

Requirements:

- define how clients resume a live remote session
- define which requests, tasks, and streams are resumable versus terminal

Responsibilities:

- keep the contract explicit at the transport boundary
- avoid inventing a resume model that conflicts with MCP expectations

### Slice B: GET/SSE and stream ownership

Requirements:

- support standalone GET-based SSE streams
- define when POST and GET stream owners may coexist, transfer, or supersede each other

Responsibilities:

- make stream ownership rules compatible with long-running tasks and late events
- prevent duplicate or ambiguous event delivery

### Slice C: hosted ownership model

Requirements:

- reduce dependence on one wrapped subprocess per remote session
- define a broader hosted-runtime ownership strategy for wrapped and native providers

Responsibilities:

- preserve current kernel/session semantics
- improve scalability without weakening isolation or auditability

### Slice D: lifecycle hardening

Requirements:

- define stale-session cleanup, server-driven drain, reconnect windows, and shutdown semantics
- expose enough status for operators to understand active versus recoverable sessions

Responsibilities:

- make cleanup deterministic
- avoid reconnect behavior that accidentally revives expired trust state

## Task breakdown

### `T10.1` Specify resumability and reconnect behavior

- write the remote resume contract
- freeze the initial hosted-session lifecycle (`initializing`, `ready`, `draining`, `deleted`, `closed`, later `expired`)
- define the initial reconnect mode as authenticated session reuse while the session remains `ready`
- define resumable session identifiers, event windows, and non-resumable terminal states
- document how resumed sessions interact with capabilities and session auth context

### `T10.2` Add GET/SSE stream support

- implement standalone GET-based event streaming where required
- align POST and GET stream behavior for initialization, tasks, and late async events
- add remote transport tests for reconnect and stream handoff

### `T10.3` Expand hosted ownership model

- define runtime ownership beyond one subprocess per session
- support broader worker or provider ownership without losing session isolation
- validate behavior for wrapped and native provider paths

### `T10.4` Add lifecycle and operator coverage

- test stale-session cleanup, reconnect windows, and drain behavior
- expose session lifecycle diagnostics in admin or debug surfaces
- update hosted-runtime docs with operational expectations

## Dependencies

- depends on E7
- should follow E9 far enough that clustered trust assumptions are reliable
- can overlap with E11 once the remote lifecycle contract is clear

## Risks

- adding a resume model that conflicts with actual MCP client expectations
- introducing broader hosted ownership that leaks state across sessions
- making reconnect rules so complex that operators cannot reason about them

## Mitigations

- keep the session lifecycle contract small and explicit
- test reconnect semantics through live peers, not only unit abstractions
- preserve strict auth-context and capability checks across resumed sessions

## Acceptance criteria

- remote sessions can reconnect or resume according to one documented contract
- GET-based SSE coverage exists and passes against the remote harness
- stale-session and shutdown behavior are deterministic and test-covered
- admin diagnostics expose enough session lifecycle state to distinguish draining, deleted, expired, and closed sessions
- hosted runtime ownership no longer requires the current one-subprocess-per-session shape for all serious deployments

## Definition of done

- implementation merged
- remote hosting docs describe resumability, stream ownership, and lifecycle behavior clearly
- later epics can depend on the remote runtime as an operational substrate rather than a feature demo
