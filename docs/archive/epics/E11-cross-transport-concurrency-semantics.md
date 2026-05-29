# E11: Cross-Transport Concurrency Semantics

## Status

Complete.

The remote `tasks-cancel` conformance gap is closed and regression-covered. `CON-04` is closed across direct/internal, wrapped stdio, and remote HTTP paths. `CON-01` is closed with explicit ownership snapshots, lineage-bearing task state, remote request-stream lease visibility, and related-task terminal metadata. `CON-03` is now closed as well: accepted URL completions and late tool-server notifications are queued in kernel session state, direct/in-process embedders have a session-owned runtime-drain surface, and remote HTTP now proves a wrapped notification can arrive on the session stream after the originating `tools/call` POST has already completed.

## Suggested issue title

`E11: unify tasks, streams, cancellation, and async completion across transports`

## Problem

Chio now supports tasks, streaming, cancellation, nested flows, and late events across multiple paths:

- direct stdio edge
- wrapped stdio edge
- remote HTTP edge
- native direct tool execution

Those features are individually strong, but they do not yet compose under one clearly finished ownership model.

The original symptoms are closed:

- transport ownership is explicit across direct, wrapped, and remote task surfaces
- cancellation semantics are green and regression-covered
- late async completions and late notifications no longer rely on edge-local pending URL maps or request-local bridges surviving by accident

## Outcome

E11 now delivers:

- one ownership model defines who owns active work, streams, and late events across transports
- task, cancellation, and completion semantics stay consistent enough to keep the former remote `tasks-cancel` gap closed
- async completion and notification delivery no longer depend on request-local scratch state
- transport differences remain implementation details, not semantic surprises

## Scope

In scope:

- task lifecycle semantics
- stream ownership and transfer rules
- cancellation race semantics
- durable async completion sources
- late-event delivery rules
- cross-transport conformance and regression coverage

Out of scope:

- remote reconnect transport details owned by E10
- brand-new protocol surfaces unrelated to long-running ownership

## Primary files and areas

- `crates/chio-core/src/session.rs`
- `crates/chio-core/src/message.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-kernel/src/lib.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-mcp-adapter/src/transport.rs`
- `crates/chio-mcp-remote/src/remote_mcp/`
- `crates/chio-cli/tests/mcp_serve.rs`
- `crates/chio-cli/tests/mcp_serve_http.rs`
- `crates/chio-conformance/tests/`

## Proposed implementation slices

### Slice A: ownership model

Requirements:

- define the active owner for work, stream emission, and terminal state updates
- make that model transport-neutral enough to apply everywhere

Responsibilities:

- keep ownership visible in session state
- avoid transport-specific one-off semantics that accumulate over time

### Slice B: task lifecycle unification

Requirements:

- align `tools/call`, `tasks/*`, nested tasks, and late task notifications under one contract
- remove behavior that depends on idle polls or lucky request timing

Responsibilities:

- preserve current interoperability where already green
- close the remaining `tasks-cancel` and race-condition gaps

### Slice C: cancellation and race semantics

Requirements:

- define what cancellation means before start, during execution, during streaming, and after terminal completion
- preserve auditable terminal states across these races

Responsibilities:

- keep cancellation fail-closed
- make receipt outcomes deterministic across transports

### Slice D: async completion and event sources

Requirements:

- give native direct tool paths durable async completion/event sources
- ensure late notifications can be emitted without request-local state surviving accidentally

Responsibilities:

- avoid coupling async completion to one transport loop
- keep late events attributable to the right session and parent work item

## Task breakdown

### `T11.1` Freeze the ownership state machine

- define work-owner, stream-owner, and terminal-owner rules
- map these rules into normalized session state
- document where ownership can transfer and where it cannot

### `T11.2` Remove transport-specific task edge cases

- align task progression across stdio, wrapped stdio, and remote HTTP
- keep the remote `tasks-cancel` conformance lane green while closing the remaining transport-shaped edges
- add regression coverage for concurrent request traffic during background task execution

### `T11.3` Normalize cancellation semantics

- define deterministic cancellation races and resulting receipts
- ensure the same high-level outcome lands across direct and wrapped paths
- preserve parent-child linkage for nested cancellations

### `T11.4` Add durable async completion sources

- harden the direct native path for late async completions and notifications
- make event-source lifecycle explicit and session-owned
- cover late completion after the original request turn has finished

## Dependencies

- depends on E6 and E7
- can overlap with E10 once remote session-lifecycle assumptions are stable enough

## Risks

- rewriting too much transport logic at once
- accidentally regressing already-green conformance slices while chasing edge cases
- making the ownership model so abstract that it is hard to debug

## Mitigations

- freeze a small, explicit state machine first
- prove each change in the transport matrix instead of only in unit tests
- keep ownership data inspectable in session/debug surfaces

## Acceptance criteria

- known long-running semantic gaps in the current docs are closed or explicitly narrowed
- `tasks-cancel` remains green in the remote conformance story
- task, stream, and cancellation receipts are consistent across direct, wrapped, stdio, and remote paths
- late async completion works for native direct providers without relying on request-local bridges

## Definition of done

- implementation merged
- conformance and integration tests prove transport-consistent async semantics
- E14 no longer needs to use "async ownership debt" as a catch-all bucket
