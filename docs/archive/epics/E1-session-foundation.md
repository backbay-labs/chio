# E1: Session Foundation

## Suggested issue title

`E1: add session model and normalized internal operations`

## Problem

Chio currently has transport primitives and tool-call logic, but no first-class session abstraction. That blocks:

- lifecycle negotiation
- cancellation
- progress
- subscriptions
- nested request lineage
- clean JSON-RPC edge integration

## Outcome

By the end of E1:

- the runtime has a session abstraction
- requests are normalized before enforcement
- the kernel can host future MCP edge work without raw transport glue leaking through

## Scope

In scope:

- session IDs and request IDs
- session state model
- in-flight request registry
- normalized `SessionOperation` and `OperationContext`
- separation of internal frame transport from higher-level request handling

Out of scope:

- full MCP JSON-RPC edge
- resources and prompts
- sampling and elicitation
- durable trust services

## Primary files and areas

- `crates/chio-core/src/`
- `crates/chio-kernel/src/`
- possible new `crates/chio-kernel/src/session/`

## Proposed implementation slices

### Slice A: core session identifiers and operation types

Candidate files:

- `crates/chio-core/src/session.rs`
- `crates/chio-core/src/lib.rs`

Proposed types:

- `SessionId`
- `RequestId`
- `ProgressToken`
- `SessionOperation`
- `OperationContext`

### Slice B: kernel session module

Candidate files:

- `crates/chio-kernel/src/session/mod.rs`
- `crates/chio-kernel/src/session/lifecycle.rs`
- `crates/chio-kernel/src/session/inflight.rs`
- `crates/chio-kernel/src/session/cancellation.rs`
- `crates/chio-kernel/src/session/progress.rs`

### Slice C: transport boundary cleanup

Candidate files:

- `crates/chio-kernel/src/transport.rs`
- `crates/chio-cli/src/main.rs`

Goal:

- make transport framing feed session-aware handling rather than directly owning the behavioral contract

## Task breakdown

### `T1.1` Define session identity and state

- add session-related IDs and state enums
- define ready/init/draining/closed state shape

### `T1.2` Define normalized operations

- introduce `SessionOperation`
- introduce `OperationContext`
- ensure types are not tool-only by naming

### `T1.3` Add in-flight registry

- add request start/completion tracking
- track progress token and cancellable flag

### `T1.4` Add kernel session host object

- add session creation
- add session teardown
- make request handling session-aware

### `T1.5` Add initial tests

- session lifecycle tests
- in-flight registry tests
- request correlation tests

## Dependencies

- depends on ADR-0001

## Risks

- over-designing session internals before the MCP edge exists
- placing JSON-RPC concepts too deep into the kernel

## Mitigations

- keep JSON-RPC identifiers at the edge-facing boundary
- keep kernel types generic enough to support non-MCP frontends later

## Acceptance criteria

- a session object exists and is test-covered
- kernel request handling can attach to a session context
- internal operations are defined independently of raw transport messages
- future progress and cancellation work has stable state holders to build on

## Definition of done

- implementation merged
- tests added
- `docs/EXECUTION_PLAN.md` remains accurate
- any new public types are documented
