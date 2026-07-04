# ADR-0001: Edge Protocol Shape

- Status: Proposed
- Decision owner: protocol lane

## Context

Chio currently uses a custom framed canonical-JSON transport between agent and kernel.

That is acceptable internally, but it is not sufficient for real MCP replacement. The external ecosystem already expects:

- JSON-RPC request and notification semantics
- lifecycle initialization
- feature negotiation
- client and server capabilities

There are two plausible directions:

1. Use JSON-RPC end to end inside the runtime.
2. Expose JSON-RPC only at the edge and translate it into a normalized internal session model.

## Decision

Chio will use:

- JSON-RPC at the public edge
- a normalized internal session model beneath the edge

The external MCP-facing layer will parse JSON-RPC and map it into internal session operations. The kernel will not become JSON-RPC-specific.

## Rationale

This preserves:

- interoperability at the edge
- a smaller, enforcement-oriented kernel core
- freedom to use optimized internal representations without forcing them onto clients

It also avoids the opposite failure modes:

- a pure custom external protocol with poor adoption
- a kernel polluted with transport and JSON-RPC concerns

## Consequences

### Positive

- existing MCP clients can be supported without teaching the kernel JSON-RPC directly
- edge transport changes do not necessarily force kernel changes
- internal operations can remain stable across stdio, HTTP, or future transports

### Negative

- there is a translation layer to maintain
- debugging may need better observability because the edge and core are separate
- errors must be mapped carefully between JSON-RPC and Chio internal errors

## Required follow-up

- define `SessionOperation` and `OperationContext`
- add a session abstraction before building the MCP edge
- document transport-level errors versus kernel-level denials

## Non-goals

- replacing the internal framed transport immediately
- committing to a native public Chio wire protocol before `v1`
