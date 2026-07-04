# ADR-0005: MCP Edge Runtime Location

- Status: Proposed
- Decision owner: protocol and interop lanes

## Context

The repository already contains `chio-mcp-adapter`, which wraps MCP servers for use under Chio.

As Chio grows an MCP-compatible public edge, there are two choices:

1. keep extending `chio-mcp-adapter` until it becomes the MCP edge runtime
2. keep `chio-mcp-adapter` focused on migration and create a separate MCP edge runtime

## Decision

Chio will keep `chio-mcp-adapter` focused on migration and adaptation of upstream MCP servers.

Chio will add a separate MCP edge runtime module or crate for first-class MCP-compatible hosting.

## Rationale

These are different responsibilities:

- the adapter translates and wraps foreign MCP servers
- the edge runtime hosts Chio itself as an MCP-compatible endpoint

Merging them would blur concerns and make both paths harder to reason about.

## Consequences

### Positive

- clearer ownership boundaries
- easier testing of hosted edge behavior versus wrapped-server behavior
- more maintainable long-term architecture

### Negative

- one more module or crate to maintain
- some duplicated MCP-shaped types may need careful factoring

## Required follow-up

- define which MCP-shaped types live in shared core/edge compatibility code
- keep adapter tests distinct from edge-runtime tests
- document when to use the adapter versus the hosted edge

## Guideline

If a change primarily helps Chio host itself as an MCP-compatible endpoint, it belongs in the edge runtime.

If a change primarily helps wrap an existing MCP server under Chio, it belongs in the adapter.
