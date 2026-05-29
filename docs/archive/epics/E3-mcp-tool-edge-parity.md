# E3: MCP Tool Edge Parity

## Suggested issue title

`E3: add MCP-compatible tool edge on top of the Chio kernel`

## Problem

Chio can currently wrap MCP servers outbound through `chio-mcp-adapter`, but it does not yet expose a first-class MCP-compatible server edge of its own.

That blocks:

- stock MCP client interoperability
- lifecycle negotiation at the edge
- `tools/list` and `tools/call` over current MCP JSON-RPC
- realistic parity testing for the secure edge story

## Outcome

By the end of E3:

- Chio exposes an MCP-compatible tool server edge
- the edge uses the session-aware kernel path introduced in E1
- policy- and capability-mediated tool calls are available to MCP clients

## Scope

In scope:

- MCP lifecycle handshake
- JSON-RPC request/notification helpers
- `tools/list`
- `tools/call`
- pagination support for tool listing
- tool-result translation into MCP result shapes

Out of scope:

- resources, prompts, and completion
- roots, sampling, and elicitation
- long-running tasks beyond metadata shaping
- dynamic tool registry updates

## Primary files and areas

- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-mcp-adapter/src/lib.rs`
- `crates/chio-mcp-adapter/src/transport.rs`
- `crates/chio-cli/src/main.rs`

## Proposed implementation slices

### Slice A: in-process MCP edge runtime

Candidate types:

- `ChioMcpEdge`
- `McpEdgeConfig`
- `McpExposedTool`

Responsibilities:

- own MCP session state
- map JSON-RPC lifecycle to kernel sessions
- map tool names to server/tool bindings

### Slice B: tool listing and pagination

Requirements:

- flatten manifests into MCP tool descriptors
- support `cursor` and `nextCursor`
- fail on duplicate exposed tool names

### Slice C: tool invocation translation

Requirements:

- translate `tools/call` params into `SessionOperation::ToolCall`
- map allow/deny/internal outcomes into MCP tool results
- preserve structured content when tool results are JSON objects

### Slice D: runtime entry point

Requirements:

- add a real CLI path that serves the MCP edge over stdio
- allow wrapping an MCP server subprocess end to end
- validate stock client style interaction with an integration test

## Task breakdown

### `T3.1` Add MCP edge runtime

- add in-process JSON-RPC dispatcher
- add lifecycle state and initialize handshake
- require `notifications/initialized` before tool operations

### `T3.2` Add listing parity

- expose tool metadata from manifests
- add pagination
- add tests for cursor flow

### `T3.3` Add invocation parity

- translate kernel responses to MCP result objects
- return `isError: true` for policy/tool denials
- add structured-content translation tests

### `T3.4` Align MCP versioning

- update stdio transport handshake to the current MCP protocol version
- add regression coverage around initialization

### `T3.5` Add a user-facing MCP serve path

- add `chio mcp serve`
- wrap an MCP server subprocess through the adapter and kernel
- add an integration test that initializes, lists tools, and calls tools through the binary

## Dependencies

- depends on E1 session foundation
- depends on E2 canonical policy/runtime wiring for useful capability issuance

## Risks

- overfitting the edge to the current static manifest model
- flattening multiple servers into one MCP namespace without a collision strategy
- returning malformed MCP result shapes for structured tool outputs

## Mitigations

- make duplicate tool names fail fast
- keep the first edge static and explicit rather than auto-merging conflicting names
- add result-shape tests for text and structured JSON outputs

## Acceptance criteria

- an MCP client can initialize against the edge
- `tools/list` returns paginated tool descriptors
- `tools/call` flows through the kernel session path
- denied tool calls return MCP tool errors instead of transport failures
- a stock client can use `chio mcp serve` as a secured MCP proxy

## Definition of done

- implementation merged
- tests added for lifecycle, pagination, and tool result translation
- binary-level coverage added for the CLI-served MCP edge
- docs and roadmap remain accurate
