# E4: Resources, Prompts, Completion, and Logging

## Status

Implemented for the kernel, in-process MCP edge, and wrapped-subprocess `chio mcp serve` path.

Delivered:

- first-class resource and prompt grants in the scope model
- kernel provider traits and session operations for resources, prompts, and completion
- MCP edge support for `resources/*`, `prompts/*`, `completion/complete`, and `logging/setLevel`
- wrapped MCP subprocess support for resources, prompt retrieval, and completion when the upstream server advertises those features

Deferred follow-ons:

- resource subscriptions and change notifications
- prompt change notifications
- passthrough of upstream MCP logging notifications

## Suggested issue title

`E4: add first-class MCP resources, prompts, completion, and logging support`

## Problem

Chio now has a usable MCP tool edge, but it still cannot host the broader contextual server surface that real MCP deployments expect.

That blocks:

- resource-oriented MCP servers
- prompt-template MCP servers
- argument completion flows
- structured server logging parity

## Outcome

By the end of E4:

- Chio exposes first-class resources and prompts
- resources and prompts are mediated by policy and capabilities, not disguised as tools
- the MCP edge can advertise and serve `resources/*`, `prompts/*`, completion, and logging

## Scope

In scope:

- provider traits for resources and prompts
- resource listing and reading
- prompt listing and retrieval
- completion handlers for prompt arguments and resource templates
- structured logging notifications at the MCP edge
- capability grant shapes for resources and prompts

Out of scope:

- roots, sampling, and elicitation
- task-augmented execution
- long-running task streaming
- persistent logging backends

## Primary files and areas

- `crates/chio-core/src/session.rs`
- `crates/chio-kernel/src/lib.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-cli/src/policy.rs`

## Proposed implementation slices

### Slice A: runtime surface expansion

Candidate additions:

- `SessionOperation::ListResources`
- `SessionOperation::ReadResource`
- `SessionOperation::ListPrompts`
- `SessionOperation::GetPrompt`
- completion and logging operation types

Responsibilities:

- keep tools, resources, and prompts distinct in the kernel
- preserve a normalized internal operation model under the JSON-RPC edge

### Slice B: provider traits

Candidate traits:

- `ResourceProvider`
- `PromptProvider`
- `CompletionProvider`
- lightweight logging emitter interface

Responsibilities:

- avoid piggybacking non-tool MCP features on `ToolServerConnection`
- make static and dynamic providers testable in-process

### Slice C: edge parity

Requirements:

- advertise `resources`, `prompts`, `completions`, and `logging` capabilities
- implement `resources/list`, `resources/read`, `prompts/list`, `prompts/get`
- add completion request handling and logging notifications
- bridge wrapped-subprocess resources/prompts/completion into the same kernel path used by in-process providers

## Task breakdown

### `T4.1` Add resource and prompt session operations

- extend session operations and responses
- add kernel entry points and state handling
- add tests for lifecycle and response typing

### `T4.2` Add provider traits and registry wiring

- introduce provider traits beside `ToolServerConnection`
- allow kernel registration of resource and prompt providers
- keep provider ownership and dispatch explicit

### `T4.3` Add capability shapes for resources and prompts

- widen the scope model beyond tool grants
- ensure policy loading can materialize the new grant types
- keep deny behavior fail-closed when grants are missing

### `T4.4` Add MCP edge support

- implement MCP handlers for resources, prompts, completion, and logging
- add pagination and list-changed notification support where appropriate
- add result-shape regression tests

## Dependencies

- depends on E1 session foundation
- depends on E2 canonical policy runtime
- depends on E3 MCP tool edge parity
- depends on D2 scope evolution timing

## Risks

- leaking tool-only assumptions into resources and prompts
- widening the capability model in a way that forces an E1-style rewrite
- overfitting the kernel to MCP naming instead of keeping a stable internal model

## Mitigations

- introduce generic grant categories rather than bolting more fields onto `ToolGrant`
- keep provider traits narrow and explicit
- test kernel operations independently of JSON-RPC edge behavior

## Acceptance criteria

- an MCP client can list and read resources through Chio
- an MCP client can list and fetch prompts through Chio
- completion requests are routed without abusing tool semantics
- logging notifications can be emitted without corrupting request/response flow
- `chio mcp serve` exposes wrapped resources, prompts, and completion when the upstream MCP server supports them

## Definition of done

- implementation merged
- tests added for kernel operations and MCP edge behavior
- policy and scope docs updated for non-tool grants
