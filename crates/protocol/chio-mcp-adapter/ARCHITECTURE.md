# chio-mcp-adapter architecture

## Overview

The adapter is an untrusted edge component. It speaks MCP to an upstream server
on one side and the Chio `ToolServerConnection` contract to the kernel on the
other, so the kernel mediates every wrapped call. Module boundaries stay
distinct at the crate root (`lib.rs` does not flatten them) to keep the edge,
native, transport, framing, and manifest surfaces separable. Hosting behavior is
deliberately absent; it belongs to `chio-mcp-edge`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the public modules and re-exports MCP edge contracts under `edge`. |
| `src/adapter.rs` | `McpAdapterConfig`, `McpAdapter`, and `SerializedMcpTransport` (shared upstream transport). |
| `src/server.rs` | `AdaptedMcpServer` and its kernel `ToolServerConnection` implementation. |
| `src/transport.rs` (+ `transport/`) | Stdio JSON-RPC routing, bounded frame reads, initialization, notification buffering, nested-flow handling, cancellation. |
| `src/framing.rs` | MCP stdio frame decoding (newline delimiter, size, UTF-8, JSON), shared by the transport and the fuzz entry point. |
| `src/manifest.rs` | Projection from `McpToolInfo` into Chio `ToolDefinition`, schema validation, annotation-to-side-effect translation. |
| `src/result_mapping.rs` | Wrapped MCP tool-result normalization. |
| `src/resources.rs` / `src/prompts.rs` | Resource and prompt provider forwarding, including completion. |
| `src/url_elicitation.rs` | URL-required elicitation admission and validation. |
| `src/errors.rs` | Adapter-error to kernel-error mapping. |
| `src/native.rs` | `NativeChioServiceBuilder` and in-process tool/resource/prompt handlers. |
| `src/loaded_weights.rs` | Explicit "unavailable" model-weights implementation for MCP surfaces. |
| `src/fuzz.rs` | Feature-gated MCP envelope parse entry point for the fuzz workspace. |

## Framing and routing

MCP stdio is newline-delimited JSON-RPC. `framing.rs` decodes one frame at a
time and enforces the delimiter, a maximum frame size, UTF-8, and JSON parse in
one place. The production transport and the fuzz entry point both route through
it, so fuzz coverage matches the production parse boundary. `SerializedMcpTransport`
shares a single upstream transport across Chio sessions; every call that touches
the shared transport (including `drain_notifications`) passes through
`with_request_gate`, while immutable `capabilities()` reads stay ungated to avoid
deadlock on cached reads.

## Trust invariants and failure modes

- The stdio reader rejects EOF before the newline delimiter for a non-empty
  frame: a delimiterless final object is not a complete frame. `read_bounded_line`
  also enforces the maximum frame size.
- Manifest projection preserves MCP annotation semantics: missing or malformed
  safety hints imply side effects, and `destructiveHint=true` overrides
  `readOnlyHint=true`.
- Result normalization inserts `isError: false` only when an MCP-shaped success
  omits it, matching `chio-mcp-edge`'s `value_to_tool_result`. Explicit upstream
  `isError` values and content bytes are preserved.
- `url_elicitation.rs` maps upstream `-32042` errors to
  `KernelError::UrlElicitationsRequired`, validates each operation's `message`,
  `url`, and `elicitationId`, and rejects empty or padded identifiers and
  non-HTTP(S) or userinfo-bearing URLs. Form-mode and mixed-mode elicitations are
  rejected on the wrapped-tool path.
- The crate fails closed on malformed upstream metadata, JSON-RPC parse errors,
  transport failures, nested-flow denials, and cancellation.

## Dependencies

`chio-kernel` supplies the `ToolServerConnection` contract and kernel error
types. `chio-mcp-edge` supplies the MCP protocol runtime and the contracts
re-exported under `edge`. `chio-manifest` supplies `ToolDefinition`. The
`chio-core` dependency is aliased to `chio-core-types`. `tokio`, `async-trait`,
and `tracing` support the async transport.

## Extension points

`NativeChioServiceBuilder` is the authoring surface for an in-process tool
server: register tool, resource, and prompt handlers and emit a manifest without
adapting an external MCP process.
