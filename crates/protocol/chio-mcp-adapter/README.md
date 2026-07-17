# chio-mcp-adapter

Wraps an existing MCP (Model Context Protocol) server as a Chio tool server. The
underlying MCP tools, resources, and prompts keep working unchanged while every
call gains Chio capability tokens, guard evaluation, and signed receipts. The
crate also carries a native authoring surface for building a Chio tool server
in-process rather than adapting an external one.

Use it to bring an existing MCP surface under Chio's capability, guard, and
receipt model without rewriting the server. MCP hosting itself lives in
`chio-mcp-edge`; this crate adapts and governs, it does not host.

## Responsibilities

- Present an adapted MCP server to the kernel as a `ToolServerConnection`
  (`AdaptedMcpServer`), forwarding tool calls, resources, and prompts.
- Project MCP tool metadata into Chio `ToolDefinition`s, preserving MCP
  annotation semantics (safety hints, `destructiveHint`).
- Frame and route stdio JSON-RPC to the upstream server with bounded reads,
  notification buffering, nested-flow handling, and cancellation.
- Admit and validate URL-required elicitations before the kernel stores pending
  session state.
- Provide `NativeChioServiceBuilder` for authoring an in-process tool server
  with the same manifest and result contracts.

## Public API

- `adapter::{McpAdapter, McpAdapterConfig, SerializedMcpTransport}` - configure
  and share an upstream MCP transport.
- `server::AdaptedMcpServer` - the kernel-facing tool server.
- `transport::StdioMcpTransport` - stdio JSON-RPC transport to a child MCP process.
- `native::NativeChioServiceBuilder` - in-process native authoring surface.
- `resources::AdaptedMcpResourceProvider`, `prompts::AdaptedMcpPromptProvider`.
- `edge::*` - re-exported MCP edge contracts (`McpToolInfo`, `McpTransport`, ...).

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Exposes `fuzz`, the libFuzzer entry point for the MCP envelope parse path. Off by default; pulls in `arbitrary`. Enabled only by the standalone `fuzz` workspace. |

## Testing

`cargo test -p chio-mcp-adapter`

## See also

- `chio-mcp-edge` - the MCP hosting runtime; this adapter wraps and governs it.
- `chio-kernel` - consumes `AdaptedMcpServer` as a governed tool server.
- `chio-mcp-remote`, `chio-hosted-mcp` - remote and hosted MCP surfaces built on this adapter.
