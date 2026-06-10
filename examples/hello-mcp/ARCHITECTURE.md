# hello-mcp Architecture

## Owning Boundary

`examples/hello-mcp` owns the maintained stdio MCP edge teaching example. It
builds a small Chio kernel, registers a single `hello_tool` server, issues the
demo capability, exposes the service through `ChioMcpEdge`, and provides the
companion bridge call that prints the underlying Chio receipt id.

The package depends on public APIs from:

- `chio-mcp-edge` for `ChioMcpEdge` and `McpEdgeConfig`.
- `chio-kernel` for the kernel, tool server trait, tool call request, receipt
  response, and stream defaults.
- `chio-core` for capability grants and generated keypairs.
- `chio-manifest` for the tool manifest projected through `tools/list`.

## Security And API Constraints

- Preserve the documented stdio JSON-RPC lifecycle and ready-state contract:
  `initialize`, `notifications/initialized`, then `tools/list` and
  `tools/call`.
- Preserve the server id `hello-mcp-srv`, tool name `hello_tool`, manifest
  schema, capability scope, and receipt-bearing bridge-call behavior.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  or runtime policy paths.
- As a protocol-edge reference, `HelloServer` self-defends its registration
  boundary and rejects unknown tool names fail-closed even though the kernel
  routes only registered tools.
- Preserve MCP JSON-RPC response shape for the smoke script and existing
  captured artifacts.
- Do not change `chio-mcp-edge` public APIs from this example slice.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`, and any
operator running `examples/hello-mcp/smoke.sh`.

No downstream crate requires code changes for this example.
