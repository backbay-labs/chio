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

## Current Pain Points

- `src/main.rs` mixes kernel construction, capability issuance, manifest
  construction, stdio serving, bridge-call execution, argument parsing, and
  tests in one binary-only module.
- The smoke script is forced to spawn the process to prove the normal
  `initialize` -> `notifications/initialized` -> `tools/list` -> `tools/call`
  flow, even though `ChioMcpEdge::handle_jsonrpc` supports direct testing.
- The `HelloServer` implementation trusts the caller-selected tool name instead
  of self-defending its own registration boundary. The kernel should already
  route only registered tools, but this example is a protocol-edge reference and
  should model a fail-closed tool server implementation too.
- The bridge-call path and stdio path construct equivalent demo state through
  tuple plumbing, which makes it harder to audit what is shared and what differs
  between the MCP wire path and direct receipt path.

## Security And API Constraints

- Preserve the documented stdio JSON-RPC lifecycle and ready-state contract:
  `initialize`, `notifications/initialized`, then `tools/list` and
  `tools/call`.
- Preserve the server id `hello-mcp-srv`, tool name `hello_tool`, manifest
  schema, capability scope, and receipt-bearing bridge-call behavior.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  or runtime policy paths.
- Preserve MCP JSON-RPC response shape for the smoke script and existing
  captured artifacts.
- Do not change `chio-mcp-edge` public APIs from this example slice.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`, and any
operator running `examples/hello-mcp/smoke.sh`.

No downstream crate should require code changes. If the package split exposes a
Cargo target issue, the fix should stay inside `examples/hello-mcp`.

## Planned Improvement

Move demo state construction, direct JSON-RPC edge helpers, bridge-call
execution, and stdio serving into `src/lib.rs`; leave `src/main.rs` as an
argument/exit wrapper. Add tests that exercise the MCP lifecycle directly
through `ChioMcpEdge::handle_jsonrpc`, prove bridge-call receipt output, and
prove the demo tool server rejects unknown tool names fail-closed. This is
architectural because it separates the protocol-edge contract from process
presentation and gives the example a reusable testable boundary.
