# hello-acp Architecture

## Owning Boundary

`examples/hello-acp` owns the maintained ACP protocol-edge teaching example. It
builds a small Chio kernel, registers one streaming-capable `hello_tool`,
projects that tool through `ChioAcpEdge`, and serves line-based JSON-RPC
requests for `session/list_capabilities`, authoritative `tool/invoke`, and the
deferred `tool/stream` plus `tool/resume` lifecycle.

The package depends on public APIs from:

- `chio-acp-edge` for `ChioAcpEdge`, `AcpEdgeConfig`, and
  `AcpKernelExecutionContext`.
- `chio-kernel` for kernel construction, the tool-server trait, streaming
  output types, and stream bounds.
- `chio-core` for generated keypairs and capability grants.
- `chio-manifest` for the tool manifest projected into ACP capability
  advertisements.

## Current Pain Points

- `src/main.rs` mixes manifest construction, kernel setup, capability issuance,
  JSON-RPC serving, argument parsing, and tests in one binary-only module.
- The smoke script proves the process path, but the package has no direct test
  for the ACP JSON-RPC lifecycle even though `ChioAcpEdge::handle_jsonrpc` is a
  synchronous package boundary.
- `HelloToolServer` ignores the selected tool name for both blocking and
  streaming calls. The kernel should route only registered tools, but the
  example should still model a self-defensive fail-closed tool server.
- The important teaching contract is that `tool/stream` creates a
  receipt-pending deferred task and `tool/resume` resolves it through the
  receipt-bearing kernel path. Today that is only asserted by the smoke script.

## Security And API Constraints

- Preserve the server id `hello-acp-srv`, capability/tool id `hello_tool`,
  capability scope, and receipt-bearing terminal metadata.
- Preserve the documented JSON-RPC flow: `session/list_capabilities`,
  `tool/invoke`, `tool/stream`, and `tool/resume`.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  approval, runtime assurance, or cross-protocol orchestration paths.
- Preserve deferred task ownership semantics and the `receiptPending` metadata
  on working task responses.
- Do not change `chio-acp-edge` public APIs from this example slice.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`,
`examples/run-hello-smokes.sh`, and any operator running
`examples/hello-acp/smoke.sh`.

No downstream crate should require code changes. If the package split exposes a
Cargo target issue, the fix should stay inside `examples/hello-acp`.

## Planned Improvement

Move demo state construction, capability-listing support, JSON-RPC serving, and
mode dispatch into `src/lib.rs`; leave `src/main.rs` as a thin process wrapper.
Add tests that exercise the authoritative ACP list/invoke/stream/resume
lifecycle directly through `ChioAcpEdge::handle_jsonrpc`, prove stdio response
framing, and prove the demo tool server rejects unknown tool names on both
blocking and streaming paths. This is architectural because it separates the ACP
edge contract from process presentation and makes the deferred receipt lifecycle
a package-local invariant.
