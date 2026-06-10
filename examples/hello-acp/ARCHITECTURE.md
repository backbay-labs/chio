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

## Security And API Constraints

- Preserve the server id `hello-acp-srv`, capability/tool id `hello_tool`,
  capability scope, and receipt-bearing terminal metadata.
- Preserve the documented JSON-RPC flow: `session/list_capabilities`,
  `tool/invoke`, `tool/stream`, and `tool/resume`.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  approval, runtime assurance, or cross-protocol orchestration paths.
- As a protocol-edge reference, `HelloToolServer` self-defends its registration
  boundary on both blocking and streaming paths even though the kernel routes
  only registered tools.
- `tool/stream` creates a receipt-pending deferred task and `tool/resume`
  resolves it through the receipt-bearing kernel path.
- Preserve deferred task ownership semantics and the `receiptPending` metadata
  on working task responses.
- Do not change `chio-acp-edge` public APIs from this example.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`,
`examples/run-hello-smokes.sh`, and any operator running
`examples/hello-acp/smoke.sh`.

No downstream crate requires code changes for this example.
