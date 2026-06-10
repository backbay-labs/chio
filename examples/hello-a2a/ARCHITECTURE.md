# hello-a2a Architecture

## Owning Boundary

`examples/hello-a2a` owns the maintained A2A protocol-edge teaching example. It
builds a small Chio kernel, registers one streaming-capable `hello_task` tool,
publishes that tool through `ChioA2aEdge`, prints the generated Agent Card, and
serves line-based JSON-RPC requests for authoritative `message/send`,
`message/stream`, and `task/get` flows.

The package depends on public APIs from:

- `chio-a2a-edge` for `ChioA2aEdge`, `A2aEdgeConfig`, and
  `A2aKernelExecutionContext`.
- `chio-kernel` for kernel construction, the tool-server trait, streaming
  output types, and stream bounds.
- `chio-core` for generated keypairs and capability grants.
- `chio-manifest` for the tool manifest projected into the Agent Card.

## Security And API Constraints

- Preserve the server id `hello-a2a-srv`, tool id `hello_task`, Agent Card skill
  shape, capability scope, and receipt-bearing metadata in terminal results.
- Preserve the documented JSON-RPC flow: `message/send`, deferred
  `message/stream`, and `task/get`.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  approval, or runtime policy paths.
- As a protocol-edge reference, `HelloStreamServer` self-defends its
  registration boundary on both blocking and streaming paths even though the
  kernel routes only registered tools.
- Preserve deferred task ownership semantics and the `receiptPending` metadata
  on working task responses.
- Do not change `chio-a2a-edge` public APIs from this example slice.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`, and any
operator running `examples/hello-a2a/smoke.sh`.

No downstream crate requires code changes for this example.
