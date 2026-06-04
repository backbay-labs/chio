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

## Current Pain Points

- `src/main.rs` mixes manifest construction, kernel setup, capability issuance,
  Agent Card printing, stdio serving, argument parsing, and tests in one
  binary-only module.
- The smoke script proves the end-to-end process path, but the package has no
  direct test for the A2A JSON-RPC lifecycle even though `ChioA2aEdge` exposes
  a synchronous `handle_jsonrpc` boundary.
- `HelloStreamServer` ignores the selected tool name for both blocking and
  streaming calls. The kernel should route only registered tools, but this
  protocol-edge example should model a self-defensive tool server too.
- The deferred task lifecycle and the terminal receipt metadata are the
  important teaching surfaces, but the current unit test only covers argument
  parsing.

## Security And API Constraints

- Preserve the server id `hello-a2a-srv`, tool id `hello_task`, Agent Card skill
  shape, capability scope, and receipt-bearing metadata in terminal results.
- Preserve the documented JSON-RPC flow: `message/send`, deferred
  `message/stream`, and `task/get`.
- Preserve kernel-mediated authorization. The example must not bypass
  capability validation, guard execution, receipt signing, revocation, budget,
  approval, or runtime policy paths.
- Preserve deferred task ownership semantics and the `receiptPending` metadata
  on working task responses.
- Do not change `chio-a2a-edge` public APIs from this example slice.

## Affected Dependents

The direct dependents are example users and docs that run or point at the smoke
flow: `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`, and any
operator running `examples/hello-a2a/smoke.sh`.

No downstream crate should require code changes. If the package split exposes a
Cargo target issue, the fix should stay inside `examples/hello-a2a`.

## Planned Improvement

Move demo state construction, Agent Card generation, JSON-RPC serving, and mode
dispatch into `src/lib.rs`; leave `src/main.rs` as a thin process wrapper. Add
tests that exercise the authoritative A2A send/stream/task-get lifecycle
directly through `ChioA2aEdge::handle_jsonrpc`, prove stdio response framing,
and prove the demo tool server rejects unknown tool names on both blocking and
streaming paths. This is architectural because it separates the protocol-edge
contract from process presentation and makes the deferred receipt lifecycle a
package-local invariant.
