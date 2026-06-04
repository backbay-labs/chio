# hello-tool Architecture

## Owning Boundary

`examples/hello-tool` is the maintained native-service adoption example. It
owns the small greet service, the priced native manifest surface, the static
resource and prompt registrations, and the runnable demo that signs and invokes
the generated service.

The package depends on public APIs from:

- `chio-mcp-adapter` for `NativeChioServiceBuilder`, `NativeTool`,
  `NativeResource`, and `NativePrompt`.
- `chio-kernel` for the tool, resource, prompt, and event traits.
- `chio-core-types` for keypairs, prompt messages, and resource contents.
- `chio-manifest` for manifest signing, pricing metadata, and latency hints.

## Current Pain Points

- `src/main.rs` currently mixes service construction, runtime printing, and
  package tests in one binary-only module.
- The native service builder is a reusable adoption contract, but downstream
  tests can only reach it through private binary internals.
- The demo uses `expect` for builder, invocation, resource, prompt, and event
  paths. That is tolerable for a toy script, but this example is the maintained
  migration reference and should model explicit fail-closed errors instead of
  panic paths.
- No test exercises the full native service surface in one place: signed
  manifest, tool, resource, prompt, and late event queue.

## Security And API Constraints

- Preserve the `greet` tool name, schema, resource URI, prompt name, server id,
  pricing metadata, and signed manifest behavior documented by the native
  adoption and tool-pricing guides.
- Keep invalid greet inputs fail-closed through `KernelError::RequestIncomplete`.
- Do not change `NativeChioServiceBuilder` or lower-level adapter APIs from this
  example slice.
- Do not weaken manifest validation or signed artifact compatibility.

## Affected Dependents

The direct dependents are documentation and smoke users that run or inspect this
example: the root README, `examples/README.md`,
`examples/EXAMPLE_SURFACE_MATRIX.md`,
`docs/start-here/NATIVE_ADOPTION_GUIDE.md`, and
`docs/reference/TOOL_PRICING_GUIDE.md`.

No downstream crate should need code changes. If splitting the binary exposes a
Cargo target or import issue, the fix should stay inside this package.

## Planned Improvement

Move service construction and the demo flow into `src/lib.rs`, keep
`src/main.rs` as a thin process wrapper, return explicit errors from the builder
and demo run path, and strengthen tests around the complete native service
surface. This is architectural because it separates the reusable native service
boundary from CLI presentation and makes the example a stable contract for
wrapped-MCP-to-native migration.
