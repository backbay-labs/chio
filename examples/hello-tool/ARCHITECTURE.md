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

## Security And API Constraints

- Preserve the `greet` tool name, schema, resource URI, prompt name, server id,
  pricing metadata, and signed manifest behavior documented by the native
  adoption and tool-pricing guides.
- Keep invalid greet inputs fail-closed through `KernelError::RequestIncomplete`.
- Do not change `NativeChioServiceBuilder` or lower-level adapter APIs from this
  example.
- Do not weaken manifest validation or signed artifact compatibility.

## Affected Dependents

The direct dependents are documentation and smoke users that run or inspect this
example: the root README, `examples/README.md`,
`examples/EXAMPLE_SURFACE_MATRIX.md`,
`docs/start-here/NATIVE_ADOPTION_GUIDE.md`, and
`docs/reference/TOOL_PRICING_GUIDE.md`.

No downstream crate requires code changes for this example.
