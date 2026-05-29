# Native Adoption Guide

This guide closes the gap between the current wrapped-MCP path and the first supported native Chio authoring path.

## Supported coding-agent start

The supported path for coding agents today is:

1. start from [`examples/policies/canonical-hushspec.yaml`](../../examples/policies/canonical-hushspec.yaml)
2. wrap the existing MCP server with `chio mcp serve --policy ./policy.yaml`
3. prove one deny, one allow, and one receipt with
   [`docs/guides/MIGRATING-FROM-MCP.md`](../guides/MIGRATING-FROM-MCP.md)

Do that first. Native authoring is the next supported step after the wrapped
path is already behaving correctly.

## Canonical policy path

For new policy authoring, use HushSpec.

- `examples/policies/canonical-hushspec.yaml` is the recommended starting point.
- `examples/policies/hushspec-guard-heavy.yaml` exercises the full shipped guard surface.

HushSpec is the only documented policy authoring path for new Chio deployments.

## Migration path: wrapped MCP to native Chio

1. Keep the same policy intent, but move policy authoring to HushSpec.
2. Start from the wrapped path you already have with `chio mcp serve` or `chio mcp serve-http`.
3. Replace the wrapped subprocess with a native service built through `NativeChioServiceBuilder`.
4. Register that native service with the kernel and expose it through the same edge surface you already use.

That lets a team migrate one server at a time without changing the trust, receipt, or guard model around it.

## Minimal native authoring surface

`chio-mcp-adapter` now ships a small higher-level native service builder:

- `NativeChioServiceBuilder`
- `NativeTool`
- `NativeResource`
- `NativePrompt`

The builder creates one service value that:

- emits a valid Chio manifest
- implements `ToolServerConnection`
- implements `ResourceProvider`
- implements `PromptProvider`
- can emit late `ToolServerEvent`s through an internal queue

Advanced users can still drop to the lower-level kernel traits directly for custom streaming, resource templates, or transport-specific behavior.

When you expose a native service through a Chio edge, the runtime contract does
not change:

- stdio and hosted edges still require `initialize` followed by `notifications/initialized`
- hosted HTTP uses `POST /mcp` for requests and `GET /mcp` plus `Last-Event-ID` for live notification replay
- caller-supplied `_meta.modelMetadata` enters the runtime as asserted provenance unless a trusted subsystem upgrades it later

## Example

The maintained example is [examples/hello-tool](../../examples/hello-tool), which now uses `NativeChioServiceBuilder` instead of hand-assembling only a manifest.

The flow is:

1. generate a server keypair
2. build the service with a tool, resource, and prompt
3. sign the generated manifest
4. invoke the service through the normal trait surface

## What this does not solve yet

- resource-template authoring ergonomics are still lower-level
- completion helpers are still lower-level
- transport bootstrapping is still a separate concern from service authoring

That is deliberate. The first native surface is meant to make common service authoring coherent, not hide every runtime primitive.
