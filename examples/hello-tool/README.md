# hello-tool

A native Chio service built directly on `NativeChioServiceBuilder`, without a wrapped MCP subprocess.

## What it shows

- a native Chio service built with `NativeChioServiceBuilder`
- one tool (`greet`)
- one resource (`memory://hello/template`)
- one prompt (`compose_greeting`)
- manifest signing with a real generated keypair
- advertised manifest pricing for pre-invocation budget planning
- a reusable library boundary with a thin binary wrapper

## Why this example exists

A native Chio service registers tools, resources, and prompts directly with the
kernel under the same policy and trust model as the wrapped-MCP adapters
(`chio mcp serve` and `chio mcp serve-http`), with no wrapped subprocess. The
migration map below pairs each wrapped-MCP shape with its native equivalent.

## Migration map

| Wrapped MCP shape | Native Chio shape |
| --- | --- |
| upstream `tools/list` | `NativeTool` definitions in `NativeChioServiceBuilder` |
| upstream `tools/call` | Rust handler closures registered on the builder |
| adapted manifest generation | `NativeChioService::manifest()` |
| adapter-backed resource / prompt providers | `NativeResource` and `NativePrompt` registrations |
| late upstream notifications | `NativeChioService::emit_event()` and `drain_events()` |

The example is intentionally small. If you need resource templates, advanced completion, or transport bootstrapping, drop down to the lower-level traits and edge types directly.

The service construction and demo flow live in `src/lib.rs`; `src/main.rs`
only handles process exit behavior. That keeps the adoption surface testable
without requiring downstream users to copy a binary-only module.

## Pricing

The `greet` tool advertises manifest pricing:

- pricing model: `per_invocation`
- quoted price: `25` minor units in `USD`
- billing unit: `invocation`

That metadata is advisory, not enforcement by itself. The actual hard stop still
comes from the capability grant's `max_cost_per_invocation` and
`max_total_cost` fields. The point of the example is to show the operator and
authority flow:

1. inspect tool pricing from the signed manifest
2. choose a safe per-call ceiling and total budget
3. issue a capability whose monetary budget is consistent with that quote

For the end-to-end planning flow, see [TOOL_PRICING_GUIDE.md](../../docs/reference/TOOL_PRICING_GUIDE.md).
