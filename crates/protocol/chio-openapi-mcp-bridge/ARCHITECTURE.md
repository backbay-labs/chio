# chio-openapi-mcp-bridge architecture

## Overview

The bridge sits outside the kernel TCB and spans two untrusted boundaries: an
operator-supplied OpenAPI document at ingest time, and an arbitrary upstream
HTTP API at invocation time. It converts a spec into a
`chio-manifest::ToolManifest` plus a parallel route-dispatch plan, then
implements `chio-kernel`'s `ToolServerConnection` so the kernel mediates every
call - capability validation and guard evaluation happen before `invoke` runs,
and egress enforcement happens inside `invoke` before the caller-supplied
dispatcher touches the network.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public surface: `OpenApiMcpBridge`, `BridgeConfig`, `BridgeError`, `RouteBinding`, `BridgedResponse`, `HttpDispatcher`, and the `ToolServerConnection` implementations `BridgeToolServer` / `OwnedBridgeToolServer`. |
| `src/dispatch.rs` | Crate-internal (`pub(crate)`): route dispatch plan construction and path-template validation, URL construction and percent-encoding, `HttpEgressContract` enforcement, redirect rejection, MCP tool-result shaping. |
| `src/fuzz.rs` | `fuzz`-feature-gated libFuzzer entry point (`fuzz_openapi_ingest`) driving arbitrary bytes through `OpenApiMcpBridge::from_spec`. |
| `src/tests.rs` | `#[cfg(test)]` regression tests for manifest generation, dispatch validation, egress enforcement, and kernel integration. |

## Spec ingest and tool dispatch

Ingest (`from_spec` / `from_parsed_spec`):

1. `from_spec` parses spec text via `chio_openapi::OpenApiSpec::parse`
   (auto-detects JSON vs YAML) and delegates to `from_parsed_spec`; callers
   that already hold a parsed `OpenApiSpec` call `from_parsed_spec` directly.
2. `chio_openapi::ManifestGenerator::generate_tools` produces one
   `chio_core::ToolDefinition` (`chio-core-types`) per publishable operation
   (`respect_publish_flag: true`, `include_output_schemas: true`).
3. Each definition converts to a `chio_manifest::ToolDefinition`
   (`convert_tool_definition`): pricing and latency hints are not derived
   from the spec and are always `None`; `has_side_effects` is the negation of
   the OpenAPI-derived `read_only` annotation. An empty resulting tool list
   is rejected (`BridgeError::Manifest`).
4. A second, independent pass over the spec (`build_route_dispatches`)
   re-applies the same `x-chio-publish` filter to build the route dispatch
   map (method, path template, query parameters, request-body requirement),
   validating that path-template placeholders and declared `in: path`
   parameters match exactly in both directions.
5. The assembled `ToolManifest` passes `chio_manifest::validate_manifest`
   before the bridge is returned.

Invocation (`invoke_tool`, reached via `ToolServerConnection::invoke` when
registered with a kernel):

1. The kernel validates the caller's capability and runs guards before
   calling `invoke` at all; a runtime-admission denial never reaches the
   dispatch logic below.
2. The route's URL is constructed from tool arguments (path expansion,
   percent-encoding, query parameters), failing closed on missing or
   malformed required parameters before any egress check runs.
3. `enforce_dispatch_contract` validates the URL, including DNS resolution,
   against `BridgeConfig::egress_contract`; a missing contract fails closed.
4. The caller's `HttpDispatcher` performs the single HTTP call.
5. The response is rejected if it carries a 3xx status; otherwise
   `enforce_bridged_response_body` checks `observed_body_bytes` against the
   contract's response-byte ceiling.
6. The response is wrapped into an MCP-shaped tool result (`content` /
   `isError` / `structuredContent`) and returned.

## Invariants and failure modes

- Manifest generation and route-dispatch construction apply the
  `x-chio-publish` filter independently; an unpublished operation is never
  invokable even though both passes read the same spec.
- Path-template placeholders and declared `in: path` parameters must match
  exactly in both directions; a mismatch fails at construction time, before
  any tool is invokable.
- Path parameter values must not be empty or a dot segment (`.`, `..`).
- Required query parameters must be present and not null or an empty array.
- An operation with a required request-body schema requires a non-null
  `arguments["body"]`.
- `invoke_tool` without a configured dispatcher returns `BridgeError::Kernel`
  rather than simulating a response, so the kernel cannot sign a receipt for
  a call that never happened.
- Live dispatch without `BridgeConfig::egress_contract` fails closed
  (`BridgeError::UpstreamError`) before the dispatcher runs.
- The response-byte ceiling is enforced against dispatcher-observed raw
  bytes, not a re-serialized JSON body; a dispatcher that omits
  `observed_body_bytes` fails closed instead of falling back to an
  under-counted estimate.
- A 3xx dispatcher response is rejected; the bridge never performs a second
  network hop on the caller's behalf.
- `#![forbid(unsafe_code)]`.

## Dependencies

`chio-openapi` parses the spec and generates the raw tool list. `chio-core`
(aliased to `chio-core-types`) supplies the pre-conversion `ToolDefinition`
and, in the `fuzz` module, `Keypair`. `chio-manifest` supplies `ToolManifest`,
`ToolDefinition`, and `validate_manifest`. `chio-mcp-edge` supplies
`McpToolInfo` for `mcp_tools_list`. `chio-egress-contract` supplies
`HttpEgressContract`. `chio-kernel` supplies the `ToolServerConnection`,
`NestedFlowBridge`, and `KernelError` types this crate implements against.
`async-trait` backs the async trait implementations; `serde`/`serde_json` and
`thiserror` back the config, response, and error types. The optional
`arbitrary` dependency is pulled in by the `fuzz` feature but not referenced
directly by `fuzz.rs`, which fuzzes raw UTF-8 bytes rather than a derived
`Arbitrary` type.

## Extension points

`HttpDispatcher` (set via `OpenApiMcpBridge::set_dispatcher`) is the
transport seam: the bridge has no HTTP client of its own, so a consumer
supplies the function that performs the single-hop request and must return
3xx responses rather than following them.
