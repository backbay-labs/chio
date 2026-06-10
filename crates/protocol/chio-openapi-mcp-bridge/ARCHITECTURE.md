# chio-openapi-mcp-bridge Architecture

## Boundaries

- `OpenApiMcpBridge` owns OpenAPI ingest, manifest conversion, route dispatch planning, and borrowed tool-server exposure.
- `OwnedBridgeToolServer` owns the same dispatch state after kernel registration consumes a bridge.
- `BridgeConfig` is caller-supplied trust configuration, including upstream base URL and the typed HTTP egress contract that gates every live dispatcher call.
- `RouteBinding` is the public method/path view. Internal dispatch state carries extra routing details (path/query/body metadata) without expanding that public struct.
- `dispatch.rs` owns URL construction and egress enforcement.
- `src/tests.rs` owns bridge-level regression tests for manifest generation, route binding, egress enforcement, body/query validation, redirect rejection, and owned server dispatch.
- The optional `fuzz` module is a feature-gated trust-boundary harness for arbitrary OpenAPI input.

## Schema-to-Dispatch Parity

The generated manifest input schema and live URL construction share one route
dispatch plan, so the advertised Chio tool contract matches the HTTP request the
bridge is willing to dispatch:

- A `{placeholder}` in the path must be a declared OpenAPI `in: path` parameter,
  and every declared path parameter must appear in the route template. Malformed
  specs fail closed before a route binding is created.
- Dot-segment path parameter values (`.`, `..`) are rejected before URL
  construction, so a downstream HTTP client cannot reparse them into real path
  segments.
- Required query parameters are validated before any query string is appended;
  missing, null, or empty-array required values fail before egress and before
  the dispatcher runs. Optional query parameters remain optional.
- An operation with a parsed request body schema requires a `body` argument;
  missing or null `body` fails before URL construction, egress enforcement, or
  dispatch.

## Egress and Redirect Boundary

- Live dispatch fails closed when egress contract state is absent or rejects the
  final URL. URL construction is deterministic because the dispatcher URL is part
  of the enforced egress boundary.
- The caller-supplied dispatcher receives only a pre-flight-checked URL. It must
  surface redirects as responses rather than following them internally, and the
  bridge rejects redirect statuses before returning a tool result, so the
  redirected authority is never reached without validation.
- `HttpEgressContract::max_response_bytes` is enforced against the upstream bytes
  the dispatcher observed. Live bridge responses require `observed_body_bytes`;
  a dispatcher that omits the count gets `BridgeError::UpstreamError` rather than
  fallback JSON reserialization, which could undercount the response size.

## Constraints

- Public `RouteBinding`, `BridgeConfig`, `BridgeError`, and response shapes stay compatible.
- The bridge must not bypass `chio-openapi` parsing, publish filtering, or `chio_manifest::validate_manifest`.

## Affected Dependents

- `chio-kernel` callers observe this crate through `ToolServerConnection`.
- `chio-mcp-edge` receives manifest-derived `McpToolInfo` entries.
- `chio-egress-contract` enforces the final URL and response-size limits.
- `chio-conformance` imports `OpenApiMcpBridge` for SSRF and response-size tests and supplies the observed byte count when proving response-size denial.
- `chio-fuzz` compiles the `fuzz` module when exercising OpenAPI ingest.
