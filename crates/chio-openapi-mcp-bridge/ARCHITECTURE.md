# chio-openapi-mcp-bridge Architecture

## Boundaries

- `OpenApiMcpBridge` owns OpenAPI ingest, manifest conversion, route dispatch planning, and borrowed tool-server exposure.
- `OwnedBridgeToolServer` owns the same dispatch state after kernel registration consumes a bridge.
- `BridgeConfig` is caller-supplied trust configuration, including upstream base URL and the typed HTTP egress contract that gates every live dispatcher call.
- `RouteBinding` is the public method/path view. Internal dispatch state must carry any extra routing details without expanding that public struct.
- The optional `fuzz` module is a feature-gated trust-boundary harness for arbitrary OpenAPI input.

## Pain Points

- `src/lib.rs` is carrying route binding, URL construction, egress enforcement, response shaping, and test fixtures in one file.
- Manifest tool generation and route dispatch planning are parallel paths, so drift between advertised input schema and live dispatch behavior is easy to miss.
- Path parameter expansion still percent-encodes unreserved `.` bytes, so `.` or
  `..` parameter values can become real URL path segments after a downstream
  HTTP client reparses the URL.
- The caller-supplied dispatcher receives only a pre-flight-checked URL. If it
  follows redirects internally, the bridge cannot validate the redirected
  authority before the second network hop.

## Constraints

- Public `RouteBinding`, `BridgeConfig`, `BridgeError`, and response shapes stay compatible.
- Live dispatch must fail closed when egress contract state is absent or rejects the final URL.
- URL construction must remain deterministic because the dispatcher URL is part of the enforced egress boundary.
- The bridge must not bypass `chio-openapi` parsing, publish filtering, or `chio_manifest::validate_manifest`.

## Affected Dependents

- `chio-kernel` callers observe this crate through `ToolServerConnection`.
- `chio-mcp-edge` receives manifest-derived `McpToolInfo` entries.
- `chio-egress-contract` enforces the final URL and response-size limits.
- `chio-fuzz` compiles the `fuzz` module when exercising OpenAPI ingest.

## Planned Improvement

Reject dot-segment path parameter values before URL construction completes, and
make redirect handling explicit at the bridge boundary. Live dispatchers must
surface redirects as responses instead of following them internally, and the
bridge must reject redirect statuses before returning a tool result.

## Path Parameter Closure Slice

### Current Boundary

`dispatch.rs` validates route templates before building `RouteDispatch` records.
It already fails closed when a `{placeholder}` in the path is not declared as an
OpenAPI `in: path` parameter.

### Pain Point

The inverse check is still missing: a path-level or operation-level `in: path`
parameter can be declared without appearing in the route template. The generated
manifest then requires an input field that live URL construction ignores. That
is schema-to-dispatch drift at the bridge trust boundary.

### Completed Material Improvement

Reject any declared path parameter that is not present in the route template
before publishing the manifest or dispatch table. Keep public `RouteBinding`
and response shapes unchanged, and prove the bridge fails closed before
creating a route binding for the malformed spec.

## Required Query Dispatch Slice

### Current Boundary

`dispatch.rs` now owns live URL construction after OpenAPI ingest. It receives
the merged path-level and operation-level parameters, records the public route
binding, expands path placeholders, appends declared query parameters, and hands
the final URL to the `HttpEgressContract` before the caller-supplied dispatcher
runs.

### Pain Point

The manifest generator already marks required query parameters in the generated
tool input schema, but the live dispatcher stores only query parameter names.
If a caller invokes the bridge directly, or a protocol layer fails to validate
the manifest schema, missing required query arguments are silently omitted from
the upstream URL. That creates drift between the advertised Chio tool contract
and the actual HTTP request the bridge is willing to dispatch.

### Security and API Constraints

The public `RouteBinding`, `BridgeConfig`, `BridgeError`, `BridgedResponse`,
`OpenApiMcpBridge`, and `OwnedBridgeToolServer` APIs must stay source
compatible. Egress contract enforcement must still run on the final URL, and
the dispatcher must not run when live request construction is missing required
OpenAPI evidence. Optional query parameters should remain optional.

### Affected Dependents

`chio-conformance` imports `OpenApiMcpBridge` for SSRF and response-size tests,
and fuzz targets compile the feature-gated ingest harness. No transitive source
changes are planned because the required-query metadata is internal to
`RouteDispatch`.

### Planned Material Improvement

Extend the internal dispatch plan from `Vec<String>` query names to query
metadata that includes OpenAPI `required`. Validate required query parameters
before appending any query string, reject missing/null/empty-array required
values before egress and before the dispatcher runs, and add focused tests for
both borrowed and owned bridge invocation paths.

## Request Body Dispatch Contract Slice

### Current Boundary

`ManifestGenerator::generate_tools` turns every parsed OpenAPI request body
schema into a required top-level `body` property in the Chio tool input schema.
`chio-openapi-mcp-bridge` then stores an internal `RouteDispatch` per tool and
uses that dispatch plan for borrowed `OpenApiMcpBridge::invoke_tool` calls and
owned `OwnedBridgeToolServer::invoke` calls.

### Pain Point

The dispatch plan carries path and query metadata, but it does not carry
whether the operation has a request body schema. A caller can invoke a body
operation directly through the bridge without a `body` argument. That bypasses
the generated manifest contract and runs the live dispatcher with arguments the
advertised Chio tool schema would reject.

### Security and API Constraints

The public bridge APIs and response shape must remain source-compatible.
Valid body-bearing calls that already supply `body` must remain valid. Missing
body evidence must fail before URL construction, egress enforcement, or live
dispatcher execution. The bridge must keep matching the current generator
contract, which treats any parsed request body schema as required.

### Affected Dependents

No transitive source changes are expected. Existing callers that invoke
request-body operations without the manifest-declared `body` field will now get
`BridgeError::UpstreamError` before dispatch.

### Completed Material Improvement

Extend `RouteDispatch` with request-body requirement metadata, validate missing
or null `body` arguments before live dispatch, and add borrowed plus owned
bridge regression tests proving the dispatcher does not run on malformed body
operations.

## Observed Response Byte Enforcement Slice

### Current Boundary

Live dispatchers return `BridgedResponse` values after reading upstream HTTP
responses. `HttpEgressContract::max_response_bytes` must be enforced against
the upstream bytes the dispatcher observed, before the bridge returns tool
content to MCP callers.

### Pain Point

When `observed_body_bytes` is absent, the bridge previously measured the
reserialized JSON body. That can be smaller than the upstream byte stream after
the dispatcher parses or normalizes a response, weakening the response-size
egress contract.

### Security and API Constraints

Keep the public `BridgedResponse` field optional for source compatibility, but
make live bridge dispatch fail closed when a dispatcher omits the observed byte
count. Redirect rejection remains independent because redirects are denied
before accepted response content is returned.

### Affected Dependents

`chio-conformance` OpenAPI bridge SSRF tests must provide the observed byte
count when proving response-size denial. Other callers that use live
dispatchers without the byte count now receive `BridgeError::UpstreamError`
instead of fallback measurement.

### Completed Material Improvement

Removed fallback JSON reserialization from response-size enforcement, required
`observed_body_bytes` for live bridge responses, and added a regression that
fails closed when dispatchers omit the observed byte count.
