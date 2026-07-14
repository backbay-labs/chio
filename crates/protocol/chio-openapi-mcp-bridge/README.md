# chio-openapi-mcp-bridge

Turns an OpenAPI 3.x HTTP API into a governed Chio tool server. It converts
the tool manifest `chio-openapi` generates from a spec into a live,
invokable `ToolServerConnection`: each tool call binds to a concrete HTTP
route, passes through a caller-supplied `HttpEgressContract`, and dispatches
via a caller-supplied transport function.

`chio-openapi` only parses the spec and produces a `ToolManifest`; it has no
notion of dispatch. This crate takes that manifest, builds the route-to-HTTP
dispatch plan, enforces egress policy on every call, and wraps HTTP responses
in MCP-shaped tool results (`content` / `isError` / `structuredContent`). It
does not implement MCP wire transport itself - register its
`ToolServerConnection` implementations with a kernel directly, or use
`chio-mcp-edge` to host the resulting tools over an actual MCP connection.

## Responsibilities

- Parse an OpenAPI spec via `chio-openapi` and convert its generated tool
  definitions into a `chio-manifest::ToolManifest`, rejecting specs that
  publish zero tools.
- Build a route dispatch plan per publishable operation (HTTP method, path
  template, declared query parameters, request-body requirement), applying
  the same `x-chio-publish` filter as manifest generation in an independent
  pass over the spec.
- Construct the live request URL from tool arguments: expand and
  percent-encode path parameters, reject empty or dot-segment (`.`, `..`)
  values, and append declared query parameters, failing closed on missing
  required parameters.
- Enforce a caller-supplied `HttpEgressContract` on every dispatch: URL/DNS
  pre-flight before the call, response-byte ceiling (checked against
  `BridgedResponse::observed_body_bytes`) after it. Live dispatch fails
  closed with no contract configured.
- Reject dispatcher responses carrying a 3xx status instead of treating them
  as a followable redirect.
- Implement `ToolServerConnection` (`BridgeToolServer`, `OwnedBridgeToolServer`)
  so a bridge registers directly with a `chio-kernel` `ChioKernel`.
- Project the manifest into `chio-mcp-edge::McpToolInfo` entries
  (`mcp_tools_list`) for MCP `tools/list` responses.

## Public API

- `OpenApiMcpBridge` - `from_spec`, `from_parsed_spec`, `set_dispatcher`,
  `manifest`, `manifest_clone`, `route_binding`, `tool_names`,
  `mcp_tools_list`, `invoke_tool`, `as_tool_server`.
- `BridgeConfig` - server identity, `base_url`, and the optional
  `egress_contract: Option<HttpEgressContract>` that gates live dispatch.
- `HttpDispatcher` - the transport hook:
  `Fn(&str, &str, &Value) -> Result<BridgedResponse, BridgeError>`.
- `BridgedResponse` - `status`, `body`, `observed_body_bytes`, `is_error`;
  the shape a dispatcher returns.
- `RouteBinding` - `method` / `path` for a tool.
- `BridgeError` - `OpenApi`, `Manifest`, `ToolNotFound`, `UpstreamError`, `Kernel`.
- `BridgeToolServer<'a>`, `OwnedBridgeToolServer` - borrowed and owned
  `ToolServerConnection` implementations.

## Usage

```rust
use chio_openapi_mcp_bridge::{BridgeConfig, BridgedResponse, OpenApiMcpBridge};
use serde_json::json;

let mut bridge = OpenApiMcpBridge::from_spec(openapi_json, BridgeConfig {
    server_id: "petstore-bridge".into(),
    server_name: "Petstore Bridge".into(),
    server_version: "1.0.0".into(),
    public_key: keypair.public_key().to_hex(),
    base_url: "https://api.example.com".into(),
    egress_contract: Some(contract),
})?;

bridge.set_dispatcher(Box::new(|method, url, _args| {
    // Perform one HTTP call. Return 3xx responses instead of following them.
    Ok(BridgedResponse {
        status: 200,
        body: json!({}),
        observed_body_bytes: Some(2),
        is_error: false,
    })
}));

let result = bridge.invoke_tool("listPets", json!({"limit": 5}))?;
```

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Exposes `fuzz::fuzz_openapi_ingest`, the libFuzzer entry point for the OpenAPI ingest path (`OpenApiMcpBridge::from_spec`). Off by default; pulls in `arbitrary`. Enabled only by the standalone `chio-fuzz` workspace. |

## Testing

`cargo test -p chio-openapi-mcp-bridge`

## See also

- `chio-openapi` - parses the OpenAPI spec and generates the raw tool
  definitions this crate converts and binds to routes.
- `chio-manifest` - defines `ToolManifest` / `ToolDefinition` and the
  structural validation the assembled manifest passes.
- `chio-egress-contract` - the SSRF and response-size policy enforced on
  every live dispatch.
- `chio-mcp-edge` - supplies `McpToolInfo`; hosts tools over actual MCP
  transports.
- `chio-kernel` - consumes `BridgeToolServer` / `OwnedBridgeToolServer` as a
  governed tool server.
- `chio-conformance` - SSRF and response-size proof tests built on this crate.
