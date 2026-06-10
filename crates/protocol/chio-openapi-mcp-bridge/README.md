# chio-openapi-mcp-bridge

`chio-openapi-mcp-bridge` presents Chio-governed HTTP APIs as MCP tool
surfaces. Given an OpenAPI 3.x specification it parses the spec with
`chio-openapi` to produce `ToolDefinition` values, wraps each route as an
MCP-visible tool via `chio-mcp-edge`, and routes invocations through the kernel
for capability validation and receipt signing before dispatching to the
upstream HTTP API.

Use this crate to put an existing REST API behind a Chio-governed MCP endpoint
without writing an MCP server by hand.
