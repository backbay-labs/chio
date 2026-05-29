# chio-openapi

`chio-openapi` is an OpenAPI 3.x specification parser and Chio `ToolManifest`
generator. It parses OpenAPI 3.0 and 3.1 documents (YAML or JSON) and produces
a `ToolManifest` where each route becomes a `ToolDefinition` with an input
schema derived from path, query, and body parameters.

Use this crate to turn an existing HTTP API description into a Chio-governed
tool surface. To expose the resulting tools over MCP, see
`chio-openapi-mcp-bridge`.
