# chio-hosted-mcp

`chio-hosted-mcp` provides Chio's hosted MCP runtime surface over Streamable HTTP
and the shared state needed to resume governed MCP sessions through the trust
plane.

Use this crate when you need the hosted MCP path instead of the local sidecar
or stdio-first `chio mcp serve` flow.
