# chio-mcp-edge

`chio-mcp-edge` exposes Chio-governed tools over MCP transports and holds the
shared protocol/runtime contracts used by Chio's MCP-facing surfaces.

Use this crate when you need to present a Chio-governed runtime as an MCP
server instead of wrapping an existing MCP server with `chio-mcp-adapter`.
