# chio-mcp-adapter-integration

Distribution integration for Chio's registry-listed MCP server. This crate
extends the `chio-mcp-edge` transport contract with the Streamable HTTP,
OAuth 2.1 + PKCE, RFC 9728 Protected Resource Metadata, and receipt-emission
surfaces used by the AWS Bedrock and MCP marketplace listing lane.

It is the packaging layer that turns the Chio MCP edge into a deployable,
marketplace-distributable MCP server. The core MCP edge transport itself lives
in `crates/chio-mcp-edge`.
