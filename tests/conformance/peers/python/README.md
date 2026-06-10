# Python Peer

An executable Python peer adapter.

Capabilities:

- Streamable HTTP client against a live `chio mcp serve-http` edge
- machine-readable `ScenarioResult` JSON output
- transcript emission compatible with the Rust conformance runner

MCP core coverage:

- initialize
- tools/list
- tools/call simple text
- resources/list
- prompts/list

Task/auth/notification coverage:

- remote HTTP task lifecycle scenarios
- remote HTTP auth-family scenarios using local OAuth discovery, auth-code + PKCE, token exchange, and protected-resource challenge handling
- remote HTTP notification and subscription scenarios for wrapped resource updates and catalog `list_changed` delivery

Not yet supported:

- Python server peer
- stdio peer mode
- broader nested callback families beyond the current remote HTTP slices
