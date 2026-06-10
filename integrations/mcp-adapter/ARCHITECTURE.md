# chio-mcp-adapter-integration Architecture

## Boundary

`chio-mcp-adapter-integration` is the distribution packaging layer for the
registry-listed MCP server. It extends the core `chio-mcp-edge` transport
contract with marketplace-facing Streamable HTTP, OAuth 2.1 with PKCE, RFC 9728
protected resource metadata, and local receipt-emission helpers.

It should not own the core MCP edge runtime, kernel admission, policy
evaluation, durable receipt storage, or hosted OAuth issuer behavior. Those live
in `chio-mcp-edge`, `chio-kernel`, `chio-policy`, storage crates, and
`chio-mcp-remote`.

## Module Boundaries

- `transport.rs` owns the local Streamable HTTP exchange facade used by the
  registry and AgentCore packaging tests.
- `oauth.rs` owns PKCE challenge generation and authorization URL construction.
- `prm.rs` owns the protected-resource metadata shape exposed to clients.
- `receipt_emit.rs` owns the local receipt JSON facade used by the distribution
  fixture lane.
- `lib.rs` is the public facade over those surfaces.

## Credential Boundary

`transport.rs` separates secret-bearing request material from diagnostic
exchange evidence. The builder validates the bearer token before constructing
the transport, the wire headers carry the real token, and the exchange log
stores only a redacted Authorization value. The core MCP edge does not see this
integration crate's local exchange log, and OAuth helpers do not mediate the
builder token once it is supplied.

## Security And API Constraints

- Keep the public builder and transport traits compatible for valid callers.
- Preserve Streamable HTTP request shape and MCP protocol version headers.
- Reject missing, padded, or control-character bearer tokens fail closed.
- Do not expose bearer token material through `exchange_log`.
- Do not change core `chio-mcp-edge` behavior or registry fixture semantics.
