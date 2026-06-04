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

## Pain Points

`StreamableHttpTransport` currently stores an exchange log with the same
authorization header value it would send on the wire. That makes a bearer token
available through diagnostic/test APIs. The builder also accepts tokens with
leading or trailing whitespace, so an accidentally padded credential can be
stored and replayed as a different Authorization header than the caller likely
intended.

This is an adapter-owned boundary. The core MCP edge does not see this
integration crate's local exchange log, and OAuth helpers do not mediate the
builder token once it is supplied.

## Security And API Constraints

- Keep the public builder and transport traits compatible for valid callers.
- Preserve Streamable HTTP request shape and MCP protocol version headers.
- Reject missing, padded, or control-character bearer tokens fail closed.
- Do not expose bearer token material through `exchange_log`.
- Do not change core `chio-mcp-edge` behavior or registry fixture semantics.

## Affected Dependents

The direct dependents are integration tests and any local packaging consumers
that inspect `StreamableHttpExchange`. Valid bearer tokens keep working. Tests
that relied on seeing the literal Authorization credential should switch to
asserting the redacted diagnostic value.

## Planned Improvement

Introduce an explicit transport credential boundary in `transport.rs`: validate
the bearer token before constructing the transport, retain the real token for
wire construction, and store only a redacted Authorization value in the exchange
log. This is architectural because it separates secret-bearing request material
from diagnostic exchange evidence at the owning adapter layer.
