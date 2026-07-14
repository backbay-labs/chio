# chio-hosted-mcp

`chio-hosted-mcp` is the public compatibility surface for Chio's hosted MCP
product path. It re-exports the Streamable HTTP MCP server from
`chio-mcp-remote` and the operator primitives from `chio-control-plane` needed
to configure and run it, so callers get one crate name instead of two. The
crate defines no types or logic of its own; `src/lib.rs` is re-exports only.

Use it when you need the hosted MCP path (remote clients over HTTP with SSE
delivery, OAuth 2.0 / DPoP, resumable sessions) rather than an adapted
external server or the stdio-first `chio mcp serve` flow.

## Responsibilities

- Re-export the hosted MCP entrypoint and its configuration type from
  `chio-mcp-remote`.
- Re-export the control-plane primitives from `chio-control-plane` needed to
  stand up a hosted deployment: kernel construction, store wiring, authority
  keypair lifecycle, default capability issuance, policy loading,
  trust-control, and enterprise federation.
- Hold none of the HTTP, OAuth, session-lifecycle, or receipt-signing logic
  itself.

## Public API

Re-exported from `chio-mcp-remote`:

- `serve_http(RemoteServeHttpConfig) -> Result<(), CliError>` - runs the
  hosted MCP HTTP/SSE server. Blocking; starts its own Tokio runtime.
- `RemoteServeHttpConfig` - listen address, auth mode (static bearer, JWT,
  introspection, local OAuth), store paths, wrapped-server command, and
  server identity fields.

Re-exported from `chio-control-plane`:

- `build_kernel`, `configure_receipt_store`, `configure_revocation_store`,
  `configure_capability_authority`, `configure_budget_store` - kernel
  construction and persistent store wiring.
- `load_or_create_authority_keypair`, `rotate_authority_keypair`,
  `authority_public_key_from_seed_file` - authority keypair lifecycle.
- `issue_default_capabilities` - default capability issuance.
- `policy`, `trust_control`, `enterprise_federation` - policy loading,
  trust-control service and clients, and enterprise identity provider
  modules.
- `CliError`, `JwtProviderProfile` - shared operator error type and JWT
  provider enum (`Generic`, `Auth0`, `Okta`, `AzureAd`).

## Testing

`cargo test -p chio-hosted-mcp`

The integration suite under `tests/` spins up a real `serve_http` instance
per test and drives it over HTTP: auth admission (static bearer, JWT, local
OAuth/PKCE), session lifecycle and idle expiry, cross-tenant session
isolation, structured JSON-RPC error responses, and receipt export into
`chio-siem`.

## See also

- `chio-mcp-remote` - implements the hosted HTTP/SSE server this crate
  re-exports.
- `chio-control-plane` - implements the operator primitives this crate
  re-exports.
- `chio-mcp-adapter` - wraps an external MCP server as a governed Chio tool
  server; does not host.
- `chio-mcp-edge` - hosts a Chio-native tool server over MCP transports; not
  the remote HTTP path.
