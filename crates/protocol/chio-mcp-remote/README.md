# chio-mcp-remote

Runs the Chio-governed MCP server that remote clients reach over HTTP: MCP
Streamable HTTP session lifecycle, OAuth 2.0 bearer and DPoP authentication,
enterprise identity federation, and per-session `chio-kernel` dispatch that
produces signed receipts. It is one of Chio's public entry points
(`public_entrypoint = true`), exposed as a single `serve_http` call.

It does not speak MCP wire protocol itself or manage an upstream process
directly: it builds sessions on `chio-mcp-adapter`'s `AdaptedMcpServer` and
reaches the `chio-mcp-edge` session engine only through the adapter's
re-exported `edge::*` module. Where `chio-mcp-adapter` wraps one MCP server
for in-process or stdio use, this crate puts that adapted server behind an
authenticated HTTP/SSE edge with its own session ledger, OAuth surface, and
admin API.

## Responsibilities

- Run the Axum HTTP surface for the MCP Streamable HTTP transport
  (`POST`/`GET`/`DELETE /mcp`): SSE delivery, `Last-Event-ID` replay from a
  bounded retained-notification window, and per-IP rate limiting (600
  requests per 60-second window, 4096 tracked keys, 8 MiB POST body cap).
- Authenticate every request under one of three bearer modes (static token,
  JWT, or token introspection), verifying EdDSA/RS256-512/PS256-512/ES256-384
  signatures plus DPoP proof-of-possession, mTLS thumbprint, and runtime
  attestation sender constraints.
- Optionally run a self-issued OAuth 2.0 authorization server
  (`LocalAuthorizationServer`) with PKCE authorization-code and
  token-exchange grants, for deployments without an external identity
  provider.
- Federate enterprise identity: OIDC/JWKS discovery, issuer matching against
  an `EnterpriseProviderRegistry`, and deterministic per-principal Chio agent
  keypairs.
- Spawn a dedicated `chio-kernel` per session (or fan out one upstream
  subprocess across sessions in `shared_hosted_owner` mode), wired to the
  receipt, revocation, budget, and capability-authority stores, so every tool
  call yields a signed `ChioReceipt`.
- Persist resumable sessions and terminal tombstones to SQLite with an
  integrity-tagged restore path, so a restart can resume in-flight sessions
  without re-authenticating.
- Serve `/admin/*` operator routes (health, authority rotation, receipts,
  revocations, budgets, session trust/drain/shutdown, Prometheus metrics)
  behind a constant-time bearer check.
- Publish OAuth protected-resource and authorization-server discovery
  metadata carrying Chio's governed-authorization profile.

## Public API

- `serve_http(config: RemoteServeHttpConfig) -> Result<(), CliError>` -
  blocking entrypoint; starts a Tokio runtime and serves until shutdown.
- `RemoteServeHttpConfig` - deployment configuration: listen address,
  auth-mode selection (static bearer, JWT, introspection, local authorization
  server), OAuth and DPoP settings, egress contract, SQLite store paths,
  policy path, server identity, hosted-isolation mode, and the wrapped
  upstream command.
- `CliError`, `JwtProviderProfile` - re-exported from `chio-control-plane`.
- `enforce_oidc_egress_contract(url: &Url, egress_contract: &HttpEgressContract)
  -> Result<(), CliError>` - runs the production OIDC-discovery egress gate
  outside a full server, for negative-conformance testing.

## Testing

`cargo test -p chio-mcp-remote`

`chio-conformance`'s `ssrf_oidc_jwks_loopback` integration test calls
`enforce_oidc_egress_contract` directly, asserting loopback and link-local
OIDC discovery URLs are denied before any connection is attempted.

## See also

- `chio-mcp-adapter` - wraps and governs the upstream MCP server this crate
  hosts; supplies `AdaptedMcpServer` and the re-exported `chio-mcp-edge`
  contracts under `edge::*`.
- `chio-mcp-edge` - the MCP protocol/session engine underneath
  `chio-mcp-adapter`; this crate has no direct dependency on it.
- `chio-hosted-mcp` - compatibility shim that re-exports `serve_http` and
  `RemoteServeHttpConfig` verbatim.
- `chio-cli` - exposes this crate's entrypoint as `chio mcp serve-http`.
- `chio-kernel` - policy evaluation, guard pipeline, and receipt signing; one
  instance runs per session.
- `chio-control-plane` - authority keypair management, policy loading, and
  store configuration.
