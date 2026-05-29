# chio-mcp-remote

Remote hosted MCP runtime surface for Chio.

## What it does

`chio-mcp-remote` runs the Chio-governed MCP server that remote clients reach
over HTTP. It handles:

- MCP session lifecycle (session creation, message dispatch, teardown) via
  an Axum HTTP service with SSE delivery.
- OAuth 2.0 and DPoP token flows: authorization code exchange, token endpoint,
  token introspection, and resource-indicator binding. Supported JWT signature
  algorithms include RS256/RS384/RS512, PS256/PS384, ES256/ES384, and Ed25519.
- Enterprise federation: pluggable identity providers (OIDC, SAML-like, custom)
  resolved through `EnterpriseProviderRegistry`.
- Per-client rate limiting (600 requests per 60-second window, 4096 tracked
  keys) enforced before session work begins.
- Admin routes (`/admin/health`, `/admin/authority`, `/admin/rotate`) for
  operator keypair management.
- Receipt-bearing kernel dispatch: every tool invocation passes through
  `chio-kernel` and produces a signed `ChioReceipt`.

The public surface re-exports `CliError` and `JwtProviderProfile` from
`chio-control-plane` and exposes the HTTP service entrypoint via
`serve_http(RemoteServeHttpConfig)`.

## Position in the system

```
Remote MCP client (browser / CLI / agent)
        |  (HTTP + SSE, OAuth 2.0 + DPoP)
  [chio-mcp-remote]
        |
  chio-kernel  ->  signed ChioReceipts
```

`chio-mcp-remote` depends on `chio-mcp-adapter` (MCP protocol types and
transport), `chio-kernel` (policy enforcement and receipts),
`chio-control-plane` (authority keypair management, policy loading, budget and
revocation stores), and `chio-egress-contract` (outbound HTTP safety).

## Crate layout

```
crates/chio-mcp-remote/
  Cargo.toml
  src/
    lib.rs              re-exports; includes session_core, http_service, oauth, tests
    remote_mcp/
      admin.rs          admin REST routes (health, authority, rotate)
      http_service.rs   Axum service entry, rate limiter, SSE delivery
      oauth.rs          OAuth token endpoint, DPoP proof validation, JWT verify
      session_core.rs   session lifecycle, kernel dispatch, receipt signing
      tests.rs          integration tests
```

## Building

```bash
cargo build -p chio-mcp-remote
cargo test -p chio-mcp-remote
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: sessions without a valid OAuth bearer or DPoP proof are rejected
  before the MCP session is created.
