# chio-mcp-remote architecture note

## Boundaries

- `lib.rs` owns the public crate surface, remote MCP module wiring, and the `serve_http(RemoteServeHttpConfig)` entrypoint.
- `remote_mcp/http_service.rs` owns Axum routing, HTTP request admission, SSE response shaping, hosted MCP session dispatch, and peer capability parsing.
- `remote_mcp/http_service_auth.rs` owns HTTP session-id extraction, remote auth-state construction, OAuth discovery metadata, local authorization-server wiring, request-time authorization validation, sender constraints, and DPoP runtime checks.
- `remote_mcp/oauth.rs` owns local authorization-server flow handling, token exchange, bearer extraction, JWT and introspection authentication, protocol header validation, and HTTP error projection.
- `remote_mcp/session_core.rs` owns remote session lifecycle state, session workers, capability issuance, and kernel construction.
- `remote_mcp/session_identity.rs` owns OIDC/JWKS discovery, JWT key resolution, federated principal construction, and enterprise identity context helpers.
- `remote_mcp/session_resume.rs` owns auth and policy fingerprints, federated agent derivation, and resumable-session integrity tags.
- `remote_mcp/session_shared_upstream.rs` owns shared hosted upstream ownership, notification taps, and fan-out accounting.
- `remote_mcp/session_forms.rs` owns admin query structs plus OAuth authorization and token request forms.
- `remote_mcp/session_store.rs` owns SQLite-backed active session rows, terminal tombstones, resume-record loading, tombstone loading, tombstone purging, and persisted capability freshness checks.
- `remote_mcp/admin.rs` owns operator-only health, authority, receipt, revocation, budget, session, and trust-control routes.

## Admission Boundaries

`MCP-Session-Id` has an internal admission boundary with explicit missing,
invalid, and valid states. Established-session `POST`, `GET`, and `DELETE`
requests require a non-empty canonical header value before session lookup;
initialize requests reject any present session header regardless of its value.
This typed boundary at the Axum edge enforces the public wire-protocol invariant
without changing the public `serve_http` API or the generated session identifier
format.

Static bearer material from `--auth-token` and `--admin-token` is validated at
configuration load time: values must be non-empty, unpadded, and control-free
before they can seed `RemoteAuthMode::StaticBearer` or admin route authorization
state, so a malformed value fails at startup rather than becoming an unusable or
log-breaking bearer credential.

## Constraints

- Preserve the public `serve_http(RemoteServeHttpConfig)` entrypoint and `RemoteServeHttpConfig` fields.
- Preserve hosted MCP wire behavior for `POST /mcp`, `GET /mcp`, `DELETE /mcp`, `MCP-Session-Id`, `MCP-Protocol-Version`, SSE replay, and ready-state admission.
- Preserve OAuth bearer, JWT, introspection, DPoP, mTLS thumbprint, attestation-bound, resource-indicator, and request-time authorization fail-closed semantics.
- Static bearer and admin tokens must be validated before constructing
  `RemoteAuthMode` or admin route state.
- Preserve receipt, revocation, budget, capability, session lifecycle, resumability, shared hosted owner, and admin route behavior.
- Keep changes scoped to `chio-mcp-remote` unless dependent tests prove a compatibility update is required.

## Dependents

- `chio-cli` exposes `chio mcp serve-http` through this crate.
- `chio-hosted-mcp` is a compatibility surface that re-exports the remote server entrypoint.
- `docs/guides/MIGRATING-FROM-MCP.md`, `docs/release/OPERATIONS_RUNBOOK.md`, and `spec/PROTOCOL.md` describe the hosted MCP HTTP/SSE lifecycle.
- `spec/SECURITY.md` defines hosted MCP TLS, DPoP, mTLS, and sender-proof requirements.
- Admin session diagnostics depend on terminal tombstone records staying internally consistent.
