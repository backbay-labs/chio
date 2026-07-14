# chio-mcp-remote architecture

## Overview

`chio-mcp-remote` is the network edge for Chio's hosted MCP surface. It runs
an Axum HTTP service that authenticates every inbound request, then drives a
per-session `chio-kernel` instance that evaluates guards and signs receipts
for each tool call. The crate itself enforces no policy: it is the admission
and session-lifecycle layer in front of the kernel, which is the actual trust
boundary. Every fallible path (store, policy, egress, or kernel construction)
fails closed.

## Module map

`lib.rs` composes the crate unconventionally. `admin.rs` and
`session_store.rs` are declared as real modules via `#[path]`
(`remote_mcp_admin`, `remote_mcp_session_store`); every other
`remote_mcp/*.rs` file is spliced into the crate root with `include!`, so
their items share `lib.rs`'s namespace without `super::` qualification. Two
of the spliced files declare their own nested real modules the same way:
`session_core.rs` for `session_core/{session,factory,ledger}.rs`, and
`oauth.rs` for
`oauth/{local_server,request_validation,helpers,bearer_auth,jwt_support}.rs`;
those nested modules pull the crate-root namespace back in with
`use super::*`.

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: `include!`/`mod` wiring, `pub use chio_control_plane::{CliError, JwtProviderProfile}`. |
| `src/remote_mcp/http_service.rs` | `serve_http`/`serve_http_async`, Axum router assembly, MCP POST/GET/DELETE handlers, SSE streaming, per-IP rate limiter, peer-capability parsing. |
| `src/remote_mcp/http_service_auth.rs` | Request admission: session-id header typing, auth-mode construction, discovery-metadata building, request-time authorization-detail/transaction-context parsing and validation, DPoP sender-constraint verification. |
| `src/remote_mcp/admin.rs` (real module `remote_mcp_admin`) | `/admin/*` routes: health, authority status/rotation, tool/child receipts, revocations, budgets, session trust/drain/shutdown, Prometheus metrics. |
| `src/remote_mcp/oauth.rs` (+ `oauth/`) | Bearer/JWT/introspection authentication (`bearer_auth.rs`); JWT decode and RSA/EC/Ed25519 signature verification (`jwt_support.rs`); the self-issued `LocalAuthorizationServer` (`local_server.rs`); OAuth request validation (`request_validation.rs`); shared signing/error helpers (`helpers.rs`). |
| `src/remote_mcp/session_core.rs` (+ `session_core/`) | `RemoteServeHttpConfig` and session/auth-mode types; `RemoteSessionFactory` spawn/restore (`factory.rs`); `RemoteSession` per-session state machine (`session.rs`); `RemoteSessionLedger` active/terminal bookkeeping (`ledger.rs`). |
| `src/remote_mcp/session_identity.rs` | OIDC discovery, JWKS resolution, JWK-to-public-key parsing, enterprise-provider matching, federated principal and agent-keypair derivation. |
| `src/remote_mcp/session_resume.rs` | Auth-contract and policy fingerprinting; resumable-session integrity-tag computation and validation. |
| `src/remote_mcp/session_shared_upstream.rs` | `SharedUpstreamOwner`/`SharedUpstreamToolServer` for `shared_hosted_owner` mode: one upstream MCP subprocess fanned out to many sessions. |
| `src/remote_mcp/session_forms.rs` | Admin query structs and OAuth authorization/token request forms (serde types only). |
| `src/remote_mcp/session_store.rs` (real module `remote_mcp_session_store`) | SQLite persistence for active-session resume records and terminal tombstones (`remote_active_sessions`, `remote_session_tombstones`). |

## Session lifecycle

1. `serve_http` blocks on a fresh Tokio runtime and calls `serve_http_async`,
   which resolves the auth mode, OAuth discovery metadata, and the optional
   local authorization server, then restores any sessions persisted at
   `session_db_path` before the listener accepts connections.
2. Every `/mcp` request passes `validate_origin` (no `Origin`, or localhost
   only) and `authenticate_session_request`, which dispatches to the
   configured `RemoteAuthMode` and returns a `SessionAuthContext`.
3. An `initialize` request spawns a session:
   `RemoteSessionFactory::spawn_session` loads policy, builds or reuses the
   upstream `AdaptedMcpServer`, constructs a `chio-kernel` wired to the
   receipt/revocation/authority/budget stores, issues default capabilities,
   and starts a `ChioMcpEdge` worker thread reachable only through an `mpsc`
   channel.
4. Established requests re-validate `MCP-Session-Id`, protocol version, and
   that the request's `SessionAuthContext` matches the session's; the
   message is sent to the worker and responses/notifications stream back
   over SSE through a `broadcast` channel, with `Last-Event-ID` replay from a
   bounded retained window.
5. `mark_ready` persists a resumable record after a successful initialize; a
   background `session_reaper_loop` polls
   `RemoteSessionLedger::cleanup_due_sessions` to expire idle sessions,
   finish draining sessions past their grace deadline, and purge old
   tombstones.
6. On restart, `restore_session` re-derives the auth and policy fingerprints,
   checks the stored resume-integrity tag, and re-validates peer
   capabilities before resuming a session without a new `initialize`.

## Invariants and failure modes

- A session never reaches `Ready` without capabilities, a kernel, and a
  running edge worker: any store, policy, or kernel-construction error
  during spawn or restore aborts the session instead of returning a partial
  one.
- `--auth-token` and `--admin-token` are validated when the auth mode and
  admin token are built (non-empty, unpadded, control-character-free) before
  they can seed `RemoteAuthMode::StaticBearer` or admin authorization.
- `--auth-introspection-url` and OIDC discovery/JWKS fetches require an
  `HttpEgressContract`; without one, the verifier or discovery path returns
  an error instead of dispatching the request.
- Resumable session records carry a SHA-256 integrity tag over a canonical
  envelope, keyed by authority/seed/control-token material
  (`derive_resume_record_integrity_seed`); `restore_session` rejects a record
  with a missing, mismatched, or unkeyable tag.
- `transition_to_terminal` is idempotent: a session already in a terminal
  state short-circuits, so a racing reaper expiry and admin shutdown cannot
  overwrite each other's tombstone.
- Admin routes require a same-origin/localhost `Origin` and a constant-time
  bearer comparison (`subtle::ConstantTimeEq`); an unset admin token rejects
  every admin request.
- `MCP-Session-Id` admission is typed (`Missing`/`Invalid`/`Valid`):
  established-session requests require a valid header, `initialize` rejects
  any header at all.

## Dependencies

- `chio-mcp-adapter` supplies `AdaptedMcpServer`, `McpAdapter`,
  `StdioMcpTransport`, and the re-exported `edge::*` (`ChioMcpEdge`,
  `McpEdgeConfig`, `McpTransport`) this crate builds sessions on.
- `chio-kernel` supplies `ChioKernel`, guard/session/DPoP types, and the
  receipt/budget/revocation traits; one kernel instance runs per session.
- `chio-control-plane` supplies policy loading, authority keypair
  management, store configuration (`configure_receipt_store`,
  `configure_revocation_store`, `configure_capability_authority`,
  `configure_budget_store`), and the `CliError`/`JwtProviderProfile` types
  re-exported at the crate root.
- `chio-core` is aliased: the `chio-core` dependency in `Cargo.toml` points
  at the `chio-core-types` package, so `chio_core::` in this crate's source
  is `chio-core-types`.
- `chio-egress-contract` (`reqwest-egress` feature) gates every outbound
  HTTP call: OIDC discovery, JWKS, and token introspection.
- `chio-store-sqlite` backs the receipt, revocation, budget, and
  capability-authority stores; `rusqlite` directly backs this crate's own
  session/tombstone tables.
- `chio-http-serve` supplies connection capping, server hygiene (timeouts,
  drain), and graceful shutdown for the Axum server.
- `chio-metrics-spec` renders the alert-pack families composed into
  `/admin/metrics` alongside `chio_kernel::render_guard_metrics_prometheus`.
- External: `axum` (HTTP/SSE), `async-stream` (SSE generators), `reqwest`
  with `rustls` (egress-contracted HTTP client), `rsa`/`p256`/`p384`/`sha2`/
  `subtle` (JWT signature verification and constant-time comparison), `url`,
  `base64`.
