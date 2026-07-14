# chio-http-serve

Graceful shutdown, connection drain, and server-hygiene helpers shared by every
Chio process that serves HTTP over `axum::serve`. It carries no HTTP protocol
types, no authorization logic, and no internal Chio dependencies: a serve site
wraps its own `axum::Router` and `Listener` with these helpers for a
consistent stop-signal, drain, and load-denial posture.

Distinct from `chio-http-core` (the HTTP request/session/verdict/receipt types
and the kernel-backed `HttpAuthority`) and `chio-http-session` (the
per-session audit journal). This crate only governs when a process stops
accepting work and how much concurrent load one serve site admits.

## Responsibilities

- Install a SIGTERM/Ctrl-C handler and fan the result out to cooperating
  tasks over a `watch` channel (`ShutdownController`, `shutdown_signal`).
- Bound only the post-signal drain, never the healthy uptime, then run a
  caller-supplied flush hook (`run_until_drained`).
- Wrap a `Router` with a request timeout, a concurrency limit fronted by load
  shedding, and an optional body-size cap (`apply_server_hygiene`, `ServeHygieneConfig`).
- Cap simultaneously accepted TCP connections at the accept loop with
  back-pressure, while keeping `ConnectInfo` available (`MaxConnListener`, `CappedPeerAddr`).

## Public API

- Shutdown: `ShutdownController` (`install`, `manual`, `subscribe`, `trigger`,
  `is_shutdown`, `signalled`), `shutdown_signal`.
- Drain: `run_until_drained(server, shutdown, drain_timeout, on_drained) ->
  Result<DrainOutcome, ServeError>`; `DrainOutcome::{Clean, Forced}`;
  `ServeError::{Io, Flush}`.
- Hygiene: `apply_server_hygiene(router, &ServeHygieneConfig) -> Router`;
  `ServeHygieneConfig` (`drain_timeout`, `request_timeout`,
  `max_concurrent_requests`, `max_connections`, `max_body_bytes`, conservative
  `Default`); `DEFAULT_DRAIN_TIMEOUT`, `DEFAULT_REQUEST_TIMEOUT`,
  `DEFAULT_MAX_CONCURRENT_REQUESTS`, `DEFAULT_MAX_CONNECTIONS`.
- Listener: `MaxConnListener<L>`, `CappedPeerAddr`, `PermittedIo<Io>`.

## Usage

```rust
use axum::Router;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};

let hygiene = ServeHygieneConfig::default();
let router = apply_server_hygiene(Router::new(), &hygiene);

let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
let listener = MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
let controller = ShutdownController::install();
let server = axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

run_until_drained(server, controller.subscribe(), hygiene.drain_timeout, async {
    Ok::<(), String>(())
})
.await
.unwrap();
```

## Testing

`cargo test -p chio-http-serve`

## See also

- `chio-http-core` - HTTP request/session/verdict/receipt types and
  `HttpAuthority`; this crate only carries the serve loop around it.
- `chio-http-session` - the per-session audit journal; unrelated data model
  despite the shared prefix.
- `chio-proof-room`, `chio-api-protect`, `chio-control-plane`, and other
  `chio-*` services - serve sites that wrap their `Router` with this crate.
