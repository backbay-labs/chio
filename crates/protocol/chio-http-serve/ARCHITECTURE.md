# chio-http-serve architecture

## Overview

`chio-http-serve` is a leaf infrastructure crate: it depends on no other
`chio-*` crate and holds no protocol, capability, or authorization logic. It
sits underneath every Chio process that terminates HTTP connections via
`axum::serve`, wrapping the site's own `Router` and `Listener` in a shared
shutdown-drain-hygiene stack. It never inspects a request's meaning; it only
governs when the process stops accepting work and how much concurrent load
one site admits before it denies more.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate doc, `#![forbid(unsafe_code)]`, module wiring, public re-exports. |
| `src/signal.rs` | `shutdown_signal` (SIGTERM/Ctrl-C future), `ShutdownController` (`watch`-channel fan-out), `pub(crate) wait_for_shutdown`. |
| `src/drain.rs` | `run_until_drained`, built on `signal::wait_for_shutdown`: bounds only the post-signal drain, then runs the flush hook. `DrainOutcome`, `ServeError`. |
| `src/hygiene.rs` | `ServeHygieneConfig`, `apply_server_hygiene`, `DEFAULT_*` constants: request timeout, concurrency limit fronted by load shedding, optional body cap. |
| `src/listener.rs` | `MaxConnListener`, `CappedPeerAddr`, `PermittedIo`: semaphore-backed connection cap at the accept loop. |
| `src/tests.rs` (`cfg(test)`) | Integration tests against real ephemeral TCP listeners: drain, hygiene denials, connection cap. |

## Composition and drain lifecycle

A serve site wires four independent pieces around its own `Router` and
`Listener`; nothing in this crate calls the others automatically.

1. `ServeHygieneConfig` is one struct read by three call sites.
   `apply_server_hygiene` reads only `max_body_bytes`, `request_timeout`, and
   `max_concurrent_requests`; `max_connections` goes to `MaxConnListener::new`
   and `drain_timeout` goes to `run_until_drained` directly, as
   `chio-proof-room`'s `serve_proof_room` does.
2. `ShutdownController::install` spawns a task awaiting `shutdown_signal` and
   publishes on a `watch` channel; `manual` builds the same controller without
   the OS task, for tests or an embedding with its own signal source.
   `controller.signalled()` feeds `with_graceful_shutdown`; `subscribe()`
   hands a receiver to `run_until_drained` and any other cooperating loop.
3. `run_until_drained` runs the serve future unbounded until it exits on its
   own or the signal fires. Only then does a `drain_timeout` deadline arm
   around the remaining in-flight requests.
4. A deadline that elapses yields `DrainOutcome::Forced` and drops the serve
   future to release the accept loop and listener; axum still finishes each
   already-dispatched connection on its own detached task in the background.
5. The `on_drained` flush hook always runs last, on both outcomes. A forced
   drain can race a still-finishing straggler connection, so the hook must
   tolerate a concurrent writer; call sites keep this safe by committing each
   acknowledged unit of work synchronously in the request handler, never in
   the flush hook.

## Invariants and failure modes

- Fail-closed signal install: a handler that cannot be installed logs and
  parks on `pending()` rather than resolving, so a missing handler degrades to
  the platform default kill instead of crash-looping or firing a spurious
  shutdown at startup.
- `DEFAULT_REQUEST_TIMEOUT` (20s) is strictly below `DEFAULT_DRAIN_TIMEOUT`
  (25s), asserted by a dedicated test, so a request admitted just before a
  stop signal reaches its own 408 inside the drain window instead of a
  forced-close severance.
- Hygiene denials are explicit and typed, never silent queuing: `TimeoutLayer`
  denies with 408, `LoadShedLayer`-in-front-of-`GlobalConcurrencyLimitLayer`
  denies over-concurrency with 503 through a `HandleErrorLayer`, and
  `DefaultBodyLimit` denies an oversized body with 413.
- `MaxConnListener::accept` acquires a semaphore permit before pulling the
  next connection off the OS queue, so a saturated server back-pressures the
  accept loop instead of buffering sockets it cannot serve. The permit
  releases only when the connection's IO drops; the semaphore is never
  closed, so a drain never revokes a still-finishing connection's permit.
- `MaxConnListener::new` clamps `max_connections` to `Semaphore::MAX_PERMITS`,
  so `usize::MAX` is a valid "uncapped" sentinel rather than a startup panic.
- Capping the listener changes its accepted IO type (`PermittedIo<L::Io>`),
  moving the site out of axum's built-in `Connected<_> for SocketAddr`; a site
  needing the peer address serves
  `into_make_service_with_connect_info::<CappedPeerAddr>()` instead.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

No internal `chio-*` crates. External: `axum` (`Router`, `serve::Listener`,
`DefaultBodyLimit`) and `tower` / `tower-http` (`GlobalConcurrencyLimitLayer`,
`LoadShedLayer`, `TimeoutLayer`, `HandleErrorLayer`) build the hygiene stack;
`tokio` (`sync::watch`, `sync::Semaphore`, `signal`) supplies the runtime
primitives; `tracing` logs signal and drain events; `thiserror` derives
`ServeError`. `axum` and `tower-http` are version-pinned directly in
`[dependencies]` rather than through the workspace table that `tokio`,
`tracing`, `thiserror`, and `tower` use.

## Extension points

`MaxConnListener<L>` is generic over any `L: Listener` (for example
`tokio::net::TcpListener`, a Unix-socket listener, or a TLS-terminating
listener), so the connection cap applies regardless of transport.
