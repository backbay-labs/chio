# RFC-0010: Graceful shutdown, drain, and server hygiene

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: none
- Depends on: RFC-0001 (hot-path deadlines and watchdogs)
- Closes findings: F61, F11, F63 (see ./README.md and the readiness review); cross-references RFC-0004 for the OS-level memory and OOM guidance

## Summary

Not one of the six `axum::serve` sites in the workspace installs a shutdown
handler, so SIGTERM (delivered on every routine deploy, scale event, and node
rotation) triggers the Rust default action and terminates the process
immediately. In-flight tool-call evaluations, proxy requests, and receipt writes
are severed mid-flight, and any request in the post-side-effect, pre-receipt-commit
window loses its audit receipt for an action that already executed. This RFC adds
one shared crate (`chio-http-serve`) that provides a fail-closed shutdown signal
(SIGTERM plus Ctrl-C feeding a `tokio::sync::watch` channel), a bounded drain
sequence (stop accepting, wait for in-flight work up to a deadline, flush the
receipt commit actor, exit), and a reusable server-hygiene layer stack (request
timeout, global concurrency limit with load-shed, body-size limit, and an optional
connection cap). All six serve sites are rewired to it. The trust-control server,
which today applies exactly one response-header layer, gains the full hygiene stack
(F11). Shippable systemd units for trust-control and the MCP edge close the
supervisor gap (F63) with `TimeoutStopSec` sized to the drain bound; the memory and
overcommit directives are owned by RFC-0004 and cross-referenced here. The posture
is fail-closed throughout: a handler that cannot be installed degrades loudly to the
pre-RFC behavior rather than crash-looping, and the hygiene limits deny (413 / 408 /
503) rather than accept unbounded work.

## Motivation

The Ubicloud "PostgreSQL and the OOM Killer" lens asks five things of an overload
or a crash: fail early, local, and graceful (not process death, not unbounded
growth); know the blast radius when a component dies mid-operation; keep internal
accounting trustworthy or loudly broken; keep budgets predictable; recover durably.
An unmanaged SIGTERM fails the first four for every serving process at once.

- **F61 (high, CONFIRMED): no graceful shutdown or drain anywhere.** Trigger: any
  routine deploy, scale event, or node rotation. Cloud Run, ECS, Azure Container
  Apps, Kubernetes, and systemd all send SIGTERM first and only escalate to SIGKILL
  after a grace period (commonly 10s to 30s). Effect: with no signal handler the
  Rust runtime takes the default terminate action and the process dies at once,
  ignoring the entire grace window. In-flight evaluations, proxy requests, and
  receipt writes are cut mid-flight. Blast radius: clients see connection resets on
  every deploy, and any request that has already applied its upstream side effect
  but has not yet committed its receipt loses that receipt permanently. On a kernel
  that mediates every tool call, this is an audit gap exercised probabilistically on
  every restart.
- **F11 (high, CONFIRMED): the trust-control HTTP server has no shutdown, timeouts,
  connection caps, or explicit body / concurrency limits.** Trigger: routine
  SIGTERM, a connection flood, or slow clients against the trust-control listener.
  Effect: SIGTERM aborts in-flight budget, revocation, and receipt requests
  mid-response; accepted connections and per-connection tasks accumulate with no
  read or processing ceiling. Blast radius: the single service that hosts capability
  revocation and budget authority for the cluster becomes unresponsive or dies on
  resource exhaustion, stalling revocation propagation and budget writes for every
  dependent kernel and tenant.
- **F63 (medium, CONFIRMED): no supervisor or OOM guidance for the documented
  bare-metal deployments.** Trigger: the runbook deploys trust-control and the MCP
  edge as raw foreground CLI invocations with no unit file, so there is no restart
  policy and no place to declare a shutdown grace period. Effect: a SIGKILL (from
  the OOM killer or an unmanaged deploy) takes down the mediator with no auto-restart
  and no configured grace window in which the F61 drain could run. Blast radius: full
  mediation outage until a human restarts. WAL plus `synchronous = FULL` keeps state
  consistent, so this is loud availability loss rather than corruption, but the drain
  work of F61 is worthless without a grace window (F63) to run it in.

The common shape: the platform offers a grace period on every stop, and Chio uses
none of it.

## Current behavior (verified 2026-07-04)

A workspace grep for `with_graceful_shutdown`, `tokio::signal`, `ctrl_c`, and
`SIGTERM` over `crates/**/*.rs` returns zero hits outside vendored `node_modules`.
There is no signal handling in any server binary. The six serve sites, each quoted
from current code:

1. **Trust-control** (`crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs:34`):

   ```rust
   // pub(crate) async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError>  (init.rs:5)
   axum::serve(listener, router).await.map_err(|error| {
       CliError::cli_other_error(format!("trust control service failed: {error}"))
   })
   ```

   Entry chain: `dispatch/trust.rs:54` -> `cmd_trust_serve` (`runtime.rs:957`) ->
   `trust_control::serve` (`config_and_public.rs:26`, a multi-thread
   `runtime.block_on`) -> `serve_async`. The router (`service_runtime/router.rs:10`,
   `pub(crate) fn build_router(state: TrustServiceState) -> Router`) applies exactly
   one layer, and only after the routes and dashboard fallback are wired
   (router.rs:544-548):

   ```rust
   let csp_value = HeaderValue::from_static(CSP_VALUE);
   router.layer(SetResponseHeaderLayer::overriding(
       axum::http::header::CONTENT_SECURITY_POLICY,
       csp_value,
   ))
   ```

   There is no `TimeoutLayer`, no concurrency limit, no load-shed, no body limit, and
   no connection cap. Health is a single `/health` route
   (`trust_control/health.rs:5-9`, `install_health_routes`); there is no readiness
   endpoint whose state can be flipped during a drain.

2. **Remote MCP edge** (`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs:249`),
   inside `async fn serve_http_async(config: RemoteServeHttpConfig) -> Result<(), CliError>`
   (http_service.rs:116). A `session_reaper_loop` background task is spawned at
   http_service.rs:203 with no stop signal:

   ```rust
   axum::serve(
       listener,
       router.into_make_service_with_connect_info::<SocketAddr>(),
   )
       .await
       .map_err(|error| CliError::cli_other_error(format!("remote MCP edge server failed: {error}")))
   ```

3. **API-protect proxy** (`crates/products/chio-api-protect/src/proxy/state.rs:323`),
   inside `pub async fn run_with_observer<F>(self, observer: F) -> Result<(), ProtectError>`
   (state.rs:220):

   ```rust
   axum::serve(
       listener,
       app.into_make_service_with_connect_info::<SocketAddr>(),
   )
   .await
   .map_err(ProtectError::Io)?;
   ```

   `ProxyState` (state.rs:138) holds
   `pub(crate) receipt_store: Option<Mutex<SqliteReceiptStore>>` (state.rs:147).
   Note carefully: this `SqliteReceiptStore` is api-protect's own local type
   (`pub(crate) struct SqliteReceiptStore { connection: Connection }`,
   proxy/state.rs:13), a plain rusqlite wrapper whose `append` (state.rs:81) runs a
   blocking `INSERT` and returns only after it commits; there is no commit actor and
   no flush API on this store, and the `Mutex` is `tokio::sync::Mutex`
   (proxy.rs:19), not std. The F61 window here is therefore the in-flight request
   itself: SIGTERM severs a proxied call after its upstream side effect but before
   the handler reaches the synchronous receipt `INSERT`. Draining in-flight
   requests closes it; no post-drain flush is needed at this site. This is still
   the widest exposure because every proxied call crosses that window.

4. **Pheromone relay** (`crates/trust/chio-pheromone-relay/src/service.rs:270`),
   inside `pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), PheromoneRelayError>`
   (service.rs:256). This site already applies one hygiene layer, a body limit
   (service.rs:268, `DefaultBodyLimit::max(max_body_bytes)`), but no timeout,
   concurrency limit, or shutdown:

   ```rust
   axum::serve(listener, router)
       .await
       .map_err(|error| PheromoneRelayError::Http(error.to_string()))
   ```

5. **Proof-room server** (`crates/products/chio-proof-room/src/server.rs:60`), inside
   `pub async fn serve_proof_room(config: ProofRoomServeConfig) -> Result<(), ProofRoomError>`
   (server.rs:48), reached from `proof-room/src/main.rs:14`:

   ```rust
   axum::serve(listener, router)
       .await
       .map_err(ProofRoomError::Serve)
   ```

6. **Proof serve (CLI)** (`crates/products/chio-cli/src/cli/dispatch/proof/serve.rs:87`),
   inside `serve_proof_bundle`. Note this site runs on a current-thread runtime built
   with `.enable_all()` (serve.rs:65-68), so the signal driver is available:

   ```rust
   axum::serve(listener, router)
       .await
       .map_err(|error| CliError::cli_io_error(format!("proof serve: {error}")))
   ```

Supporting facts for the design:

- The durable receipt store already exposes a bounded flush. On
  `chio_store_sqlite::SqliteReceiptStore`,
  `pub fn flush_receipt_writes_with_timeout(&self, timeout: Duration) -> Result<ReceiptFlushReport, ReceiptStoreError>`
  (`crates/platform/chio-store-sqlite/src/receipt_store.rs:605`) delegates to the
  commit actor's `flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError>`
  (receipt_store.rs:210, invoked at receipt_store.rs:609). Two facts scope where
  this matters. First, the actor acknowledges an `append` only after the batch
  commits (`ReceiptCommitActor::append` blocks on `result.recv()`,
  receipt_store.rs:161-201; `commit_receipt_batch` sends responses after the
  batch write, receipt_store.rs:318-356), so every receipt whose append returned
  `Ok` is already in WAL; the actor queue holds only receipts belonging to
  still-in-flight requests, and the drain is the primary F61 fix. The post-drain
  flush is the verification backstop: it proves the queue is empty and surfaces
  any pending writer error loudly. Second, in the six serve processes this store
  is held by the MCP edge's per-session kernels
  (`session_core/factory.rs:88-95` builds each session kernel and
  `configure_receipt_store` at `chio-control-plane/src/lib.rs:388` installs
  `chio_store_sqlite::SqliteReceiptStore::open(path)` via
  `kernel.set_receipt_store`), not by api-protect (which has its own synchronous
  local store, above). Kernel access to the store is crate-private
  (`pub(crate) fn with_receipt_store` at
  `chio-kernel/src/kernel/construction.rs:123`), so the MCP-edge drain hook needs
  one small public passthrough,
  `ChioKernel::flush_receipt_writes_with_timeout(&self, Duration) -> Result<ReceiptFlushReport, KernelError>`,
  delegating to `with_receipt_store`; the store API itself needs no change.
- WAL plus `synchronous = FULL` is enforced and asserted at store open
  (`crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs:3-46`), so
  a receipt that reaches disk survives a crash; the loss window is strictly the
  in-actor, not-yet-flushed queue that the drain hook flushes.
- The workspace already depends on `tower = "0.5"` with `features = ["util", "make",
  "buffer", "timeout", "load-shed", "limit", "retry"]` (`Cargo.toml:328`) and every
  serve-site crate uses `tokio = { workspace = true }` (the `full` feature set, which
  includes `signal`) and `axum = "0.8"`. The building blocks exist; nothing new is
  vendored.
- The only in-repo unit files are the two pheromone-relay units
  (`docs/release/chio-pheromone-relay/systemd/chio-pheromone-relay.service`), which
  carry `Restart=on-failure` and sandboxing but no `MemoryMax`, `OOMScoreAdjust`,
  `LimitNOFILE`, or `TimeoutStopSec`. Trust-control and the MCP edge are started as
  bare foreground processes in the runbook (`docs/release/OPERATIONS_RUNBOOK.md:107-121,133-148`).

## Design

### 1. New crate: `chio-http-serve`

A single small leaf crate, `crates/protocol/chio-http-serve`, holds the shared
helper so all six sites (which span the `platform`, `protocol`, `products`, and
`trust` groups) can depend on it without a cycle. It depends only on `tokio`
(`signal`, `rt`, `macros`, `sync`, `time`), `axum` (`0.8`), `tower` (`util`,
`limit`, `load-shed`), `tower-http` (`0.6`, `timeout`, `limit`), `tracing`, and
`thiserror`. Because it centralizes the tower features, the call sites do not add
any tower features of their own; they add one dependency and call two functions.

### 2. Shutdown signal and controller

The signal future is fail-closed against handler-install failure: it never resolves
spuriously at startup (which would crash-loop the process), and if a handler cannot
be installed it logs loudly and falls back to a pending branch so the other signal
still governs. If both fail, the process reverts to the pre-RFC behavior (platform
SIGKILL after grace), logged, which is no worse than today.

```rust
use std::future::Future;
use tokio::sync::watch;
use tracing::{error, warn};

/// Resolves on the first SIGTERM (unix) or Ctrl-C / SIGINT (all platforms).
/// A handler that cannot be installed logs and yields to a pending branch
/// rather than resolving early; it never triggers a spurious shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(source) => {
                error!(%source, "cannot install Ctrl-C handler; SIGTERM path still governs");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(source) => {
                error!(%source, "cannot install SIGTERM handler; Ctrl-C path still governs");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
```

The controller installs the handler once, exposes a `watch` receiver for background
loops (session reaper, cluster sync, checkpoint task) to stop cooperatively, and
hands the drain future to `with_graceful_shutdown`.

```rust
/// Owns the shutdown watch channel. Cheap to clone the receivers it hands out.
pub struct ShutdownController {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl ShutdownController {
    /// Spawn the signal task. The returned controller is live immediately.
    #[must_use]
    pub fn install() -> Self {
        let (tx, rx) = watch::channel(false);
        let task_tx = tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            // A closed channel (all receivers dropped) is not an error here.
            let _ = task_tx.send(true);
        });
        Self { tx, rx }
    }

    /// Receiver for background loops: `while !*rx.borrow_and_update() { rx.changed().await? }`.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }

    /// Trigger a drain programmatically (tests, admin `/shutdown`, fatal-error paths).
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// The future to pass to `with_graceful_shutdown`.
    #[must_use]
    pub fn signalled(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.rx.clone();
        async move {
            while !*rx.borrow_and_update() {
                if rx.changed().await.is_err() {
                    break; // sender dropped: treat as a shutdown request
                }
            }
        }
    }
}
```

### 3. Hygiene config and layer stack (F11)

```rust
use std::time::Duration;

/// Bounds and hygiene knobs for one serve site. `Default` is a conservative,
/// fail-closed posture: requests that exceed a bound are denied, not queued.
#[derive(Debug, Clone)]
pub struct ServeHygieneConfig {
    /// Wall-clock ceiling on the drain: how long to wait for in-flight requests
    /// to complete after the listener stops accepting. Operators must set the
    /// unit `TimeoutStopSec` at least this high. Default 25s.
    pub drain_timeout: Duration,
    /// Per-request processing timeout (`tower_http::timeout::TimeoutLayer`).
    /// `None` disables. Default `Some(30s)`.
    pub request_timeout: Option<Duration>,
    /// Max concurrent in-flight requests (`GlobalConcurrencyLimitLayer` under a
    /// `LoadShedLayer`, so surplus load sheds with 503 instead of queuing).
    /// `None` disables. Default `Some(1024)`.
    pub max_concurrent_requests: Option<usize>,
    /// Max simultaneously accepted TCP connections. `None` disables.
    /// Default `Some(2048)`.
    pub max_connections: Option<usize>,
    /// Global request body-size cap (`axum::extract::DefaultBodyLimit`). `None`
    /// preserves each route's own limit. Default `None`, because sites such as
    /// proof-room set a 32 MiB upload limit on one route that a global cap would
    /// clobber. Sites without any route-local limit set this explicitly.
    pub max_body_bytes: Option<usize>,
}

pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(25);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 2048;

impl Default for ServeHygieneConfig {
    fn default() -> Self {
        Self {
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            max_concurrent_requests: Some(DEFAULT_MAX_CONCURRENT_REQUESTS),
            max_connections: Some(DEFAULT_MAX_CONNECTIONS),
            max_body_bytes: None,
        }
    }
}
```

The layer stack is applied to the `axum::Router` before any
`into_make_service_with_connect_info` call, so the return type stays `Router` and no
site touches tower types beyond this function. Load-shed must sit outside the
concurrency limit so that requests over the limit fail fast with `Overloaded`
(mapped to 503) instead of parking. One axum constraint shapes the code:
`Router::layer` only accepts layers whose service is infallible, and both
`LoadShed` and `GlobalConcurrencyLimit` are fallible (`LoadShed` errors with
`Overloaded`), so the pair must be wrapped in
`axum::error_handling::HandleErrorLayer`, which converts the error into a
response. In a `ServiceBuilder`, the first layer listed is outermost, giving
`HandleError(LoadShed(ConcurrencyLimit(router)))`:

```rust
use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::Router;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::load_shed::LoadShedLayer;
use tower::{BoxError, ServiceBuilder};
use tower_http::timeout::TimeoutLayer;

async fn shed_to_status(error: BoxError) -> StatusCode {
    if error.is::<tower::load_shed::error::Overloaded>() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Apply request timeout, concurrency + load-shed, and an optional body cap.
#[must_use]
pub fn apply_server_hygiene(mut router: Router, cfg: &ServeHygieneConfig) -> Router {
    if let Some(limit) = cfg.max_body_bytes {
        router = router.layer(DefaultBodyLimit::max(limit));
    }
    if let Some(timeout) = cfg.request_timeout {
        router = router.layer(TimeoutLayer::new(timeout));
    }
    if let Some(max) = cfg.max_concurrent_requests {
        router = router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(shed_to_status))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(max)),
        );
    }
    router
}
```

`TimeoutLayer` yields a 408 on expiry, `LoadShedLayer` yields a 503 when the
concurrency limit is saturated, and `DefaultBodyLimit` yields a 413 on oversize.
All three are denials, matching the fail-closed house rule.

### 4. Connection cap: semaphore-guarded listener

`axum::serve` does not expose a connection cap or hyper header-read timeout, so the
cap is a listener adapter. It implements `axum::serve::Listener`, acquiring one
permit per accepted connection and releasing it when the connection's IO is dropped.
When the semaphore is exhausted, `accept` waits (back-pressure at the accept loop)
rather than unbounded-buffering new sockets.

```rust
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Wraps any `axum::serve::Listener` with a hard cap on concurrent connections.
pub struct MaxConnListener<L> {
    inner: L,
    permits: Arc<Semaphore>,
}

impl<L> MaxConnListener<L> {
    #[must_use]
    pub fn new(inner: L, max_connections: usize) -> Self {
        // `Semaphore::new` panics above `Semaphore::MAX_PERMITS`; clamp so the
        // "no cap" sentinel (`usize::MAX`) is safe rather than a startup panic.
        let permits = max_connections.min(Semaphore::MAX_PERMITS);
        Self { inner, permits: Arc::new(Semaphore::new(permits)) }
    }
}
```

The `Listener` impl holds the permit alongside the connection IO by returning a
`PermittedIo { io, _permit: OwnedSemaphorePermit }` wrapper that forwards
`AsyncRead`/`AsyncWrite` and drops the permit with the connection. `Semaphore::close`
is never called on the drain path, so accepted connections keep their permits until
they finish draining. This adapter is optional per site (`max_connections: None`
skips it); trust-control and the two proof servers enable it, and the kernel-backed
edges (mcp, api-protect) rely primarily on the concurrency limit plus the connection
cap together.

### 5. Bounded drain and error taxonomy

`with_graceful_shutdown` stops accepting on signal and then waits for in-flight
connections, but it waits indefinitely. RFC-0001 gives every mediation-path await a
budget, so in-flight evaluations converge; this RFC adds the backstop bound around
the post-signal drain and then runs the flush hook. The deadline must arm only when
the shutdown signal fires, never at server start (a naive
`tokio::time::timeout(drain_timeout, server)` around the whole serve future would
kill a healthy server `drain_timeout` after boot), so `run_until_drained` takes a
shutdown receiver and runs in two phases:

```rust
use std::time::Duration;
use tokio::sync::watch;
use tracing::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// All in-flight work completed before `drain_timeout`.
    Clean,
    /// The drain deadline elapsed; remaining connections were force-closed.
    Forced,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("serve I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Post-drain flush of a receipt store failed. Fail-closed: this is a real
    /// error the operator must see (a non-zero exit), because it means receipts
    /// may not be durable. It is never swallowed.
    #[error("post-drain receipt flush failed: {0}")]
    Flush(String),
}

/// Run a graceful serve future to completion, bounding only the post-signal
/// drain, then flush. `server` is the site's
/// `axum::serve(..).with_graceful_shutdown(ctrl.signalled())` future;
/// `shutdown` is `ctrl.subscribe()`; `on_drained` flushes the site's receipt
/// store(s) (or is a no-op).
pub async fn run_until_drained<S, D>(
    server: S,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
    on_drained: D,
) -> Result<DrainOutcome, ServeError>
where
    // `axum::serve(..).with_graceful_shutdown(..)` returns an `IntoFuture`
    // type, not a `Future`; accept it directly so call sites pass it as-is.
    S: std::future::IntoFuture<Output = std::io::Result<()>>,
    D: std::future::Future<Output = Result<(), String>>,
{
    // Box-pin rather than `tokio::pin!` so the forced-drain path can DROP the
    // serve future before the flush runs. A stack `Pin<&mut _>` from
    // `tokio::pin!` cannot be dropped early (it only borrows), but an owned
    // `Pin<Box<_>>` can, and dropping it force-closes any connection still
    // stuck at the deadline.
    let mut server = Box::pin(server.into_future());
    let signalled = async move {
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                break; // sender dropped: treat as a shutdown request
            }
        }
    };
    // Phase 1: serve until the server exits on its own or the signal fires.
    let outcome = tokio::select! {
        result = &mut server => match result {
            Ok(()) => DrainOutcome::Clean,
            Err(source) => return Err(ServeError::Io(source)),
        },
        () = signalled => {
            // Phase 2: the graceful-shutdown future has stopped the accept
            // loop; bound only the remaining in-flight drain.
            match tokio::time::timeout(drain_timeout, &mut server).await {
                Ok(Ok(())) => DrainOutcome::Clean,
                Ok(Err(source)) => return Err(ServeError::Io(source)),
                Err(_elapsed) => {
                    let drain_ms =
                        u64::try_from(drain_timeout.as_millis()).unwrap_or(u64::MAX);
                    warn!(
                        drain_timeout_ms = drain_ms,
                        "drain deadline exceeded; force-closing remaining connections"
                    );
                    DrainOutcome::Forced
                }
            }
        }
    };
    // On a forced drain the serve future is still holding open the stuck
    // connection(s). Drop it BEFORE `on_drained` so no handler can still be
    // writing when the receipt flush runs (the ordering documented in
    // section 6: nothing is writing during `on_drained`). A `Clean` outcome
    // has already run the future to completion, so this drop is a no-op there.
    if matches!(outcome, DrainOutcome::Forced) {
        drop(server);
    }
    on_drained.await.map_err(ServeError::Flush)?;
    Ok(outcome)
}
```

On `Forced`, dropping the serve future closes the remaining connections BEFORE the
flush hook runs, so no in-flight handler can enqueue or hold a receipt write after
the flush has completed; the process then exits through the normal path.

### 6. Drain sequence and ordering

Each site runs one ordered sequence. Steps 2 and 5 are hooks that no-op when a site
has nothing to do (trust-control and the proof servers have no async commit actor;
proof-room is read-only static serving).

1. **Signal received.** The `ShutdownController` watch flips to `true`.
2. **Flip readiness to NotReady (best-effort).** So a load balancer or service mesh
   stops routing new requests during the grace window. This needs a mutable
   readiness endpoint (finding F59). RFC-0010 exposes an optional
   `readiness: Option<watch::Sender<ReadyState>>` on the controller and flips it
   first; sites that predate the F59 endpoint pass `None` and the step is a no-op,
   so RFC-0010 lands without F59. When F59 lands, the flip becomes live.
3. **Stop accepting.** `with_graceful_shutdown(ctrl.signalled())` fires; the accept
   loop ends and the connection cap's `Semaphore` stops issuing new permits.
4. **Drain in-flight, bounded.** `run_until_drained` waits up to `drain_timeout`
   (RFC-0001 budgets guarantee convergence; the deadline is the backstop for a stuck
   request predating that wiring).
5. **Flush receipt stores (verification backstop).** `on_drained` calls
   `flush_receipt_writes_with_timeout(drain_timeout)` on every long-lived
   commit-actor store the process holds. Because the actor acknowledges appends
   only after commit, step 4 already made every acknowledged receipt durable;
   this step proves the actor queue is empty and surfaces any pending writer
   error as a loud, non-zero exit. Meaningful only at the MCP edge, which flushes
   each live session kernel's store through the new
   `ChioKernel::flush_receipt_writes_with_timeout` passthrough by iterating the
   session ledger; a no-op at api-protect and the relay (their local rusqlite
   stores write synchronously inside handlers, so the drain in step 4 is the
   whole fix) and at the read-only proof servers.
6. **Stop background loops.** Loops that hold a `subscribe()` receiver (session
   reaper at http_service.rs:203, cluster sync at init.rs:26, RFC-0001's checkpoint
   task) select on `rx.changed()` and return, so no task outlives the drain.
7. **Return.** `Ok(DrainOutcome::Clean | Forced)` -> exit 0; `Err(ServeError)` ->
   non-zero exit so a failed flush is loud.

Locking note: `on_drained` runs after the server future resolves, so it cannot
contend with request handlers still writing receipts. At the MCP edge the session
ledger lock is taken once to snapshot the live sessions, and each session store is
flushed outside that lock; the flush itself is the store's own bounded call, so no
async mutex is held across an await.

### 7. Per-site wiring

Each site keeps its own `axum::serve(..)` expression, appends
`.with_graceful_shutdown(ctrl.signalled())`, applies `apply_server_hygiene` to the
router before `into_make_service*`, optionally wraps the listener in
`MaxConnListener`, and returns through `run_until_drained`. Example, the widest
receipt-loss site (api-protect, `run_with_observer`, state.rs:304-328). Its local
store writes synchronously inside handlers, so the drain is the whole F61 fix here
and `on_drained` is an explicit no-op:

```rust
let ctrl = chio_http_serve::ShutdownController::install();
let cfg = chio_http_serve::ServeHygieneConfig::default();
let app = chio_http_serve::apply_server_hygiene(build_app(Arc::clone(&state)), &cfg);
let listener = chio_http_serve::MaxConnListener::new(
    listener,
    cfg.max_connections.unwrap_or(usize::MAX), // new() clamps; MAX means uncapped
);

let server = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
    .with_graceful_shutdown(ctrl.signalled());

// api-protect's receipt store (proxy/state.rs:13) commits synchronously in
// `append`; completing in-flight requests is the durability guarantee, so
// there is nothing left to flush after the drain.
let outcome = chio_http_serve::run_until_drained(server, ctrl.subscribe(), cfg.drain_timeout, async {
    Ok::<(), String>(())
})
.await
.map_err(|error| ProtectError::Io(std::io::Error::other(error.to_string())))?;
```

At the MCP edge, `on_drained` instead snapshots the live sessions from the session
ledger and calls the new `ChioKernel::flush_receipt_writes_with_timeout`
passthrough on each session kernel, joining the per-session errors into one
`Err(String)` so a single failed flush is loud.

| Site | Serve fn (current line) | Background loop to stop | `on_drained` flush |
| --- | --- | --- | --- |
| Trust-control | `serve_async` (init.rs:34) | cluster sync (init.rs:26) | no-op (per-handler synchronous writes) |
| MCP edge | `serve_http_async` (http_service.rs:249) | session reaper (http_service.rs:203) | per-session kernel store flush (new `ChioKernel` passthrough) |
| API-protect | `run_with_observer` (state.rs:323) | none | no-op (synchronous local store; drain completes in-flight writes) |
| Pheromone relay | `serve` (service.rs:270) | none | no-op (synchronous rusqlite relay store) |
| Proof-room | `serve_proof_room` (server.rs:60) | none | no-op (read-only) |
| Proof serve (CLI) | `serve_proof_bundle` (serve.rs:87) | none | no-op (read-only) |

The trust-control router already funnels through `build_router`, so
`apply_server_hygiene(build_router(state), &cfg)` in `serve_async` closes F11 in one
edit. Its `ServeHygieneConfig` sets `max_body_bytes: Some(1 * 1024 * 1024)` (no
route-local limit exists today) and `max_connections: Some(2048)`. The pheromone
relay keeps its existing `DefaultBodyLimit` (leave `max_body_bytes: None`) and gains
the timeout, concurrency, and shutdown layers.

### 8. Deployment units and OS guidance (F63)

The drain work of F61 is only reachable if the supervisor allows a grace window, so
this RFC ships two new reference units and hardens the existing relay unit for the
drain, cross-referencing RFC-0004 for the memory and overcommit directives.

- New `docs/release/systemd/chio-trust-control.service` and
  `docs/release/systemd/chio-mcp-edge.service`, each with:
  - `Type=simple`, dedicated `User`/`Group`, `StateDirectory`,
    `ConfigurationDirectory`, and the same `NoNewPrivileges` / `ProtectSystem=strict`
    sandboxing as the relay unit.
  - `Restart=on-failure`, `RestartSec=5s` (closes the "no auto-restart" half of F63).
  - `KillSignal=SIGTERM` (systemd's default, made explicit) so the drain path runs.
  - `TimeoutStopSec=35s`, chosen as `drain_timeout` (25s) plus flush and margin, so
    systemd's escalation to SIGKILL happens strictly after the bounded drain can
    finish, not during it. This is the unit-level counterpart of `drain_timeout`.
- The relay unit gains `TimeoutStopSec=35s` and `KillSignal=SIGTERM` for the same
  reason.
- Memory and OOM directives (`MemoryMax`, `MemoryHigh`, `OOMScoreAdjust`,
  `LimitNOFILE`, `LimitAS`, and `vm.overcommit_memory`) are specified once in RFC-0004
  section 5 ("Per-process RSS ceiling wired to cgroup MemoryMax", RFC-0004:612-651)
  and its "OS-level deployment guidance" appendix (RFC-0004:801-829, which also
  claims the OOM-guidance half of F63). RFC-0010 does not
  restate them; the new units reference RFC-0004 for the values and the runbook links
  both. This keeps a single source of truth for the OOM posture.
- A short runbook subsection replaces the raw foreground `chio trust serve` /
  `chio mcp serve-http` invocations (OPERATIONS_RUNBOOK.md:107-148) with
  `systemctl` steps that install these units, and documents the deploy contract:
  operators must set the platform grace period (Cloud Run `timeoutSeconds` drain, ECS
  `stopTimeout`, Kubernetes `terminationGracePeriodSeconds`) at least as high as
  `TimeoutStopSec`.

### Crates, LOC, and CI-tier placement

One new crate; the rest are edits at the six serve sites plus doc and unit files. No
source changes to signed payloads.

| Area | Files | Rough LOC |
| --- | --- | --- |
| New `chio-http-serve` (signal, controller, hygiene, listener cap, drain) | `crates/protocol/chio-http-serve/src/lib.rs` + `Cargo.toml` | ~320 |
| `ChioKernel::flush_receipt_writes_with_timeout` passthrough (public, delegates to `with_receipt_store`) | `chio-kernel/src/kernel/construction.rs` | ~15 |
| Six serve-site rewires (MCP edge also gains the session-ledger flush hook) | init.rs, http_service.rs, state.rs, service.rs, server.rs, serve.rs | ~30 each, ~180 |
| Trust-control hygiene config wiring | `service_runtime/init.rs`, `config_and_public.rs` | ~40 |
| Systemd units + runbook | `docs/release/systemd/*.service`, relay unit, OPERATIONS_RUNBOOK.md | ~120 |

CI tiers: the crate's unit and property tests run on the PR gate; the loom test on
the watch/drain ordering runs nightly; the SIGTERM soak and the drain-under-load
chaos scenarios run weekly under the PLAN-load-chaos program
(PLAN-load-soak-chaos-program.md). Honest runtimes:
PR-gate tests under 5s each (they use an in-process listener and a fake signal via
`ShutdownController::trigger`); the weekly SIGTERM-under-load soak runs ~10 min per
serve site.

## Wire, schema, and receipt impact

- **Signed payloads: none.** No receipt kind, capability, or attestation schema
  changes. A drain flushes existing receipts unchanged; canonical JSON (RFC 8785)
  serialization is untouched.
- **Receipt kinds: none new.** The value is that already-written receipts reach WAL
  before exit, closing the F61 loss window; the receipt bytes are identical.
- **HTTP surface: additive and denial-only.** New 408 (timeout), 503 (load-shed), and
  413 (body limit) responses can now occur under overload; no success response
  changes. A readiness endpoint that flips to NotReady is deferred to F59; RFC-0010
  only provides the optional flip hook.
- **Config: additive.** `ServeHygieneConfig` is a builder input constructed in each
  serve fn with defaults, not a wire type; no serialized config file changes are
  required to adopt the defaults. If a site later surfaces these as CLI flags, they
  are additive optional flags.
- **Systemd units: new files**, not a wire or schema surface.

## Migration and compatibility

- Adopting the defaults changes no success-path behavior: a healthy deploy under the
  concurrency and body ceilings behaves as today, and now drains cleanly on SIGTERM
  instead of resetting connections.
- The request timeout (30s) is a deliberate, safe change: a request that already
  exceeds 30s today is a latent hang; under RFC-0001 budgets it would already have
  been denied. Sites with legitimately long-lived streams (none of the six serve a
  long-poll on the mediation path) would set `request_timeout: None`.
- The connection cap and concurrency limit default to generous values (2048 / 1024)
  that no current single-tenant deployment approaches; they are backstops, not tuning
  knobs, and can be raised per site.
- Staged rollout: (1) land `chio-http-serve` with tests; (2) rewire the two
  highest-value receipt sites first (api-protect, MCP edge) so the F61 loss window
  closes where it is widest; (3) rewire trust-control, adding the F11 hygiene stack;
  (4) rewire the two proof servers and the relay; (5) ship the systemd units and the
  runbook change (F63). Each step is independently shippable and reversible.
- The `readiness` flip is wired as `None` until F59 lands, so no ordering dependency
  is created.

## Test and verification plan

Unit and property (PR gate), in `chio-http-serve`:
- `sigterm_drains_in_flight_request_before_exit`: bind an in-process listener, start a
  handler that sleeps 200ms and writes a receipt, fire `ShutdownController::trigger`
  mid-request, assert the response completes 200 and the receipt is flushed to a
  temp SQLite store before `run_until_drained` returns `Clean`.
- `drain_deadline_forces_close_and_still_flushes`: a handler that never returns; assert
  `run_until_drained` returns `Forced` after `drain_timeout` and the flush hook still
  runs (accounting stays trustworthy or loudly broken).
- `handler_install_failure_does_not_resolve_early`: model a failed signal install;
  assert `shutdown_signal` stays pending (no crash-loop) rather than resolving.
- `load_shed_returns_503_over_concurrency_limit` and
  `request_timeout_returns_408` and `body_limit_returns_413`: prove each hygiene layer
  denies fail-closed.
- `max_conn_listener_caps_concurrent_connections`: open N+1 connections against a cap of
  N; assert the N+1th is not accepted until one closes, and permits release on drop.
- `flush_error_surfaces_as_serve_error`: an erroring store (wedged commit actor)
  makes `run_until_drained` return `Err(ServeError::Flush)` (non-zero exit),
  never `Ok`.

Loom (nightly): `watch_drain_no_lost_wakeup` over the `ShutdownController` publish and a
`subscribe()`-driven background loop, ensuring the loop always observes the flip and
the drain future always resolves.

Soak and chaos (weekly, PLAN-load-chaos program):
- `chaos_rolling_sigterm_zero_receipt_loss`: drive steady tool-call load through the
  api-protect and MCP-edge sites, issue SIGTERM on a rotation cadence, and assert every
  executed side effect has a persisted receipt after each restart (the F61 acceptance
  test this RFC stands or falls on).
- `soak_sigterm_under_connection_flood_trust_control`: slow-client flood plus periodic
  SIGTERM against trust-control; assert FD and RSS stay bounded, drains complete within
  `TimeoutStopSec`, and revocation/budget requests are not severed mid-response (F11).
- `chaos_oom_kill_then_systemd_restart`: cross-referenced from RFC-0004; assert the new
  units auto-restart and recover from WAL with no corruption (F63).

## Acceptance criteria

- Every one of the six `axum::serve` sites installs a shutdown handler and drains
  in-flight requests on SIGTERM within `drain_timeout`; a workspace grep for
  `with_graceful_shutdown` returns six hits.
- Under rolling SIGTERM at steady load, no executed tool-call side effect is left
  without a persisted receipt (F61 closed): in-flight requests complete their
  synchronous or commit-acknowledged receipt writes during the drain, and the MCP
  edge flushes each session kernel's commit actor before exit.
- The trust-control server denies (not queues) requests over its concurrency limit,
  times out slow requests, caps body size, and caps connections (F11 closed);
  in-flight revocation and budget requests complete during the drain.
- A failed post-drain flush produces a non-zero exit and a loud log line, never a
  silent success.
- A signal handler that cannot be installed logs and degrades to the pre-RFC behavior
  without crash-looping at startup.
- Reference systemd units exist for trust-control and the MCP edge with
  `Restart=on-failure`, `KillSignal=SIGTERM`, and `TimeoutStopSec` at least
  `drain_timeout` plus margin; the runbook installs them and states the platform
  grace-period contract (F63 closed, memory directives owned by RFC-0004).

## Risks and alternatives

- **`axum::serve` does not expose hyper header-read timeouts**, so a pure slow-loris
  that dribbles request headers is bounded only by the connection cap plus the
  per-request timeout once the request is dispatched, not at the header-read stage. A
  full fix needs a manual hyper serve loop with `http1` header-read timeouts; that is
  a larger change deferred as a follow-up. The connection cap plus concurrency limit
  bound the blast radius in the meantime, which is the article's "fail local".
- **Detaching in-flight work on `Forced` drain.** If the drain deadline elapses,
  remaining connections are force-closed, which can sever a request the same way today
  does, but only for requests that outran both their RFC-0001 budget and the 25s
  drain window. With RFC-0001 budgets set below `drain_timeout`, `Forced` should never
  occur in practice; it is the backstop, and the flush still runs, so no queued
  receipt is lost even on `Forced`.
- **Drain timeout vs platform grace.** If an operator sets `TimeoutStopSec` or the
  platform grace period below `drain_timeout`, the platform SIGKILL preempts the drain.
  Mitigation: the units set `TimeoutStopSec=35s` and the runbook makes the "grace
  period >= `TimeoutStopSec`" contract explicit; a shorter grace is an operator
  misconfiguration, not a code defect.
- **One shared crate vs per-site handlers.** A per-site inline handler was rejected: it
  is exactly the copy-paste that produced six divergent serve sites and would drift
  again. Folding the helper into the existing `chio-tower` crate was rejected because
  `chio-tower` carries the kernel-service stack that pheromone-relay and the proof
  servers do not want to pull in, and because pheromone-relay already avoids a
  transport dependency to dodge a cycle; a dedicated leaf crate has no such risk.
- **Latency and throughput.** The layer stack adds a timer registration and a semaphore
  acquire per request, both negligible; load-shed adds no steady-state cost below the
  limit. The drain path runs only at shutdown. Net effect on the hot path is
  immeasurable.

## Rollout and sequencing

- **RFC-0001 lands first (dependency).** Its hot-path deadlines are what make the
  bounded drain converge: with per-request budgets, in-flight evaluations terminate
  within their budget, so `drain_timeout` is a backstop rather than the primary bound.
  RFC-0010 is still correct without RFC-0001 (the deadline force-closes a stuck
  request), but the two compose into a clean drain only when budgets are set below
  `drain_timeout`.
- **RFC-0004 is a peer, not a dependency.** RFC-0010 ships the units and the shutdown
  grace window; RFC-0004 supplies the memory/OOM directives those units carry. They can
  land in either order; the units reference RFC-0004 for values and default to
  conservative placeholders until RFC-0004's numbers are set.
- **F59 (readiness endpoint) is optional downstream.** RFC-0010's readiness flip is a
  no-op hook until F59 provides a mutable readiness surface; RFC-0010 does not block on
  it and does not author it.
- Within RFC-0010, land `chio-http-serve` and its tests first, then the two
  highest-value receipt sites (api-protect, MCP edge), then trust-control (F11), then
  the remaining sites, then the systemd units and runbook (F63).
