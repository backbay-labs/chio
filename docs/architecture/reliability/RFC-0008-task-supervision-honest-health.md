# RFC-0008: Task supervision and health surfaces that cannot lie

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0009 (SIEM isolation)
- Depends on: RFC-0009 (telemetry exporter). Related and sequenced with RFC-0001 (hot-path deadlines and watchdogs) and RFC-0002 (post-admission unwind).
- Closes findings: F27, F13, F84, F59, F09 (see ./README.md and the readiness review)

## Summary

Chio spawns several long-lived background tasks with a bare `thread::spawn` or
`tokio::spawn`, drops the join handle, and never notices when the task dies or
wedges. The receipt-commit writer thread, the trust-control cluster sync loop, and
the host SIEM exporter are each a single unsupervised point of failure whose death
is invisible: every later call returns a per-request error at most, while the health
surface that operators poll keeps reporting green. The sidecar readiness endpoint is
worse than blind: it discards its state and returns `200 Healthy` unconditionally, so
every platform probe gates open on a lie. This RFC installs one small supervisor
primitive (a new leaf crate `chio-supervisor`) that retains the join handle, wraps
the worker in `catch_unwind`, restarts with capped backoff, and after N failures
flips a PERSISTENT degraded flag. It defines a single health-state model that every
surface MUST report, wires that flag into the kernel's pre-dispatch gate so a dead or
degraded TCB writer fails closed BEFORE a tool executes, replaces the silent
mutex-poison `into_inner()` recovery for TCB state with a fail-closed policy, and
rebuilds the four lying health surfaces to reflect real state. It is the honesty
layer of the wave-3 program: RFC-0009 exports the gauges this defines, RFC-0001
supplies the wedge-detection deadline that trips the flag, and RFC-0002 supplies the
unwind boundary that makes `catch_unwind` meaningful in production.

## Motivation

The reliability lens asks that a component's internal accounting be trustworthy or
loudly broken, that the blast radius of a mid-operation death be known, and that
overload fail early and local. A background task that dies while its health surface
stays green violates all three at once: the accounting is silently wrong, the blast
radius is unbounded in time (it persists until a human notices application errors),
and nothing fails early because nothing knows anything is wrong.

Blast radius of the confirmed findings:

- F27 (medium, CONFIRMED). Trigger: a panic inside `receipt_commit_actor_loop` /
  `commit_receipt_batch`, or the thread simply exiting. Effect: because the kernel
  persists receipts AFTER the tool executes (`record_chio_receipt_with_mode`,
  `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:135`, runs
  post-dispatch),
  every mediated call still runs its side effect and then fails its response with
  `actor unavailable`; the in-memory local-log copy is skipped too because the store
  error propagates first. Deny receipts route through the same actor, so a dead actor
  stops the kernel from completing any call, allow or deny. Impact: a total receipt-write
  outage with evidence-less side effects, while `receipt_store_health` can still report
  `healthy = true` because the disconnected path sets no `last_error`.
- F13 (low, PARTIAL). Trigger: the cluster sync loop stops making progress. Effect:
  revocation, receipt, and lineage replication to this node stops; budget writes
  503 loudly within one lease TTL as quorum freshness decays, but revocation
  propagation stops SILENTLY while `/health` keeps reporting the last-known healthy
  peer counts. Impact: a capability revoked on a peer keeps being honored locally with
  a green health surface - the security-relevant residue.
- F84 (medium, CONFIRMED). Trigger: the host SIEM task panics, is never spawned after
  a deploy change, or `poll_once` fails every tick (for example the receipt db was
  rotated out from under the read-only connection). Effect: receipt export to every SIEM
  and alerting backend halts with no lag metric, no heartbeat, and no dead-man switch.
  Impact: SOC ingestion goes quiet and a stalled compliance pipeline is
  indistinguishable from a legitimately quiet system until an incident review finds the
  missing events.
- F59 (high, CONFIRMED). Trigger: any sidecar dependency degrades (capability
  authority unreachable, receipt store erroring, policy state broken). Effect:
  `/chio/health` keeps returning `200 Healthy`, so Cloud Run and ECS liveness never
  restart the container, Azure readiness never pulls it from routing, and every tool
  call is denied fail-closed or mis-served while all platform signals stay green.
  Impact: a full tenant-visible outage that persists until a human notices.
- F09 (medium, CONFIRMED). Trigger: any panic inside a critical section on a tokio
  task. Effect: the runtime catches the panic, the kernel keeps serving, and every
  later request silently operates on the half-mutated budget-registry, session, or
  receipt-log state the panicking thread left behind (the recovery is
  `poisoned.into_inner()`). For the budget registry that is silent monetary accounting
  corruption. Impact: no log line distinguishes this from healthy operation, while the
  receipt-store write lock in the same codebase already demonstrates the fail-closed
  alternative.

The through-line: every one of these is a task or lock whose failure is invisible to
the surface an operator trusts. This RFC makes the surface incapable of lying.

## Current behavior (verified 2026-07-04)

All signatures below were re-read against the working tree on the date above.

### Receipt-commit writer thread (F27)

`ReceiptCommitActor::start` spawns the writer with a bare thread and drops the handle
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:152-159`):

```rust
// receipt_store.rs:152
fn start(pool: Pool<SqliteConnectionManager>) -> Self {
    let (sender, receiver) = receipt_commit_channel();
    let health = Arc::new(ReceiptCommitWriterHealth::default());
    let actor_health = Arc::clone(&health);
    thread::spawn(move || receipt_commit_actor_loop(pool, receiver, actor_health));
    Self { sender, health }
}
```

The join handle is discarded, there is no panic hook, and nothing anywhere respawns
the thread; it is started exactly once at store open
(`crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs:122` and `:1074`).
`append` (`receipt_store.rs:161-200`) maps `TrySendError::Disconnected` to
`receipt_actor_unavailable_error()` (a plain `ReceiptStoreError::Pool` string,
`receipt_store.rs:187-190, 268-270`) and blocks on `result.recv()` at `:192` with no
timeout. The health computation reads only the last completed batch's error
(`receipt_store.rs:626-631`):

```rust
// receipt_store.rs:626
let healthy = status.healthy
    && self
        .receipt_commit_actor
        .writer_counters()
        .last_error
        .is_none();
```

`last_error` is written only by `commit_receipt_batch` (`receipt_store.rs:342-344`);
the disconnected append path sets neither `last_error` nor `failed_total`, so a dead
writer whose final batch succeeded reports `healthy = true` forever. The only external
reader of `receipt_store_health` is the CLI command `cmd_receipt_health`
(`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60-73`), which opens its OWN
`SqliteReceiptStore` via `local_receipt_store` -> `open_existing` (`:43`) - spawning a
fresh actor with zeroed counters - and explicitly refuses remote operation
(`:29-33`). It physically cannot observe the serving kernel's writer. Release builds
set `panic = "abort"` workspace-wide (`Cargo.toml:236-240`), so a writer panic aborts
the whole process (loud fail-stop); the silent-dead-thread state is reachable in
unwind (dev, test, or an RFC-0002 boundary) builds, and the WEDGED-but-alive writer is
unprotected in every build.

### Cluster sync loop (F13)

`run_cluster_sync_loop` is spawned and its handle dropped
(`crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs:26`):
`tokio::spawn(run_cluster_sync_loop(state.clone()));`. The loop itself
(`crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs:184-198`)
wraps each round in `spawn_blocking` and catches both `Err(round)` and a task panic
with `warn!`, then sleeps and continues, so the loop task rarely exits; the reachable
failure is a wedged or non-progressing round. The health snapshot
(`crates/platform/chio-control-plane/src/trust_control/health.rs:432-454`) counts
`peer.health` enum values written by the sync loop itself with no `last_contact_at`
freshness check, so the counters freeze at their last-known state. `consensus.rs:306-309`
does apply a `contact_is_fresh` aging backstop to quorum counting, which is why budget
writes fail loud while replication staleness stays silent.

### SIEM exporter (F84)

`ExporterManager::run` (`crates/observability/chio-siem/src/manager.rs:164-182`) logs
poll errors with redaction and continues; there is no metric, no heartbeat, and no
failure escalation. The cursor is in-memory only (`manager.rs:95, 139`), so a respawned
manager restarts from seq 0 and relies on backend dedup. `dlq_len` (`manager.rs:152-154`)
is the only programmatic health surface and nothing in-tree polls it. The metric names
`CHIO_SOC_EXPORT_LAG_SECONDS` and `CHIO_SOC_EXPORT_TOTAL` are specified
(`crates/observability/chio-metrics-spec/src/lib.rs:176-177` and the `describe!` blocks
at `:519-531`) but a repo-wide search finds no emitter. ADR-0009's own Required
Follow-up (line 94) already asks for "a health endpoint or status metric for DLQ depth";
this RFC delivers it.

### Sidecar health endpoint (F59)

`sidecar_health_handler` discards its state and returns `200 Healthy` unconditionally
(`crates/products/chio-api-protect/src/proxy/sidecar.rs:122-131`):

```rust
// sidecar.rs:122
pub(crate) async fn sidecar_health_handler(State(_state): State<Arc<ProxyState>>) -> Response {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: SidecarStatus::Healthy,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
        .into_response()
}
```

`SidecarStatus` already has `Degraded` and `Unhealthy` variants that no code path
returns (`crates/platform/chio-http-core/src/evaluation.rs:98-104`). The route is the
single `/chio/health` mount (`crates/products/chio-api-protect/src/proxy/router.rs:25`),
and `ProxyState` (`crates/products/chio-api-protect/src/proxy/state.rs:138-152`) holds
the very state the handler discards, including `receipt_store: Option<Mutex<SqliteReceiptStore>>`
(`:147`) and `evaluator: RequestEvaluator` (`:139`). Every deploy manifest gates on
this endpoint: Cloud Run startup and liveness probes on `:9090/chio/health`
(`deploy/cloud-run/service.yaml:114-116` and `:121-123`; the probes at `:51-60` are the
app container's own `/healthz` on `:8080` and are unaffected), the ECS `healthCheck` curl
(`deploy/ecs/task-definition.json:84`), and Azure startup, liveness, and readiness
probes (`deploy/azure/container-app.bicep:152,162,171`).

### Mutex poison recovery (F09)

Session locks swallow poison via `into_inner`
(`crates/kernel/chio-kernel/src/session.rs:18-30`):

```rust
// session.rs:25
fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}
```

The monetary budget registry does the same on admit and release
(`crates/kernel/chio-kernel/src/kernel/validation.rs:308-311, 333-336`), returning the
half-mutated guard. The one lock that fails closed is the receipt-store write lock
(`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:172-174`):

```rust
// receipt_persistence.rs:172
let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
    KernelError::Internal("receipt store write lock poisoned".to_string())
})?;
```

That is the pattern this RFC generalizes. The kernel already carries a precedent for a
process-wide serving flag consulted on the hot path: `emergency_stopped: AtomicBool`
(`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:183`), read by the evaluate
entry points, alongside the pre-dispatch readiness gates `ensure_receipt_persistence_ready`
and `ensure_federated_receipt_persistence_ready` (`construction.rs:228-251`), which today
check only configuration presence (`self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log`).

## Design

### 1. The supervisor primitive: `chio-supervisor`

New leaf crate `crates/core/chio-supervisor` (roughly 450 LOC including tests).
Dependencies: `std`, `thiserror`, and `tokio` behind an `async` feature only. It has
NO Chio dependency, mirroring the `chio-bounded` precedent from RFC-0004.

This placement is deliberate. `chio-runtime-core` was rejected as a home because it
depends on `chio-kernel` (verified in its manifest), so hosting a shared supervisor
there would drag the TCB into `chio-siem`. That directly contradicts ADR-0009, whose
whole point is that the SIEM pipeline carries no kernel dependency. A zero-Chio-dep
leaf crate lets the kernel writer (F27), the trust-control loop (F13), and the SIEM
exporter (F84) all supervise without any of them taking a dependency on each other.
(Note: ADR-0009 states `chio-siem` lists only `chio-core` as a Chio dependency; the
current manifest also lists `chio-kernel` for the receipt read-boundary types, a drift
this RFC does not widen.)

#### Health-state model

One monotonic flag per supervised surface. The core rule, taken straight from the
article: a supervisor that restarted its worker but lost data must still report the
gap, so a tripped flag NEVER clears itself on a lucky success.

```rust
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    /// Serving normally.
    Healthy,
    /// Tripped after `trip_after` restarts; the surface reports degraded and,
    /// if TCB-critical, fails evaluations closed. Restarts may still be running.
    Degraded,
    /// Terminal: restart budget exhausted; the supervisor stopped respawning.
    Failed,
}

/// Cloneable handle to one surface's health. Reads are lock-free; the reason
/// string is behind a Mutex whose only invariant is the single Option it holds,
/// so poison recovery via `into_inner` is sound here (there is no cross-field
/// state to leave half-mutated).
#[derive(Clone)]
pub struct HealthFlag(Arc<HealthState>);

struct HealthState {
    level: AtomicU8,          // HealthLevel encoded 0/1/2
    tcb_critical: bool,
    consecutive_failures: AtomicU32,
    restart_total: AtomicU64,
    last_ok_unix_ms: AtomicU64,
    last_transition_unix_ms: AtomicU64,
    reason: Mutex<Option<String>>,
}

impl HealthFlag {
    pub fn new(tcb_critical: bool) -> Self {
        Self(Arc::new(HealthState {
            level: AtomicU8::new(HealthLevel::Healthy as u8),
            tcb_critical,
            consecutive_failures: AtomicU32::new(0),
            restart_total: AtomicU64::new(0),
            last_ok_unix_ms: AtomicU64::new(0),
            last_transition_unix_ms: AtomicU64::new(0),
            reason: Mutex::new(None),
        }))
    }

    /// Record a completed unit of work. Resets the consecutive-failure counter
    /// and stamps liveness, but NEVER lowers a tripped level.
    pub fn record_ok(&self, now_ms: u64) {
        self.0.consecutive_failures.store(0, Ordering::SeqCst);
        self.0.last_ok_unix_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Record a restart-worthy failure. Returns the new consecutive count.
    /// Trips to Degraded at `trip_after` and never downgrades.
    pub fn record_failure(&self, reason: impl Into<String>, now_ms: u64, trip_after: u32) -> u32 {
        let count = self.0.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.restart_total.fetch_add(1, Ordering::SeqCst);
        self.set_reason(reason.into());
        if count >= trip_after {
            self.raise_to(HealthLevel::Degraded, now_ms);
        }
        count
    }

    /// Terminal escalation: restart budget exhausted.
    pub fn escalate_failed(&self, now_ms: u64) {
        self.raise_to(HealthLevel::Failed, now_ms);
    }

    pub fn level(&self) -> HealthLevel {
        match self.0.level.load(Ordering::SeqCst) {
            0 => HealthLevel::Healthy,
            1 => HealthLevel::Degraded,
            _ => HealthLevel::Failed,
        }
    }

    /// True when this surface must fail closed: TCB-critical and not Healthy.
    pub fn is_serving_closed(&self) -> bool {
        self.0.tcb_critical && !matches!(self.level(), HealthLevel::Healthy)
    }

    /// The one path back to Healthy: an explicit, operator-visible recovery.
    pub fn clear(&self, now_ms: u64) {
        self.0.consecutive_failures.store(0, Ordering::SeqCst);
        self.0.level.store(HealthLevel::Healthy as u8, Ordering::SeqCst);
        self.0.last_transition_unix_ms.store(now_ms, Ordering::SeqCst);
        self.set_reason_none();
    }

    fn raise_to(&self, level: HealthLevel, now_ms: u64) {
        // Monotonic: only ever raise severity.
        if (level as u8) > self.0.level.load(Ordering::SeqCst) {
            self.0.level.store(level as u8, Ordering::SeqCst);
            self.0.last_transition_unix_ms.store(now_ms, Ordering::SeqCst);
        }
    }

    fn set_reason(&self, reason: String) {
        match self.0.reason.lock() {
            Ok(mut guard) => *guard = Some(reason),
            Err(poisoned) => *poisoned.into_inner() = Some(reason),
        }
    }

    fn set_reason_none(&self) {
        match self.0.reason.lock() {
            Ok(mut guard) => *guard = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let reason = match self.0.reason.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        HealthSnapshot {
            level: self.level(),
            tcb_critical: self.0.tcb_critical,
            restart_total: self.0.restart_total.load(Ordering::SeqCst),
            consecutive_failures: self.0.consecutive_failures.load(Ordering::SeqCst),
            last_ok_unix_ms: nonzero(self.0.last_ok_unix_ms.load(Ordering::SeqCst)),
            reason,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthSnapshot {
    pub level: HealthLevel,
    pub tcb_critical: bool,
    pub restart_total: u64,
    pub consecutive_failures: u32,
    #[serde(default)]
    pub last_ok_unix_ms: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
```

No `.unwrap()`/`.expect()` anywhere; every `Mutex` poison is matched and the
single-field reason lock recovers via `into_inner`, which is sound because there is no
multi-field invariant to corrupt (this is exactly the distinction F09 draws).

#### Supervisor configuration and the sync thread supervisor

```rust
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub name: &'static str,
    /// A tripped flag on a TCB-critical surface fails evaluations closed.
    pub tcb_critical: bool,
    /// Consecutive restarts before the flag trips to Degraded.
    pub trip_after: u32,
    /// Consecutive restarts before terminal Failed and respawn stops.
    pub max_restarts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
}

/// Result of one worker-body invocation.
pub enum SupervisedOutcome {
    /// The worker observed the shutdown flag and exited cleanly. Do not restart.
    Shutdown,
    /// One iteration completed successfully (a one-shot tick such as a single
    /// `sync_cluster_once`). Loop again WITHOUT recording a failure or backing
    /// off. This is the success path: a healthy one-shot iteration reports
    /// `Continue`, so it is never misclassified as a `Restart` failure that
    /// increments the failure counter and eventually escalates to `Failed`. The
    /// worker records its own healthy heartbeat (`health.record_ok`) before
    /// returning it.
    Continue,
    /// The worker returned or failed and should be restarted.
    Restart,
}

pub struct SupervisedThread {
    handle: Option<std::thread::JoinHandle<()>>,
    health: HealthFlag,
    shutdown: Arc<AtomicBool>,
}

impl SupervisedThread {
    /// Spawn a supervised OS thread. `worker` is the loop body; on panic (under
    /// an unwind profile) or a `Restart` outcome it is re-entered with capped
    /// backoff, reusing the same owned resources. `worker` takes the shutdown
    /// flag so it can exit promptly and return `SupervisedOutcome::Shutdown`.
    pub fn spawn<F>(config: SupervisorConfig, worker: F) -> Self
    where
        F: Fn(&Arc<AtomicBool>) -> SupervisedOutcome + Send + 'static,
    {
        let health = HealthFlag::new(config.tcb_critical);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_health = health.clone();
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = match std::thread::Builder::new()
            .name(config.name.to_string())
            .spawn(move || supervise_loop(config, worker, worker_health, worker_shutdown))
        {
            Ok(handle) => Some(handle),
            Err(error) => {
                // Cannot even start: trip immediately so no surface reads green.
                health.record_failure(format!("supervisor spawn failed: {error}"), now_unix_ms(), 0);
                health.escalate_failed(now_unix_ms());
                None
            }
        };
        Self { handle, health, shutdown }
    }

    pub fn health(&self) -> HealthFlag {
        self.health.clone()
    }

    /// Signal shutdown and join. Returns the terminal health level.
    pub fn shutdown(mut self) -> HealthLevel {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.health.level()
    }
}

fn supervise_loop<F>(
    config: SupervisorConfig,
    worker: F,
    health: HealthFlag,
    shutdown: Arc<AtomicBool>,
) where
    F: Fn(&Arc<AtomicBool>) -> SupervisedOutcome,
{
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(&shutdown)));
        match outcome {
            Ok(SupervisedOutcome::Shutdown) => return,
            // Healthy one-shot tick: loop again with no failure recorded and no backoff.
            Ok(SupervisedOutcome::Continue) => continue,
            Ok(SupervisedOutcome::Restart) | Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                let reason = match &outcome {
                    Err(_) => format!("{} worker panicked", config.name),
                    _ => format!("{} worker exited", config.name),
                };
                let count = health.record_failure(reason, now_unix_ms(), config.trip_after);
                if count >= config.max_restarts {
                    health.escalate_failed(now_unix_ms());
                    return; // stop respawning; flag stays set for surfaces to read
                }
                std::thread::sleep(backoff_delay(&config, count));
            }
        }
    }
}
```

`backoff_delay` is `min(max_backoff, base_backoff * 2^(count-1))` computed with
`checked_shl`/`saturating_mul` (the exact saturating form already used by
`retry_backoff_ms` in `manager.rs:386-392`), and `now_unix_ms` is the saturating
`SystemTime` reader already present as `current_unix_ms` in `receipt_store.rs:358-363`.

Honesty about `panic = "abort"` (`Cargo.toml:240`): under the release profile a panic
aborts before `catch_unwind` can fire, so in release a writer panic is a loud process
abort that the orchestrator restarts - which is the article's "fail loud, not silent"
outcome and is acceptable. `catch_unwind`-based restart is exercised under unwind
builds and under the RFC-0002 post-admission boundary. The durable contribution in ALL
profiles is the PERSISTENT flag plus honest surface: a non-panic exit, a spawn failure,
or (via RFC-0001's watchdog) a wedged-but-alive worker each trip the flag, and the
surfaces below report it.

#### The async task supervisor (feature `async`)

```rust
#[cfg(feature = "async")]
pub fn supervise_task<F, Fut>(
    config: SupervisorConfig,
    health: HealthFlag,
    mut iteration: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = SupervisedOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Run each iteration in its OWN task so a panic inside the future
            // surfaces as a JoinError instead of unwinding out of this
            // supervisor loop. Without this boundary a panic in `iteration()`
            // aborts the loop before it can reach the `Restart` arm, so no
            // failure is recorded, no restart happens, and the HealthFlag stays
            // Healthy until some unrelated code inspects the finished handle -
            // exactly the SIEM-exporter / cluster-loop panic cases this RFC
            // exists to make loud. A panicked iteration is classified as a
            // failure and treated like `Restart`.
            let outcome = match tokio::spawn(iteration()).await {
                Ok(outcome) => outcome,
                Err(join_error) if join_error.is_panic() => {
                    // Fall through to the failure/backoff path below.
                    SupervisedOutcome::Restart
                }
                Err(_cancelled) => return, // runtime shutting down: stop cleanly
            };
            match outcome {
                SupervisedOutcome::Shutdown => return,
                // Healthy one-shot tick: loop again with no failure recorded and no backoff.
                SupervisedOutcome::Continue => continue,
                SupervisedOutcome::Restart => {
                    let count = health.record_failure(
                        format!("{} iteration panicked or failed", config.name),
                        now_unix_ms(),
                        config.trip_after,
                    );
                    if count >= config.max_restarts {
                        health.escalate_failed(now_unix_ms());
                        return;
                    }
                    tokio::time::sleep(backoff_delay(&config, count)).await;
                }
            }
        }
    })
}
```

Running each iteration under an inner `tokio::spawn` (rather than
`catch_unwind`) is deliberate: an async iteration can panic across an `.await`
point, which `catch_unwind` cannot capture cleanly, and it makes the failure
observable even under `panic = "abort"` only when the async runtime is
configured to unwind tasks; where the process aborts on panic instead, the abort
is loud and the orchestrator restarts the process (the same "fail loud, not
silent" outcome as the sync writer). The tightened `Fut: 'static` bound is
required to move the future into the inner task.

The returned `JoinHandle` is RETAINED by the caller (the fix for the dropped handles at
`init.rs:26`). Because a panicking iteration is now recorded and restarted inside the
loop, `handle.is_finished()` is a secondary backstop: it detects the terminal cases
(max-restarts reached, or the supervisor itself cancelled) so a top-level surface can
still trip the flag if the whole supervisor exits.

### 2. Wiring list

Every detached task gets a supervisor, a `HealthFlag`, and a surface that must report
it. The `tcb` column marks flags that fail evaluations closed.

| Task | Current spawn site | Supervisor | HealthFlag (tcb) | Surface that must report it |
| --- | --- | --- | --- | --- |
| Receipt-commit writer | `receipt_store.rs:157` (`thread::spawn`) | `SupervisedThread` | yes | `receipt_store_health` + kernel pre-dispatch gate |
| Cluster sync loop | `init.rs:26` (`tokio::spawn`, handle dropped) | `supervise_task`, handle retained in `TrustServiceState` | no | trust-control `/health` staleness |
| SIEM exporter | host binary `tokio::spawn` (`crates/products/chio-wall/src/commands.rs:1262`) | `supervise_task`, handle retained | no | `ExporterManager::health()` + SOC metrics + dead-man alert |
| RSS sampler (RFC-0004) | one sampler task | `supervise_task` | yes | kernel `/health` |

### 3. Receipt-commit writer (F27)

`ReceiptCommitActor` gains the supervisor's `HealthFlag`. `start` moves the receiver
and pool into a `SupervisedThread` whose worker is the existing
`receipt_commit_actor_loop`; the receiver stays owned across restarts (only the loop
body is re-entered: the worker closure captures the receiver and the loop signature
changes to borrow it, which std mpsc supports because `Receiver::recv` takes `&self`),
and the pool is cloneable and re-acquired per batch, so a caught panic can restart with
the same still-open channel and the store's sender stays valid.

```rust
struct ReceiptCommitActor {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
    writer: SupervisedThread, // retains the JoinHandle; exposes HealthFlag
}
```

Three concrete changes:

1. Typed dead-writer error. Replace the `receipt_actor_unavailable_error()` string
   returns with a typed variant so the condition is inspectable rather than a `Pool`
   string match. There are five call sites: the `append` disconnected and recv-failure
   paths (`receipt_store.rs:189, 197`) and the flush paths (`:206, :214, :232`); all
   five switch to the new variant.

   ```rust
   // added to enum ReceiptStoreError
   // (crates/kernel/chio-kernel/src/receipt_store.rs:151-185)
   #[error("receipt commit writer is dead after {restarts} restarts: {last_error}")]
   WriterDead { restarts: u64, last_error: String },
   ```

   It flows into `KernelError::ReceiptPersistence` through the existing
   `#[from] ReceiptStoreError` (`crates/kernel/chio-kernel/src/kernel/error.rs:156-157`)
   with no new kernel arm.

2. Honest `receipt_store_health`. The health computation (`receipt_store.rs:626-631`)
   ORs in the supervisor flag so a dead or degraded writer can never read green even
   when the last completed batch left `last_error = None`:

   ```rust
   let writer_level = self.receipt_commit_actor.writer.health().level();
   let healthy = status.healthy
       && self.receipt_commit_actor.writer_counters().last_error.is_none()
       && matches!(writer_level, HealthLevel::Healthy);
   ```

   `ReceiptStoreHealthReport` (`receipt_store.rs:102-117`, kernel crate) gains
   `writer_level: HealthLevel` and `writer_restart_total: u64` (both `#[serde(default)]`,
   camelCase), surfaced by the CLI renderer and the RFC-0009 exporter.

3. Fail closed BEFORE dispatch. The pre-dispatch gate `ensure_receipt_persistence_ready`
   (`construction.rs:244-251`), which today checks only config presence, additionally
   consults the writer flag:

   ```rust
   pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
       if let Some(store) = &self.receipt_store {
           if store.writer_serving_closed() {
               return Err(KernelError::Internal(
                   "durable receipt persistence degraded: commit writer is not serving".to_string(),
               ));
           }
       }
       if self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log {
           return Ok(());
       }
       Err(KernelError::Internal(
           "durable receipt persistence unavailable: no receipt store configured".to_string(),
       ))
   }
   ```

   The kernel holds the store as a trait object
   (`receipt_store: Option<Arc<dyn ReceiptStore>>`, `kernel_struct.rs:146`), so
   `writer_serving_closed` lands as a new method on the `ReceiptStore` trait
   (`crates/kernel/chio-kernel/src/receipt_store.rs:187`) with a default body returning
   `false` (a store with no writer thread has nothing to trip), overridden by
   `SqliteReceiptStore` to read the supervisor flag. This mirrors how
   `receipt_store_health` is already a defaulted trait method (`:251`).

   This is the load-bearing fix for F27: a KNOWN-dead or wedged writer now denies at the
   door via the existing fail-closed deny response, so the tool never executes and no
   evidence-less side effect occurs. Detection of the wedged-but-alive case (the append
   `recv()` with no timeout at `receipt_store.rs:192`) is RFC-0001's watchdog, which
   trips this same `HealthFlag`; this RFC owns the flag and the gate wiring, RFC-0001
   owns the deadline.

### 4. Cluster sync loop (F13)

Retain the handle and add a staleness surface. `init.rs:26` becomes
`state.set_sync_task(supervise_task(cfg, health, || async { sync_iteration(&state).await }));`,
storing the `JoinHandle` and `HealthFlag` in `TrustServiceState`. `sync_iteration`
wraps one `sync_cluster_once` (`deltas.rs:200`): on `Ok` it calls
`health.record_ok(now)`, stamps `last_sync_completed_at` in cluster state, and returns
`SupervisedOutcome::Continue` (a healthy tick, so the supervisor loops without recording
a failure); on `Err` or a caught `spawn_blocking` panic it returns
`SupervisedOutcome::Restart`. The health
snapshot (`health.rs:432-454`) adds a freshness check: a peer whose `last_contact_at`
is older than N sync intervals is reported `Unknown/stale` rather than counted at its
frozen last value, and a `chio_cluster_sync_staleness_seconds` gauge (RFC-0009) exports
`now - last_sync_completed_at`. The security residue - a revocation not propagated while
`/health` reads green - becomes visible as rising staleness.

### 5. SIEM exporter (F84)

Preserve ADR-0009 isolation: `chio-supervisor` is a zero-Chio-dep leaf, so adding it to
`chio-siem` introduces no kernel dependency. Three additions:

- `ExporterManager` gains a `HealthFlag` and a `last_success_unix_ms`. `poll_once`
  (`manager.rs:188`) calls `health.record_ok(now)` on a poll that advances the cursor
  and `health.record_failure(...)` on the `Err` arm that today only `error!`s
  (`manager.rs:170-172`).
- A health snapshot accessor:

  ```rust
  #[derive(Debug, Clone, serde::Serialize)]
  #[serde(rename_all = "camelCase")]
  pub struct SiemHealthSnapshot {
      pub cursor: u64,
      pub dlq_len: usize,
      pub last_success_unix_ms: Option<u64>,
      pub health: HealthSnapshot,
  }

  impl ExporterManager {
      pub fn health(&self) -> SiemHealthSnapshot { /* reads cursor, dlq_len, flag */ }
  }
  ```

- Emit the already-specified metrics from the poll loop: `CHIO_SOC_EXPORT_TOTAL`
  (labels `exporter`, `outcome`) per exporter result and `CHIO_SOC_EXPORT_LAG_SECONDS`
  (labels `exporter`, `severity`) as receipt-timestamp-to-ack lag, plus a
  `chio_soc_export_last_success_unix_seconds` gauge. The deployment contract documents a
  dead-man alert on the ABSENCE of `CHIO_SOC_EXPORT_TOTAL` increments, so a task that was
  never spawned is as loud as one that died. The host binary retains the `run` join
  handle and exposes `health()`.

### 6. Sidecar health surfaces (F59)

Split liveness from readiness and make readiness consult `ProxyState`.

- Add `/chio/live`: a process-only liveness route that returns `200` while the process
  runs (it may reuse the unconditional handler; a live process should not be restarted
  for a dependency blip).
- Rebuild `/chio/health` as dependency-aware readiness. `sidecar_health_handler` stops
  discarding state and consults, in order: receipt-store writability
  (`state.receipt_store` -> `receipt_store_health().healthy`, reusing the F27 flag),
  capability-authority reachability (a cached last-success timestamp on the evaluator),
  and spec/policy load state. Any failure maps to `SidecarStatus::Degraded` or
  `Unhealthy` (the existing unused variants, `evaluation.rs:102-103`) with a non-200
  status:

  ```rust
  pub(crate) async fn sidecar_health_handler(State(state): State<Arc<ProxyState>>) -> Response {
      let status = state.readiness_status().await; // Healthy | Degraded | Unhealthy
      let code = match status {
          SidecarStatus::Healthy => StatusCode::OK,
          SidecarStatus::Degraded | SidecarStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
      };
      (code, axum::Json(HealthResponse { status, version: env!("CARGO_PKG_VERSION").to_string() }))
          .into_response()
  }
  ```

- Deploy manifests repoint `livenessProbe` at `/chio/live` and `startupProbe` /
  `readinessProbe` at `/chio/health` (`deploy/cloud-run/service.yaml`,
  `deploy/ecs/task-definition.json`, `deploy/azure/container-app.bicep`).

### 7. Mutex-poison policy for TCB state (F09)

One policy, applied uniformly: TCB state whose invariant spans multiple fields fails
closed on poison; simple single-value locks may recover via `into_inner` but must be
loud. Concretely:

- Session locks (`session.rs:18-30`), budget registry (`validation.rs:308-311, 333-336`),
  and the receipt logs (`dispatch.rs` poison sites) route through a
  `poisoned_tcb_guard` helper that (1) increments a `chio_lock_poison_total{lock}`
  counter, (2) flips a kernel-wide `HealthFlag` (tcb) to Degraded, and (3) for the
  budget registry returns `Err` rather than proceeding. `admit_capability_budget`
  already returns `Result<(), String>` (`validation.rs:302`), so poison -> `Err("budget
  registry lock poisoned")` fails closed at the caller with no signature change. Session
  writes route to the receipt-store precedent shape (`Err(KernelError::Internal)`).
- The kernel-wide degraded flag is read by the pre-dispatch gate exactly like the
  writer flag in section 3, so a poisoned TCB lock denies subsequent evaluations closed
  until an operator-visible recovery.
- Single-value locks (the `HealthState.reason` above, the writer `last_error` mutex at
  `receipt_store.rs:138`) keep `into_inner` recovery, because there is no cross-field
  invariant to corrupt; the poison counter still fires so recovery is never silent.

## Wire, schema, and receipt impact

- No change to signed receipt bodies, capability tokens, or DSSE envelopes. Nothing
  this RFC adds is signed; the supervisor and health flags are runtime state.
- Health JSON surfaces gain fields, all additive and `#[serde(default)]`:
  `ReceiptStoreHealthReport` gets `writerLevel`, `writerRestartTotal`;
  `SiemHealthSnapshot` and `HealthSnapshot` are new ops payloads; the sidecar
  `HealthResponse` value set widens to include `degraded`/`unhealthy` (already valid
  `SidecarStatus` variants). Any of these that is emitted as a signed or exported
  structured payload continues to be canonical JSON per RFC 8785; today they are
  operator surfaces, not signed artifacts.
- New telemetry names surfaced by RFC-0009: `chio_task_health{surface,level}`,
  `chio_task_restart_total{surface}`, `chio_lock_poison_total{lock}`,
  `chio_cluster_sync_staleness_seconds`, `chio_soc_export_last_success_unix_seconds`,
  plus emitters for the already-specified `CHIO_SOC_EXPORT_TOTAL` /
  `CHIO_SOC_EXPORT_LAG_SECONDS` (`chio-metrics-spec/src/lib.rs:176-177`). No
  `spec/schemas` protocol file changes.

## Migration and compatibility

- `chio-supervisor` is a new additive leaf crate.
- `ReceiptStoreError::WriterDead` is a new variant; the enum is matched exhaustively
  inside the store crate, so the same change adds the arms. External matchers already
  need a wildcard given the enum size.
- Staged default: the writer supervisor and honest `receipt_store_health` land first
  with the pre-dispatch gate check behind `KernelConfig` defaulting to the existing
  fail-closed-on-error behavior; the gate's flag consultation is strictly additional
  denial of an already-broken writer, so a healthy deployment sees no change. The
  cluster staleness threshold and SIEM dead-man window ship with generous defaults and
  a release note.
- Deploy-manifest probe repointing is a coordinated change: ship `/chio/live` and the
  dependency-aware `/chio/health` in the same sidecar release as the manifest edits so
  no probe points at a route that does not yet exist.
- No data migration: all state added is process-local runtime health.

## Test and verification plan

- Unit (PR gate, seconds): `HealthFlag` is monotonic (`record_ok` never lowers a
  tripped level; `record_failure` trips at `trip_after`; `escalate_failed` is terminal;
  `clear` is the only downgrade). `is_serving_closed` is true iff tcb and not Healthy.
  `backoff_delay` saturates at `max_backoff`.
- Property (PR gate, seconds, `proptest`): for any interleaving of
  `record_ok`/`record_failure`/`escalate_failed`, the level is non-decreasing between
  `clear`s and `restart_total` equals the number of failures - the
  accounting-is-trustworthy invariant from the lens.
- Loom (nightly, minutes): a worker thread calling `record_ok`/`record_failure`
  concurrent with a reader calling `snapshot`/`is_serving_closed` observes no lost
  transition and no torn level; models the writer-plus-gate race.
- Fault-injection unit (PR gate): a `SupervisedThread` whose worker panics on the first
  invocation (unwind test profile) restarts, and after `max_restarts` panics the flag is
  `Failed` and the handle joins. A worker that returns `Restart` `trip_after` times trips
  to `Degraded`.
- Chaos (nightly, `chio-chaos` harness per PLAN-load-soak-chaos-program): kill the
  receipt-commit worker mid-batch and assert
  (a) `receipt_store_health.healthy` becomes false within one sample, (b) new evaluations
  fail closed at the pre-dispatch gate with no tool side effect (the F27 acceptance test),
  (c) the durable store is authoritative on restart. Separately, stall the cluster sync
  loop and assert `/health` reports stale peers and the staleness gauge rises; stop the
  SIEM task and assert the dead-man alert fires on absent `CHIO_SOC_EXPORT_TOTAL`.
- Soak (weekly, PLAN-load-soak-chaos-program harness, 24h): under nominal mixed traffic every
  `chio_task_health` reads Healthy and `chio_task_restart_total` stays flat; a single
  induced worker kill trips exactly one surface and recovers on operator `clear`.
- Poison test (PR gate): force a budget-registry lock poison and assert
  `admit_capability_budget` returns `Err`, the kernel degraded flag trips,
  `chio_lock_poison_total` increments, and the next evaluation fails closed.

The named proof of this RFC is the F27 chaos test: worker death -> health false ->
pre-dispatch deny with no side effect.

## Acceptance criteria

- Every task in the section-2 table is spawned through `chio-supervisor`, retains its
  join handle, and owns a `HealthFlag`; a repo test enumerates supervised surfaces and
  fails if a new long-lived `thread::spawn`/`tokio::spawn` is added without one.
- A dead or wedged receipt-commit writer makes `receipt_store_health.healthy` false and
  causes the kernel to fail closed at the pre-dispatch gate, so no tool executes without
  a persisted receipt path. `receipt_store.rs:626-631` no longer depends on `last_error`
  alone.
- The sidecar exposes a process-only `/chio/live` and a dependency-aware `/chio/health`
  that returns non-200 when the receipt store, capability authority, or policy state is
  broken; deploy probes gate on the correct route.
- SIEM export emits `CHIO_SOC_EXPORT_TOTAL` and `CHIO_SOC_EXPORT_LAG_SECONDS`, exposes
  `ExporterManager::health()`, and a documented dead-man alert fires on absent export
  activity. No `chio-kernel` dependency is added to `chio-siem`.
- Cluster `/health` reports peer staleness and exports a staleness gauge; a stalled sync
  loop is visible within N intervals.
- A poisoned TCB lock fails closed and increments `chio_lock_poison_total`; no TCB path
  proceeds on half-mutated state. `cargo clippy --workspace -- -D warnings` passes with
  no `unwrap`/`expect` in the new code.

## Risks and alternatives

- `panic = "abort"` limits `catch_unwind`-based restart to unwind profiles. Accepted:
  in release a panic is a loud abort that the orchestrator restarts, which satisfies the
  fail-loud requirement; the persistent flag plus honest surface plus wedge watchdog
  cover the non-panic and alive-but-stuck cases in every profile. Flipping the profile
  to `panic = "unwind"` is out of scope and belongs to RFC-0002's boundary work.
- A restart storm (a worker that panics immediately and forever) is bounded by
  `max_restarts` and terminal `Failed`; the supervisor stops respawning and leaves the
  flag set rather than spinning. Rejected: unbounded restart with no ceiling.
- Reading a `HealthFlag` on the pre-dispatch path adds one relaxed atomic load per
  evaluation, the same cost the existing `emergency_stopped` check already pays; no
  measurable throughput change.
- Rejected: hosting the supervisor in `chio-runtime-core`. It depends on `chio-kernel`,
  so it would pull the TCB into `chio-siem` and violate ADR-0009. A zero-dep leaf crate
  is the only placement that serves the kernel, control-plane, and SIEM callers without
  coupling them.
- Rejected: pulling a supervisor crate such as `tokio-graceful` or an actor framework.
  The surface is small (one flag, one loop wrapper, two spawn helpers), the fail-closed
  and never-self-clear semantics are bespoke, and a TCB-adjacent leaf crate must stay
  dependency-light and `unwrap`-free.
- Rejected: making the health flag self-heal on a successful poll. That is exactly the
  lie the article warns against - a worker that recovered but dropped receipts would
  read green. Recovery is operator-visible only.

## Rollout and sequencing

1. Land `crates/core/chio-supervisor` with `HealthFlag`, `SupervisedThread`,
   `supervise_task`, and their unit/property/loom tests. No behavior change elsewhere.
2. Wire the receipt-commit writer (F27): `SupervisedThread`, `WriterDead`, honest
   `receipt_store_health`, and the pre-dispatch gate flag check. Highest blast radius and
   production path, so first.
3. Fix the sidecar surfaces (F59): split `/chio/live` and dependency-aware `/chio/health`,
   then the coordinated deploy-manifest probe repointing.
4. Apply the poison policy (F09) to the session and budget-registry locks with the
   kernel degraded flag and poison counter.
5. Supervise and surface the cluster sync loop (F13) and the SIEM exporter (F84),
   including the SOC metric emitters and dead-man alert.
6. Wire all flags and counters to the RFC-0009 exporter as it lands.

Dependencies: RFC-0009 exports the gauges but is not a blocker for landing the flags
(`HealthFlag::snapshot` is readable immediately). RFC-0001 supplies the wedged-writer
deadline that trips the writer flag; without it the flag still catches worker exit,
spawn failure, and panic (unwind), and the pre-dispatch gate still fails closed on a
known-degraded writer. RFC-0002's unwind boundary is what makes `catch_unwind`-based
restart effective in a hardened production profile.
