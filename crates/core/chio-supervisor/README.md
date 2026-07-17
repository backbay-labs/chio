# chio-supervisor

Task supervision and monotonic health flags for Chio serving processes. Wraps
a long-lived worker, an OS thread ([`SupervisedThread`]) or, with the `async`
feature, a tokio task ([`SupervisedTask`]), so it restarts on panic or failure
with capped exponential backoff, and exposes a [`HealthFlag`] a serving
surface polls to know the worker is alive rather than silently dead or wedged.

Zero-Chio-dependency leaf crate: `chio-kernel`'s pre-dispatch lock-poison gate
and `chio-store-sqlite`'s writer thread each embed a `HealthFlag` without
depending on one another or on the kernel.

## Responsibilities

- Run a worker body in a restart loop with capped exponential backoff,
  catching panics so a dead worker cannot silently stop looping.
- Track health as a monotonic `HealthLevel` (`Healthy` -> `Degraded` ->
  `Failed`) that never self-heals; only `HealthFlag::clear` moves it back.
- Fail closed: a `tcb_critical` flag's `is_serving_closed()` turns true the
  instant it leaves `Healthy`, so a caller can deny work before it executes.
- Retain the worker's join handle so `Drop` can signal shutdown or abort
  in-flight work instead of leaking an orphaned thread or task.

## Public API

- `SupervisedThread::spawn(config, worker)` - supervise a synchronous
  `Fn(&Arc<AtomicBool>) -> SupervisedOutcome` closure on its own OS thread.
  `health()` clones the `HealthFlag`; `shutdown()` signals and joins,
  returning the terminal `HealthLevel`.
- `supervise_task` / `SupervisedTask::spawn(config, iteration)` (feature
  `async`) - supervise an async iteration closure as a tokio task, each
  iteration in its own child task so a panic across `.await` is caught.
  `is_finished()` reports loop exit; `abort()` cancels the loop and its
  in-flight child.
- `HealthFlag` - cloneable handle: `new`, `record_ok`, `record_failure`,
  `escalate_failed`, `clear`, `level`, `tcb_critical`, `is_serving_closed`,
  `snapshot`.
- `HealthLevel` (snake_case serde) and `HealthSnapshot` (camelCase serde) -
  the severity enum and its serializable point-in-time view.
- `SupervisorConfig::new(name, tcb_critical)` - trips to `Degraded` after 3
  consecutive restarts, `Failed` after 10, backoff from 100ms doubling to a
  60s ceiling; fields are public for a custom policy.
- `SupervisedOutcome::{Shutdown, Continue, Restart}` - returned by the worker
  body each iteration.
- `now_unix_ms` - saturating milliseconds-since-epoch used for health
  timestamps.

## Usage

```rust
use chio_supervisor::{SupervisedOutcome, SupervisedThread, SupervisorConfig};

let config = SupervisorConfig::new("receipt-writer", true);
let thread = SupervisedThread::spawn(config, |shutdown| {
    if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        return SupervisedOutcome::Shutdown;
    }
    // do one unit of work, then report the outcome
    SupervisedOutcome::Continue
});

let health = thread.health();
if health.is_serving_closed() {
    // deny work rather than serve off a degraded writer
}
```

## Feature flags

| Flag | Effect |
|------|--------|
| `async` | Enables `supervise_task` / `SupervisedTask`, the tokio-based task supervisor. Kept optional so the synchronous thread supervisor and `HealthFlag` stay usable by callers that do not link tokio. |

## Testing

`cargo test -p chio-supervisor` runs the unit and property tests. The loom
concurrency model is nightly-only and excluded by default:

```
RUSTFLAGS="--cfg loom" cargo test -p chio-supervisor --test loom_health --release
```

## See also

- `chio-kernel` - embeds a `HealthFlag` directly in its pre-dispatch
  lock-poison gate and surfaces a writer's `HealthLevel` in receipt-store
  health reports.
- `chio-store-sqlite` - supervises its SQLite writer thread with
  `SupervisedThread`.
