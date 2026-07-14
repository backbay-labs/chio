# chio-supervisor architecture

## Overview

`chio-supervisor` is a dependency-free utility crate: a restart-with-backoff
loop plus a monotonic health flag, holding no state beyond what a caller wires
into it. It does not itself sit inside the kernel's trusted computing base,
but TCB-critical consumers embed its `HealthFlag` directly into their own
fail-closed gates (`chio-kernel`'s lock-poison check) and into serving-process
writer threads (`chio-store-sqlite`'s SQLite writer), so this crate's
correctness is load-bearing for those guarantees. The design goal is honesty:
a wedged or panicking worker must make its surface report unhealthy rather
than keep reporting green.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate doc (the honesty and fail-closed contract) and public re-exports. |
| `src/config.rs` | `SupervisorConfig` restart/backoff policy, `SupervisedOutcome` per-iteration result, `backoff_delay` (saturating exponential backoff). |
| `src/health.rs` | `HealthFlag`, `HealthLevel`, `HealthSnapshot`: the monotonic, cloneable health state and its serializable snapshot. |
| `src/thread.rs` | `SupervisedThread`: synchronous OS-thread supervisor loop, `catch_unwind` panic isolation, `Drop` signals shutdown. |
| `src/task.rs` (feature `async`) | `SupervisedTask` / `supervise_task`: tokio supervisor loop; each iteration runs in its own child task so a panic across `.await` is caught, and `abort()` / `Drop` cancel the loop and its in-flight child. |
| `src/time.rs` | `now_unix_ms`, `as_millis_u64`: saturating wall-clock helpers. |
| `src/sync.rs` | Atomic / `Arc` / `Mutex` shim: std types normally, loom's models under `--cfg loom`. |

## Supervision lifecycle

1. `spawn` creates a `HealthFlag::new(tcb_critical)` in `Healthy` state and
   starts the loop on an OS thread or, with `task.rs`, a tokio task.
2. Each iteration invokes the worker body under `catch_unwind` (thread: a
   closure taking the shutdown flag; task: a closure that builds a future,
   run in its own child task so a panic across an `.await` still surfaces).
3. The loop classifies the outcome:
   - `Shutdown` - the loop returns.
   - `Continue` - `HealthFlag::record_ok` resets the consecutive-failure
     counter and stamps liveness; the loop continues immediately.
   - `Restart` or a caught panic - `HealthFlag::record_failure` increments
     the consecutive and cumulative counters, sets the reason, and trips the
     flag to `Degraded` once `trip_after` is reached. If the count reaches
     `max_restarts` the flag escalates to `Failed` and the loop stops;
     otherwise it sleeps `backoff_delay(config, count)` and retries.
4. A consumer reads `HealthFlag::is_serving_closed()` on a pre-dispatch path,
   or `snapshot()` on a health-reporting path, to decide whether to deny work
   or report status.
5. Recovery is only through an explicit `HealthFlag::clear()` from an
   operator surface; nothing in the loop itself lowers the level.

## Invariants and failure modes

- Health level is monotonic outside `clear()`: `HealthFlag::raise_to` is a
  compare-and-swap loop, so a concurrent escalation can never be lost behind
  a lower-severity raise, and a reader never observes a torn or invalid level
  (loom-checked in `tests/loom_health.rs`).
- `record_ok` never lowers a tripped level; only `clear` does, and `clear`
  preserves `restart_total` so incident history survives the recovery.
- `is_serving_closed` is true exactly when `tcb_critical && level != Healthy`.
  `trip_after == 0` trips on the first failure.
- `backoff_delay` uses saturating arithmetic (`checked_shl` falling back to
  `u64::MAX`, `saturating_mul`, then `.min(max_backoff)`), so it cannot
  overflow or panic even at `count = u32::MAX`.
- `SupervisedThread` and `SupervisedTask` both implement `Drop` to signal
  shutdown or abort in-flight work: a caller that forgets to call
  `shutdown()` / `abort()` cannot leak a running worker.
- `SupervisedTask::abort` and the per-iteration child spawn are serialized
  under one lock (`ChildControl`), so an abort landing in the window between
  spawning a child and publishing its abort handle still cancels that child
  instead of detaching it to run unsupervised.
- If the OS thread itself fails to spawn, `SupervisedThread::spawn` trips the
  flag straight to `Failed` so no surface reads `Healthy` for a worker that
  never started.
- `unwrap_used` and `expect_used` are denied crate-wide by lint; a poisoned
  reason `Mutex` is recovered with `into_inner` rather than unwrapped.

## Dependencies

No internal `chio-*` dependencies: this is a leaf crate by design so
unrelated Chio surfaces (the kernel's pre-dispatch lock-poison gate, the
SQLite receipt writer, and other serving processes) can each depend on it
without depending on one another or pulling in the kernel. External: `serde`
for `HealthLevel` / `HealthSnapshot`; `tokio` (optional, `async` feature) for
the task supervisor. Dev-only: `loom` (behind `cfg(loom)`) for the
concurrency model check, `proptest` for the health-invariant property tests,
`serde_json` for the snapshot round-trip test.
