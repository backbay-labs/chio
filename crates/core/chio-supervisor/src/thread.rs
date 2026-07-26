//! Supervised OS thread: retains the join handle, wraps the worker body in
//! `catch_unwind`, restarts with capped backoff, and trips the health flag on a
//! non-shutdown exit, a panic, or a spawn failure.

use crate::config::{backoff_delay, SupervisedOutcome, SupervisorConfig};
use crate::health::HealthFlag;
use crate::time::now_unix_ms;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// A supervised OS thread that owns its join handle and a [`HealthFlag`]. The worker
/// closure is the loop body; it receives the shutdown flag so it can exit promptly
/// and return [`SupervisedOutcome::Shutdown`].
pub struct SupervisedThread {
    handle: Option<JoinHandle<()>>,
    health: HealthFlag,
    shutdown: Arc<AtomicBool>,
}

impl SupervisedThread {
    /// Spawn a supervised thread. On a caught panic (under an unwind profile) or a
    /// [`SupervisedOutcome::Restart`], the worker body is re-entered with capped
    /// backoff, reusing the same owned resources it captured. If the thread cannot be
    /// spawned at all, the flag is tripped straight to `Failed` so no surface reads
    /// green off a worker that never started.
    pub fn spawn<F>(config: SupervisorConfig, worker: F) -> Self
    where
        F: FnMut(&Arc<AtomicBool>) -> SupervisedOutcome + Send + 'static,
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
                let now = now_unix_ms();
                health.record_failure(
                    format!("supervisor could not spawn thread: {error}"),
                    now,
                    0,
                );
                health.escalate_failed(now);
                None
            }
        };
        Self {
            handle,
            health,
            shutdown,
        }
    }

    /// A cloneable handle to this thread's health.
    #[must_use]
    pub fn health(&self) -> HealthFlag {
        self.health.clone()
    }

    /// Signal shutdown and join the worker. Returns the terminal health level.
    pub fn shutdown(self) -> crate::HealthLevel {
        self.signal_shutdown();
        self.join()
    }

    /// Join after the worker reaches its own terminal condition without setting
    /// the shutdown flag. Use when another owned resource, such as a disconnected
    /// command channel, tells the worker to drain and exit.
    pub fn join(mut self) -> crate::HealthLevel {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.health.level()
    }

    fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl Drop for SupervisedThread {
    fn drop(&mut self) {
        // Never leak a running worker: signal shutdown so the loop observes it and
        // exits on its next iteration even if the caller forgot to join.
        self.signal_shutdown();
    }
}

fn supervise_loop<F>(
    config: SupervisorConfig,
    mut worker: F,
    health: HealthFlag,
    shutdown: Arc<AtomicBool>,
) where
    F: FnMut(&Arc<AtomicBool>) -> SupervisedOutcome,
{
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| worker(&shutdown)));
        match outcome {
            Ok(SupervisedOutcome::Shutdown) => return,
            Ok(SupervisedOutcome::Continue) => {
                // A completed tick resets the consecutive-failure counter and
                // stamps liveness. Without this, isolated faults separated by
                // healthy work accumulate and eventually trip (or escalate) a
                // worker that is in fact recovering between them. A tripped level
                // is never lowered here; only an operator clear recovers that.
                health.record_ok(now_unix_ms());
                continue;
            }
            Ok(SupervisedOutcome::Restart) | Err(_) => {
                if shutdown.load(Ordering::SeqCst) {
                    return;
                }
                let now = now_unix_ms();
                let reason = match &outcome {
                    Err(_) => format!("{} worker panicked", config.name),
                    _ => format!("{} worker exited", config.name),
                };
                let count = health.record_failure(reason, now, config.trip_after);
                if count >= config.max_restarts {
                    health.escalate_failed(now);
                    return;
                }
                std::thread::sleep(backoff_delay(&config, count));
            }
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::HealthLevel;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    fn fast_config(name: &'static str, tcb: bool, max_restarts: u32) -> SupervisorConfig {
        SupervisorConfig {
            name,
            tcb_critical: tcb,
            trip_after: 2,
            max_restarts,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
        }
    }

    #[test]
    fn clean_shutdown_leaves_flag_healthy() {
        let thread = SupervisedThread::spawn(fast_config("clean", false, 5), |shutdown| {
            while !shutdown.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            SupervisedOutcome::Shutdown
        });
        let level = thread.shutdown();
        assert_eq!(level, HealthLevel::Healthy);
    }

    #[test]
    fn panicking_worker_restarts_then_escalates_to_failed() {
        let attempts = Arc::new(AtomicU32::new(0));
        let worker_attempts = Arc::clone(&attempts);
        let thread = SupervisedThread::spawn(fast_config("panic", true, 3), move |_shutdown| {
            worker_attempts.fetch_add(1, Ordering::SeqCst);
            panic!("worker blew up");
        });
        let health = thread.health();
        // Wait for the restart budget to be exhausted.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while health.level() != HealthLevel::Failed && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(health.level(), HealthLevel::Failed);
        assert!(health.is_serving_closed());
        // The supervisor stopped respawning at the budget, not before.
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        thread.shutdown();
    }

    #[test]
    fn restart_outcome_trips_to_degraded_at_trip_after() {
        let thread = SupervisedThread::spawn(fast_config("restart", false, 100), |_shutdown| {
            SupervisedOutcome::Restart
        });
        let health = thread.health();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while health.level() == HealthLevel::Healthy && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(health.level(), HealthLevel::Degraded);
        thread.shutdown();
    }

    #[test]
    fn interleaved_restart_and_continue_never_trips() {
        // A worker that fails, recovers, fails, recovers must stay healthy: each
        // successful tick resets the consecutive-failure counter, so trip_after
        // (2 here) is never reached across non-consecutive faults. Without the
        // reset on Continue, the second Restart alone would trip to Degraded even
        // though the worker keeps succeeding between faults.
        let phase = Arc::new(AtomicU32::new(0));
        let worker_phase = Arc::clone(&phase);
        let done = Arc::new(AtomicBool::new(false));
        let worker_done = Arc::clone(&done);
        let thread = SupervisedThread::spawn(fast_config("interleave", false, 1000), move |_s| {
            let n = worker_phase.fetch_add(1, Ordering::SeqCst);
            match n {
                0 | 2 | 4 => SupervisedOutcome::Restart,
                1 | 3 => SupervisedOutcome::Continue,
                _ => {
                    worker_done.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(1));
                    SupervisedOutcome::Continue
                }
            }
        });
        let health = thread.health();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(health.level(), HealthLevel::Healthy);
        thread.shutdown();
    }

    #[test]
    fn continue_outcome_never_trips() {
        let ticks = Arc::new(AtomicU32::new(0));
        let worker_ticks = Arc::clone(&ticks);
        let thread = SupervisedThread::spawn(fast_config("continue", false, 5), move |shutdown| {
            if shutdown.load(Ordering::SeqCst) {
                return SupervisedOutcome::Shutdown;
            }
            worker_ticks.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
            SupervisedOutcome::Continue
        });
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(thread.health().level(), HealthLevel::Healthy);
        thread.shutdown();
        assert!(ticks.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn join_does_not_cancel_before_the_worker_enters() {
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let thread = SupervisedThread::spawn(fast_config("join-entry", true, 5), move |shutdown| {
            release_rx.recv().unwrap_or(());
            assert!(!shutdown.load(Ordering::SeqCst));
            entered_tx.send(()).unwrap_or(());
            SupervisedOutcome::Shutdown
        });

        let joiner = std::thread::spawn(move || thread.join());
        release_tx.send(()).unwrap_or(());
        let level = joiner.join().unwrap_or(HealthLevel::Failed);
        assert_eq!(entered_rx.try_recv(), Ok(()));
        assert_eq!(level, HealthLevel::Healthy);
    }

    #[test]
    fn join_waits_through_restart_backoff() {
        let attempts = Arc::new(AtomicU32::new(0));
        let worker_attempts = Arc::clone(&attempts);
        let (restarting_tx, restarting_rx) = std::sync::mpsc::sync_channel(1);
        let (restarted_tx, restarted_rx) = std::sync::mpsc::sync_channel(1);
        let thread = SupervisedThread::spawn(
            SupervisorConfig {
                base_backoff: Duration::from_millis(25),
                max_backoff: Duration::from_millis(25),
                ..fast_config("join-backoff", true, 5)
            },
            move |shutdown| {
                let attempt = worker_attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    restarting_tx.send(()).unwrap_or(());
                    SupervisedOutcome::Restart
                } else {
                    assert!(!shutdown.load(Ordering::SeqCst));
                    restarted_tx.send(()).unwrap_or(());
                    SupervisedOutcome::Shutdown
                }
            },
        );

        restarting_rx.recv().unwrap_or(());
        let level = thread.join();
        assert_eq!(restarted_rx.try_recv(), Ok(()));
        assert_eq!(level, HealthLevel::Healthy);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
