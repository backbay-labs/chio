//! Exhaustive loom model of a worker recording a failure concurrent with a reader
//! taking a snapshot of the same `HealthFlag`. Verifies no transition is lost and no
//! level is torn. Nightly only:
//!   RUSTFLAGS="--cfg loom" cargo test -p chio-supervisor --test loom_health --release
#![cfg_attr(not(loom), allow(dead_code))]

#[cfg(loom)]
use chio_supervisor::{HealthFlag, HealthLevel};

#[cfg(loom)]
#[test]
fn concurrent_failure_and_snapshot_observe_a_consistent_level() {
    loom::model(|| {
        let flag = HealthFlag::new(true);
        let writer = flag.clone();
        let reader = flag.clone();

        let writer = loom::thread::spawn(move || {
            writer.record_failure("boom", 1, 0);
        });
        let reader = loom::thread::spawn(move || {
            // A reader must never observe a torn or invalid level, and once the
            // writer has tripped the flag the reader either sees Healthy (it read
            // before the trip) or Degraded (after), never anything in between.
            let level = reader.level();
            assert!(matches!(
                level,
                HealthLevel::Healthy | HealthLevel::Degraded
            ));
            let _ = reader.is_serving_closed();
        });

        let _ = writer.join();
        let _ = reader.join();

        // After both complete, the failure is durably recorded.
        assert_eq!(flag.level(), HealthLevel::Degraded);
        assert_eq!(flag.snapshot().restart_total, 1);
    });
}
