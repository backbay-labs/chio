//! Property tests for the accounting-is-trustworthy invariants of `HealthFlag`:
//! severity is non-decreasing between operator clears, and `restart_total` equals
//! the number of recorded failures.
#![cfg(not(loom))]

use chio_supervisor::{HealthFlag, HealthLevel};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Ok,
    Failure,
    Escalate,
    Clear,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::Ok),
        Just(Op::Failure),
        Just(Op::Escalate),
        Just(Op::Clear),
    ]
}

fn severity(level: HealthLevel) -> u8 {
    match level {
        HealthLevel::Healthy => 0,
        HealthLevel::Degraded => 1,
        HealthLevel::Failed => 2,
    }
}

proptest! {
    #[test]
    fn level_is_monotonic_between_clears_and_restart_total_counts_failures(
        ops in prop::collection::vec(op_strategy(), 0..200),
        trip_after in 0u32..5,
    ) {
        let flag = HealthFlag::new(true);
        let mut now = 1u64;
        let mut floor = 0u8;
        let mut failures: u64 = 0;

        for op in ops {
            now += 1;
            match op {
                Op::Ok => flag.record_ok(now),
                Op::Failure => {
                    flag.record_failure("boom", now, trip_after);
                    failures += 1;
                }
                Op::Escalate => flag.escalate_failed(now),
                Op::Clear => {
                    flag.clear(now);
                    // A clear resets the monotonic floor: it is the one deliberate
                    // downgrade.
                    floor = 0;
                    prop_assert_eq!(flag.level(), HealthLevel::Healthy);
                    continue;
                }
            }
            let current = severity(flag.level());
            // Between clears the level never decreases.
            prop_assert!(current >= floor);
            floor = current;
        }

        // Every recorded failure is reflected in the cumulative restart total, and a
        // clear never erases that history.
        prop_assert_eq!(flag.snapshot().restart_total, failures);
    }

    #[test]
    fn tcb_serving_closed_iff_not_healthy(
        ops in prop::collection::vec(op_strategy(), 0..100),
    ) {
        let flag = HealthFlag::new(true);
        let mut now = 1u64;
        for op in ops {
            now += 1;
            match op {
                Op::Ok => flag.record_ok(now),
                Op::Failure => { flag.record_failure("boom", now, 0); }
                Op::Escalate => flag.escalate_failed(now),
                Op::Clear => flag.clear(now),
            }
            let closed = flag.is_serving_closed();
            let healthy = matches!(flag.level(), HealthLevel::Healthy);
            prop_assert_eq!(closed, !healthy);
        }
    }
}
