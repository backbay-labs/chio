//! Real kernel-path chaos scenarios driven through a live `StackHarness`.
//!
//! Both scenarios inject a genuine hot-path fault (a tool server that hangs far
//! past the dispatch deadline; a guard that blocks far past the guard-pipeline
//! deadline) and assert the kernel fails closed with a typed deadline deny
//! rather than hanging. Each carries the InjectionNoOp discipline: a dispatch
//! that returns a normal Allow proves the deadline never fired, so the scenario
//! fails with [`ChaosError::InjectionNoOp`] instead of passing vacuously.
//!
//! The deadline knobs live in `chio_kernel::HotPathDeadlineConfig`
//! (`dispatch_budget_ms`, `guard_pipeline_budget_ms`); the harness threads them
//! into the booted kernel via `StackHarness::boot_with_deadlines`.

#![forbid(unsafe_code)]

use std::sync::mpsc;
use std::time::Duration;

use chio_chaos::{chaos_iterations, ChaosError};
use chio_kernel::{
    Guard, GuardContext, GuardDecision, HotPathDeadlineConfig, KernelError, Verdict,
};
use chio_loadgen::{LoadgenConfig, StackHarness, StoreBacking};
use chio_test_support::prelude::*;

/// Default round count for the fast PR tier. The nightly lane raises
/// `CHIO_CHAOS_ITERATIONS`.
const DEFAULT_ITERATIONS: u64 = 3;

/// Dispatch and guard-pipeline budgets driven into the kernel. Small so a
/// breach is unambiguous while leaving wide headroom over scheduling jitter.
const DISPATCH_BUDGET_MS: u64 = 200;
const GUARD_BUDGET_MS: u64 = 200;

/// Tool-server latency for the hung-server scenario, set far above the dispatch
/// budget so the deadline must fire before the tool would return. The stub
/// server sleeps asynchronously, so a fired deadline cancels the sleep with no
/// blocking-thread cost.
const HUNG_TOOL_LATENCY_MS: u64 = 4_000;

/// How long the blocking guard stalls: far past the guard-pipeline budget, and
/// bounded so the detached blocking thread does not stall runtime teardown after
/// the deadline has fired.
const GUARD_SLEEP: Duration = Duration::from_secs(2);

fn iterations() -> u64 {
    chaos_iterations(DEFAULT_ITERATIONS).test_expect("CHIO_CHAOS_ITERATIONS must be a u64")
}

/// A durable Sqlite-backed config; `tool_latency` starts at zero because the
/// hung-server scenario sets the latency at runtime via `set_tool_latency_ms`.
fn sqlite_config(db_path: std::path::PathBuf) -> LoadgenConfig {
    LoadgenConfig {
        arrival_rate_hz: 1,
        duration: Duration::from_secs(1),
        tool_latency: Duration::from_millis(0),
        store: StoreBacking::Sqlite { path: db_path },
        p99_budget: Duration::from_millis(1),
        rss_growth_budget_bytes: 0,
    }
}

/// A guard whose `evaluate` blocks well past any budget, modeling a guard doing
/// synchronous blocking I/O. It ultimately allows, so if the guard-pipeline
/// deadline never fires the whole dispatch allows and the scenario's
/// InjectionNoOp check trips.
struct BlockingGuard {
    stall: Duration,
    entered: mpsc::Sender<()>,
}

impl Guard for BlockingGuard {
    fn name(&self) -> &str {
        "chaos-blocking-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let _ = self.entered.send(());
        std::thread::sleep(self.stall);
        Ok(GuardDecision::allow())
    }
}

/// A tool server hung far past the dispatch deadline must be cut short with a
/// typed fail-closed deny, and the kernel's signed Cancelled receipt for each
/// timed-out dispatch must survive a flush.
#[test]
fn chaos_hung_tool_server_hits_deadline_and_denies() {
    let rounds = iterations();
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = sqlite_config(db_path);
    let deadlines = HotPathDeadlineConfig {
        dispatch_budget_ms: DISPATCH_BUDGET_MS,
        ..HotPathDeadlineConfig::default()
    };
    let harness = StackHarness::boot_with_deadlines(&config, deadlines)
        .test_expect("boot stack with a dispatch deadline");
    // Drive the stub tool server far past the dispatch deadline at runtime.
    harness.set_tool_latency_ms(HUNG_TOOL_LATENCY_MS);

    let floor_before = harness.flush_durable().test_expect("flush before rounds");

    for round in 0..rounds {
        let outcome = harness
            .dispatch_once_verdict()
            .test_expect("dispatch under the dispatch deadline");

        // InjectionNoOp: a normal Allow means the hung tool did not breach the
        // deadline; nothing was fault-tested this round.
        if outcome.verdict == Verdict::Allow {
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "hung-tool dispatch returned Allow; the dispatch deadline did not fire"
                )
            );
        }
        assert_eq!(
            outcome.verdict,
            Verdict::Deny,
            "round {round}: a breached dispatch deadline must deny fail-closed"
        );
        let reason = outcome.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("deadline exceeded"),
            "round {round}: deny reason must name the hot-path deadline, got {reason:?}"
        );
        assert!(
            outcome.elapsed < Duration::from_millis(HUNG_TOOL_LATENCY_MS),
            "round {round}: the deadline must cut the {HUNG_TOOL_LATENCY_MS}ms tool short, took {:?}",
            outcome.elapsed
        );
    }

    // Each timed-out dispatch emits a signed Cancelled (deny) receipt; after a
    // flush those receipts are durably committed, so the committed floor must
    // advance by at least one entry per round.
    let floor_after = harness.flush_durable().test_expect("flush after rounds");
    assert!(
        floor_after >= floor_before + rounds,
        "each timed-out dispatch must persist a deny receipt: committed floor {floor_before} -> {floor_after} over {rounds} rounds"
    );
}

/// A guard blocking far past the guard-pipeline deadline must be cut short with
/// a typed fail-closed deny.
#[test]
fn chaos_blocking_guard_times_out_fail_closed() {
    let rounds = iterations();
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = sqlite_config(db_path);
    let deadlines = HotPathDeadlineConfig {
        guard_pipeline_budget_ms: GUARD_BUDGET_MS,
        ..HotPathDeadlineConfig::default()
    };
    let mut harness = StackHarness::boot_with_deadlines(&config, deadlines)
        .test_expect("boot stack with a guard-pipeline deadline");
    let (guard_entered_sender, guard_entered_receiver) = mpsc::channel();
    harness.add_guard(Box::new(BlockingGuard {
        stall: GUARD_SLEEP,
        entered: guard_entered_sender,
    }));

    for round in 0..rounds {
        let (guard_entry, dispatch_result) = std::thread::scope(|scope| {
            let dispatch = scope.spawn(|| harness.dispatch_once_verdict());
            let guard_entry =
                guard_entered_receiver.recv_timeout(Duration::from_millis(GUARD_BUDGET_MS));
            let dispatch_result = dispatch
                .join()
                .test_expect("guard-deadline dispatch thread must not panic");
            (guard_entry, dispatch_result)
        });
        if let Err(error) = guard_entry {
            eprintln!("round {round}: blocking guard entry handshake failed: {error}");
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "blocking guard did not enter before the guard-pipeline deadline"
                )
            );
        }
        let outcome = dispatch_result.test_expect("dispatch under the guard-pipeline deadline");

        // InjectionNoOp: the guard ultimately allows, so an Allow verdict means
        // the guard-pipeline deadline never fired and the guard was never cut
        // short.
        if outcome.verdict == Verdict::Allow {
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "blocking-guard dispatch returned Allow; the guard-pipeline deadline did not fire"
                )
            );
        }
        assert_eq!(
            outcome.verdict,
            Verdict::Deny,
            "round {round}: a breached guard-pipeline deadline must deny fail-closed"
        );
        let reason = outcome.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("deadline exceeded"),
            "round {round}: deny reason must name the hot-path deadline, got {reason:?}"
        );
        assert!(
            outcome.elapsed < GUARD_SLEEP,
            "round {round}: the deadline must cut the guard short, took {:?}",
            outcome.elapsed
        );
    }
}
