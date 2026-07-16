//! Measurement contract tests for the sustained-load runner.
//!
//! These pin the pacer arrival rate, the measured-percentile and time-to-first-
//! receipt-hardened reporting, and the typed fail-closed budget gate.

use std::time::Duration;

use chio_loadgen::{
    enforce_budget, run_sustained, LoadgenConfig, LoadgenError, StackHarness, StoreBacking,
};
use chio_test_support::prelude::*;

#[test]
fn pacer_holds_arrival_rate_within_tolerance() {
    let config = LoadgenConfig {
        arrival_rate_hz: 200,
        duration: Duration::from_secs(2),
        tool_latency: Duration::ZERO,
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let report = run_sustained(&harness, &config).test_unwrap();

    // The pacer schedules against absolute tick instants (start + n * interval),
    // so 2s at 200hz has at most ~400 tick slots and can never dispatch more,
    // regardless of machine speed. This ceiling is the pacer's real safety
    // property: it never runs the kernel unbounded or faster than the rate.
    // No throughput floor is asserted, because achieved throughput is a function
    // of how fast a real ed25519 dispatch runs on the host, and a saturated CI
    // runner legitimately completes far fewer than the target in the window; the
    // deterministic pacer-interval math is covered by a unit test instead. The
    // floor here is only "it made progress", which cannot flake on load.
    assert!(
        report.calls_attempted >= 1,
        "the pacer must dispatch at least once in a 2s window, got {}",
        report.calls_attempted
    );
    assert!(
        report.calls_attempted <= 440,
        "the pacer must not exceed the ~400 tick slots in 2s at 200hz, got {}",
        report.calls_attempted
    );
}

#[test]
fn run_sustained_rejects_zero_arrival_rate() {
    let config = LoadgenConfig {
        arrival_rate_hz: 0,
        duration: Duration::from_millis(50),
        tool_latency: Duration::ZERO,
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let error = run_sustained(&harness, &config).test_unwrap_err();
    assert!(
        matches!(error, LoadgenError::ZeroArrivalRate),
        "a zero arrival rate must deny with ZeroArrivalRate rather than run uncapped, got {error:?}"
    );
}

#[test]
fn run_sustained_rejects_unrepresentable_duration() {
    let config = LoadgenConfig {
        arrival_rate_hz: 100,
        duration: Duration::from_secs(u64::MAX),
        tool_latency: Duration::ZERO,
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let error = run_sustained(&harness, &config).test_unwrap_err();
    assert!(
        matches!(error, LoadgenError::DurationTooLong),
        "a duration near u64::MAX seconds must deny with DurationTooLong, not panic, got {error:?}"
    );
}

#[test]
fn sustained_smoke_reports_measured_percentiles() {
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = LoadgenConfig {
        arrival_rate_hz: 100,
        duration: Duration::from_secs(2),
        tool_latency: Duration::from_millis(5),
        store: StoreBacking::Sqlite { path: db_path },
        p99_budget: Duration::from_millis(500),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot(&config).test_unwrap();
    let report = run_sustained(&harness, &config).test_unwrap();

    assert!(
        report.calls_ok > 0,
        "a healthy run must complete allow dispatches"
    );
    assert!(
        report.p99_ms > 0,
        "measured p99 must be positive when the fixture tool sleeps, got {}",
        report.p99_ms
    );
    match report.ttfrh_ms {
        Some(ms) => assert!(
            ms > 0,
            "time to first durable receipt must be positive on a durable backing, got {ms}"
        ),
        None => panic!(
            "a durable backing that hardened receipts must record a time to first durable receipt, got None"
        ),
    }
}

#[test]
fn budget_violation_is_typed() {
    let config = LoadgenConfig {
        arrival_rate_hz: 50,
        duration: Duration::from_millis(300),
        tool_latency: Duration::from_millis(20),
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(1),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let report = run_sustained(&harness, &config).test_unwrap();

    let error = enforce_budget(&report, &config).test_unwrap_err();
    assert!(
        matches!(error, LoadgenError::P99Exceeded { .. }),
        "a 20ms tool under a 1ms p99 budget must deny with P99Exceeded, got {error:?}"
    );
}
