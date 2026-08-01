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

    // The open-loop scheduler must deliver every configured tick. A slower
    // closed-loop run is a failed load gate, even if its p99 stays below budget.
    assert_eq!(report.calls_attempted, 400);
    assert_eq!(report.calls_ok, 400);
}

#[test]
fn slow_dispatches_do_not_collapse_the_open_loop_rate() {
    let config = LoadgenConfig {
        arrival_rate_hz: 40,
        duration: Duration::from_millis(500),
        tool_latency: Duration::from_millis(100),
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(500),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let report = run_sustained(&harness, &config).test_unwrap();

    // A synchronous dispatcher can complete at most about five 100ms calls in
    // this window. Delivering all twenty proves dispatches overlap while the
    // pacer maintains the configured arrival schedule.
    assert_eq!(report.calls_attempted, 20);
    assert_eq!(report.calls_ok, 20);
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
fn run_sustained_rejects_over_resolution_rate() {
    // A rate past the nanosecond pacer resolution floors the per-tick interval to
    // zero, collapsing every tick onto run_start and dispatching uncapped. The
    // runner must deny it with a typed error, exactly as it rejects a zero rate,
    // rather than run an unbounded max-rate loop.
    let config = LoadgenConfig {
        arrival_rate_hz: 2_000_000_000,
        duration: Duration::from_millis(50),
        tool_latency: Duration::ZERO,
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let error = run_sustained(&harness, &config).test_unwrap_err();
    assert!(
        matches!(error, LoadgenError::ArrivalRateTooHigh { arrival_rate_hz } if arrival_rate_hz == 2_000_000_000),
        "a rate above the nanosecond pacer resolution must deny with ArrivalRateTooHigh rather than run uncapped, got {error:?}"
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
