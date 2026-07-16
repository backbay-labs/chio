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

    // The upper bound proves the pacer never exceeds the target rate (2s at 200hz
    // caps at ~400 dispatches, each preceded by a real ed25519 dispatch). The
    // lower bound is deliberately loose: on a slow or debug CI runner a single
    // dispatch can legitimately take long enough to lower achieved throughput, so
    // this asserts the pacer's ceiling, not a kernel-throughput floor.
    assert!(
        (150..=440).contains(&report.calls_attempted),
        "2s at 200hz must not exceed ~400 attempts and must make real progress, got {}",
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
