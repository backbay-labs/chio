//! Boot-path contract tests for the real-stack load generator.
//!
//! These assert the fail-closed boundary of `StackHarness`: a gating boot
//! refuses a non-durable in-memory store, a store that cannot be opened yields
//! a typed error, and a durable boot persists a real receipt through the live
//! kernel dispatch path.

use std::path::PathBuf;
use std::time::Duration;

use chio_loadgen::{LoadgenConfig, LoadgenError, StackHarness, StoreBacking};
use chio_test_support::prelude::*;

fn base_config(store: StoreBacking) -> LoadgenConfig {
    LoadgenConfig {
        arrival_rate_hz: 100,
        duration: Duration::from_secs(1),
        tool_latency: Duration::from_millis(5),
        store,
        p99_budget: Duration::from_millis(50),
        rss_growth_budget_bytes: 64 * 1024 * 1024,
    }
}

#[test]
fn boot_rejects_memory_store_in_gate_mode() {
    let config = base_config(StoreBacking::Memory);

    let error = StackHarness::boot(&config).test_unwrap_err();

    assert!(
        matches!(error, LoadgenError::MemoryStoreRejectedInGate),
        "gating boot must refuse a non-durable store, got {error:?}"
    );
}

#[test]
fn boot_rejects_in_memory_sqlite_path_in_gate_mode() {
    // A durable gate must refuse a transient in-memory SQLite path so it cannot
    // advertise persistence that vanishes at exit.
    let config = base_config(StoreBacking::Sqlite {
        path: PathBuf::from(":memory:"),
    });

    let error = StackHarness::boot(&config).test_unwrap_err();

    assert!(
        matches!(error, LoadgenError::MemoryStoreRejectedInGate),
        "a gating boot must refuse an in-memory SQLite path, got {error:?}"
    );
}

#[test]
fn boot_rejects_empty_sqlite_path_in_gate_mode() {
    // SQLite opens an empty filename as a private temporary on-disk database that
    // is deleted on close, so a durable gate must refuse it exactly as it refuses
    // an in-memory path: receipts would vanish when the harness drops.
    let config = base_config(StoreBacking::Sqlite {
        path: PathBuf::from(""),
    });

    let error = StackHarness::boot(&config).test_unwrap_err();

    assert!(
        matches!(error, LoadgenError::MemoryStoreRejectedInGate),
        "a gating boot must refuse an empty (transient) SQLite path, got {error:?}"
    );
}

#[test]
fn boot_rejects_empty_main_db_file_uri_in_gate_mode() {
    // A `file:` URI whose main-database name is empty (here just the scheme) opens
    // the same private temporary on-disk database as an empty filename, so a
    // durable gate must refuse it too.
    let config = base_config(StoreBacking::Sqlite {
        path: PathBuf::from("file:?mode=rwc"),
    });

    let error = StackHarness::boot(&config).test_unwrap_err();

    assert!(
        matches!(error, LoadgenError::MemoryStoreRejectedInGate),
        "a gating boot must refuse a file: URI with an empty main database, got {error:?}"
    );
}

#[test]
fn boot_reports_store_open_error_on_unwritable_path() {
    let dir = tempfile::tempdir().test_unwrap();
    // A regular file where a directory is required: the store cannot create the
    // nested parent directory beneath it, so open must fail closed.
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").test_unwrap();
    let db_path = blocker.join("nested").join("receipts.sqlite");

    let config = base_config(StoreBacking::Sqlite { path: db_path });
    let error = StackHarness::boot(&config).test_unwrap_err();

    assert!(
        matches!(error, LoadgenError::StoreOpen(_)),
        "an unwritable store path must surface StoreOpen, got {error:?}"
    );
}

#[test]
fn boot_smoke_dispatch_persists_one_receipt() {
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = base_config(StoreBacking::Sqlite { path: db_path });
    let harness = StackHarness::boot_smoke(&config).test_unwrap();

    let latency = harness.dispatch_allow_once().test_unwrap();
    // The configurable-latency stub tool server slept for tool_latency inside
    // invoke, so a real end-to-end dispatch cannot be faster than that budget.
    assert!(
        latency >= Duration::from_millis(5),
        "dispatch latency {latency:?} must include the stub tool-server latency"
    );

    let committed_seq = harness.flush_durable().test_unwrap();
    assert!(
        committed_seq >= 1,
        "one allow dispatch must durably commit at least one receipt, got {committed_seq}"
    );
}
