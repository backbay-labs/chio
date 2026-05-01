//! Contract tests for `SqliteExecutionNonceStore`.
//!
//! Exercises the `ExecutionNonceStore` trait contract plus the durable
//! replay-prevention guarantees specific to the SQLite backend:
//!
//! * `reserve(id)` returns `Ok(true)` on first call, `Ok(false)` on
//!   replay within the retention window.
//! * Consumed nonces persist across store reopen so a kernel restart
//!   does not open a replay window.
//! * Expiry + retention grace period allows a slot to be recycled only
//!   after `expires_at` is in the past.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::ExecutionNonceStore;
use chio_store_sqlite::SqliteExecutionNonceStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

#[test]
fn fresh_nonce_is_reserved() {
    let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
    assert!(store.reserve("nonce-a").unwrap());
}

#[test]
fn replayed_nonce_is_rejected_within_retention() {
    let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
    // Use try_reserve directly to lock the clock so retention is
    // guaranteed to still apply on the second call.
    let now = 1_000_000;
    let expires_at = now + 60;
    assert!(store.try_reserve("nonce-b", now, expires_at).unwrap());
    assert!(!store.try_reserve("nonce-b", now + 1, expires_at).unwrap());
}

#[test]
fn expired_row_is_pruned_and_slot_becomes_free() {
    let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
    assert!(store.try_reserve("nonce-c", 1_000, 1_010).unwrap());
    // The signed `expires_at` is the primary replay defence; the store
    // row GC here just bounds the table size.
    assert!(store.try_reserve("nonce-c", 2_000, 2_060).unwrap());
}

#[test]
fn persists_consumed_marker_across_reopen() {
    let path = unique_db_path("chio-exec-nonce-persist");
    {
        let store = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(store
            .try_reserve("persistent-id", 1_000, 10_000_000_000)
            .unwrap());
    }
    let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
    assert!(!reopened
        .try_reserve("persistent-id", 1_001, 10_000_000_000)
        .unwrap());
    let _ = std::fs::remove_file(path);
}

#[test]
fn distinct_ids_each_succeed() {
    let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
    assert!(store.reserve("a").unwrap());
    assert!(store.reserve("b").unwrap());
    assert!(store.reserve("c").unwrap());
    assert!(!store.reserve("a").unwrap());
    assert!(!store.reserve("b").unwrap());
}

#[test]
fn trait_reserve_uses_wall_clock_now() {
    // Sanity: the trait impl goes through try_reserve with a now
    // derived from SystemTime, so it should succeed for a fresh id.
    let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
    assert!(
        <SqliteExecutionNonceStore as ExecutionNonceStore>::reserve(&store, "trait-path").unwrap()
    );
}
