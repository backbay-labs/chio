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

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::ExecutionNonceStore;
use chio_store_sqlite::SqliteExecutionNonceStore;

use chio_test_support::prelude::*;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

#[test]
fn fresh_nonce_is_reserved() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.reserve("nonce-a").test_unwrap());
}

#[test]
fn replayed_nonce_is_rejected_within_retention() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    // Use try_reserve directly to lock the clock so retention is
    // guaranteed to still apply on the second call.
    let now = 1_000_000;
    let expires_at = now + 60;
    assert!(store.try_reserve("nonce-b", now, expires_at).test_unwrap());
    assert!(!store
        .try_reserve("nonce-b", now + 1, expires_at)
        .test_unwrap());
}

#[test]
fn expired_row_is_pruned_and_slot_becomes_free() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.try_reserve("nonce-c", 1_000, 1_010).test_unwrap());
    // The signed `expires_at` is the primary replay defence; the store
    // row GC here just bounds the table size.
    assert!(store.try_reserve("nonce-c", 2_000, 2_060).test_unwrap());
}

#[test]
fn persists_consumed_marker_across_reopen() {
    let path = unique_db_path("chio-exec-nonce-persist");
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("time before epoch")
            .as_secs(),
    )
    .test_expect("wall clock fits i64");
    let expires_at = now.saturating_add(120);
    {
        let store = SqliteExecutionNonceStore::open(&path).test_unwrap();
        assert!(store
            .try_reserve("persistent-id", now, expires_at)
            .test_unwrap());
        assert!(store.is_consumed("persistent-id").test_unwrap());
    }
    let reopened = SqliteExecutionNonceStore::open(&path).test_unwrap();
    assert!(reopened.is_consumed("persistent-id").test_unwrap());
    assert!(!reopened
        .try_reserve("persistent-id", now, expires_at)
        .test_unwrap());
    let _ = std::fs::remove_file(path);
}

#[test]
fn expired_consumed_marker_does_not_block_a_validated_nonce() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.try_reserve("expired-id", 1_000, 1_100).test_unwrap());
    assert!(!store.is_consumed("expired-id").test_unwrap());
}

#[test]
fn distinct_ids_each_succeed() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.reserve("a").test_unwrap());
    assert!(store.reserve("b").test_unwrap());
    assert!(store.reserve("c").test_unwrap());
    assert!(!store.reserve("a").test_unwrap());
    assert!(!store.reserve("b").test_unwrap());
}

#[test]
fn trait_reserve_uses_wall_clock_now() {
    // Sanity: the trait impl goes through try_reserve with a now
    // derived from SystemTime, so it should succeed for a fresh id.
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(
        <SqliteExecutionNonceStore as ExecutionNonceStore>::reserve(&store, "trait-path")
            .test_unwrap()
    );
}
