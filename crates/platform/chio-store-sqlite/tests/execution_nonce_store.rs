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

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("time before epoch")
            .as_secs(),
    )
    .test_expect("timestamp fits i64")
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
    let now = now_secs();
    let expires_at = now + 60;
    assert!(store.try_reserve("nonce-b", now, expires_at).test_unwrap());
    assert!(!store
        .try_reserve("nonce-b", now + 1, expires_at)
        .test_unwrap());
}

#[test]
fn expired_row_is_pruned_and_slot_becomes_free() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    let now = now_secs();
    assert!(store.try_reserve("nonce-c", now, now + 10).test_unwrap());
    assert!(store
        .try_reserve("nonce-c", now + 1_000, now + 1_060)
        .test_unwrap());
}

#[test]
fn persists_consumed_marker_across_reopen() {
    let path = unique_db_path("chio-exec-nonce-persist");
    {
        let store = SqliteExecutionNonceStore::open(&path).test_unwrap();
        let now = now_secs();
        assert!(store
            .try_reserve("persistent-id", now, now.saturating_add(10_000_000_000))
            .test_unwrap());
    }
    let reopened = SqliteExecutionNonceStore::open(&path).test_unwrap();
    let now = now_secs();
    assert!(!reopened
        .try_reserve("persistent-id", now, now.saturating_add(10_000_000_000))
        .test_unwrap());
    let _ = std::fs::remove_file(path);
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

#[test]
fn configured_capacity_denies_new_ids_without_evicting_replay_markers() {
    let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(1).test_unwrap();
    let now = now_secs();
    assert!(store.try_reserve("capacity-a", now, now + 60).test_unwrap());
    assert!(store.try_reserve("capacity-b", now, now + 60).is_err());
    assert!(!store.try_reserve("capacity-a", now, now + 60).test_unwrap());
}
