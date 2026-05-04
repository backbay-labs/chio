//! Replay-attack resistance integration coverage.
//!
//! Each test below exercises the issuer with a [`PasskeyNonceStore`]
//! attached:
//!
//! - First mint with a fresh `(credential_id, challenge_nonce)` succeeds.
//! - Second mint with the same pair fails with
//!   [`CustodyError::ReplayDetected`] and URN
//!   `urn:chio:error:custody:replay-detected`.
//! - Different credential ids that happen to share a nonce value succeed
//!   independently (the store keys on the pair, not the nonce alone).
//! - The retention bound is `exp + clock_skew`; an entry strictly past
//!   that bound is GC-able and a fresh nonce can reuse the slot.
//! - The SQLite implementation, when compiled with
//!   `--features sqlite-store`, exhibits the same behaviour as the
//!   in-memory implementation.

use std::sync::Arc;

use chio_custody_hw::capability::ScopeSet;
use chio_custody_hw::error::CustodyError;
use chio_custody_hw::issuer::{IssuerService, MintRequest};
use chio_custody_hw::nonce_store::{InMemoryPasskeyNonceStore, PasskeyNonceStore, RecordOutcome};
use chio_custody_hw::verifier::VerifiedAssertion;
use chrono::{TimeZone, Utc};

const AUDIENCE: &str = "urn:chio:audience:kernel";

fn fixed_now() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn assertion(cred: &str) -> VerifiedAssertion {
    VerifiedAssertion {
        credential_id_b64: cred.into(),
        user_verified: true,
    }
}

fn request(nonce: &str) -> MintRequest {
    MintRequest {
        audience: AUDIENCE.into(),
        scope_set: ScopeSet::new(["tool:read"]),
        challenge_nonce: nonce.into(),
    }
}

#[test]
fn first_mint_fresh_second_mint_replay_in_memory() {
    let store: Arc<dyn PasskeyNonceStore> = Arc::new(InMemoryPasskeyNonceStore::new());
    let svc = IssuerService::new(AUDIENCE).with_nonce_store(store);
    let req = request("nonce-replay-1");

    let first = match svc.mint_capability(&assertion("cred-A"), &req, fixed_now()) {
        Ok(r) => r,
        Err(e) => panic!("first mint must be fresh: {e}"),
    };
    assert_eq!(first.capability.challenge_nonce, "nonce-replay-1");

    let res = svc.mint_capability(&assertion("cred-A"), &req, fixed_now());
    let err = match res {
        Ok(_) => panic!("second mint MUST fail-closed as replay"),
        Err(e) => e,
    };
    match &err {
        CustodyError::ReplayDetected { credential_id } => {
            assert_eq!(credential_id, "cred-A");
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }
    assert_eq!(err.urn(), "urn:chio:error:custody:replay-detected");
}

#[test]
fn distinct_credentials_share_nonce_value_safely() {
    let store: Arc<dyn PasskeyNonceStore> = Arc::new(InMemoryPasskeyNonceStore::new());
    let svc = IssuerService::new(AUDIENCE).with_nonce_store(store);
    let req = request("collision");

    let a = svc.mint_capability(&assertion("cred-A"), &req, fixed_now());
    let b = svc.mint_capability(&assertion("cred-B"), &req, fixed_now());
    assert!(a.is_ok(), "cred-A first mint must succeed");
    assert!(
        b.is_ok(),
        "cred-B with same nonce value but different credential id must NOT be a replay"
    );
}

#[test]
fn record_outcome_distinguishes_fresh_and_replay() {
    let store = InMemoryPasskeyNonceStore::new();
    let now_unix = match chrono::Utc::now().timestamp().checked_add(0) {
        Some(t) => t,
        None => panic!("clock fixture overflow"),
    };
    let exp = now_unix + 300;
    let first = match store.record_if_fresh("cred", "nonce", exp) {
        Ok(o) => o,
        Err(e) => panic!("first record: {e}"),
    };
    assert_eq!(first, RecordOutcome::Fresh);
    let second = match store.record_if_fresh("cred", "nonce", exp) {
        Ok(o) => o,
        Err(e) => panic!("second record: {e}"),
    };
    assert_eq!(second, RecordOutcome::Replayed);
}

#[test]
fn stale_entry_before_gc_is_still_treated_as_replay() {
    // The trust contract says the record path NEVER prunes; only an
    // explicit `gc_expired` sweep drops entries. That keeps a slow GC
    // from being observed as an accepted replay. This test pins the
    // behaviour: an entry past its retention bound is still a replay
    // until `gc_expired` runs.
    let store = InMemoryPasskeyNonceStore::with_clock_skew(0);
    let exp_in_past = 100;
    let first = match store.record_if_fresh("cred-stale", "nonce-stale", exp_in_past) {
        Ok(o) => o,
        Err(e) => panic!("first record: {e}"),
    };
    assert_eq!(first, RecordOutcome::Fresh);
    // Second record with the same key, even at a "far future" exp, must
    // still classify as replay because the entry has not been GC'd.
    let second = match store.record_if_fresh("cred-stale", "nonce-stale", 10_000) {
        Ok(o) => o,
        Err(e) => panic!("second record: {e}"),
    };
    assert_eq!(
        second,
        RecordOutcome::Replayed,
        "stale-but-not-GC'd entries must still trip replay detection"
    );
}

#[test]
fn concurrent_record_calls_classify_exactly_one_as_fresh() {
    // The `record_if_fresh` contract requires that two concurrent calls
    // for the same `(credential_id, challenge_nonce)` cannot both
    // observe `Fresh`. Spawning a fan of writer threads, each racing on
    // the same key, must always see exactly one `Fresh` and N-1
    // `Replayed`. This pins the atomicity property the trust contract
    // documents.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const FANOUT: usize = 16;

    let store = Arc::new(InMemoryPasskeyNonceStore::new());
    let fresh_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));
    let exp = 10_000_000_000;

    let mut handles = Vec::with_capacity(FANOUT);
    for _ in 0..FANOUT {
        let store = Arc::clone(&store);
        let fresh = Arc::clone(&fresh_count);
        let replay = Arc::clone(&replay_count);
        handles.push(std::thread::spawn(move || {
            match store.record_if_fresh("cred-race", "nonce-race", exp) {
                Ok(RecordOutcome::Fresh) => {
                    fresh.fetch_add(1, Ordering::SeqCst);
                }
                Ok(RecordOutcome::Replayed) => {
                    replay.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => panic!("race writer failed: {e}"),
            }
        }));
    }
    for handle in handles {
        if let Err(e) = handle.join() {
            panic!("race writer panicked: {e:?}");
        }
    }

    assert_eq!(
        fresh_count.load(Ordering::SeqCst),
        1,
        "exactly one writer must observe Fresh"
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        FANOUT - 1,
        "all other writers must observe Replayed"
    );
}

#[test]
fn gc_after_retention_window_unblocks_slot() {
    // The retention bound is `exp + clock_skew`. With clock_skew = 0,
    // an entry whose exp is below `now_unix_seconds` is GC-able and a
    // fresh nonce can reuse the slot.
    let store = InMemoryPasskeyNonceStore::with_clock_skew(0);
    let _ = match store.record_if_fresh("cred", "nonce", 100) {
        Ok(o) => o,
        Err(e) => panic!("seed: {e}"),
    };
    let pruned = match store.gc_expired(200) {
        Ok(n) => n,
        Err(e) => panic!("gc: {e}"),
    };
    assert_eq!(pruned, 1);
    let after = match store.record_if_fresh("cred", "nonce", 300) {
        Ok(o) => o,
        Err(e) => panic!("after-gc record: {e}"),
    };
    assert_eq!(
        after,
        RecordOutcome::Fresh,
        "after GC the (cred, nonce) slot must be reusable for a fresh capability"
    );
}

#[cfg(feature = "sqlite-store")]
mod sqlite {
    //! Durable nonce-store coverage gated on `sqlite-store`. The SQLite
    //! and in-memory implementations MUST exhibit the same observable
    //! behaviour for the issuer mint path.
    use super::*;
    use chio_custody_hw::nonce_store::SqlitePasskeyNonceStore;

    #[test]
    fn sqlite_store_detects_replay() {
        let store = match SqlitePasskeyNonceStore::open_in_memory() {
            Ok(s) => s,
            Err(e) => panic!("sqlite open: {e}"),
        };
        let store_arc: Arc<dyn PasskeyNonceStore> = Arc::new(store);
        let svc = IssuerService::new(AUDIENCE).with_nonce_store(store_arc);
        let req = request("sqlite-nonce");
        let first = svc.mint_capability(&assertion("cred-X"), &req, fixed_now());
        assert!(first.is_ok());
        let second = svc.mint_capability(&assertion("cred-X"), &req, fixed_now());
        assert!(matches!(second, Err(CustodyError::ReplayDetected { .. })));
    }

    #[test]
    fn sqlite_concurrent_record_calls_classify_exactly_one_as_fresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const FANOUT: usize = 8;

        let store = match SqlitePasskeyNonceStore::open_in_memory() {
            Ok(s) => s,
            Err(e) => panic!("sqlite open: {e}"),
        };
        let store: Arc<dyn PasskeyNonceStore> = Arc::new(store);
        let fresh_count = Arc::new(AtomicUsize::new(0));
        let replay_count = Arc::new(AtomicUsize::new(0));
        let exp = 10_000_000_000;

        let mut handles = Vec::with_capacity(FANOUT);
        for _ in 0..FANOUT {
            let store = Arc::clone(&store);
            let fresh = Arc::clone(&fresh_count);
            let replay = Arc::clone(&replay_count);
            handles.push(std::thread::spawn(move || {
                match store.record_if_fresh("cred-race", "nonce-race", exp) {
                    Ok(RecordOutcome::Fresh) => {
                        fresh.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(RecordOutcome::Replayed) => {
                        replay.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("sqlite race writer failed: {e}"),
                }
            }));
        }
        for handle in handles {
            if let Err(e) = handle.join() {
                panic!("sqlite race writer panicked: {e:?}");
            }
        }

        assert_eq!(
            fresh_count.load(Ordering::SeqCst),
            1,
            "sqlite store: exactly one writer must observe Fresh"
        );
        assert_eq!(
            replay_count.load(Ordering::SeqCst),
            FANOUT - 1,
            "sqlite store: all other writers must observe Replayed"
        );
    }
}
