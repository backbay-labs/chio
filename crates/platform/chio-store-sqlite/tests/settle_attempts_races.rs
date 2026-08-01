//! Real concurrent-actor race test for the settlement dead-letter sink.
//!
//! The dead-letter table is written by independent actors: the kernel's
//! settlement routing consumer and the `chio settle` drain driver. Their
//! serialization point is the store itself - the receipt-writer actor when one
//! is attached, statement atomicity plus the busy-timeout otherwise - not any
//! in-process lock, so the race coverage has to run against the real store.
//! (A prior loom stand-in for this protocol modeled each SQL statement as an
//! atomic step, which made every assertion true by construction; loom cannot
//! falsify cross-process database serialization, so it was replaced by this
//! test.)
//!
//! Invariants driven under contention, all of which the callers rely on:
//!
//! 1. A receipt ends with at most one dead-letter row no matter how many
//!    actors dead-letter it concurrently (keyed idempotent insert).
//! 2. A byte-identical dead-letter replay reports `Ok(false)`, never an error,
//!    even when the replay races the original insert.
//! 3. No operation surfaces a busy/backend error under contention.

use std::sync::{Arc, Barrier};

use chio_settle::{DeadLetterRecord, SettlementFailureCode, SettlementFailureReason};
use chio_store_sqlite::dead_letters::SqliteDeadLetterStore;
use chio_store_sqlite::SqliteReceiptStore;
use chio_test_support::prelude::*;

/// Rounds per actor pair. Small enough to stay far inside the busy timeout on
/// a loaded runner, large enough that the actors genuinely overlap.
const ROUNDS: u64 = 25;

fn permanent(receipt_id: &str, attempts: u32) -> DeadLetterRecord {
    DeadLetterRecord::new(
        receipt_id,
        100,
        attempts,
        SettlementFailureReason::from_detail(SettlementFailureCode::Rpc, "permanent"),
    )
}

/// Two actors dead-lettering the same receipt concurrently with an identical
/// record: exactly one insert reports a new row, the other reports the
/// existing one, and neither errors (the conflict arm is reserved for
/// divergent payloads). A byte-identical replay after the race must also
/// report the existing row without erroring.
#[test]
fn concurrent_identical_dead_letters_land_one_row() {
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");
    // Model the real cross-actor topology. Each actor owns an independent
    // receipt-store writer and therefore an independent SQLite connection. A
    // shared WriterHandle would serialize both inserts before they reached the
    // database and make this contention test true by construction.
    let receipts_a = SqliteReceiptStore::open(&db_path).test_unwrap();
    let receipts_b = SqliteReceiptStore::open(&db_path).test_unwrap();
    let store_a = Arc::new(SqliteDeadLetterStore::open_alongside(&receipts_a).test_unwrap());
    let store_b = Arc::new(SqliteDeadLetterStore::open_alongside(&receipts_b).test_unwrap());

    for round in 0..ROUNDS {
        let receipt_id = format!("dl-race-{round}");
        let barrier = Arc::new(Barrier::new(2));
        let mut actors = Vec::new();
        for store in [Arc::clone(&store_a), Arc::clone(&store_b)] {
            let barrier = Arc::clone(&barrier);
            let receipt_id = receipt_id.clone();
            actors.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .insert(&permanent(&receipt_id, 3))
                    .test_expect("concurrent identical dead-letter must not error")
            }));
        }
        let inserted: Vec<bool> = actors
            .into_iter()
            .map(|actor| actor.join().test_expect("dead-letter actor joins"))
            .collect();
        assert_eq!(
            inserted.iter().filter(|new_row| **new_row).count(),
            1,
            "round {round}: exactly one of two identical concurrent dead-letters may report a new row, got {inserted:?}"
        );

        // Invariant 2: a byte-identical replay after the race reports Ok(false).
        assert!(
            !store_a
                .insert(&permanent(&receipt_id, 3))
                .test_expect("idempotent replay must not error"),
            "round {round}: byte-identical dead-letter replay must report an existing row"
        );
    }
}
