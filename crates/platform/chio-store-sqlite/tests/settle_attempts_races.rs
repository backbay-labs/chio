//! Real concurrent-actor race test for the settlement retry sink.
//!
//! The `settle_attempts` envelope and the dead-letter table are written by two
//! independent actors: the kernel's settlement routing consumer
//! (load -> classify -> upsert / dead-letter+clear) and the `chio settle`
//! drain driver (due -> drive -> upsert / dead-letter+clear). Their
//! serialization point is SQLite itself - statement atomicity plus the
//! busy-timeout on one shared database - not any in-process lock, so the race
//! coverage has to run against the real store. (A prior loom stand-in for this
//! protocol modeled each SQL statement as an atomic step, which made every
//! assertion true by construction; loom cannot falsify cross-process database
//! serialization, so it was replaced by this test.)
//!
//! Invariants driven under contention, all of which the callers rely on:
//!
//! 1. A receipt ends with at most one dead-letter row no matter how many
//!    actors dead-letter it concurrently (keyed idempotent insert).
//! 2. A byte-identical dead-letter replay reports `Ok(false)`, never an error,
//!    even when the replay races the original insert.
//! 3. The attempt envelope converges: after both actors finish, a final
//!    `clear_attempt` leaves no row, and `load_attempt` agrees.
//! 4. No operation surfaces a busy/backend error under contention: the
//!    busy-timeout enforced at open (>= 5000ms) absorbs writer overlap.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};
use chio_store_sqlite::{SqliteReceiptStore, SqliteSettlementRetryStore};

/// Rounds per actor pair. Small enough to stay far inside the 5s busy
/// timeout on a loaded runner, large enough that the actors genuinely overlap.
const ROUNDS: u64 = 25;

fn attempt(receipt_id: &str, attempts: u32) -> SettleAttemptRecord {
    SettleAttemptRecord {
        receipt_id: receipt_id.to_string(),
        finalized_at: 100,
        attempts,
        next_visible_at: 0,
        last_reason: Some("retryable".to_string()),
    }
}

/// Routing consumer racing the drain driver on one receipt per round: the
/// consumer performs the split read-modify-write (`load_attempt` then
/// `upsert_attempt`), the driver dead-letters the same receipt and clears the
/// envelope. Every interleaving must satisfy the four module invariants.
#[test]
fn concurrent_routing_and_drain_converge_per_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("receipts.sqlite");
    let receipts = SqliteReceiptStore::open(&db_path).unwrap();
    let store = Arc::new(SqliteSettlementRetryStore::open_alongside(&receipts).unwrap());

    let new_dead_letter_rows = Arc::new(AtomicU64::new(0));

    for round in 0..ROUNDS {
        let receipt_id = format!("race-{round}");
        let barrier = Arc::new(Barrier::new(2));

        let routing = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let receipt_id = receipt_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                // Kernel routing consumer shape: split load -> upsert.
                let prior = store
                    .load_attempt(&receipt_id)
                    .expect("load under contention")
                    .map(|record| record.attempts)
                    .unwrap_or(0);
                store
                    .upsert_attempt(&attempt(&receipt_id, prior + 1))
                    .expect("upsert under contention");
            })
        };

        let drain = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let receipt_id = receipt_id.clone();
            let new_rows = Arc::clone(&new_dead_letter_rows);
            std::thread::spawn(move || {
                barrier.wait();
                // Drain driver shape: dead-letter, then clear the envelope.
                let record =
                    chio_settle::DeadLetterRecord::new(receipt_id.clone(), 100, 1, "permanent");
                let inserted = store
                    .insert_dead_letter(&record)
                    .expect("dead-letter under contention");
                if inserted {
                    new_rows.fetch_add(1, Ordering::SeqCst);
                }
                store
                    .clear_attempt(&receipt_id)
                    .expect("clear under contention");
            })
        };

        routing.join().expect("routing actor joins");
        drain.join().expect("drain actor joins");

        // Invariant 2: a byte-identical replay after the race reports Ok(false).
        let replay = chio_settle::DeadLetterRecord::new(receipt_id.clone(), 100, 1, "permanent");
        assert!(
            !store
                .insert_dead_letter(&replay)
                .expect("idempotent replay must not error"),
            "round {round}: byte-identical dead-letter replay must report an existing row"
        );

        // Invariant 3: the envelope converges. The routing upsert may have
        // resurrected the row after the drain's clear (the split RMW makes that
        // interleaving legal); a follow-up clear must always converge to empty.
        store
            .clear_attempt(&receipt_id)
            .expect("convergence clear must not error");
        assert!(
            store
                .load_attempt(&receipt_id)
                .expect("post-convergence load")
                .is_none(),
            "round {round}: attempt envelope must be empty after the convergence clear"
        );
    }

    // Invariant 1: exactly one NEW dead-letter row per receipt across every
    // round, however the actors interleaved.
    assert_eq!(
        new_dead_letter_rows.load(Ordering::SeqCst),
        ROUNDS,
        "each receipt must land exactly one new dead-letter row"
    );
}

/// Two actors dead-lettering the same receipt concurrently with an identical
/// record: exactly one insert reports a new row, the other reports the
/// existing one, and neither errors (the conflict arm is reserved for
/// divergent payloads).
#[test]
fn concurrent_identical_dead_letters_land_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("receipts.sqlite");
    let receipts = SqliteReceiptStore::open(&db_path).unwrap();
    let store = Arc::new(SqliteSettlementRetryStore::open_alongside(&receipts).unwrap());

    for round in 0..ROUNDS {
        let receipt_id = format!("dl-race-{round}");
        let barrier = Arc::new(Barrier::new(2));
        let mut actors = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let receipt_id = receipt_id.clone();
            actors.push(std::thread::spawn(move || {
                barrier.wait();
                let record =
                    chio_settle::DeadLetterRecord::new(receipt_id.clone(), 100, 3, "permanent");
                store
                    .insert_dead_letter(&record)
                    .expect("concurrent identical dead-letter must not error")
            }));
        }
        let inserted: Vec<bool> = actors
            .into_iter()
            .map(|actor| actor.join().expect("dead-letter actor joins"))
            .collect();
        assert_eq!(
            inserted.iter().filter(|new_row| **new_row).count(),
            1,
            "round {round}: exactly one of two identical concurrent dead-letters may report a new row, got {inserted:?}"
        );
    }
}
