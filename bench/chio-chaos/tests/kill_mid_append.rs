//! Real SIGKILL-mid-append crash-recovery chaos test for the SQLite receipt
//! store.
//!
//! A separate victim process (`chaos_victim`) appends receipts, flushes the
//! store as a durability barrier, and only then records an `ack <seq>` line for
//! the receipt the store just promised was durable. This test SIGKILLs the
//! victim mid-loop, round after round against one reused store, then reopens the
//! store and proves that no acknowledged receipt was ever lost. The victim is
//! located through `CARGO_BIN_EXE_chaos_victim`; the test never shells out to
//! cargo.

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use chio_chaos::{
    ack_line, chaos_iterations, chaos_receipt, chaos_seed, check_durable_acks,
    require_verified_acks, wait_until_healthy, ChaosError, ChaosRng,
};
use chio_store_sqlite::SqliteReceiptStore;
use chio_test_support::prelude::*;

/// Fixed seed used when `CHIO_CHAOS_SEED` is unset; printed on entry so a
/// failure reproduces.
const DEFAULT_SEED: u64 = 0xC10A_0515;

/// Default round count for the fast PR tier. The nightly lane raises
/// `CHIO_CHAOS_ITERATIONS`.
const DEFAULT_ITERATIONS: u64 = 5;

/// Victim loop bound, sized so the victim cannot drain it before the longest
/// seeded kill delay lands. Raising this is the fix if `InjectionNoOp` fires.
const MAX_RECEIPTS: u64 = 1_000_000;

/// SIGKILL signal number on Unix. `child.kill()` sends this; the reaped status
/// must carry it for a round to count as a genuine kill-while-alive.
const SIGKILL: i32 = 9;

/// SIGKILL the append/flush/ack victim mid-run, round after round against one
/// reused store, and prove that no acknowledged receipt is ever lost after
/// crash recovery.
#[test]
fn chaos_kill_mid_append_preserves_durable_acks() {
    let seed =
        chaos_seed(DEFAULT_SEED).test_expect("CHIO_CHAOS_SEED must be a u64 (decimal or 0x-hex)");
    eprintln!("chaos seed: {seed}");
    let rounds =
        chaos_iterations(DEFAULT_ITERATIONS).test_expect("CHIO_CHAOS_ITERATIONS must be a u64");
    let mut rng = ChaosRng::new(seed);

    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");
    let ack_path = dir.path().join("acks.log");

    let victim_bin = env!("CARGO_BIN_EXE_chaos_victim");

    let mut kills_while_alive: u64 = 0;
    let mut raced_exit: u64 = 0;
    let mut verified_acks_total: usize = 0;

    for round in 0..rounds {
        let mut child = Command::new(victim_bin)
            .arg(&db_path)
            .arg(&ack_path)
            .arg(MAX_RECEIPTS.to_string())
            // Round index as the id nonce: rounds reuse one store, and a
            // recycled OS pid would otherwise collide on the UNIQUE receipt_id.
            .arg(round.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .test_expect("spawn chaos victim");

        let delay_ms = rng.range(5, 400);
        std::thread::sleep(Duration::from_millis(delay_ms));

        // InjectionNoOp discipline: a victim that already finished on its own
        // was not fault-injected this round. Record the race; the aggregate
        // check below fails the test if EVERY round raced.
        match child.try_wait().test_expect("poll victim liveness") {
            Some(status) => {
                raced_exit += 1;
                eprintln!(
                    "round {round}: victim exited before kill (status {status:?}) after {delay_ms}ms"
                );
                // With MAX_RECEIPTS a clean drain before the kill is impossible, so
                // a benign race can only be a success exit. A non-zero exit is a
                // victim crash, not a race, and must fail the round.
                if !status.success() {
                    panic!(
                        "{}",
                        ChaosError::Victim(format!(
                            "round {round}: victim exited with failure status {status:?} before the kill; a pre-kill victim crash is a harness bug, not a race"
                        ))
                    );
                }
            }
            None => {
                child.kill().test_expect("SIGKILL victim");
                let status = child.wait().test_expect("reap victim");
                // kill() reports success even against a victim that exited on its
                // own in the window after try_wait returned None but before the
                // signal landed, so the reaped status is the real evidence. Only a
                // process the signal actually terminated is a genuine
                // kill-while-alive; a self-exit that raced the signal is the same
                // benign race as the try_wait Some arm. With MAX_RECEIPTS a clean
                // drain is impossible, so a non-signal exit is either a success
                // (benign race) or a victim crash that must fail the round.
                if status.signal() == Some(SIGKILL) {
                    kills_while_alive += 1;
                } else {
                    raced_exit += 1;
                    eprintln!(
                        "round {round}: victim self-exited (status {status:?}) racing the kill after {delay_ms}ms"
                    );
                    if !status.success() {
                        panic!(
                            "{}",
                            ChaosError::Victim(format!(
                                "round {round}: victim exited with failure status {status:?} racing the kill; a victim crash is a harness bug, not a race"
                            ))
                        );
                    }
                }
            }
        }

        verified_acks_total += assert_round_invariants(&db_path, &ack_path, round);
    }

    // If the fault never took effect in any round, the green result would be a
    // lie: nothing was crash-tested. Fail closed with a typed InjectionNoOp.
    if kills_while_alive == 0 {
        panic!(
            "{}",
            ChaosError::InjectionNoOp(
                "victim exited cleanly before the kill in every round; raise MAX_RECEIPTS"
            )
        );
    }

    // Non-vacuity: kills_while_alive only proves a signal landed. The run must
    // also have observed at least one acknowledged receipt survive recovery, or
    // it proved nothing about durability. Per-round tolerance is preserved (a
    // single round may kill before any ack); the guard bites on the run total.
    if let Err(error) = require_verified_acks(verified_acks_total) {
        panic!("{error}");
    }

    eprintln!(
        "chaos kill summary: {kills_while_alive} kills mid-append, {raced_exit} raced exits, \
         {verified_acks_total} durable acks verified over {rounds} rounds"
    );
}

/// Reopen the reused store after a kill and assert the four post-fault
/// invariants, returning the number of durable acks that verified this round (0
/// is legal for a single round that killed the victim before any ack). Each
/// failure is a typed [`ChaosError::InvariantViolated`] carrying the round and
/// the observed state.
fn assert_round_invariants(db_path: &Path, ack_path: &Path, round: u64) -> usize {
    // 1. Recovery never bricks the store.
    let store = match SqliteReceiptStore::open(db_path) {
        Ok(store) => store,
        Err(error) => panic!(
            "{}",
            ChaosError::InvariantViolated(format!(
                "round {round}: reopen after SIGKILL failed: {error}"
            ))
        ),
    };

    // 2. Health reports a verified, unpoisoned head (bounded: the writer seeds
    //    its head asynchronously, so a store sampled the instant after reopen can
    //    still be head-poisoned).
    if let Err(error) = wait_until_healthy(&store, &format!("round {round}")) {
        panic!("{error}");
    }

    // 3. No acknowledged receipt was lost.
    let verified = match check_durable_acks(&store, ack_path) {
        Ok(verified) => verified,
        Err(error) => panic!("round {round}: {error}"),
    };

    // 4. The recovered store still serves writes.
    let probe = chaos_receipt(&format!("recovery-probe-{round}"), 1)
        .test_expect("build recovery probe receipt");
    store
        .append_chio_receipt_returning_seq(&probe)
        .test_expect("append recovery probe receipt");
    store
        .flush_receipt_writes()
        .test_expect("flush recovery probe receipt");

    verified
}

/// The durable-ack checker must catch a fabricated acknowledgement for a receipt
/// the store never committed. This proves the crash test's assertion 3 is not
/// vacuous: a checker that always returned `Ok` would fail here.
#[test]
fn ack_checker_detects_fabricated_loss() {
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");
    let ack_path = dir.path().join("acks.log");

    let store = SqliteReceiptStore::open(&db_path).test_unwrap();

    // Commit a few real receipts and record honest acks for them.
    let mut honest = String::new();
    for i in 0..3u64 {
        let receipt = chaos_receipt(&format!("checker-{i}"), i + 1).test_unwrap();
        let seq = store
            .append_chio_receipt_returning_seq(&receipt)
            .test_unwrap();
        store.flush_receipt_writes().test_unwrap();
        honest.push_str(&ack_line(seq));
    }
    std::fs::write(&ack_path, &honest).test_unwrap();

    // Honest acks verify clean, and the checker counts every one it verified.
    let verified = check_durable_acks(&store, &ack_path).test_expect("honest acks must verify");
    assert_eq!(verified, 3, "three honest acks must each verify");

    // Fabricate an ack for a receipt beyond the committed floor and confirm the
    // checker reports the loss.
    let committed = store.latest_committed_entry_seq().test_unwrap();
    let fabricated = format!("{honest}{}", ack_line(committed + 10));
    let fabricated_path = dir.path().join("acks-fabricated.log");
    std::fs::write(&fabricated_path, fabricated).test_unwrap();

    let error = check_durable_acks(&store, &fabricated_path).test_unwrap_err();
    assert!(
        matches!(error, ChaosError::InvariantViolated(_)),
        "fabricated ack must be reported as InvariantViolated, got {error:?}"
    );

    // Second sabotage arm: a committed-but-lost receipt. The store keeps the
    // claim log append-only through a BEFORE DELETE trigger, so a committed
    // entry cannot vanish through SQL; a post-crash torn write or page loss
    // could still drop one physically. Reproduce that by dropping the guard
    // trigger and deleting a middle committed row behind the store's back. The
    // committed floor is unchanged, so a checker that stopped at the floor
    // comparison would still pass this ack file; only the per-ack read-back
    // catches the hole.
    let sabotage_seq = committed - 1;
    {
        let connection = rusqlite::Connection::open(&db_path).test_unwrap();
        connection
            .pragma_update(None, "busy_timeout", 5000)
            .test_unwrap();
        connection
            .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete")
            .test_unwrap();
        let deleted = connection
            .execute(
                "DELETE FROM claim_receipt_log_entries WHERE entry_seq = ?1",
                rusqlite::params![i64::try_from(sabotage_seq).test_expect("sabotage seq fits i64")],
            )
            .test_unwrap();
        assert_eq!(deleted, 1, "sabotage must delete exactly one committed row");
    }
    let error = check_durable_acks(&store, &ack_path).test_unwrap_err();
    match &error {
        ChaosError::InvariantViolated(message) => assert!(
            message.contains(&sabotage_seq.to_string()),
            "the violation must name the sabotaged entry_seq {sabotage_seq}, got: {message}"
        ),
        other => panic!("a committed-but-lost ack must be InvariantViolated, got {other:?}"),
    }
}
