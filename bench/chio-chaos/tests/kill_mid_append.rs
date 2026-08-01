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

#![cfg(all(unix, feature = "chaos-victim"))]

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// Victim loop bound. The feature-gated store hook pauses a seeded batch while
/// its SQLite `BEGIN IMMEDIATE` transaction is open, so the process cannot drain
/// this loop before the parent kills it.
const MAX_RECEIPTS: u64 = 1_000_000;

/// Bound startup and store-open time before an absent in-transaction marker is
/// treated as a broken injection lane.
const APPEND_READY_TIMEOUT: Duration = Duration::from_secs(20);

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
    let mut verified_acks_total: usize = 0;

    for round in 0..rounds {
        let ready_path = dir.path().join(format!("append-ready-{round}"));
        let release_path = dir.path().join(format!("append-release-{round}"));
        // Pause after several successful batches so the durable-ack recovery
        // assertion is non-vacuous. The nightly seed explores a different batch
        // and a different in-transaction dwell on every run.
        let pause_batch = rng.range(2, 64);
        let mut child = Command::new(victim_bin)
            .arg(&db_path)
            .arg(&ack_path)
            .arg(MAX_RECEIPTS.to_string())
            // Round index as the id nonce: rounds reuse one store, and a
            // recycled OS pid would otherwise collide on the UNIQUE receipt_id.
            .arg(round.to_string())
            .env("CHIO_CHAOS_APPEND_READY_PATH", &ready_path)
            .env("CHIO_CHAOS_APPEND_RELEASE_PATH", &release_path)
            .env("CHIO_CHAOS_APPEND_PAUSE_BATCH", pause_batch.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .test_expect("spawn chaos victim");

        wait_for_inflight_append(&mut child, &ready_path, round)
            .unwrap_or_else(|error| panic!("{error}"));
        let delay_ms = rng.range(5, 50);
        std::thread::sleep(Duration::from_millis(delay_ms));

        if let Some(status) = child.try_wait().test_expect("poll paused victim liveness") {
            panic!(
                "{}",
                ChaosError::Victim(format!(
                    "round {round}: victim exited with status {status:?} after publishing the in-transaction marker"
                ))
            );
        }
        child.kill().test_expect("SIGKILL in-flight append victim");
        let status = child.wait().test_expect("reap in-flight append victim");
        if status.signal() != Some(SIGKILL) {
            panic!(
                "{}",
                ChaosError::InvariantViolated(format!(
                    "round {round}: expected SIGKILL while append transaction was paused, got {status:?}"
                ))
            );
        }
        kills_while_alive += 1;

        verified_acks_total += assert_round_invariants(&db_path, &ack_path, round);
    }

    // If the fault never took effect in any round, the green result would be a
    // lie: nothing was crash-tested. Fail closed with a typed InjectionNoOp.
    if kills_while_alive == 0 {
        panic!(
            "{}",
            ChaosError::InjectionNoOp(
                "the in-transaction append hook never produced a SIGKILL round"
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
        "chaos kill summary: {kills_while_alive} proven in-transaction kills, \
         {verified_acks_total} durable acks verified over {rounds} rounds"
    );
}

/// Wait until the victim has written a receipt inside its transaction and
/// published the feature-gated pre-commit marker. A process exit, marker I/O
/// failure, or timeout is a failed injection, never a benign race.
fn wait_for_inflight_append(
    child: &mut std::process::Child,
    ready_path: &Path,
    round: u64,
) -> Result<(), ChaosError> {
    let deadline = Instant::now() + APPEND_READY_TIMEOUT;
    loop {
        match std::fs::metadata(ready_path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ChaosError::Boot(format!(
                    "round {round}: inspect in-transaction marker {}: {error}",
                    ready_path.display()
                )))
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ChaosError::Victim(format!("round {round}: poll victim: {error}")))?
        {
            return Err(ChaosError::Victim(format!(
                "round {round}: victim exited with status {status:?} before proving an in-flight append"
            )));
        }
        if Instant::now() >= deadline {
            return Err(ChaosError::InjectionNoOp(
                "victim never published the in-transaction append marker",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
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
