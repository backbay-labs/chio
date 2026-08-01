//! Real SIGTERM-drain chaos test for the SQLite receipt store.
//!
//! This reuses the crash victim (`chaos_victim`), which appends a receipt,
//! flushes the store as a durability barrier, and only then records an
//! `ack <seq>` line for the receipt the store just promised was durable.
//! Instead of SIGKILL, the parent sends SIGTERM (`kill -TERM`) mid-loop, round
//! after round against one reused store, then reopens and proves that no
//! acknowledged receipt was ever lost.
//!
//! Victim SIGTERM contract: default-termination. The victim installs no signal
//! handler; SIGTERM's default disposition terminates the process at an arbitrary
//! point, exactly like SIGKILL. Because the ack line is written and fsync'd only
//! after a successful store flush, the durable-ack invariant already holds no
//! matter where the process dies, so no handler (and no `signal-hook`/`unsafe`
//! dependency) is required. The assertion is therefore exit-by-signal within a
//! bounded window plus a passing [`check_durable_acks`], not a clean exit code.

#![cfg(all(unix, feature = "chaos-victim"))]
#![forbid(unsafe_code)]

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use chio_chaos::{
    chaos_iterations, chaos_receipt, chaos_seed, check_durable_acks, require_verified_acks,
    wait_until_healthy, ChaosError, ChaosRng,
};
use chio_store_sqlite::SqliteReceiptStore;
use chio_test_support::prelude::*;

/// SIGTERM signal number on Unix.
const SIGTERM: i32 = 15;

/// Fixed seed used when `CHIO_CHAOS_SEED` is unset; printed on entry so a
/// failure reproduces.
const DEFAULT_SEED: u64 = 0x516E_D0A0;

/// Default round count for the fast PR tier. The nightly lane raises
/// `CHIO_CHAOS_ITERATIONS`.
const DEFAULT_ITERATIONS: u64 = 5;

/// Victim loop bound, sized so the victim cannot drain it before the longest
/// seeded pre-signal delay lands. Raising this is the fix if `InjectionNoOp`
/// fires.
const MAX_RECEIPTS: u64 = 1_000_000;

/// Bound on how long the victim may take to terminate after SIGTERM. Default
/// termination is effectively immediate; a victim still alive after this is a
/// control failure, not a durability outcome.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll the child to exit within `timeout`, reaping it. Returns `None` if it is
/// still running when the bound elapses.
fn wait_for_exit_within(child: &mut std::process::Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().test_expect("poll victim exit") {
            Some(status) => return Some(status),
            None => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Send SIGTERM to the append/flush/ack victim mid-run, round after round
/// against one reused store, and prove that no acknowledged receipt is ever lost
/// after the victim terminates.
#[test]
fn chaos_sigterm_drain_loses_no_durable_acks() {
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

    let mut terminated_by_signal: u64 = 0;
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

        // InjectionNoOp discipline: a victim that already finished on its own was
        // not fault-injected this round. The aggregate check below fails the test
        // if NO round terminated by signal.
        if let Some(status) = child.try_wait().test_expect("poll victim liveness") {
            raced_exit += 1;
            eprintln!(
                "round {round}: victim exited before SIGTERM (status {status:?}) after {delay_ms}ms"
            );
            // With MAX_RECEIPTS a clean drain before the signal is impossible, so a
            // benign race can only be a success exit. A non-zero exit is a victim
            // crash and must fail the round.
            if !status.success() {
                panic!(
                    "{}",
                    ChaosError::Victim(format!(
                        "round {round}: victim exited with failure status {status:?} before SIGTERM; a pre-signal victim crash is a harness bug, not a race"
                    ))
                );
            }
            verified_acks_total += assert_round_invariants(&db_path, &ack_path, round);
            continue;
        }

        // Send SIGTERM via std-only means; no signal-hook dependency. A failed
        // delivery must fail the round here, not surface 30s later as a
        // misattributed "victim still alive" timeout.
        let pid = child.id();
        let kill_status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .test_expect("send SIGTERM to victim");
        if !kill_status.success() {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{}",
                ChaosError::Victim(format!(
                    "round {round}: kill -TERM {pid} exited with {kill_status:?}; signal delivery failed"
                ))
            );
        }

        let status = match wait_for_exit_within(&mut child, EXIT_TIMEOUT) {
            Some(status) => status,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{}",
                    ChaosError::Victim(format!(
                        "round {round}: victim still alive {EXIT_TIMEOUT:?} after SIGTERM"
                    ))
                );
            }
        };

        // The victim provides the default-termination contract: SIGTERM must have
        // terminated it by signal. A natural exit here means the victim raced to
        // completion between the liveness poll and the signal.
        if status.signal() == Some(SIGTERM) {
            terminated_by_signal += 1;
        } else {
            raced_exit += 1;
            eprintln!(
                "round {round}: victim exited (status {status:?}) rather than by SIGTERM after {delay_ms}ms"
            );
            // The victim raced to a natural exit instead of being terminated by
            // SIGTERM. With MAX_RECEIPTS it cannot have drained cleanly, so a
            // non-zero exit (a crash, or termination by some other signal) is a
            // victim failure and must fail the round.
            if !status.success() {
                panic!(
                    "{}",
                    ChaosError::Victim(format!(
                        "round {round}: victim exited with failure status {status:?} rather than by SIGTERM; a victim crash is a harness bug, not a race"
                    ))
                );
            }
        }

        verified_acks_total += assert_round_invariants(&db_path, &ack_path, round);
    }

    // If SIGTERM never actually terminated the victim in any round, the green
    // result would be a lie: nothing was drain-tested. Fail closed.
    if terminated_by_signal == 0 {
        panic!(
            "{}",
            ChaosError::InjectionNoOp(
                "victim exited on its own before SIGTERM in every round; raise MAX_RECEIPTS"
            )
        );
    }

    // Non-vacuity: terminated_by_signal only proves a signal landed. The run must
    // also have observed at least one acknowledged receipt survive recovery, or
    // it proved nothing about durability. Per-round tolerance is preserved; the
    // guard bites on the run total.
    if let Err(error) = require_verified_acks(verified_acks_total) {
        panic!("{error}");
    }

    eprintln!(
        "chaos sigterm summary: {terminated_by_signal} terminated by SIGTERM, {raced_exit} raced exits, \
         {verified_acks_total} durable acks verified over {rounds} rounds"
    );
}

/// Reopen the reused store after a termination and assert the post-fault
/// invariants: recovery never bricks the store, health reports a verified head,
/// no acknowledged receipt was lost, and the recovered store still serves
/// writes. Returns the number of durable acks that verified this round (0 is
/// legal for a single round that terminated the victim before any ack). Each
/// failure is a typed [`ChaosError`] carrying the round.
fn assert_round_invariants(db_path: &Path, ack_path: &Path, round: u64) -> usize {
    let store = match SqliteReceiptStore::open(db_path) {
        Ok(store) => store,
        Err(error) => panic!(
            "{}",
            ChaosError::InvariantViolated(format!(
                "round {round}: reopen after SIGTERM failed: {error}"
            ))
        ),
    };

    if let Err(error) = wait_until_healthy(&store, &format!("round {round}")) {
        panic!("{error}");
    }

    let verified = match check_durable_acks(&store, ack_path) {
        Ok(verified) => verified,
        Err(error) => panic!("round {round}: {error}"),
    };

    let probe = chaos_receipt(&format!("sigterm-recovery-probe-{round}"), 1)
        .test_expect("build recovery probe receipt");
    store
        .append_chio_receipt_returning_seq(&probe)
        .test_expect("append recovery probe receipt");
    store
        .flush_receipt_writes()
        .test_expect("flush recovery probe receipt");

    verified
}
