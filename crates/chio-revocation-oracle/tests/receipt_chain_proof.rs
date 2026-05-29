#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Receipt-chain proof.
//!
//! After the swarm test writes its JSONL receipt log, walk the
//! log and assert the `NoAllowAfterRevoke` invariant
//! on the real receipts: every allow receipt issued for a given trial
//! has `seen_epoch < revoke_epoch`, and no allow receipt has
//! `seen_epoch >= revoke_epoch`. Deny receipts are required to carry
//! `seen_epoch >= revoke_epoch`.
//!
//! The test runs the swarm fixture in-process and writes to a
//! per-test-run temp file so two parallel `cargo test` invocations
//! cannot race on a shared path.

#[path = "common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chio_federation::{RevocationGossipPushQueue, RevocationRootGossip};
use chio_kernel_core::{RevocationSnapshot, RevocationView, RevocationViewSubject};
use chio_revocation_oracle::{
    Ed25519RootSigner, EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle,
    SignedEpochRoot, SubjectId,
};

use common::{read_log, ReceiptLog, ReceiptRecord};

const PLANNER_CAP_ID: &str = "cap-planner-root";
const TRIALS: usize = 8;
const TRIAL_TIMEOUT_MS: u64 = 1500;
const CHILD_POLL_INTERVAL_US: u64 = 50;

struct ChildKernel {
    name: &'static str,
    view: Arc<RevocationView>,
}

impl ChildKernel {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            view: Arc::new(RevocationView::new()),
        }
    }

    fn planner_snapshot(&self) -> (u64, bool) {
        let snapshot = self.view.load();
        (
            snapshot.epoch,
            snapshot.is_revoked(&RevocationViewSubject::new(PLANNER_CAP_ID)),
        )
    }

    fn current_epoch(&self) -> u64 {
        self.view.current_epoch()
    }
}

fn elapsed_us(started: Instant) -> u64 {
    let elapsed = started.elapsed();
    let micros = elapsed.as_micros();
    if micros > u128::from(u64::MAX) {
        u64::MAX
    } else {
        micros as u64
    }
}

fn install_frame(child: &Arc<ChildKernel>, frame: &RevocationRootGossip) -> Result<(), String> {
    let mut revoked = std::collections::BTreeSet::new();
    revoked.insert(RevocationViewSubject::new(PLANNER_CAP_ID));
    let snapshot = RevocationSnapshot {
        epoch: frame.signed_root.root.epoch,
        root_hash: frame.signed_root.root.root_hash,
        issued_at_unix_ms: frame.signed_root.root.issued_at_unix_ms,
        revoked,
    };
    child
        .view
        .install_if_newer(snapshot)
        .map(|_| ())
        .map_err(|err| format!("install_if_newer: {err}"))
}

fn run_trial(trial_idx: u64, log: &ReceiptLog) -> Result<u64, String> {
    let planner_oracle = Arc::new(Mutex::new(InMemoryRevocationOracle::new()));
    let signer = Ed25519RootSigner::from_signing_key(
        "planner-oracle",
        "0606060606060606060606060606060606060606060606060606060606060606",
    )
    .expect("fixed seed is valid Ed25519 material");

    let push_queue =
        RevocationGossipPushQueue::new(8).map_err(|err| format!("push-queue init: {err:?}"))?;
    push_queue
        .subscribe("coder-kernel")
        .map_err(|err| format!("coder subscribe: {err:?}"))?;
    push_queue
        .subscribe("tester-kernel")
        .map_err(|err| format!("tester subscribe: {err:?}"))?;

    let coder = Arc::new(ChildKernel::new("coder"));
    let tester = Arc::new(ChildKernel::new("tester"));

    let abort = Arc::new(AtomicBool::new(false));
    let coder_deny_ts_us = Arc::new(AtomicU64::new(0));
    let tester_deny_ts_us = Arc::new(AtomicU64::new(0));
    let coder_seen_epoch = Arc::new(AtomicU64::new(0));
    let tester_seen_epoch = Arc::new(AtomicU64::new(0));

    let trial_started = Instant::now();

    let coder_handle = spawn_consult_loop(
        Arc::clone(&coder),
        Arc::clone(&abort),
        Arc::clone(&coder_deny_ts_us),
        Arc::clone(&coder_seen_epoch),
        trial_started,
        log.clone_writer(),
        "coder-cap",
    );
    let tester_handle = spawn_consult_loop(
        Arc::clone(&tester),
        Arc::clone(&abort),
        Arc::clone(&tester_deny_ts_us),
        Arc::clone(&tester_seen_epoch),
        trial_started,
        log.clone_writer(),
        "tester-cap",
    );

    thread::sleep(Duration::from_micros(200));

    let revoke_ts_us = elapsed_us(trial_started);
    let revoke_key = RevocationKey::new(
        SubjectId::from(PLANNER_CAP_ID),
        EpochNonce::new(trial_idx.saturating_add(1)),
    );
    let new_root = {
        let mut guard = planner_oracle
            .lock()
            .map_err(|err| format!("planner oracle lock: {err}"))?;
        guard
            .insert(revoke_key, revoke_ts_us / 1_000)
            .map_err(|err| format!("oracle insert: {err:?}"))?
    };
    let signed =
        SignedEpochRoot::sign(new_root.clone(), &signer).map_err(|err| format!("sign: {err:?}"))?;

    push_queue
        .enqueue_signed_root(signed.clone())
        .map_err(|err| format!("enqueue: {err:?}"))?;

    let now_unix_ms = revoke_ts_us / 1_000;
    let batches = push_queue
        .flush_batches_at(now_unix_ms)
        .map_err(|err| format!("flush: {err:?}"))?;

    for batch in batches {
        let target = match batch.recipient_kernel_id.as_str() {
            "coder-kernel" => Arc::clone(&coder),
            "tester-kernel" => Arc::clone(&tester),
            other => return Err(format!("unexpected recipient: {other}")),
        };
        for frame in &batch.frames {
            install_frame(&target, frame)?;
        }
    }

    let timeout_at = trial_started + Duration::from_millis(TRIAL_TIMEOUT_MS);
    while Instant::now() < timeout_at {
        if coder_deny_ts_us.load(Ordering::Relaxed) != 0
            && tester_deny_ts_us.load(Ordering::Relaxed) != 0
        {
            break;
        }
        thread::sleep(Duration::from_micros(CHILD_POLL_INTERVAL_US));
    }

    abort.store(true, Ordering::Relaxed);
    let _ = coder_handle.join();
    let _ = tester_handle.join();

    if coder_deny_ts_us.load(Ordering::Relaxed) == 0
        || tester_deny_ts_us.load(Ordering::Relaxed) == 0
    {
        return Err(format!(
            "trial {trial_idx}: child failed to observe deny within {TRIAL_TIMEOUT_MS}ms"
        ));
    }
    if coder.current_epoch() < new_root.epoch || tester.current_epoch() < new_root.epoch {
        return Err(format!(
            "trial {trial_idx}: child view did not advance to epoch {}",
            new_root.epoch,
        ));
    }

    Ok(new_root.epoch)
}

fn spawn_consult_loop(
    child: Arc<ChildKernel>,
    abort: Arc<AtomicBool>,
    deny_ts_us: Arc<AtomicU64>,
    seen_epoch: Arc<AtomicU64>,
    trial_started: Instant,
    log_writer: Arc<Mutex<std::fs::File>>,
    cap_id: &'static str,
) -> thread::JoinHandle<()> {
    let kernel_name = child.name;
    thread::spawn(move || loop {
        if abort.load(Ordering::Relaxed) {
            return;
        }
        let ts_us = elapsed_us(trial_started);
        let (snapshot_epoch, revoked) = child.planner_snapshot();
        let record = ReceiptRecord {
            kernel_id: kernel_name.to_string(),
            cap_id: cap_id.to_string(),
            ts_unix_us: ts_us,
            seen_epoch: snapshot_epoch,
            decision: if revoked { "deny" } else { "allow" }.to_string(),
        };
        common::write_record(&log_writer, &record);
        if revoked {
            deny_ts_us.store(ts_us, Ordering::Relaxed);
            seen_epoch.store(snapshot_epoch, Ordering::Relaxed);
            return;
        }
        thread::sleep(Duration::from_micros(CHILD_POLL_INTERVAL_US));
    })
}

#[test]
fn no_allow_receipt_after_revoke_epoch() {
    // A per-pid temp path keeps parallel `cargo test` invocations from
    // racing on a shared log file.
    let log_path: PathBuf = std::env::temp_dir().join(format!(
        "chio-revocation-chain-{}.jsonl",
        std::process::id()
    ));
    let log = ReceiptLog::create(&log_path).expect("open receipt log");
    log.write_header(TRIALS, 500);

    for idx in 0..TRIALS {
        match run_trial(idx as u64, &log) {
            Ok(revoke_epoch) => {
                log.write_trial_summary(idx as u64, revoke_epoch, 0);
            }
            Err(msg) => panic!("{msg}"),
        }
    }
    log.write_footer(0, 500);

    let readback = read_log(&log_path).expect("read receipt log");

    // Per-trial book-keeping: associate every receipt to its trial via
    // the revoke_epoch advertised by the trial summary. Because the
    // planner oracle is fresh per trial, the seen_epoch on a receipt
    // is monotone-non-decreasing within the trial: 0 (or N-1 leftover
    // from a prior trial - but each trial spins up its own view, so
    // the floor is 0 here) up until the revoke installs, then exactly
    // revoke_epoch.

    // Schema sanity: we wrote one summary per trial.
    assert_eq!(
        readback.trials.len(),
        TRIALS,
        "expected {TRIALS} trial summaries, got {}",
        readback.trials.len(),
    );

    // The summary order matches the run order, so split the receipt
    // stream by trial via the revoke_epoch monotonicity gate. The
    // writer and reader share the same view-per-trial design, so
    // every consult's seen_epoch is either 0 (pre-revoke) or the
    // current trial's revoke_epoch (post-revoke).
    let mut allow_count = 0_usize;
    let mut deny_count = 0_usize;
    let mut allow_seen_epochs: Vec<u64> = Vec::new();
    let mut deny_seen_epochs: Vec<u64> = Vec::new();

    for record in &readback.records {
        match record.decision.as_str() {
            "allow" => {
                allow_count += 1;
                allow_seen_epochs.push(record.seen_epoch);
            }
            "deny" => {
                deny_count += 1;
                deny_seen_epochs.push(record.seen_epoch);
            }
            other => panic!("unexpected decision in receipt: {other}"),
        }
    }

    // Core invariant: every allow receipt has seen_epoch < every
    // revoke_epoch produced by the test run. Equivalently:
    // allow_seen_epoch == 0 (the empty-sentinel snapshot held before
    // the trial's revoke installed). No allow may carry an epoch
    // greater than or equal to ANY revoke_epoch.
    let min_revoke_epoch = readback
        .trials
        .iter()
        .map(|t| t.revoke_epoch)
        .min()
        .unwrap_or(0);
    assert!(
        min_revoke_epoch >= 1,
        "trials should have revoke_epoch >= 1"
    );

    for seen in &allow_seen_epochs {
        assert!(
            *seen < min_revoke_epoch,
            "ALLOW receipt seen_epoch {seen} >= min revoke_epoch {min_revoke_epoch}: NoAllowAfterRevoke violated"
        );
    }

    // Sanity on the deny side: every deny carries seen_epoch >= 1
    // (because the snapshot install advanced the view past the empty
    // sentinel). Any deny with seen_epoch == 0 indicates a fail-open
    // path where the cap got marked revoked without epoch advancement.
    for seen in &deny_seen_epochs {
        assert!(
            *seen >= 1,
            "DENY receipt seen_epoch must be >= 1; got {seen}"
        );
    }

    // We expect both children to fire at least one allow and exactly
    // one deny per trial. Allow count >= 2 * trials is a soft floor
    // (each child's pre-revoke window contains at least one consult);
    // exact deny count is 2 * trials.
    assert!(
        allow_count >= 2 * TRIALS,
        "expected at least {} allow receipts, got {allow_count}",
        2 * TRIALS,
    );
    assert_eq!(
        deny_count,
        2 * TRIALS,
        "expected exactly {} deny receipts (one per child per trial), got {deny_count}",
        2 * TRIALS,
    );

    eprintln!(
        "receipt-chain proof OK across {TRIALS} trials: {allow_count} allow / {deny_count} deny receipts; min_revoke_epoch={min_revoke_epoch}; all allow seen_epoch < min_revoke_epoch."
    );
}
