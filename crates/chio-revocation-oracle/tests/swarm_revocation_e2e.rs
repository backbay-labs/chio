#![allow(clippy::expect_used, clippy::unwrap_used)]
//! 3-tier swarm acceptance test.
//!
//! Spins up a planner kernel, a coder kernel, and a tester kernel as
//! three independent oracle + view + receipt-log triples connected by
//! the federation revocation-gossip push path. The planner mints a
//! root capability `cap-planner`; coder and tester each carry a
//! capability whose delegation chain references `cap-planner`. While
//! coder and tester run a tight evaluation loop (the trust-boundary
//! "consult" call against their installed `RevocationView`), the
//! harness revokes `cap-planner` in the planner's oracle, gossips the
//! signed epoch root to both children, and measures the wall-clock
//! interval from revoke -> first deny on each child.
//!
//! The acceptance budget is 500 ms median across 100 trials, mirroring
//! the success criterion in `spec/PROTOCOL.md`.
//!
//! As a side-effect, the harness writes a structured JSONL receipt log
//! to a temp path. The companion receipt-chain-proof test builds its own
//! self-contained log and asserts that every allow receipt has
//! `seen_epoch < revoke_epoch`. The two tests share their on-disk schema
//! via `tests/common/mod.rs`.

#[path = "common/mod.rs"]
mod common;

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

use common::{ReceiptLog, ReceiptRecord};

/// Stable id of the root capability the planner mints. Coder and
/// tester carry this id as the only delegator in their delegation
/// chain; revoking it must propagate to both children.
const PLANNER_CAP_ID: &str = "cap-planner-root";

/// Number of acceptance trials. Matches the success criterion's sample
/// size: 500ms median across 100 trials.
const TRIALS: usize = 100;

/// Hard timeout per trial. If a child fails to observe the deny
/// inside this window, the trial is aborted and the test fails
/// fail-closed (we never silently treat a hang as 0ms).
const TRIAL_TIMEOUT_MS: u64 = 1500;

/// Median budget (ms) the success criterion calls out.
const MEDIAN_BUDGET_MS: u128 = 500;

/// Tight-loop sleep between consult attempts, in microseconds. Small
/// enough to capture a sub-millisecond observation but large enough
/// not to peg a CI core.
const CHILD_POLL_INTERVAL_US: u64 = 50;

/// One peer kernel running the consult tight loop.
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

    /// Models the kernel's fail-closed consult step on every dispatch.
    /// Returns `true` when `cap-planner` is revoked according to the
    /// installed snapshot. Mirrors
    /// `chio_kernel::kernel::delegation::consult_revocation_view`'s
    /// chain walk for a single ancestor link plus an optional leaf.
    fn planner_revoked(&self) -> bool {
        let snapshot = self.view.load();
        snapshot.is_revoked(&RevocationViewSubject::new(PLANNER_CAP_ID))
    }

    fn current_epoch(&self) -> u64 {
        self.view.current_epoch()
    }
}

/// Outcome of a single trial.
struct TrialOutcome {
    revoke_to_deny_ms: u128,
    revoke_epoch: u64,
}

/// Run a single revoke-to-deny trial.
///
/// `trial_idx` is incorporated into the planner cap's nonce so each
/// trial inserts a fresh leaf into the planner oracle (the in-memory
/// oracle rejects same-key re-insertion as `AlreadyRevoked`).
fn run_trial(trial_idx: u64, log: &ReceiptLog) -> Result<TrialOutcome, String> {
    let planner_oracle = Arc::new(Mutex::new(InMemoryRevocationOracle::new()));
    let signer = Ed25519RootSigner::from_signing_key(
        "planner-oracle",
        "0505050505050505050505050505050505050505050505050505050505050505",
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

    // Spawn a consult loop per child. Records a "deny" the first time
    // the installed RevocationView reports cap-planner as revoked.
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

    // Briefly let the children record allow receipts so the proof test
    // has a pre-revoke prefix to walk. Sub-millisecond suffices.
    thread::sleep(Duration::from_micros(200));

    // -- Revoke step ----------------------------------------------------
    // Planner inserts cap-planner into its oracle. The oracle returns
    // the new EpochRoot; sign it; push to the gossip queue; flush
    // batches into RevocationGossipBatch frames; install each frame's
    // SignedEpochRoot into the corresponding child view.
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

    // -- Wait for both children to deny ---------------------------------
    let timeout_at = trial_started + Duration::from_millis(TRIAL_TIMEOUT_MS);
    while Instant::now() < timeout_at {
        if coder_deny_ts_us.load(Ordering::Relaxed) != 0
            && tester_deny_ts_us.load(Ordering::Relaxed) != 0
        {
            break;
        }
        thread::sleep(Duration::from_micros(CHILD_POLL_INTERVAL_US));
    }

    // Stop loops regardless of whether we observed denies.
    abort.store(true, Ordering::Relaxed);
    let _ = coder_handle.join();
    let _ = tester_handle.join();

    let coder_deny = coder_deny_ts_us.load(Ordering::Relaxed);
    let tester_deny = tester_deny_ts_us.load(Ordering::Relaxed);

    if coder_deny == 0 || tester_deny == 0 {
        return Err(format!(
            "trial {trial_idx}: child failed to observe deny within {TRIAL_TIMEOUT_MS}ms (coder_deny_us={coder_deny}, tester_deny_us={tester_deny})"
        ));
    }

    // The acceptance metric is "revoke -> deny" measured from the
    // revoke step's wall-clock to the latest of the two child denies.
    let last_deny = coder_deny.max(tester_deny);
    let revoke_to_deny_ms = u128::from(last_deny.saturating_sub(revoke_ts_us)) / 1_000;

    // Sanity: both child views are at the new epoch.
    if coder.current_epoch() < new_root.epoch || tester.current_epoch() < new_root.epoch {
        return Err(format!(
            "trial {trial_idx}: child view did not advance to epoch {} (coder={}, tester={})",
            new_root.epoch,
            coder.current_epoch(),
            tester.current_epoch(),
        ));
    }

    Ok(TrialOutcome {
        revoke_to_deny_ms,
        revoke_epoch: new_root.epoch,
    })
}

/// Spawn the per-child consult tight loop. The thread records every
/// consult as a JSONL receipt: allow until the snapshot reports
/// cap-planner as revoked, then a single deny followed by exit.
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
        let snapshot_epoch = child.current_epoch();
        let revoked = child.planner_revoked();
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

/// Install a gossip frame into a child's RevocationView. The signed
/// root carries an `EpochRoot` whose `epoch` and `root_hash` we lift
/// into a fresh `RevocationSnapshot` containing the planner cap as
/// revoked. Mirrors what the kernel-core install path will do once a
/// production gossip frame arrives, the install is fail-closed when
/// `install_if_newer` rejects a non-monotone candidate.
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

fn elapsed_us(started: Instant) -> u64 {
    let elapsed = started.elapsed();
    let micros = elapsed.as_micros();
    if micros > u128::from(u64::MAX) {
        u64::MAX
    } else {
        micros as u64
    }
}

#[test]
fn three_tier_swarm_revoke_to_deny_under_500ms_median() {
    // Receipt log lives in the temp dir so the sibling proof test can walk it.
    let log_path = std::env::temp_dir().join("chio-revocation-e2e-receipt-log.jsonl");
    let log = ReceiptLog::create(&log_path).expect("open receipt log");

    log.write_header(TRIALS, MEDIAN_BUDGET_MS as u64);

    let mut measurements = Vec::with_capacity(TRIALS);
    for idx in 0..TRIALS {
        match run_trial(idx as u64, &log) {
            Ok(outcome) => {
                log.write_trial_summary(
                    idx as u64,
                    outcome.revoke_epoch,
                    outcome.revoke_to_deny_ms,
                );
                measurements.push(outcome.revoke_to_deny_ms);
            }
            Err(msg) => panic!("{msg}"),
        }
    }

    measurements.sort_unstable();
    let median = measurements[TRIALS / 2];
    log.write_footer(median, MEDIAN_BUDGET_MS);

    eprintln!(
        "revoke->deny min={} ms, median={} ms, max={} ms across {} trials",
        measurements.first().copied().unwrap_or(0),
        median,
        measurements.last().copied().unwrap_or(0),
        TRIALS,
    );

    assert!(
        median < MEDIAN_BUDGET_MS,
        "median revoke->deny {median}ms exceeds {MEDIAN_BUDGET_MS}ms budget across {TRIALS} trials"
    );
}
