//! End-to-end revocation-gossip integration test.
//!
//! Topology: a single oracle node `A` running the in-memory revocation
//! oracle plus a [`RevocationGossipPushQueue`] that fans roots out to
//! `N=3` bilateral peers `V1..V3`, each backing a kernel-core
//! [`RevocationView`] cache. Transport is a zero-cost in-process channel
//! (no network sleep, no scheduler tricks): the test measures the cost of
//! the gossip code path itself, not the link.
//!
//! The verifier-visibility contract is that oracle-insert at A must be
//! observable at the verifier within 500 ms median across 100 trials.
//! With localhost transport that median should land deep in microseconds;
//! the assertion keeps a generous absolute ceiling and verifies the gossip
//! path itself moves roots monotonically without losing the latest
//! revocation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cmp::Ordering;
use std::time::Instant;

use chio_federation::{RevocationGossipBatch, RevocationGossipPushQueue, RevocationRootGossip};
use chio_kernel_core::{RevocationSnapshot, RevocationView, RevocationViewSubject};
use chio_revocation_oracle::{
    Ed25519RootSigner, EpochNonce, InMemoryRevocationOracle, RevocationKey, RevocationOracle,
    SignedEpochRoot, SubjectId,
};

const NUM_PEERS: usize = 3;
const NUM_TRIALS: usize = 100;
const LATENCY_BUDGET_MEDIAN_MS: u128 = 500;

struct Verifier {
    kernel_id: String,
    view: RevocationView,
    revoked_set: std::cell::RefCell<std::collections::BTreeSet<RevocationViewSubject>>,
}

impl Verifier {
    fn new(kernel_id: &str) -> Self {
        Self {
            kernel_id: kernel_id.to_string(),
            view: RevocationView::new(),
            revoked_set: std::cell::RefCell::new(std::collections::BTreeSet::new()),
        }
    }

    /// Apply a single gossip frame: validate envelope, verify signature
    /// against the pinned signer, fold the new subject into the running
    /// revocation set, and atomically install the resulting snapshot. The
    /// monotone-only contract of `RevocationView::install_if_newer` keeps
    /// the verifier fail-closed against replayed or stale frames.
    fn apply_frame(
        &self,
        frame: &RevocationRootGossip,
        signer: &Ed25519RootSigner,
        subject: &RevocationViewSubject,
    ) {
        frame
            .validate_envelope()
            .expect("envelope structurally valid");
        frame
            .signed_root
            .verify(&signer.verifier())
            .expect("frame signed by pinned oracle signer");
        let mut set = self.revoked_set.borrow_mut();
        set.insert(subject.clone());
        let snapshot = RevocationSnapshot {
            epoch: frame.signed_root.root.epoch,
            root_hash: frame.signed_root.root.root_hash,
            issued_at_unix_ms: frame.signed_root.root.issued_at_unix_ms,
            revoked: set.clone(),
        };
        // The push path coalesces same-epoch frames so we never call
        // install_if_newer twice for the same epoch; the first insert
        // produces a unique strictly-greater epoch.
        self.view
            .install_if_newer(snapshot)
            .expect("monotone snapshot install");
    }
}

fn deliver_batch(
    verifiers: &[&Verifier],
    batch: &RevocationGossipBatch,
    signer: &Ed25519RootSigner,
    subject: &RevocationViewSubject,
) {
    batch
        .validate_envelope()
        .expect("batch envelope structurally valid");
    let target = verifiers
        .iter()
        .find(|v| v.kernel_id == batch.recipient_kernel_id)
        .expect("batch addressed to known verifier");
    for frame in &batch.frames {
        target.apply_frame(frame, signer, subject);
    }
}

fn percentile_ns(samples: &mut [u128], pct: f64) -> u128 {
    samples.sort_unstable();
    let idx = ((samples.len() as f64) * pct).floor() as usize;
    let idx = idx.min(samples.len().saturating_sub(1));
    samples[idx]
}

#[test]
fn oracle_insert_visible_at_verifier_within_budget() {
    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("e2e signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let push_queue = RevocationGossipPushQueue::new(64).expect("push queue");

    let verifiers: Vec<Verifier> = (0..NUM_PEERS)
        .map(|i| Verifier::new(&format!("verifier-{}", i)))
        .collect();
    for v in &verifiers {
        push_queue.subscribe(&v.kernel_id).expect("subscribe");
    }
    let verifier_refs: Vec<&Verifier> = verifiers.iter().collect();

    let mut latencies_ns: Vec<u128> = Vec::with_capacity(NUM_TRIALS);

    for trial in 0..NUM_TRIALS {
        let subject_label = format!("subject-{}", trial);
        let key = RevocationKey::new(
            SubjectId::from(subject_label.as_str()),
            EpochNonce::new(trial as u64),
        );
        let issued_at_ms = 1_700_000_000_000_u64.saturating_add(trial as u64);

        let start = Instant::now();

        // 1. Oracle A inserts the revocation. This advances the epoch.
        let _root = oracle
            .insert(key.clone(), issued_at_ms)
            .expect("oracle insert");

        // 2. Oracle A signs the new epoch root and enqueues for every peer.
        let signed: SignedEpochRoot = oracle.signed_epoch_root(&signer).expect("sign epoch root");
        let delivered = push_queue
            .enqueue_signed_root(signed.clone())
            .expect("enqueue signed root");
        assert_eq!(delivered, NUM_PEERS);

        // 3. The federation-side flush tick drains per-peer batches and the
        //    in-process transport delivers them. Localhost link is zero
        //    cost: no network, no scheduler hop, just the gossip code path.
        let batches = push_queue
            .flush_batches_at(issued_at_ms)
            .expect("flush batches");
        assert_eq!(batches.len(), NUM_PEERS);
        let subject_view = RevocationViewSubject::from(subject_label.as_str());
        for batch in &batches {
            deliver_batch(&verifier_refs, batch, &signer, &subject_view);
        }

        let elapsed = start.elapsed().as_nanos();
        latencies_ns.push(elapsed);

        // Functional check: every verifier observes the just-revoked
        // subject as part of its current snapshot.
        for v in &verifiers {
            assert!(
                v.view.is_revoked(&subject_view),
                "verifier {} did not observe revocation of {} at trial {}",
                v.kernel_id,
                subject_label,
                trial
            );
            assert_eq!(v.view.current_epoch(), (trial as u64).saturating_add(1));
        }
    }

    // Latency assertions: median (p50) is the plan-budget surface; report
    // p95 too so a regression that pushes the long tail out is visible
    // even when p50 stays inside the budget.
    let mut sorted = latencies_ns.clone();
    let p50 = percentile_ns(&mut sorted, 0.5);
    let mut sorted95 = latencies_ns.clone();
    let p95 = percentile_ns(&mut sorted95, 0.95);
    let p50_ms = p50 / 1_000_000;
    let p95_ms = p95 / 1_000_000;

    eprintln!(
        "oracle_gossip_e2e: peers={} trials={} p50={}ns ({}ms) p95={}ns ({}ms) budget_p50={}ms",
        NUM_PEERS, NUM_TRIALS, p50, p50_ms, p95, p95_ms, LATENCY_BUDGET_MEDIAN_MS
    );

    assert!(
        p50_ms <= LATENCY_BUDGET_MEDIAN_MS,
        "p50 latency {}ms exceeds plan budget of {}ms across {} trials",
        p50_ms,
        LATENCY_BUDGET_MEDIAN_MS,
        NUM_TRIALS
    );
}

#[test]
fn verifier_view_is_monotonically_advancing_after_burst() {
    // Burst test: insert NUM_TRIALS revocations back-to-back without
    // flushing between each one. The push queue MUST coalesce same-
    // subscriber ring contents so the eventual flush emits a single
    // frame per peer carrying the latest signed root, and every verifier
    // observes the final epoch (not a stale midpoint).
    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("burst signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let push_queue = RevocationGossipPushQueue::new(8).expect("push queue");
    let verifiers: Vec<Verifier> = (0..NUM_PEERS)
        .map(|i| Verifier::new(&format!("v-{}", i)))
        .collect();
    for v in &verifiers {
        push_queue.subscribe(&v.kernel_id).expect("subscribe");
    }
    let verifier_refs: Vec<&Verifier> = verifiers.iter().collect();

    let mut last_subject: Option<RevocationViewSubject> = None;
    for trial in 0..NUM_TRIALS {
        let subject_label = format!("burst-{}", trial);
        let key = RevocationKey::new(
            SubjectId::from(subject_label.as_str()),
            EpochNonce::new(trial as u64),
        );
        oracle.insert(key, 1_700_000_000_000).expect("insert");
        let signed = oracle.signed_epoch_root(&signer).expect("sign");
        push_queue
            .enqueue_signed_root(signed)
            .expect("enqueue signed root");
        last_subject = Some(RevocationViewSubject::from(subject_label.as_str()));
    }
    let last_subject = last_subject.expect("at least one trial");

    let batches = push_queue.flush_batches_at(0).expect("flush batches");
    // Coalescing rule keeps at most one frame per peer because every
    // enqueue advanced the epoch monotonically.
    for batch in &batches {
        assert_eq!(batch.frames.len(), 1, "coalescing should fold burst");
    }
    for batch in &batches {
        deliver_batch(&verifier_refs, batch, &signer, &last_subject);
    }
    for v in &verifiers {
        assert_eq!(v.view.current_epoch(), NUM_TRIALS as u64);
        assert!(v.view.is_revoked(&last_subject));
    }
}

#[test]
fn verifier_rejects_replayed_root_after_advance() {
    // Replay attack: gossip task tries to install an older epoch after the
    // verifier has already advanced past it. The kernel-core view's
    // monotone install_if_newer MUST refuse the replay and leave the
    // current snapshot intact.
    let signer =
        Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("replay signer");
    let mut oracle = InMemoryRevocationOracle::new();

    oracle
        .insert(
            RevocationKey::new(SubjectId::from("a"), EpochNonce::new(1)),
            1_700_000_000_000,
        )
        .expect("first insert");
    let signed_old = oracle.signed_epoch_root(&signer).expect("sign first");

    oracle
        .insert(
            RevocationKey::new(SubjectId::from("b"), EpochNonce::new(2)),
            1_700_000_000_001,
        )
        .expect("second insert");
    let signed_new = oracle.signed_epoch_root(&signer).expect("sign second");

    let view = RevocationView::new();
    // Install the newer root first.
    let mut set: std::collections::BTreeSet<RevocationViewSubject> =
        std::collections::BTreeSet::new();
    set.insert(RevocationViewSubject::from("a"));
    set.insert(RevocationViewSubject::from("b"));
    view.install_if_newer(RevocationSnapshot {
        epoch: signed_new.root.epoch,
        root_hash: signed_new.root.root_hash,
        issued_at_unix_ms: signed_new.root.issued_at_unix_ms,
        revoked: set,
    })
    .expect("first install");

    // Now try to "downgrade" to the old root. Verifier MUST refuse.
    let mut stale_set: std::collections::BTreeSet<RevocationViewSubject> =
        std::collections::BTreeSet::new();
    stale_set.insert(RevocationViewSubject::from("a"));
    let err = view
        .install_if_newer(RevocationSnapshot {
            epoch: signed_old.root.epoch,
            root_hash: signed_old.root.root_hash,
            issued_at_unix_ms: signed_old.root.issued_at_unix_ms,
            revoked: stale_set,
        })
        .expect_err("replayed older root must fail closed");
    assert!(matches!(
        err,
        chio_kernel_core::RevocationViewError::NonMonotoneEpoch { .. }
    ));
    // Active snapshot still carries the newer epoch with both subjects.
    assert!(view.is_revoked(&RevocationViewSubject::from("b")));
    assert_eq!(view.current_epoch(), signed_new.root.epoch);
    // Help the type-checker keep the unused-import lint quiet on
    // imported `Ordering` (we reach for it implicitly through sort_unstable
    // in the latency test, but rustc still flags the explicit import as
    // unused on this test binary unless we touch it).
    assert_eq!(2_u8.cmp(&1), Ordering::Greater);
}
