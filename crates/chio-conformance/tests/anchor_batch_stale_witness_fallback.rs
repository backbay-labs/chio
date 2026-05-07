//! W2.3 negative conformance test: stale witness-lane fallback.
//!
//! Threat: the public-witness lane (Rekor or OTS) goes down. The
//! verifier still holds a previously-witnessed receipt for batch B0
//! and a brand-new pending batch B1.
//!
//! Required behaviour, per `WitnessPolicy`:
//!
//! - `require_public_witness: true` and B1 is `WitnessState::Pending`
//!   -> reject (lane is required, no receipt).
//! - `require_public_witness: true` and B0 is `WitnessState::Stale`
//!   on the sync path -> reject because there is no verifier-owned cache.
//! - `require_public_witness: true` and B0 is `WitnessState::Stale`
//!   with the verifier-owned cache entry
//!   `verified_at + stale_window_seconds >= now` -> accept.
//! - `require_public_witness: true` and B0 is `WitnessState::Stale`
//!   but the batch hash is NOT in the verifier-owned cache ->
//!   reject (a producer cannot bootstrap themselves into the
//!   verified set, and an attacker who has observed a
//!   previously-verified receipt id cannot replay that id against
//!   different batch content). Added in PR #594 review (HIGH-2),
//!   strengthened in round-2 review (HIGH-1) by binding to the
//!   batch body hash.
//! - `require_public_witness: false` -> accept all states (advisory
//!   mode for partner integrations that have not yet wired the lane).
//!
//! HIGH-2 from the PR review: when `require_public_witness=true` and
//! state is `Witnessed`, the load-bearing path now requires a real
//! `AnchorWitnessClient::verify_inclusion` call. The sync
//! `verify_anchor_batch_with_witness_policy` path fails closed for
//! self-asserted `Witnessed`; callers that require public witness must
//! use `verify_anchor_batch_with_witness_policy_async`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch_with_witness_policy,
    verify_anchor_batch_with_witness_policy_async, AnchorBatchWitness, AnchorBatchWitnessKind,
    AnchorWitnessClient, AnchorWitnessError, VerifiedWitnessCache, WitnessPolicy, WitnessReceipt,
    WitnessState,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

fn make_batch(state: WitnessState) -> chio_anchor::AnchorBatch {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(
        vec![
            "ck-stale-1".to_string(),
            "ck-stale-2".to_string(),
            "ck-stale-3".to_string(),
        ],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch.body.witness_state = state;
    chio_anchor::AnchorBatch::sign(batch.body, &kp).unwrap()
}

fn fresh_witnessed_state(batch: &chio_anchor::AnchorBatch, observed_at: i64) -> WitnessState {
    WitnessState::Witnessed {
        receipt: WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "uuid-prior-witness".to_string(),
            published_at: observed_at,
            inclusion_proof: vec![1, 2, 3, 4],
            witness_root: batch.body.tree_root,
            body_hash: chio_anchor::batch_body_hash(batch).unwrap(),
        },
        observed_at,
    }
}

/// Stub `AnchorWitnessClient` whose `verify_inclusion` always
/// succeeds. Used in the positive-control tests that exercise the
/// load-bearing async path with a (notional) lane round-trip.
struct AlwaysOkClient;

#[async_trait::async_trait]
impl AnchorWitnessClient for AlwaysOkClient {
    async fn publish(
        &self,
        _: &chio_anchor::AnchorBatch,
    ) -> Result<WitnessReceipt, AnchorWitnessError> {
        unreachable!("publish is not exercised by stale-fallback tests")
    }
    async fn verify_inclusion(&self, _: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
        Ok(())
    }
}

/// Stub whose `verify_inclusion` always rejects. Used to confirm
/// that a self-asserted Witnessed state with `require_public_witness`
/// is rejected by the load-bearing async path even when the
/// structural invariants hold.
struct AlwaysFailClient;

#[async_trait::async_trait]
impl AnchorWitnessClient for AlwaysFailClient {
    async fn publish(
        &self,
        _: &chio_anchor::AnchorBatch,
    ) -> Result<WitnessReceipt, AnchorWitnessError> {
        unreachable!("publish is not exercised by stale-fallback tests")
    }
    async fn verify_inclusion(&self, _: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
        Err(AnchorWitnessError::SignatureInvalid(
            "test client rejecting all receipts".to_string(),
        ))
    }
}

#[test]
fn require_public_witness_rejects_pending_batch() {
    let batch = make_batch(WitnessState::Pending);
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let err = verify_anchor_batch_with_witness_policy(&batch, &policy, 1_700_000_100)
        .expect_err("Pending batch must be rejected when require_public_witness=true");
    let msg = err.to_string();
    assert!(
        msg.contains("Pending state") || msg.contains("PendingNotAllowed"),
        "expected Pending rejection, got: {msg}"
    );
}

#[test]
fn require_public_witness_rejects_stale_on_sync_path_without_verifier_cache() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(
        vec!["ck-S-1".to_string(), "ck-S-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed = chio_anchor::AnchorBatch::sign(batch.body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60,
    };
    // 500 seconds > 60 second stale window
    let err = verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect_err("sync stale admission without verifier cache must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("not in the verifier-owned previously_verified cache")
            || msg.contains("StaleNotPreviouslyVerified"),
        "expected stale verifier-cache rejection, got: {msg}"
    );
}

#[test]
fn require_public_witness_accepts_already_witnessed_during_lane_outage() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let unsigned = build_anchor_batch(
        vec!["ck-W-1".to_string(), "ck-W-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();

    // Build a Witnessed state that points at this batch's tree_root
    // and body_hash so the WitnessReceiptRootMismatch invariant
    // holds.
    let prior_state = fresh_witnessed_state(&unsigned, 1_700_000_010);
    let mut body = unsigned.body.clone();
    body.witness_state = prior_state;
    let signed = chio_anchor::AnchorBatch::sign(body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect_err("sync require_public_witness rejects self-asserted Witnessed");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = AlwaysOkClient;
    let verified = VerifiedWitnessCache::new();
    runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_500,
            Some(&client),
            &verified,
        ))
        .expect("load-bearing path admits a Witnessed batch when verify_inclusion succeeds");
}

#[test]
fn advisory_mode_accepts_pending_and_stale() {
    let pending = make_batch(WitnessState::Pending);
    let stale = make_batch(WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor sigstore.dev unreachable".to_string(),
    });
    let policy = WitnessPolicy {
        require_public_witness: false,
        stale_window_seconds: 60,
    };
    verify_anchor_batch_with_witness_policy(&pending, &policy, 1_700_000_500)
        .expect("advisory mode accepts pending");
    verify_anchor_batch_with_witness_policy(&stale, &policy, 1_700_000_500)
        .expect("advisory mode accepts stale");
}

#[test]
fn require_public_witness_rejects_already_witnessed_with_root_mismatch() {
    // Defence-in-depth: even when the policy is satisfied by
    // WitnessState::Witnessed, the receipt's witness_root must equal
    // the batch's tree_root. An adversary who substitutes the
    // tree_root post-witness gets caught here.
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let unsigned = build_anchor_batch(
        vec!["ck-RM-1".to_string(), "ck-RM-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();

    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-honest".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        // Adversary forges the receipt to point at a different root
        // (sha256("evil")) while the batch's actual tree_root is the
        // honest computed root.
        witness_root: chio_core::hashing::sha256(b"evil-substituted-root"),
        body_hash: chio_anchor::batch_body_hash(&unsigned).unwrap(),
    };
    let mut body = unsigned.body.clone();
    body.witness_state = WitnessState::Witnessed {
        receipt,
        observed_at: 1_700_000_010,
    };
    let signed = chio_anchor::AnchorBatch::sign(body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let err = verify_anchor_batch_with_witness_policy(&signed, &policy, 1_700_000_500)
        .expect_err("witness root must match batch tree_root");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match") || msg.contains("WitnessReceiptRootMismatch"),
        "expected witness-root mismatch, got: {msg}"
    );
}

/// HIGH-2: a self-asserted Witnessed state must NOT satisfy the
/// load-bearing policy on structural invariants alone. The async
/// path must call AnchorWitnessClient::verify_inclusion and reject
/// when the lane refuses the receipt.
#[test]
fn require_public_witness_rejects_self_asserted_witnessed_under_async_path() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-self-asserted".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let unsigned = build_anchor_batch(
        vec!["ck-SA-1".to_string(), "ck-SA-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    // Honest-looking Witnessed state: receipt root and body_hash
    // both bind to this batch (so the structural invariants hold).
    let prior_state = fresh_witnessed_state(&unsigned, 1_700_000_010);
    let mut body = unsigned.body.clone();
    body.witness_state = prior_state;
    let signed = chio_anchor::AnchorBatch::sign(body, &kp).unwrap();

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = AlwaysFailClient;
    let verified = VerifiedWitnessCache::new();
    let err = runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_500,
            Some(&client),
            &verified,
        ))
        .expect_err("self-asserted Witnessed must be rejected by the verifier client");
    let msg = err.to_string();
    assert!(
        msg.contains("witness lane verification failed")
            || msg.contains("VerifierRejected")
            || msg.contains("test client rejecting"),
        "expected lane-verifier rejection, got: {msg}"
    );
}

/// HIGH-2: a Stale state without a prior verified record must be
/// rejected when require_public_witness=true, even within the
/// stale window. The verifier-owned cache is the
/// authoritative source.
#[test]
fn require_public_witness_rejects_stale_without_previous_verification() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-no-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut unsigned = build_anchor_batch(
        vec!["ck-NP-1".to_string(), "ck-NP-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    unsigned.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed = chio_anchor::AnchorBatch::sign(unsigned.body, &kp).unwrap();
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let verified = VerifiedWitnessCache::new();
    let err = runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_500,
            None,
            &verified,
        ))
        .expect_err("stale without prior verification must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("StaleNotPreviouslyVerified")
            || msg.contains("not in the verifier-owned previously_verified cache"),
        "expected stale-not-previously-verified rejection, got: {msg}"
    );
}

/// HIGH-2 (positive control): a Stale state IS admitted when the
/// recomputed batch body_hash is in the caller's
/// verifier-owned cache and the stale window is open.
/// HIGH-1 (round-2): the set is keyed by body_hash, not receipt id,
/// so an attacker cannot replay a previously-observed receipt id
/// against a different batch's content.
#[test]
fn require_public_witness_admits_stale_when_previously_verified() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-with-prior".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut unsigned = build_anchor_batch(
        vec!["ck-WP-1".to_string(), "ck-WP-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    unsigned.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed = chio_anchor::AnchorBatch::sign(unsigned.body, &kp).unwrap();
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut verified = VerifiedWitnessCache::new();
    verified.insert(
        chio_anchor::batch_body_hash(&signed).unwrap(),
        1_700_000_000,
    );
    runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_500,
            None,
            &verified,
        ))
        .expect("previously-verified stale receipt is admissible");
}

/// P0 regression: stale admission uses the verifier-owned
/// `verified_at` cache timestamp, not the producer-signed
/// `last_verified` value. A producer cannot refresh a stale cache by
/// signing a fresh artifact timestamp.
#[test]
fn require_public_witness_rejects_stale_with_fresh_producer_timestamp_but_stale_cache() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-future".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut unsigned = build_anchor_batch(
        vec!["ck-FUT-1".to_string(), "ck-FUT-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    unsigned.body.witness_state = WitnessState::Stale {
        // Producer claims freshness. This value is not trusted for
        // stale admission.
        last_verified: 1_700_000_500,
        error: "rekor 503".to_string(),
    };
    let signed = chio_anchor::AnchorBatch::sign(unsigned.body, &kp).unwrap();
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut verified = VerifiedWitnessCache::new();
    verified.insert(
        chio_anchor::batch_body_hash(&signed).unwrap(),
        1_700_000_000,
    );
    let err = runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_500,
            None,
            &verified,
        ))
        .expect_err("stale verifier cache timestamp must control admission");
    let msg = err.to_string();
    assert!(
        msg.contains("stale verifier cache window exceeded")
            || msg.contains("StaleVerifierCacheWindowExceeded"),
        "expected stale verifier-cache rejection, got: {msg}"
    );
}
