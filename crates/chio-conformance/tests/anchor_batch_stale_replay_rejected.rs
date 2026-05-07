//! W2.3 negative conformance test: stale receipt replay across
//! different batch content (HIGH-1, PR #594 round-2 review).
//!
//! Threat: an attacker observes a single receipt id (e.g. a Rekor
//! UUID, an OTS digest) that was previously verified by a verifier
//! daemon. The attacker now constructs a NEW batch (different
//! checkpoint set, different signer, different anything) but reuses
//! the same receipt id and stamps the new batch with a `Stale`
//! `WitnessState`. If admission were keyed by receipt id, the
//! attacker's bogus batch would slip through during a lane outage.
//!
//! Required behaviour: the verifier-owned cache is keyed by the
//! recomputed `batch_body_hash` (the witness-state-excluded view) and
//! stores the verifier's own `verified_at` timestamp. Two batches with
//! the same receipt id but different content produce different body
//! hashes, so the attacker's batch is rejected on
//! `WitnessPolicyError::StaleNotPreviouslyVerified` even though the
//! receipt id matches.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    batch_body_hash, build_anchor_batch, verify_anchor_batch_with_witness_policy_async,
    AnchorBatchWitness, AnchorBatchWitnessKind, VerifiedWitnessCache, WitnessPolicy, WitnessState,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

#[test]
fn stale_admission_rejects_replay_of_receipt_id_against_different_content() {
    let kp = Keypair::generate();

    // Batch A: previously verified, body_hash recorded by the
    // verifier daemon at some earlier successful verify_inclusion.
    let witness_a = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-replay-target".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch_a = build_anchor_batch(
        vec!["ck-A-1".to_string(), "ck-A-2".to_string()],
        witness_a,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch_a.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed_a = chio_anchor::AnchorBatch::sign(batch_a.body, &kp).unwrap();
    let body_hash_a = batch_body_hash(&signed_a).unwrap();

    // Batch B: same witness_id (the attacker's chosen replay vector),
    // DIFFERENT checkpoint set so the canonical body bytes (and thus
    // the recomputed body_hash) differ from batch A.
    let witness_b = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:uuid-replay-target".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch_b = build_anchor_batch(
        vec!["ck-attacker-1".to_string(), "ck-attacker-2".to_string()],
        witness_b,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    batch_b.body.witness_state = WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    };
    let signed_b = chio_anchor::AnchorBatch::sign(batch_b.body, &kp).unwrap();
    let body_hash_b = batch_body_hash(&signed_b).unwrap();

    // Sanity: the receipt id is shared, the body_hash is not.
    assert_eq!(
        signed_a.body.witness.witness_id,
        signed_b.body.witness.witness_id
    );
    assert_ne!(body_hash_a, body_hash_b);

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    // Verifier remembers ONLY batch A's body hash (the one that
    // legitimately round-tripped against verify_inclusion).
    let mut verified = VerifiedWitnessCache::new();
    verified.insert(body_hash_a, 1_700_000_000);

    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Positive control: batch A is admitted because its body_hash
    // is in the verified set.
    runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed_a,
            &policy,
            1_700_000_100,
            None,
            &verified,
        ))
        .expect("batch A admitted: body_hash present in verifier-owned cache");

    // Negative case: batch B (same receipt id, different content)
    // must be rejected. Without the HIGH-1 fix this would slip
    // through because the receipt id matches.
    let err = runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed_b,
            &policy,
            1_700_000_100,
            None,
            &verified,
        ))
        .expect_err("batch B must be rejected: receipt id replayed across different content");
    let msg = err.to_string();
    assert!(
        msg.contains("StaleNotPreviouslyVerified")
            || msg.contains("not in the verifier-owned previously_verified cache"),
        "expected stale-not-previously-verified rejection, got: {msg}"
    );
}
