//! Spec MUST: spec/PROTOCOL.md "Anchor batch public-witness lane"
//!   immediately following). Per the spec, "Producers and consumers MUST
//!   verify_anchor_batch_with_witness_policy_async whenever
//!   require_public_witness=true. The synchronous entry point
//!   verify_anchor_batch_with_witness_policy MUST reject any policy
//!   carrying require_public_witness=true at runtime, before structural
//!   verification, regardless of WitnessState."
//!
//! Enforced call site: crates/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy
//!   (the early-return that returns AnchorError::SyncRouteRequiresAdvisoryPolicy
//!   when policy.require_public_witness=true).
//!
//! Production call path: chio_anchor::verify_anchor_batch_with_witness_policy
//!   -> early-return SyncRouteRequiresAdvisoryPolicy.
//!
//! Reverts-to-fail proof: revert the early-return at the top of
//!   verify_anchor_batch_with_witness_policy in
//!   crates/chio-anchor/src/batch.rs (delete the
//!   `if policy.require_public_witness { return Err(...) }` block) and
//!   re-run `cargo test -p chio-conformance --test
//!   b3_anchor_batch_sync_path_rejected_under_public_witness`. The
//!   first sub-test (`sync_wrapper_rejects_require_public_witness_true_*`)
//!   FAILS because the function reaches the structural verify and
//!   returns either Ok or one of the per-state policy errors (PendingNotAllowed,
//!   StaleNotPreviouslyVerified, WitnessReceiptRootMismatch) instead of
//!   SyncRouteRequiresAdvisoryPolicy. THIS IS WHAT REVERTING THE GATE
//!   LOOKS LIKE: if you re-enable the sync path under public witness,
//!   THIS TEST MUST FAIL.
//!
//! Threat: a producer constructs `WitnessPolicy { require_public_witness:
//!   true, ... }` and calls the SYNC verifier
//!   call structurally rejects Witnessed-on-sync only by accident of the
//!   per-state table inside `evaluate_witness_policy`; a future state
//!   addition or per-state rule change could re-open the bypass. PROTOCOL.md
//!
//! Why this passes Artifact D: this test imports
//!   `chio_anchor::verify_anchor_batch_with_witness_policy` directly from
//!   the production crate (no mock, no near-copy), constructs a real
//!   `AnchorBatch` via the production `chio_anchor::build_anchor_batch`
//!   pipeline, and asserts the typed `AnchorError::SyncRouteRequiresAdvisoryPolicy`
//!   variant via exhaustive `match`. Mocks: none (the test does not call
//!   the lane). The advisory-mode positive control exercises the same
//!   production sync wrapper to ensure advisory callers continue to work.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch_with_witness_policy, AnchorBatch, AnchorBatchWitness,
    AnchorBatchWitnessKind, AnchorError, WitnessPolicy, WitnessState,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

/// Build a real signed `AnchorBatch` via the production
/// `build_anchor_batch` path, then mutate the body's witness_state to the
/// requested state and re-sign. The signing path is the production
/// `AnchorBatch::sign`; the test does not redeclare any production type.
fn build_signed_batch_with_state(state: WitnessState) -> AnchorBatch {
    let kp = Keypair::generate();
    let checkpoint_ids = vec![
        "ckpt-b3-1700000000".to_string(),
        "ckpt-b3-1700000060".to_string(),
        "ckpt-b3-1700000120".to_string(),
        "ckpt-b3-1700000180".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:b3-fixture".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();
    batch.body.witness_state = state;
    AnchorBatch::sign(batch.body, &kp).unwrap()
}

#[test]
fn sync_wrapper_rejects_require_public_witness_true_pending_state() {
    let batch = build_signed_batch_with_state(WitnessState::Pending);

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 600,
    };
    let now = 1_700_000_010_i64;

    let err = verify_anchor_batch_with_witness_policy(&batch, &policy, now)
        .expect_err("sync wrapper MUST reject require_public_witness=true at the door");

    match err {
        AnchorError::SyncRouteRequiresAdvisoryPolicy => {}
        other => panic!(
            "B3 gate regression: expected SyncRouteRequiresAdvisoryPolicy, got: {other:?}. If this test fails after the gate is reverted, the structural per-state rejection has slipped back through and the routing rule is no longer load-bearing."
        ),
    }
}

#[test]
fn sync_wrapper_rejects_require_public_witness_true_stale_state() {
    let batch = build_signed_batch_with_state(WitnessState::Stale {
        last_verified: 1_700_000_000,
        error: "rekor 503".to_string(),
    });

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60,
    };
    let now = 1_700_000_500_i64;

    let err = verify_anchor_batch_with_witness_policy(&batch, &policy, now)
        .expect_err("sync wrapper MUST reject require_public_witness=true regardless of state");

    match err {
        AnchorError::SyncRouteRequiresAdvisoryPolicy => {}
        other => {
            panic!("B3 gate regression: expected SyncRouteRequiresAdvisoryPolicy, got: {other:?}")
        }
    }
}

#[test]
fn sync_wrapper_accepts_advisory_policy() {
    let batch = build_signed_batch_with_state(WitnessState::Pending);

    let policy = WitnessPolicy {
        require_public_witness: false,
        stale_window_seconds: 600,
    };
    let now = 1_700_000_010_i64;

    verify_anchor_batch_with_witness_policy(&batch, &policy, now)
        .expect("advisory-mode sync wrapper MUST still accept all states");
}

#[test]
fn sync_wrapper_gate_fires_before_structural_verify() {
    use chio_core::hashing::sha256;

    let kp = Keypair::generate();
    let checkpoint_ids = vec!["ckpt-b3-x".to_string(), "ckpt-b3-y".to_string()];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:b3-fixture-tampered".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();
    // Forge the tree_root and witness root in a paired way so that the
    // signature still verifies but a structural Merkle re-compute would
    // fail. We bypass `AnchorBatch::sign` (which would itself reject the
    // forged body) by constructing the AnchorBatch directly with a
    // signature over the forged body. Since the gate fires BEFORE
    // structural verify, the test exercises the gate ordering invariant.
    let forged_root = sha256(b"chio.anchor_batch.v1::b3-tampered");
    batch.body.tree_root = forged_root;
    batch.body.witness.root = forged_root;
    // Re-sign over the now-forged body. AnchorBatch::sign would reject
    // because the validator runs first; build the AnchorBatch directly.
    let (signature, _bytes) = kp
        .sign_canonical(&batch.body)
        .expect("canonical signing of mutated body");
    let tampered = AnchorBatch {
        body: batch.body,
        signature,
    };

    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 600,
    };
    let now = 1_700_000_010_i64;

    let err = verify_anchor_batch_with_witness_policy(&tampered, &policy, now)
        .expect_err("sync wrapper MUST reject before structural verify");

    match err {
        AnchorError::SyncRouteRequiresAdvisoryPolicy => {}
        other => panic!(
            "B3 gate ordering regression: expected SyncRouteRequiresAdvisoryPolicy, got: {other:?}. The gate must fire BEFORE structural verify; if a structural error is surfaced first, the routing rule is shadowed."
        ),
    }
}
