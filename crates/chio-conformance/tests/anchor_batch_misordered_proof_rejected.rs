//! Negative conformance test: misordered Merkle audit path.
//!
//! A verifier that short-circuits on a label compare can check that
//! `inclusion.leaf_hash == sha256(canonical(checkpoint_id))` while
//! leaving the rest of the audit path unverified. An adversary could
//! shuffle `audit_path` siblings (keeping the leaf hash itself
//! consistent so the label check still passed) and the verifier
//! would accept the batch even though the real Merkle re-compute
//! produces a different root.
//!
//! This test reverses the audit-path order on a four-leaf tree
//! (where there are at least two siblings on the path so reversal
//! actually changes the result). The verifier MUST reach real
//! Merkle math and reject.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch, AnchorBatch, AnchorBatchWitness,
    AnchorBatchWitnessKind,
};
use chio_core::hashing::Hash;
use chio_core::Keypair;

#[test]
fn anchor_batch_with_reversed_audit_path_is_rejected() {
    let kp = Keypair::generate();
    // 8-leaf tree gives every leaf an audit path of length 3 so the
    // reversal exercise is non-trivial. With 2 leaves the audit path
    // has length 1 and reversal is a no-op.
    let checkpoint_ids = vec![
        "ck-1".to_string(),
        "ck-2".to_string(),
        "ck-3".to_string(),
        "ck-4".to_string(),
        "ck-5".to_string(),
        "ck-6".to_string(),
        "ck-7".to_string(),
        "ck-8".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();
    verify_anchor_batch(&batch).expect("honest batch must verify before tampering");

    let original_path = batch.body.inclusions[0].proof.audit_path.clone();
    assert!(
        original_path.len() >= 2,
        "test setup: audit path must have at least 2 siblings to reverse"
    );

    // Reverse the audit-path order. Leaf hash stays correct, so the
    // label check (inclusion.leaf_hash == leaf_hash(leaves[i])) is
    // still satisfied. Only the real Merkle re-compute detects the
    // attack.
    batch.body.inclusions[0].proof.audit_path.reverse();
    assert_ne!(
        original_path, batch.body.inclusions[0].proof.audit_path,
        "test setup: reversal must change the audit path"
    );

    // Re-sign the body so the outer ed25519 signature still passes.
    // This is the moment a label-only short-circuit would have
    // accepted the batch.
    let resigned = AnchorBatch::sign(batch.body.clone(), &kp);
    let err = resigned.expect_err("re-signing must fail because Merkle re-compute fails");
    let msg = err.to_string();
    assert!(
        msg.contains("inclusion proof verification failed"),
        "expected real Merkle-recompute rejection, got: {msg}"
    );
}

#[test]
fn anchor_batch_with_swapped_distinct_siblings_is_rejected() {
    let kp = Keypair::generate();
    // 4-leaf tree, focus on leaf 0 whose audit path has 2 siblings
    // (leaf 1's hash, then the right subtree node hash). Swap them
    // to construct a non-reversal mutation that label-only checks
    // miss.
    let checkpoint_ids = vec![
        "ck-A".to_string(),
        "ck-B".to_string(),
        "ck-C".to_string(),
        "ck-D".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Ots,
        witness_id: "ots:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();
    verify_anchor_batch(&batch).expect("honest batch must verify before tampering");

    let path = &mut batch.body.inclusions[0].proof.audit_path;
    assert_eq!(
        path.len(),
        2,
        "test setup: leaf 0 of a 4-leaf tree must have 2 audit-path siblings"
    );
    let lhs = path[0];
    let rhs = path[1];
    assert_ne!(
        lhs, rhs,
        "test setup: the two siblings must be distinct so the swap is observable"
    );
    path.swap(0, 1);

    let resigned = AnchorBatch::sign(batch.body.clone(), &kp);
    let err = resigned.expect_err("re-signing must fail: real Merkle math rejects the swap");
    let msg = err.to_string();
    assert!(
        msg.contains("inclusion proof verification failed"),
        "expected real Merkle-recompute rejection, got: {msg}"
    );
}
