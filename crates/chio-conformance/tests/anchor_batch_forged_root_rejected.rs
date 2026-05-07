//! W2.3 negative conformance test: anchor-batch forged Merkle root.
//!
//! Threat: an adversary mints a batch, recomputes the Merkle root
//! over a different leaf set (or substitutes the root with a
//! plausible-looking but unrelated 32-byte hash), and re-signs the
//! body so the outer signature still verifies. A naive verifier that
//! only inspects the witness label or the schema string accepts the
//! batch even though every inclusion proof now fails to recompute the
//! advertised root.
//!
//! `verify_anchor_batch` rebuilds the Merkle tree from
//! `body.checkpoint_ids` and asserts:
//!
//! 1. `tree.root() == body.tree_root` (commit-binding),
//! 2. each inclusion proof recomputes that root via real Merkle math
//!    (not a label compare).
//!
//! The test mutates one of the leaves (`audit_path[0]`) so that the
//! advertised root no longer reproduces from the inclusion proof;
//! the verifier MUST reject.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_anchor::{
    build_anchor_batch, verify_anchor_batch, AnchorBatchWitness, AnchorBatchWitnessKind,
};
use chio_core::hashing::{sha256, Hash};
use chio_core::Keypair;

#[test]
fn anchor_batch_with_forged_tree_root_is_rejected_by_verifier() {
    let kp = Keypair::generate();
    let checkpoint_ids = vec![
        "ckpt-1700000000".to_string(),
        "ckpt-1700000060".to_string(),
        "ckpt-1700000120".to_string(),
        "ckpt-1700000180".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();

    // Sanity: honest batch verifies.
    verify_anchor_batch(&batch).expect("honest batch must verify before tampering");

    // Forge: substitute a hash that is plausibly shaped (32 bytes,
    // sha256 output) but does NOT match the real Merkle root over
    // the leaves. We also mutate the witness root so the
    // tree_root/witness label invariant is preserved (otherwise the
    // verifier's witness-binding check fires first and the test does
    // not exercise the real Merkle-recompute path).
    let forged_root = sha256(b"chio.anchor_batch.v1::adversary-substituted-root");
    batch.body.tree_root = forged_root;
    batch.body.witness.root = forged_root;
    // Re-sign so the outer signature now validates against the
    // mutated body. This is the exact attack the audit warned about:
    // an adversary who controls the signer can rebuild the body but
    // CANNOT rebuild the inclusion proofs without knowing every
    // original leaf, so the Merkle re-compute MUST fail.
    let signed = chio_anchor::AnchorBatch::sign(batch.body.clone(), &kp);
    // sign() validates the body before signing; it MUST reject
    // because tree.root() over the leaves does not equal forged_root.
    let err = signed.expect_err("re-signing a body whose tree_root was forged must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("forged tree_root") || msg.contains("inclusion proof"),
        "expected Merkle-recompute or forged-root error, got: {msg}"
    );
}

#[test]
fn anchor_batch_with_forged_inclusion_audit_path_is_rejected_by_verifier() {
    let kp = Keypair::generate();
    let checkpoint_ids = vec![
        "ckpt-A".to_string(),
        "ckpt-B".to_string(),
        "ckpt-C".to_string(),
        "ckpt-D".to_string(),
    ];
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Ots,
        witness_id: "ots:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(checkpoint_ids, witness, 1_700_000_000, &kp).unwrap();
    verify_anchor_batch(&batch).expect("honest batch must verify before tampering");

    // Mutate the FIRST sibling on the audit path of the first
    // inclusion proof. The leaf hash itself stays correct so the
    // label-only check (inclusion.leaf_hash == leaf_hash(leaves[0]))
    // still passes; only the real Merkle re-compute detects this.
    let original = batch.body.inclusions[0].proof.audit_path[0];
    batch.body.inclusions[0].proof.audit_path[0] = sha256(b"audit-path-substitution");
    assert_ne!(
        original, batch.body.inclusions[0].proof.audit_path[0],
        "test setup: audit path must change"
    );

    // Re-sign the body so the outer signature still passes. The
    // verifier's Merkle re-compute MUST then reject: starting from
    // the (correct) leaf hash and walking the (forged) audit path
    // produces a root that is NOT batch.body.tree_root.
    let resigned = chio_anchor::AnchorBatch::sign(batch.body.clone(), &kp);
    let err = resigned.expect_err("re-signing a body with a forged audit_path must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("inclusion proof verification failed") || msg.contains("forged tree_root"),
        "expected Merkle inclusion failure, got: {msg}"
    );
}
