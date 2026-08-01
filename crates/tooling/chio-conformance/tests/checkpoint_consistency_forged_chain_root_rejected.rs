//! Negative conformance test: forged checkpoint-chain consistency.
//!
//! Threat: the operator of a log (who holds the kernel signing key)
//! rewrites history and issues a successor checkpoint whose signed
//! `chain_root` has no append-only relation to the predecessor's. Every
//! metadata field of a consistency proof can be made to match the two
//! signed bodies, but the RFC 6962 consistency path cannot connect two
//! unrelated roots, so `verify_checkpoint_consistency_proof` MUST
//! return false.
//!
//! Before the chain commitment existed, the consistency record carried
//! no Merkle node hashes and a verifier recomputed it from the two
//! checkpoints alone, so exactly this rewrite verified.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::leaf_hash;
use chio_core::Keypair;
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_consistency_proof, build_checkpoint_with_previous,
    checkpoint_body_sha256, checkpoint_chain_leaf_hash, checkpoint_chain_root,
    verify_checkpoint_consistency_proof,
};

#[test]
fn checkpoint_consistency_proof_with_forged_chain_root_is_rejected() {
    let kp = Keypair::generate();
    let batch_one: Vec<Vec<u8>> = vec![b"receipt-1".to_vec(), b"receipt-2".to_vec()];
    let batch_two: Vec<Vec<u8>> = vec![b"receipt-3".to_vec(), b"receipt-4".to_vec()];

    let first = build_checkpoint(1, 1, 2, &batch_one, &kp).unwrap();
    let first_leaf = checkpoint_chain_leaf_hash(&first.body).unwrap();
    let second =
        build_checkpoint_with_previous(2, 3, 4, &batch_two, &kp, Some(&first), &[first_leaf])
            .unwrap();
    let chain = [
        first_leaf,
        checkpoint_chain_leaf_hash(&second.body).unwrap(),
    ];

    let honest = build_checkpoint_consistency_proof(&first, &second, &chain).unwrap();
    assert!(
        verify_checkpoint_consistency_proof(&first, &second, &honest).unwrap(),
        "the honest chain extension must verify"
    );

    // Rewrite: the successor re-commits a chain root over fabricated
    // history and re-signs with the real kernel key.
    let mut rewritten = second.clone();
    rewritten.body.chain_root =
        Some(checkpoint_chain_root(&[leaf_hash(b"fabricated-history")]).unwrap());
    rewritten.signature = kp.sign(&canonical_json_bytes(&rewritten.body).unwrap());

    let mut forged = honest.clone();
    forged.to_checkpoint_sha256 = checkpoint_body_sha256(&rewritten.body).unwrap();
    forged.to_chain_root = rewritten.body.chain_root;

    assert!(
        !verify_checkpoint_consistency_proof(&first, &rewritten, &forged).unwrap(),
        "a chain root with no append-only relation to the predecessor must be rejected"
    );
}
