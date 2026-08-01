//! Anchoring rules for checkpoint-chain consistency proofs.
//!
//! Split from `checkpoint.rs` to keep that module inside the production file
//! size limit enforced by `scripts/check-rust-file-hygiene.py`.

use chio_core::hashing::Hash;
use chio_core::merkle::MerkleProof;

use super::{checkpoint_chain_root, CheckpointError, KernelCheckpoint};

/// What ties the prefix below a consistency proof's earlier endpoint to a
/// history the verifier accepts.
///
/// A pair-level proof constrains nothing before its earlier endpoint, so for a
/// pair starting after checkpoint 1 a signing-key holder can commit an earlier
/// tree whose leading leaves are fabricated, append the later real leaf,
/// re-sign both bodies, and produce paths that verify.
#[derive(Debug, Clone, Copy)]
pub enum CheckpointConsistencyAnchor<'a> {
    /// The earlier endpoint is checkpoint 1, so its chain tree is exactly its
    /// own leaf and no prefix exists to fabricate.
    Genesis,
    /// A chain root the verifier already accepted for the earlier endpoint.
    VerifiedChainRoot(Hash),
    /// Every chain leaf from checkpoint 1 through the earlier endpoint.
    ChainPrefix(&'a [Hash]),
}

/// Whether `from_chain_root` is anchored under `anchor`. Genesis anchoring
/// constrains the verifier's inputs rather than the proof, so a mid-chain pair
/// is an error there instead of a verification failure.
pub(super) fn consistency_prefix_is_anchored(
    previous: &KernelCheckpoint,
    from_size: usize,
    from_chain_root: &Hash,
    anchor: CheckpointConsistencyAnchor<'_>,
) -> Result<bool, CheckpointError> {
    match anchor {
        CheckpointConsistencyAnchor::Genesis => {
            if from_size != 1 {
                return Err(CheckpointError::Continuity(format!(
                    "consistency proof from checkpoint {} is unanchored; only a pair starting at checkpoint 1 anchors itself",
                    previous.body.checkpoint_seq
                )));
            }
            Ok(true)
        }
        CheckpointConsistencyAnchor::VerifiedChainRoot(pinned) => Ok(pinned == *from_chain_root),
        CheckpointConsistencyAnchor::ChainPrefix(chain_leaf_hashes) => Ok(chain_leaf_hashes.len()
            == from_size
            && checkpoint_chain_root(chain_leaf_hashes)? == *from_chain_root),
    }
}

/// Whether `leaf` is committed by `root` as the final leaf of a `size`-leaf
/// chain tree, per the supplied inclusion proof.
pub(super) fn chain_leaf_is_committed(
    inclusion: &MerkleProof,
    size: usize,
    leaf: Hash,
    root: &Hash,
) -> bool {
    inclusion.tree_size == size
        && size.checked_sub(1) == Some(inclusion.leaf_index)
        && inclusion.verify_hash(leaf, root)
}
