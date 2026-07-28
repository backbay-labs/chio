//! Merkle-committed receipt batch checkpointing.
//!
//! Produces signed kernel checkpoint statements that commit a batch of receipts
//! to a Merkle root. Inclusion proofs allow verifying that a specific receipt
//! was part of a batch without replaying the entire log.
//!
//! Issuance schema: "chio.checkpoint_statement.v2"

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey, Signature, SigningAlgorithm};
use chio_core::hashing::sha256_hex;
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, verify_consistency_proof, MerkleProof, MerkleTree};
use chio_core::receipt::{
    checkpoint::CheckpointPublicationIdentityKind,
    checkpoint::CheckpointPublicationTrustAnchorBinding,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::ReceiptStoreError;

/// Legacy checkpoint statement without a checkpoint-chain commitment.
pub const CHECKPOINT_SCHEMA_V1: &str = "chio.checkpoint_statement.v1";
/// Checkpoint statement that may carry the signed checkpoint-chain commitment.
pub const CHECKPOINT_SCHEMA_V2: &str = "chio.checkpoint_statement.v2";
/// Schema used for new checkpoint issuance.
pub const CHECKPOINT_SCHEMA: &str = CHECKPOINT_SCHEMA_V2;
pub const CHECKPOINT_PUBLICATION_SCHEMA: &str = "chio.checkpoint_publication.v1";
pub const CHECKPOINT_WITNESS_SCHEMA: &str = "chio.checkpoint_witness.v1";
/// Legacy metadata-only continuity record.
pub const CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1: &str = "chio.checkpoint_consistency_proof.v1";
/// Cryptographic checkpoint-chain consistency proof.
pub const CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V2: &str = "chio.checkpoint_consistency_proof.v2";
/// Schema used for new consistency-proof issuance.
pub const CHECKPOINT_CONSISTENCY_PROOF_SCHEMA: &str = CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V2;
pub const CHECKPOINT_EQUIVOCATION_SCHEMA: &str = "chio.checkpoint_equivocation.v1";

#[must_use]
pub fn is_supported_checkpoint_schema(schema: &str) -> bool {
    matches!(schema, CHECKPOINT_SCHEMA_V1 | CHECKPOINT_SCHEMA_V2)
}

fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(<D::Error as serde::de::Error>::custom(
            "explicit null is not permitted; omit the optional field",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(<D::Error as serde::de::Error>::custom)
}

/// Error type for checkpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("merkle error: {0}")]
    Merkle(#[from] chio_core::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),
    #[error("invalid checkpoint: {0}")]
    Invalid(String),
    #[error("checkpoint signature verification failed")]
    InvalidSignature,
    #[error("checkpoint continuity error: {0}")]
    Continuity(String),
}

/// The signed body of a kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelCheckpointBody {
    /// Schema identifier for new checkpoint issuance.
    pub schema: String,
    /// Monotonic checkpoint counter.
    pub checkpoint_seq: u64,
    /// First receipt seq in this batch.
    pub batch_start_seq: u64,
    /// Last receipt seq in this batch.
    pub batch_end_seq: u64,
    /// Number of leaves in the Merkle tree.
    pub tree_size: usize,
    /// Root from MerkleTree::from_leaves.
    pub merkle_root: Hash,
    /// Unix timestamp (seconds) when the checkpoint was issued.
    pub issued_at: u64,
    /// The kernel's signing key (public).
    pub kernel_key: PublicKey,
    /// Hash of the immediately preceding checkpoint body when this checkpoint extends a prior batch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub previous_checkpoint_sha256: Option<String>,
    /// RFC 6962 root over the checkpoint-chain leaves for checkpoint_seq 1
    /// through this checkpoint, one leaf per checkpoint binding its sequence,
    /// entry range, and batch root (see [`checkpoint_chain_leaf_hash`]). This
    /// is the commitment that consistency proofs verify against. Absent on
    /// v1 checkpoints and on detached v2 checkpoints built without chain
    /// context.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub chain_root: Option<Hash>,
}

/// A signed kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelCheckpoint {
    /// The signed body.
    pub body: KernelCheckpointBody,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// A Merkle inclusion proof for a receipt within a checkpoint batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInclusionProof {
    /// Which checkpoint this proof is for.
    pub checkpoint_seq: u64,
    /// The seq of the receipt being proved.
    pub receipt_seq: u64,
    /// Index of this receipt in the Merkle leaf array.
    pub leaf_index: usize,
    /// The Merkle root this proof is against.
    pub merkle_root: Hash,
    /// The audit path proof.
    pub proof: MerkleProof,
}

impl ReceiptInclusionProof {
    /// Verify that `receipt_canonical_bytes` is included in the batch.
    #[must_use]
    pub fn verify(&self, receipt_canonical_bytes: &[u8], expected_root: &Hash) -> bool {
        self.proof.verify(receipt_canonical_bytes, expected_root)
    }
}

/// A deterministic publication record derived from a signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointPublication {
    /// Local log identity derived from the checkpoint signing key until an
    /// explicit persisted transparency log ID is available.
    pub log_id: String,
    /// Schema identifier for derived publication records.
    pub schema: String,
    /// Monotonic checkpoint counter.
    pub checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the signed checkpoint body.
    pub checkpoint_sha256: String,
    /// Merkle root published by the checkpoint.
    pub merkle_root: Hash,
    /// Timestamp when the checkpoint was issued/published.
    pub published_at: u64,
    /// The kernel key that signed the checkpoint.
    pub kernel_key: PublicKey,
    /// Cumulative log size derived from the covered entry sequence range.
    pub log_tree_size: u64,
    /// First entry sequence covered by this checkpoint batch.
    pub entry_start_seq: u64,
    /// Last entry sequence covered by this checkpoint batch.
    pub entry_end_seq: u64,
    /// Digest of the predecessor checkpoint body when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
    /// Declared verifier material when this publication is tied to a typed
    /// publication path and explicit trust-anchor policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_binding: Option<CheckpointPublicationTrustAnchorBinding>,
}

/// A deterministic witness record derived from a checkpoint's predecessor digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWitness {
    /// Local log identity derived from the checkpoint signing key.
    pub log_id: String,
    /// Schema identifier for derived witness records.
    pub schema: String,
    /// The checkpoint being witnessed.
    pub checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the witnessed checkpoint body.
    pub checkpoint_sha256: String,
    /// The later checkpoint that cites the witnessed checkpoint digest.
    pub witness_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the witness checkpoint body.
    pub witness_checkpoint_sha256: String,
    /// Timestamp from the witness checkpoint body.
    pub witnessed_at: u64,
}

/// A Merkle consistency proof between two checkpoint-chain commitments.
///
/// Proves, with RFC 6962 node hashes, that the checkpoint chain committed by
/// `to_chain_root` is an append-only extension of the chain committed by
/// `from_chain_root`. The chain tree has one leaf per checkpoint, so the tree
/// sizes are the checkpoint sequences themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointConsistencyProof {
    /// Schema identifier for consistency proof records.
    pub schema: String,
    /// Local log identity derived from the checkpoint signing key.
    pub log_id: String,
    /// Earlier checkpoint sequence in the proven prefix chain.
    pub from_checkpoint_seq: u64,
    /// Later checkpoint sequence in the proven prefix chain.
    pub to_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the earlier checkpoint body.
    pub from_checkpoint_sha256: String,
    /// Canonical SHA-256 digest of the later checkpoint body.
    pub to_checkpoint_sha256: String,
    /// Cumulative log size before the append.
    pub from_log_tree_size: u64,
    /// Cumulative log size after the append.
    pub to_log_tree_size: u64,
    /// First entry sequence appended by the later checkpoint.
    pub appended_entry_start_seq: u64,
    /// Last entry sequence appended by the later checkpoint.
    pub appended_entry_end_seq: u64,
    /// Signed chain commitment of the earlier checkpoint. Absent on legacy v1
    /// metadata-only records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_chain_root: Option<Hash>,
    /// Signed chain commitment of the later checkpoint. Absent on legacy v1
    /// metadata-only records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_chain_root: Option<Hash>,
    /// RFC 6962 consistency path from the earlier chain tree to the later
    /// chain tree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_proof_hashes: Vec<Hash>,
    /// Inclusion proof binding the earlier checkpoint's own chain leaf to
    /// `from_chain_root` at the last position of that tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_leaf_inclusion: Option<MerkleProof>,
    /// Inclusion proof binding the later checkpoint's own chain leaf to
    /// `to_chain_root` at the last position. Without both endpoints bound, a
    /// key holder could commit chain trees whose leaves are unrelated to the
    /// bodies the proof names and still produce a verifying consistency path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_leaf_inclusion: Option<MerkleProof>,
}

/// Whether `leaf` is committed by `root` as the final leaf of a `size`-leaf
/// chain tree, per the supplied inclusion proof.
fn chain_leaf_is_committed(inclusion: &MerkleProof, size: usize, leaf: Hash, root: &Hash) -> bool {
    inclusion.tree_size == size
        && size.checked_sub(1) == Some(inclusion.leaf_index)
        && inclusion.verify_hash(leaf, root)
}

/// Classifies a conflicting checkpoint observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointEquivocationKind {
    /// Two distinct checkpoints claim the same checkpoint sequence.
    ConflictingCheckpointSeq,
    /// Two distinct checkpoints claim the same log and cumulative tree size.
    ConflictingLogTreeSize,
    /// Two distinct checkpoints cite the same predecessor digest.
    ConflictingPredecessorWitness,
}

/// A deterministic conflict record derived from multiple checkpoint statements.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CheckpointEquivocation {
    /// Schema identifier for derived equivocation records.
    pub schema: String,
    /// Which transparency rule was violated.
    pub kind: CheckpointEquivocationKind,
    /// Local log identity when the conflict can be tied to one derived log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_id: Option<String>,
    /// Shared cumulative log size when the conflict is a tree-size fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_tree_size: Option<u64>,
    /// The first conflicting checkpoint sequence.
    pub first_checkpoint_seq: u64,
    /// The second conflicting checkpoint sequence.
    pub second_checkpoint_seq: u64,
    /// Canonical SHA-256 digest of the first checkpoint body.
    pub first_checkpoint_sha256: String,
    /// Canonical SHA-256 digest of the second checkpoint body.
    pub second_checkpoint_sha256: String,
    /// Shared predecessor digest when the conflict is a witness fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
}

/// Derived transparency records for a set of checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CheckpointTransparencySummary {
    /// Publication records for each checkpoint.
    pub publications: Vec<CheckpointPublication>,
    /// Witness records derived from predecessor-digest links.
    pub witnesses: Vec<CheckpointWitness>,
    /// Prefix-growth proofs derived from contiguous checkpoint extensions.
    pub consistency_proofs: Vec<CheckpointConsistencyProof>,
    /// Conflict records derived from contradictory checkpoints.
    pub equivocations: Vec<CheckpointEquivocation>,
}

#[must_use]
pub fn checkpoint_log_id(checkpoint: &KernelCheckpoint) -> String {
    let log_key_bytes: Vec<u8> = match checkpoint.body.kernel_key.algorithm() {
        SigningAlgorithm::Ed25519 => checkpoint.body.kernel_key.as_bytes().to_vec(),
        SigningAlgorithm::P256 | SigningAlgorithm::P384 | SigningAlgorithm::Hybrid => {
            checkpoint.body.kernel_key.to_hex().into_bytes()
        }
    };
    format!("local-log-{}", sha256_hex(&log_key_bytes))
}

#[must_use]
pub fn checkpoint_log_tree_size(body: &KernelCheckpointBody) -> u64 {
    body.batch_end_seq
}

fn checkpoint_batch_entry_count(body: &KernelCheckpointBody) -> Result<u64, CheckpointError> {
    body.batch_end_seq
        .checked_sub(body.batch_start_seq)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            CheckpointError::Invalid(format!(
                "invalid checkpoint entry range {}-{}",
                body.batch_start_seq, body.batch_end_seq
            ))
        })
}

/// Return the canonical SHA-256 digest for a checkpoint body.
pub fn checkpoint_body_sha256(body: &KernelCheckpointBody) -> Result<String, CheckpointError> {
    let body_bytes =
        canonical_json_bytes(body).map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    Ok(sha256_hex(&body_bytes))
}

/// Canonical leaf content for the checkpoint-chain commitment.
///
/// Deliberately excludes `issued_at`, the kernel key, and the signature so
/// that two honest builders checkpointing the same batch produce the same
/// leaf even when their wall clocks differ.
#[derive(Serialize)]
struct CheckpointChainLeaf {
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    merkle_root: Hash,
}

/// RFC 6962 leaf hash of one checkpoint's chain-commitment leaf.
pub fn checkpoint_chain_leaf_hash_from_parts(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    merkle_root: Hash,
) -> Result<Hash, CheckpointError> {
    let leaf = CheckpointChainLeaf {
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        merkle_root,
    };
    let leaf_bytes =
        canonical_json_bytes(&leaf).map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    Ok(leaf_hash(&leaf_bytes))
}

/// RFC 6962 leaf hash of a checkpoint body's chain-commitment leaf.
pub fn checkpoint_chain_leaf_hash(body: &KernelCheckpointBody) -> Result<Hash, CheckpointError> {
    checkpoint_chain_leaf_hash_from_parts(
        body.checkpoint_seq,
        body.batch_start_seq,
        body.batch_end_seq,
        body.merkle_root,
    )
}

/// Append-only frontier of the checkpoint-chain Merkle tree.
///
/// Holds one root per perfect subtree covering the leaves so far, largest
/// first, which is enough to compute the RFC 6962 tree head and to extend it.
/// Appending is amortized O(1) hashes and the root costs O(log n), so a
/// long-lived writer never rehashes the whole chain to issue one checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointChainFrontier {
    /// `(subtree root, leaf span)`, spans strictly decreasing powers of two.
    subtrees: Vec<(Hash, u64)>,
}

impl CheckpointChainFrontier {
    /// Frontier over no leaves.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Rebuild from every chain leaf in order. O(n); used once when a writer
    /// seeds or resyncs its head, never on the per-checkpoint path.
    #[must_use]
    pub fn from_leaves(chain_leaf_hashes: &[Hash]) -> Self {
        let mut frontier = Self::empty();
        for leaf in chain_leaf_hashes {
            frontier.append(*leaf);
        }
        frontier
    }

    /// Number of chain leaves covered.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.subtrees.iter().map(|(_, span)| *span).sum()
    }

    /// Extend by one chain leaf, merging equal-span neighbours so the spans
    /// stay strictly decreasing powers of two.
    pub fn append(&mut self, chain_leaf_hash: Hash) {
        self.subtrees.push((chain_leaf_hash, 1));
        while self.subtrees.len() >= 2 {
            let (right, right_span) = self.subtrees[self.subtrees.len() - 1];
            let (left, left_span) = self.subtrees[self.subtrees.len() - 2];
            if left_span != right_span {
                break;
            }
            self.subtrees.truncate(self.subtrees.len() - 2);
            self.subtrees
                .push((chio_core::merkle::node_hash(&left, &right), left_span * 2));
        }
    }

    /// Number of perfect subtrees retained; equals the population count of
    /// the leaf count.
    #[cfg(test)]
    #[must_use]
    pub fn subtree_count_for_test(&self) -> usize {
        self.subtrees.len()
    }

    /// RFC 6962 tree head over the covered leaves, or `None` when empty.
    ///
    /// Folds right-associatively, which is the same shape the recursive
    /// definition produces for a tree whose right edge is incomplete.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        let (last, _) = *self.subtrees.last()?;
        Some(
            self.subtrees[..self.subtrees.len() - 1]
                .iter()
                .rev()
                .fold(last, |acc, (subtree, _)| {
                    chio_core::merkle::node_hash(subtree, &acc)
                }),
        )
    }
}

/// Chain-commitment root over an ordered, gap-free run of chain leaves
/// starting at checkpoint_seq 1.
pub fn checkpoint_chain_root(chain_leaf_hashes: &[Hash]) -> Result<Hash, CheckpointError> {
    Ok(MerkleTree::from_hashes(chain_leaf_hashes.to_vec())?.root())
}

/// Build a deterministic publication record from a signed checkpoint.
pub fn build_checkpoint_publication(
    checkpoint: &KernelCheckpoint,
) -> Result<CheckpointPublication, CheckpointError> {
    validate_checkpoint(checkpoint)?;
    Ok(CheckpointPublication {
        log_id: checkpoint_log_id(checkpoint),
        schema: CHECKPOINT_PUBLICATION_SCHEMA.to_string(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        checkpoint_sha256: checkpoint_body_sha256(&checkpoint.body)?,
        merkle_root: checkpoint.body.merkle_root,
        published_at: checkpoint.body.issued_at,
        kernel_key: checkpoint.body.kernel_key.clone(),
        log_tree_size: checkpoint_log_tree_size(&checkpoint.body),
        entry_start_seq: checkpoint.body.batch_start_seq,
        entry_end_seq: checkpoint.body.batch_end_seq,
        previous_checkpoint_sha256: checkpoint.body.previous_checkpoint_sha256.clone(),
        trust_anchor_binding: None,
    })
}

/// Build a deterministic publication record that is explicitly bound to
/// declared trust-anchor verifier material.
pub fn build_trust_anchored_checkpoint_publication(
    checkpoint: &KernelCheckpoint,
    trust_anchor_binding: CheckpointPublicationTrustAnchorBinding,
) -> Result<CheckpointPublication, CheckpointError> {
    trust_anchor_binding
        .validate()
        .map_err(|error| CheckpointError::Invalid(error.to_string()))?;
    let publication = build_checkpoint_publication(checkpoint)?;
    if trust_anchor_binding.publication_identity.kind == CheckpointPublicationIdentityKind::LocalLog
        && trust_anchor_binding.publication_identity.identity != publication.log_id
    {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint publication local_log identity {} does not match log_id {}",
            trust_anchor_binding.publication_identity.identity, publication.log_id
        )));
    }
    let mut publication = publication;
    publication.trust_anchor_binding = Some(trust_anchor_binding);
    Ok(publication)
}

/// Build a deterministic witness record when `witness_checkpoint` cites `checkpoint`.
pub fn build_checkpoint_witness(
    checkpoint: &KernelCheckpoint,
    witness_checkpoint: &KernelCheckpoint,
) -> Result<CheckpointWitness, CheckpointError> {
    validate_checkpoint(checkpoint)?;
    validate_checkpoint(witness_checkpoint)?;

    let checkpoint_sha256 = checkpoint_body_sha256(&checkpoint.body)?;
    let witness_checkpoint_sha256 = checkpoint_body_sha256(&witness_checkpoint.body)?;
    let Some(previous_checkpoint_sha256) = witness_checkpoint
        .body
        .previous_checkpoint_sha256
        .as_deref()
    else {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} does not cite a predecessor digest",
            witness_checkpoint.body.checkpoint_seq
        )));
    };
    if previous_checkpoint_sha256 != checkpoint_sha256 {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} does not witness checkpoint {}",
            witness_checkpoint.body.checkpoint_seq, checkpoint.body.checkpoint_seq
        )));
    }

    Ok(CheckpointWitness {
        log_id: checkpoint_log_id(checkpoint),
        schema: CHECKPOINT_WITNESS_SCHEMA.to_string(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        checkpoint_sha256,
        witness_checkpoint_seq: witness_checkpoint.body.checkpoint_seq,
        witness_checkpoint_sha256,
        witnessed_at: witness_checkpoint.body.issued_at,
    })
}

fn require_chain_root(checkpoint: &KernelCheckpoint) -> Result<Hash, CheckpointError> {
    checkpoint.body.chain_root.ok_or_else(|| {
        CheckpointError::Continuity(format!(
            "checkpoint {} carries no chain commitment; consistency is unverifiable",
            checkpoint.body.checkpoint_seq
        ))
    })
}

fn chain_tree_size(checkpoint: &KernelCheckpoint) -> Result<usize, CheckpointError> {
    usize::try_from(checkpoint.body.checkpoint_seq).map_err(|_| {
        CheckpointError::Invalid(format!(
            "checkpoint_seq {} exceeds the addressable chain size",
            checkpoint.body.checkpoint_seq
        ))
    })
}

/// Ensure the two pair endpoints appear at their own positions in the
/// supplied chain leaves, then hand back the parsed sizes.
fn validate_chain_leaves_for_pair(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    chain_leaf_hashes: &[Hash],
) -> Result<(usize, usize), CheckpointError> {
    let from_size = chain_tree_size(previous)?;
    let to_size = chain_tree_size(current)?;
    // Callers reach here through `validate_checkpoint_predecessor`, which
    // forces `from_size + 1 == to_size`; re-check locally so a future direct
    // caller gets an error rather than an out-of-bounds index below.
    if from_size == 0 || from_size >= to_size {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} does not extend checkpoint {} in chain order",
            current.body.checkpoint_seq, previous.body.checkpoint_seq
        )));
    }
    if chain_leaf_hashes.len() < to_size {
        return Err(CheckpointError::Continuity(format!(
            "chain leaf count {} does not reach checkpoint {} chain size {}",
            chain_leaf_hashes.len(),
            current.body.checkpoint_seq,
            to_size
        )));
    }
    if chain_leaf_hashes[from_size - 1] != checkpoint_chain_leaf_hash(&previous.body)? {
        return Err(CheckpointError::Continuity(format!(
            "chain leaf {} does not match the predecessor checkpoint body",
            previous.body.checkpoint_seq
        )));
    }
    if chain_leaf_hashes[to_size - 1] != checkpoint_chain_leaf_hash(&current.body)? {
        return Err(CheckpointError::Continuity(format!(
            "chain leaf {} does not match the checkpoint body",
            current.body.checkpoint_seq
        )));
    }
    Ok((from_size, to_size))
}

fn validate_checkpoint_chain_commitments(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    chain_leaf_hashes: &[Hash],
    chain_tree: &MerkleTree,
) -> Result<(usize, usize), CheckpointError> {
    let (from_size, to_size) =
        validate_chain_leaves_for_pair(previous, current, chain_leaf_hashes)?;
    if let Some(from_chain_root) = previous.body.chain_root {
        if chain_tree.prefix_root(from_size)? != from_chain_root {
            return Err(CheckpointError::Continuity(format!(
                "predecessor {} chain_root does not match the retained checkpoint chain",
                previous.body.checkpoint_seq
            )));
        }
    }
    if let Some(to_chain_root) = current.body.chain_root {
        if chain_tree.prefix_root(to_size)? != to_chain_root {
            return Err(CheckpointError::Continuity(format!(
                "checkpoint {} chain_root does not extend the retained checkpoint chain",
                current.body.checkpoint_seq
            )));
        }
    }
    Ok((from_size, to_size))
}

fn build_checkpoint_consistency_proof_from_tree(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    chain_leaf_hashes: &[Hash],
    chain_tree: &MerkleTree,
) -> Result<CheckpointConsistencyProof, CheckpointError> {
    validate_checkpoint_predecessor(previous, current)?;
    let previous_log_id = checkpoint_log_id(previous);
    let current_log_id = checkpoint_log_id(current);
    if previous_log_id != current_log_id {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} derives log_id {} but predecessor {} derives {}",
            current.body.checkpoint_seq,
            current_log_id,
            previous.body.checkpoint_seq,
            previous_log_id
        )));
    }

    let from_chain_root = require_chain_root(previous)?;
    let to_chain_root = require_chain_root(current)?;
    let (from_size, to_size) =
        validate_checkpoint_chain_commitments(previous, current, chain_leaf_hashes, chain_tree)?;
    let chain_proof_hashes = chain_tree.consistency_proof_between(from_size, to_size)?;
    let from_leaf_inclusion = chain_tree.inclusion_proof_at_size(from_size - 1, from_size)?;
    let to_leaf_inclusion = chain_tree.inclusion_proof_at_size(to_size - 1, to_size)?;

    Ok(CheckpointConsistencyProof {
        schema: CHECKPOINT_CONSISTENCY_PROOF_SCHEMA.to_string(),
        log_id: current_log_id,
        from_checkpoint_seq: previous.body.checkpoint_seq,
        to_checkpoint_seq: current.body.checkpoint_seq,
        from_checkpoint_sha256: checkpoint_body_sha256(&previous.body)?,
        to_checkpoint_sha256: checkpoint_body_sha256(&current.body)?,
        from_log_tree_size: checkpoint_log_tree_size(&previous.body),
        to_log_tree_size: checkpoint_log_tree_size(&current.body),
        appended_entry_start_seq: current.body.batch_start_seq,
        appended_entry_end_seq: current.body.batch_end_seq,
        from_chain_root: Some(from_chain_root),
        to_chain_root: Some(to_chain_root),
        chain_proof_hashes,
        from_leaf_inclusion: Some(from_leaf_inclusion),
        to_leaf_inclusion: Some(to_leaf_inclusion),
    })
}

fn build_legacy_checkpoint_consistency_record(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
) -> Result<CheckpointConsistencyProof, CheckpointError> {
    validate_checkpoint_predecessor(previous, current)?;
    let previous_log_id = checkpoint_log_id(previous);
    let current_log_id = checkpoint_log_id(current);
    if previous_log_id != current_log_id {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} derives log_id {} but predecessor {} derives {}",
            current.body.checkpoint_seq,
            current_log_id,
            previous.body.checkpoint_seq,
            previous_log_id
        )));
    }
    if previous.body.schema != CHECKPOINT_SCHEMA_V1
        || current.body.schema != CHECKPOINT_SCHEMA_V1
        || previous.body.chain_root.is_some()
        || current.body.chain_root.is_some()
    {
        return Err(CheckpointError::Invalid(
            "legacy consistency records require two v1 checkpoints without chain commitments"
                .to_string(),
        ));
    }

    Ok(CheckpointConsistencyProof {
        schema: CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1.to_string(),
        log_id: current_log_id,
        from_checkpoint_seq: previous.body.checkpoint_seq,
        to_checkpoint_seq: current.body.checkpoint_seq,
        from_checkpoint_sha256: checkpoint_body_sha256(&previous.body)?,
        to_checkpoint_sha256: checkpoint_body_sha256(&current.body)?,
        from_log_tree_size: checkpoint_log_tree_size(&previous.body),
        to_log_tree_size: checkpoint_log_tree_size(&current.body),
        appended_entry_start_seq: current.body.batch_start_seq,
        appended_entry_end_seq: current.body.batch_end_seq,
        from_chain_root: None,
        to_chain_root: None,
        chain_proof_hashes: Vec::new(),
        from_leaf_inclusion: None,
        to_leaf_inclusion: None,
    })
}

/// Build a Merkle consistency proof showing that `current`'s chain commitment
/// is an append-only extension of `previous`'s.
///
/// `chain_leaf_hashes` must contain the chain leaf of every checkpoint from
/// sequence 1 through `current`, in order (see
/// [`checkpoint_chain_leaf_hash`]). Both checkpoints must carry a signed
/// `chain_root` and both roots must match the supplied leaves; the proof
/// fails to build rather than committing to unverified data.
pub fn build_checkpoint_consistency_proof(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    chain_leaf_hashes: &[Hash],
) -> Result<CheckpointConsistencyProof, CheckpointError> {
    let to_size = chain_tree_size(current)?;
    if chain_leaf_hashes.len() != to_size {
        return Err(CheckpointError::Continuity(format!(
            "chain leaf count {} does not match checkpoint {} chain size {}",
            chain_leaf_hashes.len(),
            current.body.checkpoint_seq,
            to_size
        )));
    }
    let tree = MerkleTree::from_hashes(chain_leaf_hashes.to_vec())?;
    build_checkpoint_consistency_proof_from_tree(previous, current, chain_leaf_hashes, &tree)
}

/// Verify a consistency proof against two signed checkpoints.
///
/// The Merkle path in the proof is checked against the `chain_root`
/// commitments inside the two signed bodies, so a verifier needs nothing
/// beyond the two checkpoints and the proof itself. Structural mismatches
/// (wrong pair, missing chain commitments, unsupported schema) are errors; a
/// well-formed proof that does not verify returns `Ok(false)`.
pub fn verify_checkpoint_consistency_proof(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    proof: &CheckpointConsistencyProof,
) -> Result<bool, CheckpointError> {
    validate_checkpoint_predecessor(previous, current)?;
    let previous_log_id = checkpoint_log_id(previous);
    let current_log_id = checkpoint_log_id(current);
    if previous_log_id != current_log_id {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} derives log_id {} but predecessor {} derives {}",
            current.body.checkpoint_seq,
            current_log_id,
            previous.body.checkpoint_seq,
            previous_log_id
        )));
    }
    let metadata_matches = proof.log_id == current_log_id
        && proof.from_checkpoint_seq == previous.body.checkpoint_seq
        && proof.to_checkpoint_seq == current.body.checkpoint_seq
        && proof.from_checkpoint_sha256 == checkpoint_body_sha256(&previous.body)?
        && proof.to_checkpoint_sha256 == checkpoint_body_sha256(&current.body)?
        && proof.from_log_tree_size == checkpoint_log_tree_size(&previous.body)
        && proof.to_log_tree_size == checkpoint_log_tree_size(&current.body)
        && proof.appended_entry_start_seq == current.body.batch_start_seq
        && proof.appended_entry_end_seq == current.body.batch_end_seq;
    if !metadata_matches {
        return Ok(false);
    }

    if proof.schema == CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1 {
        if previous.body.schema != CHECKPOINT_SCHEMA_V1
            || current.body.schema != CHECKPOINT_SCHEMA_V1
        {
            return Err(CheckpointError::Invalid(
                "legacy v1 consistency records apply only to v1 checkpoints".to_string(),
            ));
        }
        return Ok(proof.from_chain_root.is_none()
            && proof.to_chain_root.is_none()
            && proof.chain_proof_hashes.is_empty()
            && proof.from_leaf_inclusion.is_none()
            && proof.to_leaf_inclusion.is_none());
    }
    if proof.schema != CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V2 {
        return Err(CheckpointError::Invalid(format!(
            "unsupported consistency proof schema {}",
            proof.schema
        )));
    }
    let from_chain_root = require_chain_root(previous)?;
    let to_chain_root = require_chain_root(current)?;
    if proof.from_chain_root != Some(from_chain_root) || proof.to_chain_root != Some(to_chain_root)
    {
        return Ok(false);
    }
    let (Some(from_leaf_inclusion), Some(to_leaf_inclusion)) = (
        proof.from_leaf_inclusion.as_ref(),
        proof.to_leaf_inclusion.as_ref(),
    ) else {
        return Ok(false);
    };

    // Both committed chains must end in their own checkpoint's leaf. Binding
    // only the later endpoint would leave a pair starting after checkpoint 1
    // open: a key holder could commit an arbitrary tree as the earlier root,
    // extend it with the later real leaf, and produce paths that verify while
    // the earlier root never contained the earlier body.
    let from_size = chain_tree_size(previous)?;
    let to_size = chain_tree_size(current)?;
    if !chain_leaf_is_committed(
        from_leaf_inclusion,
        from_size,
        checkpoint_chain_leaf_hash(&previous.body)?,
        &from_chain_root,
    ) || !chain_leaf_is_committed(
        to_leaf_inclusion,
        to_size,
        checkpoint_chain_leaf_hash(&current.body)?,
        &to_chain_root,
    ) {
        return Ok(false);
    }

    Ok(verify_consistency_proof(
        from_size,
        to_size,
        &from_chain_root,
        &to_chain_root,
        &proof.chain_proof_hashes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn ordered_equivocation(
    kind: CheckpointEquivocationKind,
    log_id: Option<String>,
    log_tree_size: Option<u64>,
    first_seq: u64,
    first_sha256: String,
    second_seq: u64,
    second_sha256: String,
    previous_checkpoint_sha256: Option<String>,
) -> CheckpointEquivocation {
    if (first_seq, first_sha256.as_str()) <= (second_seq, second_sha256.as_str()) {
        CheckpointEquivocation {
            schema: CHECKPOINT_EQUIVOCATION_SCHEMA.to_string(),
            kind,
            log_id,
            log_tree_size,
            first_checkpoint_seq: first_seq,
            second_checkpoint_seq: second_seq,
            first_checkpoint_sha256: first_sha256,
            second_checkpoint_sha256: second_sha256,
            previous_checkpoint_sha256,
        }
    } else {
        CheckpointEquivocation {
            schema: CHECKPOINT_EQUIVOCATION_SCHEMA.to_string(),
            kind,
            log_id,
            log_tree_size,
            first_checkpoint_seq: second_seq,
            second_checkpoint_seq: first_seq,
            first_checkpoint_sha256: second_sha256,
            second_checkpoint_sha256: first_sha256,
            previous_checkpoint_sha256,
        }
    }
}

/// Detect whether two checkpoints conflict under Chio transparency semantics.
pub fn detect_checkpoint_equivocation(
    first: &KernelCheckpoint,
    second: &KernelCheckpoint,
) -> Result<Option<CheckpointEquivocation>, CheckpointError> {
    validate_checkpoint(first)?;
    validate_checkpoint(second)?;

    let first_sha256 = checkpoint_body_sha256(&first.body)?;
    let second_sha256 = checkpoint_body_sha256(&second.body)?;
    if first_sha256 == second_sha256 {
        return Ok(None);
    }

    let first_log_id = checkpoint_log_id(first);
    let second_log_id = checkpoint_log_id(second);
    let first_log_tree_size = checkpoint_log_tree_size(&first.body);
    let second_log_tree_size = checkpoint_log_tree_size(&second.body);

    if first.body.checkpoint_seq == second.body.checkpoint_seq {
        return Ok(Some(ordered_equivocation(
            CheckpointEquivocationKind::ConflictingCheckpointSeq,
            (first_log_id == second_log_id).then_some(first_log_id.clone()),
            (first_log_tree_size == second_log_tree_size).then_some(first_log_tree_size),
            first.body.checkpoint_seq,
            first_sha256,
            second.body.checkpoint_seq,
            second_sha256,
            first
                .body
                .previous_checkpoint_sha256
                .clone()
                .or_else(|| second.body.previous_checkpoint_sha256.clone()),
        )));
    }

    if first_log_id == second_log_id && first_log_tree_size == second_log_tree_size {
        return Ok(Some(ordered_equivocation(
            CheckpointEquivocationKind::ConflictingLogTreeSize,
            Some(first_log_id),
            Some(first_log_tree_size),
            first.body.checkpoint_seq,
            first_sha256,
            second.body.checkpoint_seq,
            second_sha256,
            first
                .body
                .previous_checkpoint_sha256
                .clone()
                .or_else(|| second.body.previous_checkpoint_sha256.clone()),
        )));
    }

    if first.body.previous_checkpoint_sha256.is_some()
        && first.body.previous_checkpoint_sha256 == second.body.previous_checkpoint_sha256
    {
        return Ok(Some(ordered_equivocation(
            CheckpointEquivocationKind::ConflictingPredecessorWitness,
            (first_log_id == second_log_id).then_some(first_log_id),
            None,
            first.body.checkpoint_seq,
            first_sha256,
            second.body.checkpoint_seq,
            second_sha256,
            first.body.previous_checkpoint_sha256.clone(),
        )));
    }

    Ok(None)
}

/// Render a checkpoint conflict as a stable, human-readable description.
#[must_use]
pub fn describe_checkpoint_equivocation(equivocation: &CheckpointEquivocation) -> String {
    match equivocation.kind {
        CheckpointEquivocationKind::ConflictingCheckpointSeq => format!(
            "checkpoint_seq {} has conflicting digests {} and {}",
            equivocation.first_checkpoint_seq,
            equivocation.first_checkpoint_sha256,
            equivocation.second_checkpoint_sha256
        ),
        CheckpointEquivocationKind::ConflictingLogTreeSize => format!(
            "log {} has conflicting checkpoints at cumulative tree size {}: {} ({}) vs {} ({})",
            equivocation.log_id.as_deref().unwrap_or("<unknown>"),
            equivocation.log_tree_size.unwrap_or_default(),
            equivocation.first_checkpoint_seq,
            equivocation.first_checkpoint_sha256,
            equivocation.second_checkpoint_seq,
            equivocation.second_checkpoint_sha256
        ),
        CheckpointEquivocationKind::ConflictingPredecessorWitness => format!(
            "predecessor digest {} is witnessed by conflicting checkpoints {} ({}) and {} ({})",
            equivocation
                .previous_checkpoint_sha256
                .as_deref()
                .unwrap_or("<missing>"),
            equivocation.first_checkpoint_seq,
            equivocation.first_checkpoint_sha256,
            equivocation.second_checkpoint_seq,
            equivocation.second_checkpoint_sha256
        ),
    }
}

/// Derive publication, witness, and equivocation records from a checkpoint set.
pub fn build_checkpoint_transparency(
    checkpoints: &[KernelCheckpoint],
) -> Result<CheckpointTransparencySummary, CheckpointError> {
    let mut publications = Vec::with_capacity(checkpoints.len());
    let mut by_digest = BTreeMap::<String, &KernelCheckpoint>::new();

    for checkpoint in checkpoints {
        publications.push(build_checkpoint_publication(checkpoint)?);
        by_digest.insert(checkpoint_body_sha256(&checkpoint.body)?, checkpoint);
    }

    publications.sort_by_key(|publication| publication.checkpoint_seq);

    let mut equivocations = Vec::new();
    for (index, checkpoint) in checkpoints.iter().enumerate() {
        for conflicting in checkpoints.iter().skip(index + 1) {
            if let Some(equivocation) = detect_checkpoint_equivocation(checkpoint, conflicting)? {
                equivocations.push(equivocation);
            }
        }
    }
    equivocations.sort();
    equivocations.dedup();
    let equivocated_digests = equivocations
        .iter()
        .flat_map(|equivocation| {
            [
                equivocation.first_checkpoint_sha256.clone(),
                equivocation.second_checkpoint_sha256.clone(),
            ]
        })
        .collect::<BTreeSet<_>>();

    // The signed chain commitment is global across checkpoint signing-key
    // rotation. Derive its leaves from the contiguous, unique sequence run
    // beginning at 1, then restrict proof endpoints to a common log identity.
    // This preserves proofs between checkpoints signed by the post-rotation
    // key without incorrectly requiring that key to have issued sequence 1.
    let mut by_seq = BTreeMap::<u64, Vec<&KernelCheckpoint>>::new();
    for checkpoint in checkpoints {
        by_seq
            .entry(checkpoint.body.checkpoint_seq)
            .or_default()
            .push(checkpoint);
    }
    let mut chain_leaf_hashes = Vec::new();
    let mut next_seq = 1u64;
    while let Some([single]) = by_seq.get(&next_seq).map(Vec::as_slice) {
        chain_leaf_hashes.push(checkpoint_chain_leaf_hash(&single.body)?);
        let Some(following) = next_seq.checked_add(1) else {
            break;
        };
        next_seq = following;
    }
    let chain_tree = (!chain_leaf_hashes.is_empty())
        .then(|| MerkleTree::from_hashes(chain_leaf_hashes.clone()))
        .transpose()?;

    let mut witnesses = Vec::new();
    let mut consistency_proofs = Vec::new();
    for checkpoint in checkpoints {
        let Some(previous_checkpoint_sha256) =
            checkpoint.body.previous_checkpoint_sha256.as_deref()
        else {
            continue;
        };
        if let Some(previous) = by_digest.get(previous_checkpoint_sha256) {
            let checkpoint_sha256 = checkpoint_body_sha256(&checkpoint.body)?;
            if let Err(error) = validate_checkpoint_predecessor(previous, checkpoint) {
                if equivocated_digests.contains(&checkpoint_sha256) {
                    continue;
                }
                return Err(error);
            }
            witnesses.push(build_checkpoint_witness(previous, checkpoint)?);
            let log_id = checkpoint_log_id(checkpoint);
            let to_size = chain_tree_size(checkpoint)?;
            if let Some(tree) = chain_tree.as_ref() {
                if chain_leaf_hashes.len() >= to_size {
                    // The checkpoint-chain commitment is global. Verify both
                    // signed roots against the retained prefix even when a
                    // signing-key rotation changes the derived log identity.
                    validate_checkpoint_chain_commitments(
                        previous,
                        checkpoint,
                        &chain_leaf_hashes,
                        tree,
                    )?;
                    if checkpoint_log_id(previous) == log_id {
                        if previous.body.schema == CHECKPOINT_SCHEMA_V1
                            && checkpoint.body.schema == CHECKPOINT_SCHEMA_V1
                        {
                            consistency_proofs.push(build_legacy_checkpoint_consistency_record(
                                previous, checkpoint,
                            )?);
                        } else if previous.body.chain_root.is_some()
                            && checkpoint.body.chain_root.is_some()
                        {
                            consistency_proofs.push(build_checkpoint_consistency_proof_from_tree(
                                previous,
                                checkpoint,
                                &chain_leaf_hashes,
                                tree,
                            )?);
                        }
                    }
                }
            }
        }
    }
    witnesses.sort_by_key(|witness| (witness.witness_checkpoint_seq, witness.checkpoint_seq));
    consistency_proofs.sort_by_key(|proof| (proof.to_checkpoint_seq, proof.from_checkpoint_seq));

    Ok(CheckpointTransparencySummary {
        publications,
        witnesses,
        consistency_proofs,
        equivocations,
    })
}

/// Validate that a checkpoint set is transparency-safe, fork-free, and
/// connected to checkpoint 1.
///
/// A caller that wants to trust a later boundary without the full prefix must
/// use a separate API that accepts an explicitly pinned boundary. This
/// verifier has no such input, so an unresolved predecessor fails closed.
pub fn validate_checkpoint_transparency(
    checkpoints: &[KernelCheckpoint],
) -> Result<CheckpointTransparencySummary, CheckpointError> {
    let mut checkpoint_seqs = BTreeSet::new();
    for checkpoint in checkpoints {
        if !checkpoint_seqs.insert(checkpoint.body.checkpoint_seq) {
            return Err(CheckpointError::Continuity(format!(
                "duplicate checkpoint sequence {}",
                checkpoint.body.checkpoint_seq
            )));
        }
    }

    let transparency = build_checkpoint_transparency(checkpoints)?;
    if let Some(equivocation) = transparency.equivocations.first() {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint equivocation detected: {}",
            describe_checkpoint_equivocation(equivocation)
        )));
    }

    let mut by_digest = BTreeMap::<String, &KernelCheckpoint>::new();
    for checkpoint in checkpoints {
        by_digest.insert(checkpoint_body_sha256(&checkpoint.body)?, checkpoint);
    }
    for checkpoint in checkpoints {
        let Some(previous_checkpoint_sha256) =
            checkpoint.body.previous_checkpoint_sha256.as_deref()
        else {
            if checkpoint.body.checkpoint_seq != 1 {
                return Err(CheckpointError::Continuity(format!(
                    "checkpoint {} is not connected to checkpoint 1",
                    checkpoint.body.checkpoint_seq
                )));
            }
            if checkpoint.body.batch_start_seq != 1 {
                return Err(CheckpointError::Continuity(format!(
                    "checkpoint 1 must start at receipt 1, got {}",
                    checkpoint.body.batch_start_seq
                )));
            }
            continue;
        };
        let previous = by_digest.get(previous_checkpoint_sha256).ok_or_else(|| {
            CheckpointError::Continuity(format!(
                "checkpoint {} has unresolved predecessor {}",
                checkpoint.body.checkpoint_seq, previous_checkpoint_sha256
            ))
        })?;
        validate_checkpoint_predecessor(previous, checkpoint)?;
    }

    Ok(transparency)
}

/// Verify that supplied transparency records match the signed checkpoint set.
///
/// Valid trust-anchor bindings are preserved in the returned summary so callers
/// can safely project publication state without collapsing back to raw
/// checkpoint-only records.
pub fn verify_checkpoint_transparency_records(
    checkpoints: &[KernelCheckpoint],
    supplied: &CheckpointTransparencySummary,
) -> Result<CheckpointTransparencySummary, CheckpointError> {
    let derived = validate_checkpoint_transparency(checkpoints)?;
    let checkpoints_by_seq = checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.body.checkpoint_seq, checkpoint))
        .collect::<BTreeMap<_, _>>();
    let derived_publications = derived
        .publications
        .iter()
        .map(|publication| (publication.checkpoint_seq, publication))
        .collect::<BTreeMap<_, _>>();

    if supplied.publications.len() != derived.publications.len() {
        return Err(CheckpointError::Continuity(
            "checkpoint publication records do not match the signed checkpoint set".to_string(),
        ));
    }

    let mut normalized_publications = Vec::with_capacity(supplied.publications.len());
    let mut matched_checkpoint_seqs = BTreeSet::new();
    for publication in &supplied.publications {
        if !matched_checkpoint_seqs.insert(publication.checkpoint_seq) {
            return Err(CheckpointError::Continuity(format!(
                "duplicate checkpoint publication record for checkpoint {}",
                publication.checkpoint_seq
            )));
        }
        let Some(derived_publication) = derived_publications
            .get(&publication.checkpoint_seq)
            .copied()
        else {
            return Err(CheckpointError::Continuity(
                "checkpoint publication records do not match the signed checkpoint set".to_string(),
            ));
        };
        let expected = match publication.trust_anchor_binding.clone() {
            Some(binding) => {
                let checkpoint = checkpoints_by_seq
                    .get(&publication.checkpoint_seq)
                    .copied()
                    .ok_or_else(|| {
                        CheckpointError::Continuity(format!(
                            "checkpoint publication {} references a missing checkpoint",
                            publication.checkpoint_seq
                        ))
                    })?;
                build_trust_anchored_checkpoint_publication(checkpoint, binding)?
            }
            None => (*derived_publication).clone(),
        };
        if publication != &expected {
            return Err(CheckpointError::Continuity(
                "checkpoint publication records do not match the signed checkpoint set".to_string(),
            ));
        }
        normalized_publications.push(expected);
    }
    if matched_checkpoint_seqs.len() != derived_publications.len() {
        return Err(CheckpointError::Continuity(
            "checkpoint publication records do not cover the signed checkpoint set".to_string(),
        ));
    }

    if supplied.witnesses != derived.witnesses {
        return Err(CheckpointError::Continuity(
            "checkpoint witness records do not match the signed checkpoint set".to_string(),
        ));
    }
    if supplied.consistency_proofs != derived.consistency_proofs {
        return Err(CheckpointError::Continuity(
            "checkpoint consistency proof records do not match the signed checkpoint set"
                .to_string(),
        ));
    }
    if supplied.equivocations != derived.equivocations {
        return Err(CheckpointError::Continuity(
            "checkpoint equivocation records do not match the signed checkpoint set".to_string(),
        ));
    }

    Ok(CheckpointTransparencySummary {
        publications: normalized_publications,
        witnesses: supplied.witnesses.clone(),
        consistency_proofs: supplied.consistency_proofs.clone(),
        equivocations: supplied.equivocations.clone(),
    })
}

/// Verify that `current` explicitly extends `previous`.
pub fn verify_checkpoint_continuity(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
) -> Result<bool, CheckpointError> {
    match validate_checkpoint_predecessor(previous, current) {
        Ok(()) => Ok(true),
        Err(CheckpointError::Continuity(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return the current Unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a signed kernel checkpoint from a batch of canonical receipt bytes.
///
/// `receipt_canonical_bytes_batch` must not be empty. The first checkpoint of
/// a chain (`checkpoint_seq == 1`) commits a single-leaf chain; a detached
/// checkpoint at a later sequence is issued without a chain commitment.
pub fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        keypair,
        None,
        &[],
    )
}

/// Build a signed kernel checkpoint that explicitly links to the previous
/// checkpoint when provided.
///
/// `prior_chain_leaf_hashes` must hold the chain leaf of every prior
/// checkpoint in sequence order (see [`checkpoint_chain_leaf_hash`]); the new
/// body then carries a `chain_root` extending them, and the leaves are
/// cross-checked against the predecessor's own commitment when it has one. An
/// empty slice is valid only with no previous checkpoint.
pub fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain_leaf_hashes: &[Hash],
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_chain_frontier(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        receipt_canonical_bytes_batch,
        keypair,
        previous_checkpoint,
        &CheckpointChainFrontier::from_leaves(prior_chain_leaf_hashes),
    )
}

/// Build a signed kernel checkpoint from the chain frontier rather than from
/// every prior leaf.
///
/// This is the hot path: a long-lived writer keeps the frontier and extends
/// it, so issuing a checkpoint costs O(log n) hashes instead of rehashing the
/// whole chain. The predecessor's signed `chain_root` is still checked, at the
/// same O(log n) cost, so the integrity guarantee is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint_with_chain_frontier(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
    prior_chain: &CheckpointChainFrontier,
) -> Result<KernelCheckpoint, CheckpointError> {
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)?;
    let merkle_root = tree.root();
    let covered_entries = batch_end_seq
        .checked_sub(batch_start_seq)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            CheckpointError::Invalid(format!(
                "invalid checkpoint entry range {batch_start_seq}-{batch_end_seq}"
            ))
        })?;
    if usize::try_from(covered_entries).ok() != Some(tree.leaf_count()) {
        return Err(CheckpointError::Invalid(format!(
            "receipt batch length {} does not match covered entry count {} for range {}-{}",
            tree.leaf_count(),
            covered_entries,
            batch_start_seq,
            batch_end_seq
        )));
    }

    let own_chain_leaf = checkpoint_chain_leaf_hash_from_parts(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        merkle_root,
    )?;
    let chain_root = match previous_checkpoint {
        None => {
            if prior_chain.leaf_count() != 0 {
                return Err(CheckpointError::Invalid(
                    "prior chain leaves supplied without a previous checkpoint".to_string(),
                ));
            }
            (checkpoint_seq == 1)
                .then(|| checkpoint_chain_root(&[own_chain_leaf]))
                .transpose()?
        }
        Some(previous) => {
            if prior_chain.leaf_count() != previous.body.checkpoint_seq {
                return Err(CheckpointError::Continuity(format!(
                    "prior chain covers {} leaves but predecessor is checkpoint {}",
                    prior_chain.leaf_count(),
                    previous.body.checkpoint_seq
                )));
            }
            // When the predecessor committed a chain, the frontier must
            // reproduce exactly that commitment: this is what stops a stale or
            // foreign frontier from being extended into a signed root.
            if let Some(previous_chain_root) = previous.body.chain_root {
                if prior_chain.root() != Some(previous_chain_root) {
                    return Err(CheckpointError::Continuity(format!(
                        "predecessor {} chain_root does not match the supplied chain",
                        previous.body.checkpoint_seq
                    )));
                }
            }
            let mut chain = prior_chain.clone();
            chain.append(own_chain_leaf);
            chain.root()
        }
    };

    let body = KernelCheckpointBody {
        schema: CHECKPOINT_SCHEMA.to_string(),
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        tree_size: tree.leaf_count(),
        merkle_root,
        issued_at: unix_now(),
        kernel_key: keypair.public_key(),
        previous_checkpoint_sha256: previous_checkpoint
            .map(|checkpoint| checkpoint_body_sha256(&checkpoint.body))
            .transpose()?,
        chain_root,
    };
    let body_bytes =
        canonical_json_bytes(&body).map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    let signature = keypair.sign(&body_bytes);
    Ok(KernelCheckpoint { body, signature })
}

/// Build an inclusion proof for a leaf in an already-built MerkleTree.
pub fn build_inclusion_proof(
    tree: &MerkleTree,
    leaf_index: usize,
    checkpoint_seq: u64,
    receipt_seq: u64,
) -> Result<ReceiptInclusionProof, CheckpointError> {
    let proof = tree.inclusion_proof(leaf_index)?;
    Ok(ReceiptInclusionProof {
        checkpoint_seq,
        receipt_seq,
        leaf_index,
        merkle_root: tree.root(),
        proof,
    })
}

/// Verify the signature on a KernelCheckpoint.
///
/// Returns `Ok(true)` if the signature is valid.
pub fn verify_checkpoint_signature(checkpoint: &KernelCheckpoint) -> Result<bool, CheckpointError> {
    let body_bytes = canonical_json_bytes(&checkpoint.body)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    Ok(checkpoint
        .body
        .kernel_key
        .verify(&body_bytes, &checkpoint.signature))
}

/// Validate the integrity of a single checkpoint statement.
pub fn validate_checkpoint(checkpoint: &KernelCheckpoint) -> Result<(), CheckpointError> {
    if !is_supported_checkpoint_schema(&checkpoint.body.schema) {
        return Err(CheckpointError::Invalid(format!(
            "unsupported checkpoint schema {}",
            checkpoint.body.schema
        )));
    }
    if checkpoint.body.checkpoint_seq == 0 {
        return Err(CheckpointError::Invalid(
            "checkpoint_seq must be greater than zero".to_string(),
        ));
    }
    if checkpoint.body.batch_start_seq == 0 {
        return Err(CheckpointError::Invalid(
            "batch_start_seq must be greater than zero".to_string(),
        ));
    }
    if checkpoint.body.batch_end_seq < checkpoint.body.batch_start_seq {
        return Err(CheckpointError::Invalid(format!(
            "batch_end_seq {} is less than batch_start_seq {}",
            checkpoint.body.batch_end_seq, checkpoint.body.batch_start_seq
        )));
    }
    if checkpoint.body.tree_size == 0 {
        return Err(CheckpointError::Invalid(
            "tree_size must be greater than zero".to_string(),
        ));
    }
    if checkpoint.body.issued_at == 0 {
        return Err(CheckpointError::Invalid(
            "issued_at must be greater than zero".to_string(),
        ));
    }
    if checkpoint
        .body
        .previous_checkpoint_sha256
        .as_deref()
        .is_some_and(|digest| !is_lowercase_sha256(digest))
    {
        return Err(CheckpointError::Invalid(
            "previous_checkpoint_sha256 must be 64 lowercase hex characters".to_string(),
        ));
    }
    let expected_tree_size = checkpoint_batch_entry_count(&checkpoint.body)?;
    if u64::try_from(checkpoint.body.tree_size).ok() != Some(expected_tree_size) {
        return Err(CheckpointError::Invalid(format!(
            "tree_size {} does not match covered entry count {} for range {}-{}",
            checkpoint.body.tree_size,
            expected_tree_size,
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        )));
    }
    if checkpoint.body.schema == CHECKPOINT_SCHEMA_V1 && checkpoint.body.chain_root.is_some() {
        return Err(CheckpointError::Invalid(
            "v1 checkpoint statements cannot carry chain_root".to_string(),
        ));
    }
    if checkpoint.body.schema == CHECKPOINT_SCHEMA_V2
        && checkpoint.body.checkpoint_seq == 1
        && checkpoint.body.chain_root.is_none()
    {
        return Err(CheckpointError::Invalid(
            "v2 checkpoint 1 must carry chain_root".to_string(),
        ));
    }
    if let Some(chain_root) = checkpoint.body.chain_root {
        if checkpoint.body.checkpoint_seq == 1
            && chain_root
                != checkpoint_chain_root(&[checkpoint_chain_leaf_hash(&checkpoint.body)?])?
        {
            return Err(CheckpointError::Invalid(
                "chain_root of the first checkpoint does not commit its own chain leaf".to_string(),
            ));
        }
    }
    if !verify_checkpoint_signature(checkpoint)? {
        return Err(CheckpointError::InvalidSignature);
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate that `checkpoint` cleanly extends `predecessor`.
pub fn validate_checkpoint_predecessor(
    predecessor: &KernelCheckpoint,
    checkpoint: &KernelCheckpoint,
) -> Result<(), CheckpointError> {
    validate_checkpoint(predecessor)?;
    validate_checkpoint(checkpoint)?;

    let expected_checkpoint_seq =
        predecessor
            .body
            .checkpoint_seq
            .checked_add(1)
            .ok_or_else(|| {
                CheckpointError::Continuity("predecessor checkpoint_seq overflowed u64".to_string())
            })?;
    if checkpoint.body.checkpoint_seq != expected_checkpoint_seq {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint_seq {} does not immediately follow predecessor {}",
            checkpoint.body.checkpoint_seq, predecessor.body.checkpoint_seq
        )));
    }

    let expected_batch_start = predecessor
        .body
        .batch_end_seq
        .checked_add(1)
        .ok_or_else(|| {
            CheckpointError::Continuity("predecessor batch_end_seq overflowed u64".to_string())
        })?;
    if checkpoint.body.batch_start_seq != expected_batch_start {
        return Err(CheckpointError::Continuity(format!(
            "batch_start_seq {} does not immediately follow predecessor batch_end_seq {}",
            checkpoint.body.batch_start_seq, predecessor.body.batch_end_seq
        )));
    }

    let Some(previous_checkpoint_sha256) = checkpoint.body.previous_checkpoint_sha256.as_deref()
    else {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} is missing predecessor digest",
            checkpoint.body.checkpoint_seq
        )));
    };
    let expected_previous_checkpoint_sha256 = checkpoint_body_sha256(&predecessor.body)?;
    if previous_checkpoint_sha256 != expected_previous_checkpoint_sha256 {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} does not match predecessor digest {}",
            checkpoint.body.checkpoint_seq, expected_previous_checkpoint_sha256
        )));
    }

    if predecessor.body.chain_root.is_some() && checkpoint.body.chain_root.is_none() {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} drops the chain commitment its predecessor carries",
            checkpoint.body.checkpoint_seq
        )));
    }
    if checkpoint.body.schema == CHECKPOINT_SCHEMA_V2 && checkpoint.body.chain_root.is_none() {
        return Err(CheckpointError::Continuity(format!(
            "v2 checkpoint {} does not start or extend the chain commitment",
            checkpoint.body.checkpoint_seq
        )));
    }

    Ok(())
}

#[cfg(test)]
#[path = "checkpoint/tests.rs"]
mod tests;
