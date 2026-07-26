//! Merkle-committed receipt batch checkpointing.
//!
//! Produces signed kernel checkpoint statements that commit a batch of receipts
//! to a Merkle root. Inclusion proofs allow verifying that a specific receipt
//! was part of a batch without replaying the entire log.
//!
//! Schema: "chio.checkpoint_statement.v1"

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
use serde::{Deserialize, Serialize};

use crate::ReceiptStoreError;

pub const CHECKPOINT_SCHEMA: &str = "chio.checkpoint_statement.v1";
pub const CHECKPOINT_PUBLICATION_SCHEMA: &str = "chio.checkpoint_publication.v1";
pub const CHECKPOINT_WITNESS_SCHEMA: &str = "chio.checkpoint_witness.v1";
pub const CHECKPOINT_CONSISTENCY_PROOF_SCHEMA: &str = "chio.checkpoint_consistency_proof.v1";
pub const CHECKPOINT_EQUIVOCATION_SCHEMA: &str = "chio.checkpoint_equivocation.v1";

#[must_use]
pub fn is_supported_checkpoint_schema(schema: &str) -> bool {
    schema == CHECKPOINT_SCHEMA
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_sha256: Option<String>,
    /// RFC 6962 root over the checkpoint-chain leaves for checkpoint_seq 1
    /// through this checkpoint, one leaf per checkpoint binding its sequence,
    /// entry range, and batch root (see [`checkpoint_chain_leaf_hash`]). This
    /// is the commitment that consistency proofs verify against. Absent on
    /// checkpoints issued before the chain commitment existed and on detached
    /// checkpoints built without chain context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Signed chain commitment of the earlier checkpoint.
    pub from_chain_root: Hash,
    /// Signed chain commitment of the later checkpoint.
    pub to_chain_root: Hash,
    /// RFC 6962 consistency path from the earlier chain tree to the later
    /// chain tree.
    pub chain_proof_hashes: Vec<Hash>,
    /// Inclusion proof binding the earlier checkpoint's own chain leaf to
    /// `from_chain_root` at the last position of that tree.
    pub from_leaf_inclusion: MerkleProof,
    /// Inclusion proof binding the later checkpoint's own chain leaf to
    /// `to_chain_root` at the last position. Without both endpoints bound, a
    /// key holder could commit chain trees whose leaves are unrelated to the
    /// bodies the proof names and still produce a verifying consistency path.
    pub to_leaf_inclusion: MerkleProof,
}

/// Whether `leaf` is committed by `root` as the final leaf of a `size`-leaf
/// chain tree, per the supplied inclusion proof.
fn chain_leaf_is_committed(inclusion: &MerkleProof, size: usize, leaf: Hash, root: &Hash) -> bool {
    inclusion.tree_size == size
        && inclusion.leaf_index + 1 == size
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
    if chain_leaf_hashes.len() != to_size {
        return Err(CheckpointError::Continuity(format!(
            "chain leaf count {} does not match checkpoint {} chain size {}",
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
        validate_chain_leaves_for_pair(previous, current, chain_leaf_hashes)?;
    if checkpoint_chain_root(&chain_leaf_hashes[..from_size])? != from_chain_root {
        return Err(CheckpointError::Continuity(format!(
            "predecessor {} chain_root does not match the supplied chain leaves",
            previous.body.checkpoint_seq
        )));
    }
    let tree = MerkleTree::from_hashes(chain_leaf_hashes.to_vec())?;
    if tree.root() != to_chain_root {
        return Err(CheckpointError::Continuity(format!(
            "checkpoint {} chain_root does not match the supplied chain leaves",
            current.body.checkpoint_seq
        )));
    }
    let chain_proof_hashes = tree.consistency_proof(from_size)?;
    let to_leaf_inclusion = tree.inclusion_proof(to_size - 1)?;
    let from_leaf_inclusion = MerkleTree::from_hashes(chain_leaf_hashes[..from_size].to_vec())?
        .inclusion_proof(from_size - 1)?;

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
        from_chain_root,
        to_chain_root,
        chain_proof_hashes,
        from_leaf_inclusion,
        to_leaf_inclusion,
    })
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
    if proof.schema != CHECKPOINT_CONSISTENCY_PROOF_SCHEMA {
        return Err(CheckpointError::Invalid(format!(
            "unsupported consistency proof schema {}",
            proof.schema
        )));
    }
    let from_chain_root = require_chain_root(previous)?;
    let to_chain_root = require_chain_root(current)?;

    let metadata_matches = proof.log_id == current_log_id
        && proof.from_checkpoint_seq == previous.body.checkpoint_seq
        && proof.to_checkpoint_seq == current.body.checkpoint_seq
        && proof.from_checkpoint_sha256 == checkpoint_body_sha256(&previous.body)?
        && proof.to_checkpoint_sha256 == checkpoint_body_sha256(&current.body)?
        && proof.from_log_tree_size == checkpoint_log_tree_size(&previous.body)
        && proof.to_log_tree_size == checkpoint_log_tree_size(&current.body)
        && proof.appended_entry_start_seq == current.body.batch_start_seq
        && proof.appended_entry_end_seq == current.body.batch_end_seq
        && proof.from_chain_root == from_chain_root
        && proof.to_chain_root == to_chain_root;
    if !metadata_matches {
        return Ok(false);
    }

    // Both committed chains must end in their own checkpoint's leaf. Binding
    // only the later endpoint would leave a pair starting after checkpoint 1
    // open: a key holder could commit an arbitrary tree as the earlier root,
    // extend it with the later real leaf, and produce paths that verify while
    // the earlier root never contained the earlier body.
    let from_size = chain_tree_size(previous)?;
    let to_size = chain_tree_size(current)?;
    if !chain_leaf_is_committed(
        &proof.from_leaf_inclusion,
        from_size,
        checkpoint_chain_leaf_hash(&previous.body)?,
        &from_chain_root,
    ) || !chain_leaf_is_committed(
        &proof.to_leaf_inclusion,
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

    // Chain leaves are derivable only for the contiguous, unique run of
    // sequences starting at 1; a consistency proof needs every leaf up to its
    // later checkpoint, so pairs beyond that run (or without signed chain
    // commitments) yield witness records but no proof.
    // Runs are per log: a set may carry checkpoints from several independent
    // logs whose sequences interleave, and mixing their leaves would build a
    // chain that belongs to neither.
    let mut by_log_seq = BTreeMap::<(String, u64), Vec<&KernelCheckpoint>>::new();
    for checkpoint in checkpoints {
        by_log_seq
            .entry((
                checkpoint_log_id(checkpoint),
                checkpoint.body.checkpoint_seq,
            ))
            .or_default()
            .push(checkpoint);
    }
    let mut chain_leaf_hashes_by_log = BTreeMap::<String, Vec<Hash>>::new();
    for (log_id, _) in by_log_seq.keys() {
        if chain_leaf_hashes_by_log.contains_key(log_id) {
            continue;
        }
        let mut chain_leaf_hashes = Vec::new();
        let mut next_seq = 1u64;
        while let Some([single]) = by_log_seq
            .get(&(log_id.clone(), next_seq))
            .map(Vec::as_slice)
        {
            chain_leaf_hashes.push(checkpoint_chain_leaf_hash(&single.body)?);
            let Some(following) = next_seq.checked_add(1) else {
                break;
            };
            next_seq = following;
        }
        chain_leaf_hashes_by_log.insert(log_id.clone(), chain_leaf_hashes);
    }

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
            if checkpoint_log_id(previous) == log_id
                && previous.body.chain_root.is_some()
                && checkpoint.body.chain_root.is_some()
            {
                let to_size = chain_tree_size(checkpoint)?;
                if let Some(chain_leaf_hashes) = chain_leaf_hashes_by_log
                    .get(&log_id)
                    .filter(|leaves| leaves.len() >= to_size)
                {
                    consistency_proofs.push(build_checkpoint_consistency_proof(
                        previous,
                        checkpoint,
                        &chain_leaf_hashes[..to_size],
                    )?);
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

/// Validate that a checkpoint set is transparency-safe and fork-free.
pub fn validate_checkpoint_transparency(
    checkpoints: &[KernelCheckpoint],
) -> Result<CheckpointTransparencySummary, CheckpointError> {
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
            continue;
        };
        if let Some(previous) = by_digest.get(previous_checkpoint_sha256) {
            validate_checkpoint_predecessor(previous, checkpoint)?;
        }
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
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)?;
    let merkle_root = tree.root();

    let own_chain_leaf = checkpoint_chain_leaf_hash_from_parts(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        merkle_root,
    )?;
    let chain_root = match previous_checkpoint {
        None => {
            if !prior_chain_leaf_hashes.is_empty() {
                return Err(CheckpointError::Invalid(
                    "prior chain leaves supplied without a previous checkpoint".to_string(),
                ));
            }
            (checkpoint_seq == 1)
                .then(|| checkpoint_chain_root(&[own_chain_leaf]))
                .transpose()?
        }
        Some(previous) => {
            if prior_chain_leaf_hashes.len() as u64 != previous.body.checkpoint_seq {
                return Err(CheckpointError::Continuity(format!(
                    "prior chain leaf count {} does not match predecessor checkpoint_seq {}",
                    prior_chain_leaf_hashes.len(),
                    previous.body.checkpoint_seq
                )));
            }
            if prior_chain_leaf_hashes.last() != Some(&checkpoint_chain_leaf_hash(&previous.body)?)
            {
                return Err(CheckpointError::Continuity(format!(
                    "last prior chain leaf does not match predecessor checkpoint {}",
                    previous.body.checkpoint_seq
                )));
            }
            if let Some(previous_chain_root) = previous.body.chain_root {
                if checkpoint_chain_root(prior_chain_leaf_hashes)? != previous_chain_root {
                    return Err(CheckpointError::Continuity(format!(
                        "predecessor {} chain_root does not match the supplied chain leaves",
                        previous.body.checkpoint_seq
                    )));
                }
            }
            let mut chain = prior_chain_leaf_hashes.to_vec();
            chain.push(own_chain_leaf);
            Some(checkpoint_chain_root(&chain)?)
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt_bytes(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("{{\"receipt_id\":\"rcpt-{i:04}\",\"seq\":{i}}}").into_bytes())
            .collect()
    }

    fn chain_leaves(checkpoints: &[&KernelCheckpoint]) -> Vec<Hash> {
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint_chain_leaf_hash(&checkpoint.body).expect("chain leaf"))
            .collect()
    }

    #[test]
    fn build_checkpoint_100_has_tree_size_100() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(100);
        let cp = build_checkpoint(1, 1, 100, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.tree_size, 100);
    }

    #[test]
    fn build_checkpoint_signature_verifies() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(10);
        let cp = build_checkpoint(1, 1, 10, &batch, &kp).expect("build_checkpoint failed");
        assert!(
            verify_checkpoint_signature(&cp).expect("verify failed"),
            "signature should be valid"
        );
    }

    #[test]
    fn build_checkpoint_wrong_key_fails_verification() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let mut cp = build_checkpoint(1, 1, 5, &batch, &kp1).expect("build_checkpoint failed");
        // Replace the kernel_key with a different key -- signature no longer matches.
        cp.body.kernel_key = kp2.public_key();
        assert!(
            !verify_checkpoint_signature(&cp).expect("verify call failed"),
            "tampered key should fail"
        );
    }

    #[test]
    fn build_checkpoint_single_receipt() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(1);
        let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.tree_size, 1);
        assert!(
            verify_checkpoint_signature(&cp).expect("verify failed"),
            "single-receipt checkpoint should have valid signature"
        );
    }

    #[test]
    fn build_checkpoint_single_receipt_merkle_root_equals_leaf_hash() {
        // Degenerate case: a single-receipt batch must produce a Merkle root
        // equal to the leaf hash of that receipt's canonical bytes (per RFC 6962:
        // LeafHash(bytes) = SHA256(0x00 || bytes)).
        use chio_core::merkle::leaf_hash;

        let kp = Keypair::generate();
        let leaf_bytes = b"single-receipt-canonical-bytes";
        let batch = vec![leaf_bytes.to_vec()];
        let cp = build_checkpoint(1, 1, 1, &batch, &kp).expect("build_checkpoint failed");

        let expected_root = leaf_hash(leaf_bytes);
        assert_eq!(
            cp.body.merkle_root, expected_root,
            "single-receipt checkpoint merkle_root must equal leaf_hash of the receipt bytes"
        );
        assert_eq!(cp.body.tree_size, 1);
        assert!(
            verify_checkpoint_signature(&cp).expect("verify failed"),
            "single-receipt checkpoint signature should verify"
        );
    }

    #[test]
    fn schema_is_v1() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(3);
        let cp = build_checkpoint(1, 1, 3, &batch, &kp).expect("build_checkpoint failed");
        assert_eq!(cp.body.schema, CHECKPOINT_SCHEMA);
        assert!(cp.body.previous_checkpoint_sha256.is_none());
    }

    #[test]
    fn build_checkpoint_with_previous_sets_continuity_hash() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp)
            .expect("first checkpoint build failed");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second checkpoint build failed");
        let expected_previous_checkpoint_sha256 =
            checkpoint_body_sha256(&first.body).expect("previous digest");

        assert_eq!(
            second.body.previous_checkpoint_sha256.as_deref(),
            Some(expected_previous_checkpoint_sha256.as_str())
        );
        assert!(
            verify_checkpoint_continuity(&first, &second).expect("continuity verification"),
            "second checkpoint should extend the first"
        );
    }

    #[test]
    fn build_checkpoint_transparency_derives_publications_and_witnesses() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("build second");

        let transparency =
            validate_checkpoint_transparency(&[first.clone(), second.clone()]).expect("summary");

        assert_eq!(transparency.publications.len(), 2);
        assert_eq!(transparency.witnesses.len(), 1);
        assert_eq!(transparency.consistency_proofs.len(), 1);
        assert!(transparency.equivocations.is_empty());
        assert_eq!(
            transparency.publications[0].log_id,
            checkpoint_log_id(&first)
        );
        assert_eq!(transparency.publications[0].log_tree_size, 3);
        assert_eq!(transparency.publications[1].entry_start_seq, 4);
        assert_eq!(transparency.publications[1].entry_end_seq, 6);
        assert_eq!(
            transparency.publications[0].checkpoint_sha256,
            checkpoint_body_sha256(&first.body).expect("first digest")
        );
        assert_eq!(transparency.witnesses[0].log_id, checkpoint_log_id(&first));
        assert_eq!(transparency.witnesses[0].checkpoint_seq, 1);
        assert_eq!(transparency.witnesses[0].witness_checkpoint_seq, 2);
        assert_eq!(transparency.consistency_proofs[0].from_log_tree_size, 3);
        assert_eq!(transparency.consistency_proofs[0].to_log_tree_size, 6);
    }

    #[test]
    fn checkpoint_log_id_preserves_historical_ed25519_hashing() {
        let kp = Keypair::generate();
        let checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");

        assert_eq!(
            checkpoint_log_id(&checkpoint),
            format!("local-log-{}", sha256_hex(kp.public_key().as_bytes()))
        );
    }

    #[test]
    fn build_trust_anchored_checkpoint_publication_records_binding() {
        let kp = Keypair::generate();
        let checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
        let publication = build_trust_anchored_checkpoint_publication(
            &checkpoint,
            CheckpointPublicationTrustAnchorBinding {
                publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                    "transparency.example/checkpoints/1",
                ),
                trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                    "did:chio:operator-root",
                ),
                trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
                signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
                publication_profile_version: "phase4-preview.v1".to_string(),
            },
        )
        .expect("build trust-anchored publication");

        assert_eq!(
            publication
                .trust_anchor_binding
                .as_ref()
                .expect("binding")
                .trust_anchor_ref,
            "chio_checkpoint_witness_chain"
        );
        assert_eq!(
            publication
                .trust_anchor_binding
                .as_ref()
                .expect("binding")
                .publication_identity
                .identity,
            "transparency.example/checkpoints/1"
        );
        assert_eq!(publication.log_id, checkpoint_log_id(&checkpoint));
    }

    #[test]
    fn verify_checkpoint_transparency_records_rejects_duplicate_publication_coverage() {
        let kp = Keypair::generate();
        let first =
            build_checkpoint(1, 1, 2, &make_receipt_bytes(2), &kp).expect("first checkpoint");
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &make_receipt_bytes(2),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second checkpoint");
        let derived = validate_checkpoint_transparency(&[first.clone(), second.clone()])
            .expect("transparency");
        let supplied = CheckpointTransparencySummary {
            publications: vec![
                derived.publications[0].clone(),
                derived.publications[0].clone(),
            ],
            witnesses: derived.witnesses.clone(),
            consistency_proofs: derived.consistency_proofs.clone(),
            equivocations: derived.equivocations.clone(),
        };

        let error = verify_checkpoint_transparency_records(&[first, second], &supplied)
            .expect_err("duplicate publication coverage should fail");
        assert!(
            error
                .to_string()
                .contains("duplicate checkpoint publication record"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_trust_anchored_checkpoint_publication_rejects_invalid_binding() {
        let kp = Keypair::generate();
        let checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
        let error = build_trust_anchored_checkpoint_publication(
            &checkpoint,
            CheckpointPublicationTrustAnchorBinding {
                publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::TransparencyService,
                    "",
                ),
                trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::Did,
                    "did:chio:operator-root",
                ),
                trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
                signer_cert_ref: "".to_string(),
                publication_profile_version: "phase4-preview.v1".to_string(),
            },
        )
        .expect_err("blank signer certificate ref must be rejected");
        assert!(error.to_string().contains("publication_identity.identity"));
    }

    #[test]
    fn build_trust_anchored_checkpoint_publication_rejects_mismatched_local_log_identity() {
        let kp = Keypair::generate();
        let checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build checkpoint");
        let error = build_trust_anchored_checkpoint_publication(
            &checkpoint,
            CheckpointPublicationTrustAnchorBinding {
                publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
                    "local-log-not-the-real-one",
                ),
                trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::OperatorRoot,
                    "chio-operator-root",
                ),
                trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
                signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
                publication_profile_version: "phase4-preview.v1".to_string(),
            },
        )
        .expect_err("mismatched local log identity must be rejected");
        assert!(error.to_string().contains("does not match log_id"));
    }

    #[test]
    fn detect_checkpoint_equivocation_reports_conflicting_sequence() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
            .expect("first checkpoint");
        let conflicting = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"changed".to_vec()], &kp)
            .expect("conflicting checkpoint");

        let equivocation = detect_checkpoint_equivocation(&first, &conflicting)
            .expect("equivocation detection")
            .expect("expected conflict");
        assert_eq!(
            equivocation.kind,
            CheckpointEquivocationKind::ConflictingCheckpointSeq
        );
        assert_eq!(equivocation.first_checkpoint_seq, 1);
        assert_eq!(equivocation.second_checkpoint_seq, 1);
    }

    #[test]
    fn checkpoint_rejects_same_log_same_tree_size_fork() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let fork = build_checkpoint_with_previous(
            9,
            1,
            6,
            &[
                b"fork-one".to_vec(),
                b"fork-two".to_vec(),
                b"fork-three".to_vec(),
                b"fork-four".to_vec(),
                b"fork-five".to_vec(),
                b"fork-six".to_vec(),
            ],
            &kp,
            None,
            &[],
        )
        .expect("fork");

        let error = validate_checkpoint_transparency(&[first, second, fork])
            .expect_err("same-log same-tree-size fork should fail");
        assert!(
            error.to_string().contains("cumulative tree size 6"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn checkpoint_consistency_proof_verifies_chain_growth() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let third = build_checkpoint_with_previous(
            3,
            7,
            9,
            &make_receipt_bytes(3),
            &kp,
            Some(&second),
            &chain_leaves(&[&first, &second]),
        )
        .expect("third");

        let leaves = chain_leaves(&[&first, &second, &third]);
        let proof =
            build_checkpoint_consistency_proof(&first, &second, &leaves[..2]).expect("proof");
        assert_eq!(proof.schema, CHECKPOINT_CONSISTENCY_PROOF_SCHEMA);
        assert_eq!(proof.log_id, checkpoint_log_id(&first));
        assert_eq!(proof.from_log_tree_size, 3);
        assert_eq!(proof.to_log_tree_size, 6);
        assert_eq!(proof.appended_entry_start_seq, 4);
        assert_eq!(proof.appended_entry_end_seq, 6);
        assert_eq!(Some(proof.from_chain_root), first.body.chain_root);
        assert_eq!(Some(proof.to_chain_root), second.body.chain_root);
        assert!(
            verify_checkpoint_consistency_proof(&first, &second, &proof).expect("verify proof"),
            "chain-growth proof should verify"
        );

        let later = build_checkpoint_consistency_proof(&second, &third, &leaves).expect("later");
        assert!(
            !later.chain_proof_hashes.is_empty(),
            "a chain extension past one leaf must carry node hashes"
        );
        assert!(
            verify_checkpoint_consistency_proof(&second, &third, &later).expect("verify later"),
            "second chain-growth proof should verify"
        );
    }

    #[test]
    fn checkpoint_consistency_proof_rejects_unrelated_chain_root() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let leaves = chain_leaves(&[&first, &second]);
        let honest = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

        // A key-holding log that rewrites history: the successor commits a
        // chain root with no append-only relation to the predecessor's, and
        // re-signs. Every metadata field can be made to match, but the Merkle
        // path cannot.
        let mut rewritten = second.clone();
        rewritten.body.chain_root =
            Some(checkpoint_chain_root(&[leaf_hash(b"rewritten-history")]).expect("root"));
        rewritten.signature = kp.sign(
            &canonical_json_bytes(&rewritten.body).expect("canonical rewritten checkpoint body"),
        );

        let mut forged = honest.clone();
        forged.to_checkpoint_sha256 =
            checkpoint_body_sha256(&rewritten.body).expect("rewritten digest");
        forged.to_chain_root = rewritten.body.chain_root.expect("rewritten chain root");
        assert!(
            !verify_checkpoint_consistency_proof(&first, &rewritten, &forged)
                .expect("verify forged"),
            "a chain root with no append-only relation must not verify"
        );

        // Tampering any single field of an otherwise honest proof fails too.
        let mut tampered = honest.clone();
        tampered.to_chain_root = Hash::zero();
        assert!(
            !verify_checkpoint_consistency_proof(&first, &second, &tampered)
                .expect("verify tampered"),
            "a tampered to_chain_root must not verify"
        );
        let mut truncated = honest.clone();
        truncated.chain_proof_hashes.push(Hash::zero());
        assert!(
            !verify_checkpoint_consistency_proof(&first, &second, &truncated)
                .expect("verify extended"),
            "an extended proof path must not verify"
        );
    }

    #[test]
    fn checkpoint_consistency_proof_requires_the_committed_chain_to_end_in_this_checkpoint() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let leaves = chain_leaves(&[&first, &second]);
        let honest = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

        // A key holder commits a chain whose last leaf is not its own body and
        // re-signs. The verifier recomputes from the checkpoint's true leaf, so
        // the substituted root cannot be reproduced.
        let smuggled_leaf = leaf_hash(b"not-this-checkpoint");
        let smuggled_chain =
            MerkleTree::from_hashes(vec![leaves[0], smuggled_leaf]).expect("smuggled chain");
        let mut smuggled = second.clone();
        smuggled.body.chain_root = Some(smuggled_chain.root());
        smuggled.signature = kp.sign(
            &canonical_json_bytes(&smuggled.body).expect("canonical smuggled checkpoint body"),
        );
        let mut smuggled_proof = honest.clone();
        smuggled_proof.to_checkpoint_sha256 =
            checkpoint_body_sha256(&smuggled.body).expect("smuggled digest");
        smuggled_proof.to_chain_root = smuggled_chain.root();
        smuggled_proof.chain_proof_hashes =
            smuggled_chain.consistency_proof(1).expect("smuggled path");
        smuggled_proof.to_leaf_inclusion = smuggled_chain
            .inclusion_proof(1)
            .expect("smuggled inclusion");
        assert!(
            !verify_checkpoint_consistency_proof(&first, &smuggled, &smuggled_proof)
                .expect("verify smuggled chain"),
            "a chain whose last leaf is not this checkpoint must not verify"
        );

        let mut wrong_index = honest.clone();
        wrong_index.to_leaf_inclusion.leaf_index = 0;
        assert!(
            !verify_checkpoint_consistency_proof(&first, &second, &wrong_index)
                .expect("verify wrong index"),
            "the checkpoint leaf must be proven at the last position"
        );
    }

    /// A pair starting after checkpoint 1 must bind BOTH endpoints. The forged
    /// chain here has correct sizes and a genuine prefix relation, and its
    /// later endpoint really does commit the later body, so every other check
    /// passes: only binding the earlier leaf catches that checkpoint 2's
    /// signed root never contained checkpoint 2.
    #[test]
    fn checkpoint_consistency_proof_binds_the_earlier_endpoint_too() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let third = build_checkpoint_with_previous(
            3,
            7,
            9,
            &make_receipt_bytes(3),
            &kp,
            Some(&second),
            &chain_leaves(&[&first, &second]),
        )
        .expect("third");
        let honest_leaves = chain_leaves(&[&first, &second, &third]);
        let honest =
            build_checkpoint_consistency_proof(&second, &third, &honest_leaves).expect("honest");

        // Same sizes as the honest chain, but the second leaf is junk instead
        // of checkpoint 2's body; checkpoint 3's real leaf is still appended.
        let forged_from = vec![honest_leaves[0], leaf_hash(b"never-checkpoint-two")];
        let mut forged_to = forged_from.clone();
        forged_to.push(honest_leaves[2]);
        let forged_from_tree = MerkleTree::from_hashes(forged_from).expect("forged from tree");
        let forged_to_tree = MerkleTree::from_hashes(forged_to).expect("forged to tree");

        let mut forged_second = second.clone();
        forged_second.body.chain_root = Some(forged_from_tree.root());
        forged_second.signature = kp.sign(
            &canonical_json_bytes(&forged_second.body).expect("canonical forged second body"),
        );
        let mut forged_third = third.clone();
        forged_third.body.previous_checkpoint_sha256 =
            Some(checkpoint_body_sha256(&forged_second.body).expect("forged second digest"));
        forged_third.body.chain_root = Some(forged_to_tree.root());
        forged_third.signature = kp
            .sign(&canonical_json_bytes(&forged_third.body).expect("canonical forged third body"));

        let forged = CheckpointConsistencyProof {
            from_checkpoint_sha256: checkpoint_body_sha256(&forged_second.body)
                .expect("forged from digest"),
            to_checkpoint_sha256: checkpoint_body_sha256(&forged_third.body)
                .expect("forged to digest"),
            from_chain_root: forged_from_tree.root(),
            to_chain_root: forged_to_tree.root(),
            chain_proof_hashes: forged_to_tree.consistency_proof(2).expect("forged path"),
            from_leaf_inclusion: forged_from_tree
                .inclusion_proof(1)
                .expect("forged from leaf"),
            to_leaf_inclusion: forged_to_tree.inclusion_proof(2).expect("forged to leaf"),
            ..honest
        };

        // The later endpoint and the consistency path are internally valid.
        assert!(
            verify_consistency_proof(
                2,
                3,
                &forged.from_chain_root,
                &forged.to_chain_root,
                &forged.chain_proof_hashes,
            ),
            "the forged chain is genuinely prefix-related, so only leaf binding can catch it"
        );
        assert!(
            !verify_checkpoint_consistency_proof(&forged_second, &forged_third, &forged)
                .expect("verify forged mid-chain pair"),
            "an earlier root that does not commit the earlier body must not verify"
        );
    }

    #[test]
    fn checkpoint_consistency_proof_requires_chain_commitment() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        let leaves = chain_leaves(&[&first, &second]);
        let proof = build_checkpoint_consistency_proof(&first, &second, &leaves).expect("proof");

        // A legacy pair without chain commitments is unverifiable, not false.
        let mut legacy_first = first.clone();
        legacy_first.body.chain_root = None;
        legacy_first.signature = kp
            .sign(&canonical_json_bytes(&legacy_first.body).expect("canonical legacy first body"));
        let mut legacy_second = second.clone();
        legacy_second.body.previous_checkpoint_sha256 =
            Some(checkpoint_body_sha256(&legacy_first.body).expect("legacy digest"));
        legacy_second.body.chain_root = None;
        legacy_second.signature = kp.sign(
            &canonical_json_bytes(&legacy_second.body).expect("canonical legacy second body"),
        );

        let error = verify_checkpoint_consistency_proof(&legacy_first, &legacy_second, &proof)
            .expect_err("legacy pair should be unverifiable");
        assert!(
            error.to_string().contains("no chain commitment"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_predecessor_rejects_chain_commitment_downgrade() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let mut second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second");
        second.body.chain_root = None;
        second.signature = kp.sign(
            &canonical_json_bytes(&second.body).expect("canonical downgraded checkpoint body"),
        );

        let error =
            validate_checkpoint_predecessor(&first, &second).expect_err("downgrade should fail");
        assert!(
            error.to_string().contains("drops the chain commitment"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_rejects_first_checkpoint_chain_root_mismatch() {
        let kp = Keypair::generate();
        let mut checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        checkpoint.body.chain_root = Some(Hash::zero());
        checkpoint.signature = kp.sign(
            &canonical_json_bytes(&checkpoint.body).expect("canonical tampered checkpoint body"),
        );

        let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
        assert!(
            error
                .to_string()
                .contains("does not commit its own chain leaf"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn checkpoint_body_rejects_unknown_fields() {
        let kp = Keypair::generate();
        let checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let mut body_value =
            serde_json::to_value(&checkpoint.body).expect("serialize checkpoint body");
        body_value["smuggled_field"] = serde_json::json!("payload");

        let error = serde_json::from_value::<KernelCheckpointBody>(body_value)
            .expect_err("unknown body field should be rejected");
        assert!(
            error.to_string().contains("smuggled_field"),
            "unexpected error: {error}"
        );

        let mut checkpoint_value = serde_json::to_value(&checkpoint).expect("serialize checkpoint");
        checkpoint_value["extra"] = serde_json::json!(1);
        let error = serde_json::from_value::<KernelCheckpoint>(checkpoint_value)
            .expect_err("unknown top-level field should be rejected");
        assert!(
            error.to_string().contains("extra"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn legacy_checkpoint_body_without_chain_root_still_roundtrips() {
        let kp = Keypair::generate();
        let mut checkpoint =
            build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        checkpoint.body.chain_root = None;
        checkpoint.signature = kp.sign(
            &canonical_json_bytes(&checkpoint.body).expect("canonical legacy checkpoint body"),
        );

        let json = serde_json::to_string(&checkpoint).expect("serialize");
        assert!(
            !json.contains("chain_root"),
            "an absent chain commitment must not appear on the wire"
        );
        let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.body.chain_root, None);
        assert!(
            verify_checkpoint_signature(&restored).expect("verify"),
            "legacy checkpoint signature must survive the roundtrip"
        );
    }

    #[test]
    fn inclusion_proof_verifies_for_leaf_n() {
        let batch = make_receipt_bytes(10);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
        assert!(
            proof.verify(&batch[5], &root),
            "inclusion proof should verify"
        );
    }

    #[test]
    fn inclusion_proof_tampered_bytes_fail() {
        let batch = make_receipt_bytes(10);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        let proof = build_inclusion_proof(&tree, 5, 1, 6).expect("proof failed");
        assert!(
            !proof.verify(b"tampered bytes that are not in the tree", &root),
            "tampered bytes should not verify"
        );
    }

    #[test]
    fn inclusion_proof_all_100_leaves_verify() {
        let batch = make_receipt_bytes(100);
        let tree = MerkleTree::from_leaves(&batch).expect("tree build failed");
        let root = tree.root();
        for (i, leaf) in batch.iter().enumerate().take(100) {
            let proof = build_inclusion_proof(&tree, i, 1, i as u64 + 1).expect("proof failed");
            assert!(proof.verify(leaf, &root), "leaf {i} inclusion proof failed");
        }
    }

    #[test]
    fn checkpoint_body_schema_field() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let cp = build_checkpoint(7, 101, 105, &batch, &kp).expect("build failed");
        let json = serde_json::to_string(&cp.body).expect("serialize failed");
        assert!(
            json.contains(CHECKPOINT_SCHEMA),
            "JSON should contain schema string"
        );
    }

    #[test]
    fn checkpoint_schema_support_matches_current_v1() {
        assert!(is_supported_checkpoint_schema(CHECKPOINT_SCHEMA));
    }

    #[test]
    fn kernel_checkpoint_serde_roundtrip() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(5);
        let cp = build_checkpoint(1, 1, 5, &batch, &kp).expect("build failed");
        let json = serde_json::to_string(&cp).expect("serialize failed");
        let restored: KernelCheckpoint = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(cp.body.checkpoint_seq, restored.body.checkpoint_seq);
        assert_eq!(cp.body.tree_size, restored.body.tree_size);
        assert_eq!(cp.signature.to_hex(), restored.signature.to_hex());
        // Verify signature still works after roundtrip.
        assert!(
            verify_checkpoint_signature(&restored).expect("verify failed"),
            "roundtripped checkpoint signature should verify"
        );
    }

    #[test]
    fn validate_checkpoint_rejects_zero_checkpoint_seq() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(3);
        let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
        checkpoint.body.checkpoint_seq = 0;

        let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
        assert!(
            error
                .to_string()
                .contains("checkpoint_seq must be greater than zero"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_rejects_tampered_signature() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(3);
        let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
        checkpoint.body.issued_at = checkpoint.body.issued_at.saturating_add(1);

        let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
        assert!(
            matches!(error, CheckpointError::InvalidSignature),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_rejects_tree_size_that_does_not_match_entry_range() {
        let kp = Keypair::generate();
        let batch = make_receipt_bytes(3);
        let mut checkpoint = build_checkpoint(1, 1, 3, &batch, &kp).expect("build failed");
        checkpoint.body.tree_size = 2;
        checkpoint.signature =
            kp.sign(&canonical_json_bytes(&checkpoint.body).expect("canonical checkpoint body"));

        let error = validate_checkpoint(&checkpoint).expect_err("checkpoint should be invalid");
        assert!(
            error
                .to_string()
                .contains("tree_size 2 does not match covered entry count 3"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_predecessor_accepts_contiguous_batches() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("build failed");

        validate_checkpoint_predecessor(&first, &second).expect("continuity should hold");
    }

    #[test]
    fn validate_checkpoint_predecessor_rejects_batch_gap() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let second = build_checkpoint_with_previous(
            2,
            5,
            6,
            &make_receipt_bytes(2),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("build failed");

        let error =
            validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
        assert!(
            error.to_string().contains("does not immediately follow"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_predecessor_rejects_wrong_predecessor_digest() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let mut second = build_checkpoint_with_previous(
            2,
            4,
            6,
            &make_receipt_bytes(3),
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("build failed");
        second.body.previous_checkpoint_sha256 = Some("not-the-real-digest".to_string());
        second.signature =
            kp.sign(&canonical_json_bytes(&second.body).expect("canonical second checkpoint body"));

        let error =
            validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
        assert!(
            error
                .to_string()
                .contains("does not match predecessor digest"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_predecessor_rejects_missing_predecessor_digest() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let second = build_checkpoint(2, 4, 6, &make_receipt_bytes(3), &kp).expect("build failed");

        let error =
            validate_checkpoint_predecessor(&first, &second).expect_err("continuity should fail");
        assert!(
            error.to_string().contains("missing predecessor digest"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validate_checkpoint_transparency_rejects_predecessor_fork() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp)
            .expect("first checkpoint");
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"three".to_vec(), b"four".to_vec()],
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("second checkpoint");
        let mut fork = build_checkpoint_with_previous(
            3,
            5,
            6,
            &[b"five".to_vec(), b"six".to_vec()],
            &kp,
            Some(&first),
            &chain_leaves(&[&first]),
        )
        .expect("fork checkpoint");
        fork.signature =
            kp.sign(&canonical_json_bytes(&fork.body).expect("canonical fork checkpoint body"));

        let error = validate_checkpoint_transparency(&[first, second, fork])
            .expect_err("forked checkpoint set should fail");
        assert!(
            error
                .to_string()
                .contains("checkpoint equivocation detected"),
            "unexpected error: {error}"
        );
    }
}
