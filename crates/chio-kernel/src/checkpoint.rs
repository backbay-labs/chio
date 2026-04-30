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
use chio_core::merkle::{MerkleProof, MerkleTree};
use chio_core::receipt::{
    CheckpointPublicationIdentityKind, CheckpointPublicationTrustAnchorBinding,
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
}

/// A signed kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A deterministic prefix-growth proof derived from checkpoint continuity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointConsistencyProof {
    /// Schema identifier for derived consistency proof records.
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

/// Build a deterministic consistency proof when `current` cleanly extends `previous`.
pub fn build_checkpoint_consistency_proof(
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
    })
}

/// Verify that a consistency proof matches a concrete checkpoint extension.
pub fn verify_checkpoint_consistency_proof(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    proof: &CheckpointConsistencyProof,
) -> Result<bool, CheckpointError> {
    Ok(*proof == build_checkpoint_consistency_proof(previous, current)?)
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
            if checkpoint_log_id(previous) == checkpoint_log_id(checkpoint) {
                consistency_proofs.push(build_checkpoint_consistency_proof(previous, checkpoint)?);
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
/// `receipt_canonical_bytes_batch` must not be empty.
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
    )
}

/// Build a signed kernel checkpoint that explicitly links to the previous checkpoint when provided.
pub fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
) -> Result<KernelCheckpoint, CheckpointError> {
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)?;
    let merkle_root = tree.root();
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

    if let Some(previous_checkpoint_sha256) = checkpoint.body.previous_checkpoint_sha256.as_deref()
    {
        let expected_previous_checkpoint_sha256 = checkpoint_body_sha256(&predecessor.body)?;
        if previous_checkpoint_sha256 != expected_previous_checkpoint_sha256 {
            return Err(CheckpointError::Continuity(format!(
                "checkpoint {} does not match predecessor digest {}",
                checkpoint.body.checkpoint_seq, expected_previous_checkpoint_sha256
            )));
        }
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
        let second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
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
        let second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
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
                publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
                    chio_core::receipt::CheckpointPublicationIdentityKind::TransparencyService,
                    "transparency.example/checkpoints/1",
                ),
                trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::CheckpointTrustAnchorIdentityKind::Did,
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
        let second =
            build_checkpoint_with_previous(2, 3, 4, &make_receipt_bytes(2), &kp, Some(&first))
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
                publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
                    chio_core::receipt::CheckpointPublicationIdentityKind::TransparencyService,
                    "",
                ),
                trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::CheckpointTrustAnchorIdentityKind::Did,
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
                publication_identity: chio_core::receipt::CheckpointPublicationIdentity::new(
                    chio_core::receipt::CheckpointPublicationIdentityKind::LocalLog,
                    "local-log-not-the-real-one",
                ),
                trust_anchor_identity: chio_core::receipt::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::CheckpointTrustAnchorIdentityKind::OperatorRoot,
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
        let second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
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
    fn checkpoint_consistency_proof_verifies_prefix_growth() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("first");
        let second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
                .expect("second");

        let proof = build_checkpoint_consistency_proof(&first, &second).expect("proof");
        assert_eq!(proof.log_id, checkpoint_log_id(&first));
        assert_eq!(proof.from_log_tree_size, 3);
        assert_eq!(proof.to_log_tree_size, 6);
        assert_eq!(proof.appended_entry_start_seq, 4);
        assert_eq!(proof.appended_entry_end_seq, 6);
        assert!(
            verify_checkpoint_consistency_proof(&first, &second, &proof).expect("verify proof"),
            "prefix-growth proof should verify"
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
        for i in 0..100 {
            let proof = build_inclusion_proof(&tree, i, 1, i as u64 + 1).expect("proof failed");
            assert!(
                proof.verify(&batch[i], &root),
                "leaf {i} inclusion proof failed"
            );
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
        let second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
                .expect("build failed");

        validate_checkpoint_predecessor(&first, &second).expect("continuity should hold");
    }

    #[test]
    fn validate_checkpoint_predecessor_rejects_batch_gap() {
        let kp = Keypair::generate();
        let first = build_checkpoint(1, 1, 3, &make_receipt_bytes(3), &kp).expect("build failed");
        let second =
            build_checkpoint_with_previous(2, 5, 6, &make_receipt_bytes(2), &kp, Some(&first))
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
        let mut second =
            build_checkpoint_with_previous(2, 4, 6, &make_receipt_bytes(3), &kp, Some(&first))
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
        )
        .expect("second checkpoint");
        let mut fork = build_checkpoint_with_previous(
            3,
            5,
            6,
            &[b"five".to_vec(), b"six".to_vec()],
            &kp,
            Some(&first),
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
