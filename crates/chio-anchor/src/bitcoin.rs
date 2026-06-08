use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::merkle::MerkleTree;
use chio_core::web3::anchors::{AnchorInclusionProof, Web3BitcoinAnchor, Web3SuperRootInclusion};
use chio_kernel::checkpoint::KernelCheckpoint;
use opentimestamps::attestation::Attestation;
use opentimestamps::ser::DigestType;
use opentimestamps::timestamp::{Step, StepData};
use opentimestamps::DetachedTimestampFile;
use serde::{Deserialize, Serialize};

use crate::AnchorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOtsSubmission {
    pub schema: String,
    pub calendar_urls: Vec<String>,
    pub document_hash_algorithm: String,
    pub document_digest: chio_core::hashing::Hash,
    pub checkpoint_seqs: Vec<u64>,
    pub checkpoint_roots: Vec<chio_core::hashing::Hash>,
    pub aggregated_checkpoint_start: u64,
    pub aggregated_checkpoint_end: u64,
    pub super_root: chio_core::hashing::Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedOtsProof {
    pub schema: String,
    pub digest_algorithm: String,
    pub start_digest: String,
    pub bitcoin_attestation_heights: Vec<u64>,
    pub pending_calendars: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinAnchorAggregation {
    pub submission: PreparedOtsSubmission,
    pub inclusion_proof: Web3SuperRootInclusion,
}

pub fn prepare_ots_submission(
    checkpoints: &[KernelCheckpoint],
    calendar_urls: &[String],
) -> Result<PreparedOtsSubmission, AnchorError> {
    if checkpoints.is_empty() {
        return Err(AnchorError::InvalidInput(
            "OTS submission requires at least one checkpoint".to_string(),
        ));
    }
    if calendar_urls.is_empty() {
        return Err(AnchorError::InvalidInput(
            "OTS submission requires at least one calendar URL".to_string(),
        ));
    }
    if checkpoints
        .windows(2)
        .any(|pair| pair[1].body.checkpoint_seq != pair[0].body.checkpoint_seq.saturating_add(1))
    {
        return Err(AnchorError::InvalidInput(
            "OTS submission requires contiguous checkpoint sequences".to_string(),
        ));
    }
    let checkpoint_seqs: Vec<u64> = checkpoints
        .iter()
        .map(|checkpoint| checkpoint.body.checkpoint_seq)
        .collect();
    let checkpoint_roots: Vec<chio_core::hashing::Hash> = checkpoints
        .iter()
        .map(|checkpoint| checkpoint.body.merkle_root)
        .collect();
    let tree = MerkleTree::from_hashes(checkpoint_roots.clone())
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let super_root = tree.root();
    let (Some(aggregated_checkpoint_start), Some(aggregated_checkpoint_end)) =
        (checkpoint_seqs.first(), checkpoint_seqs.last())
    else {
        return Err(AnchorError::Verification(
            "OTS submission requires at least one checkpoint".to_string(),
        ));
    };
    Ok(PreparedOtsSubmission {
        schema: "chio.anchor.ots-submission.v1".to_string(),
        calendar_urls: calendar_urls.to_vec(),
        document_hash_algorithm: "sha256".to_string(),
        document_digest: chio_core::hashing::sha256(super_root.as_bytes()),
        aggregated_checkpoint_start: *aggregated_checkpoint_start,
        aggregated_checkpoint_end: *aggregated_checkpoint_end,
        checkpoint_seqs,
        checkpoint_roots,
        super_root,
    })
}

pub fn inspect_ots_proof(ots_proof_b64: &str) -> Result<ParsedOtsProof, AnchorError> {
    let bytes = BASE64_STANDARD.decode(ots_proof_b64).map_err(|error| {
        AnchorError::InvalidInput(format!("invalid OTS base64 payload: {error}"))
    })?;
    let detached = DetachedTimestampFile::from_reader(bytes.as_slice())
        .map_err(|error| AnchorError::Verification(format!("invalid OTS payload: {error}")))?;

    let mut bitcoin_attestation_heights = Vec::new();
    let mut pending_calendars = Vec::new();
    collect_attestations(
        &detached.timestamp.first_step,
        &mut bitcoin_attestation_heights,
        &mut pending_calendars,
    );

    Ok(ParsedOtsProof {
        schema: "chio.anchor.ots-proof-inspection.v1".to_string(),
        digest_algorithm: match detached.digest_type {
            DigestType::Sha1 => "sha1",
            DigestType::Sha256 => "sha256",
            DigestType::Ripemd160 => "ripemd160",
        }
        .to_string(),
        start_digest: format!("0x{}", hex::encode(detached.timestamp.start_digest)),
        bitcoin_attestation_heights,
        pending_calendars,
    })
}

pub fn verify_ots_proof_for_submission(
    submission: &PreparedOtsSubmission,
    ots_proof_b64: &str,
    expected_bitcoin_height: Option<u64>,
) -> Result<ParsedOtsProof, AnchorError> {
    let inspection = inspect_ots_proof(ots_proof_b64)?;
    if inspection.digest_algorithm != submission.document_hash_algorithm {
        return Err(AnchorError::Verification(format!(
            "OTS digest algorithm {} does not match expected {}",
            inspection.digest_algorithm, submission.document_hash_algorithm
        )));
    }
    if inspection.start_digest != submission.document_digest.to_hex_prefixed() {
        return Err(AnchorError::Verification(
            "OTS proof does not commit to the expected Chio super-root document digest".to_string(),
        ));
    }
    if inspection.bitcoin_attestation_heights.is_empty() {
        return Err(AnchorError::Verification(
            "OTS proof is still pending and does not yet contain a Bitcoin attestation".to_string(),
        ));
    }
    if let Some(height) = expected_bitcoin_height {
        if !inspection.bitcoin_attestation_heights.contains(&height) {
            return Err(AnchorError::Verification(format!(
                "OTS proof does not attest to Bitcoin block height {}",
                height
            )));
        }
    }
    Ok(inspection)
}

pub fn verify_bitcoin_anchor_for_proof(
    proof: &AnchorInclusionProof,
) -> Result<ParsedOtsProof, AnchorError> {
    let bitcoin_anchor = proof.bitcoin_anchor.as_ref().ok_or_else(|| {
        AnchorError::Verification("proof does not include Bitcoin anchor data".to_string())
    })?;
    if bitcoin_anchor.method != "opentimestamps" {
        return Err(AnchorError::Verification(format!(
            "unsupported Bitcoin anchor method {}",
            bitcoin_anchor.method
        )));
    }
    if bitcoin_anchor.bitcoin_block_hash.trim().is_empty() {
        return Err(AnchorError::Verification(
            "Bitcoin anchor block hash must be non-empty".to_string(),
        ));
    }

    let super_root = proof.super_root_inclusion.as_ref().ok_or_else(|| {
        AnchorError::Verification(
            "Bitcoin anchor verification requires super-root inclusion metadata".to_string(),
        )
    })?;
    if proof.checkpoint_statement.checkpoint_seq < super_root.aggregated_checkpoint_start
        || proof.checkpoint_statement.checkpoint_seq > super_root.aggregated_checkpoint_end
    {
        return Err(AnchorError::Verification(format!(
            "checkpoint {} falls outside aggregated Bitcoin super-root range {}-{}",
            proof.checkpoint_statement.checkpoint_seq,
            super_root.aggregated_checkpoint_start,
            super_root.aggregated_checkpoint_end
        )));
    }

    let expected_document_digest = chio_core::hashing::sha256(super_root.super_root.as_bytes());
    let inspection = inspect_ots_proof(&bitcoin_anchor.ots_proof_b64)?;
    if inspection.digest_algorithm != "sha256" {
        return Err(AnchorError::Verification(format!(
            "OTS digest algorithm {} does not match expected sha256",
            inspection.digest_algorithm
        )));
    }
    if inspection.start_digest != expected_document_digest.to_hex_prefixed() {
        return Err(AnchorError::Verification(
            "OTS proof does not commit to the expected Chio super-root digest".to_string(),
        ));
    }
    if !inspection
        .bitcoin_attestation_heights
        .contains(&bitcoin_anchor.bitcoin_block_height)
    {
        return Err(AnchorError::Verification(format!(
            "OTS proof does not attest to Bitcoin block height {}",
            bitcoin_anchor.bitcoin_block_height
        )));
    }
    Ok(inspection)
}

pub fn attach_bitcoin_anchor(
    proof: &AnchorInclusionProof,
    submission: &PreparedOtsSubmission,
    bitcoin_block_height: u64,
    bitcoin_block_hash: String,
    ots_proof_b64: String,
) -> Result<AnchorInclusionProof, AnchorError> {
    if ots_proof_b64.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "OTS proof payload must be non-empty".to_string(),
        ));
    }
    verify_ots_proof_for_submission(submission, &ots_proof_b64, Some(bitcoin_block_height))?;
    let checkpoint_index = submission
        .checkpoint_seqs
        .iter()
        .position(|seq| *seq == proof.checkpoint_statement.checkpoint_seq)
        .ok_or_else(|| {
            AnchorError::Verification(format!(
                "checkpoint {} is not part of the aggregated Bitcoin submission",
                proof.checkpoint_statement.checkpoint_seq
            ))
        })?;
    let checkpoint_root = submission
        .checkpoint_roots
        .get(checkpoint_index)
        .ok_or_else(|| AnchorError::Verification("checkpoint root missing".to_string()))?;
    if checkpoint_root != &proof.checkpoint_statement.merkle_root {
        return Err(AnchorError::Verification(
            "aggregated Bitcoin submission root does not match the checkpoint root".to_string(),
        ));
    }

    let tree = MerkleTree::from_hashes(submission.checkpoint_roots.clone())
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let inclusion = tree
        .inclusion_proof(checkpoint_index)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;

    let mut upgraded = proof.clone();
    upgraded.super_root_inclusion = Some(Web3SuperRootInclusion {
        super_root: submission.super_root,
        proof: inclusion,
        aggregated_checkpoint_start: submission.aggregated_checkpoint_start,
        aggregated_checkpoint_end: submission.aggregated_checkpoint_end,
    });
    upgraded.bitcoin_anchor = Some(Web3BitcoinAnchor {
        method: "opentimestamps".to_string(),
        ots_proof_b64,
        bitcoin_block_height,
        bitcoin_block_hash,
    });
    Ok(upgraded)
}

fn collect_attestations(
    step: &Step,
    bitcoin_attestation_heights: &mut Vec<u64>,
    pending_calendars: &mut Vec<String>,
) {
    if let StepData::Attestation(attestation) = &step.data {
        match attestation {
            Attestation::Bitcoin { height } => bitcoin_attestation_heights.push(*height as u64),
            Attestation::Pending { uri } => pending_calendars.push(uri.clone()),
            Attestation::Unknown { .. } => {}
        }
    }
    for next in &step.next {
        collect_attestations(next, bitcoin_attestation_heights, pending_calendars);
    }
}
