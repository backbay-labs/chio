use chio_core::canonical_json_bytes;
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, MerkleProof, MerkleTree};
use chio_core::signed_artifact::CHIO_ANCHOR_BATCH_V1_SCHEMA;
use chio_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::AnchorError;

/// Public witness lane for an anchor batch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorBatchWitnessKind {
    Rekor,
    Ots,
    SolanaMemo,
}

/// Public-witness descriptor bound into the signed batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorBatchWitness {
    pub kind: AnchorBatchWitnessKind,
    pub witness_id: String,
    pub root: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
}

/// Per-element Merkle inclusion proof for a batch member.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorBatchInclusion {
    pub checkpoint_id: String,
    pub leaf_hash: Hash,
    pub proof: MerkleProof,
}

/// Signed anchor-batch body. Per-receipt local signatures remain authoritative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorBatchBody {
    pub schema: String,
    pub tree_root: Hash,
    pub checkpoint_ids: Vec<String>,
    pub inclusions: Vec<AnchorBatchInclusion>,
    pub witness: AnchorBatchWitness,
    pub issued_at: u64,
    pub signer_key: PublicKey,
}

/// Signed anchor batch artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorBatch {
    pub body: AnchorBatchBody,
    pub signature: Signature,
}

impl AnchorBatch {
    pub fn sign(body: AnchorBatchBody, keypair: &Keypair) -> Result<Self, AnchorError> {
        validate_anchor_batch_body(&body)?;
        let (signature, _bytes) = keypair
            .sign_canonical(&body)
            .map_err(|error| AnchorError::Serialization(error.to_string()))?;
        Ok(Self { body, signature })
    }

    pub fn verify_signature(&self) -> Result<bool, AnchorError> {
        validate_anchor_batch_body(&self.body)?;
        self.body
            .signer_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|error| AnchorError::Verification(error.to_string()))
    }
}

/// Build a signed `chio.anchor_batch.v1` from checkpoint IDs.
pub fn build_anchor_batch(
    checkpoint_ids: Vec<String>,
    witness: AnchorBatchWitness,
    issued_at: u64,
    keypair: &Keypair,
) -> Result<AnchorBatch, AnchorError> {
    // W2.4: emit `chio_anchor_round_latency_seconds` at the anchor
    // publish boundary. The signing and Merkle-tree work happens here so
    // round latency captures the full publish path.
    let started_at = std::time::Instant::now();
    let result = (|| {
        let body =
            build_anchor_batch_body(checkpoint_ids, witness, issued_at, keypair.public_key())?;
        AnchorBatch::sign(body, keypair)
    })();
    let elapsed_nanos = u64::try_from(started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let outcome = if result.is_ok() {
        crate::metrics::ANCHOR_OUTCOME_SUCCESS
    } else {
        crate::metrics::ANCHOR_OUTCOME_ERROR
    };
    crate::metrics::observe_anchor_round_latency_nanos(outcome, elapsed_nanos);
    result
}

/// Build an unsigned anchor-batch body and all inclusion proofs.
pub fn build_anchor_batch_body(
    checkpoint_ids: Vec<String>,
    mut witness: AnchorBatchWitness,
    issued_at: u64,
    signer_key: PublicKey,
) -> Result<AnchorBatchBody, AnchorError> {
    if checkpoint_ids.is_empty() {
        return Err(AnchorError::InvalidInput(
            "anchor batch requires at least one checkpoint ID".to_string(),
        ));
    }
    let leaves = checkpoint_ids
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let tree_root = tree.root();
    witness.root = tree_root;
    let mut inclusions = Vec::with_capacity(checkpoint_ids.len());
    for (index, checkpoint_id) in checkpoint_ids.iter().enumerate() {
        let proof = tree
            .inclusion_proof(index)
            .map_err(|error| AnchorError::Verification(error.to_string()))?;
        inclusions.push(AnchorBatchInclusion {
            checkpoint_id: checkpoint_id.clone(),
            leaf_hash: leaf_hash(&leaves[index]),
            proof,
        });
    }
    Ok(AnchorBatchBody {
        schema: CHIO_ANCHOR_BATCH_V1_SCHEMA.to_string(),
        tree_root,
        checkpoint_ids,
        inclusions,
        witness,
        issued_at,
        signer_key,
    })
}

/// Verify the batch root, inclusion proofs, witness binding, and signature.
pub fn verify_anchor_batch(batch: &AnchorBatch) -> Result<(), AnchorError> {
    if !batch.verify_signature()? {
        return Err(AnchorError::Verification(
            "anchor batch signature verification failed".to_string(),
        ));
    }
    Ok(())
}

fn validate_anchor_batch_body(body: &AnchorBatchBody) -> Result<(), AnchorError> {
    if body.schema != CHIO_ANCHOR_BATCH_V1_SCHEMA {
        return Err(AnchorError::Verification(format!(
            "unsupported anchor batch schema: {}",
            body.schema
        )));
    }
    if body.checkpoint_ids.is_empty() {
        return Err(AnchorError::Verification(
            "anchor batch checkpoint_ids must not be empty".to_string(),
        ));
    }
    if body.checkpoint_ids.len() != body.inclusions.len() {
        return Err(AnchorError::Verification(
            "anchor batch checkpoint_ids and inclusions length mismatch".to_string(),
        ));
    }
    if body.witness.root != body.tree_root {
        return Err(AnchorError::Verification(
            "anchor batch witness root does not match tree_root".to_string(),
        ));
    }
    let leaves = body
        .checkpoint_ids
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    if tree.root() != body.tree_root {
        return Err(AnchorError::Verification(
            "anchor batch forged tree_root".to_string(),
        ));
    }
    for (index, inclusion) in body.inclusions.iter().enumerate() {
        if inclusion.checkpoint_id != body.checkpoint_ids[index] {
            return Err(AnchorError::Verification(
                "anchor batch inclusion order does not match checkpoint_ids".to_string(),
            ));
        }
        let expected_leaf = leaf_hash(&leaves[index]);
        if inclusion.leaf_hash != expected_leaf {
            return Err(AnchorError::Verification(
                "anchor batch inclusion leaf hash mismatch".to_string(),
            ));
        }
        if !inclusion
            .proof
            .verify_hash(inclusion.leaf_hash, &body.tree_root)
        {
            return Err(AnchorError::Verification(
                "anchor batch inclusion proof verification failed".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn anchor_batch_roundtrip_and_negative_roots() {
        let kp = Keypair::generate();
        let checkpoint_ids = vec![
            "checkpoint-a".to_string(),
            "checkpoint-b".to_string(),
            "checkpoint-c".to_string(),
        ];
        let placeholder_witness = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:uuid".to_string(),
            root: Hash::zero(),
            observed_at: Some(1710000000),
        };
        let body = build_anchor_batch_body(
            checkpoint_ids,
            placeholder_witness,
            1710000000,
            kp.public_key(),
        )
        .unwrap();
        let batch = AnchorBatch::sign(body, &kp).unwrap();
        verify_anchor_batch(&batch).unwrap();

        let mut forged = batch.clone();
        forged.body.tree_root = Hash::zero();
        assert!(verify_anchor_batch(&forged).is_err());

        let mut misordered = batch.clone();
        misordered.body.inclusions.swap(0, 1);
        assert!(verify_anchor_batch(&misordered).is_err());

        let mut impersonated = batch;
        impersonated.body.witness.root = Hash::zero();
        assert!(verify_anchor_batch(&impersonated).is_err());
    }
}
