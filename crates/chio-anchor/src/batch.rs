use chio_core::canonical_json_bytes;
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, MerkleProof, MerkleTree};
use chio_core::signed_artifact::CHIO_ANCHOR_BATCH_V1_SCHEMA;
use chio_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::witness::{
    evaluate_witness_policy, evaluate_witness_policy_with_verifier, AnchorWitnessClient,
    VerifiedWitnessCache, WitnessPolicy, WitnessPolicyError, WitnessState,
};
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
///
/// `witness_state` carries the lane lifecycle introduced by W2.3
/// (`Pending` -> `Witnessed` -> `Stale`). The field defaults to
/// [`WitnessState::Pending`] for older artifacts that pre-date the
/// state machine, preserving wire compatibility for v1 batches that
/// never went through a public-witness lane.
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
    /// Always serialized. A non-Rust signer that emits explicit
    /// `witnessState: {"kind":"pending"}` produces canonical bytes
    /// that Rust verification must match. Stripping the field on
    /// the Rust side via `skip_serializing_if` would canonicalize
    /// to a different byte sequence and reject otherwise-valid
    /// cross-SDK batches.
    #[serde(default)]
    pub witness_state: WitnessState,
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
        if self
            .body
            .signer_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|error| AnchorError::Verification(error.to_string()))?
        {
            return Ok(true);
        }
        if self.body.witness_state != WitnessState::Pending {
            return Ok(false);
        }
        let legacy = LegacyAnchorBatchBody::from_body(&self.body);
        self.body
            .signer_key
            .verify_canonical(&legacy, &self.signature)
            .map_err(|error| AnchorError::Verification(error.to_string()))
    }
}

/// Canonical signing view for v1 batches produced before `witnessState`
/// was added to the body. Deserialization still defaults the field to
/// `Pending`; verification falls back to this view only for that state.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyAnchorBatchBody<'a> {
    schema: &'a str,
    tree_root: &'a Hash,
    checkpoint_ids: &'a [String],
    inclusions: &'a [AnchorBatchInclusion],
    witness: &'a AnchorBatchWitness,
    issued_at: u64,
    signer_key: &'a PublicKey,
}

impl<'a> LegacyAnchorBatchBody<'a> {
    fn from_body(body: &'a AnchorBatchBody) -> Self {
        Self {
            schema: &body.schema,
            tree_root: &body.tree_root,
            checkpoint_ids: &body.checkpoint_ids,
            inclusions: &body.inclusions,
            witness: &body.witness,
            issued_at: body.issued_at,
            signer_key: &body.signer_key,
        }
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
        witness_state: WitnessState::Pending,
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

/// Verify the batch and apply [`WitnessPolicy`] using `now` (UNIX
/// seconds) as the wall clock. This sync entry point does NOT call out
/// to the witness lane and has no verifier-owned stale cache.
///
/// When `policy.require_public_witness=true`, this function fails
/// closed for `Witnessed` and `Stale` states after structural checks.
/// Use [`verify_anchor_batch_with_witness_policy_async`] for
/// load-bearing public-witness verification and stale fallback.
/// Advisory mode (`require_public_witness=false`) remains available
/// for callers that intentionally treat witness state as non-binding.
pub fn verify_anchor_batch_with_witness_policy(
    batch: &AnchorBatch,
    policy: &WitnessPolicy,
    now: i64,
) -> Result<(), AnchorError> {
    verify_anchor_batch(batch)?;
    evaluate_witness_policy(batch, &batch.body.witness_state, policy, now)
        .map_err(witness_policy_to_anchor_error)
}

/// Verify the batch and apply [`WitnessPolicy`] WITH live
/// witness-lane verification when `require_public_witness=true`.
///
/// `client`: the [`AnchorWitnessClient`] backing the lane named in
/// `batch.body.witness.kind`. Required when the policy is
/// load-bearing AND the state is `Witnessed`.
///
/// `previously_verified_witnesses`: verifier-owned cache from
/// recomputed `batch_body_hash` (witness-state-excluded) to the
/// verifier's own successful `verify_inclusion` timestamp. Used for
/// `Stale` admission when the lane is currently down. Binding to the
/// batch body hash and verifier timestamp, not the receipt id or
/// producer-signed `last_verified`, prevents replay and fabricated
/// freshness.
pub async fn verify_anchor_batch_with_witness_policy_async(
    batch: &AnchorBatch,
    policy: &WitnessPolicy,
    now: i64,
    client: Option<&dyn AnchorWitnessClient>,
    previously_verified_witnesses: &VerifiedWitnessCache,
) -> Result<(), AnchorError> {
    verify_anchor_batch(batch)?;
    evaluate_witness_policy_with_verifier(
        batch,
        &batch.body.witness_state,
        policy,
        now,
        client,
        previously_verified_witnesses,
    )
    .await
    .map_err(witness_policy_to_anchor_error)
}

fn witness_policy_to_anchor_error(error: WitnessPolicyError) -> AnchorError {
    AnchorError::Verification(format!("witness policy violation: {error}"))
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

    #[test]
    fn verifies_legacy_signature_that_omitted_pending_witness_state() {
        let kp = Keypair::generate();
        let witness = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:legacy".to_string(),
            root: Hash::zero(),
            observed_at: Some(1710000000),
        };
        let body = build_anchor_batch_body(
            vec!["checkpoint-legacy".to_string()],
            witness,
            1710000000,
            kp.public_key(),
        )
        .unwrap();
        let legacy_view = LegacyAnchorBatchBody::from_body(&body);
        let (signature, _) = kp.sign_canonical(&legacy_view).unwrap();
        let batch = AnchorBatch { body, signature };

        verify_anchor_batch(&batch).expect("legacy omitted witnessState signature verifies");
    }
}
