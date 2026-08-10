//! Finding-status epoch and portable proof artifacts.
//!
//! A status epoch is independently signed by the governance-pinned feed
//! operator. The unsigned proof input carries the exact canonical signed
//! epoch bytes and a fixed-depth sparse path. Its authority comes from the
//! enclosed signature and path, never from caller-supplied root fields.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, finding_status_key_hash, verify_finding_status_inclusion,
    verify_finding_status_non_inclusion, FindingStatusSparseLeaf, FindingStatusSparseProof,
    FINDING_STATUS_BRANCH_DOMAIN, FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
use serde::{Deserialize, Serialize};

use crate::envelope::{require_ed25519, signed_envelope_sha256, verify_pinned_envelope};
use crate::profile::FindingAuthorityKeyPolicy;
use crate::validate::{
    require_bounded_id, require_hex64, require_i_json_u64, require_nonzero, require_window,
    FindingError,
};

/// Registered signed status epoch schema.
pub const FINDING_STATUS_EPOCH_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_STATUS_EPOCH_V1_SCHEMA;

/// Registered unsigned portable proof-input schema.
pub const FINDING_STATUS_PROOF_INPUT_SCHEMA_V1: &str = "chio.finding.status-proof-input.v1";

/// Signature domain bound inside the signed body.
pub const FINDING_STATUS_SIGNATURE_DOMAIN: &str = "chio.finding.status.v1";

/// Maximum number of anchoring references a root can carry.
pub const MAX_FINDING_STATUS_ANCHOR_REFS: usize = 16;

/// Exact canonical signed epoch size bound before base64 transport.
pub const MAX_FINDING_STATUS_EPOCH_BYTES: usize = 65_536;

/// Exact canonical proof-input size bound.
pub const MAX_FINDING_STATUS_PROOF_BYTES: usize = 131_072;

/// Base64 size bound enforced before decoding either carried artifact.
pub const MAX_FINDING_STATUS_ENCODED_BYTES: usize = 196_608;

const STATUS_EPOCH_ID_DOMAIN: &[u8] = b"chio.finding.status-epoch.v1\0";

/// The only status represented by the v1 feed. Live findings are absent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatusValue {
    Retracted,
}

/// Body signed by one authorized status-feed operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingStatusEpoch {
    pub schema: String,
    /// SHA-256 of the domain-separated canonical body with this field empty.
    pub status_epoch_id: String,
    pub signature_domain: String,
    pub status_map_version: String,
    pub proof_semantics: String,
    pub feed_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub operator_id: String,
    pub operator_key: PublicKey,
    pub operator_key_epoch: u64,
    pub root_hash: String,
    pub tree_depth: u16,
    pub hash_algorithm: String,
    pub key_hash_domain: String,
    pub empty_leaf_domain: String,
    pub occupied_leaf_domain: String,
    pub branch_domain: String,
    pub empty_leaf_hash: String,
    pub anchor_refs: Vec<String>,
    pub generated_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Operator-signed status epoch envelope.
pub type SignedFindingStatusEpoch = SignedExportEnvelope<FindingStatusEpoch>;

/// The governance-pinned authorization a verifier supplies out of band.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingStatusOperatorAuthorization {
    pub role: FindingStatusOperatorRole,
    pub feed_id: String,
    pub operator: FindingAuthorityKeyPolicy,
    /// Present when governance has withdrawn this key.
    pub revoked_from: Option<u64>,
}

/// Closed role vocabulary prevents a different authority from being reused.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatusOperatorRole {
    FindingStatusOperator,
}

/// Trusted freshness inputs. These values never come from the proof carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingStatusFreshnessPolicy {
    pub now: u64,
    pub max_epoch_age_secs: u64,
}

/// Common non-inclusion branch. Unknown and inclusion-only members reject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingStatusNonInclusionProofInput {
    pub schema: String,
    pub feed_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub finding_id: String,
    pub status_epoch_id: String,
    pub status_epoch_sha256: String,
    pub signed_status_epoch_b64: String,
    pub root_hash: String,
    pub siblings: Vec<String>,
    pub checked_at: u64,
}

/// Inclusion branch, including the exact retracted value and intent digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingStatusInclusionProofInput {
    pub schema: String,
    pub feed_id: String,
    pub key_domain_nonce: u64,
    pub map_epoch: u64,
    pub finding_id: String,
    pub status_epoch_id: String,
    pub status_epoch_sha256: String,
    pub signed_status_epoch_b64: String,
    pub root_hash: String,
    pub siblings: Vec<String>,
    pub checked_at: u64,
    pub status: FindingStatusValue,
    pub retraction_intent_sha256: String,
}

/// Closed tagged portable verifier input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "proof_kind", rename_all = "snake_case")]
pub enum FindingStatusProofInput {
    NonInclusion(FindingStatusNonInclusionProofInput),
    Inclusion(FindingStatusInclusionProofInput),
}

struct ProofCommon<'a> {
    schema: &'a str,
    feed_id: &'a str,
    key_domain_nonce: u64,
    map_epoch: u64,
    finding_id: &'a str,
    status_epoch_id: &'a str,
    status_epoch_sha256: &'a str,
    signed_status_epoch_b64: &'a str,
    root_hash: &'a str,
    siblings: &'a [String],
    checked_at: u64,
}

impl FindingStatusEpoch {
    /// Validate every version, domain, tree, identity, and validity binding.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_STATUS_EPOCH_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.status_epoch_id, "status_epoch_id")?;
        if self.signature_domain != FINDING_STATUS_SIGNATURE_DOMAIN {
            return Err(FindingError::InvalidField("signature_domain"));
        }
        if self.status_map_version != FINDING_STATUS_MAP_VERSION {
            return Err(FindingError::InvalidField("status_map_version"));
        }
        if self.proof_semantics != FINDING_STATUS_PROOF_SEMANTICS {
            return Err(FindingError::InvalidField("proof_semantics"));
        }
        require_bounded_id(&self.feed_id, "feed_id")?;
        if self.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE {
            return Err(FindingError::InvalidField("key_domain_nonce"));
        }
        require_i_json_u64(self.map_epoch, "map_epoch")?;
        require_nonzero(self.map_epoch, "map_epoch")?;
        require_bounded_id(&self.operator_id, "operator_id")?;
        require_ed25519(&self.operator_key, "operator_key")?;
        require_i_json_u64(self.operator_key_epoch, "operator_key_epoch")?;
        require_nonzero(self.operator_key_epoch, "operator_key_epoch")?;
        require_hex64(&self.root_hash, "root_hash")?;
        if usize::from(self.tree_depth) != FINDING_STATUS_SPARSE_DEPTH {
            return Err(FindingError::InvalidField("tree_depth"));
        }
        if self.hash_algorithm != FINDING_STATUS_HASH_ALGORITHM {
            return Err(FindingError::InvalidField("hash_algorithm"));
        }
        if self.key_hash_domain != FINDING_STATUS_KEY_HASH_DOMAIN {
            return Err(FindingError::InvalidField("key_hash_domain"));
        }
        if self.empty_leaf_domain != FINDING_STATUS_EMPTY_LEAF_DOMAIN {
            return Err(FindingError::InvalidField("empty_leaf_domain"));
        }
        if self.occupied_leaf_domain != FINDING_STATUS_OCCUPIED_LEAF_DOMAIN {
            return Err(FindingError::InvalidField("occupied_leaf_domain"));
        }
        if self.branch_domain != FINDING_STATUS_BRANCH_DOMAIN {
            return Err(FindingError::InvalidField("branch_domain"));
        }
        require_hex64(&self.empty_leaf_hash, "empty_leaf_hash")?;
        if self.empty_leaf_hash != hex::encode(finding_status_empty_leaf_hash()) {
            return Err(FindingError::InvalidField("empty_leaf_hash"));
        }
        if self.anchor_refs.len() > MAX_FINDING_STATUS_ANCHOR_REFS {
            return Err(FindingError::SizeLimitExceeded("anchor_refs"));
        }
        let mut anchors = BTreeSet::new();
        for anchor in &self.anchor_refs {
            require_bounded_id(anchor, "anchor_refs[]")?;
            if !anchors.insert(anchor.as_str()) {
                return Err(FindingError::DuplicateEntry("anchor_refs[]"));
            }
        }
        require_nonzero(self.generated_at, "generated_at")?;
        require_window(
            self.valid_from,
            self.valid_until,
            "valid_from",
            "valid_until",
        )?;
        if self.generated_at < self.valid_from || self.generated_at >= self.valid_until {
            return Err(FindingError::InvalidValidityWindow);
        }
        self.verify_status_epoch_id()
    }

    /// Recompute the content-addressed status epoch id.
    pub fn verify_status_epoch_id(&self) -> Result<(), FindingError> {
        if compute_status_epoch_id(self)? == self.status_epoch_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("status_epoch_id"))
        }
    }
}

impl FindingStatusOperatorAuthorization {
    pub fn validate(&self) -> Result<(), FindingError> {
        require_bounded_id(&self.feed_id, "status_operator.feed_id")?;
        self.operator.validate("status_operator.operator")?;
        if let Some(revoked_from) = self.revoked_from {
            require_nonzero(revoked_from, "status_operator.revoked_from")?;
            if revoked_from <= self.operator.valid_from {
                return Err(FindingError::InvalidValidityWindow);
            }
        }
        Ok(())
    }
}

impl FindingStatusProofInput {
    /// Strict canonical digest of this unsigned verifier input.
    pub fn canonical_sha256(&self) -> Result<String, FindingError> {
        let bytes = chio_core_types::canonical_json_bytes(self)
            .map_err(|_| FindingError::Canonicalization)?;
        Ok(chio_core_types::crypto::sha256_hex(&bytes))
    }

    /// The finding id this proof authenticates.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        match self {
            Self::NonInclusion(proof) => &proof.finding_id,
            Self::Inclusion(proof) => &proof.finding_id,
        }
    }

    fn common(&self) -> ProofCommon<'_> {
        match self {
            Self::NonInclusion(proof) => ProofCommon {
                schema: &proof.schema,
                feed_id: &proof.feed_id,
                key_domain_nonce: proof.key_domain_nonce,
                map_epoch: proof.map_epoch,
                finding_id: &proof.finding_id,
                status_epoch_id: &proof.status_epoch_id,
                status_epoch_sha256: &proof.status_epoch_sha256,
                signed_status_epoch_b64: &proof.signed_status_epoch_b64,
                root_hash: &proof.root_hash,
                siblings: &proof.siblings,
                checked_at: proof.checked_at,
            },
            Self::Inclusion(proof) => ProofCommon {
                schema: &proof.schema,
                feed_id: &proof.feed_id,
                key_domain_nonce: proof.key_domain_nonce,
                map_epoch: proof.map_epoch,
                finding_id: &proof.finding_id,
                status_epoch_id: &proof.status_epoch_id,
                status_epoch_sha256: &proof.status_epoch_sha256,
                signed_status_epoch_b64: &proof.signed_status_epoch_b64,
                root_hash: &proof.root_hash,
                siblings: &proof.siblings,
                checked_at: proof.checked_at,
            },
        }
    }
}

/// Content-address the complete status epoch body under its schema domain.
pub fn compute_status_epoch_id(epoch: &FindingStatusEpoch) -> Result<String, FindingError> {
    let mut body = epoch.clone();
    body.status_epoch_id.clear();
    let canonical =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    let mut preimage = Vec::with_capacity(STATUS_EPOCH_ID_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(STATUS_EPOCH_ID_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(chio_core_types::crypto::sha256_hex(&preimage))
}

/// Digest of the exact signed status epoch envelope.
pub fn status_epoch_envelope_sha256(
    signed: &SignedFindingStatusEpoch,
) -> Result<String, FindingError> {
    signed_envelope_sha256(signed)
}

/// Build a portable non-inclusion carrier from one signed epoch and sparse
/// path. Construction rechecks the path against the signed root so a server
/// cannot accidentally publish a self-inconsistent response.
pub fn build_status_non_inclusion_proof_input(
    signed: &SignedFindingStatusEpoch,
    finding_id: &str,
    sparse: &FindingStatusSparseProof,
    checked_at: u64,
) -> Result<FindingStatusProofInput, FindingError> {
    signed.body.validate()?;
    require_nonzero(checked_at, "status_proof.checked_at")?;
    let root = decode_hex_32(&signed.body.root_hash, "status_epoch.root_hash")?;
    verify_finding_status_non_inclusion(&root, finding_id, sparse)
        .map_err(|_| FindingError::InvalidField("status_proof.path"))?;
    let (status_epoch_sha256, signed_status_epoch_b64, siblings) =
        portable_proof_members(signed, sparse)?;
    let proof = FindingStatusProofInput::NonInclusion(FindingStatusNonInclusionProofInput {
        schema: FINDING_STATUS_PROOF_INPUT_SCHEMA_V1.to_string(),
        feed_id: signed.body.feed_id.clone(),
        key_domain_nonce: signed.body.key_domain_nonce,
        map_epoch: signed.body.map_epoch,
        finding_id: finding_id.to_string(),
        status_epoch_id: signed.body.status_epoch_id.clone(),
        status_epoch_sha256,
        signed_status_epoch_b64,
        root_hash: signed.body.root_hash.clone(),
        siblings,
        checked_at,
    });
    ensure_proof_size(&proof)?;
    Ok(proof)
}

/// Build a portable inclusion carrier for the exact retraction intent.
pub fn build_status_inclusion_proof_input(
    signed: &SignedFindingStatusEpoch,
    finding_id: &str,
    retraction_intent_sha256: &str,
    sparse: &FindingStatusSparseProof,
    checked_at: u64,
) -> Result<FindingStatusProofInput, FindingError> {
    signed.body.validate()?;
    require_nonzero(checked_at, "status_proof.checked_at")?;
    let root = decode_hex_32(&signed.body.root_hash, "status_epoch.root_hash")?;
    verify_finding_status_inclusion(&root, finding_id, retraction_intent_sha256, sparse)
        .map_err(|_| FindingError::InvalidField("status_proof.path"))?;
    let (status_epoch_sha256, signed_status_epoch_b64, siblings) =
        portable_proof_members(signed, sparse)?;
    let proof = FindingStatusProofInput::Inclusion(FindingStatusInclusionProofInput {
        schema: FINDING_STATUS_PROOF_INPUT_SCHEMA_V1.to_string(),
        feed_id: signed.body.feed_id.clone(),
        key_domain_nonce: signed.body.key_domain_nonce,
        map_epoch: signed.body.map_epoch,
        finding_id: finding_id.to_string(),
        status_epoch_id: signed.body.status_epoch_id.clone(),
        status_epoch_sha256,
        signed_status_epoch_b64,
        root_hash: signed.body.root_hash.clone(),
        siblings,
        checked_at,
        status: FindingStatusValue::Retracted,
        retraction_intent_sha256: retraction_intent_sha256.to_string(),
    });
    ensure_proof_size(&proof)?;
    Ok(proof)
}

/// Verify the epoch against a governance-pinned feed-operator authorization.
pub fn verify_signed_status_epoch(
    signed: &SignedFindingStatusEpoch,
    authorization: &FindingStatusOperatorAuthorization,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    authorization.validate()?;
    if signed.body.feed_id != authorization.feed_id {
        return Err(FindingError::AuthorityMismatch("status_epoch.feed_id"));
    }
    if signed.body.operator_id != authorization.operator.authority_id
        || signed.body.operator_key != authorization.operator.key
        || signed.body.operator_key_epoch != authorization.operator.key_epoch
    {
        return Err(FindingError::AuthorityMismatch("status_epoch.operator"));
    }
    if signed.body.valid_from < authorization.operator.valid_from
        || signed.body.valid_until > authorization.operator.valid_until
        || signed.body.generated_at < authorization.operator.valid_from
        || signed.body.generated_at >= authorization.operator.valid_until
    {
        return Err(FindingError::AuthorityMismatch(
            "status_epoch.operator_validity",
        ));
    }
    if authorization
        .revoked_from
        .is_some_and(|revoked_from| signed.body.generated_at >= revoked_from)
    {
        return Err(FindingError::AuthorityMismatch(
            "status_epoch.operator_revocation",
        ));
    }
    verify_pinned_envelope(signed, &authorization.operator.key, "status_epoch")
}

/// Parse exact canonical signed epoch bytes. Duplicate, unknown, non-I-JSON,
/// non-canonical, and typed-round-trip mismatches all reject.
pub fn parse_signed_status_epoch(raw: &[u8]) -> Result<SignedFindingStatusEpoch, FindingError> {
    parse_exact_canonical(raw, MAX_FINDING_STATUS_EPOCH_BYTES, "status_epoch")
}

/// Decode exact signed epoch bytes from the proof carrier.
pub fn decode_signed_status_epoch_b64(
    encoded: &str,
) -> Result<SignedFindingStatusEpoch, FindingError> {
    let raw = decode_bounded_b64(encoded, "status_epoch.encoded")?;
    parse_signed_status_epoch(&raw)
}

/// Parse a strict canonical portable proof input.
pub fn parse_status_proof_input(raw: &[u8]) -> Result<FindingStatusProofInput, FindingError> {
    parse_exact_canonical(raw, MAX_FINDING_STATUS_PROOF_BYTES, "status_proof")
}

/// Decode and strict-parse a portable proof input.
pub fn decode_status_proof_input_b64(
    encoded: &str,
) -> Result<FindingStatusProofInput, FindingError> {
    let raw = decode_bounded_b64(encoded, "status_proof.encoded")?;
    parse_status_proof_input(&raw)
}

/// Verify the signed epoch, all portable cross-bindings, freshness, and path.
pub fn verify_status_proof_input(
    proof: &FindingStatusProofInput,
    authorization: &FindingStatusOperatorAuthorization,
    freshness: FindingStatusFreshnessPolicy,
) -> Result<SignedFindingStatusEpoch, FindingError> {
    let common = proof.common();
    validate_common(&common)?;
    let signed_epoch = decode_signed_status_epoch_b64(common.signed_status_epoch_b64)?;
    verify_signed_status_epoch(&signed_epoch, authorization)?;
    let envelope_digest = status_epoch_envelope_sha256(&signed_epoch)?;
    if common.feed_id != signed_epoch.body.feed_id
        || common.key_domain_nonce != signed_epoch.body.key_domain_nonce
        || common.map_epoch != signed_epoch.body.map_epoch
        || common.status_epoch_id != signed_epoch.body.status_epoch_id
        || common.status_epoch_sha256 != envelope_digest
        || common.root_hash != signed_epoch.body.root_hash
    {
        return Err(FindingError::InvalidField("status_proof.epoch_binding"));
    }
    verify_freshness(
        &signed_epoch.body,
        common.checked_at,
        authorization,
        freshness,
    )?;

    let root_hash = decode_hex_32(common.root_hash, "status_proof.root_hash")?;
    let key_hash = finding_status_key_hash(common.finding_id)
        .map_err(|_| FindingError::InvalidField("status_proof.finding_id"))?;
    let siblings = common
        .siblings
        .iter()
        .map(|sibling| decode_hex_32(sibling, "status_proof.siblings[]"))
        .collect::<Result<Vec<_>, _>>()?;

    match proof {
        FindingStatusProofInput::NonInclusion(_) => {
            let sparse = FindingStatusSparseProof {
                key_hash,
                siblings,
                leaf: None,
            };
            verify_finding_status_non_inclusion(&root_hash, common.finding_id, &sparse)
                .map_err(|_| FindingError::InvalidField("status_proof.path"))?;
        }
        FindingStatusProofInput::Inclusion(inclusion) => {
            require_hex64(
                &inclusion.retraction_intent_sha256,
                "retraction_intent_sha256",
            )?;
            let sparse = FindingStatusSparseProof {
                key_hash,
                siblings,
                leaf: Some(FindingStatusSparseLeaf {
                    finding_id: common.finding_id.to_string(),
                    retraction_intent_sha256: inclusion.retraction_intent_sha256.clone(),
                }),
            };
            verify_finding_status_inclusion(
                &root_hash,
                common.finding_id,
                &inclusion.retraction_intent_sha256,
                &sparse,
            )
            .map_err(|_| FindingError::InvalidField("status_proof.path"))?;
        }
    }
    Ok(signed_epoch)
}

fn validate_common(common: &ProofCommon<'_>) -> Result<(), FindingError> {
    if common.schema != FINDING_STATUS_PROOF_INPUT_SCHEMA_V1 {
        return Err(FindingError::UnsupportedSchema(common.schema.to_string()));
    }
    require_bounded_id(common.feed_id, "status_proof.feed_id")?;
    if common.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE {
        return Err(FindingError::InvalidField("status_proof.key_domain_nonce"));
    }
    require_i_json_u64(common.map_epoch, "status_proof.map_epoch")?;
    require_nonzero(common.map_epoch, "status_proof.map_epoch")?;
    require_hex64(common.finding_id, "status_proof.finding_id")?;
    require_hex64(common.status_epoch_id, "status_proof.status_epoch_id")?;
    require_hex64(
        common.status_epoch_sha256,
        "status_proof.status_epoch_sha256",
    )?;
    if common.signed_status_epoch_b64.is_empty()
        || common.signed_status_epoch_b64.len() > MAX_FINDING_STATUS_ENCODED_BYTES
    {
        return Err(FindingError::SizeLimitExceeded(
            "status_proof.signed_status_epoch_b64",
        ));
    }
    require_hex64(common.root_hash, "status_proof.root_hash")?;
    if common.siblings.len() != FINDING_STATUS_SPARSE_DEPTH {
        return Err(FindingError::InvalidField("status_proof.siblings"));
    }
    for sibling in common.siblings {
        require_hex64(sibling, "status_proof.siblings[]")?;
    }
    require_nonzero(common.checked_at, "status_proof.checked_at")
}

fn portable_proof_members(
    signed: &SignedFindingStatusEpoch,
    sparse: &FindingStatusSparseProof,
) -> Result<(String, String, Vec<String>), FindingError> {
    let signed_bytes = chio_core_types::canonical_json_bytes(signed)
        .map_err(|_| FindingError::Canonicalization)?;
    if signed_bytes.len() > MAX_FINDING_STATUS_EPOCH_BYTES {
        return Err(FindingError::SizeLimitExceeded("status_epoch"));
    }
    Ok((
        status_epoch_envelope_sha256(signed)?,
        STANDARD.encode(signed_bytes),
        sparse.siblings.iter().map(hex::encode).collect(),
    ))
}

fn ensure_proof_size(proof: &FindingStatusProofInput) -> Result<(), FindingError> {
    let canonical =
        chio_core_types::canonical_json_bytes(proof).map_err(|_| FindingError::Canonicalization)?;
    if canonical.len() > MAX_FINDING_STATUS_PROOF_BYTES {
        Err(FindingError::SizeLimitExceeded("status_proof"))
    } else {
        Ok(())
    }
}

fn verify_freshness(
    epoch: &FindingStatusEpoch,
    checked_at: u64,
    authorization: &FindingStatusOperatorAuthorization,
    freshness: FindingStatusFreshnessPolicy,
) -> Result<(), FindingError> {
    require_nonzero(freshness.now, "status_freshness.now")?;
    require_nonzero(
        freshness.max_epoch_age_secs,
        "status_freshness.max_epoch_age_secs",
    )?;
    if checked_at < epoch.generated_at
        || checked_at < epoch.valid_from
        || checked_at >= epoch.valid_until
        || checked_at > freshness.now
        || freshness.now < epoch.valid_from
        || freshness.now >= epoch.valid_until
    {
        return Err(FindingError::InvalidField("status_proof.freshness"));
    }
    let epoch_age = freshness
        .now
        .checked_sub(epoch.generated_at)
        .ok_or(FindingError::InvalidField("status_proof.freshness"))?;
    let proof_age = freshness
        .now
        .checked_sub(checked_at)
        .ok_or(FindingError::InvalidField("status_proof.freshness"))?;
    if epoch_age > freshness.max_epoch_age_secs || proof_age > freshness.max_epoch_age_secs {
        return Err(FindingError::InvalidField("status_proof.freshness"));
    }
    if authorization
        .revoked_from
        .is_some_and(|revoked_from| freshness.now >= revoked_from)
    {
        return Err(FindingError::AuthorityMismatch(
            "status_epoch.operator_revocation",
        ));
    }
    Ok(())
}

fn parse_exact_canonical<T>(
    raw: &[u8],
    max_bytes: usize,
    field: &'static str,
) -> Result<T, FindingError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if raw.is_empty() || raw.len() > max_bytes {
        return Err(FindingError::SizeLimitExceeded(field));
    }
    let text = std::str::from_utf8(raw).map_err(|_| FindingError::NonCanonicalBytes(field))?;
    let strict = chio_core_types::canonical_json_bytes_from_str(text)
        .map_err(|_| FindingError::NonCanonicalBytes(field))?;
    if strict.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes(field));
    }
    let typed: T = serde_json::from_slice(raw).map_err(|_| FindingError::InvalidField(field))?;
    let typed_canonical = chio_core_types::canonical_json_bytes(&typed)
        .map_err(|_| FindingError::Canonicalization)?;
    if typed_canonical.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes(field));
    }
    Ok(typed)
}

fn decode_bounded_b64(encoded: &str, field: &'static str) -> Result<Vec<u8>, FindingError> {
    if encoded.is_empty() || encoded.len() > MAX_FINDING_STATUS_ENCODED_BYTES {
        return Err(FindingError::SizeLimitExceeded(field));
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| FindingError::InvalidField(field))
}

fn decode_hex_32(value: &str, field: &'static str) -> Result<[u8; 32], FindingError> {
    require_hex64(value, field)?;
    let decoded = hex::decode(value).map_err(|_| FindingError::MalformedDigest(field))?;
    decoded
        .try_into()
        .map_err(|_| FindingError::MalformedDigest(field))
}
