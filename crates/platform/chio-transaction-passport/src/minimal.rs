use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use chio_core_types::{
    canonical::{canonical_json_bytes, canonical_json_bytes_from_str},
    crypto::{Keypair, Signature},
    hashing::Hash,
    merkle::{leaf_hash, MerkleProof},
    PublicKey,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::TransactionPassportError;
use super::evidence_graph::{
    validate_claim_set_artifact_bindings, validate_claim_set_node_binding, validate_evidence_graph,
    validate_evidence_graph_artifact_bytes, validate_minimal_governed_action_artifact_bindings,
    validate_minimal_governed_action_evidence, validate_verifier_policy_node_binding,
    TransactionEvidenceGraph,
};
use super::ids::TRANSACTION_PASSPORT_SCHEMA_ID;
use super::types::{
    TransactionClaimResult, TransactionOmissionPolicyEntry, TransactionPassport,
    TransactionVerifierReport,
};
use super::validation::{require_non_empty, validate_bundle_relative_path, validate_sha256_hex};
use super::verifier_policy::{
    validate_standalone_transaction_claims, validate_verifier_policy, TransactionVerifierPolicy,
};

pub fn verify_minimal_passport_schema(
    passport: &TransactionPassport,
) -> Result<(), TransactionPassportError> {
    verify_minimal_passport_schema_at(passport, Utc::now())
}

pub fn verify_minimal_passport_schema_at(
    passport: &TransactionPassport,
    now: DateTime<Utc>,
) -> Result<(), TransactionPassportError> {
    if passport.schema != TRANSACTION_PASSPORT_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedSchema(
            passport.schema.clone(),
        ));
    }
    require_non_empty(&passport.id, "passport.id").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "id".to_string(),
            message: error.to_string(),
        }
    })?;
    require_non_empty(&passport.issued_at, "passport.issued_at").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "issued_at".to_string(),
            message: error.to_string(),
        }
    })?;
    validate_passport_validity_window(passport, now)?;
    require_non_empty(&passport.issuer, "passport.issuer").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "issuer".to_string(),
            message: error.to_string(),
        }
    })?;
    require_non_empty(&passport.signature, "passport.signature").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "signature".to_string(),
            message: error.to_string(),
        }
    })?;
    Signature::from_hex(&passport.signature).map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "signature".to_string(),
            message: error.to_string(),
        }
    })?;

    validate_sha256_hex(&passport.evidence_graph_sha256).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphDigest(passport.evidence_graph_sha256.clone())
    })?;
    validate_sha256_hex(&passport.claim_set_sha256).map_err(|_| {
        TransactionPassportError::InvalidClaimSetDigest(passport.claim_set_sha256.clone())
    })?;
    validate_sha256_hex(&passport.verifier_policy_sha256).map_err(|_| {
        TransactionPassportError::InvalidVerifierPolicyDigest(
            passport.verifier_policy_sha256.clone(),
        )
    })?;
    validate_bundle_relative_path(&passport.evidence_graph_path).map_err(|_| {
        TransactionPassportError::UnsafeEvidenceGraphPath(passport.evidence_graph_path.clone())
    })?;
    validate_bundle_relative_path(&passport.claim_set_path).map_err(|_| {
        TransactionPassportError::UnsafeClaimSetPath(passport.claim_set_path.clone())
    })?;
    validate_bundle_relative_path(&passport.verifier_policy_path).map_err(|_| {
        TransactionPassportError::UnsafeVerifierPolicyPath(passport.verifier_policy_path.clone())
    })?;

    Ok(())
}

fn validate_passport_validity_window(
    passport: &TransactionPassport,
    now: DateTime<Utc>,
) -> Result<(), TransactionPassportError> {
    let not_before = optional_passport_timestamp("not_before", passport.not_before.as_deref())?;
    let expires_at = optional_passport_timestamp("expires_at", passport.expires_at.as_deref())?;
    if let (Some(not_before), Some(expires_at)) = (not_before, expires_at) {
        if expires_at <= not_before {
            return Err(TransactionPassportError::InvalidPassportValidityWindow(
                "expires_at must be after not_before".to_string(),
            ));
        }
    }
    if let Some(not_before) = not_before {
        if now < not_before {
            return Err(TransactionPassportError::PassportNotYetValid {
                not_before: not_before.to_rfc3339(),
                now: now.to_rfc3339(),
            });
        }
    }
    if let Some(expires_at) = expires_at {
        if now >= expires_at {
            return Err(TransactionPassportError::PassportExpired {
                expires_at: expires_at.to_rfc3339(),
                now: now.to_rfc3339(),
            });
        }
    }
    Ok(())
}

fn optional_passport_timestamp(
    field: &str,
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, TransactionPassportError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .map_err(|error| TransactionPassportError::InvalidPassportTimestamp {
                    field: field.to_string(),
                    value: value.to_string(),
                    message: error.to_string(),
                })
        })
        .transpose()
}

pub fn sign_transaction_passport(
    passport: &TransactionPassport,
    keypair: &Keypair,
) -> Result<String, TransactionPassportError> {
    let issuer_key = passport_issuer_public_key(&passport.issuer)?;
    if issuer_key != keypair.public_key() {
        return Err(TransactionPassportError::InvalidPassportSignature(
            "signer does not match issuer".to_string(),
        ));
    }
    let body = transaction_passport_signature_body(passport)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| TransactionPassportError::InvalidPassportSignature(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn verify_transaction_passport_signature(
    passport: &TransactionPassport,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    verify_minimal_passport_schema(passport)?;
    if trusted_root_signer_keys.is_empty() {
        return Err(TransactionPassportError::MissingTrustedTransactionRootKeys);
    }
    let signer_key = passport_issuer_public_key(&passport.issuer)?;
    if !trusted_root_signer_keys
        .iter()
        .any(|trusted_key| trusted_key == &signer_key)
    {
        return Err(TransactionPassportError::UntrustedTransactionPassportSigner);
    }
    let signature = Signature::from_hex(&passport.signature)
        .map_err(|error| TransactionPassportError::InvalidPassportSignature(error.to_string()))?;
    let body = transaction_passport_signature_body(passport)?;
    let verified = signer_key
        .verify_canonical(&body, &signature)
        .map_err(|error| TransactionPassportError::InvalidPassportSignature(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::InvalidPassportSignature(
            "verification failed".to_string(),
        ))
    }
}

pub fn verify_transaction_passport_signature_with_evidence_graph(
    passport: &TransactionPassport,
    signed_evidence_graph_bytes: &[u8],
    scoped_evidence_graph_bytes: &[u8],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    let mut signed_passport = passport.clone();
    signed_passport.evidence_graph_sha256 = super::sha256_hex(signed_evidence_graph_bytes);
    verify_transaction_passport_signature(&signed_passport, trusted_root_signer_keys)?;
    if signed_evidence_graph_bytes != scoped_evidence_graph_bytes {
        validate_scoped_evidence_graph_subset(
            signed_evidence_graph_bytes,
            scoped_evidence_graph_bytes,
        )?;
    }
    Ok(())
}

fn validate_scoped_evidence_graph_subset(
    signed_evidence_graph_bytes: &[u8],
    scoped_evidence_graph_bytes: &[u8],
) -> Result<(), TransactionPassportError> {
    let signed_graph: Value =
        serde_json::from_slice(signed_evidence_graph_bytes).map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    let scoped_graph: Value =
        serde_json::from_slice(scoped_evidence_graph_bytes).map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    ensure_scoped_entries_are_subset(&signed_graph, &scoped_graph, "nodes")?;
    ensure_scoped_entries_are_subset(&signed_graph, &scoped_graph, "edges")
}

fn ensure_scoped_entries_are_subset(
    signed_graph: &Value,
    scoped_graph: &Value,
    field: &str,
) -> Result<(), TransactionPassportError> {
    let signed_entries = graph_entries(signed_graph, field)?;
    let scoped_entries = graph_entries(scoped_graph, field)?;
    let signed_entry_keys = evidence_graph_entry_keys(signed_entries)?;
    for scoped_entry in scoped_entries {
        let scoped_entry_key = evidence_graph_entry_key(scoped_entry)?;
        if !signed_entry_keys.contains(&scoped_entry_key) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("scoped evidence graph {field} entry is not in signed root graph"),
            ));
        }
    }
    Ok(())
}

fn graph_entries<'a>(
    graph: &'a Value,
    field: &str,
) -> Result<&'a Vec<Value>, TransactionPassportError> {
    graph.get(field).and_then(Value::as_array).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "evidence graph missing {field}"
        ))
    })
}

fn evidence_graph_entry_keys(
    entries: &[Value],
) -> Result<BTreeSet<String>, TransactionPassportError> {
    entries.iter().map(evidence_graph_entry_key).collect()
}

fn evidence_graph_entry_key(entry: &Value) -> Result<String, TransactionPassportError> {
    serde_json::to_string(entry)
        .map_err(|error| TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string()))
}

fn transaction_passport_signature_body(
    passport: &TransactionPassport,
) -> Result<serde_json::Value, TransactionPassportError> {
    let mut body = serde_json::to_value(passport).map_err(|error| {
        TransactionPassportError::InvalidPassportSignature(format!(
            "signature body invalid: {error}"
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        TransactionPassportError::InvalidPassportSignature("signature body invalid".to_string())
    })?;
    object.remove("signature");
    Ok(body)
}

fn passport_issuer_public_key(issuer: &str) -> Result<PublicKey, TransactionPassportError> {
    let public_key_hex = issuer.strip_prefix("did:chio:").unwrap_or(issuer);
    if public_key_hex.len() != 64 || !public_key_hex.bytes().all(is_lower_hex_byte) {
        return Err(TransactionPassportError::InvalidPassportSignature(
            "issuer is not self-certifying".to_string(),
        ));
    }
    PublicKey::from_hex(public_key_hex).map_err(|error| {
        TransactionPassportError::InvalidPassportSignature(format!(
            "issuer public key invalid: {error}"
        ))
    })
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

pub fn verify_minimal_passport_artifacts(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    // No artifact bytes or pinned checkpoint keys are available on this
    // surface, so the anchored transparency tier is unreachable here by
    // construction.
    verify_minimal_passport_artifacts_with_anchor_inputs(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        &BTreeMap::new(),
        &[],
    )
}

fn verify_minimal_passport_artifacts_with_anchor_inputs(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_minimal_passport_schema(passport)?;

    let evidence_graph_sha256 = super::sha256_hex(evidence_graph_bytes);
    if evidence_graph_sha256 != passport.evidence_graph_sha256 {
        return Err(TransactionPassportError::EvidenceGraphDigestMismatch {
            expected: passport.evidence_graph_sha256.clone(),
            actual: evidence_graph_sha256,
        });
    }

    let verifier_policy_sha256 = super::sha256_hex(verifier_policy_bytes);
    if verifier_policy_sha256 != passport.verifier_policy_sha256 {
        return Err(TransactionPassportError::VerifierPolicyDigestMismatch {
            expected: passport.verifier_policy_sha256.clone(),
            actual: verifier_policy_sha256,
        });
    }

    let evidence_graph: TransactionEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    let evidence_graph_value: Value =
        serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    validate_evidence_graph(&evidence_graph)?;
    validate_claim_set_node_binding(
        &evidence_graph,
        &passport.claim_set_path,
        &passport.claim_set_sha256,
    )?;

    let verifier_policy: TransactionVerifierPolicy = serde_json::from_slice(verifier_policy_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
    validate_verifier_policy(&verifier_policy)?;
    validate_passport_omission_policy(passport, &verifier_policy)?;
    enforce_verifier_policy_gates(
        passport,
        &verifier_policy,
        &evidence_graph_value,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?;
    let transparency_state = evidence_graph_transparency_state(
        evidence_graph_nodes(&evidence_graph_value)?,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?;

    Ok(TransactionVerifierReport::verified(passport, passport_path)
        .with_transparency_state(transparency_state))
}

pub fn verify_passport_root_and_claim_set_artifacts(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_passport_root_and_claim_set_artifacts_with_external_claims(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_root_signer_keys,
        &[],
    )
}

pub fn verify_passport_root_and_claim_set_artifacts_with_external_claims(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_transaction_passport_signature(passport, trusted_root_signer_keys)?;
    // Passport root signers are not checkpoint signers: the issuer's own key
    // is necessarily in `trusted_root_signer_keys`, so reusing that set would
    // reduce the anchored tier to issuer self-assertion. Callers that pin log
    // kernel keys use the `_with_transparency_anchors` entry point.
    verify_passport_root_and_claim_set_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        &[],
        externally_verified_claims,
    )
}

/// Keys a verifier pins out of band for one verification.
///
/// The two roles are deliberately separate. A passport issuer is always in
/// `passport_root_signers` (that is what makes its passport verifiable), so
/// reusing that set for checkpoints would reduce the `trust_anchored` tier to
/// issuer self-assertion.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransactionTrustAnchors<'a> {
    /// Keys accepted as passport root signers.
    pub passport_root_signers: &'a [PublicKey],
    /// Transparency log kernel keys whose signed checkpoints may promote
    /// evidence to the `trust_anchored` tier. Empty means the anchored tier
    /// is unreachable and verification settles at the preview tier.
    pub checkpoint_signers: &'a [PublicKey],
}

impl TransactionTrustAnchors<'_> {
    /// Reject a checkpoint signer set that overlaps the passport root signers,
    /// so a verifier cannot configure the anchored tier into self-attestation.
    fn validate(&self) -> Result<(), TransactionPassportError> {
        if self
            .checkpoint_signers
            .iter()
            .any(|checkpoint_key| self.passport_root_signers.contains(checkpoint_key))
        {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                "trusted checkpoint signer keys must be disjoint from passport root signer keys"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Verify a root passport and additionally allow promotion to the
/// `trust_anchored` transparency tier using the pinned checkpoint keys in
/// `trust_anchors`.
pub fn verify_passport_root_and_claim_set_artifacts_with_transparency_anchors(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trust_anchors: TransactionTrustAnchors<'_>,
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_transaction_passport_signature(passport, trust_anchors.passport_root_signers)?;
    trust_anchors.validate()?;
    verify_passport_root_and_claim_set_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trust_anchors.checkpoint_signers,
        externally_verified_claims,
    )
}

pub fn verify_passport_root_and_claim_set_artifacts_unchecked_signature_with_external_claims(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    // No pinned checkpoint keys on this surface, so the anchored transparency
    // tier is unreachable.
    verify_passport_root_and_claim_set_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        &[],
        externally_verified_claims,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_passport_root_and_claim_set_artifacts_bound(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    let claim_results = verify_signed_root_graph_binding(
        passport,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_checkpoint_signer_keys,
        externally_verified_claims,
    )?;
    let evidence_graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    let transparency_state = evidence_graph_transparency_state(
        evidence_graph_nodes(&evidence_graph)?,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?;
    Ok(TransactionVerifierReport::verified(passport, passport_path)
        .with_transparency_state(transparency_state.to_string())
        .with_claim_results(claim_results))
}

/// Transparency state derived from evidence-graph bytes alone.
///
/// Anchor verification needs artifact bytes and pinned checkpoint signer
/// keys, so this surface can report `transparency_preview` or `not_present`
/// but never `trust_anchored`.
pub fn transaction_evidence_graph_transparency_state(
    evidence_graph_bytes: &[u8],
) -> Result<String, TransactionPassportError> {
    let evidence_graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    Ok(evidence_graph_transparency_state(
        evidence_graph_nodes(&evidence_graph)?,
        &BTreeMap::new(),
        &[],
    )?
    .to_string())
}

/// Transparency state derived with artifact bytes and separately pinned
/// checkpoint signer keys. This is the product integration surface for merged
/// family reports whose passport verification happens in a separate step.
pub fn transaction_evidence_graph_transparency_state_with_anchors(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> Result<String, TransactionPassportError> {
    let evidence_graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    Ok(evidence_graph_transparency_state(
        evidence_graph_nodes(&evidence_graph)?,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?
    .to_string())
}

fn verify_signed_root_graph_binding(
    passport: &TransactionPassport,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
    externally_verified_claims: &[String],
) -> Result<Vec<TransactionClaimResult>, TransactionPassportError> {
    let evidence_graph_sha256 = super::sha256_hex(evidence_graph_bytes);
    if evidence_graph_sha256 != passport.evidence_graph_sha256 {
        return Err(TransactionPassportError::EvidenceGraphDigestMismatch {
            expected: passport.evidence_graph_sha256.clone(),
            actual: evidence_graph_sha256,
        });
    }

    let verifier_policy_sha256 = super::sha256_hex(verifier_policy_bytes);
    if verifier_policy_sha256 != passport.verifier_policy_sha256 {
        return Err(TransactionPassportError::VerifierPolicyDigestMismatch {
            expected: passport.verifier_policy_sha256.clone(),
            actual: verifier_policy_sha256,
        });
    }

    let verifier_policy: TransactionVerifierPolicy = serde_json::from_slice(verifier_policy_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
    validate_verifier_policy(&verifier_policy)?;
    validate_passport_omission_policy(passport, &verifier_policy)?;
    let evidence_graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    validate_root_graph_schema(&evidence_graph)?;
    enforce_verifier_policy_gates(
        passport,
        &verifier_policy,
        &evidence_graph,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?;
    let effective_required_claims = verifier_policy.effective_required_claims();
    let nodes = evidence_graph_nodes(&evidence_graph)?;
    let claim_set_path = validate_root_graph_node_binding(
        nodes,
        "claim-set",
        &passport.claim_set_path,
        &passport.claim_set_sha256,
    )?;
    validate_root_graph_node_binding(
        nodes,
        "verifier-policy",
        &passport.verifier_policy_path,
        &passport.verifier_policy_sha256,
    )?;
    validate_claim_set_bytes(
        artifacts,
        &claim_set_path,
        &passport.claim_set_sha256,
        &effective_required_claims,
        externally_verified_claims,
    )
}

fn validate_root_graph_schema(evidence_graph: &Value) -> Result<(), TransactionPassportError> {
    let schema = evidence_graph
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(
                "evidence graph missing schema".to_string(),
            )
        })?;
    if schema != super::ids::TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedEvidenceGraphSchema(
            schema.to_string(),
        ));
    }
    Ok(())
}

fn evidence_graph_nodes(evidence_graph: &Value) -> Result<&Vec<Value>, TransactionPassportError> {
    evidence_graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(
                "evidence graph missing nodes".to_string(),
            )
        })
}

fn validate_root_graph_node_binding(
    nodes: &[Value],
    role: &'static str,
    expected_path: &str,
    expected_sha256: &str,
) -> Result<String, TransactionPassportError> {
    let node = root_graph_node_for_role(nodes, role)?;
    let path = graph_node_string(node, "path")?;
    if !path_matches_or_contains_suffix(path, expected_path) {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!("{role} evidence graph path mismatch"),
        ));
    }
    let sha256 = graph_node_string(node, "sha256")?;
    if sha256 != expected_sha256 {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!("{role} evidence graph digest mismatch"),
        ));
    }
    Ok(path.to_string())
}

fn root_graph_node_for_role<'a>(
    nodes: &'a [Value],
    role: &'static str,
) -> Result<&'a Value, TransactionPassportError> {
    let mut matches = nodes.iter().filter(|node| {
        node.get("role")
            .and_then(Value::as_str)
            .is_some_and(|node_role| node_role == role)
    });
    let node = matches.next().ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "minimal governed action evidence missing: {role}"
        ))
    })?;
    if matches.next().is_some() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!("duplicate evidence graph node role: {role}"),
        ));
    }
    Ok(node)
}

fn graph_node_string<'a>(
    node: &'a Value,
    field: &'static str,
) -> Result<&'a str, TransactionPassportError> {
    node.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
                "evidence graph node {field} must not be empty"
            ))
        })
}

fn enforce_verifier_policy_gates(
    passport: &TransactionPassport,
    policy: &TransactionVerifierPolicy,
    evidence_graph: &Value,
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if !policy.accepted_passport_issuers().is_empty()
        && !policy
            .accepted_passport_issuers()
            .iter()
            .any(|issuer| verifier_policy_issuer_matches(issuer, &passport.issuer))
    {
        return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
            "passport issuer not accepted by verifier policy".to_string(),
        ));
    }

    let nodes = evidence_graph_nodes(evidence_graph)?;
    for required_role in policy.required_evidence_roles() {
        if !nodes.iter().any(|node| {
            node.get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| role == required_role)
        }) {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                format!("missing verifier policy required evidence role: {required_role}"),
            ));
        }
    }

    let transparency_state =
        evidence_graph_transparency_state(nodes, artifacts, trusted_checkpoint_signer_keys)?;
    if !policy.accepted_transparency_states().is_empty()
        && !policy
            .accepted_transparency_states()
            .iter()
            .any(|state| state == transparency_state)
    {
        return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
            format!("transparency state not accepted by verifier policy: {transparency_state}"),
        ));
    }

    Ok(())
}

fn verifier_policy_issuer_matches(accepted_issuer: &str, passport_issuer: &str) -> bool {
    accepted_issuer == passport_issuer
        || issuer_key_part(accepted_issuer) == issuer_key_part(passport_issuer)
}

fn issuer_key_part(issuer: &str) -> &str {
    issuer.strip_prefix("did:chio:").unwrap_or(issuer)
}

const TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1_ID: &str = "chio.transparency.inclusion-proof.v1";
const TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V2_ID: &str = "chio.transparency.inclusion-proof.v2";
const CHECKPOINT_STATEMENT_SCHEMA_V1_ID: &str = "chio.checkpoint_statement.v1";
const CHECKPOINT_STATEMENT_SCHEMA_V2_ID: &str = "chio.checkpoint_statement.v2";
const RECEIPT_EVIDENCE_ROLE: &str = "receipt";

/// Payload of a `chio.transparency.inclusion-proof.v2` artifact as consumed
/// for transparency-state promotion. V2 uses RFC 6962 hashing over receipt
/// bytes and embeds the signed checkpoint statement. The registered v1
/// selective-disclosure format has different leaf and node hashing and remains
/// preview-only here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencyInclusionProofArtifact {
    schema: String,
    proof_id: String,
    log_id: String,
    artifact_ref: String,
    root_hash: String,
    leaf_hash: String,
    tree_size: u64,
    leaf_index: u64,
    checkpoint: String,
    inclusion_path: Vec<String>,
    verified_at: u64,
    checkpoint_statement: CheckpointStatementArtifact,
}

/// Signed checkpoint statement embedded in an inclusion-proof artifact. The
/// body is kept as raw JSON so the signature verifies over exactly the bytes
/// the signer canonicalized.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointStatementArtifact {
    body: Value,
    signature: String,
}

/// Strict wire mirror of a kernel checkpoint body. This crate deliberately
/// does not depend on `chio-kernel`, so it validates the same signed fields
/// locally after signature verification.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointStatementBody {
    schema: String,
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: Hash,
    issued_at: u64,
    kernel_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_checkpoint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_root: Option<Hash>,
}

#[derive(Serialize)]
struct CheckpointStatementChainLeaf {
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    merkle_root: Hash,
}

impl CheckpointStatementBody {
    fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.schema.as_str(),
            CHECKPOINT_STATEMENT_SCHEMA_V1_ID | CHECKPOINT_STATEMENT_SCHEMA_V2_ID
        ) {
            return Err(format!(
                "checkpoint statement carries unsupported schema {}",
                self.schema
            ));
        }
        if self.checkpoint_seq == 0 {
            return Err(
                "checkpoint statement checkpoint_seq must be greater than zero".to_string(),
            );
        }
        if self.batch_start_seq == 0 {
            return Err(
                "checkpoint statement batch_start_seq must be greater than zero".to_string(),
            );
        }
        let covered_entries = self
            .batch_end_seq
            .checked_sub(self.batch_start_seq)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| "checkpoint statement entry range is invalid".to_string())?;
        if self.tree_size == 0 || self.tree_size != covered_entries {
            return Err(format!(
                "checkpoint statement tree_size {} does not match covered entry count {}",
                self.tree_size, covered_entries
            ));
        }
        if self.schema == CHECKPOINT_STATEMENT_SCHEMA_V1_ID && self.chain_root.is_some() {
            return Err("v1 checkpoint statements cannot carry chain_root".to_string());
        }
        if self.schema == CHECKPOINT_STATEMENT_SCHEMA_V2_ID && self.checkpoint_seq == 1 {
            let Some(chain_root) = self.chain_root else {
                return Err("v2 checkpoint 1 must carry chain_root".to_string());
            };
            let chain_leaf = CheckpointStatementChainLeaf {
                checkpoint_seq: self.checkpoint_seq,
                batch_start_seq: self.batch_start_seq,
                batch_end_seq: self.batch_end_seq,
                merkle_root: self.merkle_root,
            };
            let chain_leaf_bytes = canonical_json_bytes(&chain_leaf).map_err(|error| {
                format!("checkpoint chain leaf is not canonicalizable: {error}")
            })?;
            if chain_root != leaf_hash(&chain_leaf_bytes) {
                return Err(
                    "chain_root of the first checkpoint does not commit its own chain leaf"
                        .to_string(),
                );
            }
        }
        if let Some(previous) = self.previous_checkpoint_sha256.as_deref() {
            validate_sha256_hex(previous).map_err(|()| {
                "checkpoint statement previous_checkpoint_sha256 is invalid".to_string()
            })?;
        }
        if self.issued_at == 0 {
            return Err("checkpoint statement issued_at must be greater than zero".to_string());
        }
        Ok(())
    }
}

/// Outcome of examining one transparency-inclusion-proof node.
enum TransparencyAnchor {
    /// The anchor verified against a pinned checkpoint signer.
    Verified,
    /// This verifier lacks the inputs to judge the anchor (no pinned
    /// checkpoint keys, or the artifact bytes are not in this bundle), so the
    /// node supports the preview tier and nothing stronger.
    NotEvaluable,
    /// The anchor was checkable and did not hold.
    Invalid(String),
}

/// Transparency state of an evidence graph, promoted to `trust_anchored` only
/// after cryptographic verification.
///
/// A node labeled as an inclusion proof is a promotion candidate, never a
/// promotion: the anchored tier requires the digest-bound artifact to carry a
/// Merkle inclusion proof whose root is committed by a checkpoint statement
/// signed by one of `trusted_checkpoint_signer_keys`, with the proven leaf
/// bound to this transaction's receipt.
///
/// A candidate this verifier cannot judge degrades to the preview tier. A
/// candidate it can judge and that fails is an error, not a downgrade:
/// silently reporting preview would let malformed transparency evidence ride
/// through a policy that accepts the preview tier.
fn evidence_graph_transparency_state(
    nodes: &[Value],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> Result<&'static str, TransactionPassportError> {
    let mut has_transparency_preview = false;
    let mut has_verified_anchor = false;
    for node in nodes {
        let role = node.get("role").and_then(Value::as_str).unwrap_or_default();
        let schema = node
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if role == "transparency-inclusion-proof"
            || matches!(
                schema,
                TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1_ID
                    | TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V2_ID
            )
        {
            match transparency_anchor_state(node, nodes, artifacts, trusted_checkpoint_signer_keys)
            {
                TransparencyAnchor::Verified => has_verified_anchor = true,
                TransparencyAnchor::NotEvaluable => has_transparency_preview = true,
                TransparencyAnchor::Invalid(reason) => {
                    return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                        format!("transparency inclusion proof is invalid: {reason}"),
                    ))
                }
            }
            continue;
        }
        if role.contains("transparency") || schema.contains("transparency") {
            has_transparency_preview = true;
        }
    }
    if has_verified_anchor {
        Ok("trust_anchored")
    } else if has_transparency_preview {
        Ok("transparency_preview")
    } else {
        Ok("not_present")
    }
}

/// Cryptographic gate for `trust_anchored`. Every check fails closed.
fn transparency_anchor_state(
    node: &Value,
    nodes: &[Value],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> TransparencyAnchor {
    if trusted_checkpoint_signer_keys.is_empty() {
        return TransparencyAnchor::NotEvaluable;
    }
    let (Some(path), Some(node_sha256)) = (
        node.get("path").and_then(Value::as_str),
        node.get("sha256").and_then(Value::as_str),
    ) else {
        return TransparencyAnchor::Invalid("node is missing path or sha256".to_string());
    };
    // A bundle that does not carry the artifact cannot be judged here; the
    // digest binding of graph artifacts is enforced separately.
    let Some(bytes) = artifacts.get(path) else {
        return TransparencyAnchor::NotEvaluable;
    };
    if super::sha256_hex(bytes) != node_sha256 {
        return TransparencyAnchor::Invalid(format!("{path} does not match its declared digest"));
    }
    let Ok(raw_json) = std::str::from_utf8(bytes) else {
        return TransparencyAnchor::Invalid(format!("{path} is not a readable inclusion proof"));
    };
    let canonical_artifact_bytes = match canonical_json_bytes_from_str(raw_json) {
        Ok(bytes) => bytes,
        Err(error) => {
            return TransparencyAnchor::Invalid(format!(
                "{path} is not a strict inclusion proof: {error}"
            ))
        }
    };
    let Ok(raw_artifact) = serde_json::from_slice::<Value>(&canonical_artifact_bytes) else {
        return TransparencyAnchor::Invalid(format!("{path} is not a readable inclusion proof"));
    };
    let Some(schema) = raw_artifact.get("schema").and_then(Value::as_str) else {
        return TransparencyAnchor::Invalid(format!("{path} has no inclusion proof schema"));
    };
    let Some(node_schema) = node.get("schema").and_then(Value::as_str) else {
        return TransparencyAnchor::Invalid(
            "transparency node has no declared inclusion proof schema".to_string(),
        );
    };
    if node_schema != schema {
        return TransparencyAnchor::Invalid(format!(
            "transparency node schema {node_schema} does not match artifact schema {schema}"
        ));
    }
    if schema == TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1_ID {
        // V1 is the registered selective-disclosure proof. Its leaf is the
        // SHA-256 digest of the subject digest string and its internal nodes
        // are unprefixed. It cannot be interpreted as the RFC 6962 receipt
        // proof below, even if an unknown checkpoint_statement field was
        // tolerated by a producer.
        return TransparencyAnchor::NotEvaluable;
    }
    if schema != TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V2_ID {
        return TransparencyAnchor::Invalid(format!("unsupported inclusion proof schema {schema}"));
    }
    let artifact: TransparencyInclusionProofArtifact = match serde_json::from_value(raw_artifact) {
        Ok(artifact) => artifact,
        Err(error) => {
            return TransparencyAnchor::Invalid(format!(
                "v2 inclusion proof envelope is invalid: {error}"
            ))
        }
    };
    if artifact.schema != TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V2_ID {
        return TransparencyAnchor::Invalid(format!(
            "unsupported inclusion proof schema {}",
            artifact.schema
        ));
    }
    for (field, value) in [
        ("proof_id", artifact.proof_id.as_str()),
        ("log_id", artifact.log_id.as_str()),
        ("checkpoint", artifact.checkpoint.as_str()),
    ] {
        if value.trim().is_empty() {
            return TransparencyAnchor::Invalid(format!(
                "v2 inclusion proof {field} must not be empty"
            ));
        }
    }
    if artifact.verified_at == 0 {
        return TransparencyAnchor::Invalid(
            "v2 inclusion proof verified_at must be greater than zero".to_string(),
        );
    }
    if artifact.tree_size == 0 || artifact.leaf_index >= artifact.tree_size {
        return TransparencyAnchor::Invalid(
            "v2 inclusion proof leaf position is outside the committed tree".to_string(),
        );
    };
    let statement = artifact.checkpoint_statement;

    let invalid = |reason: &str| TransparencyAnchor::Invalid(reason.to_string());

    // The checkpoint statement must be signed by a pinned key over its
    // canonical body, and must commit the root the proof targets.
    let Some(body) = statement.body.as_object() else {
        return invalid("checkpoint statement body is not an object");
    };
    for optional_field in ["previous_checkpoint_sha256", "chain_root"] {
        if body.get(optional_field).is_some_and(Value::is_null) {
            return TransparencyAnchor::Invalid(format!(
                "checkpoint statement {optional_field} must be omitted rather than null"
            ));
        }
    }
    let Some(kernel_key) = body
        .get("kernel_key")
        .and_then(Value::as_str)
        .and_then(|hex| PublicKey::from_hex(hex).ok())
    else {
        return invalid("checkpoint statement kernel_key is unreadable");
    };
    // An anchor from a signer this verifier does not pin is outside what it
    // can judge rather than corrupt evidence.
    if !trusted_checkpoint_signer_keys.contains(&kernel_key) {
        return TransparencyAnchor::NotEvaluable;
    }
    let Ok(signature) = Signature::from_hex(&statement.signature) else {
        return invalid("checkpoint statement signature is unreadable");
    };
    if statement.signature != signature.to_hex() {
        return invalid("checkpoint statement signature uses a noncanonical encoding");
    }
    let Ok(body_bytes) = canonical_json_bytes(&statement.body) else {
        return invalid("checkpoint statement body is not canonicalizable");
    };
    if !kernel_key.verify(&body_bytes, &signature) {
        return invalid("checkpoint statement signature does not verify");
    }
    let checkpoint_body: CheckpointStatementBody = match serde_json::from_value(statement.body) {
        Ok(checkpoint_body) => checkpoint_body,
        Err(error) => {
            return TransparencyAnchor::Invalid(format!(
                "checkpoint statement body is invalid: {error}"
            ))
        }
    };
    let Ok(typed_body_bytes) = canonical_json_bytes(&checkpoint_body) else {
        return invalid("parsed checkpoint statement body is not canonicalizable");
    };
    if typed_body_bytes != body_bytes {
        return invalid("checkpoint statement body uses noncanonical field encodings");
    }
    if checkpoint_body.kernel_key != kernel_key {
        return invalid("checkpoint statement kernel_key changed during parsing");
    }
    if let Err(reason) = checkpoint_body.validate() {
        return TransparencyAnchor::Invalid(reason);
    };
    let committed_root = checkpoint_body.merkle_root;
    let committed_tree_size = checkpoint_body.tree_size;

    // The proof must target exactly the committed tree, and its audit path
    // must recompute the committed root from the leaf.
    let Ok(root_hash) = Hash::from_hex(&artifact.root_hash) else {
        return invalid("inclusion proof root_hash is unreadable");
    };
    if !hash_encoding_is_canonical(&artifact.root_hash, &root_hash) {
        return invalid("inclusion proof root_hash uses a noncanonical encoding");
    }
    if root_hash != committed_root || artifact.tree_size != committed_tree_size {
        return invalid("inclusion proof does not target the committed checkpoint tree");
    }
    let Ok(leaf) = Hash::from_hex(&artifact.leaf_hash) else {
        return invalid("inclusion proof leaf_hash is unreadable");
    };
    if !hash_encoding_is_canonical(&artifact.leaf_hash, &leaf) {
        return invalid("inclusion proof leaf_hash uses a noncanonical encoding");
    }
    let (Ok(tree_size), Ok(leaf_index)) = (
        usize::try_from(artifact.tree_size),
        usize::try_from(artifact.leaf_index),
    ) else {
        return invalid("inclusion proof tree position is out of range");
    };
    let Ok(audit_path) = artifact
        .inclusion_path
        .iter()
        .map(|hex| Hash::from_hex(hex))
        .collect::<Result<Vec<_>, _>>()
    else {
        return invalid("inclusion proof audit path is unreadable");
    };
    if artifact
        .inclusion_path
        .iter()
        .zip(&audit_path)
        .any(|(encoded, hash)| !hash_encoding_is_canonical(encoded, hash))
    {
        return invalid("inclusion proof audit path uses a noncanonical encoding");
    }
    let proof = MerkleProof {
        tree_size,
        leaf_index,
        audit_path,
    };
    if !proof.verify_hash(leaf, &root_hash) {
        return invalid("inclusion proof does not recompute the committed root");
    }

    // The proven leaf must be the RFC 6962 leaf hash of THIS transaction's
    // receipt. Accepting any digest-bound artifact would let a published
    // (receipt, proof, checkpoint) triple from an unrelated transaction be
    // grafted into this graph as an extra node and carry the anchored tier
    // with it, so the subject is pinned to the single `receipt` role.
    let mut receipt_nodes = nodes.iter().filter(|candidate| {
        candidate.get("role").and_then(Value::as_str) == Some(RECEIPT_EVIDENCE_ROLE)
    });
    let (Some(receipt_node), None) = (receipt_nodes.next(), receipt_nodes.next()) else {
        return invalid("graph does not carry exactly one receipt to anchor");
    };
    let Some(receipt_sha256) = receipt_node.get("sha256").and_then(Value::as_str) else {
        return invalid("receipt node is missing sha256");
    };
    if receipt_sha256 != artifact.artifact_ref {
        return invalid("inclusion proof subject is not this transaction's receipt");
    }
    let Some(receipt_path) = receipt_node.get("path").and_then(Value::as_str) else {
        return invalid("receipt node is missing path");
    };
    let Some(subject_bytes) = artifacts.get(receipt_path) else {
        return TransparencyAnchor::NotEvaluable;
    };
    if super::sha256_hex(subject_bytes) != artifact.artifact_ref {
        return invalid("receipt bytes do not match the proven subject digest");
    }
    if leaf == leaf_hash(subject_bytes) {
        TransparencyAnchor::Verified
    } else {
        TransparencyAnchor::Invalid(
            "proven leaf is not the RFC 6962 leaf hash of the receipt".to_string(),
        )
    }
}

fn hash_encoding_is_canonical(encoded: &str, hash: &Hash) -> bool {
    let canonical = hash.to_hex();
    encoded == canonical.as_str()
        || encoded
            .strip_prefix("0x")
            .is_some_and(|hex| hex == canonical.as_str())
}

fn validate_claim_set_bytes(
    artifacts: &BTreeMap<String, Vec<u8>>,
    claim_set_path: &str,
    expected_claim_set_sha256: &str,
    required_claims: &[String],
    externally_verified_claims: &[String],
) -> Result<Vec<TransactionClaimResult>, TransactionPassportError> {
    let bytes = artifacts.get(claim_set_path).ok_or_else(|| {
        TransactionPassportError::MissingEvidenceGraphArtifact(claim_set_path.to_string())
    })?;
    let actual_claim_set_sha256 = super::sha256_hex(bytes);
    if actual_claim_set_sha256 != expected_claim_set_sha256 {
        return Err(
            TransactionPassportError::EvidenceGraphArtifactDigestMismatch {
                path: claim_set_path.to_string(),
                expected: expected_claim_set_sha256.to_string(),
                actual: actual_claim_set_sha256,
            },
        );
    }
    let claim_set: RootClaimSet = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "invalid claim set: {error}"
        ))
    })?;
    if claim_set.schema != super::ids::TRANSACTION_CLAIM_SET_SCHEMA_ID {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "unsupported claim set schema".to_string(),
        ));
    }
    require_non_empty(&claim_set.id, "claim set id").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&claim_set.issued_at, "claim set issued_at").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    if claim_set.claims.is_empty() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "claim set must contain at least one claim".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for claim in &claim_set.claims {
        require_non_empty(&claim.claim_id, "claim id").map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
        require_non_empty(&claim.verifier_module, "claim verifier module").map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
        validate_claim_refs(&claim.required_evidence, "required evidence")?;
        validate_claim_refs(&claim.evidence_refs, "evidence ref")?;
        if !seen.insert(claim.claim_id.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate claim set claim: {}", claim.claim_id),
            ));
        }
        match claim.status.as_str() {
            "verified" | "omitted" | "unsupported" => {}
            "failed" => {
                if claim
                    .failure_reason
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
                {
                    return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                        "failed claim set entry missing failure reason".to_string(),
                    ));
                }
            }
            _ => {
                return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                    format!("unsupported claim set status: {}", claim.status),
                ));
            }
        }
    }
    for required_claim in required_claims {
        let Some(claim) = claim_set
            .claims
            .iter()
            .find(|claim| claim.claim_id == *required_claim)
        else {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("claim set missing required claim: {required_claim}"),
            ));
        };
        if claim.status != "verified" {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("claim set required claim was not verified: {required_claim}"),
            ));
        }
        if required_claim.starts_with("claim.risk.")
            && !externally_verified_claims
                .iter()
                .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(TransactionPassportError::RiskComptrollerClaimFailed(
                format!("required risk claim not verified by comptroller: {required_claim}"),
            ));
        }
    }
    Ok(claim_set
        .claims
        .into_iter()
        .map(RootClaimSetClaim::into_claim_result)
        .collect())
}

fn validate_passport_omission_policy(
    passport: &TransactionPassport,
    verifier_policy: &TransactionVerifierPolicy,
) -> Result<(), TransactionPassportError> {
    let mut seen = BTreeSet::new();
    for entry in &passport.omission_policy {
        validate_omission_policy_entry(entry)?;
        if !seen.insert(entry.claim_id.as_str()) {
            return Err(TransactionPassportError::InvalidPassportField {
                field: "omission_policy".to_string(),
                message: format!("duplicate omission policy claim: {}", entry.claim_id),
            });
        }
        if !verifier_policy
            .omitted_claims()
            .iter()
            .any(|claim| claim == &entry.claim_id)
        {
            return Err(TransactionPassportError::InvalidPassportField {
                field: "omission_policy".to_string(),
                message: format!(
                    "omission policy claim is not declared omitted: {}",
                    entry.claim_id
                ),
            });
        }
    }
    for omitted_claim in verifier_policy.omitted_claims() {
        if !passport
            .omission_policy
            .iter()
            .any(|entry| entry.claim_id == *omitted_claim)
        {
            return Err(TransactionPassportError::InvalidPassportField {
                field: "omission_policy".to_string(),
                message: format!("passport omission policy missing claim: {omitted_claim}"),
            });
        }
    }
    Ok(())
}

fn validate_omission_policy_entry(
    entry: &TransactionOmissionPolicyEntry,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&entry.claim_id, "omission policy claim id").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "omission_policy".to_string(),
            message: error.to_string(),
        }
    })?;
    require_non_empty(&entry.reason, "omission policy reason").map_err(|error| {
        TransactionPassportError::InvalidPassportField {
            field: "omission_policy".to_string(),
            message: error.to_string(),
        }
    })?;
    if !matches!(
        entry.status.as_str(),
        "omitted_no_join_path"
            | "omitted_privacy_policy"
            | "omitted_external_protocol_lacks_slot"
            | "omitted_not_applicable"
            | "omitted_unsupported_current_version"
    ) {
        return Err(TransactionPassportError::InvalidPassportField {
            field: "omission_policy".to_string(),
            message: format!("unsupported omission policy status: {}", entry.status),
        });
    }
    Ok(())
}

fn validate_claim_refs(
    values: &[String],
    label: &'static str,
) -> Result<(), TransactionPassportError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label).map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
        if !seen.insert(value.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate claim set {label}: {value}"),
            ));
        }
    }
    Ok(())
}

fn path_matches_or_contains_suffix(path: &str, expected_suffix: &str) -> bool {
    let path_components = normal_path_components(path);
    let suffix_components = normal_path_components(expected_suffix);
    !suffix_components.is_empty() && path_components.ends_with(&suffix_components)
}

fn normal_path_components(path: &str) -> Vec<&str> {
    Path::new(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootClaimSet {
    schema: String,
    id: String,
    issued_at: String,
    claims: Vec<RootClaimSetClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootClaimSetClaim {
    claim_id: String,
    status: String,
    #[serde(default)]
    required_evidence: Vec<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    failure_reason: Option<String>,
    verifier_module: String,
}

impl RootClaimSetClaim {
    fn into_claim_result(self) -> TransactionClaimResult {
        TransactionClaimResult {
            claim_id: self.claim_id,
            status: self.status,
            required_evidence: self.required_evidence,
            evidence_refs: self.evidence_refs,
            failure_reason: self.failure_reason,
            verifier_module: self.verifier_module,
        }
    }
}

pub fn verify_standalone_minimal_passport_artifacts(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_transaction_passport_signature(passport, trusted_root_signer_keys)?;
    // Root signers are not checkpoint signers; see
    // `verify_standalone_minimal_passport_artifacts_with_transparency_anchors`.
    verify_standalone_minimal_passport_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_root_signer_keys,
        &[],
    )
}

pub fn verify_standalone_minimal_passport_artifacts_unchecked_signature(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_standalone_minimal_passport_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_root_signer_keys,
        &[],
    )
}

/// Verify a standalone governed-action passport and additionally allow
/// promotion to the `trust_anchored` transparency tier using the pinned
/// checkpoint keys in `trust_anchors`.
pub fn verify_standalone_minimal_passport_artifacts_with_transparency_anchors(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trust_anchors: TransactionTrustAnchors<'_>,
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_transaction_passport_signature(passport, trust_anchors.passport_root_signers)?;
    trust_anchors.validate()?;
    verify_standalone_minimal_passport_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trust_anchors.passport_root_signers,
        trust_anchors.checkpoint_signers,
    )
}

fn verify_standalone_minimal_passport_artifacts_bound(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
    trusted_checkpoint_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    let report = verify_minimal_passport_artifacts_with_anchor_inputs(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_checkpoint_signer_keys,
    )?;
    let verifier_policy: TransactionVerifierPolicy = serde_json::from_slice(verifier_policy_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
    validate_standalone_transaction_claims(&verifier_policy)?;
    let effective_required_claims = verifier_policy.effective_required_claims();
    let evidence_graph: TransactionEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    validate_minimal_governed_action_evidence(&evidence_graph)?;
    validate_claim_set_node_binding(
        &evidence_graph,
        &passport.claim_set_path,
        &passport.claim_set_sha256,
    )?;
    validate_verifier_policy_node_binding(
        &evidence_graph,
        &passport.verifier_policy_path,
        &passport.verifier_policy_sha256,
    )?;
    validate_evidence_graph_artifact_bytes(&evidence_graph, artifacts)?;
    validate_claim_set_artifact_bindings(&evidence_graph, artifacts, &effective_required_claims)?;
    validate_minimal_governed_action_artifact_bindings(
        &evidence_graph,
        artifacts,
        trusted_root_signer_keys,
    )?;
    let claim_results = validate_claim_set_bytes(
        artifacts,
        &passport.claim_set_path,
        &passport.claim_set_sha256,
        &effective_required_claims,
        &[],
    )?;
    Ok(report.with_claim_results(claim_results))
}
