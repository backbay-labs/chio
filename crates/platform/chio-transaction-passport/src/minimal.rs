use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use chio_core_types::{
    crypto::{Keypair, Signature},
    PublicKey,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
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
    enforce_verifier_policy_gates(passport, &verifier_policy, &evidence_graph_value)?;
    let transparency_state =
        evidence_graph_transparency_state(evidence_graph_nodes(&evidence_graph_value)?);

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
    verify_passport_root_and_claim_set_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
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
    verify_passport_root_and_claim_set_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        externally_verified_claims,
    )
}

fn verify_passport_root_and_claim_set_artifacts_bound(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    let claim_results = verify_signed_root_graph_binding(
        passport,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        externally_verified_claims,
    )?;
    let transparency_state = transaction_evidence_graph_transparency_state(evidence_graph_bytes)?;
    Ok(TransactionVerifierReport::verified(passport, passport_path)
        .with_transparency_state(transparency_state)
        .with_claim_results(claim_results))
}

pub fn transaction_evidence_graph_transparency_state(
    evidence_graph_bytes: &[u8],
) -> Result<String, TransactionPassportError> {
    let evidence_graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    Ok(evidence_graph_transparency_state(evidence_graph_nodes(&evidence_graph)?).to_string())
}

fn verify_signed_root_graph_binding(
    passport: &TransactionPassport,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
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
    enforce_verifier_policy_gates(passport, &verifier_policy, &evidence_graph)?;
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

    let transparency_state = evidence_graph_transparency_state(nodes);
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

fn evidence_graph_transparency_state(nodes: &[Value]) -> &'static str {
    let mut has_transparency_preview = false;
    for node in nodes {
        let role = node.get("role").and_then(Value::as_str).unwrap_or_default();
        let schema = node
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if role == "transparency-inclusion-proof"
            || schema == "chio.transparency.inclusion-proof.v1"
        {
            return "trust_anchored";
        }
        if role.contains("transparency") || schema.contains("transparency") {
            has_transparency_preview = true;
        }
    }
    if has_transparency_preview {
        "transparency_preview"
    } else {
        "not_present"
    }
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
    verify_standalone_minimal_passport_artifacts_bound(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trusted_root_signer_keys,
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
    )
}

fn verify_standalone_minimal_passport_artifacts_bound(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    let report = verify_minimal_passport_artifacts(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
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
