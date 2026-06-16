use std::collections::BTreeMap;

use super::error::TransactionPassportError;
use super::evidence_graph::{
    validate_evidence_graph, validate_evidence_graph_artifact_bytes,
    validate_minimal_governed_action_artifact_bindings, validate_minimal_governed_action_evidence,
    validate_verifier_policy_node_binding, TransactionEvidenceGraph,
};
use super::ids::TRANSACTION_PASSPORT_SCHEMA_ID;
use super::types::{TransactionPassport, TransactionVerifierReport};
use super::validation::{validate_bundle_relative_path, validate_sha256_hex};
use super::verifier_policy::{
    validate_standalone_transaction_claims, validate_verifier_policy, TransactionVerifierPolicy,
};

pub fn verify_minimal_passport_schema(
    passport: &TransactionPassport,
) -> Result<(), TransactionPassportError> {
    if passport.schema != TRANSACTION_PASSPORT_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedSchema(
            passport.schema.clone(),
        ));
    }

    validate_sha256_hex(&passport.evidence_graph_sha256).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphDigest(passport.evidence_graph_sha256.clone())
    })?;
    validate_sha256_hex(&passport.verifier_policy_sha256).map_err(|_| {
        TransactionPassportError::InvalidVerifierPolicyDigest(
            passport.verifier_policy_sha256.clone(),
        )
    })?;
    validate_bundle_relative_path(&passport.evidence_graph_path).map_err(|_| {
        TransactionPassportError::UnsafeEvidenceGraphPath(passport.evidence_graph_path.clone())
    })?;
    validate_bundle_relative_path(&passport.verifier_policy_path).map_err(|_| {
        TransactionPassportError::UnsafeVerifierPolicyPath(passport.verifier_policy_path.clone())
    })?;

    Ok(())
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
    validate_evidence_graph(&evidence_graph)?;

    let verifier_policy: TransactionVerifierPolicy = serde_json::from_slice(verifier_policy_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
    validate_verifier_policy(&verifier_policy)?;

    Ok(TransactionVerifierReport::verified(passport, passport_path))
}

pub fn verify_standalone_minimal_passport_artifacts(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
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
    let evidence_graph: TransactionEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
        })?;
    validate_minimal_governed_action_evidence(&evidence_graph)?;
    validate_verifier_policy_node_binding(
        &evidence_graph,
        &passport.verifier_policy_path,
        &passport.verifier_policy_sha256,
    )?;
    validate_evidence_graph_artifact_bytes(&evidence_graph, artifacts)?;
    validate_minimal_governed_action_artifact_bindings(&evidence_graph, artifacts)?;
    Ok(report)
}
