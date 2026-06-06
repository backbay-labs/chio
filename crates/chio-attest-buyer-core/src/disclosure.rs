use std::collections::BTreeSet;

use chio_core_types::receipt::ChioReceipt;
use chio_selective_disclosure::{
    project_receipt_body, project_workflow_receipt_body, receipt_signed_projection,
    verify_signed_projection, Projection, SelectiveDisclosureProof, BBS_CIPHERSUITE_SHA256,
    PROJECTION_VERSION_RECEIPT_V1, PROJECTION_VERSION_WORKFLOW_V1,
};
use serde::{Deserialize, Serialize};

use crate::context::ChioVerificationContext;
use crate::error::ChioPackageError;
use crate::proof_package::ChioProofPackage;
use crate::validation::validate_trust_field;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioDisclosurePolicy {
    pub projection_version: String,
    pub ciphersuite: String,
    pub message_count: usize,
    pub required_disclosed_indices: Vec<u16>,
    pub required_disclosed_fields: Vec<String>,
}

pub(crate) fn validate_disclosure_policy(
    policy: &ChioDisclosurePolicy,
) -> Result<(), ChioPackageError> {
    match policy.projection_version.as_str() {
        PROJECTION_VERSION_WORKFLOW_V1 | PROJECTION_VERSION_RECEIPT_V1 => {}
        _ => {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy projection version {} is unsupported",
                policy.projection_version
            )));
        }
    }
    if policy.ciphersuite != BBS_CIPHERSUITE_SHA256 {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy ciphersuite is unsupported".to_string(),
        ));
    }
    if policy.message_count == 0 {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy message count must be non-zero".to_string(),
        ));
    }
    let mut seen_indices = BTreeSet::new();
    for index in &policy.required_disclosed_indices {
        if usize::from(*index) >= policy.message_count {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy required index {index} is out of range"
            )));
        }
        if !seen_indices.insert(*index) {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy has duplicate required index {index}"
            )));
        }
    }
    let mut seen_fields = BTreeSet::new();
    for field in &policy.required_disclosed_fields {
        validate_trust_field(field, "disclosurePolicy.requiredDisclosedFields")?;
        if !seen_fields.insert(field) {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy has duplicate required field {field}"
            )));
        }
    }
    if seen_indices.is_empty() || seen_fields.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy must require at least one index and field".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn disclosure_projection_for_proof(
    package: &ChioProofPackage,
    proof: &SelectiveDisclosureProof,
) -> Result<Projection, ChioPackageError> {
    match proof.projection_version.as_str() {
        PROJECTION_VERSION_WORKFLOW_V1 => workflow_projection_for_proof(package, proof),
        PROJECTION_VERSION_RECEIPT_V1 => receipt_projection_for_proof(package, proof),
        _ => Err(ChioPackageError::SelectiveDisclosure(format!(
            "projection version {} is unsupported",
            proof.projection_version
        ))),
    }
}

pub(crate) fn workflow_projection_for_proof(
    package: &ChioProofPackage,
    proof: &SelectiveDisclosureProof,
) -> Result<Projection, ChioPackageError> {
    let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    if proof.subject_sha256_hex != projection.subject_sha256_hex {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof subject does not match workflow receipt body".to_string(),
        ));
    }
    Ok(projection)
}

pub(crate) fn receipt_projection_for_proof(
    package: &ChioProofPackage,
    proof: &SelectiveDisclosureProof,
) -> Result<Projection, ChioPackageError> {
    let mut matched: Option<(&ChioReceipt, Projection)> = None;
    for receipt in &package.tool_receipts {
        let projection = project_receipt_body(&receipt.body())
            .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
        if projection.subject_sha256_hex != proof.subject_sha256_hex {
            continue;
        }
        if matched.is_some() {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof subject {} matches multiple tool receipts",
                proof.subject_sha256_hex
            )));
        }
        matched = Some((receipt, projection));
    }

    let Some((receipt, projection)) = matched else {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof subject does not match any tool receipt body".to_string(),
        ));
    };

    let signed = receipt_signed_projection(receipt).map_err(|error| {
        ChioPackageError::SelectiveDisclosure(format!("receipt BBS binding failed: {error}"))
    })?;
    if signed.projection_version != proof.projection_version {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS projection version does not match proof".to_string(),
        ));
    }
    if signed.subject_sha256_hex != proof.subject_sha256_hex {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS subject does not match proof".to_string(),
        ));
    }
    if signed.ciphersuite != proof.ciphersuite {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS ciphersuite does not match proof".to_string(),
        ));
    }
    if signed.issuer_fingerprint != proof.issuer_fingerprint
        || signed.issuer_public_key_hex != proof.issuer_public_key_hex
    {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS issuer does not match proof".to_string(),
        ));
    }
    if signed.message_count != proof.message_count
        || projection.messages.len() != proof.message_count
    {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS message count does not match proof".to_string(),
        ));
    }
    let bbs_signature_valid = verify_signed_projection(&signed, &projection).map_err(|error| {
        ChioPackageError::SelectiveDisclosure(format!(
            "receipt BBS signature verification failed: {error}"
        ))
    })?;
    if !bbs_signature_valid {
        return Err(ChioPackageError::SelectiveDisclosure(
            "receipt BBS signature is invalid".to_string(),
        ));
    }

    Ok(projection)
}

pub(crate) fn verify_disclosure_contract(
    proof: &SelectiveDisclosureProof,
    projection: &Projection,
    policy: &ChioDisclosurePolicy,
    context: &ChioVerificationContext,
) -> Result<(), ChioPackageError> {
    if proof.projection_version != policy.projection_version {
        return Err(ChioPackageError::SelectiveDisclosure(format!(
            "projection version {} is not verifier-approved",
            proof.projection_version
        )));
    }
    if projection.version != policy.projection_version {
        return Err(ChioPackageError::SelectiveDisclosure(
            "workflow projection does not match disclosure policy".to_string(),
        ));
    }
    if proof.ciphersuite != policy.ciphersuite {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof ciphersuite does not match disclosure policy".to_string(),
        ));
    }
    if proof.message_count != policy.message_count
        || projection.messages.len() != policy.message_count
    {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof message count does not match disclosure policy".to_string(),
        ));
    }
    let expected_nonce = context.expected_bbs_proof_nonce_hex()?;
    if proof.proof_nonce_hex != expected_nonce {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof nonce does not match verifier context".to_string(),
        ));
    }
    let disclosed_indices = proof
        .disclosed_indices
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if disclosed_indices.len() != proof.disclosed_indices.len() {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof carries duplicate disclosed index".to_string(),
        ));
    }
    for index in &policy.required_disclosed_indices {
        if !disclosed_indices.contains(index) {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof does not disclose required index {index}"
            )));
        }
    }
    let disclosed_fields = proof
        .disclosed
        .iter()
        .map(|message| message.field.as_str())
        .collect::<BTreeSet<_>>();
    for field in &policy.required_disclosed_fields {
        if !disclosed_fields.contains(field.as_str()) {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof does not disclose required field {field}"
            )));
        }
    }
    for disclosed in &proof.disclosed {
        let Some(projected) = projection
            .messages
            .iter()
            .find(|message| message.index == disclosed.index)
        else {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof discloses out-of-range index {}",
                disclosed.index
            )));
        };
        if disclosed.field != projected.field
            || disclosed.encoding != projected.encoding
            || disclosed.bytes_hex != projected.bytes_hex
        {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof disclosed message {} does not match projection",
                disclosed.index
            )));
        }
    }
    Ok(())
}
