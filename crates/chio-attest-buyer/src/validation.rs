use std::collections::BTreeSet;

use crate::error::{boundary_rejection, BuyerAttestationError};
use crate::schemas::{
    CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
};
use crate::types::{BuyerAttestationPacket, BuyerAttestationReviewPackage};

pub(crate) fn validate_buyer_attestation_packet_boundary(
    packet: &BuyerAttestationPacket,
) -> Result<(), BuyerAttestationError> {
    if packet.schema != CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA {
        return Err(boundary_rejection(
            "unsupported_buyer_attestation_packet_schema",
            "buyer attestation packet declared an unsupported schema",
        ));
    }
    validate_non_empty(&packet.packet_id, "buyer_packet_empty_id")?;
    validate_non_empty(&packet.buyer_id, "buyer_packet_empty_buyer")?;
    validate_non_empty(&packet.capability_id, "buyer_packet_empty_capability")?;
    ensure_sha256_hash(
        &packet.treaty_scope_sha256,
        "buyer_packet_invalid_treaty_hash",
    )?;
    ensure_sha256_hash(
        &packet.ladder_intersection_sha256,
        "buyer_packet_invalid_intersection_hash",
    )?;
    ensure_sha256_hash(
        &packet.cross_boundary_admission_report_sha256,
        "buyer_packet_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &packet.continuation_sha256,
        "buyer_packet_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &packet.receipt_lineage_statement_sha256,
        "buyer_packet_invalid_lineage_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_invocation_sha256,
        "buyer_packet_invalid_bilateral_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_dsse_sha256,
        "buyer_packet_invalid_bilateral_dsse_hash",
    )?;
    ensure_sha256_hash(
        &packet.workflow_receipt_sha256,
        "buyer_packet_invalid_workflow_hash",
    )?;
    ensure_sha256_hash(
        &packet.proof_package_sha256,
        "buyer_packet_invalid_package_hash",
    )?;
    ensure_sha256_hash(
        &packet.verifier_report_sha256,
        "buyer_packet_invalid_verifier_hash",
    )
}

pub(crate) fn validate_buyer_attestation_review_package_boundary(
    package: &BuyerAttestationReviewPackage,
) -> Result<(), BuyerAttestationError> {
    if package.schema != CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA {
        return Err(boundary_rejection(
            "unsupported_buyer_attestation_review_package_schema",
            "buyer attestation review package declared an unsupported schema",
        ));
    }
    validate_non_empty(&package.package_id, "buyer_review_package_empty_id")?;
    validate_non_empty(&package.packet_id, "buyer_review_package_empty_packet")?;
    validate_non_empty(&package.buyer_id, "buyer_review_package_empty_buyer")?;
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for artifact in &package.artifacts {
        validate_non_empty(&artifact.role, "buyer_review_artifact_empty_role")?;
        validate_non_empty(
            &artifact.relative_path,
            "buyer_review_artifact_empty_relative_path",
        )?;
        validate_relative_evidence_path(
            &artifact.relative_path,
            "buyer_review_artifact_unsafe_path",
        )?;
        ensure_sha256_hash(
            &artifact.artifact_sha256,
            "buyer_review_artifact_invalid_hash",
        )?;
        if artifact.byte_count == 0 {
            return Err(boundary_rejection(
                "buyer_review_artifact_empty_bytes",
                "buyer review artifact byte count must be nonzero",
            ));
        }
        if !roles.insert(artifact.role.clone()) {
            return Err(boundary_rejection(
                "chio_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            ));
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return Err(boundary_rejection(
                "chio_buyer_review_duplicate_artifact_path",
                "buyer review package contains duplicate artifact path",
            ));
        }
    }
    Ok(())
}

fn validate_non_empty(value: &str, code: &'static str) -> Result<(), BuyerAttestationError> {
    if value.trim().is_empty() {
        return Err(boundary_rejection(
            code,
            "buyer attestation field must not be empty",
        ));
    }
    Ok(())
}

fn ensure_sha256_hash(hash: &str, code: &'static str) -> Result<(), BuyerAttestationError> {
    if hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Ok(());
    }
    Err(boundary_rejection(
        code,
        format!("buyer attestation hash {hash} is not sha256 hex"),
    ))
}

fn validate_relative_evidence_path(
    path: &str,
    code: &'static str,
) -> Result<(), BuyerAttestationError> {
    if is_safe_relative_evidence_path(path) {
        return Ok(());
    }
    Err(boundary_rejection(
        code,
        format!("buyer review artifact path {path:?} is not a safe relative path"),
    ))
}

fn is_safe_relative_evidence_path(path: &str) -> bool {
    path.trim() == path
        && !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.contains("//")
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
