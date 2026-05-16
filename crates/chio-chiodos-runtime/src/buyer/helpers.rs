use std::collections::{BTreeMap, BTreeSet};

use crate::schema::{
    CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA, CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA,
};
use crate::types::{
    BuyerAttestationReviewArtifactRef, BuyerAttestationReviewCheck, BuyerAttestationReviewPackage,
    BuyerAttestationReviewReport,
};
use crate::validation::{
    ensure_sha256_hash, rejected, validate_non_empty, validate_relative_evidence_path,
};
use crate::ChiodosRuntimeError;

pub(super) fn buyer_review_verification_context_window(
    context: &serde_json::Value,
) -> Option<(u64, u64)> {
    let issued_at = context.get("issuedAtUnixMs")?.as_u64()?;
    let expires_at = context.get("expiresAtUnixMs")?.as_u64()?;
    (expires_at > issued_at).then_some((issued_at, expires_at))
}

pub(super) fn validate_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
) -> Result<(), ChiodosRuntimeError> {
    if package.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_package_schema",
            "buyer attestation review package declared an unsupported schema",
        );
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
            return rejected(
                "buyer_review_artifact_empty_bytes",
                "buyer review artifact byte count must be nonzero",
            );
        }
        if !roles.insert(artifact.role.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_path",
                "buyer review package contains duplicate artifact path",
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_buyer_attestation_review_report(
    report: &BuyerAttestationReviewReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_report_schema",
            "buyer attestation review report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.package_id, "buyer_review_report_empty_package")?;
    validate_non_empty(&report.packet_id, "buyer_review_report_empty_packet")?;
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_review_report_missing_failure_code",
            "rejected buyer attestation review report must include failure code",
        );
    }
    Ok(())
}

pub(super) fn review_refs_by_role(
    package: &BuyerAttestationReviewPackage,
) -> Result<BTreeMap<String, BuyerAttestationReviewArtifactRef>, ChiodosRuntimeError> {
    let mut refs = BTreeMap::new();
    for artifact in &package.artifacts {
        if refs
            .insert(artifact.role.clone(), artifact.clone())
            .is_some()
        {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
    }
    Ok(refs)
}

pub(super) fn parse_review_json<T: serde::de::DeserializeOwned>(
    sources_by_role: &BTreeMap<String, Vec<u8>>,
    role: &str,
) -> Result<T, ChiodosRuntimeError> {
    let bytes = sources_by_role
        .get(role)
        .ok_or_else(|| ChiodosRuntimeError::Rejected {
            code: "chiodos_buyer_review_missing_artifact_role",
            detail: format!("buyer review package is missing artifact role {role}"),
        })?;
    serde_json::from_slice(bytes).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub(super) fn buyer_review_check(
    code: &str,
    passed: bool,
    severity: &str,
    artifact_role: &str,
    expected_sha256: Option<String>,
    observed_sha256: Option<String>,
    message: &str,
) -> BuyerAttestationReviewCheck {
    BuyerAttestationReviewCheck {
        code: code.to_string(),
        passed,
        severity: severity.to_string(),
        artifact_role: artifact_role.to_string(),
        expected_sha256,
        observed_sha256,
        message: message.to_string(),
    }
}

pub(super) fn buyer_review_rejection_report(
    package: &BuyerAttestationReviewPackage,
    failure_code: &str,
    checks: Vec<BuyerAttestationReviewCheck>,
) -> BuyerAttestationReviewReport {
    BuyerAttestationReviewReport {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}
