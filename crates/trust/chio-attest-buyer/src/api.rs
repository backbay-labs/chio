use chio_attest_buyer_core::context::verification_context_from_json;
use chio_attest_buyer_core::proof_package::proof_package_from_json;
use chio_attest_buyer_core::report::{report_json, verify_package_report};
use chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_from_json;

use crate::conversions::{
    local_review_report, local_verification_report, runtime_core_bilateral_invocation,
    runtime_core_buyer_attestation_packet, runtime_core_cross_boundary_admission_report,
    runtime_core_cross_kernel_continuation, runtime_core_receipt_lineage_statement,
    runtime_core_review_bundle, runtime_core_review_package, runtime_core_review_sources,
};
use crate::error::{chio_attest_buyer_code, json_error, BuyerAttestationError, RuntimeBuyerError};
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationReviewCheck,
    BuyerAttestationReviewPackage, BuyerAttestationReviewReport, BuyerAttestationReviewSource,
    BuyerAttestationReviewTrustContext, BuyerAttestationVerificationReport,
    ChioProofVerificationReport, CrossBoundaryAdmissionReport, CrossKernelContinuation,
    ReceiptLineageBundle, ReceiptLineageStatement,
};
use crate::validation::{
    validate_buyer_attestation_packet_boundary, validate_buyer_attestation_review_package_boundary,
};

pub fn buyer_attestation_packet_from_json(
    json: &str,
) -> Result<BuyerAttestationPacket, BuyerAttestationError> {
    let packet = serde_json::from_str::<BuyerAttestationPacket>(json)
        .map_err(|error| json_error("Chio buyer attestation packet JSON", error))?;
    validate_buyer_attestation_packet_boundary(&packet)?;
    Ok(packet)
}

pub fn buyer_attestation_review_package_from_json(
    json: &str,
) -> Result<BuyerAttestationReviewPackage, BuyerAttestationError> {
    let package = serde_json::from_str::<BuyerAttestationReviewPackage>(json)
        .map_err(|error| json_error("Chio buyer attestation review package JSON", error))?;
    validate_buyer_attestation_review_package_boundary(&package)?;
    Ok(package)
}

pub fn buyer_attestation_verification_report_json(
    report: &BuyerAttestationVerificationReport,
) -> Result<String, BuyerAttestationError> {
    let runtime_core = chio_runtime_core::BuyerAttestationVerificationReport {
        schema: report.schema.clone(),
        packet_id: report.packet_id.clone(),
        verification_state: report.verification_state.clone(),
        accepted: report.accepted,
        failure_code: report.failure_code.as_deref().map(chio_attest_buyer_code),
        checks: report
            .checks
            .iter()
            .map(|check| chio_attest_buyer_code(check))
            .collect(),
    };
    chio_runtime_core::buyer_attestation_verification_report_json(&runtime_core)
        .map_err(BuyerAttestationError::from_runtime)
}

pub fn buyer_attestation_review_report_json(
    report: &BuyerAttestationReviewReport,
) -> Result<String, BuyerAttestationError> {
    let runtime_core = chio_runtime_core::BuyerAttestationReviewReport {
        schema: report.schema.clone(),
        package_id: report.package_id.clone(),
        packet_id: report.packet_id.clone(),
        accepted: report.accepted,
        failure_code: report.failure_code.as_deref().map(chio_attest_buyer_code),
        checks: report
            .checks
            .iter()
            .map(|check| chio_runtime_core::BuyerAttestationReviewCheck {
                code: chio_attest_buyer_code(&check.code),
                passed: check.passed,
                severity: check.severity.clone(),
                artifact_role: check.artifact_role.clone(),
                expected_sha256: check.expected_sha256.clone(),
                observed_sha256: check.observed_sha256.clone(),
                message: check.message.clone(),
            })
            .collect(),
    };
    chio_runtime_core::buyer_attestation_review_report_json(&runtime_core)
        .map_err(BuyerAttestationError::from_runtime)
}

pub fn buyer_attestation_packet_sha256(
    packet: &BuyerAttestationPacket,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::buyer_attestation_packet_sha256(&runtime_core_buyer_attestation_packet(
        packet,
    ))
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn receipt_lineage_statement_sha256(
    statement: &ReceiptLineageStatement,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::receipt_lineage_statement_sha256(&runtime_core_receipt_lineage_statement(
        statement,
    ))
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn bilateral_invocation_binding_sha256(
    invocation: &BilateralInvocation,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::bilateral_invocation_binding_sha256(&runtime_core_bilateral_invocation(
        invocation,
    ))
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn verify_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<BuyerAttestationVerificationReport, BuyerAttestationError> {
    chio_runtime_core::verify_buyer_attestation_packet(
        &runtime_core_buyer_attestation_packet(packet),
        &runtime_core_receipt_lineage_statement(lineage),
        &runtime_core_cross_kernel_continuation(continuation),
        &runtime_core_cross_boundary_admission_report(admission),
        &runtime_core_bilateral_invocation(bilateral),
    )
    .map(local_verification_report)
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn verify_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
) -> Result<BuyerAttestationReviewReport, BuyerAttestationError> {
    chio_runtime_core::verify_buyer_attestation_review_package(
        &runtime_core_review_package(package),
        &runtime_core_review_sources(sources),
    )
    .map(local_review_report)
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn verify_buyer_attestation_review_package_with_trust(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: &BuyerAttestationReviewTrustContext<'_>,
) -> Result<BuyerAttestationReviewReport, BuyerAttestationError> {
    let runtime_core_trust = chio_runtime_core::BuyerAttestationReviewTrustContext {
        verifier_trust_bundle: trust_context.verifier_trust_bundle,
        verification_context: trust_context.verification_context,
    };
    chio_runtime_core::verify_buyer_attestation_review_package_with_trust(
        &runtime_core_review_package(package),
        &runtime_core_review_sources(sources),
        &runtime_core_trust,
    )
    .map(local_review_report)
    .map_err(BuyerAttestationError::from_runtime)
}

pub fn verify_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<bool, BuyerAttestationError> {
    chio_runtime_core::verify_receipt_lineage_bundle(&runtime_core_review_bundle(bundle))
        .map_err(BuyerAttestationError::from_runtime)
}

pub fn verify_buyer_attestation_review_package_with_proof_replay_json(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    verifier_trust_bundle_json: &str,
    verification_context_json: &str,
) -> Result<BuyerAttestationReviewReport, BuyerAttestationError> {
    let verifier_trust_bundle_value = parse_json_value(
        "Chio buyer verifier trust bundle JSON",
        verifier_trust_bundle_json,
    )?;
    let verification_context_value = parse_json_value(
        "Chio buyer verification context JSON",
        verification_context_json,
    )?;
    let trust_context = BuyerAttestationReviewTrustContext {
        verifier_trust_bundle: &verifier_trust_bundle_value,
        verification_context: &verification_context_value,
    };
    let mut report =
        verify_buyer_attestation_review_package_with_trust(package, sources, &trust_context)?;
    if report.accepted {
        replay_core_verifier(
            &mut report,
            sources,
            verifier_trust_bundle_json,
            verification_context_json,
        )?;
    }
    Ok(report)
}

pub fn verify_proof_package_json(
    proof_package_json: &str,
    verifier_trust_bundle_json: &str,
    verification_context_json: &str,
) -> Result<ChioProofVerificationReport, BuyerAttestationError> {
    let proof_package = proof_package_from_json(proof_package_json)
        .map_err(|error| json_error("Chio attest proof package", error))?;
    let trust_bundle = verifier_trust_bundle_from_json(verifier_trust_bundle_json)
        .map_err(|error| json_error("Chio verifier trust bundle", error))?;
    let context = verification_context_from_json(verification_context_json)
        .map_err(|error| json_error("Chio verification context", error))?;
    let report = verify_package_report(&proof_package, &trust_bundle, &context);
    let json =
        report_json(&report).map_err(|error| json_error("Chio attest proof report", error))?;
    Ok(ChioProofVerificationReport {
        accepted: report.accepted,
        failure_code: report.failure.as_ref().map(|failure| failure.code.clone()),
        json,
    })
}

fn parse_json_value(label: &str, json: &str) -> Result<serde_json::Value, BuyerAttestationError> {
    serde_json::from_str(json).map_err(|error| json_error(label, error))
}

fn replay_core_verifier(
    report: &mut BuyerAttestationReviewReport,
    sources: &[BuyerAttestationReviewSource],
    verifier_trust_bundle_json: &str,
    verification_context_json: &str,
) -> Result<(), BuyerAttestationError> {
    let proof_package_bytes = review_source_bytes(sources, "proof_package").ok_or_else(|| {
        BuyerAttestationError::from_runtime(RuntimeBuyerError::Rejected {
            code: "chio_attest_buyer_review_missing_proof_package",
            detail: "buyer review package is missing proof_package artifact".to_string(),
        })
    })?;
    let proof_package_json = std::str::from_utf8(proof_package_bytes)
        .map_err(|error| json_error("Chio buyer proof package artifact", error))?;
    let proof_package = proof_package_from_json(proof_package_json)
        .map_err(|error| json_error("Chio buyer proof package", error))?;
    let trust_bundle = verifier_trust_bundle_from_json(verifier_trust_bundle_json)
        .map_err(|error| json_error("Chio buyer verifier trust bundle", error))?;
    let context = verification_context_from_json(verification_context_json)
        .map_err(|error| json_error("Chio buyer verification context", error))?;
    let verifier_report = verify_package_report(&proof_package, &trust_bundle, &context);
    if verifier_report.accepted {
        report.checks.push(BuyerAttestationReviewCheck {
            code: "chio_attest_buyer.review.existing_verifier_replayed".to_string(),
            passed: true,
            severity: "info".to_string(),
            artifact_role: "proof_package".to_string(),
            expected_sha256: None,
            observed_sha256: None,
            message: "proof replay accepted the bundled proof package".to_string(),
        });
    } else {
        report.accepted = false;
        report.failure_code = Some("chio_attest_buyer_review_verifier_report_rejected".to_string());
        report.checks.push(BuyerAttestationReviewCheck {
            code: "chio_attest_buyer.review.existing_verifier_replayed".to_string(),
            passed: false,
            severity: "error".to_string(),
            artifact_role: "proof_package".to_string(),
            expected_sha256: None,
            observed_sha256: None,
            message: "proof replay rejected the bundled proof package".to_string(),
        });
    }
    Ok(())
}

fn review_source_bytes<'a>(
    sources: &'a [BuyerAttestationReviewSource],
    role: &str,
) -> Option<&'a [u8]> {
    sources
        .iter()
        .find(|source| source.role == role)
        .map(|source| source.bytes.as_slice())
}
