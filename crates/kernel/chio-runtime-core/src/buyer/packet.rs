use crate::hash::canonical_sha256;
use crate::schema::{
    CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA,
};
use crate::treaty::{
    validate_bilateral_invocation, validate_cross_kernel_continuation,
    validate_receipt_lineage_statement,
};
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationVerificationReport,
    CrossBoundaryAdmissionReport, CrossKernelContinuation, ReceiptLineageStatement,
};
use crate::validation::{ensure_sha256_hash, rejected, validate_non_empty};
use crate::{
    bilateral_invocation_binding_sha256, receipt_lineage_statement_sha256,
    validate_cross_boundary_admission_report, ChioRuntimeError,
};

pub fn verify_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<BuyerAttestationVerificationReport, ChioRuntimeError> {
    verify_buyer_attestation_packet_with_resolved_dsse(
        packet,
        lineage,
        continuation,
        admission,
        bilateral,
        None,
    )
}

pub(crate) fn verify_buyer_attestation_packet_with_resolved_dsse(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
    resolved_bilateral_dsse_sha256: Option<&str>,
) -> Result<BuyerAttestationVerificationReport, ChioRuntimeError> {
    validate_buyer_attestation_packet(packet)?;
    validate_receipt_lineage_statement(lineage)?;
    validate_cross_kernel_continuation(continuation)?;
    validate_cross_boundary_admission_report(admission)?;
    validate_bilateral_invocation(bilateral)?;
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)?;
    let mut checks = vec!["chio_buyer.packet_valid".to_string()];
    if packet.settlement_claimed {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chio_buyer_packet_settlement_claimed",
            checks,
        ));
    }
    if lineage.evidence_class != "verified" {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chio_buyer_packet_lineage_not_verified",
            checks,
        ));
    }
    if packet.buyer_id != continuation.source_kernel_id
        || lineage.source_kernel_id != continuation.source_kernel_id
        || lineage.target_kernel_id != continuation.target_kernel_id
        || bilateral.signer_kernel_ids.len() != 2
        || bilateral.signer_kernel_ids.first() != Some(&continuation.source_kernel_id)
        || bilateral.signer_kernel_ids.get(1) != Some(&continuation.target_kernel_id)
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chio_buyer_packet_identity_mismatch",
            checks,
        ));
    }
    if packet.capability_id != continuation.capability_id
        || bilateral.capability_id != continuation.capability_id
        || continuation.action_class_id != admission.action_class_id
        || bilateral.action_class_id != continuation.action_class_id
        || bilateral.treaty_id != admission.treaty_id
        || bilateral.consistency_model != admission.consistency_model
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chio_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    if receipt_lineage_statement_sha256(lineage)? != packet.receipt_lineage_statement_sha256
        || canonical_sha256(continuation)? != packet.continuation_sha256
        || canonical_sha256(admission)? != packet.cross_boundary_admission_report_sha256
        || bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.continuation_sha256 != packet.continuation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || bilateral.continuation_sha256 != packet.continuation_sha256
        || bilateral.lineage_statement_sha256 != packet.receipt_lineage_statement_sha256
        || bilateral.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || bilateral.local_receipt_sha256 != lineage.parent_receipt_sha256
        || bilateral.remote_receipt_sha256 != lineage.child_receipt_sha256
        || admission.treaty_scope_sha256 != packet.treaty_scope_sha256
        || admission.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || verified_evidence_missing_or_mismatch(
            admission,
            "receipt_lineage",
            &packet.receipt_lineage_statement_sha256,
        )
        || verified_evidence_missing_or_mismatch(
            admission,
            "bilateral_invocation",
            &packet.bilateral_invocation_sha256,
        )
        || !admission.accepted
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chio_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    if resolved_bilateral_dsse_sha256 != Some(packet.bilateral_dsse_sha256.as_str()) {
        return Ok(buyer_packet_unresolved_report(
            packet,
            "chio_buyer_packet_dsse_unresolved",
            checks,
        ));
    }
    checks.push("chio_buyer.lineage_verified".to_string());
    checks.push("chio_buyer.bilateral_dsse_hash_resolved".to_string());
    Ok(BuyerAttestationVerificationReport {
        schema: CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "hash_resolved".to_string(),
        accepted: true,
        failure_code: None,
        checks,
    })
}

fn verified_evidence_missing_or_mismatch(
    admission: &CrossBoundaryAdmissionReport,
    evidence_class: &str,
    artifact_sha256: &str,
) -> bool {
    let mut refs = admission
        .verified_evidence
        .iter()
        .filter(|evidence| evidence.evidence_class == evidence_class);
    let Some(evidence) = refs.next() else {
        return true;
    };
    refs.next().is_some() || evidence.artifact_sha256 != artifact_sha256 || !evidence.verified
}

fn validate_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
) -> Result<(), ChioRuntimeError> {
    if !is_supported_buyer_attestation_packet_schema(&packet.schema) {
        return rejected(
            "unsupported_buyer_attestation_packet_schema",
            "buyer attestation packet declared an unsupported schema",
        );
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

fn is_supported_buyer_attestation_packet_schema(schema: &str) -> bool {
    matches!(schema, CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA)
}

pub(crate) fn validate_buyer_attestation_verification_report(
    report: &BuyerAttestationVerificationReport,
) -> Result<(), ChioRuntimeError> {
    if !is_supported_buyer_attestation_verification_report_schema(&report.schema) {
        return rejected(
            "unsupported_buyer_attestation_verification_report_schema",
            "buyer attestation verification report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.packet_id, "buyer_verification_empty_packet")?;
    match (report.accepted, report.verification_state.as_str()) {
        (true, "hash_resolved") | (false, "rejected" | "unresolved") => {}
        _ => {
            return rejected(
                "buyer_verification_invalid_state",
                "buyer attestation packet verification state must describe resolved, unresolved, or rejected review",
            )
        }
    }
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_verification_missing_failure_code",
            "rejected buyer attestation verification report must include failure code",
        );
    }
    Ok(())
}

fn is_supported_buyer_attestation_verification_report_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA
    )
}

fn buyer_packet_unresolved_report(
    packet: &BuyerAttestationPacket,
    failure_code: &'static str,
    checks: Vec<String>,
) -> BuyerAttestationVerificationReport {
    BuyerAttestationVerificationReport {
        schema: CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "unresolved".to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}

fn buyer_packet_rejection_report(
    packet: &BuyerAttestationPacket,
    failure_code: &'static str,
    checks: Vec<String>,
) -> BuyerAttestationVerificationReport {
    BuyerAttestationVerificationReport {
        schema: CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "rejected".to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}
