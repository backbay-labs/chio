use crate::error::chio_attest_buyer_code;
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationReviewArtifactRef,
    BuyerAttestationReviewCheck, BuyerAttestationReviewPackage, BuyerAttestationReviewReport,
    BuyerAttestationReviewSource, BuyerAttestationVerificationReport, CrossBoundaryAdmissionReport,
    CrossBoundaryEvidenceRef, CrossKernelContinuation, ReceiptLineageBundle,
    ReceiptLineageStatement,
};

pub(crate) fn runtime_core_cross_kernel_continuation(
    value: &CrossKernelContinuation,
) -> chio_runtime_core::CrossKernelContinuation {
    chio_runtime_core::CrossKernelContinuation {
        schema: value.schema.clone(),
        continuation_id: value.continuation_id.clone(),
        source_kernel_id: value.source_kernel_id.clone(),
        target_kernel_id: value.target_kernel_id.clone(),
        parent_receipt_sha256: value.parent_receipt_sha256.clone(),
        parent_session_anchor_sha256: value.parent_session_anchor_sha256.clone(),
        capability_id: value.capability_id.clone(),
        action_class_id: value.action_class_id.clone(),
        audience_tool: value.audience_tool.clone(),
        nonce: value.nonce.clone(),
        issued_at_unix_ms: value.issued_at_unix_ms,
        expires_at_unix_ms: value.expires_at_unix_ms,
    }
}

pub(crate) fn runtime_core_receipt_lineage_statement(
    value: &ReceiptLineageStatement,
) -> chio_runtime_core::ReceiptLineageStatement {
    chio_runtime_core::ReceiptLineageStatement {
        schema: value.schema.clone(),
        statement_id: value.statement_id.clone(),
        parent_receipt_sha256: value.parent_receipt_sha256.clone(),
        child_receipt_sha256: value.child_receipt_sha256.clone(),
        continuation_sha256: value.continuation_sha256.clone(),
        bilateral_invocation_sha256: value.bilateral_invocation_sha256.clone(),
        evidence_class: value.evidence_class.clone(),
        source_kernel_id: value.source_kernel_id.clone(),
        target_kernel_id: value.target_kernel_id.clone(),
    }
}

fn runtime_core_cross_boundary_evidence_ref(
    value: &CrossBoundaryEvidenceRef,
) -> chio_runtime_core::CrossBoundaryEvidenceRef {
    chio_runtime_core::CrossBoundaryEvidenceRef {
        evidence_class: value.evidence_class.clone(),
        artifact_sha256: value.artifact_sha256.clone(),
        verified: value.verified,
    }
}

pub(crate) fn runtime_core_cross_boundary_admission_report(
    value: &CrossBoundaryAdmissionReport,
) -> chio_runtime_core::CrossBoundaryAdmissionReport {
    chio_runtime_core::CrossBoundaryAdmissionReport {
        schema: value.schema.clone(),
        treaty_id: value.treaty_id.clone(),
        action_class_id: value.action_class_id.clone(),
        accepted: value.accepted,
        failure_code: value.failure_code.clone(),
        mode: value.mode.clone(),
        consistency_model: value.consistency_model.clone(),
        co_sign: value.co_sign.clone(),
        required_evidence: value.required_evidence.clone(),
        present_evidence: value.present_evidence.clone(),
        verified_evidence: value
            .verified_evidence
            .iter()
            .map(runtime_core_cross_boundary_evidence_ref)
            .collect(),
        treaty_scope_sha256: value.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: value.ladder_intersection_sha256.clone(),
        expected_ladder_intersection_sha256: value.expected_ladder_intersection_sha256.clone(),
        checks: value.checks.clone(),
    }
}

pub(crate) fn runtime_core_bilateral_invocation(
    value: &BilateralInvocation,
) -> chio_runtime_core::BilateralInvocation {
    chio_runtime_core::BilateralInvocation {
        schema: value.schema.clone(),
        invocation_id: value.invocation_id.clone(),
        treaty_id: value.treaty_id.clone(),
        ladder_intersection_sha256: value.ladder_intersection_sha256.clone(),
        continuation_sha256: value.continuation_sha256.clone(),
        lineage_statement_sha256: value.lineage_statement_sha256.clone(),
        action_class_id: value.action_class_id.clone(),
        consistency_model: value.consistency_model.clone(),
        capability_id: value.capability_id.clone(),
        request_sha256: value.request_sha256.clone(),
        outcome_sha256: value.outcome_sha256.clone(),
        local_receipt_sha256: value.local_receipt_sha256.clone(),
        remote_receipt_sha256: value.remote_receipt_sha256.clone(),
        signer_kernel_ids: value.signer_kernel_ids.clone(),
    }
}

pub(crate) fn runtime_core_buyer_attestation_packet(
    value: &BuyerAttestationPacket,
) -> chio_runtime_core::BuyerAttestationPacket {
    chio_runtime_core::BuyerAttestationPacket {
        schema: value.schema.clone(),
        packet_id: value.packet_id.clone(),
        buyer_id: value.buyer_id.clone(),
        capability_id: value.capability_id.clone(),
        treaty_scope_sha256: value.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: value.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: value
            .cross_boundary_admission_report_sha256
            .clone(),
        continuation_sha256: value.continuation_sha256.clone(),
        receipt_lineage_statement_sha256: value.receipt_lineage_statement_sha256.clone(),
        bilateral_invocation_sha256: value.bilateral_invocation_sha256.clone(),
        bilateral_dsse_sha256: value.bilateral_dsse_sha256.clone(),
        workflow_receipt_sha256: value.workflow_receipt_sha256.clone(),
        proof_package_sha256: value.proof_package_sha256.clone(),
        verifier_report_sha256: value.verifier_report_sha256.clone(),
        budget_refs: value.budget_refs.clone(),
        settlement_claimed: value.settlement_claimed,
    }
}

fn runtime_core_review_artifact_ref(
    value: &BuyerAttestationReviewArtifactRef,
) -> chio_runtime_core::BuyerAttestationReviewArtifactRef {
    chio_runtime_core::BuyerAttestationReviewArtifactRef {
        role: value.role.clone(),
        relative_path: value.relative_path.clone(),
        artifact_sha256: value.artifact_sha256.clone(),
        byte_count: value.byte_count,
    }
}

pub(crate) fn runtime_core_review_package(
    value: &BuyerAttestationReviewPackage,
) -> chio_runtime_core::BuyerAttestationReviewPackage {
    chio_runtime_core::BuyerAttestationReviewPackage {
        schema: value.schema.clone(),
        package_id: value.package_id.clone(),
        packet_id: value.packet_id.clone(),
        buyer_id: value.buyer_id.clone(),
        generated_at_unix_ms: value.generated_at_unix_ms,
        artifacts: value
            .artifacts
            .iter()
            .map(runtime_core_review_artifact_ref)
            .collect(),
    }
}

fn runtime_core_review_source(
    value: &BuyerAttestationReviewSource,
) -> chio_runtime_core::BuyerAttestationReviewSource {
    chio_runtime_core::BuyerAttestationReviewSource {
        role: value.role.clone(),
        relative_path: value.relative_path.clone(),
        bytes: value.bytes.clone(),
    }
}

pub(crate) fn runtime_core_review_sources(
    sources: &[BuyerAttestationReviewSource],
) -> Vec<chio_runtime_core::BuyerAttestationReviewSource> {
    sources.iter().map(runtime_core_review_source).collect()
}

pub(crate) fn runtime_core_review_bundle(
    value: &ReceiptLineageBundle,
) -> chio_runtime_core::ReceiptLineageBundle {
    chio_runtime_core::ReceiptLineageBundle {
        schema: value.schema.clone(),
        bundle_id: value.bundle_id.clone(),
        root_receipt_sha256: value.root_receipt_sha256.clone(),
        leaf_receipt_sha256: value.leaf_receipt_sha256.clone(),
        statements: value
            .statements
            .iter()
            .map(runtime_core_receipt_lineage_statement)
            .collect(),
    }
}

pub(crate) fn local_verification_report(
    value: chio_runtime_core::BuyerAttestationVerificationReport,
) -> BuyerAttestationVerificationReport {
    BuyerAttestationVerificationReport {
        schema: value.schema,
        packet_id: value.packet_id,
        verification_state: value.verification_state,
        accepted: value.accepted,
        failure_code: value.failure_code.map(|code| chio_attest_buyer_code(&code)),
        checks: value
            .checks
            .into_iter()
            .map(|check| chio_attest_buyer_code(&check))
            .collect(),
    }
}

pub(crate) fn local_review_report(
    value: chio_runtime_core::BuyerAttestationReviewReport,
) -> BuyerAttestationReviewReport {
    BuyerAttestationReviewReport {
        schema: value.schema,
        package_id: value.package_id,
        packet_id: value.packet_id,
        accepted: value.accepted,
        failure_code: value.failure_code.map(|code| chio_attest_buyer_code(&code)),
        checks: value
            .checks
            .into_iter()
            .map(|check| BuyerAttestationReviewCheck {
                code: chio_attest_buyer_code(&check.code),
                passed: check.passed,
                severity: check.severity,
                artifact_role: check.artifact_role,
                expected_sha256: check.expected_sha256,
                observed_sha256: check.observed_sha256,
                message: check.message,
            })
            .collect(),
    }
}
