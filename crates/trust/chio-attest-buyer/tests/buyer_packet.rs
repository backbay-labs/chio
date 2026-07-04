use chio_attest_buyer::{
    bilateral_invocation_binding_sha256, receipt_lineage_statement_sha256,
    verify_buyer_attestation_packet, BilateralInvocation, BuyerAttestationPacket,
    CrossBoundaryAdmissionReport, CrossBoundaryEvidenceRef, CrossKernelContinuation,
    ReceiptLineageStatement, CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA,
    CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};

#[test]
fn buyer_packet_without_hydrated_dsse_is_unresolved() -> Result<(), Box<dyn std::error::Error>> {
    let continuation = CrossKernelContinuation {
        schema: CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continuation:buyer:001".to_string(),
        source_kernel_id: "did:chio:buyer".to_string(),
        target_kernel_id: "did:chio:seller".to_string(),
        parent_receipt_sha256: "11".repeat(32),
        parent_session_anchor_sha256: "22".repeat(32),
        capability_id: "capability:buyer:001".to_string(),
        action_class_id: "chio.tool.invoke".to_string(),
        audience_tool: "seller.lookup".to_string(),
        nonce: "nonce-buyer-001".to_string(),
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_766_000_060_000,
    };
    let continuation_sha256 = canonical_sha256(&continuation)?;

    let mut lineage = ReceiptLineageStatement {
        schema: CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage:buyer:001".to_string(),
        parent_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        child_receipt_sha256: "33".repeat(32),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: "00".repeat(32),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };

    let mut bilateral = BilateralInvocation {
        schema: CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "bilateral:buyer:001".to_string(),
        treaty_id: "treaty:buyer-seller:001".to_string(),
        ladder_intersection_sha256: "44".repeat(32),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: "00".repeat(32),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: "55".repeat(32),
        outcome_sha256: "66".repeat(32),
        local_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        remote_receipt_sha256: lineage.child_receipt_sha256.clone(),
        signer_kernel_ids: vec![
            continuation.source_kernel_id.clone(),
            continuation.target_kernel_id.clone(),
        ],
    };
    let bilateral_sha256 = bilateral_invocation_binding_sha256(&bilateral)?;
    lineage.bilateral_invocation_sha256 = bilateral_sha256.clone();
    let lineage_sha256 = receipt_lineage_statement_sha256(&lineage)?;
    bilateral.lineage_statement_sha256 = lineage_sha256.clone();

    let admission = CrossBoundaryAdmissionReport {
        schema: "chio.federation.cross-boundary-admission-report.v1".to_string(),
        treaty_id: bilateral.treaty_id.clone(),
        action_class_id: continuation.action_class_id.clone(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: bilateral.consistency_model.clone(),
        co_sign: "bilateral_required".to_string(),
        required_evidence: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        present_evidence: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_sha256.clone(),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: bilateral_sha256.clone(),
                verified: true,
            },
        ],
        treaty_scope_sha256: "77".repeat(32),
        ladder_intersection_sha256: bilateral.ladder_intersection_sha256.clone(),
        expected_ladder_intersection_sha256: None,
        checks: vec!["accepted".to_string()],
    };

    let packet = BuyerAttestationPacket {
        schema: "chio.attest.buyer-attestation-packet.v1".to_string(),
        packet_id: "buyer-packet:001".to_string(),
        buyer_id: continuation.source_kernel_id.clone(),
        capability_id: continuation.capability_id.clone(),
        treaty_scope_sha256: admission.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: canonical_sha256(&admission)?,
        continuation_sha256: canonical_sha256(&continuation)?,
        receipt_lineage_statement_sha256: lineage_sha256,
        bilateral_invocation_sha256: bilateral_sha256,
        bilateral_dsse_sha256: "88".repeat(32),
        workflow_receipt_sha256: "99".repeat(32),
        proof_package_sha256: "aa".repeat(32),
        verifier_report_sha256: "bb".repeat(32),
        budget_refs: Vec::new(),
        settlement_claimed: false,
    };

    let report =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;

    assert!(!report.accepted);
    assert_eq!(report.verification_state, "unresolved");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_attest_buyer_packet_dsse_unresolved")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| !check.contains("chio_buyer_packet") && !check.contains("chio_buyer.")),
        "Chio packet reports must not expose runtime-core check codes: {:#?}",
        report.checks
    );
    Ok(())
}

#[test]
fn chio_buyer_packet_schema_emits_chio_report_schema() -> Result<(), Box<dyn std::error::Error>> {
    let continuation = CrossKernelContinuation {
        schema: CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continuation:buyer:chio-schema".to_string(),
        source_kernel_id: "did:chio:buyer".to_string(),
        target_kernel_id: "did:chio:seller".to_string(),
        parent_receipt_sha256: "11".repeat(32),
        parent_session_anchor_sha256: "22".repeat(32),
        capability_id: "capability:buyer:chio-schema".to_string(),
        action_class_id: "chio.tool.invoke".to_string(),
        audience_tool: "seller.lookup".to_string(),
        nonce: "nonce-buyer-chio-schema".to_string(),
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_766_000_060_000,
    };
    let continuation_sha256 = canonical_sha256(&continuation)?;
    let mut lineage = ReceiptLineageStatement {
        schema: CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage:buyer:chio-schema".to_string(),
        parent_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        child_receipt_sha256: "33".repeat(32),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: "00".repeat(32),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    let mut bilateral = BilateralInvocation {
        schema: CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "bilateral:buyer:chio-schema".to_string(),
        treaty_id: "treaty:buyer-seller:001".to_string(),
        ladder_intersection_sha256: "44".repeat(32),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: "00".repeat(32),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: "55".repeat(32),
        outcome_sha256: "66".repeat(32),
        local_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        remote_receipt_sha256: lineage.child_receipt_sha256.clone(),
        signer_kernel_ids: vec![
            continuation.source_kernel_id.clone(),
            continuation.target_kernel_id.clone(),
        ],
    };
    let bilateral_sha256 = bilateral_invocation_binding_sha256(&bilateral)?;
    lineage.bilateral_invocation_sha256 = bilateral_sha256.clone();
    let lineage_sha256 = receipt_lineage_statement_sha256(&lineage)?;
    bilateral.lineage_statement_sha256 = lineage_sha256.clone();
    let admission = CrossBoundaryAdmissionReport {
        schema: "chio.federation.cross-boundary-admission-report.v1".to_string(),
        treaty_id: bilateral.treaty_id.clone(),
        action_class_id: continuation.action_class_id.clone(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: bilateral.consistency_model.clone(),
        co_sign: "bilateral_required".to_string(),
        required_evidence: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        present_evidence: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_sha256.clone(),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: bilateral_sha256.clone(),
                verified: true,
            },
        ],
        treaty_scope_sha256: "77".repeat(32),
        ladder_intersection_sha256: bilateral.ladder_intersection_sha256.clone(),
        expected_ladder_intersection_sha256: None,
        checks: vec!["accepted".to_string()],
    };
    let packet = BuyerAttestationPacket {
        schema: "chio.attest.buyer-attestation-packet.v1".to_string(),
        packet_id: "buyer-packet:chio-schema".to_string(),
        buyer_id: continuation.source_kernel_id.clone(),
        capability_id: continuation.capability_id.clone(),
        treaty_scope_sha256: admission.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: canonical_sha256(&admission)?,
        continuation_sha256: canonical_sha256(&continuation)?,
        receipt_lineage_statement_sha256: lineage_sha256,
        bilateral_invocation_sha256: bilateral_sha256,
        bilateral_dsse_sha256: "88".repeat(32),
        workflow_receipt_sha256: "99".repeat(32),
        proof_package_sha256: "aa".repeat(32),
        verifier_report_sha256: "bb".repeat(32),
        budget_refs: Vec::new(),
        settlement_claimed: false,
    };

    let report =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;

    assert!(!report.accepted);
    assert_eq!(report.verification_state, "unresolved");
    assert_eq!(
        report.schema,
        "chio.attest.buyer-attestation-verification-report.v1"
    );
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_attest_buyer_packet_dsse_unresolved")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| !check.contains("chio_buyer_packet") && !check.contains("chio_buyer.")),
        "Chio packet reports must not expose runtime-core check codes: {:#?}",
        report.checks
    );
    Ok(())
}

fn canonical_sha256(
    value: &impl serde::Serialize,
) -> Result<String, chio_core_types::error::Error> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}
