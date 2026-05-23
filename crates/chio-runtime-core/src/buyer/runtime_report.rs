use crate::buyer::proof_package::{
    proof_package_array_contains_field, proof_package_contains_parent_lineage_anchor,
    proof_package_contains_signed_receipt, workflow_receipt_contains_step_hash,
};
use crate::hash::canonical_sha256;
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationReviewArtifactRef,
    RuntimeEvidenceManifest, RuntimeProofRegenerationInput, RuntimeProofRegenerationReport,
    RuntimeStepEvidence, RuntimeWorkflowRunReport,
};
use crate::validation::{
    validate_runtime_evidence_manifest, validate_runtime_proof_regeneration_input,
    validate_runtime_proof_regeneration_report, validate_runtime_workflow_run_report,
};

pub(super) struct BuyerReviewRuntimeReportContext<'a> {
    pub(super) runtime_run_report: &'a RuntimeWorkflowRunReport,
    pub(super) proof_regeneration_report: &'a RuntimeProofRegenerationReport,
    pub(super) packet: &'a BuyerAttestationPacket,
    pub(super) bilateral: &'a BilateralInvocation,
    pub(super) proof_package: &'a serde_json::Value,
    pub(super) workflow_receipt: &'a serde_json::Value,
    pub(super) runtime_evidence_manifest: &'a RuntimeEvidenceManifest,
    pub(super) proof_regeneration_input: &'a RuntimeProofRegenerationInput,
    pub(super) proof_sha256: &'a str,
    pub(super) verifier_sha256: &'a str,
    pub(super) workflow_sha256: &'a str,
    pub(super) bilateral_dsse_sha256: &'a str,
    pub(super) trust_bundle_sha256: &'a str,
    pub(super) verification_context_sha256: &'a str,
    pub(super) artifact_refs: &'a [BuyerAttestationReviewArtifactRef],
}

pub(super) fn verify_buyer_review_runtime_reports(
    context: BuyerReviewRuntimeReportContext<'_>,
) -> Result<RuntimeStepEvidence, &'static str> {
    let BuyerReviewRuntimeReportContext {
        runtime_run_report,
        proof_regeneration_report,
        packet,
        bilateral,
        proof_package,
        workflow_receipt,
        runtime_evidence_manifest,
        proof_regeneration_input,
        proof_sha256,
        verifier_sha256,
        workflow_sha256,
        bilateral_dsse_sha256,
        trust_bundle_sha256,
        verification_context_sha256,
        artifact_refs,
    } = context;
    if validate_runtime_workflow_run_report(runtime_run_report).is_err()
        || validate_runtime_proof_regeneration_report(proof_regeneration_report).is_err()
        || validate_runtime_evidence_manifest(runtime_evidence_manifest).is_err()
        || validate_runtime_proof_regeneration_input(proof_regeneration_input).is_err()
        || !runtime_run_report.accepted
        || !proof_regeneration_report.accepted
        || runtime_run_report.generated_at_unix_ms != runtime_evidence_manifest.generated_at_unix_ms
        || proof_regeneration_report.generated_at_unix_ms
            != runtime_evidence_manifest.generated_at_unix_ms
    {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    let proof_regeneration_sha256 = canonical_sha256(proof_regeneration_report)
        .map_err(|_| "chio_buyer_review_runtime_report_mismatch")?;
    let runtime_run_sha256 = canonical_sha256(runtime_run_report)
        .map_err(|_| "chio_buyer_review_runtime_report_mismatch")?;
    let manifest_sha256 = canonical_sha256(runtime_evidence_manifest)
        .map_err(|_| "chio_buyer_review_runtime_report_mismatch")?;
    if runtime_run_report
        .proof_regeneration_report_sha256
        .as_deref()
        != Some(proof_regeneration_sha256.as_str())
        || runtime_run_report.run_id != proof_regeneration_report.run_id
        || runtime_evidence_manifest.run_id != runtime_run_report.run_id
        || runtime_evidence_manifest.workflow_run_report_sha256 != runtime_run_sha256
        || runtime_evidence_manifest.proof_regeneration_report_sha256 != proof_regeneration_sha256
        || proof_regeneration_input.run_id != runtime_run_report.run_id
        || proof_regeneration_input.evidence_manifest_sha256 != manifest_sha256
        || proof_regeneration_input.workflow_run_report_sha256 != runtime_run_sha256
        || proof_regeneration_input.source_records != proof_regeneration_report.source_records
        || runtime_run_report.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.trust_bundle_sha256 != trust_bundle_sha256
        || proof_regeneration_input.verification_context_sha256 != verification_context_sha256
        || proof_regeneration_report.proof_package_sha256.as_deref() != Some(proof_sha256)
        || proof_regeneration_report.verifier_report_sha256.as_deref() != Some(verifier_sha256)
        || proof_regeneration_report.workflow_receipt_sha256.as_deref() != Some(workflow_sha256)
    {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    verify_runtime_evidence_manifest_artifacts(runtime_evidence_manifest, artifact_refs)?;
    let Some(step) = runtime_run_report
        .step_evidence
        .iter()
        .find(|step| step.bilateral_dsse_sha256 == bilateral_dsse_sha256)
    else {
        return Err("chio_buyer_review_runtime_report_mismatch");
    };
    if step.lease_id.is_none() || step.governance_receipt_id.is_none() {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    if step.admission_report_sha256 != packet.cross_boundary_admission_report_sha256
        || step.tool_receipt_sha256 != bilateral.remote_receipt_sha256
        || step.parent_receipt_sha256.as_deref() != Some(bilateral.local_receipt_sha256.as_str())
        || step.output_sha256 != bilateral.outcome_sha256
    {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    if !workflow_receipt_contains_step_hash(workflow_receipt, &step.workflow_step_sha256)? {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    if !proof_package_contains_signed_receipt(proof_package, &step.tool_receipt_sha256)? {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    if let Some(parent_receipt_sha256) = step.parent_receipt_sha256.as_deref() {
        if !proof_package_contains_parent_lineage_anchor(
            proof_package,
            workflow_receipt,
            &step.workflow_step_sha256,
            parent_receipt_sha256,
        )? {
            return Err("chio_buyer_review_proof_package_mismatch");
        }
    }
    if !proof_package_array_contains_field(
        proof_package,
        "capabilityLeases",
        "leaseId",
        step.lease_id
            .as_deref()
            .ok_or("chio_buyer_review_runtime_report_mismatch")?,
    ) || !proof_package_array_contains_field(
        proof_package,
        "governanceReceipts",
        "receiptId",
        step.governance_receipt_id
            .as_deref()
            .ok_or("chio_buyer_review_runtime_report_mismatch")?,
    ) {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    let source_record_matches = proof_regeneration_report
        .source_records
        .iter()
        .any(|record| {
            record.step_index == step.step_index
                && record.admission_report_sha256 == step.admission_report_sha256
                && record.tool_receipt_sha256 == step.tool_receipt_sha256
                && record.bilateral_dsse_sha256 == step.bilateral_dsse_sha256
                && record.workflow_step_sha256 == step.workflow_step_sha256
        });
    if !source_record_matches {
        return Err("chio_buyer_review_runtime_report_mismatch");
    }
    Ok(step.clone())
}

fn verify_runtime_evidence_manifest_artifacts(
    manifest: &RuntimeEvidenceManifest,
    artifact_refs: &[BuyerAttestationReviewArtifactRef],
) -> Result<(), &'static str> {
    for role in [
        "bilateral_dsse_envelope",
        "workflow_receipt",
        "proof_package",
        "verifier_report",
        "proof_regeneration_report",
        "runtime_run_report",
    ] {
        let Some(artifact) = artifact_refs.iter().find(|artifact| artifact.role == role) else {
            return Err("chio_buyer_review_runtime_report_mismatch");
        };
        let Some(entry) = manifest.entries.iter().find(|entry| entry.role == role) else {
            return Err("chio_buyer_review_runtime_report_mismatch");
        };
        if entry.path != artifact.relative_path
            || entry.sha256 != artifact.artifact_sha256
            || entry.byte_count != artifact.byte_count
        {
            return Err("chio_buyer_review_runtime_report_mismatch");
        }
    }
    Ok(())
}
