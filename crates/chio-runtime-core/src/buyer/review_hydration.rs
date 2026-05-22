use std::collections::BTreeMap;

use crate::buyer::helpers::parse_review_json;
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, CrossBoundaryAdmissionReport,
    CrossKernelContinuation, ReceiptLineageBundle, ReceiptLineageStatement,
    RuntimeEvidenceManifest, RuntimeProofRegenerationInput, RuntimeProofRegenerationReport,
    RuntimeWorkflowRunReport,
};
use crate::ChioRuntimeError;

pub(super) const BUYER_REVIEW_REQUIRED_ROLES: &[&str] = &[
    "buyer_attestation_packet",
    "receipt_lineage_statement",
    "receipt_lineage_bundle",
    "cross_kernel_continuation",
    "cross_boundary_admission_report",
    "bilateral_invocation",
    "bilateral_dsse_envelope",
    "workflow_receipt",
    "proof_package",
    "verifier_report",
    "proof_regeneration_report",
    "runtime_run_report",
    "runtime_evidence_manifest",
    "proof_regeneration_input",
];

pub(super) struct BuyerReviewHydratedArtifacts {
    pub(super) packet: BuyerAttestationPacket,
    pub(super) lineage: ReceiptLineageStatement,
    pub(super) lineage_bundle: ReceiptLineageBundle,
    pub(super) continuation: CrossKernelContinuation,
    pub(super) admission: CrossBoundaryAdmissionReport,
    pub(super) bilateral: BilateralInvocation,
    pub(super) bilateral_dsse: chio_federation::DsseEnvelope,
    pub(super) proof_package: serde_json::Value,
    pub(super) workflow_receipt: serde_json::Value,
    pub(super) verifier_report: serde_json::Value,
    pub(super) proof_regeneration_report: RuntimeProofRegenerationReport,
    pub(super) runtime_run_report: RuntimeWorkflowRunReport,
    pub(super) runtime_evidence_manifest: RuntimeEvidenceManifest,
    pub(super) proof_regeneration_input: RuntimeProofRegenerationInput,
}

impl BuyerReviewHydratedArtifacts {
    pub(super) fn from_bound_sources(
        source_bytes_by_role: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ChioRuntimeError> {
        Ok(Self {
            packet: parse_review_json(source_bytes_by_role, "buyer_attestation_packet")?,
            lineage: parse_review_json(source_bytes_by_role, "receipt_lineage_statement")?,
            lineage_bundle: parse_review_json(source_bytes_by_role, "receipt_lineage_bundle")?,
            continuation: parse_review_json(source_bytes_by_role, "cross_kernel_continuation")?,
            admission: parse_review_json(source_bytes_by_role, "cross_boundary_admission_report")?,
            bilateral: parse_review_json(source_bytes_by_role, "bilateral_invocation")?,
            bilateral_dsse: parse_review_json(source_bytes_by_role, "bilateral_dsse_envelope")?,
            proof_package: parse_review_json(source_bytes_by_role, "proof_package")?,
            workflow_receipt: parse_review_json(source_bytes_by_role, "workflow_receipt")?,
            verifier_report: parse_review_json(source_bytes_by_role, "verifier_report")?,
            proof_regeneration_report: parse_review_json(
                source_bytes_by_role,
                "proof_regeneration_report",
            )?,
            runtime_run_report: parse_review_json(source_bytes_by_role, "runtime_run_report")?,
            runtime_evidence_manifest: parse_review_json(
                source_bytes_by_role,
                "runtime_evidence_manifest",
            )?,
            proof_regeneration_input: parse_review_json(
                source_bytes_by_role,
                "proof_regeneration_input",
            )?,
        })
    }
}
