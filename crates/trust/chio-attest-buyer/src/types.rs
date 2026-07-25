use chio_runtime_core::GovernanceLadderQuorum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossKernelContinuation {
    pub schema: String,
    pub continuation_id: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
    pub parent_receipt_sha256: String,
    pub parent_session_anchor_sha256: String,
    pub capability_id: String,
    pub action_class_id: String,
    pub audience_tool: String,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageStatement {
    pub schema: String,
    pub statement_id: String,
    pub parent_receipt_sha256: String,
    pub child_receipt_sha256: String,
    pub continuation_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub evidence_class: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryEvidenceRef {
    pub evidence_class: String,
    pub artifact_sha256: String,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryAdmissionReport {
    pub schema: String,
    pub treaty_id: String,
    pub action_class_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub mode: String,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub required_evidence: Vec<String>,
    pub present_evidence: Vec<String>,
    #[serde(default)]
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ladder_intersection_sha256: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BilateralInvocation {
    pub schema: String,
    pub invocation_id: String,
    pub treaty_id: String,
    pub ladder_intersection_sha256: String,
    pub continuation_sha256: String,
    pub lineage_statement_sha256: String,
    pub action_class_id: String,
    pub consistency_model: String,
    pub capability_id: String,
    pub request_sha256: String,
    pub outcome_sha256: String,
    pub local_receipt_sha256: String,
    pub remote_receipt_sha256: String,
    pub signer_kernel_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationPacket {
    pub schema: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub capability_id: String,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    pub cross_boundary_admission_report_sha256: String,
    pub continuation_sha256: String,
    pub receipt_lineage_statement_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_receipt_sha256: String,
    pub proof_package_sha256: String,
    pub verifier_report_sha256: String,
    pub budget_refs: Vec<String>,
    pub settlement_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationVerificationReport {
    pub schema: String,
    pub packet_id: String,
    pub verification_state: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageBundle {
    pub schema: String,
    pub bundle_id: String,
    pub root_receipt_sha256: String,
    pub leaf_receipt_sha256: String,
    pub statements: Vec<ReceiptLineageStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewArtifactRef {
    pub role: String,
    pub relative_path: String,
    pub artifact_sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyerAttestationReviewSource {
    pub role: String,
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

pub struct BuyerAttestationReviewTrustContext<'a> {
    pub verifier_trust_bundle: &'a serde_json::Value,
    pub verification_context: &'a serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChioProofVerificationReport {
    pub accepted: bool,
    pub failure_code: Option<String>,
    pub json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub generated_at_unix_ms: u64,
    pub artifacts: Vec<BuyerAttestationReviewArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewCheck {
    pub code: String,
    pub passed: bool,
    pub severity: String,
    pub artifact_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_sha256: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewReport {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<BuyerAttestationReviewCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifestEntry {
    pub role: String,
    pub path: String,
    pub sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifest {
    pub schema: String,
    pub run_id: String,
    pub generated_at_unix_ms: u64,
    pub workflow_run_report_sha256: String,
    pub proof_regeneration_report_sha256: String,
    pub entries: Vec<RuntimeEvidenceManifestEntry>,
}
