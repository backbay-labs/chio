//! Chio buyer attestation verification boundary.
//!
//! This crate owns the public Chio buyer proof verification API. The public
//! data types are defined here so callers depend on Chio shapes, not on the
//! proof verifier core. This crate delegates full proof replay to the hardened verifier core
//! so hash-only DSSE remains unresolved and full review keeps strict
//! treaty-bound DSSE semantics.

#![forbid(unsafe_code)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

pub const CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA: &str =
    "chio.attest.buyer-attestation-packet.v1";
pub const CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA: &str =
    "chio.attest.buyer-attestation-review-package.v1";
pub const CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA: &str =
    "chio.attest.buyer-attestation-review-report.v1";
pub const CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA: &str =
    "chio.attest.buyer-attestation-verification-report.v1";
pub const CHIO_ATTEST_BUYER_ATTESTATION_EXPLANATION_SCHEMA: &str =
    "chio.attest.buyer-attestation-explanation.v1";
pub const CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA: &str =
    "chio.federation.bilateral-invocation.v1";
pub const CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA: &str =
    "chio.federation.cross-kernel-continuation.v1";
pub const CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA: &str =
    "chio.federation.receipt-lineage-bundle.v1";
pub const CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA: &str =
    "chio.federation.receipt-lineage-statement.v1";

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

type HistoricalBuyerError = chio_runtime_core::ChioRuntimeError;

#[derive(Debug)]
pub struct BuyerAttestationError {
    code: String,
    source: HistoricalBuyerError,
}

impl BuyerAttestationError {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    fn from_historical(source: HistoricalBuyerError) -> Self {
        let code = chio_attest_buyer_code(source.code());
        Self { code, source }
    }
}

impl fmt::Display for BuyerAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for BuyerAttestationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

// --- Conversions between Chio-owned shapes and the proof verifier backend.

fn historical_cross_kernel_continuation(
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

fn historical_receipt_lineage_statement(
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

fn historical_cross_boundary_evidence_ref(
    value: &CrossBoundaryEvidenceRef,
) -> chio_runtime_core::CrossBoundaryEvidenceRef {
    chio_runtime_core::CrossBoundaryEvidenceRef {
        evidence_class: value.evidence_class.clone(),
        artifact_sha256: value.artifact_sha256.clone(),
        verified: value.verified,
    }
}

fn historical_cross_boundary_admission_report(
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
            .map(historical_cross_boundary_evidence_ref)
            .collect(),
        treaty_scope_sha256: value.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: value.ladder_intersection_sha256.clone(),
        expected_ladder_intersection_sha256: value.expected_ladder_intersection_sha256.clone(),
        checks: value.checks.clone(),
    }
}

fn historical_bilateral_invocation(
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

fn historical_buyer_attestation_packet(
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

fn historical_review_artifact_ref(
    value: &BuyerAttestationReviewArtifactRef,
) -> chio_runtime_core::BuyerAttestationReviewArtifactRef {
    chio_runtime_core::BuyerAttestationReviewArtifactRef {
        role: value.role.clone(),
        relative_path: value.relative_path.clone(),
        artifact_sha256: value.artifact_sha256.clone(),
        byte_count: value.byte_count,
    }
}

fn historical_review_package(
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
            .map(historical_review_artifact_ref)
            .collect(),
    }
}

fn historical_review_source(
    value: &BuyerAttestationReviewSource,
) -> chio_runtime_core::BuyerAttestationReviewSource {
    chio_runtime_core::BuyerAttestationReviewSource {
        role: value.role.clone(),
        relative_path: value.relative_path.clone(),
        bytes: value.bytes.clone(),
    }
}

fn historical_review_sources(
    sources: &[BuyerAttestationReviewSource],
) -> Vec<chio_runtime_core::BuyerAttestationReviewSource> {
    sources.iter().map(historical_review_source).collect()
}

fn historical_review_bundle(
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
            .map(historical_receipt_lineage_statement)
            .collect(),
    }
}

fn local_verification_report(
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

fn local_review_report(
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

fn chio_attest_buyer_code(code: &str) -> String {
    let retired_buyer_prefix = ["chio", "dos", "_buyer."].concat();
    let retired_buyer_packet_prefix = ["chio", "dos", "_buyer_packet."].concat();
    let retired_buyer_review_prefix = ["chio", "dos", "_buyer_review."].concat();
    for (historical_prefix, chio_prefix) in [
        (retired_buyer_prefix.as_str(), "chio_attest_buyer.packet."),
        (
            retired_buyer_packet_prefix.as_str(),
            "chio_attest_buyer.packet.",
        ),
        (
            retired_buyer_review_prefix.as_str(),
            "chio_attest_buyer.review.",
        ),
        ("chio_buyer.", "chio_attest_buyer.packet."),
        ("chio_buyer_review.", "chio_attest_buyer.review."),
        ("buyer_review.", "chio_attest_buyer.review."),
        ("chio_buyer_packet.", "chio_attest_buyer.packet."),
        ("buyer_packet.", "chio_attest_buyer.packet."),
        ("chio_buyer_review_", "chio_attest_buyer_review_"),
        ("buyer_review_", "chio_attest_buyer_review_"),
        ("chio_buyer_packet_", "chio_attest_buyer_packet_"),
        ("buyer_packet_", "chio_attest_buyer_packet_"),
    ] {
        if let Some(suffix) = code.strip_prefix(historical_prefix) {
            return format!("{chio_prefix}{suffix}");
        }
    }
    code.to_string()
}

// --- Public Chio buyer attestation API.

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
    let historical = chio_runtime_core::BuyerAttestationVerificationReport {
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
    chio_runtime_core::buyer_attestation_verification_report_json(&historical)
        .map_err(BuyerAttestationError::from_historical)
}

pub fn buyer_attestation_review_report_json(
    report: &BuyerAttestationReviewReport,
) -> Result<String, BuyerAttestationError> {
    let historical = chio_runtime_core::BuyerAttestationReviewReport {
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
    chio_runtime_core::buyer_attestation_review_report_json(&historical)
        .map_err(BuyerAttestationError::from_historical)
}

pub fn buyer_attestation_packet_sha256(
    packet: &BuyerAttestationPacket,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::buyer_attestation_packet_sha256(&historical_buyer_attestation_packet(packet))
        .map_err(BuyerAttestationError::from_historical)
}

pub fn receipt_lineage_statement_sha256(
    statement: &ReceiptLineageStatement,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::receipt_lineage_statement_sha256(&historical_receipt_lineage_statement(
        statement,
    ))
    .map_err(BuyerAttestationError::from_historical)
}

pub fn bilateral_invocation_binding_sha256(
    invocation: &BilateralInvocation,
) -> Result<String, BuyerAttestationError> {
    chio_runtime_core::bilateral_invocation_binding_sha256(&historical_bilateral_invocation(
        invocation,
    ))
    .map_err(BuyerAttestationError::from_historical)
}

pub fn verify_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<BuyerAttestationVerificationReport, BuyerAttestationError> {
    chio_runtime_core::verify_buyer_attestation_packet(
        &historical_buyer_attestation_packet(packet),
        &historical_receipt_lineage_statement(lineage),
        &historical_cross_kernel_continuation(continuation),
        &historical_cross_boundary_admission_report(admission),
        &historical_bilateral_invocation(bilateral),
    )
    .map(local_verification_report)
    .map_err(BuyerAttestationError::from_historical)
}

pub fn verify_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
) -> Result<BuyerAttestationReviewReport, BuyerAttestationError> {
    chio_runtime_core::verify_buyer_attestation_review_package(
        &historical_review_package(package),
        &historical_review_sources(sources),
    )
    .map(local_review_report)
    .map_err(BuyerAttestationError::from_historical)
}

pub fn verify_buyer_attestation_review_package_with_trust(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: &BuyerAttestationReviewTrustContext<'_>,
) -> Result<BuyerAttestationReviewReport, BuyerAttestationError> {
    let historical_trust = chio_runtime_core::BuyerAttestationReviewTrustContext {
        verifier_trust_bundle: trust_context.verifier_trust_bundle,
        verification_context: trust_context.verification_context,
    };
    chio_runtime_core::verify_buyer_attestation_review_package_with_trust(
        &historical_review_package(package),
        &historical_review_sources(sources),
        &historical_trust,
    )
    .map(local_review_report)
    .map_err(BuyerAttestationError::from_historical)
}

pub fn verify_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<bool, BuyerAttestationError> {
    chio_runtime_core::verify_receipt_lineage_bundle(&historical_review_bundle(bundle))
        .map_err(BuyerAttestationError::from_historical)
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
        replay_historical_verifier(
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
    let proof_package = chio_attest_buyer_core::proof_package_from_json(proof_package_json)
        .map_err(|error| json_error("Chio attest proof package", error))?;
    let trust_bundle =
        chio_attest_buyer_core::verifier_trust_bundle_from_json(verifier_trust_bundle_json)
            .map_err(|error| json_error("Chio verifier trust bundle", error))?;
    let context = chio_attest_buyer_core::verification_context_from_json(verification_context_json)
        .map_err(|error| json_error("Chio verification context", error))?;
    let report =
        chio_attest_buyer_core::verify_package_report(&proof_package, &trust_bundle, &context);
    let json = chio_attest_buyer_core::report_json(&report)
        .map_err(|error| json_error("Chio attest proof report", error))?;
    Ok(ChioProofVerificationReport {
        accepted: report.accepted,
        failure_code: report.failure.as_ref().map(|failure| failure.code.clone()),
        json,
    })
}

fn parse_json_value(label: &str, json: &str) -> Result<serde_json::Value, BuyerAttestationError> {
    serde_json::from_str(json).map_err(|error| json_error(label, error))
}

fn json_error(label: &str, error: impl fmt::Display) -> BuyerAttestationError {
    BuyerAttestationError::from_historical(HistoricalBuyerError::Json(format!("{label}: {error}")))
}

fn boundary_rejection(code: &'static str, detail: impl Into<String>) -> BuyerAttestationError {
    BuyerAttestationError::from_historical(HistoricalBuyerError::Rejected {
        code,
        detail: detail.into(),
    })
}

fn validate_buyer_attestation_packet_boundary(
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

fn validate_buyer_attestation_review_package_boundary(
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

fn replay_historical_verifier(
    report: &mut BuyerAttestationReviewReport,
    sources: &[BuyerAttestationReviewSource],
    verifier_trust_bundle_json: &str,
    verification_context_json: &str,
) -> Result<(), BuyerAttestationError> {
    let proof_package_bytes = review_source_bytes(sources, "proof_package").ok_or_else(|| {
        BuyerAttestationError::from_historical(HistoricalBuyerError::Rejected {
            code: "chio_attest_buyer_review_missing_proof_package",
            detail: "buyer review package is missing proof_package artifact".to_string(),
        })
    })?;
    let proof_package_json = std::str::from_utf8(proof_package_bytes)
        .map_err(|error| json_error("Chio buyer proof package artifact", error))?;
    let proof_package = chio_attest_buyer_core::proof_package_from_json(proof_package_json)
        .map_err(|error| json_error("Chio buyer proof package", error))?;
    let trust_bundle =
        chio_attest_buyer_core::verifier_trust_bundle_from_json(verifier_trust_bundle_json)
            .map_err(|error| json_error("Chio buyer verifier trust bundle", error))?;
    let context = chio_attest_buyer_core::verification_context_from_json(verification_context_json)
        .map_err(|error| json_error("Chio buyer verification context", error))?;
    let verifier_report =
        chio_attest_buyer_core::verify_package_report(&proof_package, &trust_bundle, &context);
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

// Round-trip the runtime evidence manifest through the historical type so
// that the historical crate's manifest invariants are honored even when
// callers obtain the manifest through Chio shapes.
pub fn runtime_evidence_manifest_from_json(
    json: &str,
) -> Result<RuntimeEvidenceManifest, BuyerAttestationError> {
    let historical: chio_runtime_core::RuntimeEvidenceManifest = serde_json::from_str(json)
        .map_err(|error| json_error("Chio runtime evidence manifest JSON", error))?;
    chio_runtime_core::validate_runtime_evidence_manifest(&historical)
        .map_err(BuyerAttestationError::from_historical)?;
    Ok(RuntimeEvidenceManifest {
        schema: historical.schema,
        run_id: historical.run_id,
        generated_at_unix_ms: historical.generated_at_unix_ms,
        workflow_run_report_sha256: historical.workflow_run_report_sha256,
        proof_regeneration_report_sha256: historical.proof_regeneration_report_sha256,
        entries: historical
            .entries
            .into_iter()
            .map(|entry| RuntimeEvidenceManifestEntry {
                role: entry.role,
                path: entry.path,
                sha256: entry.sha256,
                byte_count: entry.byte_count,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_error_helper_keeps_chio_boundary_code_and_label() {
        let parse_error = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => panic!("invalid JSON must fail"),
            Err(error) => error,
        };
        let error = json_error("Chio buyer packet JSON", parse_error);

        assert_eq!(error.code(), "runtime_admission_json");
        assert!(
            error.to_string().contains("Chio buyer packet JSON"),
            "label should remain visible in public error text"
        );
    }
}
