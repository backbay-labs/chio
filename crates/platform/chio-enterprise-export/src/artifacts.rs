use std::{collections::BTreeSet, path::Path};

use chio_core_types::crypto::{PublicKey, Signature};
use chio_core_types::receipt::body::ChioReceipt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use chio_risk_comptroller::{
    validate_risk_evidence_refs,
    validate_risk_portfolio_reports as validate_comptroller_portfolio_reports,
    validate_risk_report as validate_comptroller_report, RiskEvidenceRefKind,
};
use chio_transaction_passport::{TransactionPassport, TransactionPassportError};

pub(super) use chio_risk_comptroller::RiskComptrollerReport;

use super::evidence::{
    validate_bundle_relative_path, validate_sha256_hex, EnterpriseEvidenceGraph,
};
use super::EnterpriseExportBundle;

const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
const ENTERPRISE_APPROVAL_CASE_SCHEMA: &str = "chio.enterprise.approval-case.v1";
const ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA: &str = "chio.enterprise.control-evidence-map.v1";
const ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA: &str = "chio.enterprise.data-governance-report.v1";
const ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA: &str = "chio.enterprise.evidence-export-bundle.v1";
const ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA: &str = "chio.enterprise.telemetry-projection.v1";
const RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
const RISK_GUARANTEE_DECISION_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
const WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v2";
const WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";
const MIN_ENTERPRISE_AUDIT_RETENTION_DAYS: u64 = 365;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DataGovernanceReport {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    allowed_regions: Vec<String>,
    observed_region: String,
    retention_class: String,
    legal_hold_status: String,
    redaction_profile_ref: String,
    disclosure_capsule_ref: String,
    leakage_ledger_ref: String,
    field_classifications: Vec<FieldClassification>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldClassification {
    field: String,
    classification: String,
    export_action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalCase {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    evidence_export_bundle_digest: String,
    signature: String,
    decision: String,
    decision_subject: String,
    approvers: Vec<String>,
    required_quorum: u64,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceExportBundleArtifact {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    approval_case_ref: String,
    bundle_digest: String,
    artifacts: Vec<ExportArtifactRef>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExportArtifactRef {
    role: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TelemetryProjection {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    events: Vec<TelemetryEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryEvent {
    event_id: String,
    event_kind: String,
    artifact_ref: String,
    artifact_sha256: String,
    receipt_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlEvidenceMap {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    controls: Vec<ControlEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlEvidence {
    control_id: String,
    control_family: String,
    claim_ref: String,
    gate_ref: String,
}

pub(super) fn validate_risk_report(
    passport: &TransactionPassport,
    report: &RiskComptrollerReport,
    bundle: &EnterpriseExportBundle,
    graph: &EnterpriseEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    validate_comptroller_report(passport, report)?;
    validate_risk_evidence_refs(report, |evidence_ref, kind| {
        graph_contains_risk_evidence_kind(bundle, graph, evidence_ref, kind)
    })
}

pub(super) fn validate_risk_portfolio_reports(
    reports: &[RiskComptrollerReport],
) -> Result<(), TransactionPassportError> {
    validate_comptroller_portfolio_reports(reports)
}

pub(super) fn select_referenced_risk_report<'a>(
    reports: &'a [RiskComptrollerReport],
    data_governance: &DataGovernanceReport,
    export_bundle: &EvidenceExportBundleArtifact,
    telemetry: &TelemetryProjection,
    approval: &ApprovalCase,
    control_map: &ControlEvidenceMap,
) -> Result<&'a RiskComptrollerReport, TransactionPassportError> {
    let expected_ref = data_governance.risk_comptroller_report_ref.as_str();
    require_non_empty(expected_ref, "risk_comptroller_report_ref")?;
    for (field, actual_ref) in [
        (
            "evidence export risk_comptroller_report_ref",
            export_bundle.risk_comptroller_report_ref.as_str(),
        ),
        (
            "telemetry projection risk_comptroller_report_ref",
            telemetry.risk_comptroller_report_ref.as_str(),
        ),
        (
            "approval case risk_comptroller_report_ref",
            approval.risk_comptroller_report_ref.as_str(),
        ),
        (
            "control map risk_comptroller_report_ref",
            control_map.risk_comptroller_report_ref.as_str(),
        ),
    ] {
        require_non_empty(actual_ref, field)?;
        if actual_ref != expected_ref {
            return Err(claim_failed(format!("{field} mismatch")));
        }
    }
    reports
        .iter()
        .find(|report| report.id == expected_ref)
        .ok_or_else(|| claim_failed("referenced risk report missing"))
}

pub(super) fn validate_data_governance(
    passport: &TransactionPassport,
    risk_report: &RiskComptrollerReport,
    report: &DataGovernanceReport,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &report.schema),
        ("id", &report.id),
        ("issued_at", &report.issued_at),
        ("passport_id", &report.passport_id),
        (
            "risk_comptroller_report_ref",
            &report.risk_comptroller_report_ref,
        ),
        ("observed_region", &report.observed_region),
        ("retention_class", &report.retention_class),
        ("legal_hold_status", &report.legal_hold_status),
        ("redaction_profile_ref", &report.redaction_profile_ref),
        ("disclosure_capsule_ref", &report.disclosure_capsule_ref),
        ("leakage_ledger_ref", &report.leakage_ledger_ref),
    ] {
        require_non_empty(value, field)?;
    }
    if report.passport_id != passport.id {
        return Err(claim_failed("data governance passport mismatch"));
    }
    if report.risk_comptroller_report_ref != risk_report.id {
        return Err(claim_failed("data governance risk report mismatch"));
    }
    if report.allowed_regions.is_empty()
        || !report
            .allowed_regions
            .iter()
            .any(|region| region == &report.observed_region)
    {
        return Err(claim_failed("data governance region not allowed"));
    }
    if report.legal_hold_status != "not_held" {
        return Err(claim_failed("data governance legal hold blocks export"));
    }
    validate_retention_class(&report.retention_class)?;
    if report.field_classifications.is_empty() {
        return Err(claim_failed(
            "data governance field classifications missing",
        ));
    }
    for field in &report.field_classifications {
        validate_field_classification(field)?;
    }
    Ok(())
}

pub(super) fn validate_evidence_export_bundle(
    bundle: &EnterpriseExportBundle,
    passport: &TransactionPassport,
    risk_report: &RiskComptrollerReport,
    data_governance: &DataGovernanceReport,
    approval: &ApprovalCase,
    export_bundle: &EvidenceExportBundleArtifact,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &export_bundle.schema),
        ("id", &export_bundle.id),
        ("issued_at", &export_bundle.issued_at),
        ("passport_id", &export_bundle.passport_id),
        (
            "risk_comptroller_report_ref",
            &export_bundle.risk_comptroller_report_ref,
        ),
        ("approval_case_ref", &export_bundle.approval_case_ref),
        ("bundle_digest", &export_bundle.bundle_digest),
    ] {
        require_non_empty(value, field)?;
    }
    if export_bundle.passport_id != passport.id {
        return Err(claim_failed("evidence export passport mismatch"));
    }
    if export_bundle.risk_comptroller_report_ref != risk_report.id {
        return Err(claim_failed("evidence export risk report mismatch"));
    }
    if export_bundle.approval_case_ref != approval.id {
        return Err(claim_failed("evidence export approval case mismatch"));
    }
    let export_issued_at =
        parse_rfc3339_utc(&export_bundle.issued_at, "evidence export issued_at")?;
    let approval_issued_at = parse_rfc3339_utc(&approval.issued_at, "approval issued_at")?;
    let approval_expires_at = parse_rfc3339_utc(&approval.expires_at, "approval expires_at")?;
    if export_issued_at < approval_issued_at {
        return Err(claim_failed("approval case issued after export issuance"));
    }
    if export_issued_at >= approval_expires_at {
        return Err(claim_failed("approval case expired before export issuance"));
    }
    validate_sha256_hex(&export_bundle.bundle_digest)
        .map_err(|_| claim_failed("export bundle digest mismatch"))?;

    let canonical =
        chio_core_types::canonical_json_bytes(&export_bundle.artifacts).map_err(|error| {
            claim_failed(format!(
                "export bundle digest canonicalization failed: {error}"
            ))
        })?;
    let actual_digest = chio_core_types::sha256_hex(&canonical);
    if actual_digest != export_bundle.bundle_digest {
        return Err(claim_failed("export bundle digest mismatch"));
    }

    let mut roles = BTreeSet::new();
    for artifact in &export_bundle.artifacts {
        validate_export_artifact_ref(bundle, artifact)?;
        if !roles.insert(artifact.role.as_str()) {
            return Err(claim_failed(format!(
                "duplicate export artifact role: {}",
                artifact.role
            )));
        }
    }
    for required_role in [
        "transaction_passport",
        "verifier_report",
        "risk_comptroller_report",
        "disclosure_capsule",
        "leakage_ledger",
        "data_governance_report",
    ] {
        if !roles.contains(required_role) {
            return Err(claim_failed(format!(
                "missing export artifact role: {required_role}"
            )));
        }
    }
    ensure_export_role_field_points_to(
        bundle,
        &export_bundle.artifacts,
        "transaction_passport",
        "passport_id",
        &passport.id,
        "passport",
    )?;
    ensure_export_role_field_points_to(
        bundle,
        &export_bundle.artifacts,
        "verifier_report",
        "passport_id",
        &passport.id,
        "passport",
    )?;
    ensure_export_role_field_points_to(
        bundle,
        &export_bundle.artifacts,
        "verifier_report",
        "verdict",
        "verified",
        "verdict",
    )?;
    ensure_export_role_points_to(
        bundle,
        &export_bundle.artifacts,
        "risk_comptroller_report",
        &risk_report.id,
    )?;
    ensure_export_role_points_to(
        bundle,
        &export_bundle.artifacts,
        "data_governance_report",
        &data_governance.id,
    )?;
    ensure_export_role_points_to(
        bundle,
        &export_bundle.artifacts,
        "disclosure_capsule",
        &data_governance.disclosure_capsule_ref,
    )?;
    ensure_export_role_points_to(
        bundle,
        &export_bundle.artifacts,
        "leakage_ledger",
        &data_governance.leakage_ledger_ref,
    )?;
    Ok(())
}

pub(super) fn validate_telemetry_projection(
    bundle: &EnterpriseExportBundle,
    passport: &TransactionPassport,
    risk_report: &RiskComptrollerReport,
    telemetry: &TelemetryProjection,
    trusted_receipt_kernel_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &telemetry.schema),
        ("id", &telemetry.id),
        ("issued_at", &telemetry.issued_at),
        ("passport_id", &telemetry.passport_id),
        (
            "risk_comptroller_report_ref",
            &telemetry.risk_comptroller_report_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if telemetry.passport_id != passport.id {
        return Err(claim_failed("telemetry projection passport mismatch"));
    }
    if telemetry.risk_comptroller_report_ref != risk_report.id {
        return Err(claim_failed("telemetry projection risk report mismatch"));
    }
    let mut event_kinds = BTreeSet::new();
    for event in &telemetry.events {
        require_non_empty(&event.event_id, "event_id")?;
        require_non_empty(&event.event_kind, "event_kind")?;
        require_non_empty(&event.artifact_ref, "artifact_ref")?;
        validate_sha256_hex(&event.artifact_sha256)
            .map_err(|_| claim_failed("telemetry artifact digest invalid"))?;
        let bytes = bundle.artifacts.get(&event.artifact_ref).ok_or_else(|| {
            TransactionPassportError::MissingEnterpriseArtifact(event.artifact_ref.clone())
        })?;
        let actual_digest = chio_core_types::sha256_hex(bytes);
        if actual_digest != event.artifact_sha256 {
            return Err(claim_failed("telemetry artifact digest mismatch"));
        }
        if let Some(receipt_ref) = event.receipt_ref.as_deref() {
            require_non_empty(receipt_ref, "receipt_ref")?;
            let receipt_bytes = bundle.artifacts.get(receipt_ref).ok_or_else(|| {
                TransactionPassportError::MissingEnterpriseArtifact(receipt_ref.to_string())
            })?;
            let receipt: ChioReceipt = serde_json::from_slice(receipt_bytes)
                .map_err(|_| claim_failed("telemetry receipt invalid"))?;
            let signature_valid = receipt
                .verify_signature()
                .map_err(|_| claim_failed("telemetry receipt signature invalid"))?;
            if !signature_valid {
                return Err(claim_failed("telemetry receipt signature invalid"));
            }
            if !trusted_receipt_kernel_keys.contains(&receipt.kernel_key) {
                return Err(claim_failed("telemetry receipt signer untrusted"));
            }
            validate_telemetry_receipt_binding(event, &receipt)?;
        } else if event.event_kind == "siem_export" {
            return Err(claim_failed("telemetry SIEM event missing receipt"));
        }
        event_kinds.insert(event.event_kind.as_str());
    }
    for required_event in ["allow", "denied_guard", "risk_verifier"] {
        if !event_kinds.contains(required_event) {
            return Err(claim_failed(format!(
                "telemetry projection missing event: {required_event}"
            )));
        }
    }
    Ok(())
}

fn validate_telemetry_receipt_binding(
    event: &TelemetryEvent,
    receipt: &ChioReceipt,
) -> Result<(), TransactionPassportError> {
    if receipt.content_hash != event.artifact_sha256 {
        return Err(claim_failed("telemetry receipt content hash mismatch"));
    }
    if receipt.tool_name != event.event_kind {
        return Err(claim_failed("telemetry receipt action mismatch"));
    }
    let action_hash_valid = receipt
        .action
        .verify_hash()
        .map_err(|_| claim_failed("telemetry receipt action invalid"))?;
    if !action_hash_valid {
        return Err(claim_failed("telemetry receipt action invalid"));
    }
    for (field, expected) in [
        ("event_id", event.event_id.as_str()),
        ("artifact_ref", event.artifact_ref.as_str()),
        ("artifact_sha256", event.artifact_sha256.as_str()),
    ] {
        if receipt
            .action
            .parameters
            .get(field)
            .and_then(serde_json::Value::as_str)
            != Some(expected)
        {
            return Err(claim_failed("telemetry receipt action mismatch"));
        }
    }
    Ok(())
}

pub(super) fn validate_approval_case(
    passport: &TransactionPassport,
    risk_report: &RiskComptrollerReport,
    export_bundle: &EvidenceExportBundleArtifact,
    approval: &ApprovalCase,
    trusted_approval_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &approval.schema),
        ("id", &approval.id),
        ("issued_at", &approval.issued_at),
        ("passport_id", &approval.passport_id),
        (
            "risk_comptroller_report_ref",
            &approval.risk_comptroller_report_ref,
        ),
        (
            "evidence_export_bundle_digest",
            &approval.evidence_export_bundle_digest,
        ),
        ("signature", &approval.signature),
        ("decision", &approval.decision),
        ("decision_subject", &approval.decision_subject),
        ("expires_at", &approval.expires_at),
    ] {
        require_non_empty(value, field)?;
    }
    if approval.passport_id != passport.id {
        return Err(claim_failed("approval case passport mismatch"));
    }
    if approval.risk_comptroller_report_ref != risk_report.id {
        return Err(claim_failed("approval case risk report mismatch"));
    }
    validate_sha256_hex(&approval.evidence_export_bundle_digest)
        .map_err(|_| claim_failed("approval case export bundle digest mismatch"))?;
    if approval.evidence_export_bundle_digest != export_bundle.bundle_digest {
        return Err(claim_failed("approval case export bundle digest mismatch"));
    }
    if approval.decision != "approved" || approval.decision_subject != "evidence-export" {
        return Err(claim_failed("evidence export approval denied"));
    }
    let mut unique_approvers = BTreeSet::new();
    for approver in &approval.approvers {
        let approver = approver.trim();
        if approver.is_empty() {
            return Err(claim_failed("approval approver identity missing"));
        }
        unique_approvers.insert(approver);
    }
    if approval.required_quorum == 0
        || unique_approvers.len()
            < usize::try_from(approval.required_quorum)
                .map_err(|_| claim_failed("approval quorum overflow"))?
    {
        return Err(claim_failed("approval quorum not satisfied"));
    }
    let issued_at = parse_rfc3339_utc(&approval.issued_at, "approval issued_at")?;
    let expires_at = parse_rfc3339_utc(&approval.expires_at, "approval expires_at")?;
    if expires_at <= issued_at {
        return Err(claim_failed("approval case expired before issuance"));
    }
    verify_approval_signature(approval, trusted_approval_signer_keys)?;
    Ok(())
}

fn verify_approval_signature(
    approval: &ApprovalCase,
    trusted_approval_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    let Some(signature_ref) = approval.signature.strip_prefix("sig-ed25519:") else {
        return Err(claim_failed("approval signature unsupported"));
    };
    let Some((public_key_hex, signature_hex)) = signature_ref.split_once(':') else {
        return Err(claim_failed("approval signature malformed"));
    };
    require_non_empty(public_key_hex, "approval signature public key")?;
    require_non_empty(signature_hex, "approval signature")?;
    let public_key = PublicKey::from_hex(public_key_hex)
        .map_err(|_| claim_failed("approval signature public key invalid"))?;
    if !trusted_approval_signer_keys.contains(&public_key) {
        return Err(claim_failed("approval signer untrusted"));
    }
    let signature = Signature::from_hex(signature_hex)
        .map_err(|_| claim_failed("approval signature invalid"))?;
    let verified = public_key
        .verify_canonical(&approval_signature_body(approval), &signature)
        .map_err(|_| claim_failed("approval signature invalid"))?;
    if verified {
        Ok(())
    } else {
        Err(claim_failed("approval signature invalid"))
    }
}

#[derive(Serialize)]
struct ApprovalCaseSignatureBody<'a> {
    schema: &'a str,
    id: &'a str,
    issued_at: &'a str,
    passport_id: &'a str,
    risk_comptroller_report_ref: &'a str,
    evidence_export_bundle_digest: &'a str,
    decision: &'a str,
    decision_subject: &'a str,
    approvers: &'a [String],
    required_quorum: u64,
    expires_at: &'a str,
}

fn approval_signature_body(approval: &ApprovalCase) -> ApprovalCaseSignatureBody<'_> {
    ApprovalCaseSignatureBody {
        schema: &approval.schema,
        id: &approval.id,
        issued_at: &approval.issued_at,
        passport_id: &approval.passport_id,
        risk_comptroller_report_ref: &approval.risk_comptroller_report_ref,
        evidence_export_bundle_digest: &approval.evidence_export_bundle_digest,
        decision: &approval.decision,
        decision_subject: &approval.decision_subject,
        approvers: &approval.approvers,
        required_quorum: approval.required_quorum,
        expires_at: &approval.expires_at,
    }
}

pub(super) fn validate_control_map(
    bundle: &EnterpriseExportBundle,
    graph: &EnterpriseEvidenceGraph,
    passport: &TransactionPassport,
    risk_report: &RiskComptrollerReport,
    control_map: &ControlEvidenceMap,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &control_map.schema),
        ("id", &control_map.id),
        ("issued_at", &control_map.issued_at),
        ("passport_id", &control_map.passport_id),
        (
            "risk_comptroller_report_ref",
            &control_map.risk_comptroller_report_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if control_map.passport_id != passport.id {
        return Err(claim_failed("control map passport mismatch"));
    }
    if control_map.risk_comptroller_report_ref != risk_report.id {
        return Err(claim_failed("control map risk report mismatch"));
    }
    if control_map.controls.is_empty() {
        return Err(claim_failed("control map must include controls"));
    }
    for control in &control_map.controls {
        require_non_empty(&control.control_id, "control_id")?;
        require_non_empty(&control.control_family, "control_family")?;
        require_non_empty(&control.claim_ref, "claim_ref")?;
        require_non_empty(&control.gate_ref, "gate_ref")?;
        if !is_enterprise_claim(&control.claim_ref) {
            return Err(claim_failed(format!(
                "control map cites unsupported claim: {}",
                control.claim_ref
            )));
        }
        let Some(gate_node) = graph
            .nodes
            .iter()
            .find(|node| graph_node_ref_matches(bundle, node, &control.gate_ref))
        else {
            return Err(claim_failed("control gate did not run"));
        };
        if !graph_node_artifact_matches(bundle, gate_node) {
            return Err(claim_failed("control gate did not run"));
        }
        if !node_schema_proves_claim(&gate_node.schema, &control.claim_ref) {
            return Err(claim_failed("control gate does not prove cited claim"));
        }
    }
    Ok(())
}

fn validate_retention_class(retention_class: &str) -> Result<(), TransactionPassportError> {
    let Some(days_text) = retention_class
        .strip_prefix("audit-")
        .and_then(|value| value.strip_suffix('d'))
    else {
        return Err(claim_failed("data governance retention class unsupported"));
    };
    if days_text.is_empty() {
        return Err(claim_failed("data governance retention class unsupported"));
    }
    let days = days_text
        .parse::<u64>()
        .map_err(|_| claim_failed("data governance retention class unsupported"))?;
    if days < MIN_ENTERPRISE_AUDIT_RETENTION_DAYS {
        return Err(claim_failed(
            "data governance retention shorter than policy",
        ));
    }
    Ok(())
}

fn validate_field_classification(
    field: &FieldClassification,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&field.field, "field")?;
    require_non_empty(&field.classification, "classification")?;
    require_non_empty(&field.export_action, "export_action")?;
    if field.classification == "pii" && field.export_action != "redacted" {
        return Err(claim_failed("PII field was not redacted"));
    }
    Ok(())
}

fn validate_export_artifact_ref(
    bundle: &EnterpriseExportBundle,
    artifact: &ExportArtifactRef,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&artifact.role, "artifact role")?;
    require_non_empty(&artifact.path, "artifact path")?;
    validate_bundle_relative_path(&artifact.path).map_err(|_| {
        TransactionPassportError::InvalidEnterpriseArtifact {
            path: artifact.path.clone(),
            message: "unsafe artifact path".to_string(),
        }
    })?;
    validate_sha256_hex(&artifact.sha256).map_err(|_| {
        TransactionPassportError::InvalidEnterpriseArtifact {
            path: artifact.path.clone(),
            message: "invalid artifact digest".to_string(),
        }
    })?;
    let bytes = bundle.artifacts.get(&artifact.path).ok_or_else(|| {
        TransactionPassportError::MissingEnterpriseArtifact(artifact.path.clone())
    })?;
    let actual_digest = chio_core_types::sha256_hex(bytes);
    if actual_digest != artifact.sha256 {
        return Err(TransactionPassportError::InvalidEnterpriseArtifact {
            path: artifact.path.clone(),
            message: format!(
                "digest mismatch: expected {}, got {actual_digest}",
                artifact.sha256
            ),
        });
    }
    Ok(())
}

fn ensure_export_role_points_to(
    bundle: &EnterpriseExportBundle,
    artifacts: &[ExportArtifactRef],
    role: &str,
    expected_id: &str,
) -> Result<(), TransactionPassportError> {
    ensure_export_role_field_points_to(bundle, artifacts, role, "id", expected_id, "id")
}

fn ensure_export_role_field_points_to(
    bundle: &EnterpriseExportBundle,
    artifacts: &[ExportArtifactRef],
    role: &str,
    field: &str,
    expected_value: &str,
    mismatch_label: &str,
) -> Result<(), TransactionPassportError> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.role == role)
        .ok_or_else(|| claim_failed(format!("missing export artifact role: {role}")))?;
    require_non_empty(&artifact.path, "artifact path")?;
    let bytes = bundle.artifacts.get(&artifact.path).ok_or_else(|| {
        TransactionPassportError::MissingEnterpriseArtifact(artifact.path.clone())
    })?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidEnterpriseArtifact {
            path: artifact.path.clone(),
            message: error.to_string(),
        }
    })?;
    let actual_value = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidEnterpriseArtifact {
            path: artifact.path.clone(),
            message: format!("missing {field}"),
        })?;
    if actual_value != expected_value {
        return Err(claim_failed(format!(
            "export artifact {mismatch_label} mismatch for role: {role}"
        )));
    }
    Ok(())
}

fn is_enterprise_claim(claim: &str) -> bool {
    matches!(
        claim,
        "claim.enterprise.data_governance_bound"
            | "claim.enterprise.evidence_export_digest_bound"
            | "claim.enterprise.telemetry_projection_bound"
            | "claim.enterprise.export_approval_bound"
            | "claim.enterprise.control_map_bound"
    )
}

fn node_schema_proves_claim(schema: &str, claim_ref: &str) -> bool {
    matches!(
        (claim_ref, schema),
        (
            "claim.enterprise.data_governance_bound",
            ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA
        ) | (
            "claim.enterprise.evidence_export_digest_bound",
            ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
        ) | (
            "claim.enterprise.telemetry_projection_bound",
            ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA
        ) | (
            "claim.enterprise.export_approval_bound",
            ENTERPRISE_APPROVAL_CASE_SCHEMA
        ) | (
            "claim.enterprise.control_map_bound",
            ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA
        )
    )
}

fn graph_contains_risk_evidence_kind(
    bundle: &EnterpriseExportBundle,
    graph: &EnterpriseEvidenceGraph,
    evidence_ref: &str,
    kind: RiskEvidenceRefKind,
) -> bool {
    graph.nodes.iter().any(|node| {
        graph_node_ref_matches(bundle, node, evidence_ref)
            && risk_evidence_schema_matches_kind(&node.schema, kind)
            && graph_node_artifact_matches(bundle, node)
    })
}

fn graph_node_ref_matches(
    bundle: &EnterpriseExportBundle,
    node: &super::evidence::EnterpriseEvidenceNode,
    evidence_ref: &str,
) -> bool {
    node.id == evidence_ref
        || node.sha256 == evidence_ref
        || node.path == evidence_ref
        || Path::new(&node.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            == Some(evidence_ref)
        || graph_node_artifact_id_matches(bundle, node, evidence_ref)
}

fn graph_node_artifact_id_matches(
    bundle: &EnterpriseExportBundle,
    node: &super::evidence::EnterpriseEvidenceNode,
    evidence_ref: &str,
) -> bool {
    let Some(bytes) = bundle.artifacts.get(&node.path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id == evidence_ref)
}

fn graph_node_artifact_matches(
    bundle: &EnterpriseExportBundle,
    node: &super::evidence::EnterpriseEvidenceNode,
) -> bool {
    let Some(bytes) = bundle.artifacts.get(&node.path) else {
        return false;
    };
    if chio_core_types::sha256_hex(bytes) != node.sha256 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    value.get("schema").and_then(serde_json::Value::as_str) == Some(node.schema.as_str())
}

fn risk_evidence_schema_matches_kind(schema: &str, kind: RiskEvidenceRefKind) -> bool {
    match kind {
        RiskEvidenceRefKind::AuthorityReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::SupportingEvidence => matches!(
            schema,
            ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA
                | ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA
                | ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA
                | COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA
        ),
        RiskEvidenceRefKind::ReserveLedgerReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Settlement => matches!(
            schema,
            ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA
                | WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Jurisdiction => matches!(
            schema,
            RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA
                | ENTERPRISE_APPROVAL_CASE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
    }
}

fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| claim_failed(format!("invalid {field}: {error}")))
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::EnterpriseExportClaimFailed(message.into())
}
