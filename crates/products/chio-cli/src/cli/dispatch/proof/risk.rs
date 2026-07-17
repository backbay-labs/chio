use super::*;
use chrono::{DateTime, Utc};
use std::{collections::BTreeSet, fs, path::Path};

const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";
const RISK_COMPTROLLER_REPORT_SCHEMA: &str = "chio.risk.comptroller-report.v1";
const ENTERPRISE_APPROVAL_CASE_SCHEMA: &str = "chio.enterprise.approval-case.v1";
const ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA: &str = "chio.enterprise.control-evidence-map.v1";
const ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA: &str = "chio.enterprise.data-governance-report.v1";
const ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA: &str = "chio.enterprise.evidence-export-bundle.v1";
const ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA: &str = "chio.enterprise.telemetry-projection.v1";
const RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
const RISK_GUARANTEE_DECISION_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
const COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v2";
const WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";

pub(super) struct RiskRoute {
    pub(super) through_enterprise: bool,
    pub(super) through_trust_market: bool,
    pub(super) standalone: bool,
}

pub(super) fn risk_route(
    evidence_graph_bytes: &[u8],
    requires_risk: bool,
) -> Result<RiskRoute, CliError> {
    let through_enterprise =
        requires_risk && evidence_graph_has_enterprise_risk_context(evidence_graph_bytes)?;
    let through_trust_market =
        requires_risk && evidence_graph_has_trust_market_risk_context(evidence_graph_bytes)?;
    Ok(RiskRoute {
        through_enterprise,
        through_trust_market,
        standalone: requires_risk && !through_enterprise && !through_trust_market,
    })
}

pub(super) fn verify_standalone_risk_claim(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    claim_requirements: &VerifierPolicyClaimRequirements,
    passport_report_path: &str,
) -> Result<serde_json::Value, CliError> {
    let trusted_risk_comptroller_signer_keys =
        enterprise_trusted_risk_comptroller_signer_keys_from_env()?;
    let risk_report = load_risk_comptroller_report_from_graph(
        bundle_dir,
        evidence_graph_bytes,
        &trusted_risk_comptroller_signer_keys,
    )?;
    chio_control_plane::risk_comptroller::validate_risk_report(passport, &risk_report)
        .map_err(map_proof_error)?;
    let risk_evidence_graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    chio_control_plane::risk_comptroller::validate_risk_evidence_refs(
        &risk_report,
        |evidence_ref, kind| {
            standalone_risk_evidence_ref_matches(
                &risk_evidence_graph.nodes,
                bundle_dir,
                evidence_ref,
                kind,
            )
        },
    )
    .map_err(map_proof_error)?;
    validate_standalone_risk_evidence_content(
        passport,
        &risk_report.id,
        bundle_dir,
        evidence_graph_bytes,
    )?;
    let verified_claims = vec![CLAIM_RISK_COMPTROLLER_REPORT_BOUND.to_string()];
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", passport.id),
        "issued_at": passport.issued_at.clone(),
        "verdict": "verified",
        "passport_id": passport.id.clone(),
        "passport_path": passport_report_path,
        "evidence_graph_sha256": passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": passport.evidence_graph_path.clone(),
        "verifier_policy_sha256": passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": passport.verifier_policy_path.clone(),
        "risk_comptroller_report_ref": risk_report.id,
        "order_id": risk_report.order_id,
        "subject": risk_report.subject,
        "verified_claims": verified_claims,
    });
    ensure_required_claims_verified(claim_requirements, &report, CLAIM_PREFIX_RISK, "risk")?;
    Ok(report)
}

#[derive(serde::Deserialize)]
struct StandaloneRiskApprovalCase {
    schema: String,
    id: String,
    issued_at: String,
    passport_id: String,
    risk_comptroller_report_ref: String,
    decision: String,
    decision_subject: String,
    approvers: Vec<String>,
    required_quorum: u64,
    expires_at: String,
}

fn validate_standalone_risk_evidence_content(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    risk_report_id: &str,
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<(), CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    for node in graph.nodes {
        if node.schema.as_deref() == Some(ENTERPRISE_APPROVAL_CASE_SCHEMA) {
            let approval: StandaloneRiskApprovalCase = load_graph_json_artifact(
                bundle_dir,
                &node,
                ENTERPRISE_APPROVAL_CASE_SCHEMA,
                "risk approval case",
            )?;
            validate_standalone_risk_approval_case(passport, risk_report_id, &approval)?;
        }
    }
    Ok(())
}

fn validate_standalone_risk_approval_case(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    risk_report_id: &str,
    approval: &StandaloneRiskApprovalCase,
) -> Result<(), CliError> {
    for (field, value) in [
        ("approval case schema", &approval.schema),
        ("approval case id", &approval.id),
        ("approval case issued_at", &approval.issued_at),
        ("approval case passport id", &approval.passport_id),
        (
            "approval case risk comptroller report ref",
            &approval.risk_comptroller_report_ref,
        ),
        ("approval case decision", &approval.decision),
        ("approval case decision subject", &approval.decision_subject),
        ("approval case expires_at", &approval.expires_at),
    ] {
        if value.is_empty() {
            return Err(CliError::cli_other_error(format!(
                "proof verify: risk {field} missing"
            )));
        }
    }
    if approval.passport_id != passport.id {
        return Err(CliError::cli_other_error(
            "proof verify: risk approval case passport mismatch",
        ));
    }
    if approval.risk_comptroller_report_ref != risk_report_id {
        return Err(CliError::cli_other_error(
            "proof verify: risk approval case report mismatch",
        ));
    }
    if approval.decision != "approved" || approval.decision_subject != "evidence-export" {
        return Err(CliError::cli_other_error(
            "proof verify: risk approval case denied",
        ));
    }
    let passport_issued_at =
        parse_risk_timestamp(&passport.issued_at, "risk transaction passport issued_at")?;
    let approval_issued_at =
        parse_risk_timestamp(&approval.issued_at, "risk approval case issued_at")?;
    let approval_expires_at =
        parse_risk_timestamp(&approval.expires_at, "risk approval case expires_at")?;
    if approval_issued_at >= approval_expires_at
        || passport_issued_at < approval_issued_at
        || passport_issued_at >= approval_expires_at
    {
        return Err(CliError::cli_other_error(
            "proof verify: risk approval case outside validity window",
        ));
    }
    let required_quorum = usize::try_from(approval.required_quorum)
        .map_err(|_| CliError::cli_other_error("proof verify: risk approval quorum overflow"))?;
    let mut unique_approvers = BTreeSet::new();
    for approver in &approval.approvers {
        let approver = approver.trim();
        if approver.is_empty() {
            return Err(CliError::cli_other_error(
                "proof verify: risk approval approver missing",
            ));
        }
        if !unique_approvers.insert(approver) {
            return Err(CliError::cli_other_error(
                "proof verify: risk approval approver duplicate",
            ));
        }
    }
    if required_quorum == 0 || unique_approvers.len() < required_quorum {
        return Err(CliError::cli_other_error(
            "proof verify: risk approval quorum not satisfied",
        ));
    }
    Ok(())
}

fn parse_risk_timestamp(value: &str, label: &str) -> Result<DateTime<Utc>, CliError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| CliError::cli_other_error(format!("proof verify: {label} invalid")))
}

#[derive(serde::Deserialize)]
struct EvidenceGraphRoleIndex {
    nodes: Vec<EvidenceGraphRoleNode>,
}

#[derive(serde::Deserialize)]
struct EvidenceGraphRoleNode {
    role: String,
}

fn risk_evidence_schema_matches_kind(
    schema: &str,
    kind: chio_control_plane::risk_comptroller::RiskEvidenceRefKind,
) -> bool {
    use chio_control_plane::risk_comptroller::RiskEvidenceRefKind;

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

fn standalone_risk_evidence_ref_matches(
    nodes: &[GraphArtifactNode],
    bundle_dir: &Path,
    evidence_ref: &str,
    kind: chio_control_plane::risk_comptroller::RiskEvidenceRefKind,
) -> bool {
    nodes.iter().any(|node| {
        if !standalone_risk_evidence_ref_matches_node(node, evidence_ref) {
            return false;
        }
        let Ok(schema) = graph_node_schema(node, "risk evidence") else {
            return false;
        };
        risk_evidence_schema_matches_kind(schema, kind)
            && load_graph_bytes_artifact(bundle_dir, node, schema, "risk evidence").is_ok()
    })
}

fn standalone_risk_evidence_ref_matches_node(node: &GraphArtifactNode, evidence_ref: &str) -> bool {
    node.id.as_deref() == Some(evidence_ref)
        || node.sha256.as_deref() == Some(evidence_ref)
        || node.path == evidence_ref
        || Path::new(&node.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            == Some(evidence_ref)
}

fn evidence_graph_has_enterprise_risk_context(
    evidence_graph_bytes: &[u8],
) -> Result<bool, CliError> {
    evidence_graph_has_any_role(evidence_graph_bytes, is_enterprise_risk_context_role)
}

fn evidence_graph_has_trust_market_risk_context(
    evidence_graph_bytes: &[u8],
) -> Result<bool, CliError> {
    evidence_graph_has_any_role(evidence_graph_bytes, is_trust_market_risk_context_role)
}

fn evidence_graph_has_any_role(
    evidence_graph_bytes: &[u8],
    predicate: fn(&str) -> bool,
) -> Result<bool, CliError> {
    let graph: EvidenceGraphRoleIndex = serde_json::from_slice(evidence_graph_bytes)?;
    Ok(graph.nodes.iter().any(|node| predicate(&node.role)))
}

fn is_enterprise_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "data-governance-report"
            | "evidence-export-bundle"
            | "telemetry-projection"
            | "approval-case"
            | "control-evidence-map"
    )
}

fn is_trust_market_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "provider-discovery-snapshot"
            | "provider-selection-report"
            | "trust-scorecard-snapshot"
            | "reputation-import-report"
            | "sla-commitment"
            | "sla-performance-report"
            | "collateral-position-report"
            | "guarantee-decision"
            | "adjudication-jurisdiction-receipt"
    )
}

fn load_risk_comptroller_report_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    trusted_authority_keys: &[chio_core_types::PublicKey],
) -> Result<chio_control_plane::risk_comptroller::RiskComptrollerReport, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let risk_report_nodes = graph_nodes_by_role(&graph.nodes, "risk-comptroller-report");

    let risk_report_node = match risk_report_nodes.as_slice() {
        [node] => *node,
        [] => {
            return Err(CliError::cli_other_error(
                "proof verify: missing risk comptroller report",
            ));
        }
        _ => {
            return Err(CliError::cli_other_error(
                "proof verify: multiple risk comptroller reports",
            ));
        }
    };

    let schema = graph_node_schema(risk_report_node, "risk comptroller report")?;
    if schema != RISK_COMPTROLLER_REPORT_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "proof verify: unsupported risk comptroller report schema: {schema}",
        )));
    }

    let artifact_path = resolve_bundle_artifact_path(bundle_dir, &risk_report_node.path)?;
    let bytes = fs::read(artifact_path)?;
    let actual_digest = chio_core::sha256_hex(&bytes);
    let expected_digest = graph_node_sha256(risk_report_node, "risk comptroller report")?;
    if actual_digest != expected_digest {
        return Err(CliError::cli_other_error(format!(
            "proof verify: risk comptroller report digest mismatch: expected {}, got {}",
            expected_digest, actual_digest,
        )));
    }

    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    chio_control_plane::risk_comptroller::validate_risk_report_signature(
        &value,
        trusted_authority_keys,
    )
    .map_err(map_proof_error)?;
    serde_json::from_value(value).map_err(CliError::from)
}
