use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use chio_core_types::PublicKey;
use chio_transaction_passport::{
    verify_minimal_passport_artifacts, verify_transaction_passport_signature_with_evidence_graph,
    TransactionPassport, TransactionPassportError, TRANSACTION_VERIFIER_REPORT_SCHEMA_ID,
};

mod artifacts;
mod claims;
mod evidence;
mod policy;

use artifacts::{
    select_referenced_risk_report, validate_approval_case, validate_control_map,
    validate_data_governance, validate_evidence_export_bundle, validate_risk_portfolio_reports,
    validate_risk_report, validate_telemetry_projection, ApprovalCase, ControlEvidenceMap,
    DataGovernanceReport, EvidenceExportBundleArtifact, RiskComptrollerReport, TelemetryProjection,
};
use claims::{
    push_claim_once, CLAIM_CONTROL_MAP_BOUND, CLAIM_DATA_GOVERNANCE_BOUND,
    CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND, CLAIM_EXPORT_APPROVAL_BOUND,
    CLAIM_RISK_COMPTROLLER_REPORT_BOUND, CLAIM_TELEMETRY_PROJECTION_BOUND,
};
use evidence::{
    find_node, find_nodes, parse_artifact, parse_graph, parse_signed_risk_comptroller_report,
    require_node, EnterpriseEvidenceRole,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct EnterpriseExportBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub root_evidence_graph_bytes: Option<Vec<u8>>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub trusted_receipt_kernel_keys: Vec<PublicKey>,
    pub trusted_approval_signer_keys: Vec<PublicKey>,
    pub trusted_risk_comptroller_signer_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseVerifierReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub risk_comptroller_report_ref: String,
    pub verified_claims: Vec<String>,
    pub enterprise_sections: EnterpriseVerifierSections,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseVerifierSections {
    pub data_governance_report_ref: String,
    pub evidence_export_bundle_ref: String,
    pub telemetry_projection_ref: String,
    pub approval_case_ref: String,
    pub control_evidence_map_ref: String,
}

pub fn verify_enterprise_export(
    bundle: &EnterpriseExportBundle,
) -> Result<EnterpriseVerifierReport, TransactionPassportError> {
    let signed_evidence_graph_bytes = bundle
        .root_evidence_graph_bytes
        .as_deref()
        .unwrap_or(&bundle.evidence_graph_bytes);
    verify_transaction_passport_signature_with_evidence_graph(
        &bundle.passport,
        signed_evidence_graph_bytes,
        &bundle.evidence_graph_bytes,
        &bundle.trusted_passport_signer_keys,
    )?;
    verify_minimal_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
    )?;

    let graph = parse_graph(&bundle.evidence_graph_bytes)?;
    let policy = parse_policy(&bundle.verifier_policy_bytes)?;

    let risk_reports = find_nodes(&graph, EnterpriseEvidenceRole::RiskComptrollerReport)
        .map(|node| {
            parse_signed_risk_comptroller_report(
                bundle,
                node,
                &bundle.trusted_risk_comptroller_signer_keys,
            )
        })
        .collect::<Result<Vec<RiskComptrollerReport>, TransactionPassportError>>()?;
    let data_governance_node = require_node(&graph, EnterpriseEvidenceRole::DataGovernanceReport)?;
    let export_bundle_node = require_node(&graph, EnterpriseEvidenceRole::EvidenceExportBundle)?;
    let telemetry_node = require_node(&graph, EnterpriseEvidenceRole::TelemetryProjection)?;
    let approval_node = find_node(&graph, EnterpriseEvidenceRole::ApprovalCase)
        .ok_or_else(|| enterprise_claim_failed("missing approval case"))?;
    let control_map_node = require_node(&graph, EnterpriseEvidenceRole::ControlEvidenceMap)?;

    let data_governance: DataGovernanceReport = parse_artifact(
        bundle,
        data_governance_node,
        "chio.enterprise.data-governance-report.v1",
    )?;
    let export_bundle: EvidenceExportBundleArtifact = parse_artifact(
        bundle,
        export_bundle_node,
        "chio.enterprise.evidence-export-bundle.v1",
    )?;
    let telemetry: TelemetryProjection = parse_artifact(
        bundle,
        telemetry_node,
        "chio.enterprise.telemetry-projection.v1",
    )?;
    let approval: ApprovalCase =
        parse_artifact(bundle, approval_node, "chio.enterprise.approval-case.v1")?;
    let control_map: ControlEvidenceMap = parse_artifact(
        bundle,
        control_map_node,
        "chio.enterprise.control-evidence-map.v1",
    )?;
    let risk_report = select_referenced_risk_report(
        &risk_reports,
        &data_governance,
        &export_bundle,
        &telemetry,
        &approval,
        &control_map,
    )?;

    let mut verified_claims = Vec::new();
    for risk_report in &risk_reports {
        validate_risk_report(&bundle.passport, risk_report, bundle, &graph)?;
    }
    validate_risk_portfolio_reports(&risk_reports)?;
    push_claim_once(&mut verified_claims, CLAIM_RISK_COMPTROLLER_REPORT_BOUND);
    validate_data_governance(&bundle.passport, risk_report, &data_governance)?;
    push_claim_once(&mut verified_claims, CLAIM_DATA_GOVERNANCE_BOUND);

    validate_evidence_export_bundle(
        bundle,
        &bundle.passport,
        risk_report,
        &data_governance,
        &approval,
        &export_bundle,
    )?;
    push_claim_once(&mut verified_claims, CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND);

    validate_telemetry_projection(
        bundle,
        &bundle.passport,
        risk_report,
        &telemetry,
        &bundle.trusted_receipt_kernel_keys,
    )?;
    push_claim_once(&mut verified_claims, CLAIM_TELEMETRY_PROJECTION_BOUND);

    validate_approval_case(
        &bundle.passport,
        risk_report,
        &export_bundle,
        &approval,
        &bundle.trusted_approval_signer_keys,
    )?;
    push_claim_once(&mut verified_claims, CLAIM_EXPORT_APPROVAL_BOUND);

    validate_control_map(bundle, &graph, &bundle.passport, risk_report, &control_map)?;
    push_claim_once(&mut verified_claims, CLAIM_CONTROL_MAP_BOUND);

    ensure_required_claims_verified(&policy.required_claims, &verified_claims)?;

    Ok(EnterpriseVerifierReport {
        schema: TRANSACTION_VERIFIER_REPORT_SCHEMA_ID.to_string(),
        id: format!("enterprise-verifier-report-{}", bundle.passport.id),
        issued_at: bundle.passport.issued_at.clone(),
        verdict: "verified".to_string(),
        passport_id: bundle.passport.id.clone(),
        risk_comptroller_report_ref: risk_report.id.clone(),
        verified_claims,
        enterprise_sections: EnterpriseVerifierSections {
            data_governance_report_ref: data_governance.id,
            evidence_export_bundle_ref: export_bundle.id,
            telemetry_projection_ref: telemetry.id,
            approval_case_ref: approval.id,
            control_evidence_map_ref: control_map.id,
        },
    })
}

fn enterprise_policy_claim(required_claim: &str) -> bool {
    required_claim.starts_with("claim.enterprise.")
        || required_claim == CLAIM_RISK_COMPTROLLER_REPORT_BOUND
}

fn ensure_required_claims_verified(
    required_claims: &[String],
    verified_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for required_claim in required_claims {
        if !enterprise_policy_claim(required_claim) {
            continue;
        }
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(enterprise_claim_failed(format!(
                "required claim not verified: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn enterprise_claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::EnterpriseExportClaimFailed(message.into())
}
