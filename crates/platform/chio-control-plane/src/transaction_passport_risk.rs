use std::collections::BTreeMap;

use chio_core::{sha256_hex, PublicKey};
use chio_risk_comptroller::RiskComptrollerReport;
use chio_transaction_passport::{
    verify_passport_root_and_claim_set_artifacts_with_external_claims, TransactionPassport,
    TransactionPassportError, TransactionVerifierReport,
};
use serde::Deserialize;

const RISK_COMPTROLLER_REPORT_SCHEMA: &str = "chio.risk.comptroller-report.v1";
const RISK_COMPTROLLER_REPORT_ROLE: &str = "risk-comptroller-report";

#[derive(Debug, Clone)]
pub struct TransactionPassportRiskVerificationBundle {
    pub passport: TransactionPassport,
    pub passport_path: String,
    pub evidence_graph_bytes: Vec<u8>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub trusted_risk_comptroller_signer_keys: Vec<PublicKey>,
}

pub fn verify_passport_root_claim_set_and_risk_report(
    bundle: &TransactionPassportRiskVerificationBundle,
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    let risk_report = graph_bound_signed_risk_report(bundle)?;
    verify_passport_root_and_claim_set_artifacts_with_external_claims(
        &bundle.passport,
        bundle.passport_path.clone(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trusted_passport_signer_keys,
        risk_report.verified_claims(),
    )
}

#[derive(Deserialize)]
struct EvidenceGraph {
    nodes: Vec<EvidenceGraphNode>,
}

#[derive(Deserialize)]
struct EvidenceGraphNode {
    role: String,
    schema: String,
    path: String,
    sha256: String,
}

fn graph_bound_signed_risk_report(
    bundle: &TransactionPassportRiskVerificationBundle,
) -> Result<RiskComptrollerReport, TransactionPassportError> {
    let graph: EvidenceGraph = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .map_err(|error| invalid_graph(format!("invalid evidence graph: {error}")))?;
    let mut risk_nodes = graph
        .nodes
        .iter()
        .filter(|node| node.role == RISK_COMPTROLLER_REPORT_ROLE);
    let node = risk_nodes
        .next()
        .ok_or_else(|| risk_failed("missing risk comptroller report"))?;
    if risk_nodes.next().is_some() {
        return Err(risk_failed("multiple risk comptroller reports"));
    }
    if node.schema != RISK_COMPTROLLER_REPORT_SCHEMA {
        return Err(risk_failed(format!(
            "unsupported risk comptroller report schema: {}",
            node.schema
        )));
    }
    let bytes = bundle
        .artifacts
        .get(&node.path)
        .ok_or_else(|| TransactionPassportError::MissingEvidenceGraphArtifact(node.path.clone()))?;
    let actual_digest = sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(
            TransactionPassportError::EvidenceGraphArtifactDigestMismatch {
                path: node.path.clone(),
                expected: node.sha256.clone(),
                actual: actual_digest,
            },
        );
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| risk_failed(error.to_string()))?;
    chio_risk_comptroller::validate_signed_risk_report(
        &bundle.passport,
        &value,
        &bundle.trusted_risk_comptroller_signer_keys,
    )
}

fn invalid_graph(message: String) -> TransactionPassportError {
    TransactionPassportError::InvalidEvidenceGraphArtifact(message)
}

fn risk_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::RiskComptrollerClaimFailed(message.into())
}
