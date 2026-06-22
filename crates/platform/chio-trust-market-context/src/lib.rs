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
    validate_collateral_guarantee, validate_discovery, validate_jurisdiction,
    validate_reputation_import, validate_risk_report, validate_scorecard, validate_selection,
    validate_sla, AdjudicationJurisdictionReceipt, CollateralPositionReport, GuaranteeDecision,
    ProviderDiscoverySnapshot, ProviderSelectionReport, ReputationImportReport,
    RiskComptrollerReport, SlaCommitment, SlaPerformanceReport, TrustScorecardSnapshot,
};
use claims::{
    blocked_market_claim, push_claim_once, CLAIM_COLLATERAL_GUARANTEE_BOUND, CLAIM_DISCOVERY_BOUND,
    CLAIM_JURISDICTION_BOUND, CLAIM_REPUTATION_IMPORT_BOUND, CLAIM_RISK_COMPTROLLER_REPORT_BOUND,
    CLAIM_SCORECARD_BOUND, CLAIM_SELECTION_BOUND, CLAIM_SLA_BOUND,
    CLAIM_UNSUPPORTED_MARKET_LIMITED,
};
use evidence::{
    bundle_contains_risk_evidence_kind, bundle_contains_verified_receipt_node_id, parse_graph,
    parse_signed_artifact, require_node, TrustMarketEvidenceRole,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct TrustMarketBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub root_evidence_graph_bytes: Option<Vec<u8>>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub trusted_market_authority_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustMarketVerifierReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub verified_claims: Vec<String>,
    pub unsupported_claims: Vec<String>,
    pub trust_market_sections: TrustMarketVerifierSections,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustMarketVerifierSections {
    pub provider_discovery_snapshot_ref: String,
    pub provider_selection_report_ref: String,
    pub trust_scorecard_ref: String,
    pub reputation_import_ref: String,
    pub sla_commitment_ref: String,
    #[serde(skip)]
    pub sla_remedy_ref: String,
    pub sla_performance_report_ref: String,
    pub risk_comptroller_report_ref: String,
    pub collateral_position_ref: String,
    pub guarantee_decision_ref: String,
    pub adjudication_jurisdiction_ref: String,
    #[serde(skip)]
    pub slash_authority_ref: String,
    pub selected_provider_subject: String,
}

pub fn verify_trust_market_context(
    bundle: &TrustMarketBundle,
) -> Result<TrustMarketVerifierReport, TransactionPassportError> {
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
    reject_required_unsupported_market_claims(&policy.required_claims)?;
    let trusted_market_authority_keys = trusted_market_authority_keys(&policy, bundle)?;

    let discovery: ProviderDiscoverySnapshot = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::ProviderDiscoverySnapshot)?,
        "chio.commerce.provider-discovery-snapshot.v1",
        &trusted_market_authority_keys,
    )?;
    let selection: ProviderSelectionReport = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::ProviderSelectionReport)?,
        "chio.commerce.provider-selection-report.v1",
        &trusted_market_authority_keys,
    )?;
    let scorecard: TrustScorecardSnapshot = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::TrustScorecardSnapshot)?,
        "chio.trust.scorecard-snapshot.v1",
        &trusted_market_authority_keys,
    )?;
    let reputation_import: ReputationImportReport = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::ReputationImportReport)?,
        "chio.trust.reputation-import-report.v1",
        &trusted_market_authority_keys,
    )?;
    let sla: SlaCommitment = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::SlaCommitment)?,
        "chio.commerce.sla-commitment.v1",
        &trusted_market_authority_keys,
    )?;
    let sla_performance: SlaPerformanceReport = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::SlaPerformanceReport)?,
        "chio.commerce.sla-performance-report.v1",
        &trusted_market_authority_keys,
    )?;
    let risk_report: RiskComptrollerReport = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::RiskComptrollerReport)?,
        "chio.risk.comptroller-report.v1",
        &trusted_market_authority_keys,
    )?;
    let collateral: CollateralPositionReport = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::CollateralPositionReport)?,
        "chio.risk.collateral-position-report.v1",
        &trusted_market_authority_keys,
    )?;
    let guarantee: GuaranteeDecision = parse_signed_artifact(
        bundle,
        require_node(&graph, TrustMarketEvidenceRole::GuaranteeDecision)?,
        "chio.risk.guarantee-decision.v1",
        &trusted_market_authority_keys,
    )?;
    let jurisdiction: AdjudicationJurisdictionReceipt = parse_signed_artifact(
        bundle,
        require_node(
            &graph,
            TrustMarketEvidenceRole::AdjudicationJurisdictionReceipt,
        )?,
        "chio.risk.adjudication-jurisdiction-receipt.v1",
        &trusted_market_authority_keys,
    )?;

    let mut verified_claims = Vec::new();
    validate_discovery(&bundle.passport, &discovery)?;
    push_claim_once(&mut verified_claims, CLAIM_DISCOVERY_BOUND);

    validate_reputation_import(
        &reputation_import,
        &scorecard,
        policy.max_reputation_import_weight,
    )?;
    push_claim_once(&mut verified_claims, CLAIM_REPUTATION_IMPORT_BOUND);

    validate_scorecard(&scorecard, &reputation_import)?;
    push_claim_once(&mut verified_claims, CLAIM_SCORECARD_BOUND);

    validate_selection(
        &bundle.passport,
        &discovery,
        &selection,
        &scorecard,
        &sla,
        |receipt_ref| {
            bundle_contains_verified_receipt_node_id(
                bundle,
                &graph,
                receipt_ref,
                &trusted_market_authority_keys,
            )
        },
    )?;
    validate_risk_report(
        &bundle.passport,
        &selection,
        &risk_report,
        |evidence_ref, kind| {
            bundle_contains_risk_evidence_kind(
                bundle,
                &graph,
                evidence_ref,
                kind,
                &trusted_market_authority_keys,
            )
        },
    )?;
    push_claim_once(&mut verified_claims, CLAIM_RISK_COMPTROLLER_REPORT_BOUND);
    push_claim_once(&mut verified_claims, CLAIM_SELECTION_BOUND);

    validate_sla(&selection, &sla, &sla_performance, &collateral, &guarantee)?;
    push_claim_once(&mut verified_claims, CLAIM_SLA_BOUND);

    validate_jurisdiction(&selection, &jurisdiction, &guarantee)?;
    push_claim_once(&mut verified_claims, CLAIM_JURISDICTION_BOUND);

    validate_collateral_guarantee(&selection, &sla, &collateral, &guarantee, &jurisdiction)?;
    push_claim_once(&mut verified_claims, CLAIM_COLLATERAL_GUARANTEE_BOUND);

    validate_unsupported_claims(&policy.unsupported_claims)?;
    push_claim_once(&mut verified_claims, CLAIM_UNSUPPORTED_MARKET_LIMITED);

    ensure_required_claims_verified(&policy.required_claims, &verified_claims)?;

    Ok(TrustMarketVerifierReport {
        schema: TRANSACTION_VERIFIER_REPORT_SCHEMA_ID.to_string(),
        id: format!("trust-market-verifier-report-{}", bundle.passport.id),
        issued_at: bundle.passport.issued_at.clone(),
        verdict: "verified".to_string(),
        passport_id: bundle.passport.id.clone(),
        verified_claims,
        unsupported_claims: policy.unsupported_claims,
        trust_market_sections: TrustMarketVerifierSections {
            provider_discovery_snapshot_ref: discovery.id,
            provider_selection_report_ref: selection.id,
            trust_scorecard_ref: scorecard.id,
            reputation_import_ref: reputation_import.id,
            sla_commitment_ref: sla.id,
            sla_remedy_ref: sla.remedy_policy_ref,
            sla_performance_report_ref: sla_performance.id,
            risk_comptroller_report_ref: risk_report.id,
            collateral_position_ref: collateral.collateral_id,
            guarantee_decision_ref: guarantee.guarantee_id,
            adjudication_jurisdiction_ref: jurisdiction.jurisdiction_id,
            slash_authority_ref: collateral.slash_authority_ref,
            selected_provider_subject: selection.selected_provider_subject,
        },
    })
}

fn trusted_market_authority_keys(
    policy: &policy::TrustMarketVerifierPolicy,
    bundle: &TrustMarketBundle,
) -> Result<Vec<PublicKey>, TransactionPassportError> {
    if bundle.trusted_market_authority_keys.is_empty() {
        return Err(claim_failed("trusted market authority keys missing"));
    }
    let trusted = bundle
        .trusted_market_authority_keys
        .iter()
        .filter(|key| {
            policy
                .trusted_market_authority_keys
                .iter()
                .any(|policy_key| policy_key == *key)
        })
        .cloned()
        .collect::<Vec<_>>();
    if trusted.is_empty() {
        return Err(claim_failed(
            "trusted market authority keys do not match verifier policy",
        ));
    }
    Ok(trusted)
}

fn reject_required_unsupported_market_claims(
    required_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for claim in required_claims {
        if blocked_market_claim(claim) {
            return Err(claim_failed(format!(
                "unsupported market claim cannot be required: {claim}"
            )));
        }
    }
    Ok(())
}

fn validate_unsupported_claims(
    unsupported_claims: &[String],
) -> Result<(), TransactionPassportError> {
    if unsupported_claims.is_empty() {
        return Err(claim_failed("unsupported market claims missing"));
    }
    for claim in unsupported_claims {
        if !blocked_market_claim(claim) {
            return Err(claim_failed(format!(
                "unknown unsupported market claim: {claim}"
            )));
        }
    }
    Ok(())
}

fn ensure_required_claims_verified(
    required_claims: &[String],
    verified_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for required_claim in required_claims {
        if !trust_market_policy_claim(required_claim) {
            continue;
        }
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(claim_failed(format!(
                "required claim not verified: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn trust_market_policy_claim(required_claim: &str) -> bool {
    required_claim.starts_with("claim.trust_market.")
        || required_claim == CLAIM_RISK_COMPTROLLER_REPORT_BOUND
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::TrustMarketClaimFailed(message.into())
}
