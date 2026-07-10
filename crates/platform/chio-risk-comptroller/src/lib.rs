use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::Deserialize;

mod ledger;
use ledger::{
    is_terminal_reserve_consumption, validate_risk_reserve_ledger,
    validate_risk_sanction_reserve_ledger,
};

use chio_transaction_passport::{TransactionPassport, TransactionPassportError};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskComptrollerReport {
    schema: String,
    pub id: String,
    issued_at: String,
    passport_id: String,
    pub order_id: String,
    pub subject: String,
    verdict: String,
    risk_state: String,
    #[serde(default)]
    pub signature: String,
    facility: RiskFacilityState,
    #[serde(default)]
    facility_lifecycle: Vec<RiskFacilityTransition>,
    coverage: RiskCoverageBinding,
    reconciliation: RiskReconciliation,
    #[serde(default)]
    premium: Option<RiskPremiumBinding>,
    actuarial_evidence: RiskActuarialEvidence,
    insurance_copy: RiskInsuranceCopy,
    #[serde(default)]
    capital_decomposition: Option<RiskCapitalDecomposition>,
    #[serde(default)]
    capital_instructions: Vec<RiskCapitalInstruction>,
    #[serde(default)]
    reserve_ledger: Vec<RiskReserveLedgerEntry>,
    #[serde(default)]
    sanction_reserve_ledger: Vec<RiskSanctionReserveLedgerEntry>,
    #[serde(default)]
    appeals: Vec<RiskClaimAppeal>,
    verified_claims: Vec<String>,
}

impl RiskComptrollerReport {
    pub fn verified_claims(&self) -> &[String] {
        &self.verified_claims
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskEvidenceRefKind {
    AuthorityReceipt,
    SupportingEvidence,
    ReserveLedgerReceipt,
    Settlement,
    Jurisdiction,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskFacilityState {
    facility_id: String,
    policy_id: String,
    state: String,
    capital_currency: String,
    capital_units: u64,
    reserve_currency: String,
    reserve_units: u64,
    reserve_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskFacilityTransition {
    transition_id: String,
    policy_id: String,
    from_state: String,
    to_state: String,
    authority_receipt_ref: String,
    evidence_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskCoverageBinding {
    coverage_id: String,
    order_id: String,
    subject: String,
    #[serde(default)]
    beneficiary_subject: Option<String>,
    #[serde(default)]
    covered_claim_ids: Vec<String>,
    currency: String,
    exposure_units: u64,
    reserve_ref: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskReconciliation {
    order_id: String,
    currency: String,
    exposure_units: u64,
    reserve_units: u64,
    consumed_reserve_units: u64,
    payout_units: u64,
    settlement_units: u64,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskActuarialEvidence {
    model_ref: String,
    evidence_ref: String,
    currency: String,
    supported_exposure_units: u64,
    confidence_level_bps: u64,
    backtest: RiskActuarialBacktest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskActuarialBacktest {
    backtest_id: String,
    window_start: String,
    window_end: String,
    sample_size: u64,
    observed_loss_ratio_bps: u64,
    maximum_loss_ratio_bps: u64,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskInsuranceCopy {
    copy_id: String,
    actuarial_evidence_ref: String,
    currency: String,
    maximum_coverage_units: u64,
    coverage_statement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskPremiumBinding {
    premium_id: String,
    quote_ref: String,
    coverage_id: String,
    order_id: String,
    subject: String,
    currency: String,
    coverage_exposure_units: u64,
    quoted_premium_units: u64,
    bound_premium_units: u64,
    collected_premium_units: u64,
    #[serde(default)]
    observed_payment_ref: Option<String>,
    #[serde(default)]
    settlement_ref: Option<String>,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskCapitalDecomposition {
    decomposition_id: String,
    source_kind: String,
    source_ref: String,
    currency: String,
    committed_units: u64,
    held_units: u64,
    drawn_units: u64,
    disbursed_units: u64,
    impaired_units: u64,
    available_units: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskCapitalInstruction {
    instruction_id: String,
    reserve_entry_id: String,
    order_id: String,
    claim_id: String,
    reserve_ref: String,
    currency: String,
    units: u64,
    settlement_ref: String,
    intended_action: String,
    source_kind: String,
    intended_state: String,
    reconciled_state: String,
    #[serde(default)]
    observed_execution_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskReserveLedgerEntry {
    entry_id: String,
    receipt_ref: String,
    lane: String,
    reserve_ref: String,
    claim_id: String,
    currency: String,
    units: u64,
    settlement_ref: String,
    #[serde(default)]
    payer_subject: Option<String>,
    #[serde(default)]
    payee_subject: Option<String>,
    #[serde(default)]
    sanction_bridge: Option<RiskSanctionBridge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskSanctionBridge {
    bridge_id: String,
    authority_receipt_ref: String,
    evidence_ref: String,
    jurisdiction_ref: String,
    sanction_subject: String,
    maximum_slash_units: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskSanctionReserveLedgerEntry {
    entry_id: String,
    bridge_id: String,
    lane: String,
    receipt_ref: String,
    reserve_ref: String,
    claim_id: String,
    currency: String,
    units: u64,
    settlement_ref: String,
    authority_receipt_ref: String,
    evidence_ref: String,
    jurisdiction_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskClaimAppeal {
    appeal_id: String,
    claim_id: String,
    status: String,
    blocks: Vec<String>,
}

pub fn validate_risk_report(
    passport: &TransactionPassport,
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &report.schema),
        ("id", &report.id),
        ("issued_at", &report.issued_at),
        ("passport_id", &report.passport_id),
        ("order_id", &report.order_id),
        ("subject", &report.subject),
        ("verdict", &report.verdict),
        ("risk_state", &report.risk_state),
    ] {
        require_non_empty(value, field)?;
    }
    if report.schema != "chio.risk.comptroller-report.v1" {
        return Err(claim_failed("risk comptroller report schema mismatch"));
    }
    if report.passport_id != passport.id {
        return Err(claim_failed("risk comptroller report passport mismatch"));
    }
    if report.verdict != "verified" || report.risk_state != "reconciled" {
        return Err(claim_failed("risk comptroller report was not verified"));
    }
    if !report
        .verified_claims
        .iter()
        .any(|claim| claim == "claim.risk.comptroller_report_bound")
    {
        return Err(claim_failed("risk comptroller report claim missing"));
    }
    validate_risk_facility_state(&report.facility, &report.facility_lifecycle)?;
    validate_risk_coverage_binding(report, &report.coverage)?;
    validate_risk_reconciliation(report, &report.reconciliation)?;
    validate_risk_premium_binding(report)?;
    validate_risk_actuarial_limits(report, &report.actuarial_evidence, &report.insurance_copy)?;
    validate_risk_capital_decomposition(report)?;
    validate_risk_claim_appeals(report, &report.appeals)?;
    validate_risk_reserve_ledger(report, &report.reserve_ledger)?;
    validate_risk_sanction_reserve_ledger(
        report,
        &report.reserve_ledger,
        &report.sanction_reserve_ledger,
    )?;
    validate_risk_capital_instructions(report)?;
    validate_risk_coverage_claim_scope(report)?;
    validate_risk_facility_closure(report)?;
    Ok(())
}

pub fn validate_signed_risk_report(
    passport: &TransactionPassport,
    report_value: &serde_json::Value,
    trusted_authority_keys: &[PublicKey],
) -> Result<RiskComptrollerReport, TransactionPassportError> {
    validate_risk_report_signature(report_value, trusted_authority_keys)?;
    let report: RiskComptrollerReport = serde_json::from_value(report_value.clone())
        .map_err(|error| claim_failed(error.to_string()))?;
    validate_risk_report(passport, &report)?;
    Ok(report)
}

pub fn validate_risk_report_signature(
    report_value: &serde_json::Value,
    trusted_authority_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if trusted_authority_keys.is_empty() {
        return Err(claim_failed("risk comptroller trusted signer keys missing"));
    }
    let signature_value = report_value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed("risk comptroller report signature missing"))?;
    let Some(signature_ref) = signature_value.strip_prefix("sig-ed25519:") else {
        return Err(claim_failed(
            "risk comptroller report signature unsupported",
        ));
    };
    let Some((public_key_hex, signature_hex)) = signature_ref.split_once(':') else {
        return Err(claim_failed("risk comptroller report signature malformed"));
    };
    require_non_empty(public_key_hex, "risk_comptroller_signature_public_key")?;
    require_non_empty(signature_hex, "risk_comptroller_signature")?;
    let public_key = PublicKey::from_hex(public_key_hex)
        .map_err(|_| claim_failed("risk comptroller report signature public key invalid"))?;
    if !trusted_authority_keys.contains(&public_key) {
        return Err(claim_failed("risk comptroller report signer untrusted"));
    }
    let signature = Signature::from_hex(signature_hex)
        .map_err(|_| claim_failed("risk comptroller report signature invalid"))?;
    let mut signed_value = report_value.clone();
    signed_value
        .as_object_mut()
        .ok_or_else(|| claim_failed("risk comptroller report signature payload invalid"))?
        .remove("signature");
    let verified = public_key
        .verify_canonical(&signed_value, &signature)
        .map_err(|_| claim_failed("risk comptroller report signature invalid"))?;
    if verified {
        Ok(())
    } else {
        Err(claim_failed("risk comptroller report signature invalid"))
    }
}

pub fn validate_risk_portfolio_reports(
    reports: &[RiskComptrollerReport],
) -> Result<(), TransactionPassportError> {
    let mut portfolios: BTreeMap<(String, String), RiskPortfolioAccumulator> = BTreeMap::new();
    let mut reserves: BTreeMap<String, RiskPortfolioReserveAccumulator> = BTreeMap::new();
    let mut counted_portfolio_reserves = BTreeSet::<(String, String, String)>::new();
    let mut terminal_consumption_by_reserve_claim = BTreeSet::<(&str, &str)>::new();
    let mut reserve_receipt_refs = BTreeSet::<&str>::new();
    for report in reports {
        let key = (
            report.subject.clone(),
            report.facility.capital_currency.clone(),
        );
        let accumulator =
            portfolios
                .entry(key.clone())
                .or_insert_with(|| RiskPortfolioAccumulator {
                    capital_units: report.facility.capital_units,
                    obligation_units: 0,
                });
        if accumulator.capital_units != report.facility.capital_units {
            return Err(claim_failed("risk portfolio capital mismatch"));
        }
        accumulator.obligation_units = accumulator
            .obligation_units
            .checked_add(report.coverage.exposure_units)
            .ok_or_else(|| claim_failed("risk portfolio capital adequacy overflow"))?;
        if counted_portfolio_reserves.insert((key.0, key.1, report.facility.reserve_ref.clone())) {
            accumulator.obligation_units = accumulator
                .obligation_units
                .checked_add(report.facility.reserve_units)
                .ok_or_else(|| claim_failed("risk portfolio capital adequacy overflow"))?;
        }
        let reserve_accumulator = reserves
            .entry(report.facility.reserve_ref.clone())
            .or_insert_with(|| RiskPortfolioReserveAccumulator {
                facility_id: report.facility.facility_id.clone(),
                currency: report.facility.reserve_currency.clone(),
                reserve_units: report.facility.reserve_units,
                consumed_units: 0,
            });
        if reserve_accumulator.facility_id != report.facility.facility_id {
            return Err(claim_failed("risk portfolio reserve facility mismatch"));
        }
        if reserve_accumulator.currency != report.facility.reserve_currency
            || reserve_accumulator.reserve_units != report.facility.reserve_units
        {
            return Err(claim_failed("risk portfolio reserve mismatch"));
        }
        reserve_accumulator.consumed_units = reserve_accumulator
            .consumed_units
            .checked_add(report.reconciliation.consumed_reserve_units)
            .ok_or_else(|| claim_failed("risk portfolio reserve overflow"))?;
        for entry in &report.reserve_ledger {
            if !reserve_receipt_refs.insert(entry.receipt_ref.as_str()) {
                return Err(claim_failed(
                    "risk portfolio reserve ledger duplicate receipt",
                ));
            }
            if is_terminal_reserve_consumption(&entry.lane)
                && !terminal_consumption_by_reserve_claim
                    .insert((entry.reserve_ref.as_str(), entry.claim_id.as_str()))
            {
                return Err(claim_failed("risk portfolio reserve double consumption"));
            }
        }
    }
    for accumulator in portfolios.values() {
        if accumulator.obligation_units > accumulator.capital_units {
            return Err(claim_failed("risk portfolio capital adequacy breach"));
        }
    }
    for accumulator in reserves.values() {
        if accumulator.consumed_units > accumulator.reserve_units {
            return Err(claim_failed("risk portfolio reserve overconsumed"));
        }
    }
    Ok(())
}

struct RiskPortfolioAccumulator {
    capital_units: u64,
    obligation_units: u64,
}

struct RiskPortfolioReserveAccumulator {
    facility_id: String,
    currency: String,
    reserve_units: u64,
    consumed_units: u64,
}

pub fn validate_risk_evidence_refs(
    report: &RiskComptrollerReport,
    mut contains_ref: impl FnMut(&str, RiskEvidenceRefKind) -> bool,
) -> Result<(), TransactionPassportError> {
    for transition in &report.facility_lifecycle {
        if !contains_ref(
            &transition.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        ) {
            return Err(claim_failed("risk facility lifecycle authority missing"));
        }
        if !contains_ref(
            &transition.evidence_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        ) {
            return Err(claim_failed("risk facility lifecycle evidence missing"));
        }
    }
    if !contains_ref(
        &report.actuarial_evidence.evidence_ref,
        RiskEvidenceRefKind::SupportingEvidence,
    ) {
        return Err(claim_failed("risk actuarial evidence missing"));
    }
    let Some(premium) = report.premium.as_ref() else {
        return Err(claim_failed("risk premium binding missing"));
    };
    if !contains_ref(&premium.quote_ref, RiskEvidenceRefKind::SupportingEvidence) {
        return Err(claim_failed("risk premium quote evidence missing"));
    }
    if let Some(observed_payment_ref) = premium.observed_payment_ref.as_ref() {
        if !contains_ref(
            observed_payment_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        ) {
            return Err(claim_failed("risk premium payment evidence missing"));
        }
    }
    if let Some(settlement_ref) = premium.settlement_ref.as_ref() {
        if !contains_ref(settlement_ref, RiskEvidenceRefKind::Settlement) {
            return Err(claim_failed("risk premium settlement evidence missing"));
        }
    }
    let Some(capital) = report.capital_decomposition.as_ref() else {
        return Err(claim_failed("risk capital decomposition missing"));
    };
    if !contains_ref(&capital.source_ref, RiskEvidenceRefKind::AuthorityReceipt) {
        return Err(claim_failed("risk capital source evidence missing"));
    }
    for entry in &report.reserve_ledger {
        if !contains_ref(
            &entry.receipt_ref,
            RiskEvidenceRefKind::ReserveLedgerReceipt,
        ) {
            return Err(claim_failed("risk reserve ledger receipt missing"));
        }
        if !contains_ref(&entry.settlement_ref, RiskEvidenceRefKind::Settlement) {
            return Err(claim_failed("risk reserve ledger settlement missing"));
        }
        let Some(sanction_bridge) = entry.sanction_bridge.as_ref() else {
            continue;
        };
        if !contains_ref(
            &sanction_bridge.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        ) {
            return Err(claim_failed("risk market slash sanction authority missing"));
        }
        if !contains_ref(
            &sanction_bridge.evidence_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        ) {
            return Err(claim_failed("risk market slash sanction evidence missing"));
        }
        if !contains_ref(
            &sanction_bridge.jurisdiction_ref,
            RiskEvidenceRefKind::Jurisdiction,
        ) {
            return Err(claim_failed("risk market slash jurisdiction missing"));
        }
    }
    for entry in &report.sanction_reserve_ledger {
        if !contains_ref(
            &entry.receipt_ref,
            RiskEvidenceRefKind::ReserveLedgerReceipt,
        ) {
            return Err(claim_failed("risk sanction reserve ledger receipt missing"));
        }
        if !contains_ref(&entry.settlement_ref, RiskEvidenceRefKind::Settlement) {
            return Err(claim_failed(
                "risk sanction reserve ledger settlement missing",
            ));
        }
        if !contains_ref(
            &entry.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        ) {
            return Err(claim_failed(
                "risk sanction reserve ledger authority missing",
            ));
        }
        if !contains_ref(&entry.evidence_ref, RiskEvidenceRefKind::SupportingEvidence) {
            return Err(claim_failed(
                "risk sanction reserve ledger evidence missing",
            ));
        }
        if !contains_ref(&entry.jurisdiction_ref, RiskEvidenceRefKind::Jurisdiction) {
            return Err(claim_failed(
                "risk sanction reserve ledger jurisdiction missing",
            ));
        }
    }
    Ok(())
}

fn validate_risk_facility_state(
    facility: &RiskFacilityState,
    facility_lifecycle: &[RiskFacilityTransition],
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("facility_id", &facility.facility_id),
        ("facility_policy_id", &facility.policy_id),
        ("facility_state", &facility.state),
        ("capital_currency", &facility.capital_currency),
        ("reserve_currency", &facility.reserve_currency),
        ("reserve_ref", &facility.reserve_ref),
    ] {
        require_non_empty(value, field)?;
    }
    if !is_supported_risk_facility_state(&facility.state) {
        return Err(claim_failed("risk facility state unsupported"));
    }
    if facility.capital_units == 0 {
        return Err(claim_failed("risk capital state missing"));
    }
    if facility.reserve_units == 0 {
        return Err(claim_failed("risk reserve state missing"));
    }
    if facility.reserve_units > facility.capital_units {
        return Err(claim_failed("risk reserve exceeds capital"));
    }
    if facility.reserve_currency != facility.capital_currency {
        return Err(claim_failed("risk reserve currency mismatch"));
    }
    if risk_facility_lifecycle_requires_replay(&facility.state) && facility_lifecycle.is_empty() {
        return Err(claim_failed("risk facility lifecycle replay missing"));
    }
    validate_risk_facility_lifecycle(facility, facility_lifecycle)?;
    Ok(())
}

fn validate_risk_facility_lifecycle(
    facility: &RiskFacilityState,
    transitions: &[RiskFacilityTransition],
) -> Result<(), TransactionPassportError> {
    if transitions.is_empty() {
        return Ok(());
    }

    let mut transition_ids = BTreeSet::new();
    let mut transitions_by_from_state = BTreeMap::new();
    for (index, transition) in transitions.iter().enumerate() {
        validate_risk_facility_transition(transition)?;
        if transition.policy_id != facility.policy_id {
            return Err(claim_failed("risk facility lifecycle policy mismatch"));
        }
        if !transition_ids.insert(transition.transition_id.as_str()) {
            return Err(claim_failed("risk facility lifecycle duplicate transition"));
        }
        if transitions_by_from_state
            .insert(transition.from_state.as_str(), index)
            .is_some()
        {
            return Err(claim_failed("risk facility lifecycle replay gap"));
        }

        if !is_supported_risk_facility_state(&transition.from_state)
            || !is_supported_risk_facility_state(&transition.to_state)
        {
            return Err(claim_failed("risk facility lifecycle state unsupported"));
        }
        if !is_allowed_risk_facility_transition(&transition.from_state, &transition.to_state) {
            return Err(claim_failed("risk facility lifecycle replay gap"));
        }
    }

    let mut current_state = "evidence_cold";
    let mut used_transition_indexes = BTreeSet::new();
    while current_state != facility.state {
        let Some(index) = transitions_by_from_state.get(current_state).copied() else {
            if !used_transition_indexes.is_empty() {
                return Err(claim_failed("risk facility lifecycle final state mismatch"));
            }
            return Err(claim_failed("risk facility lifecycle replay gap"));
        };
        if !used_transition_indexes.insert(index) {
            return Err(claim_failed("risk facility lifecycle replay gap"));
        }
        current_state = transitions[index].to_state.as_str();
    }

    if used_transition_indexes.len() != transitions.len() {
        return Err(claim_failed("risk facility lifecycle replay gap"));
    }
    Ok(())
}

fn validate_risk_facility_transition(
    transition: &RiskFacilityTransition,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("facility_transition_id", &transition.transition_id),
        ("facility_transition_policy_id", &transition.policy_id),
        ("facility_transition_from_state", &transition.from_state),
        ("facility_transition_to_state", &transition.to_state),
        (
            "facility_transition_authority_receipt_ref",
            &transition.authority_receipt_ref,
        ),
        ("facility_transition_evidence_ref", &transition.evidence_ref),
    ] {
        require_non_empty(value, field)?;
    }
    Ok(())
}

fn is_supported_risk_facility_state(state: &str) -> bool {
    matches!(
        state,
        "evidence_cold"
            | "underwriting_ready"
            | "facility_granted"
            | "reserve_held"
            | "capital_allocatable"
            | "coverage_bound"
            | "claim_open"
            | "claim_decided"
            | "payout_matched"
            | "settlement_matched"
            | "reserve_controlled"
            | "closed"
    )
}

fn risk_facility_lifecycle_requires_replay(state: &str) -> bool {
    matches!(
        state,
        "coverage_bound"
            | "capital_allocatable"
            | "claim_open"
            | "claim_decided"
            | "payout_matched"
            | "settlement_matched"
            | "reserve_controlled"
            | "closed"
    )
}

fn is_allowed_risk_facility_transition(from_state: &str, to_state: &str) -> bool {
    matches!(
        (from_state, to_state),
        ("evidence_cold", "underwriting_ready")
            | ("underwriting_ready", "facility_granted")
            | ("facility_granted", "reserve_held")
            | ("reserve_held", "capital_allocatable")
            | ("reserve_held", "coverage_bound")
            | ("capital_allocatable", "coverage_bound")
            | ("coverage_bound", "claim_open")
            | ("coverage_bound", "settlement_matched")
            | ("claim_open", "claim_decided")
            | ("claim_decided", "payout_matched")
            | ("payout_matched", "settlement_matched")
            | ("settlement_matched", "reserve_controlled")
            | ("reserve_controlled", "closed")
    )
}

fn validate_risk_coverage_binding(
    report: &RiskComptrollerReport,
    coverage: &RiskCoverageBinding,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("coverage_id", &coverage.coverage_id),
        ("coverage_order_id", &coverage.order_id),
        ("coverage_subject", &coverage.subject),
        ("coverage_currency", &coverage.currency),
        ("coverage_reserve_ref", &coverage.reserve_ref),
        ("coverage_status", &coverage.status),
    ] {
        require_non_empty(value, field)?;
    }
    if coverage.order_id != report.order_id {
        return Err(claim_failed("risk coverage order mismatch"));
    }
    if coverage.subject != report.subject {
        return Err(claim_failed("risk coverage subject mismatch"));
    }
    if let Some(beneficiary_subject) = &coverage.beneficiary_subject {
        require_non_empty(beneficiary_subject, "coverage_beneficiary_subject")?;
    }
    let mut covered_claim_ids = BTreeSet::new();
    for claim_id in &coverage.covered_claim_ids {
        require_non_empty(claim_id, "coverage_covered_claim_ids")?;
        if !covered_claim_ids.insert(claim_id.as_str()) {
            return Err(claim_failed("risk coverage duplicate claim id"));
        }
    }
    if coverage.reserve_ref != report.facility.reserve_ref {
        return Err(claim_failed("risk coverage reserve mismatch"));
    }
    if coverage.currency != report.facility.reserve_currency {
        return Err(claim_failed("risk coverage currency mismatch"));
    }
    if coverage.exposure_units == 0 {
        return Err(claim_failed("risk exposure state missing"));
    }
    if coverage.exposure_units > report.facility.capital_units {
        return Err(claim_failed("risk exposure exceeds capital"));
    }
    let total_obligation_units = coverage
        .exposure_units
        .checked_add(report.facility.reserve_units)
        .ok_or_else(|| claim_failed("risk capital adequacy overflow"))?;
    if total_obligation_units > report.facility.capital_units {
        return Err(claim_failed("risk capital adequacy breach"));
    }
    if coverage.status != "bound" {
        return Err(claim_failed("risk coverage is not bound"));
    }
    if !risk_facility_state_reaches_bound_coverage(&report.facility.state) {
        return Err(claim_failed("risk facility lifecycle replay missing"));
    }
    Ok(())
}

fn risk_facility_state_reaches_bound_coverage(state: &str) -> bool {
    matches!(
        state,
        "coverage_bound"
            | "claim_open"
            | "claim_decided"
            | "payout_matched"
            | "settlement_matched"
            | "reserve_controlled"
            | "closed"
    )
}

fn validate_risk_reconciliation(
    report: &RiskComptrollerReport,
    reconciliation: &RiskReconciliation,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("reconciliation_order_id", &reconciliation.order_id),
        ("reconciliation_currency", &reconciliation.currency),
        ("reconciliation_status", &reconciliation.status),
    ] {
        require_non_empty(value, field)?;
    }
    if reconciliation.order_id != report.order_id {
        return Err(claim_failed("risk reconciliation order mismatch"));
    }
    if reconciliation.currency != report.coverage.currency {
        return Err(claim_failed("risk reconciliation currency mismatch"));
    }
    if reconciliation.exposure_units != report.coverage.exposure_units {
        return Err(claim_failed("risk reconciliation exposure mismatch"));
    }
    if reconciliation.reserve_units != report.facility.reserve_units {
        return Err(claim_failed("risk reconciliation reserve mismatch"));
    }
    if reconciliation.consumed_reserve_units > reconciliation.reserve_units {
        return Err(claim_failed("risk reserve overconsumed"));
    }
    if reconciliation.payout_units != reconciliation.settlement_units {
        return Err(claim_failed("risk payout settlement mismatch"));
    }
    if reconciliation.status != "balanced" {
        return Err(claim_failed("risk reconciliation is not balanced"));
    }
    Ok(())
}

fn validate_risk_premium_binding(
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    let Some(premium) = report.premium.as_ref() else {
        return Err(claim_failed("risk premium binding missing"));
    };
    for (field, value) in [
        ("premium_id", &premium.premium_id),
        ("premium_quote_ref", &premium.quote_ref),
        ("premium_coverage_id", &premium.coverage_id),
        ("premium_order_id", &premium.order_id),
        ("premium_subject", &premium.subject),
        ("premium_currency", &premium.currency),
        ("premium_status", &premium.status),
    ] {
        require_non_empty(value, field)?;
    }
    if premium.coverage_id != report.coverage.coverage_id {
        return Err(claim_failed("risk premium coverage mismatch"));
    }
    if premium.order_id != report.order_id {
        return Err(claim_failed("risk premium order mismatch"));
    }
    if premium.subject != report.coverage.subject {
        return Err(claim_failed("risk premium subject mismatch"));
    }
    if premium.currency != report.coverage.currency {
        return Err(claim_failed("risk premium currency mismatch"));
    }
    if premium.coverage_exposure_units != report.coverage.exposure_units {
        return Err(claim_failed("risk premium exposure mismatch"));
    }
    if premium.quoted_premium_units == 0 || premium.bound_premium_units == 0 {
        return Err(claim_failed("risk premium units missing"));
    }
    if premium.bound_premium_units != premium.quoted_premium_units {
        return Err(claim_failed("risk premium quote mismatch"));
    }
    match premium.status.as_str() {
        "bound" => {
            if premium.collected_premium_units != 0 {
                return Err(claim_failed("risk premium collection mismatch"));
            }
        }
        "collected" => {
            if premium.collected_premium_units != premium.bound_premium_units {
                return Err(claim_failed("risk premium collection mismatch"));
            }
            if optional_non_empty(
                premium.observed_payment_ref.as_ref(),
                "premium_observed_payment_ref",
            )?
            .is_none()
                && optional_non_empty(premium.settlement_ref.as_ref(), "premium_settlement_ref")?
                    .is_none()
            {
                return Err(claim_failed("risk premium collection evidence missing"));
            }
        }
        _ => return Err(claim_failed("risk premium status unsupported")),
    }
    Ok(())
}

fn validate_risk_capital_decomposition(
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    let Some(capital) = report.capital_decomposition.as_ref() else {
        return Err(claim_failed("risk capital decomposition missing"));
    };
    for (field, value) in [
        ("capital_decomposition_id", &capital.decomposition_id),
        ("capital_decomposition_source_kind", &capital.source_kind),
        ("capital_decomposition_source_ref", &capital.source_ref),
        ("capital_decomposition_currency", &capital.currency),
    ] {
        require_non_empty(value, field)?;
    }
    if capital.source_kind != "facility_commitment" {
        return Err(claim_failed("risk capital source unsupported"));
    }
    if capital.currency != report.facility.capital_currency {
        return Err(claim_failed("risk capital currency mismatch"));
    }
    if capital.committed_units != report.facility.capital_units {
        return Err(claim_failed("risk capital committed mismatch"));
    }
    if capital.held_units != report.facility.reserve_units {
        return Err(claim_failed("risk capital held mismatch"));
    }
    let deductions = capital
        .held_units
        .checked_add(capital.drawn_units)
        .and_then(|units| units.checked_add(capital.disbursed_units))
        .and_then(|units| units.checked_add(capital.impaired_units))
        .ok_or_else(|| claim_failed("risk capital decomposition overflow"))?;
    let expected_available_units = capital.committed_units.saturating_sub(deductions);
    if capital.available_units != expected_available_units {
        return Err(claim_failed("risk capital available mismatch"));
    }
    Ok(())
}

fn validate_risk_actuarial_limits(
    report: &RiskComptrollerReport,
    actuarial: &RiskActuarialEvidence,
    insurance_copy: &RiskInsuranceCopy,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("actuarial_model_ref", &actuarial.model_ref),
        ("actuarial_evidence_ref", &actuarial.evidence_ref),
        ("actuarial_currency", &actuarial.currency),
        ("actuarial_backtest_id", &actuarial.backtest.backtest_id),
        (
            "actuarial_backtest_window_start",
            &actuarial.backtest.window_start,
        ),
        (
            "actuarial_backtest_window_end",
            &actuarial.backtest.window_end,
        ),
        ("actuarial_backtest_status", &actuarial.backtest.status),
        ("insurance_copy_id", &insurance_copy.copy_id),
        (
            "insurance_copy_actuarial_evidence_ref",
            &insurance_copy.actuarial_evidence_ref,
        ),
        ("insurance_copy_currency", &insurance_copy.currency),
        (
            "insurance_copy_coverage_statement",
            &insurance_copy.coverage_statement,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if actuarial.currency != report.coverage.currency {
        return Err(claim_failed("risk actuarial currency mismatch"));
    }
    if insurance_copy.currency != report.coverage.currency {
        return Err(claim_failed("risk insurance copy currency mismatch"));
    }
    if insurance_copy.actuarial_evidence_ref != actuarial.model_ref {
        return Err(claim_failed(
            "risk insurance copy actuarial evidence mismatch",
        ));
    }
    if actuarial.supported_exposure_units == 0 {
        return Err(claim_failed("risk actuarial support missing"));
    }
    if insurance_copy.maximum_coverage_units == 0 {
        return Err(claim_failed("risk insurance copy coverage missing"));
    }
    if actuarial.confidence_level_bps == 0 || actuarial.confidence_level_bps > 10_000 {
        return Err(claim_failed("risk actuarial confidence unsupported"));
    }
    let window_start = parse_rfc3339_utc(
        &actuarial.backtest.window_start,
        "actuarial backtest window_start",
    )?;
    let window_end = parse_rfc3339_utc(
        &actuarial.backtest.window_end,
        "actuarial backtest window_end",
    )?;
    if window_end < window_start {
        return Err(claim_failed("risk actuarial backtest window inverted"));
    }
    if actuarial.backtest.sample_size == 0 {
        return Err(claim_failed("risk actuarial backtest sample missing"));
    }
    if actuarial.backtest.observed_loss_ratio_bps > 10_000
        || actuarial.backtest.maximum_loss_ratio_bps > 10_000
    {
        return Err(claim_failed("risk actuarial backtest ratio unsupported"));
    }
    if actuarial.backtest.status != "passed" {
        return Err(claim_failed("risk actuarial backtest did not pass"));
    }
    if actuarial.backtest.observed_loss_ratio_bps > actuarial.backtest.maximum_loss_ratio_bps {
        return Err(claim_failed("risk actuarial backtest breach"));
    }
    if report.coverage.exposure_units > actuarial.supported_exposure_units {
        return Err(claim_failed("risk coverage exceeds actuarial support"));
    }
    if insurance_copy.maximum_coverage_units > actuarial.supported_exposure_units {
        return Err(claim_failed(
            "risk insurance copy exceeds actuarial support",
        ));
    }
    if insurance_copy.maximum_coverage_units < report.coverage.exposure_units {
        return Err(claim_failed("risk insurance copy undercovers exposure"));
    }
    if insurance_copy.maximum_coverage_units > report.coverage.exposure_units {
        return Err(claim_failed("risk insurance copy exceeds bound coverage"));
    }
    Ok(())
}

fn validate_risk_facility_closure(
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    if report.facility.state == "closed"
        && report.reconciliation.consumed_reserve_units != report.facility.reserve_units
    {
        return Err(claim_failed("risk facility closure reserve unreconciled"));
    }
    Ok(())
}

fn validate_risk_capital_instructions(
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    let claim_payouts = report
        .reserve_ledger
        .iter()
        .filter(|entry| entry.lane == "claim_payout")
        .collect::<Vec<_>>();
    if claim_payouts.is_empty() {
        if report.capital_instructions.is_empty() {
            return Ok(());
        }
        return Err(claim_failed("risk capital instruction unbound"));
    }

    let mut instructions_by_entry = BTreeMap::new();
    for instruction in &report.capital_instructions {
        validate_risk_capital_instruction(instruction)?;
        if instructions_by_entry
            .insert(instruction.reserve_entry_id.as_str(), instruction)
            .is_some()
        {
            return Err(claim_failed(
                "risk capital instruction duplicate reserve entry",
            ));
        }
    }

    for entry in claim_payouts {
        let Some(instruction) = instructions_by_entry.remove(entry.entry_id.as_str()) else {
            return Err(claim_failed("risk capital instruction missing"));
        };
        if !instruction.matches_claim_payout(report, entry) {
            return Err(claim_failed("risk capital instruction mismatch"));
        }
    }

    if !instructions_by_entry.is_empty() {
        return Err(claim_failed("risk capital instruction unbound"));
    }
    Ok(())
}

fn validate_risk_capital_instruction(
    instruction: &RiskCapitalInstruction,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("capital_instruction_id", &instruction.instruction_id),
        (
            "capital_instruction_reserve_entry_id",
            &instruction.reserve_entry_id,
        ),
        ("capital_instruction_order_id", &instruction.order_id),
        ("capital_instruction_claim_id", &instruction.claim_id),
        ("capital_instruction_reserve_ref", &instruction.reserve_ref),
        ("capital_instruction_currency", &instruction.currency),
        (
            "capital_instruction_settlement_ref",
            &instruction.settlement_ref,
        ),
        (
            "capital_instruction_intended_action",
            &instruction.intended_action,
        ),
        ("capital_instruction_source_kind", &instruction.source_kind),
        (
            "capital_instruction_intended_state",
            &instruction.intended_state,
        ),
        (
            "capital_instruction_reconciled_state",
            &instruction.reconciled_state,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if instruction.units == 0 {
        return Err(claim_failed("risk capital instruction units missing"));
    }
    if instruction.intended_action != "transfer_funds" {
        return Err(claim_failed("risk capital instruction action unsupported"));
    }
    if instruction.source_kind != "facility_commitment" {
        return Err(claim_failed("risk capital instruction source unsupported"));
    }
    if instruction.intended_state != "pending_execution" {
        return Err(claim_failed("risk capital instruction state unsupported"));
    }
    if optional_non_empty(
        instruction.observed_execution_ref.as_ref(),
        "capital_instruction_observed_execution_ref",
    )?
    .is_some()
        || instruction.reconciled_state != "not_observed"
    {
        return Err(claim_failed("risk payout preobserved instruction"));
    }
    Ok(())
}

impl RiskCapitalInstruction {
    fn matches_claim_payout(
        &self,
        report: &RiskComptrollerReport,
        entry: &RiskReserveLedgerEntry,
    ) -> bool {
        self.reserve_entry_id == entry.entry_id
            && self.order_id == report.order_id
            && self.claim_id == entry.claim_id
            && self.reserve_ref == entry.reserve_ref
            && self.currency == entry.currency
            && self.units == entry.units
            && self.settlement_ref == entry.settlement_ref
    }
}

fn validate_risk_settlement_counterparties(
    report: &RiskComptrollerReport,
    entry: &RiskReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    let payer_subject =
        optional_non_empty(entry.payer_subject.as_ref(), "reserve_ledger_payer_subject")?;
    let payee_subject =
        optional_non_empty(entry.payee_subject.as_ref(), "reserve_ledger_payee_subject")?;

    if payer_subject.is_some() != payee_subject.is_some() {
        return Err(claim_failed("risk settlement counterparty mismatch"));
    }

    if entry.lane != "claim_payout" {
        if payer_subject.is_some() {
            return Err(claim_failed(
                "risk reserve ledger counterparty lane unsupported",
            ));
        }
        return Ok(());
    }

    let Some(payer_subject) = payer_subject else {
        return Err(claim_failed("risk settlement counterparty mismatch"));
    };
    let Some(payee_subject) = payee_subject else {
        return Err(claim_failed("risk settlement counterparty mismatch"));
    };

    if payer_subject != report.coverage.subject {
        return Err(claim_failed("risk settlement counterparty mismatch"));
    }
    if let Some(beneficiary_subject) = report.coverage.beneficiary_subject.as_deref() {
        if payee_subject != beneficiary_subject {
            return Err(claim_failed("risk settlement counterparty mismatch"));
        }
    } else if payee_subject != report.coverage.subject {
        return Err(claim_failed("risk settlement counterparty mismatch"));
    }
    Ok(())
}

fn validate_risk_coverage_claim_scope(
    report: &RiskComptrollerReport,
) -> Result<(), TransactionPassportError> {
    for entry in &report.reserve_ledger {
        if report.coverage.covered_claim_ids.is_empty()
            || !report
                .coverage
                .covered_claim_ids
                .iter()
                .any(|claim_id| claim_id == &entry.claim_id)
        {
            return Err(claim_failed("risk claim outside coverage"));
        }
    }
    Ok(())
}

fn validate_risk_claim_appeals(
    report: &RiskComptrollerReport,
    appeals: &[RiskClaimAppeal],
) -> Result<(), TransactionPassportError> {
    let mut appeal_ids = BTreeSet::new();
    let mut open_appeal_blocks_by_claim = BTreeMap::<&str, BTreeSet<&str>>::new();
    for appeal in appeals {
        validate_risk_claim_appeal(appeal)?;
        if !appeal_ids.insert(appeal.appeal_id.as_str()) {
            return Err(claim_failed("risk appeal duplicate id"));
        }
        if !report.coverage.covered_claim_ids.is_empty()
            && !report
                .coverage
                .covered_claim_ids
                .iter()
                .any(|claim_id| claim_id == &appeal.claim_id)
        {
            return Err(claim_failed("risk appeal outside coverage"));
        }
        if appeal.status != "open" {
            continue;
        }
        let blocks = open_appeal_blocks_by_claim
            .entry(appeal.claim_id.as_str())
            .or_default();
        for block in &appeal.blocks {
            blocks.insert(block.as_str());
        }
    }

    if report.facility.state == "closed"
        && open_appeal_blocks_facility_closure(report, &open_appeal_blocks_by_claim)
    {
        return Err(claim_failed("risk open appeal blocks facility closure"));
    }

    for entry in &report.reserve_ledger {
        if is_terminal_reserve_consumption(&entry.lane)
            && open_appeal_blocks_by_claim
                .get(entry.claim_id.as_str())
                .is_some_and(|blocks| blocks.contains(entry.lane.as_str()))
        {
            return Err(claim_failed("risk open appeal blocks reserve action"));
        }
    }
    Ok(())
}

fn open_appeal_blocks_facility_closure(
    report: &RiskComptrollerReport,
    open_appeal_blocks_by_claim: &BTreeMap<&str, BTreeSet<&str>>,
) -> bool {
    if report.coverage.covered_claim_ids.is_empty() {
        return open_appeal_blocks_by_claim
            .values()
            .any(|blocks| blocks.contains("facility_closure"));
    }
    report.coverage.covered_claim_ids.iter().any(|claim_id| {
        open_appeal_blocks_by_claim
            .get(claim_id.as_str())
            .is_some_and(|blocks| blocks.contains("facility_closure"))
    })
}

fn validate_risk_claim_appeal(appeal: &RiskClaimAppeal) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("appeal_id", &appeal.appeal_id),
        ("appeal_claim_id", &appeal.claim_id),
        ("appeal_status", &appeal.status),
    ] {
        require_non_empty(value, field)?;
    }
    if !matches!(
        appeal.status.as_str(),
        "open" | "resolved" | "denied" | "withdrawn"
    ) {
        return Err(claim_failed("risk appeal status unsupported"));
    }
    if appeal.blocks.is_empty() {
        return Err(claim_failed("risk appeal block list missing"));
    }
    for block in &appeal.blocks {
        require_non_empty(block, "appeal_blocks")?;
        if !matches!(
            block.as_str(),
            "claim_payout"
                | "reserve_release"
                | "reserve_slash"
                | "market_slash"
                | "facility_closure"
                | "write_off"
        ) {
            return Err(claim_failed("risk appeal block unsupported"));
        }
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn optional_non_empty<'a>(
    value: Option<&'a String>,
    field: &'static str,
) -> Result<Option<&'a str>, TransactionPassportError> {
    match value {
        Some(value) => {
            require_non_empty(value, field)?;
            Ok(Some(value.as_str()))
        }
        None => Ok(None),
    }
}

fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| claim_failed(format!("invalid risk timestamp: {field}")))
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::RiskComptrollerClaimFailed(message.into())
}
