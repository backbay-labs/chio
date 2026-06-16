use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

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
    facility: RiskFacilityState,
    #[serde(default)]
    facility_lifecycle: Vec<RiskFacilityTransition>,
    coverage: RiskCoverageBinding,
    reconciliation: RiskReconciliation,
    actuarial_evidence: RiskActuarialEvidence,
    insurance_copy: RiskInsuranceCopy,
    #[serde(default)]
    reserve_ledger: Vec<RiskReserveLedgerEntry>,
    #[serde(default)]
    sanction_reserve_ledger: Vec<RiskSanctionReserveLedgerEntry>,
    #[serde(default)]
    appeals: Vec<RiskClaimAppeal>,
    verified_claims: Vec<String>,
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
    validate_risk_actuarial_limits(report, &report.actuarial_evidence, &report.insurance_copy)?;
    validate_risk_claim_appeals(report, &report.appeals)?;
    validate_risk_reserve_ledger(report, &report.reserve_ledger)?;
    validate_risk_sanction_reserve_ledger(
        report,
        &report.reserve_ledger,
        &report.sanction_reserve_ledger,
    )?;
    validate_risk_coverage_claim_scope(report)?;
    validate_risk_facility_closure(report)?;
    Ok(())
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
    let mut previous_to_state: Option<&str> = None;
    let mut final_state: Option<&str> = None;
    for transition in transitions {
        validate_risk_facility_transition(transition)?;
        if !transition_ids.insert(transition.transition_id.as_str()) {
            return Err(claim_failed("risk facility lifecycle duplicate transition"));
        }
        if let Some(previous_to_state) = previous_to_state {
            if previous_to_state != transition.from_state {
                return Err(claim_failed("risk facility lifecycle replay gap"));
            }
        } else if transition.from_state != "evidence_cold" {
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

        previous_to_state = Some(transition.to_state.as_str());
        final_state = Some(transition.to_state.as_str());
    }

    if final_state != Some(facility.state.as_str()) {
        return Err(claim_failed("risk facility lifecycle final state mismatch"));
    }
    Ok(())
}

fn validate_risk_facility_transition(
    transition: &RiskFacilityTransition,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("facility_transition_id", &transition.transition_id),
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
    Ok(())
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
    if insurance_copy.maximum_coverage_units > report.coverage.exposure_units {
        return Err(claim_failed("risk insurance copy exceeds bound coverage"));
    }
    Ok(())
}

fn validate_risk_reserve_ledger(
    report: &RiskComptrollerReport,
    entries: &[RiskReserveLedgerEntry],
) -> Result<(), TransactionPassportError> {
    if entries.is_empty() {
        if report.reconciliation.consumed_reserve_units == 0
            && report.reconciliation.payout_units == 0
        {
            return Ok(());
        }
        return Err(claim_failed("risk reserve ledger missing"));
    }

    let mut entry_ids = BTreeSet::new();
    let mut receipt_refs = BTreeSet::new();
    let mut terminal_consumption_by_reserve_claim: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    let mut prior_reserve_slash_units: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    let mut reversed_reserve_slash_units: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    let mut consumed_units = 0u64;
    let mut claim_payout_units = 0u64;
    for entry in entries {
        validate_risk_reserve_ledger_entry(report, entry)?;
        if !entry_ids.insert(entry.entry_id.as_str()) {
            return Err(claim_failed("risk reserve ledger duplicate entry"));
        }
        if !receipt_refs.insert(entry.receipt_ref.as_str()) {
            return Err(claim_failed("risk reserve ledger duplicate receipt"));
        }
        let reserve_claim = (entry.reserve_ref.as_str(), entry.claim_id.as_str());
        if entry.lane == "reverse_slash" {
            let Some(prior_slash_units) = prior_reserve_slash_units.get(&reserve_claim).copied()
            else {
                return Err(claim_failed(
                    "risk reverse slash missing prior reserve slash",
                ));
            };
            let reversed_units = reversed_reserve_slash_units
                .entry(reserve_claim)
                .or_insert(0);
            *reversed_units = reversed_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reverse slash overflow"))?;
            if *reversed_units > prior_slash_units {
                return Err(claim_failed(
                    "risk reverse slash exceeds prior reserve slash",
                ));
            }
            consumed_units = consumed_units
                .checked_sub(entry.units)
                .ok_or_else(|| claim_failed("risk reverse slash exceeds prior reserve slash"))?;
        }
        if is_terminal_reserve_consumption(&entry.lane) {
            if terminal_consumption_by_reserve_claim
                .insert(reserve_claim, entry.lane.as_str())
                .is_some()
            {
                return Err(claim_failed("risk reserve double consumption"));
            }
            consumed_units = consumed_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reserve ledger overflow"))?;
        }
        if entry.lane == "claim_payout" {
            claim_payout_units = claim_payout_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk payout ledger overflow"))?;
        }
        if entry.lane == "reserve_slash" {
            let prior_slash_units = prior_reserve_slash_units.entry(reserve_claim).or_insert(0);
            *prior_slash_units = prior_slash_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reserve slash overflow"))?;
        }
    }

    if consumed_units != report.reconciliation.consumed_reserve_units {
        return Err(claim_failed("risk reserve ledger consumption mismatch"));
    }
    if claim_payout_units != report.reconciliation.payout_units {
        return Err(claim_failed("risk payout ledger mismatch"));
    }
    Ok(())
}

fn validate_risk_sanction_reserve_ledger(
    report: &RiskComptrollerReport,
    reserve_entries: &[RiskReserveLedgerEntry],
    sanction_entries: &[RiskSanctionReserveLedgerEntry],
) -> Result<(), TransactionPassportError> {
    let market_slashes: Vec<&RiskReserveLedgerEntry> = reserve_entries
        .iter()
        .filter(|entry| entry.lane == "market_slash")
        .collect();
    if market_slashes.is_empty() {
        if sanction_entries.is_empty() {
            return Ok(());
        }
        return Err(claim_failed("risk sanction reserve ledger unsupported"));
    }
    if sanction_entries.is_empty() {
        return Err(claim_failed("risk sanction reserve ledger missing"));
    }

    let mut bridge_ids = BTreeSet::new();
    for market_slash in &market_slashes {
        let Some(sanction_bridge) = market_slash.sanction_bridge.as_ref() else {
            return Err(claim_failed("risk market slash requires sanction bridge"));
        };
        if !bridge_ids.insert(sanction_bridge.bridge_id.as_str()) {
            return Err(claim_failed("risk sanction bridge duplicate"));
        }
    }

    let mut entry_ids = BTreeSet::new();
    let mut receipt_refs = BTreeSet::new();
    for sanction_entry in sanction_entries {
        validate_risk_sanction_reserve_ledger_entry(report, sanction_entry)?;
        if !entry_ids.insert(sanction_entry.entry_id.as_str()) {
            return Err(claim_failed("risk sanction reserve ledger duplicate entry"));
        }
        if !receipt_refs.insert(sanction_entry.receipt_ref.as_str()) {
            return Err(claim_failed(
                "risk sanction reserve ledger duplicate receipt",
            ));
        }
    }

    for sanction_entry in sanction_entries {
        let matches_market_slash = market_slashes.iter().any(|market_slash| {
            market_slash
                .sanction_bridge
                .as_ref()
                .is_some_and(|bridge| sanction_entry.matches_market_slash(market_slash, bridge))
        });
        if !matches_market_slash {
            return Err(claim_failed("risk sanction reserve ledger unbound entry"));
        }
    }

    for market_slash in market_slashes {
        let Some(sanction_bridge) = market_slash.sanction_bridge.as_ref() else {
            return Err(claim_failed("risk market slash requires sanction bridge"));
        };
        if !sanction_entries.iter().any(|sanction_entry| {
            sanction_entry.matches_market_slash(market_slash, sanction_bridge)
        }) {
            return Err(claim_failed("risk sanction reserve ledger missing"));
        }
    }
    Ok(())
}

impl RiskSanctionReserveLedgerEntry {
    fn matches_market_slash(
        &self,
        market_slash: &RiskReserveLedgerEntry,
        sanction_bridge: &RiskSanctionBridge,
    ) -> bool {
        self.lane == "market_slash"
            && self.bridge_id == sanction_bridge.bridge_id
            && self.receipt_ref == market_slash.receipt_ref
            && self.reserve_ref == market_slash.reserve_ref
            && self.claim_id == market_slash.claim_id
            && self.currency == market_slash.currency
            && self.units == market_slash.units
            && self.settlement_ref == market_slash.settlement_ref
            && self.authority_receipt_ref == sanction_bridge.authority_receipt_ref
            && self.evidence_ref == sanction_bridge.evidence_ref
            && self.jurisdiction_ref == sanction_bridge.jurisdiction_ref
    }
}

fn validate_risk_sanction_reserve_ledger_entry(
    report: &RiskComptrollerReport,
    entry: &RiskSanctionReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("sanction_reserve_ledger_entry_id", &entry.entry_id),
        ("sanction_reserve_ledger_bridge_id", &entry.bridge_id),
        ("sanction_reserve_ledger_lane", &entry.lane),
        ("sanction_reserve_ledger_receipt_ref", &entry.receipt_ref),
        ("sanction_reserve_ledger_reserve_ref", &entry.reserve_ref),
        ("sanction_reserve_ledger_claim_id", &entry.claim_id),
        ("sanction_reserve_ledger_currency", &entry.currency),
        (
            "sanction_reserve_ledger_settlement_ref",
            &entry.settlement_ref,
        ),
        (
            "sanction_reserve_ledger_authority_receipt_ref",
            &entry.authority_receipt_ref,
        ),
        ("sanction_reserve_ledger_evidence_ref", &entry.evidence_ref),
        (
            "sanction_reserve_ledger_jurisdiction_ref",
            &entry.jurisdiction_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if entry.lane != "market_slash" {
        return Err(claim_failed(
            "risk sanction reserve ledger lane unsupported",
        ));
    }
    if entry.reserve_ref != report.facility.reserve_ref {
        return Err(claim_failed(
            "risk sanction reserve ledger reserve mismatch",
        ));
    }
    if entry.currency != report.facility.reserve_currency {
        return Err(claim_failed(
            "risk sanction reserve ledger currency mismatch",
        ));
    }
    if entry.units == 0 {
        return Err(claim_failed("risk sanction reserve ledger units missing"));
    }
    Ok(())
}

fn validate_risk_reserve_ledger_entry(
    report: &RiskComptrollerReport,
    entry: &RiskReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("reserve_ledger_entry_id", &entry.entry_id),
        ("reserve_ledger_receipt_ref", &entry.receipt_ref),
        ("reserve_ledger_lane", &entry.lane),
        ("reserve_ledger_reserve_ref", &entry.reserve_ref),
        ("reserve_ledger_claim_id", &entry.claim_id),
        ("reserve_ledger_currency", &entry.currency),
        ("reserve_ledger_settlement_ref", &entry.settlement_ref),
    ] {
        require_non_empty(value, field)?;
    }
    if !matches!(
        entry.lane.as_str(),
        "claim_payout"
            | "reserve_release"
            | "reserve_slash"
            | "market_slash"
            | "hold"
            | "reverse_slash"
            | "write_off"
    ) {
        return Err(claim_failed("risk reserve ledger lane unsupported"));
    }
    if entry.lane == "market_slash" {
        validate_market_slash_sanction_bridge(report, entry)?;
    } else if entry.sanction_bridge.is_some() {
        return Err(claim_failed("risk sanction bridge lane unsupported"));
    }
    if entry.reserve_ref != report.facility.reserve_ref {
        return Err(claim_failed("risk reserve ledger reserve mismatch"));
    }
    if !report.coverage.covered_claim_ids.is_empty()
        && !report
            .coverage
            .covered_claim_ids
            .iter()
            .any(|claim_id| claim_id == &entry.claim_id)
    {
        return Err(claim_failed("risk claim outside coverage"));
    }
    if entry.currency != report.facility.reserve_currency {
        return Err(claim_failed("risk reserve ledger currency mismatch"));
    }
    if entry.units == 0 {
        return Err(claim_failed("risk reserve ledger units missing"));
    }
    validate_risk_settlement_counterparties(report, entry)?;
    Ok(())
}

fn validate_market_slash_sanction_bridge(
    report: &RiskComptrollerReport,
    entry: &RiskReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    let Some(sanction_bridge) = entry.sanction_bridge.as_ref() else {
        return Err(claim_failed("risk market slash requires sanction bridge"));
    };
    for (field, value) in [
        ("sanction_bridge_id", &sanction_bridge.bridge_id),
        (
            "sanction_bridge_authority_receipt_ref",
            &sanction_bridge.authority_receipt_ref,
        ),
        (
            "sanction_bridge_evidence_ref",
            &sanction_bridge.evidence_ref,
        ),
        (
            "sanction_bridge_jurisdiction_ref",
            &sanction_bridge.jurisdiction_ref,
        ),
        ("sanction_bridge_subject", &sanction_bridge.sanction_subject),
    ] {
        require_non_empty(value, field)?;
    }
    if sanction_bridge.sanction_subject != report.coverage.subject {
        return Err(claim_failed("risk market slash sanction subject mismatch"));
    }
    if sanction_bridge.maximum_slash_units == 0 {
        return Err(claim_failed("risk market slash sanction limit missing"));
    }
    if entry.units > sanction_bridge.maximum_slash_units {
        return Err(claim_failed("risk market slash exceeds sanction bridge"));
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

fn is_terminal_reserve_consumption(lane: &str) -> bool {
    matches!(
        lane,
        "claim_payout" | "reserve_release" | "reserve_slash" | "market_slash" | "write_off"
    )
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

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::RiskComptrollerClaimFailed(message.into())
}
