use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use chio_risk_comptroller::{
    validate_risk_evidence_refs, validate_risk_report as validate_comptroller_report,
    RiskEvidenceRefKind,
};
use chio_transaction_passport::{TransactionPassport, TransactionPassportError};

pub(super) use chio_risk_comptroller::RiskComptrollerReport;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderDiscoverySnapshot {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    order_id: String,
    order_intent_ref: String,
    market_scope: String,
    provider_candidates: Vec<ProviderCandidate>,
    freshness_window: FreshnessWindow,
    discovery_authority_ref: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCandidate {
    subject: String,
    provider_passport_ref: String,
    service_manifest_ref: String,
    availability_ref: String,
    pricing_surface_ref: String,
    jurisdiction_ref: String,
    excluded: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderSelectionReport {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    passport_id: String,
    pub(super) order_id: String,
    discovery_snapshot_ref: String,
    pub(super) selected_provider_subject: String,
    ranking_policy_ref: String,
    scorecard_ref: String,
    sla_commitment_ref: String,
    price_quote_ref: String,
    risk_report_ref: String,
    override_receipt_ref: String,
    selection_reason_codes: Vec<String>,
    ranking_results: Vec<RankingResult>,
    rejected_candidate_summaries: Vec<RejectedCandidateSummary>,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RankingResult {
    provider_subject: String,
    rank: u64,
    total_score: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedCandidateSummary {
    provider_subject: String,
    reason_codes: Vec<String>,
    redacted_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustScorecardSnapshot {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    pub(super) subject: String,
    scope: String,
    verifier_policy_ref: String,
    component_scores: Vec<ComponentScore>,
    issuer_trust_roots: Vec<String>,
    reputation_snapshot_refs: Vec<String>,
    portable_reputation_import_refs: Vec<String>,
    sla_performance_refs: Vec<String>,
    negative_event_refs: Vec<String>,
    freshness_window: FreshnessWindow,
    score_floor: u64,
    score_ceiling: u64,
    computed_score: u64,
    downgrade_reasons: Vec<String>,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentScore {
    component: String,
    score: u64,
    weight: u64,
    evidence_ref: String,
    stale: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReputationImportReport {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    subject: String,
    source_network: String,
    issuer: String,
    issuer_trust_ref: String,
    source_reputation_ref: String,
    negative_event_refs: Vec<String>,
    subject_binding_ref: String,
    privacy_profile_ref: String,
    decay_policy_ref: String,
    local_weight: u64,
    import_verdict: String,
    usage: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SlaCommitment {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    order_id: String,
    provider_subject: String,
    buyer_subject: String,
    service_scope: String,
    metric_definitions: Vec<MetricDefinition>,
    measurement_policy_ref: String,
    effective_window: EffectiveWindow,
    exclusions_ref: String,
    pub(super) remedy_policy_ref: String,
    collateral_position_ref: String,
    guarantee_decision_ref: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricDefinition {
    metric: String,
    target: u64,
    unit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SlaPerformanceReport {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    performance_id: String,
    sla_ref: String,
    order_id: String,
    provider_subject: String,
    measurement_policy_ref: String,
    measurement_evidence_refs: Vec<String>,
    measured_at: String,
    computed_metric_results: Vec<ComputedMetricResult>,
    breach_verdict: String,
    remedy_ref: String,
    dispute_ref: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputedMetricResult {
    metric: String,
    value: u64,
    unit: String,
    passed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollateralPositionReport {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    pub(super) collateral_id: String,
    subject: String,
    order_id: String,
    currency_or_asset: String,
    amount: u64,
    source_type: String,
    source_ref: String,
    lock_start: String,
    lock_expiry: String,
    claim_priority: String,
    pub(super) slash_authority_ref: String,
    release_policy_ref: String,
    consumed_amount_refs: Vec<String>,
    available_amount: u64,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuaranteeDecision {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    pub(super) guarantee_id: String,
    order_id: String,
    provider_subject: String,
    beneficiary_subject: String,
    guarantee_type: String,
    maximum_remedy: u64,
    currency: String,
    backing_refs: Vec<String>,
    coverage_decision_ref: String,
    sla_commitment_ref: String,
    claim_window: EffectiveWindow,
    exclusions_ref: String,
    adjudication_jurisdiction_ref: String,
    verdict: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdjudicationJurisdictionReceipt {
    schema: String,
    pub(super) id: String,
    issued_at: String,
    pub(super) jurisdiction_id: String,
    order_id: String,
    policy_ref: String,
    covered_dispute_types: Vec<String>,
    adjudicator_subjects: Vec<String>,
    appeal_authority_refs: Vec<String>,
    slash_authority_refs: Vec<String>,
    remedy_limits: Vec<RemedyLimit>,
    evidence_rules_ref: String,
    effective_window: EffectiveWindow,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemedyLimit {
    currency: String,
    maximum_remedy: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessWindow {
    valid_from: String,
    valid_until: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectiveWindow {
    start: String,
    end: String,
}

pub(super) fn validate_discovery(
    passport: &TransactionPassport,
    discovery: &ProviderDiscoverySnapshot,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &discovery.schema),
        ("id", &discovery.id),
        ("issued_at", &discovery.issued_at),
        ("passport_id", &discovery.passport_id),
        ("order_id", &discovery.order_id),
        ("order_intent_ref", &discovery.order_intent_ref),
        ("market_scope", &discovery.market_scope),
        (
            "discovery_authority_ref",
            &discovery.discovery_authority_ref,
        ),
        ("signature", &discovery.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if discovery.passport_id != passport.id {
        return Err(claim_failed("discovery passport mismatch"));
    }
    if discovery.provider_candidates.is_empty() {
        return Err(claim_failed("discovery candidates missing"));
    }
    for candidate in &discovery.provider_candidates {
        validate_provider_candidate(candidate)?;
    }
    ensure_freshness_contains(
        &discovery.freshness_window,
        &discovery.issued_at,
        "discovery snapshot is stale",
    )
}

pub(super) fn validate_reputation_import(
    import: &ReputationImportReport,
    scorecard: &TrustScorecardSnapshot,
    max_weight: u64,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &import.schema),
        ("id", &import.id),
        ("issued_at", &import.issued_at),
        ("subject", &import.subject),
        ("source_network", &import.source_network),
        ("issuer", &import.issuer),
        ("issuer_trust_ref", &import.issuer_trust_ref),
        ("source_reputation_ref", &import.source_reputation_ref),
        ("subject_binding_ref", &import.subject_binding_ref),
        ("privacy_profile_ref", &import.privacy_profile_ref),
        ("decay_policy_ref", &import.decay_policy_ref),
        ("import_verdict", &import.import_verdict),
        ("usage", &import.usage),
        ("signature", &import.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if import.subject != scorecard.subject {
        return Err(claim_failed("reputation import subject mismatch"));
    }
    if import.import_verdict != "accepted" {
        return Err(claim_failed("reputation import was not accepted"));
    }
    if import.usage != "scoring_input" {
        return Err(claim_failed(
            "reputation import cannot prove collateral or solvency",
        ));
    }
    if import.local_weight > max_weight {
        return Err(claim_failed(
            "reputation import local weight exceeds policy",
        ));
    }
    if !scorecard
        .issuer_trust_roots
        .iter()
        .any(|root| root == &import.issuer_trust_ref)
    {
        return Err(claim_failed("reputation import issuer not trusted"));
    }
    let mut portable_reputation_weight = 0_u64;
    let mut has_portable_reputation_component = false;
    for component in &scorecard.component_scores {
        if component.component == "portable_reputation" {
            has_portable_reputation_component = true;
            if component.evidence_ref != import.id {
                return Err(claim_failed(
                    "scorecard portable reputation evidence mismatch",
                ));
            }
            portable_reputation_weight =
                portable_reputation_weight
                    .checked_add(component.weight)
                    .ok_or_else(|| claim_failed("scorecard portable reputation weight overflow"))?;
        }
    }
    if !has_portable_reputation_component {
        return Err(claim_failed(
            "scorecard missing portable reputation component",
        ));
    }
    if portable_reputation_weight > import.local_weight {
        return Err(claim_failed(
            "scorecard portable reputation weight exceeds import limit",
        ));
    }
    let _ = &import.negative_event_refs;
    Ok(())
}

pub(super) fn validate_scorecard(
    scorecard: &TrustScorecardSnapshot,
    reputation_import: &ReputationImportReport,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &scorecard.schema),
        ("id", &scorecard.id),
        ("issued_at", &scorecard.issued_at),
        ("subject", &scorecard.subject),
        ("scope", &scorecard.scope),
        ("verifier_policy_ref", &scorecard.verifier_policy_ref),
        ("signature", &scorecard.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if scorecard.scope != "local-policy" {
        return Err(claim_failed("scorecard must be local-policy scoped"));
    }
    if scorecard.component_scores.is_empty() {
        return Err(claim_failed("scorecard component scores missing"));
    }
    if scorecard.score_floor >= scorecard.score_ceiling {
        return Err(claim_failed("scorecard range is invalid"));
    }
    if scorecard.computed_score < scorecard.score_floor
        || scorecard.computed_score > scorecard.score_ceiling
    {
        return Err(claim_failed("scorecard computed score outside range"));
    }
    if !scorecard
        .portable_reputation_import_refs
        .iter()
        .any(|reference| reference == &reputation_import.id)
    {
        return Err(claim_failed("scorecard missing reputation import"));
    }
    ensure_freshness_contains(
        &scorecard.freshness_window,
        &scorecard.issued_at,
        "scorecard snapshot is stale",
    )?;
    let recomputed_score = recompute_score(scorecard)?;
    if recomputed_score != scorecard.computed_score {
        return Err(claim_failed("scorecard recompute mismatch"));
    }
    let _ = &scorecard.reputation_snapshot_refs;
    let _ = &scorecard.sla_performance_refs;
    let _ = &scorecard.negative_event_refs;
    let _ = &scorecard.downgrade_reasons;
    Ok(())
}

pub(super) fn validate_selection(
    passport: &TransactionPassport,
    discovery: &ProviderDiscoverySnapshot,
    selection: &ProviderSelectionReport,
    scorecard: &TrustScorecardSnapshot,
    sla: &SlaCommitment,
    mut contains_override_receipt_ref: impl FnMut(&str) -> bool,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &selection.schema),
        ("id", &selection.id),
        ("issued_at", &selection.issued_at),
        ("passport_id", &selection.passport_id),
        ("order_id", &selection.order_id),
        ("discovery_snapshot_ref", &selection.discovery_snapshot_ref),
        (
            "selected_provider_subject",
            &selection.selected_provider_subject,
        ),
        ("ranking_policy_ref", &selection.ranking_policy_ref),
        ("scorecard_ref", &selection.scorecard_ref),
        ("sla_commitment_ref", &selection.sla_commitment_ref),
        ("price_quote_ref", &selection.price_quote_ref),
        ("risk_report_ref", &selection.risk_report_ref),
        ("signature", &selection.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if selection.passport_id != passport.id {
        return Err(claim_failed("selection passport mismatch"));
    }
    if selection.discovery_snapshot_ref != discovery.id {
        return Err(claim_failed("selection discovery mismatch"));
    }
    if selection.order_id != discovery.order_id {
        return Err(claim_failed("selection order mismatch"));
    }
    if !discovery.contains_available_provider(&selection.selected_provider_subject) {
        return Err(claim_failed(
            "selected provider absent from discovery snapshot",
        ));
    }
    ensure_timestamp_at_or_after(
        &selection.issued_at,
        &discovery.issued_at,
        "selection predates discovery snapshot",
    )?;
    if scorecard.subject != selection.selected_provider_subject {
        return Err(claim_failed("selection scorecard subject mismatch"));
    }
    if selection.scorecard_ref != scorecard.id {
        return Err(claim_failed("selection scorecard ref mismatch"));
    }
    ensure_freshness_contains(
        &scorecard.freshness_window,
        &selection.issued_at,
        "scorecard snapshot is stale at selection",
    )?;
    let selected_score = selection
        .ranking_results
        .iter()
        .find(|result| result.provider_subject == selection.selected_provider_subject)
        .ok_or_else(|| claim_failed("selection ranking missing selected provider"))?;
    if selected_score.total_score != scorecard.computed_score {
        return Err(claim_failed("selection scorecard score mismatch"));
    }
    if selection.sla_commitment_ref != sla.id {
        return Err(claim_failed("selection SLA ref mismatch"));
    }
    if selection.ranking_results.is_empty() {
        return Err(claim_failed("selection ranking results missing"));
    }
    validate_ranking(selection, discovery, &mut contains_override_receipt_ref)?;
    for summary in &selection.rejected_candidate_summaries {
        validate_rejected_candidate_summary(summary)?;
    }
    for reason in &selection.selection_reason_codes {
        require_non_empty(reason, "selection reason code")?;
    }
    ensure_freshness_contains(
        &discovery.freshness_window,
        &selection.issued_at,
        "discovery snapshot is stale",
    )
}

pub(super) fn validate_risk_report(
    passport: &TransactionPassport,
    selection: &ProviderSelectionReport,
    report: &RiskComptrollerReport,
    contains_ref: impl FnMut(&str, RiskEvidenceRefKind) -> bool,
) -> Result<(), TransactionPassportError> {
    validate_comptroller_report(passport, report)?;
    validate_risk_evidence_refs(report, contains_ref)?;
    if report.id != selection.risk_report_ref {
        return Err(claim_failed("selection risk report ref mismatch"));
    }
    if report.order_id != selection.order_id {
        return Err(claim_failed("risk comptroller report order mismatch"));
    }
    if report.subject != selection.selected_provider_subject {
        return Err(claim_failed("risk comptroller report subject mismatch"));
    }
    Ok(())
}

pub(super) fn validate_sla(
    selection: &ProviderSelectionReport,
    sla: &SlaCommitment,
    performance: &SlaPerformanceReport,
    collateral: &CollateralPositionReport,
    guarantee: &GuaranteeDecision,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &sla.schema),
        ("id", &sla.id),
        ("issued_at", &sla.issued_at),
        ("order_id", &sla.order_id),
        ("provider_subject", &sla.provider_subject),
        ("buyer_subject", &sla.buyer_subject),
        ("service_scope", &sla.service_scope),
        ("measurement_policy_ref", &sla.measurement_policy_ref),
        ("exclusions_ref", &sla.exclusions_ref),
        ("remedy_policy_ref", &sla.remedy_policy_ref),
        ("collateral_position_ref", &sla.collateral_position_ref),
        ("guarantee_decision_ref", &sla.guarantee_decision_ref),
        ("signature", &sla.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if sla.order_id != selection.order_id {
        return Err(claim_failed("SLA order mismatch"));
    }
    if sla.provider_subject != selection.selected_provider_subject {
        return Err(claim_failed("SLA provider mismatch"));
    }
    if sla.metric_definitions.is_empty() {
        return Err(claim_failed("SLA metric definitions missing"));
    }
    for metric in &sla.metric_definitions {
        validate_metric_definition(metric)?;
    }
    if sla.collateral_position_ref != collateral.collateral_id {
        return Err(claim_failed("SLA collateral ref mismatch"));
    }
    if sla.guarantee_decision_ref != guarantee.guarantee_id {
        return Err(claim_failed("SLA guarantee ref mismatch"));
    }
    validate_sla_performance(selection, sla, performance)
}

pub(super) fn validate_jurisdiction(
    selection: &ProviderSelectionReport,
    jurisdiction: &AdjudicationJurisdictionReceipt,
    guarantee: &GuaranteeDecision,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &jurisdiction.schema),
        ("id", &jurisdiction.id),
        ("issued_at", &jurisdiction.issued_at),
        ("jurisdiction_id", &jurisdiction.jurisdiction_id),
        ("order_id", &jurisdiction.order_id),
        ("policy_ref", &jurisdiction.policy_ref),
        ("evidence_rules_ref", &jurisdiction.evidence_rules_ref),
        ("signature", &jurisdiction.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if jurisdiction.order_id != selection.order_id {
        return Err(claim_failed("jurisdiction order mismatch"));
    }
    if guarantee.adjudication_jurisdiction_ref != jurisdiction.jurisdiction_id {
        return Err(claim_failed("guarantee jurisdiction mismatch"));
    }
    if jurisdiction.covered_dispute_types.is_empty()
        || jurisdiction.adjudicator_subjects.is_empty()
        || jurisdiction.slash_authority_refs.is_empty()
        || jurisdiction.remedy_limits.is_empty()
    {
        return Err(claim_failed("jurisdiction authority set missing"));
    }
    for value in jurisdiction
        .covered_dispute_types
        .iter()
        .chain(jurisdiction.adjudicator_subjects.iter())
        .chain(jurisdiction.appeal_authority_refs.iter())
        .chain(jurisdiction.slash_authority_refs.iter())
    {
        require_non_empty(value, "jurisdiction authority value")?;
    }
    if !jurisdiction
        .covered_dispute_types
        .iter()
        .any(|dispute_type| dispute_type == "collateral_slash")
    {
        return Err(claim_failed("jurisdiction slash dispute type missing"));
    }
    if !remedy_limit_covers(jurisdiction, &guarantee.currency, guarantee.maximum_remedy) {
        return Err(claim_failed("jurisdiction remedy limit too low"));
    }
    ensure_effective_window_contains(
        &jurisdiction.effective_window,
        &guarantee.claim_window.start,
        "jurisdiction window does not cover guarantee",
    )?;
    ensure_effective_window_contains(
        &jurisdiction.effective_window,
        &guarantee.claim_window.end,
        "jurisdiction window does not cover guarantee",
    )
}

pub(super) fn validate_collateral_guarantee(
    selection: &ProviderSelectionReport,
    sla: &SlaCommitment,
    collateral: &CollateralPositionReport,
    guarantee: &GuaranteeDecision,
    jurisdiction: &AdjudicationJurisdictionReceipt,
) -> Result<(), TransactionPassportError> {
    validate_collateral(selection, collateral)?;
    validate_guarantee(selection, sla, collateral, guarantee)?;
    if !jurisdiction
        .slash_authority_refs
        .iter()
        .any(|authority| authority == &collateral.slash_authority_ref)
    {
        return Err(claim_failed("slash authority not bound to jurisdiction"));
    }
    Ok(())
}

fn validate_sla_performance(
    selection: &ProviderSelectionReport,
    sla: &SlaCommitment,
    performance: &SlaPerformanceReport,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &performance.schema),
        ("id", &performance.id),
        ("issued_at", &performance.issued_at),
        ("performance_id", &performance.performance_id),
        ("sla_ref", &performance.sla_ref),
        ("order_id", &performance.order_id),
        ("provider_subject", &performance.provider_subject),
        (
            "measurement_policy_ref",
            &performance.measurement_policy_ref,
        ),
        ("measured_at", &performance.measured_at),
        ("breach_verdict", &performance.breach_verdict),
        ("signature", &performance.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if performance.sla_ref != sla.id {
        return Err(claim_failed("SLA performance ref mismatch"));
    }
    if performance.order_id != selection.order_id {
        return Err(claim_failed("SLA performance order mismatch"));
    }
    if performance.provider_subject != selection.selected_provider_subject {
        return Err(claim_failed("SLA performance provider mismatch"));
    }
    if performance.measurement_policy_ref != sla.measurement_policy_ref {
        return Err(claim_failed("SLA measurement policy mismatch"));
    }
    if performance.measurement_evidence_refs.is_empty() {
        return Err(claim_failed("SLA measurement evidence missing"));
    }
    for evidence_ref in &performance.measurement_evidence_refs {
        require_non_empty(evidence_ref, "SLA measurement evidence ref")?;
    }
    if performance.computed_metric_results.is_empty() {
        return Err(claim_failed("SLA metric results missing"));
    }
    for result in &performance.computed_metric_results {
        let definition = sla
            .metric_definitions
            .iter()
            .find(|definition| definition.metric == result.metric && definition.unit == result.unit)
            .ok_or_else(|| claim_failed("SLA performance metric mismatch"))?;
        validate_metric_result(result, definition)?;
    }
    for definition in &sla.metric_definitions {
        if !performance
            .computed_metric_results
            .iter()
            .any(|result| result.metric == definition.metric && result.unit == definition.unit)
        {
            return Err(claim_failed("SLA performance metric missing"));
        }
    }
    if performance.breach_verdict != "none" {
        return Err(claim_failed("SLA breach not resolved"));
    }
    ensure_effective_window_contains(
        &sla.effective_window,
        &performance.measured_at,
        "SLA evidence outside effective window",
    )?;
    let _ = &performance.remedy_ref;
    let _ = &performance.dispute_ref;
    Ok(())
}

fn validate_collateral(
    selection: &ProviderSelectionReport,
    collateral: &CollateralPositionReport,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &collateral.schema),
        ("id", &collateral.id),
        ("issued_at", &collateral.issued_at),
        ("collateral_id", &collateral.collateral_id),
        ("subject", &collateral.subject),
        ("order_id", &collateral.order_id),
        ("currency_or_asset", &collateral.currency_or_asset),
        ("source_type", &collateral.source_type),
        ("source_ref", &collateral.source_ref),
        ("lock_start", &collateral.lock_start),
        ("lock_expiry", &collateral.lock_expiry),
        ("claim_priority", &collateral.claim_priority),
        ("slash_authority_ref", &collateral.slash_authority_ref),
        ("release_policy_ref", &collateral.release_policy_ref),
        ("signature", &collateral.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if collateral.subject != selection.selected_provider_subject {
        return Err(claim_failed("collateral subject mismatch"));
    }
    if collateral.order_id != selection.order_id {
        return Err(claim_failed("collateral order mismatch"));
    }
    if currency_is_cross_currency(&collateral.currency_or_asset) {
        return Err(claim_failed("collateral cross-currency netting rejected"));
    }
    if collateral.source_type != "bond" {
        return Err(claim_failed("collateral source type unsupported"));
    }
    if collateral.amount == 0 || collateral.available_amount == 0 {
        return Err(claim_failed("collateral amount missing"));
    }
    if collateral.available_amount > collateral.amount {
        return Err(claim_failed("collateral available amount exceeds amount"));
    }
    for consumed_ref in &collateral.consumed_amount_refs {
        require_non_empty(consumed_ref, "collateral consumed amount ref")?;
    }
    ensure_time_order(
        &collateral.lock_start,
        &collateral.lock_expiry,
        "collateral lock window invalid",
    )
}

fn validate_guarantee(
    selection: &ProviderSelectionReport,
    sla: &SlaCommitment,
    collateral: &CollateralPositionReport,
    guarantee: &GuaranteeDecision,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &guarantee.schema),
        ("id", &guarantee.id),
        ("issued_at", &guarantee.issued_at),
        ("guarantee_id", &guarantee.guarantee_id),
        ("order_id", &guarantee.order_id),
        ("provider_subject", &guarantee.provider_subject),
        ("beneficiary_subject", &guarantee.beneficiary_subject),
        ("guarantee_type", &guarantee.guarantee_type),
        ("currency", &guarantee.currency),
        ("coverage_decision_ref", &guarantee.coverage_decision_ref),
        ("sla_commitment_ref", &guarantee.sla_commitment_ref),
        (
            "adjudication_jurisdiction_ref",
            &guarantee.adjudication_jurisdiction_ref,
        ),
        ("verdict", &guarantee.verdict),
        ("signature", &guarantee.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if guarantee.order_id != selection.order_id {
        return Err(claim_failed("guarantee order mismatch"));
    }
    if guarantee.provider_subject != selection.selected_provider_subject {
        return Err(claim_failed("guarantee provider mismatch"));
    }
    if guarantee.beneficiary_subject != sla.buyer_subject {
        return Err(claim_failed("guarantee beneficiary mismatch"));
    }
    if guarantee.guarantee_type != "bounded_sla_remedy" {
        return Err(claim_failed("guarantee type unsupported"));
    }
    if guarantee.verdict != "backed" {
        return Err(claim_failed("guarantee was not backed"));
    }
    if guarantee.sla_commitment_ref != sla.id {
        return Err(claim_failed("guarantee SLA mismatch"));
    }
    if guarantee.backing_refs.is_empty()
        || !guarantee
            .backing_refs
            .iter()
            .any(|reference| reference == &collateral.collateral_id)
    {
        return Err(claim_failed("guarantee backing missing"));
    }
    if guarantee.currency != collateral.currency_or_asset {
        return Err(claim_failed("guarantee currency mismatch"));
    }
    if guarantee.maximum_remedy == 0 || guarantee.maximum_remedy > collateral.available_amount {
        return Err(claim_failed("guarantee remedy exceeds backing"));
    }
    ensure_time_order(
        &guarantee.claim_window.start,
        &guarantee.claim_window.end,
        "guarantee claim window invalid",
    )?;
    ensure_effective_window_contains(
        &sla.effective_window,
        &guarantee.claim_window.start,
        "guarantee starts outside SLA window",
    )?;
    ensure_effective_window_contains(
        &sla.effective_window,
        &guarantee.claim_window.end,
        "guarantee ends outside SLA window",
    )?;
    ensure_timestamp_at_or_after(
        &guarantee.claim_window.start,
        &collateral.lock_start,
        "collateral lock starts after guarantee claim window",
    )?;
    ensure_timestamp_at_or_after(
        &collateral.lock_expiry,
        &guarantee.claim_window.end,
        "collateral lock expires before guarantee claim window",
    )?;
    ensure_timestamp_at_or_after(
        &collateral.lock_expiry,
        &sla.effective_window.end,
        "collateral lock expires before SLA window",
    )?;
    let _ = &guarantee.exclusions_ref;
    Ok(())
}

impl ProviderDiscoverySnapshot {
    fn contains_available_provider(&self, provider_subject: &str) -> bool {
        self.provider_candidates
            .iter()
            .any(|candidate| candidate.subject == provider_subject && !candidate.excluded)
    }
}

fn validate_provider_candidate(
    candidate: &ProviderCandidate,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("provider subject", &candidate.subject),
        ("provider passport ref", &candidate.provider_passport_ref),
        ("service manifest ref", &candidate.service_manifest_ref),
        ("availability ref", &candidate.availability_ref),
        ("pricing surface ref", &candidate.pricing_surface_ref),
        ("jurisdiction ref", &candidate.jurisdiction_ref),
    ] {
        require_non_empty(value, field)?;
    }
    Ok(())
}

fn validate_ranking(
    selection: &ProviderSelectionReport,
    discovery: &ProviderDiscoverySnapshot,
    contains_override_receipt_ref: &mut impl FnMut(&str) -> bool,
) -> Result<(), TransactionPassportError> {
    let selected = selection
        .ranking_results
        .iter()
        .find(|result| result.provider_subject == selection.selected_provider_subject)
        .ok_or_else(|| claim_failed("selection ranking missing selected provider"))?;
    if selected.rank != 1 && selection.override_receipt_ref.is_empty() {
        return Err(claim_failed(
            "lower-ranked provider selected without override receipt",
        ));
    }
    let top_rank_count = selection
        .ranking_results
        .iter()
        .filter(|result| result.rank == 1)
        .count();
    if top_rank_count != 1 && selection.override_receipt_ref.is_empty() {
        return Err(claim_failed("ranking result rank is ambiguous"));
    }
    if (selected.rank != 1 || top_rank_count != 1)
        && !contains_override_receipt_ref(&selection.override_receipt_ref)
    {
        return Err(claim_failed("selection override receipt missing"));
    }
    let mut ranked_providers = BTreeSet::new();
    for result in &selection.ranking_results {
        require_non_empty(&result.provider_subject, "ranking provider subject")?;
        if !ranked_providers.insert(result.provider_subject.as_str()) {
            return Err(claim_failed("selection ranking duplicate provider"));
        }
        if result.rank == 0 || result.total_score > 100 {
            return Err(claim_failed("ranking result outside policy range"));
        }
    }
    for higher in &selection.ranking_results {
        for lower in &selection.ranking_results {
            if higher.total_score > lower.total_score && higher.rank > lower.rank {
                return Err(claim_failed("selection ranking order mismatch"));
            }
        }
    }
    for candidate in &discovery.provider_candidates {
        if !candidate.excluded && !ranked_providers.contains(candidate.subject.as_str()) {
            return Err(claim_failed(
                "selection ranking missing available candidate",
            ));
        }
    }
    Ok(())
}

fn validate_rejected_candidate_summary(
    summary: &RejectedCandidateSummary,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&summary.provider_subject, "rejected candidate subject")?;
    if summary.reason_codes.is_empty() {
        return Err(claim_failed("rejected candidate reason missing"));
    }
    for reason in &summary.reason_codes {
        require_non_empty(reason, "rejected candidate reason")?;
    }
    let _ = &summary.redacted_fields;
    Ok(())
}

fn validate_metric_definition(metric: &MetricDefinition) -> Result<(), TransactionPassportError> {
    require_non_empty(&metric.metric, "SLA metric")?;
    require_non_empty(&metric.unit, "SLA metric unit")?;
    if metric.target == 0 {
        return Err(claim_failed("SLA metric target missing"));
    }
    Ok(())
}

fn validate_metric_result(
    result: &ComputedMetricResult,
    definition: &MetricDefinition,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&result.metric, "SLA result metric")?;
    require_non_empty(&result.unit, "SLA result unit")?;
    if result.value > definition.target {
        return Err(claim_failed("SLA metric target exceeded"));
    }
    if !result.passed {
        return Err(claim_failed("SLA metric failed"));
    }
    Ok(())
}

fn recompute_score(scorecard: &TrustScorecardSnapshot) -> Result<u64, TransactionPassportError> {
    let mut weight_sum = 0_u64;
    let mut weighted_total = 0_u64;
    for component in &scorecard.component_scores {
        require_non_empty(&component.component, "score component")?;
        require_non_empty(&component.evidence_ref, "score evidence ref")?;
        if component.stale {
            return Err(claim_failed("scorecard component evidence is stale"));
        }
        if component.score < scorecard.score_floor || component.score > scorecard.score_ceiling {
            return Err(claim_failed("scorecard component score outside range"));
        }
        weight_sum = weight_sum
            .checked_add(component.weight)
            .ok_or_else(|| claim_failed("scorecard weight overflow"))?;
        let weighted = component
            .score
            .checked_mul(component.weight)
            .ok_or_else(|| claim_failed("scorecard weighted score overflow"))?;
        weighted_total = weighted_total
            .checked_add(weighted)
            .ok_or_else(|| claim_failed("scorecard weighted score overflow"))?;
    }
    if weight_sum != 100 {
        return Err(claim_failed("scorecard weights must sum to 100"));
    }
    Ok(weighted_total / weight_sum)
}

fn remedy_limit_covers(
    jurisdiction: &AdjudicationJurisdictionReceipt,
    currency: &str,
    maximum_remedy: u64,
) -> bool {
    jurisdiction
        .remedy_limits
        .iter()
        .any(|limit| limit.currency == currency && limit.maximum_remedy >= maximum_remedy)
}

fn currency_is_cross_currency(value: &str) -> bool {
    value.contains(',') || value.contains('+') || value.eq_ignore_ascii_case("multi-currency")
}

fn ensure_freshness_contains(
    window: &FreshnessWindow,
    timestamp: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    let valid_from = parse_time(&window.valid_from, "freshness valid_from")?;
    let valid_until = parse_time(&window.valid_until, "freshness valid_until")?;
    let observed_at = parse_time(timestamp, "freshness timestamp")?;
    if valid_from <= observed_at && observed_at <= valid_until {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn ensure_effective_window_contains(
    window: &EffectiveWindow,
    timestamp: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    let start = parse_time(&window.start, "window start")?;
    let end = parse_time(&window.end, "window end")?;
    let observed_at = parse_time(timestamp, "window timestamp")?;
    if start <= observed_at && observed_at <= end {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn ensure_timestamp_at_or_after(
    candidate: &str,
    minimum: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    let candidate = parse_time(candidate, "candidate timestamp")?;
    let minimum = parse_time(minimum, "minimum timestamp")?;
    if candidate >= minimum {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn ensure_time_order(
    start: &str,
    end: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    let start = parse_time(start, "start timestamp")?;
    let end = parse_time(end, "end timestamp")?;
    if start <= end {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn parse_time(value: &str, field: &'static str) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| claim_failed(format!("{field} is not RFC3339: {error}")))
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::TrustMarketClaimFailed(message.into())
}
