use std::collections::HashSet;

use crate::capability::scope::MonetaryAmount;
use crate::error::AutonomyContractError;
use crate::model::*;

pub fn validate_autonomous_pricing_input(
    input: &AutonomousPricingInputArtifact,
) -> Result<(), AutonomyContractError> {
    if input.schema != CHIO_AUTONOMOUS_PRICING_INPUT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            input.schema.clone(),
        ));
    }
    ensure_non_empty(&input.input_id, "autonomous_pricing_input.input_id")?;
    ensure_non_empty(&input.subject_key, "autonomous_pricing_input.subject_key")?;
    ensure_non_empty(&input.provider_id, "autonomous_pricing_input.provider_id")?;
    validate_currency_code(&input.currency, "autonomous_pricing_input.currency")?;
    validate_positive_money(
        &input.requested_coverage_amount,
        "autonomous_pricing_input.requested_coverage_amount",
    )?;
    if !money_currency_matches_declared(&input.requested_coverage_amount, &input.currency) {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input coverage amount currency must match currency".to_string(),
        ));
    }
    if input.receipt_history_window_secs == 0 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input receipt_history_window_secs must be non-zero".to_string(),
        ));
    }
    if input.reputation_score_bps > 10_000 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input reputation_score_bps must be <= 10000".to_string(),
        ));
    }
    if input.available_capital_units == 0 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input available_capital_units must be non-zero".to_string(),
        ));
    }
    if input.evidence_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_pricing_input.evidence_refs",
        ));
    }

    let mut ids = HashSet::new();
    let mut kinds = HashSet::new();
    for evidence in &input.evidence_refs {
        ensure_non_empty(
            &evidence.reference_id,
            "autonomous_pricing_input.evidence_refs.reference_id",
        )?;
        if !ids.insert(evidence.reference_id.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(
                evidence.reference_id.clone(),
            ));
        }
        kinds.insert(evidence.kind);
    }
    for required in [
        AutonomousEvidenceKind::UnderwritingDecision,
        AutonomousEvidenceKind::ExposureLedger,
        AutonomousEvidenceKind::CreditScorecard,
        AutonomousEvidenceKind::CapitalBook,
    ] {
        if !kinds.contains(&required) {
            return Err(AutonomyContractError::UnknownReference(format!(
                "autonomous pricing input missing required evidence {:?}",
                required
            )));
        }
    }
    if (input.pending_loss_units > 0 || input.settled_loss_units > 0)
        && !kinds.contains(&AutonomousEvidenceKind::CreditLossLifecycle)
    {
        return Err(AutonomyContractError::UnknownReference(
            "autonomous pricing input with loss units must include credit_loss_lifecycle evidence"
                .to_string(),
        ));
    }
    if input.latest_web3_settlement_state.is_some()
        && !kinds.contains(&AutonomousEvidenceKind::Web3SettlementReceipt)
    {
        return Err(AutonomyContractError::UnknownReference(
            "autonomous pricing input with latest_web3_settlement_state must include web3_settlement_receipt evidence"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_autonomous_pricing_authority_envelope(
    envelope: &AutonomousPricingAuthorityEnvelopeArtifact,
) -> Result<(), AutonomyContractError> {
    if envelope.schema != CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            envelope.schema.clone(),
        ));
    }
    ensure_non_empty(
        &envelope.envelope_id,
        "autonomous_authority_envelope.envelope_id",
    )?;
    ensure_non_empty(
        &envelope.subject_key,
        "autonomous_authority_envelope.subject_key",
    )?;
    ensure_non_empty(
        &envelope.provider_id,
        "autonomous_authority_envelope.provider_id",
    )?;
    validate_currency_code(&envelope.currency, "autonomous_authority_envelope.currency")?;
    if envelope.permitted_actions.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_authority_envelope.permitted_actions",
        ));
    }
    ensure_unique_copy_values(
        &envelope.permitted_actions,
        "autonomous_authority_envelope.permitted_actions",
    )?;
    if envelope.authority_chain_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_authority_envelope.authority_chain_refs",
        ));
    }
    ensure_unique_strings(
        &envelope.authority_chain_refs,
        "autonomous_authority_envelope.authority_chain_refs",
    )?;
    validate_positive_money(
        &envelope.max_coverage_amount,
        "autonomous_authority_envelope.max_coverage_amount",
    )?;
    validate_positive_money(
        &envelope.max_premium_amount,
        "autonomous_authority_envelope.max_premium_amount",
    )?;
    if !money_currency_matches_declared(&envelope.max_coverage_amount, &envelope.currency) {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_coverage_amount currency must match envelope currency"
                .to_string(),
        ));
    }
    if !money_currency_matches_declared(&envelope.max_premium_amount, &envelope.currency) {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_premium_amount currency must match envelope currency"
                .to_string(),
        ));
    }
    if envelope.max_rate_change_bps == 0 || envelope.max_rate_change_bps > 10_000 {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_rate_change_bps must be between 1 and 10000".to_string(),
        ));
    }
    if envelope.max_daily_decisions == 0 {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_daily_decisions must be non-zero".to_string(),
        ));
    }
    if let Some(threshold) = envelope.requires_human_review_above_premium.as_ref() {
        validate_positive_money(
            threshold,
            "autonomous_authority_envelope.requires_human_review_above_premium",
        )?;
        if !money_currency_matches_declared(threshold, &envelope.currency) {
            return Err(AutonomyContractError::InvalidEnvelope(
                "autonomous authority premium review threshold currency must match envelope currency"
                    .to_string(),
            ));
        }
        if threshold.units > envelope.max_premium_amount.units {
            return Err(AutonomyContractError::InvalidEnvelope(
                "autonomous authority premium review threshold cannot exceed max_premium_amount"
                    .to_string(),
            ));
        }
    }
    if envelope.not_before >= envelope.not_after {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority not_before must be earlier than not_after".to_string(),
        ));
    }
    match envelope.kind {
        AutonomousAuthorityEnvelopeKind::OperatorPolicy => {}
        AutonomousAuthorityEnvelopeKind::RegulatedRole => {
            ensure_non_empty(
                envelope.regulated_role.as_deref().unwrap_or_default(),
                "autonomous_authority_envelope.regulated_role",
            )?;
        }
        AutonomousAuthorityEnvelopeKind::DelegatedMarketAuthority => {
            ensure_non_empty(
                envelope
                    .delegated_authority_reference
                    .as_deref()
                    .unwrap_or_default(),
                "autonomous_authority_envelope.delegated_authority_reference",
            )?;
        }
    }
    if envelope.automation_mode != AutonomousAutomationMode::Active
        && envelope
            .permitted_actions
            .contains(&AutonomousPricingAction::Bind)
    {
        return Err(AutonomyContractError::InvalidEnvelope(
            "only active automation envelopes may permit bind".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_autonomous_pricing_decision(
    decision: &AutonomousPricingDecisionArtifact,
) -> Result<(), AutonomyContractError> {
    if decision.schema != CHIO_AUTONOMOUS_PRICING_DECISION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            decision.schema.clone(),
        ));
    }
    ensure_non_empty(
        &decision.decision_id,
        "autonomous_pricing_decision.decision_id",
    )?;
    validate_autonomous_pricing_input(&decision.pricing_input)?;
    validate_autonomous_pricing_authority_envelope(&decision.authority_envelope)?;
    validate_model_provenance(&decision.model)?;
    validate_positive_money(
        &decision.suggested_coverage_amount,
        "autonomous_pricing_decision.suggested_coverage_amount",
    )?;
    validate_positive_money(
        &decision.suggested_premium_amount,
        "autonomous_pricing_decision.suggested_premium_amount",
    )?;
    if !money_currency_matches_declared(
        &decision.suggested_coverage_amount,
        &decision.authority_envelope.currency,
    ) || !money_currency_matches_declared(
        &decision.suggested_premium_amount,
        &decision.authority_envelope.currency,
    ) {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision money fields must match envelope currency".to_string(),
        ));
    }
    if decision.pricing_input.subject_key != decision.authority_envelope.subject_key
        || decision.pricing_input.provider_id != decision.authority_envelope.provider_id
        || decision.pricing_input.currency != decision.authority_envelope.currency
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision input must match authority envelope subject/provider/currency"
                .to_string(),
        ));
    }
    if decision.suggested_coverage_amount.units
        > decision.authority_envelope.max_coverage_amount.units
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision coverage exceeds authority envelope".to_string(),
        ));
    }
    if decision.suggested_premium_amount.units
        > decision.authority_envelope.max_premium_amount.units
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision premium exceeds authority envelope".to_string(),
        ));
    }
    if let Some(ceiling_factor_bps) = decision.suggested_ceiling_factor_bps {
        if ceiling_factor_bps == 0 || ceiling_factor_bps > 10_000 {
            return Err(AutonomyContractError::InvalidDecision(
                "autonomous pricing decision suggested_ceiling_factor_bps must be between 1 and 10000"
                    .to_string(),
            ));
        }
    }
    if decision.confidence_bps == 0 || decision.confidence_bps > 10_000 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision confidence_bps must be between 1 and 10000".to_string(),
        ));
    }
    if decision.explanation_factors.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_pricing_decision.explanation_factors",
        ));
    }
    let mut factor_codes = HashSet::new();
    for factor in &decision.explanation_factors {
        ensure_non_empty(
            &factor.code,
            "autonomous_pricing_decision.explanation_factors.code",
        )?;
        ensure_non_empty(
            &factor.description,
            "autonomous_pricing_decision.explanation_factors.description",
        )?;
        if factor.weight_bps == 0 || factor.weight_bps > 10_000 {
            return Err(AutonomyContractError::InvalidDecision(
                "autonomous pricing explanation factor weight_bps must be between 1 and 10000"
                    .to_string(),
            ));
        }
        if !factor_codes.insert(factor.code.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(factor.code.clone()));
        }
    }
    if decision.authority_envelope.automation_mode == AutonomousAutomationMode::Shadow
        && decision.review_state != AutonomousDecisionReviewState::ShadowOnly
    {
        return Err(AutonomyContractError::InvalidDecision(
            "shadow automation decisions must use review_state shadow_only".to_string(),
        ));
    }
    if decision.review_state == AutonomousDecisionReviewState::ShadowOnly
        && decision.authority_envelope.automation_mode != AutonomousAutomationMode::Shadow
    {
        return Err(AutonomyContractError::InvalidDecision(
            "review_state shadow_only requires a shadow automation envelope".to_string(),
        ));
    }
    if decision.disposition == AutonomousPricingDisposition::ManualReview
        && decision.review_state == AutonomousDecisionReviewState::AutoApproved
    {
        return Err(AutonomyContractError::InvalidDecision(
            "manual-review pricing decisions cannot be auto approved".to_string(),
        ));
    }
    if let Some(threshold) = decision
        .authority_envelope
        .requires_human_review_above_premium
        .as_ref()
    {
        if decision.review_state == AutonomousDecisionReviewState::AutoApproved
            && decision.suggested_premium_amount.units > threshold.units
        {
            return Err(AutonomyContractError::InvalidDecision(
                "auto-approved pricing decisions cannot exceed the premium review threshold"
                    .to_string(),
            ));
        }
    }
    if decision.disposition == AutonomousPricingDisposition::BindWithinEnvelope {
        if !decision
            .authority_envelope
            .permitted_actions
            .contains(&AutonomousPricingAction::Bind)
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions require bind permission in the authority envelope"
                    .to_string(),
            ));
        }
        if !decision
            .authority_envelope
            .support_boundary
            .live_bind_supported
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions require live_bind_supported".to_string(),
            ));
        }
        if decision.authority_envelope.requires_human_review_for_bind
            && decision.review_state == AutonomousDecisionReviewState::AutoApproved
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions cannot be auto approved when human review is required for bind"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_capital_pool_optimization(
    optimization: &CapitalPoolOptimizationArtifact,
) -> Result<(), AutonomyContractError> {
    if optimization.schema != CHIO_CAPITAL_POOL_OPTIMIZATION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            optimization.schema.clone(),
        ));
    }
    ensure_non_empty(
        &optimization.optimization_id,
        "capital_pool_optimization.optimization_id",
    )?;
    ensure_non_empty(
        &optimization.subject_key,
        "capital_pool_optimization.subject_key",
    )?;
    validate_currency_code(&optimization.currency, "capital_pool_optimization.currency")?;
    ensure_non_empty(
        &optimization.pricing_decision_ref,
        "capital_pool_optimization.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &optimization.capital_book_ref,
        "capital_pool_optimization.capital_book_ref",
    )?;
    if optimization.facility_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_optimization.facility_refs",
        ));
    }
    ensure_unique_strings(
        &optimization.facility_refs,
        "capital_pool_optimization.facility_refs",
    )?;
    ensure_unique_strings(
        &optimization.pending_claim_refs,
        "capital_pool_optimization.pending_claim_refs",
    )?;
    if optimization.target_reserve_ratio_bps == 0 || optimization.target_reserve_ratio_bps > 10_000
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization target_reserve_ratio_bps must be between 1 and 10000"
                .to_string(),
        ));
    }
    if optimization.max_facility_utilization_bps == 0
        || optimization.max_facility_utilization_bps > 10_000
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization max_facility_utilization_bps must be between 1 and 10000"
                .to_string(),
        ));
    }
    if optimization.max_bind_capacity_units == 0 {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization max_bind_capacity_units must be non-zero".to_string(),
        ));
    }
    if optimization.recommendations.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_optimization.recommendations",
        ));
    }
    for recommendation in &optimization.recommendations {
        ensure_non_empty(
            &recommendation.source_ref,
            "capital_pool_optimization.recommendations.source_ref",
        )?;
        ensure_non_empty(
            &recommendation.rationale,
            "capital_pool_optimization.recommendations.rationale",
        )?;
        validate_positive_money(
            &recommendation.amount,
            "capital_pool_optimization.recommendations.amount",
        )?;
        if !money_currency_matches_declared(&recommendation.amount, &optimization.currency) {
            return Err(AutonomyContractError::InvalidOptimization(
                "capital pool optimization recommendation amounts must match optimization currency"
                    .to_string(),
            ));
        }
        if recommendation.action == CapitalOptimizationAction::ShiftCapacity
            && recommendation
                .destination_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(AutonomyContractError::InvalidOptimization(
                "shift-capacity recommendations require destination_ref".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_capital_pool_simulation_report(
    report: &CapitalPoolSimulationReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_CAPITAL_POOL_SIMULATION_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(
        &report.simulation_id,
        "capital_pool_simulation.simulation_id",
    )?;
    ensure_non_empty(&report.subject_key, "capital_pool_simulation.subject_key")?;
    validate_currency_code(&report.currency, "capital_pool_simulation.currency")?;
    validate_capital_pool_optimization(&report.baseline_optimization)?;
    validate_capital_pool_optimization(&report.candidate_optimization)?;
    if report.baseline_optimization.subject_key != report.subject_key
        || report.candidate_optimization.subject_key != report.subject_key
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation subject_key must match both baseline and candidate optimizations"
                .to_string(),
        ));
    }
    if report.baseline_optimization.currency != report.currency
        || report.candidate_optimization.currency != report.currency
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation currency must match both baseline and candidate optimizations"
                .to_string(),
        ));
    }
    if report.baseline_optimization.optimization_id == report.candidate_optimization.optimization_id
    {
        return Err(AutonomyContractError::DuplicateValue(
            report.baseline_optimization.optimization_id.clone(),
        ));
    }
    if !report
        .baseline_optimization
        .support_boundary
        .scenario_comparison_supported
        || !report
            .candidate_optimization
            .support_boundary
            .scenario_comparison_supported
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation requires scenario_comparison_supported on both optimizations"
                .to_string(),
        ));
    }
    if report.deltas.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_simulation.deltas",
        ));
    }
    for delta in &report.deltas {
        ensure_non_empty(
            &delta.metric_name,
            "capital_pool_simulation.deltas.metric_name",
        )?;
        ensure_non_empty(
            &delta.description,
            "capital_pool_simulation.deltas.description",
        )?;
    }
    ensure_non_empty(
        &report.recommended_operator_action,
        "capital_pool_simulation.recommended_operator_action",
    )?;
    Ok(())
}

pub fn validate_autonomous_execution_decision(
    decision: &AutonomousExecutionDecisionArtifact,
) -> Result<(), AutonomyContractError> {
    if decision.schema != CHIO_AUTONOMOUS_EXECUTION_DECISION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            decision.schema.clone(),
        ));
    }
    for (value, field) in [
        (&decision.execution_id, "autonomous_execution.execution_id"),
        (
            &decision.pricing_decision_ref,
            "autonomous_execution.pricing_decision_ref",
        ),
        (
            &decision.optimization_ref,
            "autonomous_execution.optimization_ref",
        ),
        (
            &decision.authority_envelope_ref,
            "autonomous_execution.authority_envelope_ref",
        ),
        (&decision.subject_key, "autonomous_execution.subject_key"),
        (&decision.provider_id, "autonomous_execution.provider_id"),
    ] {
        ensure_non_empty(value, field)?;
    }
    validate_currency_code(&decision.currency, "autonomous_execution.currency")?;
    if decision.safety_gates.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_execution.safety_gates",
        ));
    }
    let mut gate_names = HashSet::new();
    for gate in &decision.safety_gates {
        ensure_non_empty(&gate.name, "autonomous_execution.safety_gates.name")?;
        ensure_non_empty(
            &gate.description,
            "autonomous_execution.safety_gates.description",
        )?;
        if !gate_names.insert(gate.name.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(gate.name.clone()));
        }
    }
    validate_rollback_control(&decision.rollback_control)?;

    let all_gates_passed = decision.safety_gates.iter().all(|gate| gate.passed);
    if decision.lifecycle_state == AutonomousExecutionLifecycleState::Executed && !all_gates_passed
    {
        return Err(AutonomyContractError::InvalidExecution(
            "executed autonomous actions require all safety gates to pass".to_string(),
        ));
    }
    if decision.lifecycle_state == AutonomousExecutionLifecycleState::Blocked && all_gates_passed {
        return Err(AutonomyContractError::InvalidExecution(
            "blocked autonomous actions require at least one failed safety gate".to_string(),
        ));
    }

    match decision.action {
        AutonomousExecutionAction::Reprice | AutonomousExecutionAction::Renew => {
            ensure_non_empty(
                decision.quote_response_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.quote_response_ref",
            )?;
            if decision.auto_bind_decision_ref.is_some()
                || decision.bound_coverage_ref.is_some()
                || decision.settlement_dispatch_ref.is_some()
            {
                return Err(AutonomyContractError::InvalidExecution(
                    "reprice and renew automation cannot embed bind or settlement references"
                        .to_string(),
                ));
            }
        }
        AutonomousExecutionAction::Decline => {
            if decision.auto_bind_decision_ref.is_some()
                || decision.bound_coverage_ref.is_some()
                || decision.settlement_dispatch_ref.is_some()
            {
                return Err(AutonomyContractError::InvalidExecution(
                    "decline automation cannot embed bind or settlement references".to_string(),
                ));
            }
        }
        AutonomousExecutionAction::Bind => {
            ensure_non_empty(
                decision.quote_response_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.quote_response_ref",
            )?;
            ensure_non_empty(
                decision
                    .auto_bind_decision_ref
                    .as_deref()
                    .unwrap_or_default(),
                "autonomous_execution.auto_bind_decision_ref",
            )?;
            ensure_non_empty(
                decision.bound_coverage_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.bound_coverage_ref",
            )?;
            if decision.lifecycle_state == AutonomousExecutionLifecycleState::Executed {
                ensure_non_empty(
                    decision
                        .settlement_dispatch_ref
                        .as_deref()
                        .unwrap_or_default(),
                    "autonomous_execution.settlement_dispatch_ref",
                )?;
            }
        }
    }

    Ok(())
}

pub fn validate_autonomous_comparison_report(
    report: &AutonomousComparisonReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_AUTONOMOUS_COMPARISON_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.comparison_id, "autonomous_comparison.comparison_id")?;
    ensure_non_empty(
        &report.pricing_decision_ref,
        "autonomous_comparison.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &report.manual_decision_ref,
        "autonomous_comparison.manual_decision_ref",
    )?;
    if report.disposition != AutonomousComparisonDisposition::Match && report.deltas.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_comparison.deltas",
        ));
    }
    if report.disposition == AutonomousComparisonDisposition::ManualOverride {
        ensure_non_empty(
            report.override_reference.as_deref().unwrap_or_default(),
            "autonomous_comparison.override_reference",
        )?;
    }
    for delta in &report.deltas {
        for (value, field) in [
            (&delta.field, "autonomous_comparison.deltas.field"),
            (
                &delta.automated_value,
                "autonomous_comparison.deltas.automated_value",
            ),
            (
                &delta.manual_value,
                "autonomous_comparison.deltas.manual_value",
            ),
            (
                &delta.description,
                "autonomous_comparison.deltas.description",
            ),
        ] {
            ensure_non_empty(value, field)?;
        }
    }
    Ok(())
}

pub fn validate_autonomous_drift_report(
    report: &AutonomousDriftReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_AUTONOMOUS_DRIFT_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.drift_report_id, "autonomous_drift.drift_report_id")?;
    ensure_non_empty(&report.subject_key, "autonomous_drift.subject_key")?;
    ensure_non_empty(
        &report.pricing_decision_ref,
        "autonomous_drift.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &report.optimization_ref,
        "autonomous_drift.optimization_ref",
    )?;
    validate_autonomous_rollback_plan(&report.rollback_plan)?;
    validate_autonomous_comparison_report(&report.comparison_report)?;
    if report.drift_signals.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_drift.drift_signals",
        ));
    }
    let mut critical_kinds = HashSet::new();
    for signal in &report.drift_signals {
        ensure_non_empty(&signal.metric_name, "autonomous_drift.metric_name")?;
        ensure_non_empty(&signal.description, "autonomous_drift.description")?;
        if signal.threshold_value == 0 {
            return Err(AutonomyContractError::InvalidDrift(
                "autonomous drift threshold_value must be non-zero".to_string(),
            ));
        }
        if signal.severity == AutonomousDriftSeverity::Critical {
            critical_kinds.insert(signal.kind);
        }
    }
    if !critical_kinds.is_empty() && !report.fail_safe_engaged {
        return Err(AutonomyContractError::InvalidDrift(
            "critical drift signals require fail_safe_engaged".to_string(),
        ));
    }
    for kind in critical_kinds {
        if !report.rollback_plan.triggers.contains(&kind) {
            return Err(AutonomyContractError::InvalidDrift(format!(
                "rollback plan does not cover critical drift trigger {:?}",
                kind
            )));
        }
    }
    Ok(())
}

pub fn validate_autonomous_rollback_plan(
    plan: &AutonomousRollbackPlanArtifact,
) -> Result<(), AutonomyContractError> {
    if plan.schema != CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            plan.schema.clone(),
        ));
    }
    ensure_non_empty(&plan.plan_id, "autonomous_rollback.plan_id")?;
    ensure_non_empty(&plan.subject_key, "autonomous_rollback.subject_key")?;
    if plan.triggers.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_rollback.triggers",
        ));
    }
    if plan.actions.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_rollback.actions",
        ));
    }
    ensure_unique_copy_values(&plan.triggers, "autonomous_rollback.triggers")?;
    ensure_unique_copy_values(&plan.actions, "autonomous_rollback.actions")?;
    Ok(())
}

pub fn validate_autonomous_qualification_matrix(
    matrix: &AutonomousQualificationMatrix,
) -> Result<(), AutonomyContractError> {
    if matrix.schema != CHIO_AUTONOMOUS_QUALIFICATION_MATRIX_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    ensure_non_empty(&matrix.profile_id, "autonomous_qualification.profile_id")?;
    if matrix.cases.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_qualification.cases",
        ));
    }
    let mut seen_ids = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "autonomous_qualification.cases.id")?;
        ensure_non_empty(&case.name, "autonomous_qualification.cases.name")?;
        ensure_non_empty(&case.notes, "autonomous_qualification.cases.notes")?;
        if case.requirement_ids.is_empty() {
            return Err(AutonomyContractError::InvalidQualificationCase(format!(
                "qualification case `{}` requires at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "autonomous_qualification.cases.requirement_ids",
        )?;
        if !seen_ids.insert(case.id.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(case.id.clone()));
        }
    }
    Ok(())
}

fn validate_model_provenance(
    model: &AutonomousModelProvenance,
) -> Result<(), AutonomyContractError> {
    for (value, field) in [
        (&model.model_id, "autonomous_model.model_id"),
        (&model.model_version, "autonomous_model.model_version"),
        (&model.engine_family, "autonomous_model.engine_family"),
        (&model.input_hash, "autonomous_model.input_hash"),
        (
            &model.explanation_version,
            "autonomous_model.explanation_version",
        ),
    ] {
        ensure_non_empty(value, field)?;
    }
    if model.training_cutoff > model.published_at {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous model training_cutoff must be <= published_at".to_string(),
        ));
    }
    Ok(())
}

fn validate_rollback_control(
    control: &AutonomousExecutionRollbackControl,
) -> Result<(), AutonomyContractError> {
    ensure_non_empty(
        &control.rollback_plan_ref,
        "autonomous_execution.rollback_control.rollback_plan_ref",
    )?;
    ensure_non_empty(
        &control.human_interrupt_contact,
        "autonomous_execution.rollback_control.human_interrupt_contact",
    )?;
    Ok(())
}

fn validate_positive_money(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    if amount.units == 0 {
        return Err(AutonomyContractError::InvalidDecision(format!(
            "{field} must be greater than zero"
        )));
    }
    validate_currency_code(&amount.currency, field)
}

pub(super) fn money_currency_matches_declared(
    amount: &MonetaryAmount,
    declared_currency: &str,
) -> bool {
    amount.currency == declared_currency
}

fn validate_currency_code(
    currency: &str,
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    if currency.len() != 3
        || !currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(AutonomyContractError::InvalidDecision(format!(
            "{field} must be a 3-letter uppercase currency code"
        )));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), AutonomyContractError> {
    if value.trim().is_empty() {
        return Err(AutonomyContractError::MissingField(field));
    }
    Ok(())
}

pub(super) fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    let mut seen = HashSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if value.trim() != value {
            return Err(AutonomyContractError::InvalidDecision(format!(
                "{field} must not contain values with surrounding whitespace"
            )));
        }
        if !seen.insert(value.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), AutonomyContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(AutonomyContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}
