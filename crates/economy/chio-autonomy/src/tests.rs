use super::*;
use crate::capability::{runtime_attestation::RuntimeAssuranceTier, scope::MonetaryAmount};
use crate::market::LiabilityCoverageClass;
use crate::validation::{ensure_unique_strings, money_currency_matches_declared};
use crate::web3::settlement::Web3SettlementLifecycleState;

fn parse_fixture<T>(fixture: &'static str, body: &str) -> T
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("{fixture} fixture must parse: {error}"))
}

fn require_valid<T, E>(result: Result<T, E>, context: &'static str) -> T
where
    E: std::fmt::Debug,
{
    result.unwrap_or_else(|error| panic!("{context} should validate: {error:?}"))
}

fn sample_input() -> AutonomousPricingInputArtifact {
    AutonomousPricingInputArtifact {
        schema: CHIO_AUTONOMOUS_PRICING_INPUT_SCHEMA.to_string(),
        input_id: "api-1".to_string(),
        generated_at: 1_743_379_200,
        subject_key: "subject-1".to_string(),
        provider_id: "carrier-1".to_string(),
        coverage_class: LiabilityCoverageClass::ProfessionalLiability,
        currency: "USD".to_string(),
        requested_coverage_amount: MonetaryAmount {
            units: 120_000,
            currency: "USD".to_string(),
        },
        receipt_history_window_secs: 2_592_000,
        reputation_score_bps: 8_200,
        runtime_assurance_tier: RuntimeAssuranceTier::Verified,
        pending_loss_units: 0,
        settled_loss_units: 2_500,
        available_capital_units: 600_000,
        latest_web3_settlement_state: Some(Web3SettlementLifecycleState::Settled),
        evidence_refs: vec![
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::UnderwritingDecision,
                reference_id: "uwd-1".to_string(),
                observed_at: Some(1_743_379_100),
                locator: Some("underwriting:uwd-1".to_string()),
            },
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::ExposureLedger,
                reference_id: "eld-1".to_string(),
                observed_at: Some(1_743_379_100),
                locator: Some("ledger:eld-1".to_string()),
            },
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::CreditScorecard,
                reference_id: "score-1".to_string(),
                observed_at: Some(1_743_379_050),
                locator: Some("scorecard:score-1".to_string()),
            },
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::CapitalBook,
                reference_id: "cb-1".to_string(),
                observed_at: Some(1_743_379_150),
                locator: Some("capital-book:cb-1".to_string()),
            },
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::CreditLossLifecycle,
                reference_id: "loss-1".to_string(),
                observed_at: Some(1_743_378_900),
                locator: Some("loss:loss-1".to_string()),
            },
            AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                reference_id: "receipt-web3-1".to_string(),
                observed_at: Some(1_743_379_000),
                locator: Some("web3-settlement:receipt-web3-1".to_string()),
            },
        ],
        support_boundary: AutonomousPricingSupportBoundary::default(),
        note: Some("Feeds one bounded autonomous pricing decision over Chio truth.".to_string()),
    }
}

fn sample_authority_envelope() -> AutonomousPricingAuthorityEnvelopeArtifact {
    AutonomousPricingAuthorityEnvelopeArtifact {
        schema: CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE_SCHEMA.to_string(),
        envelope_id: "ape-1".to_string(),
        issued_at: 1_743_379_200,
        subject_key: "subject-1".to_string(),
        provider_id: "carrier-1".to_string(),
        currency: "USD".to_string(),
        kind: AutonomousAuthorityEnvelopeKind::DelegatedMarketAuthority,
        automation_mode: AutonomousAutomationMode::Active,
        permitted_actions: vec![
            AutonomousPricingAction::Reprice,
            AutonomousPricingAction::Renew,
            AutonomousPricingAction::Decline,
            AutonomousPricingAction::Bind,
        ],
        authority_chain_refs: vec![
            "underwriting-committee-approval".to_string(),
            "operator-treasury-approval".to_string(),
        ],
        max_coverage_amount: MonetaryAmount {
            units: 150_000,
            currency: "USD".to_string(),
        },
        max_premium_amount: MonetaryAmount {
            units: 6_000,
            currency: "USD".to_string(),
        },
        max_rate_change_bps: 750,
        max_daily_decisions: 20,
        requires_human_review_for_bind: false,
        requires_human_review_above_premium: Some(MonetaryAmount {
            units: 5_000,
            currency: "USD".to_string(),
        }),
        regulated_role: None,
        delegated_authority_reference: Some("lpa-1".to_string()),
        not_before: 1_743_379_200,
        not_after: 1_743_465_600,
        support_boundary: AutonomousPricingSupportBoundary::default(),
        note: Some("Binds automation to one delegated pricing authority envelope.".to_string()),
    }
}

fn sample_decision() -> AutonomousPricingDecisionArtifact {
    AutonomousPricingDecisionArtifact {
        schema: CHIO_AUTONOMOUS_PRICING_DECISION_SCHEMA.to_string(),
        decision_id: "apd-1".to_string(),
        issued_at: 1_743_379_260,
        pricing_input: sample_input(),
        model: AutonomousModelProvenance {
            model_id: "pricing-model-chio-1".to_string(),
            model_version: "2026.03.31".to_string(),
            engine_family: "gradient_boosted_policy".to_string(),
            published_at: 1_743_379_000,
            training_cutoff: 1_743_292_800,
            input_hash: "4e4efc0ad4f8c80ad4c76f2f3ae2122e9b6cf407cdb2d43516c8f8e4dfd2c1df"
                .to_string(),
            explanation_version: "counterfactual-v1".to_string(),
            supports_counterfactuals: true,
            supports_shadow_evaluation: true,
        },
        authority_envelope: sample_authority_envelope(),
        disposition: AutonomousPricingDisposition::BindWithinEnvelope,
        review_state: AutonomousDecisionReviewState::AutoApproved,
        suggested_coverage_amount: MonetaryAmount {
            units: 110_000,
            currency: "USD".to_string(),
        },
        suggested_premium_amount: MonetaryAmount {
            units: 4_800,
            currency: "USD".to_string(),
        },
        suggested_ceiling_factor_bps: Some(9_000),
        confidence_bps: 8_700,
        explanation_factors: vec![
            AutonomousPricingExplanationFactor {
                code: "strong-runtime-assurance".to_string(),
                description: "Verified runtime assurance supports automated bind posture."
                    .to_string(),
                direction: AutonomousPricingExplanationDirection::Decrease,
                weight_bps: 2_500,
                evidence_refs: vec![AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::RuntimeAssuranceAppraisal,
                    reference_id: "raa-1".to_string(),
                    observed_at: Some(1_743_379_000),
                    locator: Some("appraisal:raa-1".to_string()),
                }],
            },
            AutonomousPricingExplanationFactor {
                code: "settled-web3-history".to_string(),
                description:
                    "Recent settled web3 history reduces uncertainty for automated renewal and bind."
                        .to_string(),
                direction: AutonomousPricingExplanationDirection::Decrease,
                weight_bps: 2_000,
                evidence_refs: vec![AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                    reference_id: "receipt-web3-1".to_string(),
                    observed_at: Some(1_743_379_000),
                    locator: Some("web3-settlement:receipt-web3-1".to_string()),
                }],
            },
        ],
        comparison_baseline_ref: Some("uwd-1".to_string()),
        note: Some("Auto-approves one renewal/bind decision inside the active envelope.".to_string()),
    }
}

fn sample_optimization() -> CapitalPoolOptimizationArtifact {
    CapitalPoolOptimizationArtifact {
        schema: CHIO_CAPITAL_POOL_OPTIMIZATION_SCHEMA.to_string(),
        optimization_id: "cpo-1".to_string(),
        issued_at: 1_743_379_320,
        subject_key: "subject-1".to_string(),
        currency: "USD".to_string(),
        pricing_decision_ref: "apd-1".to_string(),
        capital_book_ref: "cb-1".to_string(),
        facility_refs: vec!["facility-1".to_string(), "facility-2".to_string()],
        pending_claim_refs: vec!["claim-1".to_string()],
        target_reserve_ratio_bps: 3_500,
        max_facility_utilization_bps: 7_000,
        max_bind_capacity_units: 250_000,
        recommendations: vec![
            CapitalPoolRecommendation {
                action: CapitalOptimizationAction::IncreaseReserve,
                source_ref: "pool:primary".to_string(),
                destination_ref: None,
                amount: MonetaryAmount {
                    units: 25_000,
                    currency: "USD".to_string(),
                },
                rationale: "Raise reserve coverage before new autonomous binds.".to_string(),
            },
            CapitalPoolRecommendation {
                action: CapitalOptimizationAction::ShiftCapacity,
                source_ref: "facility-2".to_string(),
                destination_ref: Some("facility-1".to_string()),
                amount: MonetaryAmount {
                    units: 15_000,
                    currency: "USD".to_string(),
                },
                rationale: "Move capacity toward the lower-loss facility.".to_string(),
            },
        ],
        support_boundary: CapitalPoolOptimizationSupportBoundary::default(),
        note: Some("Keeps optimization bounded and override-ready.".to_string()),
    }
}

fn sample_simulation() -> CapitalPoolSimulationReport {
    let baseline = sample_optimization();
    let mut candidate = sample_optimization();
    candidate.optimization_id = "cpo-2".to_string();
    candidate.target_reserve_ratio_bps = 4_000;
    candidate.max_bind_capacity_units = 230_000;
    CapitalPoolSimulationReport {
        schema: CHIO_CAPITAL_POOL_SIMULATION_REPORT_SCHEMA.to_string(),
        simulation_id: "cps-1".to_string(),
        generated_at: 1_743_379_380,
        subject_key: "subject-1".to_string(),
        currency: "USD".to_string(),
        baseline_optimization: baseline,
        candidate_optimization: candidate,
        simulation_mode: CapitalPoolSimulationMode::WhatIf,
        deltas: vec![
            CapitalPoolSimulationDelta {
                metric_name: "reserve_ratio_bps".to_string(),
                baseline_units: 3_500,
                candidate_units: 4_000,
                description: "Candidate scenario raises the reserve floor by 500 bps.".to_string(),
            },
            CapitalPoolSimulationDelta {
                metric_name: "max_bind_capacity_units".to_string(),
                baseline_units: 250_000,
                candidate_units: 230_000,
                description:
                    "Candidate scenario trims bind capacity to create more reserve headroom."
                        .to_string(),
            },
        ],
        recommended_operator_action:
            "Adopt the candidate reserve posture for the next renewal cohort.".to_string(),
        note: Some(
            "Compares baseline and candidate capital strategies without mutating live state."
                .to_string(),
        ),
    }
}

fn sample_execution_decision() -> AutonomousExecutionDecisionArtifact {
    AutonomousExecutionDecisionArtifact {
        schema: CHIO_AUTONOMOUS_EXECUTION_DECISION_SCHEMA.to_string(),
        execution_id: "aed-1".to_string(),
        issued_at: 1_743_379_440,
        pricing_decision_ref: "apd-1".to_string(),
        optimization_ref: "cpo-1".to_string(),
        authority_envelope_ref: "ape-1".to_string(),
        subject_key: "subject-1".to_string(),
        provider_id: "carrier-1".to_string(),
        currency: "USD".to_string(),
        action: AutonomousExecutionAction::Bind,
        lifecycle_state: AutonomousExecutionLifecycleState::Executed,
        quote_response_ref: Some("quote-response-1".to_string()),
        auto_bind_decision_ref: Some("auto-bind-1".to_string()),
        bound_coverage_ref: Some("bound-coverage-1".to_string()),
        settlement_dispatch_ref: Some("dispatch-web3-1".to_string()),
        safety_gates: vec![
            AutonomousExecutionSafetyGate {
                name: "authority-within-envelope".to_string(),
                passed: true,
                description: "Coverage and premium remain inside the active authority envelope."
                    .to_string(),
            },
            AutonomousExecutionSafetyGate {
                name: "capital-headroom".to_string(),
                passed: true,
                description: "Capital-pool optimization preserved minimum reserve headroom."
                    .to_string(),
            },
        ],
        rollback_control: AutonomousExecutionRollbackControl {
            rollback_plan_ref: "arp-1".to_string(),
            interruptible: true,
            human_interrupt_contact: "ops@chio.example".to_string(),
        },
        note: Some("Executes one bounded autonomous bind over the official web3 lane.".to_string()),
    }
}

fn sample_comparison_report() -> AutonomousComparisonReport {
    AutonomousComparisonReport {
        schema: CHIO_AUTONOMOUS_COMPARISON_REPORT_SCHEMA.to_string(),
        comparison_id: "acr-1".to_string(),
        generated_at: 1_743_379_500,
        pricing_decision_ref: "apd-1".to_string(),
        manual_decision_ref: "uwd-manual-1".to_string(),
        disposition: AutonomousComparisonDisposition::NarrowerThanManual,
        deltas: vec![AutonomousComparisonDelta {
            field: "premium_units".to_string(),
            automated_value: "4800".to_string(),
            manual_value: "5100".to_string(),
            description: "Automation priced inside the manual ceiling.".to_string(),
        }],
        override_reference: None,
        note: Some(
            "Shows automation staying narrower than the comparable manual decision.".to_string(),
        ),
    }
}

fn sample_rollback_plan() -> AutonomousRollbackPlanArtifact {
    AutonomousRollbackPlanArtifact {
        schema: CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA.to_string(),
        plan_id: "arp-1".to_string(),
        issued_at: 1_743_379_560,
        subject_key: "subject-1".to_string(),
        safe_state: AutonomousSafeState::DelegatedOnly,
        triggers: vec![
            AutonomousDriftKind::SettlementFailureRate,
            AutonomousDriftKind::PremiumVariance,
        ],
        actions: vec![
            AutonomousRollbackAction::SwitchToSafeState,
            AutonomousRollbackAction::CancelPendingExecution,
            AutonomousRollbackAction::RequireHumanApproval,
        ],
        requires_operator_ack: true,
        note: Some(
            "Falls back to delegated pricing when automation drifts beyond the accepted envelope."
                .to_string(),
        ),
    }
}

fn sample_drift_report() -> AutonomousDriftReport {
    AutonomousDriftReport {
        schema: CHIO_AUTONOMOUS_DRIFT_REPORT_SCHEMA.to_string(),
        drift_report_id: "adr-1".to_string(),
        generated_at: 1_743_379_620,
        subject_key: "subject-1".to_string(),
        pricing_decision_ref: "apd-1".to_string(),
        optimization_ref: "cpo-1".to_string(),
        drift_signals: vec![AutonomousDriftSignal {
            kind: AutonomousDriftKind::SettlementFailureRate,
            severity: AutonomousDriftSeverity::Critical,
            metric_name: "failed_settlement_rate_bps".to_string(),
            observed_value: 275,
            threshold_value: 100,
            description: "Settlement failures exceeded the automation safe-state threshold."
                .to_string(),
            evidence_refs: vec![AutonomousEvidenceReference {
                kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                reference_id: "receipt-web3-1".to_string(),
                observed_at: Some(1_743_379_000),
                locator: Some("web3-settlement:receipt-web3-1".to_string()),
            }],
        }],
        rollback_plan: sample_rollback_plan(),
        comparison_report: sample_comparison_report(),
        fail_safe_engaged: true,
        note: Some(
            "Fail-safe engaged after settlement drift breached the critical threshold.".to_string(),
        ),
    }
}

#[test]
fn shadow_mode_requires_shadow_review_state() {
    let mut decision = sample_decision();
    decision.authority_envelope.automation_mode = AutonomousAutomationMode::Shadow;
    decision.authority_envelope.permitted_actions = vec![AutonomousPricingAction::Reprice];
    decision.disposition = AutonomousPricingDisposition::Reprice;
    assert!(matches!(
        validate_autonomous_pricing_decision(&decision),
        Err(AutonomyContractError::InvalidDecision(_))
    ));
}

#[test]
fn capital_pool_simulation_requires_matching_subject() {
    let mut report = sample_simulation();
    report.candidate_optimization.subject_key = "subject-2".to_string();
    assert!(matches!(
        validate_capital_pool_simulation_report(&report),
        Err(AutonomyContractError::InvalidOptimization(_))
    ));
}

#[test]
fn bind_execution_requires_settlement_dispatch_when_executed() {
    let mut execution = sample_execution_decision();
    execution.settlement_dispatch_ref = None;
    assert!(matches!(
        validate_autonomous_execution_decision(&execution),
        Err(AutonomyContractError::MissingField(_))
    ));
}

#[test]
fn critical_drift_requires_fail_safe() {
    let mut report = sample_drift_report();
    report.fail_safe_engaged = false;
    assert!(matches!(
        validate_autonomous_drift_report(&report),
        Err(AutonomyContractError::InvalidDrift(_))
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let envelope: AutonomousPricingAuthorityEnvelopeArtifact = parse_fixture(
        "CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE.json"),
    );
    let decision: AutonomousPricingDecisionArtifact = parse_fixture(
        "CHIO_AUTONOMOUS_PRICING_DECISION_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_PRICING_DECISION_EXAMPLE.json"),
    );
    let optimization: CapitalPoolOptimizationArtifact = parse_fixture(
        "CHIO_CAPITAL_POOL_OPTIMIZATION_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_CAPITAL_POOL_OPTIMIZATION_EXAMPLE.json"),
    );
    let simulation: CapitalPoolSimulationReport = parse_fixture(
        "CHIO_CAPITAL_POOL_SIMULATION_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_CAPITAL_POOL_SIMULATION_EXAMPLE.json"),
    );
    let execution: AutonomousExecutionDecisionArtifact = parse_fixture(
        "CHIO_AUTONOMOUS_EXECUTION_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_EXECUTION_EXAMPLE.json"),
    );
    let comparison: AutonomousComparisonReport = parse_fixture(
        "CHIO_AUTONOMOUS_COMPARISON_REPORT_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_COMPARISON_REPORT_EXAMPLE.json"),
    );
    let drift: AutonomousDriftReport = parse_fixture(
        "CHIO_AUTONOMOUS_DRIFT_REPORT_EXAMPLE",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_DRIFT_REPORT_EXAMPLE.json"),
    );
    let matrix: AutonomousQualificationMatrix = parse_fixture(
        "CHIO_AUTONOMOUS_QUALIFICATION_MATRIX",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_QUALIFICATION_MATRIX.json"),
    );

    require_valid(
        validate_autonomous_pricing_authority_envelope(&envelope),
        "autonomous pricing authority envelope",
    );
    require_valid(
        validate_autonomous_pricing_decision(&decision),
        "autonomous pricing decision",
    );
    require_valid(
        validate_capital_pool_optimization(&optimization),
        "capital pool optimization",
    );
    require_valid(
        validate_capital_pool_simulation_report(&simulation),
        "capital pool simulation report",
    );
    require_valid(
        validate_autonomous_execution_decision(&execution),
        "autonomous execution decision",
    );
    require_valid(
        validate_autonomous_comparison_report(&comparison),
        "autonomous comparison report",
    );
    require_valid(
        validate_autonomous_drift_report(&drift),
        "autonomous drift report",
    );
    require_valid(
        validate_autonomous_qualification_matrix(&matrix),
        "autonomous qualification matrix",
    );
}

#[test]
fn pricing_input_requires_capital_book_evidence() {
    let mut input = sample_input();
    input
        .evidence_refs
        .retain(|evidence| evidence.kind != AutonomousEvidenceKind::CapitalBook);
    assert!(matches!(
        validate_autonomous_pricing_input(&input),
        Err(AutonomyContractError::UnknownReference(_))
    ));
}

#[test]
fn pricing_input_requires_web3_evidence_when_settlement_state_present() {
    let mut input = sample_input();
    input
        .evidence_refs
        .retain(|evidence| evidence.kind != AutonomousEvidenceKind::Web3SettlementReceipt);
    assert!(matches!(
        validate_autonomous_pricing_input(&input),
        Err(AutonomyContractError::UnknownReference(_))
    ));
}

#[test]
fn pricing_input_rejects_padded_money_currency() {
    let mut input = sample_input();
    input.requested_coverage_amount.currency = " usd ".to_string();

    assert!(matches!(
        validate_autonomous_pricing_input(&input),
        Err(AutonomyContractError::InvalidDecision(message))
            if message.contains("currency")
    ));
}

#[test]
fn money_currency_matcher_requires_exact_currency_match() {
    let amount = MonetaryAmount {
        units: 1,
        currency: "USD".to_string(),
    };

    assert!(money_currency_matches_declared(&amount, "USD"));
    assert!(!money_currency_matches_declared(
        &MonetaryAmount {
            units: 1,
            currency: " usd ".to_string(),
        },
        "USD"
    ));
    assert!(!money_currency_matches_declared(&amount, "EUR"));
}

#[test]
fn unique_string_lists_reject_blank_or_padded_entries() {
    assert!(matches!(
        ensure_unique_strings(&["ok".to_string(), " ".to_string()], "authority_refs"),
        Err(AutonomyContractError::MissingField("authority_refs"))
    ));
    assert!(matches!(
        ensure_unique_strings(
            &["ok".to_string(), " padded ".to_string()],
            "authority_refs",
        ),
        Err(AutonomyContractError::InvalidDecision(message))
            if message.contains("surrounding whitespace")
    ));
}

#[test]
fn delegated_authority_requires_reference() {
    let mut envelope = sample_authority_envelope();
    envelope.delegated_authority_reference = None;
    assert!(matches!(
        validate_autonomous_pricing_authority_envelope(&envelope),
        Err(AutonomyContractError::MissingField(
            "autonomous_authority_envelope.delegated_authority_reference"
        ))
    ));
}

#[test]
fn non_active_authority_cannot_permit_bind() {
    let mut envelope = sample_authority_envelope();
    envelope.automation_mode = AutonomousAutomationMode::Advisory;
    assert!(matches!(
        validate_autonomous_pricing_authority_envelope(&envelope),
        Err(AutonomyContractError::InvalidEnvelope(_))
    ));
}

#[test]
fn pricing_decision_rejects_duplicate_explanation_codes() {
    let mut decision = sample_decision();
    decision
        .explanation_factors
        .push(decision.explanation_factors[0].clone());
    assert!(matches!(
        validate_autonomous_pricing_decision(&decision),
        Err(AutonomyContractError::DuplicateValue(_))
    ));
}

#[test]
fn bind_decision_cannot_auto_approve_when_human_review_required() {
    let mut decision = sample_decision();
    decision.authority_envelope.requires_human_review_for_bind = true;
    assert!(matches!(
        validate_autonomous_pricing_decision(&decision),
        Err(AutonomyContractError::InvalidDecision(_))
    ));
}

#[test]
fn optimization_shift_capacity_requires_destination_ref() {
    let mut optimization = sample_optimization();
    optimization.recommendations[1].destination_ref = None;
    assert!(matches!(
        validate_capital_pool_optimization(&optimization),
        Err(AutonomyContractError::InvalidOptimization(_))
    ));
}

#[test]
fn capital_pool_simulation_requires_scenario_comparison_support() {
    let mut report = sample_simulation();
    report
        .candidate_optimization
        .support_boundary
        .scenario_comparison_supported = false;
    assert!(matches!(
        validate_capital_pool_simulation_report(&report),
        Err(AutonomyContractError::InvalidOptimization(_))
    ));
}

#[test]
fn comparison_report_manual_override_requires_reference() {
    let mut report = sample_comparison_report();
    report.disposition = AutonomousComparisonDisposition::ManualOverride;
    report.override_reference = None;
    assert!(matches!(
        validate_autonomous_comparison_report(&report),
        Err(AutonomyContractError::MissingField(
            "autonomous_comparison.override_reference"
        ))
    ));
}

#[test]
fn rollback_plan_rejects_duplicate_triggers() {
    let mut plan = sample_rollback_plan();
    plan.triggers.push(plan.triggers[0]);
    assert!(matches!(
        validate_autonomous_rollback_plan(&plan),
        Err(AutonomyContractError::DuplicateValue(_))
    ));
}

#[test]
fn qualification_matrix_requires_requirement_ids() {
    let mut matrix: AutonomousQualificationMatrix = parse_fixture(
        "CHIO_AUTONOMOUS_QUALIFICATION_MATRIX",
        include_str!("../../../../docs/standards/CHIO_AUTONOMOUS_QUALIFICATION_MATRIX.json"),
    );
    matrix.cases[0].requirement_ids.clear();
    assert!(matches!(
        validate_autonomous_qualification_matrix(&matrix),
        Err(AutonomyContractError::InvalidQualificationCase(_))
    ));
}

#[test]
fn pricing_decision_rejects_future_training_cutoff() {
    let mut decision = sample_decision();
    decision.model.training_cutoff = decision.model.published_at + 1;
    assert!(matches!(
        validate_autonomous_pricing_decision(&decision),
        Err(AutonomyContractError::InvalidDecision(_))
    ));
}
