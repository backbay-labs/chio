use super::*;
use crate::credit::SignedCreditProviderRiskPackage;

fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
where
    E: std::fmt::Debug,
{
    result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
}

fn require_err<T, E>(result: Result<T, E>, context: &'static str) -> E
where
    T: std::fmt::Debug,
{
    match result {
        Ok(value) => panic!("{context} unexpectedly succeeded: {value:?}"),
        Err(error) => error,
    }
}

fn require_some<T>(value: Option<T>, context: &'static str) -> T {
    value.unwrap_or_else(|| panic!("{context}"))
}

#[test]
fn market_query_limit_helper_clamps_default_and_edges() {
    assert_eq!(bounded_market_query_limit(None, 100), 50);
    assert_eq!(bounded_market_query_limit(Some(0), 100), 1);
    assert_eq!(bounded_market_query_limit(Some(25), 100), 25);
    assert_eq!(bounded_market_query_limit(Some(500), 100), 100);
}

fn sample_report() -> LiabilityProviderReport {
    LiabilityProviderReport {
        schema: LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_id: "carrier-alpha".to_string(),
        display_name: "Carrier Alpha".to_string(),
        provider_type: LiabilityProviderType::AdmittedCarrier,
        provider_url: Some("https://carrier.example.com".to_string()),
        lifecycle_state: LiabilityProviderLifecycleState::Active,
        support_boundary: LiabilityProviderSupportBoundary::default(),
        policies: vec![LiabilityJurisdictionPolicy {
            jurisdiction: "us-ny".to_string(),
            coverage_classes: vec![LiabilityCoverageClass::ToolExecution],
            supported_currencies: vec!["USD".to_string()],
            required_evidence: vec![LiabilityEvidenceRequirement::CreditProviderRiskPackage],
            max_coverage_amount: Some(MonetaryAmount {
                units: 50_000,
                currency: "USD".to_string(),
            }),
            claims_supported: true,
            quote_ttl_seconds: 3_600,
            notes: None,
        }],
        provenance: LiabilityProviderProvenance {
            configured_by: "operator".to_string(),
            configured_at: 1_700_000_000,
            source_ref: "compliance-runbook".to_string(),
            change_reason: None,
        },
    }
}

fn sample_risk_package() -> SignedCreditProviderRiskPackage {
    let keypair = crate::crypto::Keypair::generate();
    let exposure = require_ok(
        crate::credit::SignedExposureLedgerReport::sign(
            crate::credit::ExposureLedgerReport {
                schema: crate::credit::EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: crate::credit::ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::ExposureLedgerQuery::default()
                },
                support_boundary: crate::credit::ExposureLedgerSupportBoundary::default(),
                summary: crate::credit::ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                positions: vec![crate::credit::ExposureLedgerCurrencyPosition {
                    currency: "USD".to_string(),
                    governed_max_exposure_units: 4_000,
                    reserved_units: 0,
                    settled_units: 4_000,
                    pending_units: 0,
                    failed_units: 0,
                    provisional_loss_units: 0,
                    recovered_units: 0,
                    quoted_premium_units: 0,
                    active_quoted_premium_units: 0,
                }],
                receipts: Vec::new(),
                decisions: Vec::new(),
            },
            &keypair,
        ),
        "sign exposure",
    );
    let scorecard = require_ok(
        crate::credit::SignedCreditScorecardReport::sign(
            crate::credit::CreditScorecardReport {
                schema: crate::credit::CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: crate::credit::ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::ExposureLedgerQuery::default()
                },
                support_boundary: crate::credit::CreditScorecardSupportBoundary::default(),
                summary: crate::credit::CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: crate::credit::CreditScorecardConfidence::High,
                    band: crate::credit::CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: crate::credit::CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: crate::credit::CreditScorecardProbationStatus {
                    probationary: false,
                    reasons: Vec::new(),
                    receipt_count: 1,
                    span_days: 1,
                    target_receipt_count: 1,
                    target_span_days: 1,
                },
                dimensions: Vec::new(),
                anomalies: Vec::new(),
            },
            &keypair,
        ),
        "sign scorecard",
    );

    require_ok(
        SignedCreditProviderRiskPackage::sign(
            crate::credit::CreditProviderRiskPackage {
                schema: crate::credit::CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: crate::credit::CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::CreditProviderRiskPackageQuery::default()
                },
                support_boundary: crate::credit::CreditProviderRiskPackageSupportBoundary::default(
                ),
                exposure,
                scorecard,
                facility_report: crate::credit::CreditFacilityReport {
                    schema: crate::credit::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: crate::credit::ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..crate::credit::ExposureLedgerQuery::default()
                    },
                    scorecard: crate::credit::CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: crate::credit::CreditScorecardConfidence::High,
                        band: crate::credit::CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: crate::credit::CreditFacilityDisposition::Grant,
                    prerequisites: crate::credit::CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier:
                            crate::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: crate::credit::CreditFacilitySupportBoundary::default(),
                    terms: Some(crate::credit::CreditFacilityTerms {
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_500,
                        concentration_cap_bps: 3_000,
                        ttl_seconds: 86_400,
                        capital_source:
                            crate::credit::CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
                compliance_score: None,
                latest_facility: Some(crate::credit::CreditProviderFacilitySnapshot {
                    facility_id: "cfd-1".to_string(),
                    issued_at: 3,
                    expires_at: 4,
                    disposition: crate::credit::CreditFacilityDisposition::Grant,
                    lifecycle_state: crate::credit::CreditFacilityLifecycleState::Active,
                    credit_limit: Some(MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    }),
                    supersedes_facility_id: None,
                    signer_key: keypair.public_key().to_hex(),
                }),
                runtime_assurance: Some(crate::credit::CreditRuntimeAssuranceState {
                    governed_receipts: 1,
                    runtime_assurance_receipts: 1,
                    highest_tier: Some(
                        crate::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
                    ),
                    latest_schema: Some("chio.runtime-attestation.azure-maa.jwt.v1".to_string()),
                    latest_verifier_family: Some(
                        crate::appraisal::AttestationVerifierFamily::AzureMaa,
                    ),
                    latest_verifier: Some("verifier.chio".to_string()),
                    latest_evidence_sha256: Some("sha256-runtime".to_string()),
                    observed_verifier_families: vec![
                        crate::appraisal::AttestationVerifierFamily::AzureMaa,
                    ],
                    stale: false,
                }),
                certification: crate::credit::CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: crate::credit::CreditRecentLossHistory {
                    summary: crate::credit::CreditRecentLossSummary {
                        matching_loss_events: 0,
                        returned_loss_events: 0,
                        failed_settlement_events: 0,
                        provisional_loss_events: 0,
                        recovered_events: 0,
                    },
                    entries: Vec::new(),
                },
                evidence_refs: Vec::new(),
            },
            &keypair,
        ),
        "sign risk package",
    )
}

fn sign_export<T>(body: T) -> SignedExportEnvelope<T>
where
    T: serde::Serialize + Clone,
{
    let keypair = crate::crypto::Keypair::generate();
    require_ok(SignedExportEnvelope::sign(body, &keypair), "sign export")
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn sample_provider_policy() -> LiabilityProviderPolicyReference {
    let report = sample_report();
    let policy = &report.policies[0];
    LiabilityProviderPolicyReference {
        provider_id: report.provider_id,
        provider_record_id: "lpr-1".to_string(),
        display_name: report.display_name,
        jurisdiction: policy.jurisdiction.clone(),
        coverage_class: policy.coverage_classes[0],
        currency: "USD".to_string(),
        required_evidence: policy.required_evidence.clone(),
        max_coverage_amount: policy.max_coverage_amount.clone(),
        claims_supported: policy.claims_supported,
        quote_ttl_seconds: policy.quote_ttl_seconds,
        bound_coverage_supported: true,
    }
}

fn sample_quote_request_artifact() -> LiabilityQuoteRequestArtifact {
    LiabilityQuoteRequestArtifact {
        schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: "lqr-1".to_string(),
        issued_at: 1_700_000_000,
        provider_policy: sample_provider_policy(),
        requested_coverage_amount: usd(10_000),
        requested_effective_from: 1_700_010_000,
        requested_effective_until: 1_700_020_000,
        risk_package: sample_risk_package(),
        notes: Some("initial market inquiry".to_string()),
    }
}

fn sample_quote_response_artifact(
    quote_request: SignedLiabilityQuoteRequest,
) -> LiabilityQuoteResponseArtifact {
    LiabilityQuoteResponseArtifact {
        schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        quote_response_id: "lqp-1".to_string(),
        issued_at: quote_request.body.issued_at + 120,
        quote_request,
        provider_quote_ref: "carrier-alpha-quote".to_string(),
        disposition: LiabilityQuoteDisposition::Quoted,
        supersedes_quote_response_id: None,
        quoted_terms: Some(LiabilityQuoteTerms {
            quoted_coverage_amount: usd(10_000),
            quoted_premium_amount: usd(500),
            quoted_deductible_amount: Some(usd(1_000)),
            expires_at: 1_700_003_000,
        }),
        decline_reason: None,
    }
}

fn sample_credit_scorecard_summary() -> crate::credit::CreditScorecardSummary {
    crate::credit::CreditScorecardSummary {
        matching_receipts: 2,
        returned_receipts: 2,
        matching_decisions: 1,
        returned_decisions: 1,
        currencies: vec!["USD".to_string()],
        mixed_currency_book: false,
        confidence: crate::credit::CreditScorecardConfidence::High,
        band: crate::credit::CreditScorecardBand::Prime,
        overall_score: 0.94,
        anomaly_count: 0,
        probationary: false,
    }
}

fn sample_credit_facility() -> crate::credit::SignedCreditFacility {
    sign_export(crate::credit::CreditFacilityArtifact {
        schema: crate::credit::CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id: "cfd-1".to_string(),
        issued_at: 1_700_000_100,
        expires_at: 1_700_086_500,
        lifecycle_state: crate::credit::CreditFacilityLifecycleState::Active,
        supersedes_facility_id: None,
        report: crate::credit::CreditFacilityReport {
            schema: crate::credit::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_090,
            filters: crate::credit::ExposureLedgerQuery {
                agent_subject: Some("subject-1".to_string()),
                ..crate::credit::ExposureLedgerQuery::default()
            },
            scorecard: sample_credit_scorecard_summary(),
            disposition: crate::credit::CreditFacilityDisposition::Grant,
            prerequisites: crate::credit::CreditFacilityPrerequisites {
                minimum_runtime_assurance_tier:
                    crate::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                manual_review_required: false,
            },
            support_boundary: crate::credit::CreditFacilitySupportBoundary::default(),
            terms: Some(crate::credit::CreditFacilityTerms {
                credit_limit: usd(12_000),
                utilization_ceiling_bps: 8_000,
                reserve_ratio_bps: 1_500,
                concentration_cap_bps: 3_000,
                ttl_seconds: 86_400,
                capital_source: crate::credit::CreditFacilityCapitalSource::OperatorInternal,
            }),
            findings: Vec::new(),
        },
    })
}

fn sample_underwriting_input() -> crate::underwriting::UnderwritingPolicyInput {
    crate::underwriting::UnderwritingPolicyInput {
        schema: crate::underwriting::UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at: 1_700_000_120,
        filters: crate::underwriting::UnderwritingPolicyInputQuery {
            agent_subject: Some("subject-1".to_string()),
            ..crate::underwriting::UnderwritingPolicyInputQuery::default()
        },
        taxonomy: crate::underwriting::UnderwritingRiskTaxonomy::default(),
        receipts: crate::underwriting::UnderwritingReceiptEvidence {
            matching_receipts: 2,
            returned_receipts: 2,
            allow_count: 2,
            deny_count: 0,
            cancelled_count: 0,
            incomplete_count: 0,
            governed_receipts: 2,
            approval_receipts: 1,
            approved_receipts: 1,
            call_chain_receipts: 0,
            runtime_assurance_receipts: 1,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            actionable_settlement_receipts: 0,
            metered_receipts: 0,
            actionable_metered_receipts: 0,
            shared_evidence_reference_count: 0,
            shared_evidence_proof_required_count: 0,
            receipt_refs: Vec::new(),
        },
        reputation: Some(crate::underwriting::UnderwritingReputationEvidence {
            subject_key: "subject-1".to_string(),
            effective_score: 0.94,
            probationary: false,
            resolved_tier: Some("prime".to_string()),
            imported_signal_count: 0,
            accepted_imported_signal_count: 0,
        }),
        certification: Some(crate::underwriting::UnderwritingCertificationEvidence {
            tool_server_id: "server-1".to_string(),
            state: crate::underwriting::UnderwritingCertificationState::Active,
            artifact_id: Some("cert-1".to_string()),
            verdict: Some("pass".to_string()),
            checked_at: Some(1_700_000_110),
            published_at: Some(1_700_000_111),
        }),
        runtime_assurance: Some(crate::underwriting::UnderwritingRuntimeAssuranceEvidence {
            governed_receipts: 2,
            runtime_assurance_receipts: 1,
            highest_tier: Some(
                crate::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
            ),
            latest_schema: Some("chio.runtime-attestation.enterprise.v1".to_string()),
            latest_verifier_family: Some(
                crate::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            ),
            latest_verifier: Some("verifier.chio".to_string()),
            latest_evidence_sha256: Some("sha256-attest".to_string()),
            observed_verifier_families: vec![
                crate::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            ],
        }),
        compliance_score: None,
        signals: Vec::new(),
    }
}

fn sample_underwriting_decision() -> crate::underwriting::SignedUnderwritingDecision {
    sign_export(crate::underwriting::UnderwritingDecisionArtifact {
        schema: crate::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: "uwd-1".to_string(),
        issued_at: 1_700_000_130,
        evaluation: crate::underwriting::UnderwritingDecisionReport {
            schema: crate::underwriting::UNDERWRITING_DECISION_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_129,
            policy: crate::underwriting::UnderwritingDecisionPolicy::default(),
            outcome: crate::underwriting::UnderwritingDecisionOutcome::Approve,
            risk_class: crate::underwriting::UnderwritingRiskClass::Baseline,
            suggested_ceiling_factor: Some(1.0),
            findings: Vec::new(),
            input: sample_underwriting_input(),
        },
        lifecycle_state: crate::underwriting::UnderwritingDecisionLifecycleState::Active,
        review_state: crate::underwriting::UnderwritingReviewState::Approved,
        supersedes_decision_id: None,
        budget: crate::underwriting::UnderwritingBudgetRecommendation {
            action: crate::underwriting::UnderwritingBudgetAction::Preserve,
            ceiling_factor: Some(1.0),
            rationale: "approved under baseline risk profile".to_string(),
        },
        premium: crate::underwriting::UnderwritingPremiumQuote {
            state: crate::underwriting::UnderwritingPremiumState::Quoted,
            basis_points: Some(500),
            quoted_amount: Some(usd(500)),
            rationale: "5% premium quote".to_string(),
        },
    })
}

fn sample_capital_book() -> crate::credit::SignedCapitalBookReport {
    sign_export(crate::credit::CapitalBookReport {
        schema: crate::credit::CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
        generated_at: 1_700_000_140,
        query: crate::credit::CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            ..crate::credit::CapitalBookQuery::default()
        },
        subject_key: "subject-1".to_string(),
        support_boundary: crate::credit::CapitalBookSupportBoundary::default(),
        summary: crate::credit::CapitalBookSummary {
            matching_receipts: 2,
            returned_receipts: 2,
            matching_facilities: 1,
            returned_facilities: 1,
            matching_bonds: 1,
            returned_bonds: 1,
            matching_loss_events: 1,
            returned_loss_events: 1,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            funding_sources: 1,
            ledger_events: 0,
            truncated_receipts: false,
            truncated_facilities: false,
            truncated_bonds: false,
            truncated_loss_events: false,
        },
        sources: vec![crate::credit::CapitalBookSource {
            source_id: "facility-source-1".to_string(),
            kind: crate::credit::CapitalBookSourceKind::FacilityCommitment,
            owner_role: crate::credit::CapitalBookRole::OperatorTreasury,
            counterparty_role: crate::credit::CapitalBookRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            currency: "USD".to_string(),
            jurisdiction: Some("us-ny".to_string()),
            capital_source: Some(crate::credit::CreditFacilityCapitalSource::OperatorInternal),
            facility_id: Some("cfd-1".to_string()),
            bond_id: None,
            committed_amount: Some(usd(12_000)),
            held_amount: None,
            drawn_amount: None,
            disbursed_amount: Some(usd(1_000)),
            released_amount: None,
            repaid_amount: None,
            impaired_amount: Some(usd(1_000)),
            description: "facility commitment".to_string(),
        }],
        events: Vec::new(),
    })
}

fn sample_exposure_report() -> crate::credit::SignedExposureLedgerReport {
    sign_export(crate::credit::ExposureLedgerReport {
        schema: crate::credit::EXPOSURE_LEDGER_SCHEMA.to_string(),
        generated_at: 1_700_010_350,
        filters: crate::credit::ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            ..crate::credit::ExposureLedgerQuery::default()
        },
        support_boundary: crate::credit::ExposureLedgerSupportBoundary::default(),
        summary: crate::credit::ExposureLedgerSummary {
            matching_receipts: 2,
            returned_receipts: 2,
            matching_decisions: 1,
            returned_decisions: 1,
            active_decisions: 1,
            superseded_decisions: 0,
            actionable_receipts: 0,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            truncated_receipts: false,
            truncated_decisions: false,
        },
        positions: vec![crate::credit::ExposureLedgerCurrencyPosition {
            currency: "USD".to_string(),
            governed_max_exposure_units: 10_000,
            reserved_units: 0,
            settled_units: 10_000,
            pending_units: 0,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 500,
            active_quoted_premium_units: 500,
        }],
        receipts: Vec::new(),
        decisions: Vec::new(),
    })
}

fn sample_credit_bond() -> crate::credit::SignedCreditBond {
    sign_export(crate::credit::CreditBondArtifact {
        schema: crate::credit::CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
        bond_id: "bond-1".to_string(),
        issued_at: 1_700_010_360,
        expires_at: 1_700_096_760,
        lifecycle_state: crate::credit::CreditBondLifecycleState::Active,
        supersedes_bond_id: None,
        report: crate::credit::CreditBondReport {
            schema: crate::credit::CREDIT_BOND_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_010_359,
            filters: crate::credit::ExposureLedgerQuery {
                agent_subject: Some("subject-1".to_string()),
                ..crate::credit::ExposureLedgerQuery::default()
            },
            exposure: sample_exposure_report().body.summary.clone(),
            scorecard: sample_credit_scorecard_summary(),
            disposition: crate::credit::CreditBondDisposition::Lock,
            prerequisites: crate::credit::CreditBondPrerequisites {
                active_facility_required: true,
                active_facility_met: true,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                currency_coherent: true,
            },
            support_boundary: crate::credit::CreditBondSupportBoundary::default(),
            latest_facility_id: Some("cfd-1".to_string()),
            terms: Some(crate::credit::CreditBondTerms {
                facility_id: "cfd-1".to_string(),
                credit_limit: usd(12_000),
                collateral_amount: usd(6_000),
                reserve_requirement_amount: usd(3_000),
                outstanding_exposure_amount: usd(9_000),
                reserve_ratio_bps: 1_500,
                coverage_ratio_bps: 12_000,
                capital_source: crate::credit::CreditFacilityCapitalSource::OperatorInternal,
            }),
            findings: Vec::new(),
        },
    })
}

fn sample_credit_loss_lifecycle() -> crate::credit::SignedCreditLossLifecycle {
    sign_export(crate::credit::CreditLossLifecycleArtifact {
        schema: crate::credit::CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: "loss-1".to_string(),
        issued_at: 1_700_010_370,
        bond_id: "bond-1".to_string(),
        event_kind: crate::credit::CreditLossLifecycleEventKind::Delinquency,
        projected_bond_lifecycle_state: crate::credit::CreditBondLifecycleState::Active,
        reserve_control_source_id: None,
        authority_chain: Vec::new(),
        execution_window: None,
        rail: None,
        observed_execution: None,
        reconciled_state: None,
        execution_state: None,
        appeal_state: None,
        appeal_window_ends_at: None,
        description: Some("claim loss marker".to_string()),
        report: crate::credit::CreditLossLifecycleReport {
            schema: crate::credit::CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_010_369,
            query: crate::credit::CreditLossLifecycleQuery {
                bond_id: "bond-1".to_string(),
                event_kind: crate::credit::CreditLossLifecycleEventKind::Delinquency,
                amount: Some(usd(1_000)),
            },
            summary: crate::credit::CreditLossLifecycleSummary {
                bond_id: "bond-1".to_string(),
                facility_id: Some("cfd-1".to_string()),
                capability_id: Some("cap-1".to_string()),
                agent_subject: Some("subject-1".to_string()),
                tool_server: Some("server-1".to_string()),
                tool_name: Some("tool-a".to_string()),
                current_bond_lifecycle_state: crate::credit::CreditBondLifecycleState::Active,
                projected_bond_lifecycle_state: crate::credit::CreditBondLifecycleState::Active,
                current_delinquent_amount: Some(usd(1_000)),
                current_recovered_amount: None,
                current_written_off_amount: None,
                current_released_reserve_amount: None,
                current_slashed_reserve_amount: None,
                outstanding_delinquent_amount: Some(usd(1_000)),
                releaseable_reserve_amount: Some(usd(2_000)),
                reserve_control_source_id: None,
                execution_state: None,
                appeal_state: None,
                appeal_window_ends_at: None,
                event_amount: Some(usd(1_000)),
            },
            support_boundary: crate::credit::CreditLossLifecycleSupportBoundary::default(),
            findings: Vec::new(),
        },
    })
}

#[derive(Clone)]
struct MarketFixtures {
    quote_response: SignedLiabilityQuoteResponse,
    pricing_authority: SignedLiabilityPricingAuthority,
    placement: SignedLiabilityPlacement,
    bound_coverage: SignedLiabilityBoundCoverage,
    claim_package: SignedLiabilityClaimPackage,
    claim_response: SignedLiabilityClaimResponse,
    claim_dispute: SignedLiabilityClaimDispute,
    claim_adjudication: SignedLiabilityClaimAdjudication,
    payout_instruction: SignedLiabilityClaimPayoutInstruction,
    payout_receipt: SignedLiabilityClaimPayoutReceipt,
    settlement_instruction: SignedLiabilityClaimSettlementInstruction,
    settlement_receipt: SignedLiabilityClaimSettlementReceipt,
}

fn sample_market_fixtures() -> MarketFixtures {
    let quote_request = sign_export(sample_quote_request_artifact());
    let quote_response = sign_export(sample_quote_response_artifact(quote_request.clone()));
    let capital_book = sample_capital_book();
    let pricing_authority = sign_export(LiabilityPricingAuthorityArtifact {
        schema: LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA.to_string(),
        authority_id: "lpa-1".to_string(),
        issued_at: 1_700_000_150,
        quote_request: quote_request.clone(),
        provider_policy: quote_request.body.provider_policy.clone(),
        facility: sample_credit_facility(),
        underwriting_decision: sample_underwriting_decision(),
        capital_book: capital_book.clone(),
        envelope: LiabilityPricingAuthorityEnvelope {
            kind: LiabilityPricingAuthorityEnvelopeKind::ProviderDelegate,
            delegate_id: "pricing-delegate-1".to_string(),
            regulated_role: None,
            authority_chain_ref: Some("auth-chain-1".to_string()),
        },
        max_coverage_amount: usd(10_000),
        max_premium_amount: usd(500),
        expires_at: 1_700_002_000,
        auto_bind_enabled: true,
        notes: Some("carrier delegated pricing authority".to_string()),
    });
    let placement = sign_export(LiabilityPlacementArtifact {
        schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
        placement_id: "lpl-1".to_string(),
        issued_at: 1_700_000_160,
        quote_response: quote_response.clone(),
        selected_coverage_amount: usd(10_000),
        selected_premium_amount: usd(500),
        effective_from: quote_response
            .body
            .quote_request
            .body
            .requested_effective_from,
        effective_until: quote_response
            .body
            .quote_request
            .body
            .requested_effective_until,
        placement_ref: Some("placement-ref-1".to_string()),
        notes: None,
    });
    let bound_coverage = sign_export(LiabilityBoundCoverageArtifact {
        schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
        bound_coverage_id: "lbc-1".to_string(),
        issued_at: 1_700_000_170,
        placement: placement.clone(),
        policy_number: "POL-Chio-1".to_string(),
        carrier_reference: Some("carrier-ref-1".to_string()),
        bound_at: 1_700_000_171,
        effective_from: placement.body.effective_from,
        effective_until: placement.body.effective_until,
        coverage_amount: placement.body.selected_coverage_amount.clone(),
        premium_amount: placement.body.selected_premium_amount.clone(),
    });
    let claim_package = sign_export(LiabilityClaimPackageArtifact {
        schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
        claim_id: "clm-1".to_string(),
        issued_at: 1_700_010_400,
        bound_coverage: bound_coverage.clone(),
        exposure: sample_exposure_report(),
        bond: sample_credit_bond(),
        loss_event: sample_credit_loss_lifecycle(),
        claimant: "subject-1".to_string(),
        claim_event_at: 1_700_010_500,
        claim_amount: usd(9_000),
        claim_ref: Some("claim-ref-1".to_string()),
        narrative: "tool execution loss".to_string(),
        receipt_ids: vec!["rcpt-1".to_string(), "rcpt-2".to_string()],
        evidence_refs: Vec::new(),
    });
    let claim_response = sign_export(LiabilityClaimResponseArtifact {
        schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        claim_response_id: "clr-1".to_string(),
        issued_at: 1_700_010_600,
        claim: claim_package.clone(),
        provider_response_ref: "provider-claim-1".to_string(),
        disposition: LiabilityClaimResponseDisposition::Accepted,
        covered_amount: Some(usd(7_000)),
        response_note: Some("partial acceptance".to_string()),
        denial_reason: None,
        evidence_refs: Vec::new(),
    });
    let claim_dispute = sign_export(LiabilityClaimDisputeArtifact {
        schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
        dispute_id: "cld-1".to_string(),
        issued_at: 1_700_010_700,
        provider_response: claim_response.clone(),
        opened_by: "subject-1".to_string(),
        reason: "remaining uncovered amount disputed".to_string(),
        note: None,
        evidence_refs: Vec::new(),
    });
    let claim_adjudication = sign_export(LiabilityClaimAdjudicationArtifact {
        schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
        adjudication_id: "cla-1".to_string(),
        issued_at: 1_700_010_800,
        dispute: claim_dispute.clone(),
        adjudicator: "arbiter.chio".to_string(),
        outcome: LiabilityClaimAdjudicationOutcome::PartialSettlement,
        awarded_amount: Some(usd(6_000)),
        note: Some("partial settlement ordered".to_string()),
        evidence_refs: Vec::new(),
    });
    let capital_instruction = sign_export(crate::credit::CapitalExecutionInstructionArtifact {
        schema: crate::credit::CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        instruction_id: "cei-1".to_string(),
        issued_at: 1_700_010_850,
        query: crate::credit::CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            ..crate::credit::CapitalBookQuery::default()
        },
        subject_key: "subject-1".to_string(),
        source_id: "facility-source-1".to_string(),
        source_kind: crate::credit::CapitalBookSourceKind::FacilityCommitment,
        governed_receipt_id: Some("rc-1".to_string()),
        completion_flow_row_id: Some("economic-completion-flow:rc-1".to_string()),
        action: crate::credit::CapitalExecutionInstructionAction::TransferFunds,
        owner_role: crate::credit::CapitalExecutionRole::FacilityProvider,
        counterparty_role: crate::credit::CapitalExecutionRole::AgentCounterparty,
        counterparty_id: "subject-1".to_string(),
        amount: Some(usd(6_000)),
        authority_chain: Vec::new(),
        execution_window: crate::credit::CapitalExecutionWindow {
            not_before: 1_700_010_850,
            not_after: 1_700_011_200,
        },
        rail: crate::credit::CapitalExecutionRail {
            kind: crate::credit::CapitalExecutionRailKind::Api,
            rail_id: "rail-1".to_string(),
            custody_provider_id: "custody-1".to_string(),
            source_account_ref: None,
            destination_account_ref: None,
            jurisdiction: Some("us-ny".to_string()),
        },
        intended_state: crate::credit::CapitalExecutionIntendedState::PendingExecution,
        reconciled_state: crate::credit::CapitalExecutionReconciledState::NotObserved,
        related_instruction_id: None,
        observed_execution: None,
        support_boundary: crate::credit::CapitalExecutionInstructionSupportBoundary::default(),
        evidence_refs: Vec::new(),
        description: "claim payout transfer".to_string(),
    });
    let payout_instruction = sign_export(LiabilityClaimPayoutInstructionArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        payout_instruction_id: "cpi-1".to_string(),
        issued_at: 1_700_010_900,
        adjudication: claim_adjudication.clone(),
        capital_instruction: capital_instruction.clone(),
        payout_amount: usd(6_000),
        note: None,
    });
    let payout_receipt = sign_export(LiabilityClaimPayoutReceiptArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        payout_receipt_id: "cpr-1".to_string(),
        issued_at: 1_700_011_000,
        payout_instruction: payout_instruction.clone(),
        payout_receipt_ref: "payout-receipt-1".to_string(),
        reconciliation_state: LiabilityClaimPayoutReconciliationState::Matched,
        observed_execution: crate::credit::CapitalExecutionObservation {
            observed_at: 1_700_011_000,
            external_reference_id: "exec-1".to_string(),
            amount: usd(6_000),
        },
        note: None,
    });
    let facility_provider = crate::crypto::Keypair::generate();
    let facility_provider_id = facility_provider.public_key().to_hex();
    let custodian = crate::crypto::Keypair::generate();
    let custodian_id = custodian.public_key().to_hex();
    let settlement_instruction = sign_export(LiabilityClaimSettlementInstructionArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        settlement_instruction_id: "csi-1".to_string(),
        issued_at: 1_700_011_100,
        payout_receipt: payout_receipt.clone(),
        capital_book: capital_book.clone(),
        settlement_kind: LiabilityClaimSettlementKind::FacilityReimbursement,
        settlement_amount: usd(5_000),
        topology: LiabilityClaimSettlementRoleTopology {
            payer: LiabilityClaimSettlementRoleBinding {
                role: crate::credit::CapitalExecutionRole::FacilityProvider,
                party_id: facility_provider_id.clone(),
                jurisdiction: Some("us-ny".to_string()),
                note: None,
            },
            payee: LiabilityClaimSettlementRoleBinding {
                role: crate::credit::CapitalExecutionRole::AgentCounterparty,
                party_id: "subject-1".to_string(),
                jurisdiction: Some("us-ny".to_string()),
                note: None,
            },
            beneficiary: None,
        },
        authority_chain: vec![
            require_ok(
                crate::credit::CapitalExecutionAuthorityStep::signed(
                    crate::credit::CapitalExecutionRole::FacilityProvider,
                    &facility_provider,
                    1_700_011_050,
                    1_700_011_600,
                    None,
                ),
                "facility-provider authority proof",
            ),
            require_ok(
                crate::credit::CapitalExecutionAuthorityStep::signed(
                    crate::credit::CapitalExecutionRole::Custodian,
                    &custodian,
                    1_700_011_050,
                    1_700_011_600,
                    None,
                ),
                "custodian authority proof",
            ),
        ],
        execution_window: crate::credit::CapitalExecutionWindow {
            not_before: 1_700_011_100,
            not_after: 1_700_011_500,
        },
        rail: crate::credit::CapitalExecutionRail {
            kind: crate::credit::CapitalExecutionRailKind::Ach,
            rail_id: "ach-1".to_string(),
            custody_provider_id: custodian_id,
            source_account_ref: None,
            destination_account_ref: None,
            jurisdiction: Some("us-ny".to_string()),
        },
        settlement_reference: Some("settle-1".to_string()),
        note: None,
    });
    let settlement_receipt = sign_export(LiabilityClaimSettlementReceiptArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        settlement_receipt_id: "csr-1".to_string(),
        issued_at: 1_700_011_200,
        settlement_instruction: settlement_instruction.clone(),
        settlement_receipt_ref: "settlement-receipt-1".to_string(),
        reconciliation_state: LiabilityClaimSettlementReconciliationState::Matched,
        observed_execution: crate::credit::CapitalExecutionObservation {
            observed_at: 1_700_011_200,
            external_reference_id: "settle-exec-1".to_string(),
            amount: usd(5_000),
        },
        observed_payer_id: facility_provider_id,
        observed_payee_id: "subject-1".to_string(),
        note: None,
    });

    MarketFixtures {
        quote_response,
        pricing_authority,
        placement,
        bound_coverage,
        claim_package,
        claim_response,
        claim_dispute,
        claim_adjudication,
        payout_instruction,
        payout_receipt,
        settlement_instruction,
        settlement_receipt,
    }
}

#[test]
fn liability_provider_report_rejects_duplicate_jurisdictions() {
    let mut report = sample_report();
    report.policies.push(report.policies[0].clone());
    let error = require_err(report.validate(), "duplicate jurisdiction rejected");
    assert!(error.contains("duplicate jurisdiction policy"));
}

#[test]
fn liability_provider_report_rejects_invalid_currency() {
    let mut report = sample_report();
    report.policies[0].supported_currencies = vec!["usdollars".to_string()];
    let error = require_err(report.validate(), "invalid currency rejected");
    assert!(error.contains("invalid currency"));
}

#[test]
fn liability_provider_resolution_query_normalizes_fields() {
    let query = LiabilityProviderResolutionQuery {
        provider_id: " carrier-alpha ".to_string(),
        jurisdiction: "US-NY".to_string(),
        coverage_class: LiabilityCoverageClass::ToolExecution,
        currency: "usd".to_string(),
    }
    .normalized();

    assert_eq!(query.provider_id, "carrier-alpha");
    assert_eq!(query.jurisdiction, "us-ny");
    assert_eq!(query.currency, "USD");
}

#[test]
fn liability_quote_request_rejects_currency_mismatch() {
    let report = sample_report();
    let request = LiabilityQuoteRequestArtifact {
        schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: "lqr-test".to_string(),
        issued_at: 1_700_000_000,
        provider_policy: LiabilityProviderPolicyReference {
            provider_id: report.provider_id.clone(),
            provider_record_id: "lpr-test".to_string(),
            display_name: report.display_name.clone(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: LiabilityCoverageClass::ToolExecution,
            currency: "USD".to_string(),
            required_evidence: vec![LiabilityEvidenceRequirement::CreditProviderRiskPackage],
            max_coverage_amount: Some(MonetaryAmount {
                units: 50_000,
                currency: "USD".to_string(),
            }),
            claims_supported: true,
            quote_ttl_seconds: 3_600,
            bound_coverage_supported: true,
        },
        requested_coverage_amount: MonetaryAmount {
            units: 10_000,
            currency: "EUR".to_string(),
        },
        requested_effective_from: 1_700_010_000,
        requested_effective_until: 1_700_020_000,
        risk_package: sample_risk_package(),
        notes: None,
    };

    let error = require_err(request.validate(), "currency mismatch rejected");
    assert!(error.contains("currency must match provider policy currency"));
}

#[test]
fn liability_market_workflow_query_normalizes_fields() {
    let query = LiabilityMarketWorkflowQuery {
        quote_request_id: Some(" q-1 ".to_string()),
        provider_id: Some(" carrier-alpha ".to_string()),
        agent_subject: Some(" subject-1 ".to_string()),
        jurisdiction: Some("US-NY".to_string()),
        coverage_class: Some(LiabilityCoverageClass::ToolExecution),
        currency: Some("usd".to_string()),
        limit: Some(500),
    }
    .normalized();

    assert_eq!(query.quote_request_id.as_deref(), Some("q-1"));
    assert_eq!(query.provider_id.as_deref(), Some("carrier-alpha"));
    assert_eq!(query.agent_subject.as_deref(), Some("subject-1"));
    assert_eq!(query.jurisdiction.as_deref(), Some("us-ny"));
    assert_eq!(query.currency.as_deref(), Some("USD"));
    assert_eq!(query.limit, Some(MAX_LIABILITY_MARKET_WORKFLOW_LIMIT));
}

#[test]
fn liability_provider_list_query_normalizes_and_clamps_fields() {
    let query = LiabilityProviderListQuery {
        provider_id: Some("carrier-alpha".to_string()),
        jurisdiction: Some(" US-NY ".to_string()),
        coverage_class: Some(LiabilityCoverageClass::ToolExecution),
        currency: Some(" usd ".to_string()),
        lifecycle_state: Some(LiabilityProviderLifecycleState::Active),
        limit: Some(500),
    }
    .normalized();

    assert_eq!(query.jurisdiction.as_deref(), Some("us-ny"));
    assert_eq!(query.currency.as_deref(), Some("USD"));
    assert_eq!(query.limit, Some(MAX_LIABILITY_PROVIDER_LIST_LIMIT));
}

#[test]
fn liability_provider_resolution_query_rejects_invalid_currency() {
    let error = require_err(
        LiabilityProviderResolutionQuery {
            provider_id: "carrier-alpha".to_string(),
            jurisdiction: "us-ny".to_string(),
            coverage_class: LiabilityCoverageClass::ToolExecution,
            currency: "usdollars".to_string(),
        }
        .validate(),
        "invalid currency rejected",
    );

    assert!(error.contains("three-letter uppercase"));
}

#[test]
fn liability_pricing_authority_envelope_requires_regulated_role() {
    let error = require_err(
        LiabilityPricingAuthorityEnvelope {
            kind: LiabilityPricingAuthorityEnvelopeKind::RegulatedRole,
            delegate_id: "delegate-1".to_string(),
            regulated_role: None,
            authority_chain_ref: None,
        }
        .validate(),
        "regulated role required",
    );

    assert!(error.contains("regulated_role"));
}

#[test]
fn liability_quote_response_validates_quoted_terms_path() {
    let fixtures = sample_market_fixtures();
    assert!(fixtures.quote_response.body.validate().is_ok());
}

#[test]
fn liability_quote_response_rejects_wrong_schema_and_empty_id() {
    let fixtures = sample_market_fixtures();
    let mut response = fixtures.quote_response.body.clone();
    response.schema = "chio.market.quote-response.v0".to_string();
    let error = require_err(response.validate(), "wrong quote response schema rejected");
    assert!(error.contains("unsupported liability quote response schema"));

    let mut response = fixtures.quote_response.body.clone();
    response.quote_response_id = " ".to_string();
    let error = require_err(response.validate(), "empty quote response id rejected");
    assert!(error.contains("quote_response_id"));

    let mut response = fixtures.quote_response.body.clone();
    response.quote_response_id = " quote-1 ".to_string();
    let error = require_err(response.validate(), "padded quote response id rejected");
    assert!(error.contains("quote_response_id"));
}

#[test]
fn liability_quote_response_rejects_control_character_id() {
    let fixtures = sample_market_fixtures();
    let mut response = fixtures.quote_response.body.clone();
    response.quote_response_id = "quote-1\nquote-2".to_string();

    let error = require_err(
        response.validate(),
        "control-character quote response id rejected",
    );

    assert!(error.contains("quote_response_id"));
    assert!(error.contains("control characters"));
}

#[test]
fn liability_quote_response_declined_requires_reason() {
    let fixtures = sample_market_fixtures();
    let mut response = fixtures.quote_response.body.clone();
    response.disposition = LiabilityQuoteDisposition::Declined;
    response.quoted_terms = None;
    response.decline_reason = Some("   ".to_string());

    let error = require_err(response.validate(), "declined response requires reason");
    assert!(error.contains("declined quote responses require decline_reason"));
}

#[test]
fn liability_pricing_authority_validates_happy_path() {
    let fixtures = sample_market_fixtures();
    assert!(fixtures.pricing_authority.body.validate().is_ok());
}

#[test]
fn liability_pricing_authority_rejects_auto_bind_without_claim_support() {
    let fixtures = sample_market_fixtures();
    let mut authority = fixtures.pricing_authority.body.clone();
    let mut quote_request = authority.quote_request.body.clone();
    quote_request.provider_policy.claims_supported = false;
    authority.quote_request = sign_export(quote_request);
    authority.provider_policy = authority.quote_request.body.provider_policy.clone();

    let error = require_err(authority.validate(), "auto-bind requires claim support");
    assert!(error.contains("cannot enable auto_bind"));
}

#[test]
fn liability_placement_rejects_expired_quote() {
    let fixtures = sample_market_fixtures();
    let mut placement = fixtures.placement.body.clone();
    let expires_at = require_some(
        placement.quote_response.body.quoted_terms.as_ref(),
        "quoted terms",
    )
    .expires_at;
    placement.issued_at = expires_at;

    let error = require_err(placement.validate(), "expired quote rejected");
    assert!(error.contains("cannot be issued after the quote expires"));
}

#[test]
fn liability_bound_coverage_rejects_provider_without_bound_coverage() {
    let fixtures = sample_market_fixtures();
    let mut coverage = fixtures.bound_coverage.body.clone();
    let mut placement = coverage.placement.body.clone();
    let mut quote_response = placement.quote_response.body.clone();
    let mut quote_request = quote_response.quote_request.body.clone();
    quote_request.provider_policy.bound_coverage_supported = false;
    quote_response.quote_request = sign_export(quote_request);
    placement.quote_response = sign_export(quote_response);
    coverage.placement = sign_export(placement);

    let error = require_err(coverage.validate(), "provider must support bound coverage");
    assert!(error.contains("does not support bound coverage"));
}

#[test]
fn liability_auto_bind_decision_validates_auto_bound_flow() {
    let fixtures = sample_market_fixtures();
    let decision = LiabilityAutoBindDecisionArtifact {
        schema: LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: "abd-1".to_string(),
        issued_at: 1_700_000_180,
        authority: fixtures.pricing_authority,
        quote_response: fixtures.quote_response,
        disposition: LiabilityAutoBindDisposition::AutoBound,
        findings: Vec::new(),
        placement: Some(fixtures.placement),
        bound_coverage: Some(fixtures.bound_coverage),
    };

    assert!(decision.validate().is_ok());
}

#[test]
fn liability_auto_bind_decision_rejects_manual_review_with_embedded_artifacts() {
    let fixtures = sample_market_fixtures();
    let decision = LiabilityAutoBindDecisionArtifact {
        schema: LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id: "abd-1".to_string(),
        issued_at: 1_700_000_180,
        authority: fixtures.pricing_authority,
        quote_response: fixtures.quote_response,
        disposition: LiabilityAutoBindDisposition::ManualReview,
        findings: Vec::new(),
        placement: Some(fixtures.placement),
        bound_coverage: Some(fixtures.bound_coverage),
    };

    let error = require_err(
        decision.validate(),
        "manual review cannot embed issued artifacts",
    );
    assert!(error.contains("cannot embed issued placement or bound coverage"));
}

#[test]
fn liability_claim_package_rejects_duplicate_receipts() {
    let fixtures = sample_market_fixtures();
    let mut claim = fixtures.claim_package.body.clone();
    claim.receipt_ids = vec!["rcpt-1".to_string(), "rcpt-1".to_string()];

    let error = require_err(claim.validate(), "duplicate receipt ids rejected");
    assert!(error.contains("receipt references must be unique"));
}

#[test]
fn liability_claim_package_rejects_tampered_bound_coverage_signature() {
    let fixtures = sample_market_fixtures();
    let mut claim = fixtures.claim_package.body.clone();
    claim.bound_coverage.body.policy_number = "POL-forged".to_string();

    let error = require_err(claim.validate(), "tampered coverage rejected");
    assert!(error.contains("bound_coverage signature verification failed"));
}

#[test]
fn liability_claim_response_rejects_denied_without_reason() {
    let fixtures = sample_market_fixtures();
    let mut response = fixtures.claim_response.body.clone();
    response.disposition = LiabilityClaimResponseDisposition::Denied;
    response.covered_amount = None;
    response.denial_reason = None;

    let error = require_err(response.validate(), "denied responses require reason");
    assert!(error.contains("denied claim responses require denial_reason"));
}

#[test]
fn liability_claim_response_rejects_tampered_nested_claim_signature() {
    let fixtures = sample_market_fixtures();
    let mut response = fixtures.claim_response.body.clone();
    response.claim.body.claim_amount = usd(1);

    let error = require_err(response.validate(), "tampered claim rejected");
    assert!(error.contains("claim response claim signature verification failed"));
}

#[test]
fn liability_claim_dispute_rejects_fully_accepted_response() {
    let fixtures = sample_market_fixtures();
    let mut dispute = fixtures.claim_dispute.body.clone();
    let mut provider_response = dispute.provider_response.body.clone();
    provider_response.covered_amount = Some(provider_response.claim.body.claim_amount.clone());
    dispute.provider_response = sign_export(provider_response);

    let error = require_err(
        dispute.validate(),
        "fully accepted response cannot be disputed",
    );
    assert!(error.contains("denied or partially accepted"));
}

#[test]
fn liability_claim_adjudication_rejects_partial_settlement_at_full_amount() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.awarded_amount = Some(
        adjudication
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_amount
            .clone(),
    );

    let error = require_err(
        adjudication.validate(),
        "partial settlement must be less than full claim",
    );
    assert!(error.contains("must be less than claim_amount"));
}

#[test]
fn liability_claim_workflow_query_normalizes_and_clamps_fields() {
    let query = LiabilityClaimWorkflowQuery {
        claim_id: Some(" clm-1 ".to_string()),
        provider_id: Some(" carrier-alpha ".to_string()),
        agent_subject: Some(" subject-1 ".to_string()),
        jurisdiction: Some("US-NY".to_string()),
        policy_number: Some(" POL-Chio-1 ".to_string()),
        limit: Some(500),
    }
    .normalized();

    assert_eq!(query.claim_id.as_deref(), Some("clm-1"));
    assert_eq!(query.provider_id.as_deref(), Some("carrier-alpha"));
    assert_eq!(query.agent_subject.as_deref(), Some("subject-1"));
    assert_eq!(query.jurisdiction.as_deref(), Some("us-ny"));
    assert_eq!(query.policy_number.as_deref(), Some("POL-Chio-1"));
    assert_eq!(query.limit, Some(MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT));
}

#[test]
fn liability_claim_payout_instruction_validates_transfer_flow() {
    let fixtures = sample_market_fixtures();
    assert!(fixtures.payout_instruction.body.validate().is_ok());
}

#[test]
fn liability_claim_payout_instruction_rejects_observed_capital_instruction() {
    let fixtures = sample_market_fixtures();
    let mut payout = fixtures.payout_instruction.body.clone();
    let mut capital_instruction = payout.capital_instruction.body.clone();
    capital_instruction.observed_execution = Some(crate::credit::CapitalExecutionObservation {
        observed_at: 1_700_011_000,
        external_reference_id: "exec-early".to_string(),
        amount: usd(6_000),
    });
    capital_instruction.reconciled_state = crate::credit::CapitalExecutionReconciledState::Matched;
    payout.capital_instruction = sign_export(capital_instruction);

    let error = require_err(
        payout.validate(),
        "observed capital instruction should be rejected",
    );
    assert!(error.contains("require an unreconciled capital_instruction"));
}

#[test]
fn liability_claim_payout_receipt_rejects_matched_amount_mismatch() {
    let fixtures = sample_market_fixtures();
    let mut receipt = fixtures.payout_receipt.body.clone();
    receipt.observed_execution.amount = usd(5_500);

    let error = require_err(
        receipt.validate(),
        "matched payouts require identical amount",
    );
    assert!(error.contains("observed_execution amount to match payout_amount"));
}

#[test]
fn liability_claim_payout_receipt_rejects_tampered_nested_instruction_signature() {
    let fixtures = sample_market_fixtures();
    let mut receipt = fixtures.payout_receipt.body.clone();
    receipt.payout_instruction.body.payout_amount = usd(1);

    let error = require_err(receipt.validate(), "tampered payout instruction rejected");
    assert!(error.contains("payout_instruction signature verification failed"));
}

#[test]
fn liability_claim_settlement_instruction_validates_topology_and_authority_chain() {
    let fixtures = sample_market_fixtures();
    assert!(fixtures.settlement_instruction.body.validate().is_ok());
}

#[test]
fn liability_claim_settlement_instruction_rejects_missing_custodian_approval() {
    let fixtures = sample_market_fixtures();
    let mut instruction = fixtures.settlement_instruction.body.clone();
    instruction
        .authority_chain
        .retain(|step| step.role != crate::credit::CapitalExecutionRole::Custodian);

    let error = require_err(instruction.validate(), "custodian approval required");
    assert!(error.contains("missing the custody-provider execution step"));
}

#[test]
fn liability_claim_settlement_instruction_rejects_self_asserted_authority_role() {
    let fixtures = sample_market_fixtures();
    let mut instruction = fixtures.settlement_instruction.body.clone();
    instruction.authority_chain[0].principal_id = "facility-provider-self-asserted".to_string();

    let error = require_err(instruction.validate(), "self-asserted settlement authority");
    assert!(error.contains("authority proof signer must match principalId"));
}

#[test]
fn liability_claim_settlement_receipt_rejects_counterparty_match_in_mismatch_state() {
    let fixtures = sample_market_fixtures();
    let mut receipt = fixtures.settlement_receipt.body.clone();
    receipt.reconciliation_state =
        LiabilityClaimSettlementReconciliationState::CounterpartyMismatch;

    let error = require_err(
        receipt.validate(),
        "counterparty mismatch requires differing counterparties",
    );
    assert!(error.contains("require at least one observed counterparty to differ"));
}
