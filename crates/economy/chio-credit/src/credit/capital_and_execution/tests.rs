    use super::*;
    use crate::crypto::Keypair;

    fn validation_error(result: Result<(), String>, message: &str) -> String {
        match result {
            Ok(()) => panic!("{message}"),
            Err(error) => error,
        }
    }

    fn signed_authority_step(
        role: CapitalExecutionRole,
        principal: &Keypair,
        approved_at: u64,
        expires_at: u64,
        note: Option<&str>,
    ) -> CapitalExecutionAuthorityStep {
        CapitalExecutionAuthorityStep::signed(
            role,
            principal,
            approved_at,
            expires_at,
            note.map(str::to_string),
        )
        .unwrap()
    }

    fn valid_capital_instruction_artifact() -> CapitalExecutionInstructionArtifact {
        let treasury = Keypair::generate();
        let custodian = Keypair::generate();
        let custodian_id = custodian.public_key().to_hex();
        CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-validator-1".to_string(),
            issued_at: 10,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:bond:cbd-1".to_string(),
            source_kind: CapitalBookSourceKind::ReserveBook,
            governed_receipt_id: None,
            completion_flow_row_id: None,
            action: CapitalExecutionInstructionAction::LockReserve,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: 400,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                signed_authority_step(CapitalExecutionRole::OperatorTreasury, &treasury, 9, 20, None),
                signed_authority_step(CapitalExecutionRole::Custodian, &custodian, 9, 20, None),
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 10,
                not_after: 20,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Manual,
                rail_id: "rail-1".to_string(),
                custody_provider_id: custodian_id,
                source_account_ref: Some("reserve-main".to_string()),
                destination_account_ref: None,
                jurisdiction: Some("US-NY".to_string()),
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::Matched,
            related_instruction_id: None,
            observed_execution: Some(CapitalExecutionObservation {
                observed_at: 12,
                external_reference_id: "wire-1".to_string(),
                amount: MonetaryAmount {
                    units: 400,
                    currency: "USD".to_string(),
                },
            }),
            support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
            evidence_refs: Vec::new(),
            description: "lock reserve".to_string(),
        }
    }

    #[test]
    fn bounded_limit_helper_preserves_default_and_clamps_edges() {
        assert_eq!(bounded_limit_or_default(None, 50, 100), 50);
        assert_eq!(bounded_limit_or_default(Some(0), 50, 100), 1);
        assert_eq!(bounded_limit_or_default(Some(75), 50, 100), 75);
        assert_eq!(bounded_limit_or_default(Some(250), 50, 100), 100);
    }

    #[test]
    fn exposure_ledger_query_clamps_limits() {
        let query = ExposureLedgerQuery {
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            ..ExposureLedgerQuery::default()
        };

        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT
        );
        assert_eq!(
            query.decision_limit_or_default(),
            MAX_EXPOSURE_LEDGER_DECISION_LIMIT
        );
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
    }

    #[test]
    fn exposure_ledger_query_requires_anchor() {
        let query = ExposureLedgerQuery::default();
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require at least one anchor")
        );
    }

    #[test]
    fn capital_execution_instruction_requires_source_owner_authority() {
        let mut artifact = valid_capital_instruction_artifact();
        let owner_role = artifact.owner_role;
        artifact
            .authority_chain
            .retain(|step| step.role != owner_role);

        let error = validation_error(
            artifact.validate(),
            "missing source-owner authority must reject",
        );
        assert!(error.contains("source-owner approval"));
    }

    #[test]
    fn capital_execution_instruction_rejects_authority_proof_principal_mismatch() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.authority_chain[0].principal_id = "treasury-self-asserted".to_string();

        let error = validation_error(
            artifact.validate(),
            "self-asserted authority principal must reject",
        );
        assert!(error.contains("authority proof signer must match principalId"));
    }

    #[test]
    fn capital_execution_instruction_rejects_tampered_authority_proof_body() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.authority_chain[0].authority_proof.body.role =
            CapitalExecutionRole::FacilityProvider;

        let error = validation_error(
            artifact.validate(),
            "tampered authority proof body must reject",
        );
        assert!(error.contains("authority proof signature verification failed"));
    }

    #[test]
    fn exposure_ledger_query_rejects_blank_filter_values() {
        let query = ExposureLedgerQuery {
            agent_subject: Some(" ".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("--agent-subject must be non-empty")
        );

        let query = ExposureLedgerQuery {
            tool_server: Some(" tool-server ".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("--tool-server must not contain surrounding whitespace")
        );
    }

    #[test]
    fn exposure_ledger_query_requires_tool_server_when_tool_name_present() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            tool_name: Some("transfer".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("must also specify --tool-server")
        );
    }

    #[test]
    fn exposure_ledger_query_rejects_inverted_time_window() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            since: Some(20),
            until: Some(10),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("less than or equal to --until")
        );
    }

    #[test]
    fn credit_backtest_query_requires_subject_scope() {
        let query = CreditBacktestQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditBacktestQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require --agent-subject")
        );
    }

    #[test]
    fn credit_backtest_query_clamps_limits() {
        let query = CreditBacktestQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            window_count: Some(999),
            stale_after_seconds: Some(0),
            window_seconds: Some(0),
            ..CreditBacktestQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
        assert_eq!(
            normalized.window_count,
            Some(MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
        );
        assert_eq!(normalized.window_seconds, Some(1));
        assert_eq!(normalized.stale_after_seconds, Some(1));
    }

    #[test]
    fn provider_risk_package_query_requires_subject_scope() {
        let query = CreditProviderRiskPackageQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditProviderRiskPackageQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require --agent-subject")
        );
    }

    #[test]
    fn provider_risk_package_query_clamps_recent_loss_limit() {
        let query = CreditProviderRiskPackageQuery {
            agent_subject: Some("subject-1".to_string()),
            recent_loss_limit: Some(999),
            ..CreditProviderRiskPackageQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.recent_loss_limit,
            Some(MAX_CREDIT_PROVIDER_LOSS_LIMIT)
        );
    }

    #[test]
    fn capital_book_query_requires_subject_scope() {
        let query = CapitalBookQuery {
            capability_id: Some("cap-1".to_string()),
            ..CapitalBookQuery::default()
        };
        assert!(query.validate().unwrap_err().contains("--agent-subject"));
    }

    #[test]
    fn capital_book_query_clamps_limits() {
        let query = CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            facility_limit: Some(999),
            bond_limit: Some(999),
            loss_event_limit: Some(999),
            ..CapitalBookQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.facility_limit,
            Some(MAX_CREDIT_FACILITY_LIST_LIMIT)
        );
        assert_eq!(normalized.bond_limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
        assert_eq!(
            normalized.loss_event_limit,
            Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
        );
    }

    #[test]
    fn bonded_execution_simulation_query_requires_bond_id() {
        let query = CreditBondedExecutionSimulationQuery {
            bond_id: "   ".to_string(),
            autonomy_tier: GovernedAutonomyTier::Delegated,
            runtime_assurance_tier: RuntimeAssuranceTier::Attested,
            call_chain_present: true,
        };
        assert!(query.validate().unwrap_err().contains("--bond-id"));
    }

    #[test]
    fn bonded_execution_control_policy_defaults_fail_closed() {
        let policy = CreditBondedExecutionControlPolicy::default();
        assert!(!policy.kill_switch);
        assert!(policy.require_delegated_call_chain);
        assert!(policy.deny_if_bond_not_active);
        assert!(policy.deny_if_outstanding_delinquency);
    }

    #[test]
    fn capital_execution_instruction_artifact_validates_authority_and_reconciliation() {
        let artifact = valid_capital_instruction_artifact();
        artifact.validate().unwrap();
    }

    #[test]
    fn capital_execution_instruction_rejects_control_character_identities() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.instruction_id = "cei-1\ncei-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character instruction id to fail"),
            Err(error) => error,
        };
        assert!(error.contains("instructionId"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.subject_key = "subject-1\nsubject-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character subject key to fail"),
            Err(error) => error,
        };
        assert!(error.contains("subjectKey"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.rail.rail_id = "rail-1\nrail-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character rail id to fail"),
            Err(error) => error,
        };
        assert!(error.contains("railId"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.authority_chain[0].principal_id = "principal-1\nprincipal-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character authority principal to fail"),
            Err(error) => error,
        };
        assert!(error.contains("principalId"));
        assert!(error.contains("control characters"));
    }

    #[test]
    fn capital_execution_envelope_rejects_stale_authority() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.execution_window.not_after = 30;
        let error = validate_capital_execution_envelope(
            &artifact.authority_chain,
            &artifact.execution_window,
            &artifact.rail,
            21,
        )
        .unwrap_err();

        assert!(error.contains("stale"));
    }

    #[test]
    fn capital_execution_envelope_rejects_future_dated_authority_approval() {
        let mut artifact = valid_capital_instruction_artifact();
        let treasury = Keypair::generate();
        artifact.authority_chain[0] = signed_authority_step(
            CapitalExecutionRole::OperatorTreasury,
            &treasury,
            artifact.issued_at + 1,
            artifact.execution_window.not_after,
            None,
        );

        let error = validate_capital_execution_envelope(
            &artifact.authority_chain,
            &artifact.execution_window,
            &artifact.rail,
            artifact.issued_at,
        )
        .unwrap_err();

        assert!(error.contains("approvedAt"));
        assert!(error.contains("after instruction issuance"));
    }

    #[test]
    fn capital_instruction_artifact_rejects_transfer_without_completion_flow() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.source_kind = CapitalBookSourceKind::FacilityCommitment;
        artifact.action = CapitalExecutionInstructionAction::TransferFunds;
        artifact.governed_receipt_id = Some("rcpt-1".to_string());
        artifact.completion_flow_row_id = None;

        let error = artifact.validate().unwrap_err();

        assert!(error.contains("completionFlowRowId"));
    }

    #[test]
    fn capital_instruction_artifact_rejects_observed_execution_amount_mismatch() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.observed_execution = Some(CapitalExecutionObservation {
            observed_at: 12,
            external_reference_id: "wire-1".to_string(),
            amount: MonetaryAmount {
                units: 401,
                currency: "USD".to_string(),
            },
        });

        let error = artifact.validate().unwrap_err();

        assert!(error.contains("does not match intended amount"));
    }

    #[test]
    fn credit_bond_list_query_clamps_limit() {
        let query = CreditBondListQuery {
            agent_subject: Some("subject-1".to_string()),
            limit: Some(9_999),
            ..CreditBondListQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(normalized.limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
    }

    #[test]
    fn credit_bond_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: "cbd-1".to_string(),
                issued_at: 10,
                expires_at: 20,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 10,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: ExposureLedgerSummary {
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
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: Some("cfd-1".to_string()),
                    terms: Some(CreditBondTerms {
                        facility_id: "cfd-1".to_string(),
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        collateral_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        reserve_requirement_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        outstanding_exposure_amount: MonetaryAmount {
                            units: 0,
                            currency: "USD".to_string(),
                        },
                        reserve_ratio_bps: 1_000,
                        coverage_ratio_bps: 10_000,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: vec![CreditBondFinding {
                        code: CreditBondReasonCode::ReserveHeld,
                        description: "reserve state is held".to_string(),
                        evidence_refs: Vec::new(),
                    }],
                },
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditBond =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn provider_risk_package_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let exposure = SignedExposureLedgerReport::sign(
            ExposureLedgerReport {
                schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: ExposureLedgerSupportBoundary::default(),
                summary: ExposureLedgerSummary {
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
                positions: vec![ExposureLedgerCurrencyPosition {
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
        )
        .unwrap();
        let scorecard = SignedCreditScorecardReport::sign(
            CreditScorecardReport {
                schema: CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: CreditScorecardSupportBoundary::default(),
                summary: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: CreditScorecardProbationStatus {
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
        )
        .unwrap();
        let envelope = SignedCreditProviderRiskPackage::sign(
            CreditProviderRiskPackage {
                schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CreditProviderRiskPackageQuery::default()
                },
                support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
                exposure,
                scorecard,
                facility_report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditFacilityDisposition::Grant,
                    prerequisites: CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: CreditFacilitySupportBoundary::default(),
                    terms: Some(CreditFacilityTerms {
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_500,
                        concentration_cap_bps: 3_000,
                        ttl_seconds: 86_400,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
                compliance_score: None,
                latest_facility: Some(CreditProviderFacilitySnapshot {
                    facility_id: "cfd-1".to_string(),
                    issued_at: 3,
                    expires_at: 4,
                    disposition: CreditFacilityDisposition::Grant,
                    lifecycle_state: CreditFacilityLifecycleState::Active,
                    credit_limit: Some(MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    }),
                    supersedes_facility_id: None,
                    signer_key: keypair.public_key().to_hex(),
                }),
                runtime_assurance: Some(CreditRuntimeAssuranceState {
                    governed_receipts: 1,
                    runtime_assurance_receipts: 1,
                    highest_tier: Some(RuntimeAssuranceTier::Verified),
                    latest_schema: Some("chio.runtime-attestation.azure-maa.jwt.v1".to_string()),
                    latest_verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                    latest_verifier: Some("verifier.chio".to_string()),
                    latest_evidence_sha256: Some("sha256-runtime".to_string()),
                    observed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    stale: false,
                }),
                certification: CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: CreditRecentLossHistory {
                    summary: CreditRecentLossSummary {
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
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditProviderRiskPackage =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_book_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalBookReport::sign(
            CapitalBookReport {
                schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
                generated_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                support_boundary: CapitalBookSupportBoundary::default(),
                summary: CapitalBookSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_facilities: 1,
                    returned_facilities: 1,
                    matching_bonds: 1,
                    returned_bonds: 1,
                    matching_loss_events: 1,
                    returned_loss_events: 1,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    funding_sources: 2,
                    ledger_events: 3,
                    truncated_receipts: false,
                    truncated_facilities: false,
                    truncated_bonds: false,
                    truncated_loss_events: false,
                },
                sources: vec![
                    CapitalBookSource {
                        source_id: "capital-source:facility:cfd-1".to_string(),
                        kind: CapitalBookSourceKind::FacilityCommitment,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: Some(MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        }),
                        held_amount: None,
                        drawn_amount: Some(MonetaryAmount {
                            units: 500,
                            currency: "USD".to_string(),
                        }),
                        disbursed_amount: Some(MonetaryAmount {
                            units: 2_000,
                            currency: "USD".to_string(),
                        }),
                        released_amount: None,
                        repaid_amount: None,
                        impaired_amount: None,
                        description: "facility source".to_string(),
                    },
                    CapitalBookSource {
                        source_id: "capital-source:bond:cbd-1".to_string(),
                        kind: CapitalBookSourceKind::ReserveBook,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: None,
                        held_amount: Some(MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        }),
                        drawn_amount: None,
                        disbursed_amount: None,
                        released_amount: Some(MonetaryAmount {
                            units: 50,
                            currency: "USD".to_string(),
                        }),
                        repaid_amount: Some(MonetaryAmount {
                            units: 200,
                            currency: "USD".to_string(),
                        }),
                        impaired_amount: Some(MonetaryAmount {
                            units: 300,
                            currency: "USD".to_string(),
                        }),
                        description: "bond source".to_string(),
                    },
                ],
                events: vec![CapitalBookEvent {
                    event_id: "commit:cfd-1".to_string(),
                    kind: CapitalBookEventKind::Commit,
                    occurred_at: 10,
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    owner_role: CapitalBookRole::OperatorTreasury,
                    counterparty_role: CapitalBookRole::AgentCounterparty,
                    counterparty_id: "subject-1".to_string(),
                    amount: MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    },
                    facility_id: Some("cfd-1".to_string()),
                    bond_id: None,
                    loss_event_id: None,
                    receipt_id: None,
                    description: "commit".to_string(),
                    evidence_refs: vec![CapitalBookEvidenceReference {
                        kind: CapitalBookEvidenceKind::CreditFacility,
                        reference_id: "cfd-1".to_string(),
                        observed_at: Some(10),
                        locator: Some("credit-facility:cfd-1".to_string()),
                    }],
                }],
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalBookReport =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_execution_instruction_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let treasury = Keypair::generate();
        let custodian = Keypair::generate();
        let custodian_id = custodian.public_key().to_hex();
        let envelope = SignedCapitalExecutionInstruction::sign(
            CapitalExecutionInstructionArtifact {
                schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
                instruction_id: "cei-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                source_id: "capital-source:bond:cbd-1".to_string(),
                source_kind: CapitalBookSourceKind::ReserveBook,
                governed_receipt_id: None,
                completion_flow_row_id: None,
                action: CapitalExecutionInstructionAction::LockReserve,
                owner_role: CapitalExecutionRole::OperatorTreasury,
                counterparty_role: CapitalExecutionRole::AgentCounterparty,
                counterparty_id: "subject-1".to_string(),
                amount: Some(MonetaryAmount {
                    units: 400,
                    currency: "USD".to_string(),
                }),
                authority_chain: vec![
                    signed_authority_step(
                        CapitalExecutionRole::OperatorTreasury,
                        &treasury,
                        9,
                        20,
                        None,
                    ),
                    signed_authority_step(
                        CapitalExecutionRole::Custodian,
                        &custodian,
                        9,
                        20,
                        None,
                    ),
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: custodian_id,
                    source_account_ref: Some("reserve-main".to_string()),
                    destination_account_ref: None,
                    jurisdiction: Some("US-NY".to_string()),
                },
                intended_state: CapitalExecutionIntendedState::PendingExecution,
                reconciled_state: CapitalExecutionReconciledState::Matched,
                related_instruction_id: None,
                observed_execution: Some(CapitalExecutionObservation {
                    observed_at: 12,
                    external_reference_id: "wire-1".to_string(),
                    amount: MonetaryAmount {
                        units: 400,
                        currency: "USD".to_string(),
                    },
                }),
                support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditBond,
                    reference_id: "cbd-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("credit-bond:cbd-1".to_string()),
                }],
                description: "lock reserve".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalExecutionInstruction =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_allocation_decision_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let treasury = Keypair::generate();
        let custodian = Keypair::generate();
        let custodian_id = custodian.public_key().to_hex();
        let envelope = SignedCapitalAllocationDecision::sign(
            CapitalAllocationDecisionArtifact {
                schema: CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA.to_string(),
                allocation_id: "cad-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                governed_receipt_id: "rc-1".to_string(),
                intent_id: "intent-1".to_string(),
                approval_token_id: Some("approval-1".to_string()),
                capability_id: "cap-1".to_string(),
                tool_server: "ledger".to_string(),
                tool_name: "transfer".to_string(),
                requested_amount: MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                },
                facility_id: Some("cfd-1".to_string()),
                bond_id: Some("cbd-1".to_string()),
                source_id: Some("capital-source:facility:cfd-1".to_string()),
                source_kind: Some(CapitalBookSourceKind::FacilityCommitment),
                reserve_source_id: Some("capital-source:bond:cbd-1".to_string()),
                outcome: CapitalAllocationDecisionOutcome::Allocate,
                authority_chain: vec![
                    signed_authority_step(
                        CapitalExecutionRole::OperatorTreasury,
                        &treasury,
                        9,
                        20,
                        None,
                    ),
                    signed_authority_step(
                        CapitalExecutionRole::Custodian,
                        &custodian,
                        9,
                        20,
                        None,
                    ),
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: custodian_id,
                    source_account_ref: Some("facility-main".to_string()),
                    destination_account_ref: Some("merchant-1".to_string()),
                    jurisdiction: Some("US-NY".to_string()),
                },
                current_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                projected_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                current_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                required_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                reserve_delta_amount: None,
                utilization_ceiling_amount: Some(MonetaryAmount {
                    units: 900,
                    currency: "USD".to_string(),
                }),
                concentration_cap_amount: Some(MonetaryAmount {
                    units: 350,
                    currency: "USD".to_string(),
                }),
                instruction_drafts: vec![CapitalAllocationInstructionDraft {
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    source_kind: CapitalBookSourceKind::FacilityCommitment,
                    action: CapitalExecutionInstructionAction::TransferFunds,
                    amount: MonetaryAmount {
                        units: 300,
                        currency: "USD".to_string(),
                    },
                    description: "transfer approved funds".to_string(),
                }],
                support_boundary: CapitalAllocationDecisionSupportBoundary::default(),
                findings: Vec::new(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rc-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("receipt:rc-1".to_string()),
                }],
                description: "allocate governed action".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalAllocationDecision =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }
