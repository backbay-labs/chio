use super::*;

pub(crate) fn build_credit_provider_risk_package_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    keypair: &Keypair,
    query: &CreditProviderRiskPackageQuery,
    read_context: chio_kernel::ReceiptReadContext,
) -> Result<CreditProviderRiskPackage, TrustHttpError> {
    let normalized = query.normalized();
    if let Err(message) = normalized.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let subject_key = normalized.agent_subject.clone().ok_or_else(|| {
        TrustHttpError::bad_request("provider risk packages require subject scope")
    })?;
    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized.capability_id.clone(),
        agent_subject: normalized.agent_subject.clone(),
        tool_server: normalized.tool_server.clone(),
        tool_name: normalized.tool_name.clone(),
        since: normalized.since,
        until: normalized.until,
        receipt_limit: normalized.receipt_limit,
        read_context: Some(read_context.clone()),
    };
    let (matching_loss_events, recent_loss_receipts) = receipt_store
        .query_recent_credit_loss_receipts(
            &behavioral_query,
            normalized.recent_loss_limit_or_default(),
        )
        .map_err(trust_http_error_from_receipt_store)?;
    let exposure_query = normalized.exposure_query().normalized();
    let exposure_report = build_exposure_ledger_report_with_context(
        receipt_store,
        &exposure_query,
        read_context.clone(),
    )?;
    let signed_exposure = SignedExposureLedgerReport::sign(exposure_report.clone(), keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    // Anchor the reputation scoring trust set to this signer's public key so
    // locally signed receipts are not silently filtered out (see
    // chio-reputation::receipt_integrity_valid).
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let scorecard_report = build_credit_scorecard_report_with_context(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        &exposure_query,
        read_context.clone(),
        &trusted_kernel_keys,
    )?;
    let signed_scorecard = SignedCreditScorecardReport::sign(scorecard_report.clone(), keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let facility_report = build_credit_facility_report_from_store_with_context(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &exposure_query,
        read_context.clone(),
        &trusted_kernel_keys,
    )?;
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&exposure_query),
        read_context.clone(),
        &trusted_kernel_keys,
    )?;
    let latest_facility = latest_credit_facility_snapshot(
        receipt_store,
        normalized.capability_id.as_deref(),
        normalized.agent_subject.as_deref(),
        normalized.tool_server.as_deref(),
        normalized.tool_name.as_deref(),
    )?;
    let stale_runtime_evidence = exposure_report
        .receipts
        .iter()
        .map(|row| row.timestamp)
        .max()
        .is_none_or(|timestamp| {
            unix_timestamp_now().saturating_sub(timestamp)
                > UnderwritingDecisionPolicy::default().maximum_receipt_age_seconds
        });

    let evidence_refs =
        collect_credit_provider_risk_evidence(&scorecard_report, &underwriting_input);

    Ok(CreditProviderRiskPackage {
        schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        subject_key,
        filters: normalized.clone(),
        support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
        exposure: signed_exposure,
        scorecard: signed_scorecard,
        facility_report,
        compliance_score: underwriting_input.compliance_score.clone(),
        latest_facility,
        runtime_assurance: underwriting_input
            .runtime_assurance
            .as_ref()
            .map(|runtime| CreditRuntimeAssuranceState {
                governed_receipts: runtime.governed_receipts,
                runtime_assurance_receipts: runtime.runtime_assurance_receipts,
                highest_tier: runtime.highest_tier,
                latest_schema: runtime.latest_schema.clone(),
                latest_verifier_family: runtime.latest_verifier_family,
                latest_verifier: runtime.latest_verifier.clone(),
                latest_evidence_sha256: runtime.latest_evidence_sha256.clone(),
                observed_verifier_families: runtime.observed_verifier_families.clone(),
                stale: stale_runtime_evidence,
            }),
        certification: CreditCertificationState {
            required: normalized.tool_server.is_some(),
            state: underwriting_input
                .certification
                .as_ref()
                .map(|certification| certification.state.clone()),
            artifact_id: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.artifact_id.clone()),
            checked_at: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.checked_at),
            published_at: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.published_at),
        },
        recent_loss_history: build_credit_recent_loss_history(
            matching_loss_events,
            &recent_loss_receipts,
            normalized.recent_loss_limit_or_default(),
        )?,
        evidence_refs,
    })
}

pub(crate) fn build_credit_scorecard_report(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditScorecardReport, TrustHttpError> {
    build_credit_scorecard_report_with_context(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        trusted_kernel_keys,
    )
}

pub(crate) fn build_credit_scorecard_report_with_context(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    read_context: chio_kernel::ReceiptReadContext,
    trusted_kernel_keys: &[String],
) -> Result<CreditScorecardReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }
    let subject_key = normalized_query.agent_subject.clone().ok_or_else(|| {
        TrustHttpError::bad_request(
            "credit scorecard queries require --agent-subject because scorecards are subject-scoped"
                .to_string(),
        )
    })?;

    let exposure = build_exposure_ledger_report_with_context(
        receipt_store,
        &normalized_query,
        read_context.clone(),
    )?;
    if exposure.summary.matching_receipts == 0 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit scorecard requires at least one matching governed receipt".to_string(),
        ));
    }

    let mut inspection = issuance::inspect_local_reputation_with_read_context(
        &subject_key,
        Some(receipt_db_path),
        budget_db_path,
        normalized_query.since,
        normalized_query.until,
        issuance_policy,
        trusted_kernel_keys,
        &read_context,
    )
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;

    inspection.imported_trust = Some(
        reputation::build_imported_trust_report(
            receipt_db_path,
            &inspection.subject_key,
            inspection.since,
            inspection.until,
            unix_timestamp_now(),
            &inspection.scoring,
        )
        .map_err(|error| TrustHttpError::internal(error.to_string()))?,
    );

    let exposure_units =
        credit_scorecard_position_denominator(&exposure.positions).ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                "credit scorecard requires monetary exposure in the requested window".to_string(),
            )
        })?;
    let confidence = resolve_credit_scorecard_confidence(&inspection);
    let probation = build_credit_scorecard_probation(&inspection, confidence);
    let dimensions = build_credit_scorecard_dimensions(
        &subject_key,
        &exposure,
        &inspection,
        exposure_units as f64,
    );
    let overall_score = compute_credit_scorecard_overall_score(&dimensions).ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit scorecard could not compute a deterministic score from the requested evidence"
                .to_string(),
        )
    })?;
    let anomalies =
        build_credit_scorecard_anomalies(&subject_key, &exposure, &inspection, exposure_units);
    let band = resolve_credit_scorecard_band(overall_score, probation.probationary);
    let imported_trust = inspection.imported_trust.as_ref();

    Ok(CreditScorecardReport {
        schema: CREDIT_SCORECARD_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: normalized_query,
        support_boundary: CreditScorecardSupportBoundary::default(),
        summary: CreditScorecardSummary {
            matching_receipts: exposure.summary.matching_receipts,
            returned_receipts: exposure.summary.returned_receipts,
            matching_decisions: exposure.summary.matching_decisions,
            returned_decisions: exposure.summary.returned_decisions,
            currencies: exposure.summary.currencies.clone(),
            mixed_currency_book: exposure.summary.mixed_currency_book,
            confidence,
            band,
            overall_score: round_credit_score_value(overall_score),
            anomaly_count: anomalies.len() as u64,
            probationary: probation.probationary,
        },
        reputation: CreditScorecardReputationContext {
            effective_score: round_credit_score_value(inspection.effective_score),
            probationary: inspection.probationary,
            resolved_tier: inspection
                .resolved_tier
                .as_ref()
                .map(|tier| tier.name.clone()),
            imported_signal_count: imported_trust.map_or(0, |report| report.signal_count),
            accepted_imported_signal_count: imported_trust
                .map_or(0, |report| report.accepted_count),
        },
        positions: exposure.positions,
        probation,
        dimensions,
        anomalies,
    })
}

pub(crate) fn build_credit_facility_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditFacilityReport, TrustHttpError> {
    build_credit_facility_report_from_store_with_context(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        trusted_kernel_keys,
    )
}

fn build_credit_facility_report_from_store_with_context(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    read_context: chio_kernel::ReceiptReadContext,
    trusted_kernel_keys: &[String],
) -> Result<CreditFacilityReport, TrustHttpError> {
    let scorecard = build_credit_scorecard_report_with_context(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        query,
        read_context.clone(),
        trusted_kernel_keys,
    )?;
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&scorecard.filters),
        read_context,
        trusted_kernel_keys,
    )?;
    let minimum_runtime_assurance_tier =
        credit_facility_minimum_runtime_assurance_tier(scorecard.summary.band);
    let runtime_assurance = underwriting_input.runtime_assurance.as_ref();
    let runtime_assurance_met = runtime_assurance
        .and_then(|runtime| runtime.highest_tier)
        .is_some_and(|tier| tier >= minimum_runtime_assurance_tier);
    let mixed_runtime_assurance_provenance =
        runtime_assurance.is_some_and(|runtime| runtime.observed_verifier_families.len() > 1);
    let certification_required = scorecard.filters.tool_server.is_some();
    let certification_met = !certification_required
        || underwriting_input
            .certification
            .as_ref()
            .is_some_and(|certification| {
                certification.state == UnderwritingCertificationState::Active
            });
    let mixed_currency_book = scorecard.summary.mixed_currency_book;
    let probationary = scorecard.summary.probationary;
    let restricted = scorecard.summary.band == CreditScorecardBand::Restricted;
    let failed_backlog = credit_facility_has_reason(
        &scorecard,
        CreditScorecardReasonCode::FailedSettlementBacklog,
    );
    let pending_backlog = credit_facility_has_reason(
        &scorecard,
        CreditScorecardReasonCode::PendingSettlementBacklog,
    );

    let disposition =
        if restricted || !runtime_assurance_met || (certification_required && !certification_met) {
            CreditFacilityDisposition::Deny
        } else if mixed_currency_book
            || failed_backlog
            || probationary
            || pending_backlog
            || mixed_runtime_assurance_provenance
        {
            CreditFacilityDisposition::ManualReview
        } else {
            CreditFacilityDisposition::Grant
        };

    let prerequisites = CreditFacilityPrerequisites {
        minimum_runtime_assurance_tier,
        runtime_assurance_met,
        certification_required,
        certification_met,
        manual_review_required: disposition == CreditFacilityDisposition::ManualReview,
    };
    let terms = if disposition == CreditFacilityDisposition::Grant {
        build_credit_facility_terms(&scorecard)
    } else {
        None
    };
    let findings = build_credit_facility_findings(
        &scorecard,
        &underwriting_input,
        &prerequisites,
        disposition,
    );

    Ok(CreditFacilityReport {
        schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: scorecard.filters.clone(),
        scorecard: scorecard.summary,
        disposition,
        prerequisites,
        support_boundary: CreditFacilitySupportBoundary::default(),
        terms,
        findings,
    })
}

pub(crate) fn build_credit_bond_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditBondReport, TrustHttpError> {
    let scorecard = build_credit_scorecard_report(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        query,
        trusted_kernel_keys,
    )?;
    let exposure = build_exposure_ledger_report(receipt_store, &scorecard.filters)?;
    if exposure.summary.mixed_currency_book || exposure.positions.len() != 1 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit bond evaluation requires one coherent currency book because Chio does not auto-net reserve accounting across currencies"
                .to_string(),
        ));
    }
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&scorecard.filters),
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        trusted_kernel_keys,
    )?;

    let facility_policy = build_credit_facility_report_from_store(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &scorecard.filters,
        trusted_kernel_keys,
    )?;
    let latest_facility = latest_active_granted_credit_facility(
        receipt_store,
        scorecard.filters.capability_id.as_deref(),
        scorecard.filters.agent_subject.as_deref(),
        scorecard.filters.tool_server.as_deref(),
        scorecard.filters.tool_name.as_deref(),
    )?;
    let position = exposure.positions.first().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit bond evaluation requires one monetary exposure position".to_string(),
        )
    })?;

    let pending_backlog = underwriting_input.receipts.pending_settlement_receipts > 0
        || credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::PendingSettlementBacklog,
        );
    let failed_backlog = underwriting_input.receipts.failed_settlement_receipts > 0
        || credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::FailedSettlementBacklog,
        );
    let net_provisional_loss_units = position
        .provisional_loss_units
        .saturating_sub(position.recovered_units);
    let outstanding_exposure_units = credit_bond_outstanding_units(position);
    let active_facility_required =
        outstanding_exposure_units > 0 || pending_backlog || failed_backlog;
    let active_facility_met = latest_facility.is_some();

    let prerequisites = CreditBondPrerequisites {
        active_facility_required,
        active_facility_met,
        runtime_assurance_met: facility_policy.prerequisites.runtime_assurance_met,
        certification_required: facility_policy.prerequisites.certification_required,
        certification_met: facility_policy.prerequisites.certification_met,
        currency_coherent: true,
    };

    let (disposition, terms, under_collateralized) = match latest_facility.as_ref() {
        Some(facility) => {
            let facility_terms = facility.body.report.terms.as_ref().ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit facility `{}` is missing grant terms required for bond accounting",
                        facility.body.facility_id
                    ),
                )
            })?;
            if facility_terms.credit_limit.currency != position.currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit bond evaluation cannot mix facility currency `{}` with exposure currency `{}`",
                        facility_terms.credit_limit.currency, position.currency
                    ),
                ));
            }
            let terms = build_credit_bond_terms(
                position,
                facility_terms,
                facility.body.facility_id.clone(),
            );
            let under_collateralized = terms.coverage_ratio_bps < 10_000;
            let disposition =
                if failed_backlog || net_provisional_loss_units > 0 || under_collateralized {
                    CreditBondDisposition::Impair
                } else if outstanding_exposure_units > 0 || pending_backlog {
                    CreditBondDisposition::Lock
                } else {
                    CreditBondDisposition::Hold
                };
            (disposition, Some(terms), under_collateralized)
        }
        None => {
            let disposition = if active_facility_required {
                CreditBondDisposition::Impair
            } else {
                CreditBondDisposition::Release
            };
            (disposition, None, false)
        }
    };
    let findings = build_credit_bond_findings(
        &scorecard,
        &exposure,
        &prerequisites,
        disposition,
        pending_backlog,
        failed_backlog,
        under_collateralized,
    );

    Ok(CreditBondReport {
        schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: scorecard.filters.clone(),
        exposure: exposure.summary,
        scorecard: scorecard.summary,
        disposition,
        prerequisites,
        support_boundary: CreditBondSupportBoundary {
            autonomy_gating_supported: true,
            ..CreditBondSupportBoundary::default()
        },
        latest_facility_id: latest_facility
            .as_ref()
            .map(|facility| facility.body.facility_id.clone()),
        terms,
        findings,
    })
}

pub(crate) fn issue_signed_credit_bond_detailed(
    args: CreditIssuanceArgs<'_>,
) -> Result<SignedCreditBond, TrustHttpError> {
    let CreditIssuanceArgs {
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        supersedes_artifact_id,
    } = args;
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key anchors the
    // reputation scoring trust set; reuse it to sign the bond artifact below.
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        &trusted_kernel_keys,
    )?;
    let latest_facility_expires_at = latest_active_granted_credit_facility(
        &receipt_store,
        report.filters.capability_id.as_deref(),
        report.filters.agent_subject.as_deref(),
        report.filters.tool_server.as_deref(),
        report.filters.tool_name.as_deref(),
    )?
    .map(|facility| facility.body.expires_at);
    let issued_at = unix_timestamp_now();
    let artifact = build_credit_bond_artifact(
        report,
        issued_at,
        supersedes_artifact_id.map(ToOwned::to_owned),
        latest_facility_expires_at,
    )?;
    let signed = SignedCreditBond::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_bond(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

fn build_credit_bond_artifact(
    report: CreditBondReport,
    issued_at: u64,
    supersedes_bond_id: Option<String>,
    latest_facility_expires_at: Option<u64>,
) -> Result<CreditBondArtifact, TrustHttpError> {
    let lifecycle_state = match report.disposition {
        CreditBondDisposition::Lock | CreditBondDisposition::Hold => {
            CreditBondLifecycleState::Active
        }
        CreditBondDisposition::Release => CreditBondLifecycleState::Released,
        CreditBondDisposition::Impair => CreditBondLifecycleState::Impaired,
    };
    let expires_at = latest_facility_expires_at
        .unwrap_or_else(|| issued_at.saturating_add(credit_bond_ttl_seconds(&report)));
    let bond_id_input = canonical_json_bytes(&(
        CREDIT_BOND_ARTIFACT_SCHEMA,
        issued_at,
        expires_at,
        lifecycle_state,
        &supersedes_bond_id,
        &report,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let bond_id = format!("cbd-{}", sha256_hex(&bond_id_input));

    Ok(CreditBondArtifact {
        schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
        bond_id,
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_bond_id,
        report,
    })
}

pub(crate) fn build_credit_bonded_execution_simulation_report_from_store(
    receipt_store: &SqliteReceiptStore,
    request: &CreditBondedExecutionSimulationRequest,
) -> Result<CreditBondedExecutionSimulationReport, TrustHttpError> {
    request
        .query
        .validate()
        .map_err(TrustHttpError::bad_request)?;

    let bond_row = receipt_store
        .resolve_credit_bond(&request.query.bond_id)
        .map_err(trust_http_error_from_receipt_store)?
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::NOT_FOUND,
                format!("credit bond `{}` not found", request.query.bond_id),
            )
        })?;
    let lifecycle_history = receipt_store
        .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
            event_id: None,
            bond_id: Some(request.query.bond_id.clone()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    let support_boundary = CreditBondedExecutionSupportBoundary {
        external_escrow_execution_supported: bond_row
            .bond
            .body
            .report
            .support_boundary
            .external_escrow_execution_supported,
        ..CreditBondedExecutionSupportBoundary::default()
    };
    let default_evaluation = evaluate_credit_bonded_execution(
        &bond_row,
        &lifecycle_history,
        &request.query,
        &CreditBondedExecutionControlPolicy::default(),
        &support_boundary,
    )?;
    let simulated_evaluation = evaluate_credit_bonded_execution(
        &bond_row,
        &lifecycle_history,
        &request.query,
        &request.policy,
        &support_boundary,
    )?;

    Ok(CreditBondedExecutionSimulationReport {
        schema: CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: request.query.clone(),
        policy: request.policy.clone(),
        support_boundary,
        bond: bond_row.bond,
        default_evaluation: default_evaluation.clone(),
        simulated_evaluation: simulated_evaluation.clone(),
        delta: build_credit_bonded_execution_simulation_delta(
            &default_evaluation,
            &simulated_evaluation,
        ),
    })
}

fn evaluate_credit_bonded_execution(
    bond_row: &chio_kernel::CreditBondRow,
    lifecycle_history: &CreditLossLifecycleListReport,
    query: &chio_kernel::CreditBondedExecutionSimulationQuery,
    policy: &CreditBondedExecutionControlPolicy,
    support_boundary: &CreditBondedExecutionSupportBoundary,
) -> Result<CreditBondedExecutionEvaluation, TrustHttpError> {
    let outstanding_delinquency_amount =
        credit_bonded_execution_outstanding_delinquency_amount(&bond_row.bond, lifecycle_history)?;
    let outstanding_delinquency_refs =
        credit_bonded_execution_loss_evidence(&bond_row.bond, lifecycle_history);
    let bond_refs = credit_bonded_execution_bond_evidence(&bond_row.bond);
    let mut findings = Vec::new();

    if policy.kill_switch {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::KillSwitchEnabled,
            description:
                "operator control policy kill-switch is enabled, so Chio denies bonded execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !bond_row
        .bond
        .body
        .report
        .support_boundary
        .autonomy_gating_supported
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::AutonomyGatingUnsupported,
            description:
                "the bond report does not claim autonomy gating support, so Chio fails closed"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if policy.deny_if_bond_not_active
        && bond_row.lifecycle_state != CreditBondLifecycleState::Active
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::BondNotActive,
            description: format!(
                "bond `{}` is {:?}, so Chio denies reserve-backed execution",
                bond_row.bond.body.bond_id, bond_row.lifecycle_state
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !matches!(
        bond_row.bond.body.report.disposition,
        CreditBondDisposition::Lock | CreditBondDisposition::Hold
    ) {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::BondDispositionUnsupported,
            description: format!(
                "bond disposition {:?} does not support reserve-backed execution",
                bond_row.bond.body.report.disposition
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if bond_row
        .bond
        .body
        .report
        .prerequisites
        .active_facility_required
        && !bond_row.bond.body.report.prerequisites.active_facility_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::ActiveFacilityUnavailable,
            description:
                "reserve-backed execution requires an active granted facility for this bond"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !bond_row
        .bond
        .body
        .report
        .prerequisites
        .runtime_assurance_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::RuntimePrerequisiteUnmet,
            description:
                "bond prerequisites do not meet the runtime-assurance floor required for reserve-backed execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if bond_row
        .bond
        .body
        .report
        .prerequisites
        .certification_required
        && !bond_row.bond.body.report.prerequisites.certification_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::CertificationPrerequisiteUnmet,
            description:
                "bond prerequisites require an active certification record before reserve-backed execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    let minimum_autonomy_runtime = query.autonomy_tier.minimum_runtime_assurance();
    if query.runtime_assurance_tier < minimum_autonomy_runtime {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::RuntimeAssuranceBelowAutonomyMinimum,
            description: format!(
                "requested runtime assurance {:?} is below the {:?} floor for autonomy tier {:?}",
                query.runtime_assurance_tier, minimum_autonomy_runtime, query.autonomy_tier
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if let Some(policy_minimum) = policy.minimum_runtime_assurance_tier {
        if query.runtime_assurance_tier < policy_minimum {
            findings.push(CreditBondedExecutionFinding {
                code: CreditBondedExecutionFindingCode::RuntimeAssuranceBelowPolicyMinimum,
                description: format!(
                    "operator control policy requires runtime assurance {:?}, but the request supplied {:?}",
                    policy_minimum, query.runtime_assurance_tier
                ),
                evidence_refs: bond_refs.clone(),
            });
        }
    }

    if let Some(maximum_autonomy_tier) = policy.maximum_autonomy_tier {
        if query.autonomy_tier > maximum_autonomy_tier {
            findings.push(CreditBondedExecutionFinding {
                code: CreditBondedExecutionFindingCode::AutonomyTierAbovePolicyMaximum,
                description: format!(
                    "operator control policy caps bonded execution at {:?}, but the request asked for {:?}",
                    maximum_autonomy_tier, query.autonomy_tier
                ),
                evidence_refs: bond_refs.clone(),
            });
        }
    }

    if policy.require_delegated_call_chain
        && query.autonomy_tier.requires_call_chain()
        && !query.call_chain_present
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::MissingDelegatedCallChain,
            description: "delegated or autonomous bonded execution requires call-chain context"
                .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if policy.require_locked_reserve
        && bond_row.bond.body.report.disposition != CreditBondDisposition::Lock
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::ReserveNotLocked,
            description:
                "operator control policy requires a locked reserve posture before execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if lifecycle_history.summary.matching_events > lifecycle_history.summary.returned_events {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::LossLifecycleHistoryTruncated,
            description:
                "bonded execution simulation requires complete loss lifecycle history, but the returned page was truncated"
                    .to_string(),
            evidence_refs: outstanding_delinquency_refs.clone(),
        });
    }

    if policy.deny_if_outstanding_delinquency
        && outstanding_delinquency_amount
            .as_ref()
            .is_some_and(|amount| amount.units > 0)
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::OutstandingDelinquency,
            description:
                "outstanding delinquent bonded loss remains unresolved, so Chio denies execution"
                    .to_string(),
            evidence_refs: outstanding_delinquency_refs,
        });
    }

    let decision = if findings.is_empty() {
        CreditBondedExecutionDecision::Allow
    } else {
        CreditBondedExecutionDecision::Deny
    };
    let sandbox_integration_ready = decision == CreditBondedExecutionDecision::Allow
        && support_boundary.sandbox_simulation_supported
        && bond_row
            .bond
            .body
            .report
            .support_boundary
            .autonomy_gating_supported;

    Ok(CreditBondedExecutionEvaluation {
        decision,
        autonomy_tier: query.autonomy_tier,
        runtime_assurance_tier: query.runtime_assurance_tier,
        bond_lifecycle_state: bond_row.lifecycle_state,
        bond_disposition: bond_row.bond.body.report.disposition,
        sandbox_integration_ready,
        outstanding_delinquency_amount,
        findings,
    })
}

fn credit_bonded_execution_outstanding_delinquency_amount(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Result<Option<MonetaryAmount>, TrustHttpError> {
    let currency = bond
        .body
        .report
        .terms
        .as_ref()
        .map(|terms| terms.credit_limit.currency.clone())
        .or_else(|| {
            lifecycle_history.events.iter().find_map(|row| {
                row.event
                    .body
                    .report
                    .summary
                    .event_amount
                    .as_ref()
                    .map(|amount| amount.currency.clone())
            })
        });
    let Some(currency) = currency else {
        return Ok(None);
    };
    let accounting = compute_credit_loss_lifecycle_accounting(&currency, lifecycle_history)
        .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?;
    Ok(amount_if_nonzero(
        accounting.outstanding_delinquent_units(),
        &currency,
    ))
}

fn credit_bonded_execution_bond_evidence(
    bond: &SignedCreditBond,
) -> Vec<CreditScorecardEvidenceReference> {
    vec![CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::CreditBond,
        reference_id: bond.body.bond_id.clone(),
        observed_at: Some(bond.body.issued_at),
        locator: Some(format!("credit-bond:{}", bond.body.bond_id)),
    }]
}

fn credit_bonded_execution_loss_evidence(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut evidence_refs = credit_bonded_execution_bond_evidence(bond);
    let mut seen = BTreeSet::from([format!("credit-bond:{}", bond.body.bond_id)]);
    for row in &lifecycle_history.events {
        let key = format!("credit-loss-lifecycle:{}", row.event.body.event_id);
        if seen.insert(key.clone()) {
            evidence_refs.push(CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::CreditLossLifecycle,
                reference_id: row.event.body.event_id.clone(),
                observed_at: Some(row.event.body.issued_at),
                locator: Some(key),
            });
        }
    }
    evidence_refs
}

fn build_credit_bonded_execution_simulation_delta(
    default_evaluation: &CreditBondedExecutionEvaluation,
    simulated_evaluation: &CreditBondedExecutionEvaluation,
) -> CreditBondedExecutionSimulationDelta {
    let default_reasons = credit_bonded_execution_reason_keys(default_evaluation);
    let simulated_reasons = credit_bonded_execution_reason_keys(simulated_evaluation);

    CreditBondedExecutionSimulationDelta {
        decision_changed: default_evaluation.decision != simulated_evaluation.decision,
        sandbox_integration_changed: default_evaluation.sandbox_integration_ready
            != simulated_evaluation.sandbox_integration_ready,
        added_reasons: simulated_reasons
            .iter()
            .filter(|reason| !default_reasons.contains(reason))
            .cloned()
            .collect(),
        removed_reasons: default_reasons
            .iter()
            .filter(|reason| !simulated_reasons.contains(reason))
            .cloned()
            .collect(),
    }
}

fn credit_bonded_execution_reason_keys(
    evaluation: &CreditBondedExecutionEvaluation,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in evaluation
        .findings
        .iter()
        .map(|finding| credit_bonded_execution_reason_key(finding.code).to_string())
    {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons
}

fn credit_bonded_execution_reason_key(code: CreditBondedExecutionFindingCode) -> &'static str {
    match code {
        CreditBondedExecutionFindingCode::KillSwitchEnabled => "kill_switch_enabled",
        CreditBondedExecutionFindingCode::AutonomyGatingUnsupported => {
            "autonomy_gating_unsupported"
        }
        CreditBondedExecutionFindingCode::BondNotActive => "bond_not_active",
        CreditBondedExecutionFindingCode::BondDispositionUnsupported => {
            "bond_disposition_unsupported"
        }
        CreditBondedExecutionFindingCode::ActiveFacilityUnavailable => {
            "active_facility_unavailable"
        }
        CreditBondedExecutionFindingCode::RuntimePrerequisiteUnmet => "runtime_prerequisite_unmet",
        CreditBondedExecutionFindingCode::CertificationPrerequisiteUnmet => {
            "certification_prerequisite_unmet"
        }
        CreditBondedExecutionFindingCode::RuntimeAssuranceBelowAutonomyMinimum => {
            "runtime_assurance_below_autonomy_minimum"
        }
        CreditBondedExecutionFindingCode::RuntimeAssuranceBelowPolicyMinimum => {
            "runtime_assurance_below_policy_minimum"
        }
        CreditBondedExecutionFindingCode::MissingDelegatedCallChain => {
            "missing_delegated_call_chain"
        }
        CreditBondedExecutionFindingCode::AutonomyTierAbovePolicyMaximum => {
            "autonomy_tier_above_policy_maximum"
        }
        CreditBondedExecutionFindingCode::ReserveNotLocked => "reserve_not_locked",
        CreditBondedExecutionFindingCode::OutstandingDelinquency => "outstanding_delinquency",
        CreditBondedExecutionFindingCode::LossLifecycleHistoryTruncated => {
            "loss_lifecycle_history_truncated"
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CreditLossLifecycleAccountingState {
    pub(crate) currency: String,
    pub(crate) delinquent_units: u64,
    pub(crate) recovered_units: u64,
    pub(crate) reserve_released_units: u64,
    pub(crate) reserve_slashed_units: u64,
    pub(crate) written_off_units: u64,
}

impl CreditLossLifecycleAccountingState {
    fn outstanding_delinquent_units(&self) -> u64 {
        self.delinquent_units.saturating_sub(
            self.recovered_units
                .saturating_add(self.written_off_units)
                .saturating_add(self.reserve_slashed_units),
        )
    }

    fn remaining_reserve_units(&self, total_reserve_units: u64) -> u64 {
        total_reserve_units.saturating_sub(
            self.reserve_released_units
                .saturating_add(self.reserve_slashed_units),
        )
    }
}

fn credit_loss_lifecycle_control_supported(kind: CreditLossLifecycleEventKind) -> bool {
    matches!(
        kind,
        CreditLossLifecycleEventKind::ReserveRelease | CreditLossLifecycleEventKind::ReserveSlash
    )
}

fn credit_loss_lifecycle_reserve_source_query(bond: &SignedCreditBond) -> CapitalBookQuery {
    CapitalBookQuery {
        capability_id: bond.body.report.filters.capability_id.clone(),
        agent_subject: bond.body.report.filters.agent_subject.clone(),
        tool_server: bond.body.report.filters.tool_server.clone(),
        tool_name: bond.body.report.filters.tool_name.clone(),
        since: bond.body.report.filters.since,
        until: bond.body.report.filters.until,
        receipt_limit: Some(chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT),
        facility_limit: Some(MAX_CREDIT_FACILITY_LIST_LIMIT),
        bond_limit: Some(MAX_CREDIT_BOND_LIST_LIMIT),
        loss_event_limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
    }
}

fn resolve_credit_loss_lifecycle_reserve_source(
    receipt_store: &SqliteReceiptStore,
    bond: &SignedCreditBond,
) -> Result<CapitalBookSource, TrustHttpError> {
    let capital_book = build_capital_book_report_from_store(
        receipt_store,
        &credit_loss_lifecycle_reserve_source_query(bond),
    )?;
    capital_book
        .sources
        .into_iter()
        .find(|source| {
            source.kind == CapitalBookSourceKind::ReserveBook
                && source.bond_id.as_deref() == Some(bond.body.bond_id.as_str())
        })
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "credit reserve control requires one reserve-book source for bond `{}`",
                    bond.body.bond_id
                ),
            )
        })
}

pub(crate) fn build_credit_loss_lifecycle_report_from_store(
    receipt_store: &SqliteReceiptStore,
    query: &CreditLossLifecycleQuery,
) -> Result<CreditLossLifecycleReport, TrustHttpError> {
    query.validate().map_err(TrustHttpError::bad_request)?;

    let bond_row = receipt_store
        .resolve_credit_bond(&query.bond_id)
        .map_err(trust_http_error_from_receipt_store)?
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::NOT_FOUND,
                format!("credit bond `{}` not found", query.bond_id),
            )
        })?;
    let bond = &bond_row.bond;
    let terms = bond.body.report.terms.as_ref().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "credit bond `{}` is missing terms required for loss lifecycle accounting",
                query.bond_id
            ),
        )
    })?;
    let currency = terms.collateral_amount.currency.clone();

    let lifecycle_history = receipt_store
        .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
            event_id: None,
            bond_id: Some(query.bond_id.clone()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    let accounting = compute_credit_loss_lifecycle_accounting(&currency, &lifecycle_history)
        .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?;
    let loss_query = BehavioralFeedQuery {
        capability_id: bond.body.report.filters.capability_id.clone(),
        agent_subject: bond.body.report.filters.agent_subject.clone(),
        tool_server: bond.body.report.filters.tool_server.clone(),
        tool_name: bond.body.report.filters.tool_name.clone(),
        since: bond.body.report.filters.since,
        until: bond.body.report.filters.until,
        receipt_limit: Some(chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
    };
    let (_, recent_loss_receipts) = receipt_store
        .query_recent_credit_loss_receipts(
            &loss_query,
            chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT,
        )
        .map_err(trust_http_error_from_receipt_store)?;
    let (current_outstanding_loss_units, current_loss_evidence_refs) =
        build_credit_loss_lifecycle_outstanding_loss_state(&recent_loss_receipts, &currency)?;

    let exposure = build_exposure_ledger_report(receipt_store, &bond.body.report.filters)?;
    if exposure.summary.mixed_currency_book {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit loss lifecycle requires one coherent currency book because Chio does not auto-net lifecycle accounting across currencies"
                .to_string(),
        ));
    }
    let position = exposure
        .positions
        .iter()
        .find(|position| position.currency == currency)
        .cloned()
        .unwrap_or_else(|| empty_exposure_position(&currency));
    let outstanding_delinquent_units = accounting.outstanding_delinquent_units();
    let releaseable_reserve_units =
        accounting.remaining_reserve_units(terms.reserve_requirement_amount.units);
    let current_outstanding_exposure_units =
        credit_bond_outstanding_units(&position).max(current_outstanding_loss_units);
    let recordable_delinquency_units =
        current_outstanding_loss_units.saturating_sub(accounting.delinquent_units);
    let unresolved_live_exposure_units =
        current_outstanding_exposure_units.saturating_sub(accounting.delinquent_units);

    let (event_amount, projected_bond_lifecycle_state, findings) = match query.event_kind {
        CreditLossLifecycleEventKind::Delinquency => {
            if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit loss delinquency requires active bond `{}`",
                        query.bond_id
                    ),
                ));
            }
            if recordable_delinquency_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit loss delinquency requires new outstanding failed or delinquent bonded exposure"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > recordable_delinquency_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit loss delinquency amount {} exceeds recordable outstanding loss {}",
                                amount.units, recordable_delinquency_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: recordable_delinquency_units,
                    currency: currency.clone(),
                },
            };

            (
                Some(event_amount),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::DelinquencyRecorded,
                    description:
                        "new outstanding bonded loss has been recorded as delinquent against the bond"
                            .to_string(),
                    evidence_refs: current_loss_evidence_refs,
                }],
            )
        }
        CreditLossLifecycleEventKind::Recovery => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit recovery requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit recovery requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit recovery amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                bond_row.lifecycle_state,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::RecoveryRecorded,
                    description:
                        "recovery has been recorded against previously delinquent bonded exposure"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::ReserveRelease => {
            if outstanding_delinquent_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires outstanding delinquency to be cleared first"
                        .to_string(),
                ));
            }
            if unresolved_live_exposure_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires no unbooked outstanding exposure to remain"
                        .to_string(),
                ));
            }
            if releaseable_reserve_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release is unavailable because the reserve is already fully released"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > releaseable_reserve_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit reserve release amount {} exceeds releasable reserve {}",
                                amount.units, releaseable_reserve_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: releaseable_reserve_units,
                    currency: currency.clone(),
                },
            };
            (
                Some(event_amount),
                CreditBondLifecycleState::Released,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::ReserveReleased,
                    description:
                        "reserve backing has been explicitly released after delinquency was cleared"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Recovery,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::ReserveSlash => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve slash requires outstanding delinquent amount".to_string(),
                ));
            }
            if releaseable_reserve_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve slash is unavailable because the reserve is fully exhausted or released"
                        .to_string(),
                ));
            }
            let max_slash_units = releaseable_reserve_units.min(outstanding_delinquent_units);
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > max_slash_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit reserve slash amount {} exceeds slashable reserve {}",
                                amount.units, max_slash_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: max_slash_units,
                    currency: currency.clone(),
                },
            };
            (
                Some(event_amount),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::ReserveSlashed,
                    description:
                        "reserve backing has been explicitly slashed against outstanding delinquent exposure"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::WriteOff => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit write-off requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit write-off requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit write-off amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::WriteOffRecorded,
                    description: "outstanding delinquent exposure has been explicitly written off"
                        .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
    };

    Ok(CreditLossLifecycleReport {
        schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: query.clone(),
        summary: chio_kernel::CreditLossLifecycleSummary {
            bond_id: bond.body.bond_id.clone(),
            facility_id: bond.body.report.latest_facility_id.clone(),
            capability_id: bond.body.report.filters.capability_id.clone(),
            agent_subject: bond.body.report.filters.agent_subject.clone(),
            tool_server: bond.body.report.filters.tool_server.clone(),
            tool_name: bond.body.report.filters.tool_name.clone(),
            current_bond_lifecycle_state: bond_row.lifecycle_state,
            projected_bond_lifecycle_state,
            current_delinquent_amount: amount_if_nonzero(accounting.delinquent_units, &currency),
            current_recovered_amount: amount_if_nonzero(accounting.recovered_units, &currency),
            current_written_off_amount: amount_if_nonzero(accounting.written_off_units, &currency),
            current_released_reserve_amount: amount_if_nonzero(
                accounting.reserve_released_units,
                &currency,
            ),
            current_slashed_reserve_amount: amount_if_nonzero(
                accounting.reserve_slashed_units,
                &currency,
            ),
            outstanding_delinquent_amount: amount_if_nonzero(
                outstanding_delinquent_units,
                &currency,
            ),
            releaseable_reserve_amount: amount_if_nonzero(releaseable_reserve_units, &currency),
            reserve_control_source_id: None,
            execution_state: None,
            appeal_state: None,
            appeal_window_ends_at: None,
            event_amount,
        },
        support_boundary: CreditLossLifecycleSupportBoundary::default(),
        findings,
    })
}

pub(crate) fn issue_signed_credit_loss_lifecycle_detailed(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CreditLossLifecycleIssueRequest,
) -> Result<SignedCreditLossLifecycle, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let mut report = build_credit_loss_lifecycle_report_from_store(&receipt_store, &request.query)?;
    let issued_at = unix_timestamp_now();
    let (
        reserve_control_source_id,
        authority_chain,
        execution_window,
        rail,
        observed_execution,
        reconciled_state,
        execution_state,
        appeal_state,
        appeal_window_ends_at,
        description,
    ) = if credit_loss_lifecycle_control_supported(request.query.event_kind) {
        let execution_window = request.execution_window.clone().ok_or_else(|| {
            TrustHttpError::bad_request("credit reserve control issuance requires executionWindow")
        })?;
        let rail = request.rail.clone().ok_or_else(|| {
            TrustHttpError::bad_request("credit reserve control issuance requires rail")
        })?;
        validate_capital_execution_envelope(
            &request.authority_chain,
            &execution_window,
            &rail,
            issued_at,
        )?;
        let bond_row = receipt_store
            .resolve_credit_bond(&request.query.bond_id)
            .map_err(trust_http_error_from_receipt_store)?
            .ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::NOT_FOUND,
                    format!("credit bond `{}` not found", request.query.bond_id),
                )
            })?;
        let reserve_source =
            resolve_credit_loss_lifecycle_reserve_source(&receipt_store, &bond_row.bond)?;
        let owner_role = capital_execution_role_from_book_role(reserve_source.owner_role);
        ensure_capital_execution_owner_authority(&request.authority_chain, owner_role)?;
        let event_amount = report.summary.event_amount.as_ref().ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                "credit reserve control requires a computed event amount".to_string(),
            )
        })?;
        let reconciled_state = if let Some(observed_execution) = &request.observed_execution {
            if &observed_execution.amount != event_amount {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve control observedExecution amount does not match event amount",
                ));
            }
            if observed_execution.observed_at < execution_window.not_before
                || observed_execution.observed_at > execution_window.not_after
            {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve control observedExecution timestamp falls outside the execution window",
                ));
            }
            Some(CapitalExecutionReconciledState::Matched)
        } else {
            Some(CapitalExecutionReconciledState::NotObserved)
        };
        let execution_state = Some(if request.observed_execution.is_some() {
            CreditReserveControlExecutionState::Executed
        } else {
            CreditReserveControlExecutionState::PendingExecution
        });
        let appeal_state = Some(match request.appeal_window_ends_at {
            Some(ends_at) => {
                if ends_at < issued_at {
                    return Err(TrustHttpError::bad_request(
                        "credit reserve control appealWindowEndsAt must be >= issuance time",
                    ));
                }
                if ends_at > issued_at {
                    CreditReserveControlAppealState::Open
                } else {
                    CreditReserveControlAppealState::Closed
                }
            }
            None => CreditReserveControlAppealState::Unsupported,
        });
        report.summary.reserve_control_source_id = Some(reserve_source.source_id.clone());
        report.summary.execution_state = execution_state;
        report.summary.appeal_state = appeal_state;
        report.summary.appeal_window_ends_at = request.appeal_window_ends_at;
        (
            Some(reserve_source.source_id),
            request.authority_chain.clone(),
            Some(execution_window),
            Some(rail),
            request.observed_execution.clone(),
            reconciled_state,
            execution_state,
            appeal_state,
            request.appeal_window_ends_at,
            Some(request.description.clone().unwrap_or_else(|| {
                format!(
                    "{:?} reserve control for bond `{}`",
                    request.query.event_kind, request.query.bond_id
                )
            })),
        )
    } else {
        if !request.authority_chain.is_empty()
            || request.execution_window.is_some()
            || request.rail.is_some()
            || request.observed_execution.is_some()
            || request.appeal_window_ends_at.is_some()
            || request.description.is_some()
        {
            return Err(TrustHttpError::bad_request(
                "execution metadata is only valid for reserve release and reserve slash lifecycle issuance",
            ));
        }
        (
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };
    let event_id_input = canonical_json_bytes(&(
        CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
        issued_at,
        &report,
        &reserve_control_source_id,
        &authority_chain,
        &execution_window,
        &rail,
        &observed_execution,
        &appeal_window_ends_at,
        &description,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let event = CreditLossLifecycleArtifact {
        schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: format!("cll-{}", sha256_hex(&event_id_input)),
        issued_at,
        bond_id: report.query.bond_id.clone(),
        event_kind: report.query.event_kind,
        projected_bond_lifecycle_state: report.summary.projected_bond_lifecycle_state,
        reserve_control_source_id,
        authority_chain,
        execution_window,
        rail,
        observed_execution,
        reconciled_state,
        execution_state,
        appeal_state,
        appeal_window_ends_at,
        description,
        report,
    };
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedCreditLossLifecycle::sign(event, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_loss_lifecycle(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

pub(crate) fn issue_signed_credit_facility_detailed(
    args: CreditIssuanceArgs<'_>,
) -> Result<SignedCreditFacility, TrustHttpError> {
    let CreditIssuanceArgs {
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        supersedes_artifact_id,
    } = args;
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key anchors the
    // reputation scoring trust set; reuse it to sign the facility artifact.
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        &trusted_kernel_keys,
    )?;
    let issued_at = unix_timestamp_now();
    let artifact = build_credit_facility_artifact(
        report,
        issued_at,
        supersedes_artifact_id.map(ToOwned::to_owned),
    )?;
    let signed = SignedCreditFacility::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_facility(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

fn build_credit_facility_artifact(
    report: CreditFacilityReport,
    issued_at: u64,
    supersedes_facility_id: Option<String>,
) -> Result<CreditFacilityArtifact, TrustHttpError> {
    let lifecycle_state = if report.disposition == CreditFacilityDisposition::Deny {
        CreditFacilityLifecycleState::Denied
    } else {
        CreditFacilityLifecycleState::Active
    };
    let expires_at = issued_at.saturating_add(credit_facility_ttl_seconds(&report));
    let facility_id_input = canonical_json_bytes(&(
        CREDIT_FACILITY_ARTIFACT_SCHEMA,
        issued_at,
        expires_at,
        lifecycle_state,
        &supersedes_facility_id,
        &report,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let facility_id = format!("cfd-{}", sha256_hex(&facility_id_input));

    Ok(CreditFacilityArtifact {
        schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id,
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_facility_id,
        report,
    })
}

fn underwriting_input_query_from_exposure_query(
    query: &ExposureLedgerQuery,
) -> UnderwritingPolicyInputQuery {
    UnderwritingPolicyInputQuery {
        capability_id: query.capability_id.clone(),
        agent_subject: query.agent_subject.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        since: query.since,
        until: query.until,
        receipt_limit: query.receipt_limit,
    }
}

fn credit_facility_minimum_runtime_assurance_tier(
    band: CreditScorecardBand,
) -> RuntimeAssuranceTier {
    match band {
        CreditScorecardBand::Prime
        | CreditScorecardBand::Standard
        | CreditScorecardBand::Guarded => RuntimeAssuranceTier::Attested,
        CreditScorecardBand::Probationary | CreditScorecardBand::Restricted => {
            RuntimeAssuranceTier::Verified
        }
    }
}

pub(crate) fn build_credit_facility_terms(
    scorecard: &CreditScorecardReport,
) -> Option<CreditFacilityTerms> {
    let position = match scorecard.positions.as_slice() {
        [position] => position,
        _ => return None,
    };
    let base_units = position.governed_max_exposure_units.max(
        position
            .settled_units
            .saturating_add(position.pending_units),
    );
    if base_units == 0 {
        return None;
    }

    let band_factor = match scorecard.summary.band {
        CreditScorecardBand::Prime => 1.0,
        CreditScorecardBand::Standard => 0.85,
        CreditScorecardBand::Guarded => 0.65,
        CreditScorecardBand::Probationary => 0.40,
        CreditScorecardBand::Restricted => 0.0,
    };
    let confidence_factor = match scorecard.summary.confidence {
        CreditScorecardConfidence::High => 1.0,
        CreditScorecardConfidence::Medium => 0.9,
        CreditScorecardConfidence::Low => 0.75,
    };
    let credit_limit_units = ((base_units as f64) * band_factor * confidence_factor).floor() as u64;
    if credit_limit_units == 0 {
        return None;
    }

    let (utilization_ceiling_bps, reserve_ratio_bps, concentration_cap_bps, ttl_seconds) =
        match scorecard.summary.band {
            CreditScorecardBand::Prime => (9_000, 1_000, 3_500, 30 * 86_400),
            CreditScorecardBand::Standard => (8_000, 1_500, 3_000, 14 * 86_400),
            CreditScorecardBand::Guarded => (6_500, 2_500, 2_000, 7 * 86_400),
            CreditScorecardBand::Probationary | CreditScorecardBand::Restricted => return None,
        };

    Some(CreditFacilityTerms {
        credit_limit: MonetaryAmount {
            units: credit_limit_units,
            currency: position.currency.clone(),
        },
        utilization_ceiling_bps,
        reserve_ratio_bps,
        concentration_cap_bps,
        ttl_seconds,
        capital_source: CreditFacilityCapitalSource::OperatorInternal,
    })
}

fn build_credit_facility_findings(
    scorecard: &CreditScorecardReport,
    underwriting_input: &UnderwritingPolicyInput,
    prerequisites: &CreditFacilityPrerequisites,
    disposition: CreditFacilityDisposition,
) -> Vec<CreditFacilityFinding> {
    let mut findings = Vec::new();
    if scorecard.summary.band == CreditScorecardBand::Restricted {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::ScoreRestricted,
            description: "scorecard band is restricted, so Chio denies facility allocation"
                .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.probationary {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::ProbationaryScore,
            description:
                "scorecard remains probationary, so Chio requires provider review before allocation"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.confidence == CreditScorecardConfidence::Low {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::LowConfidence,
            description:
                "scorecard confidence is low, so Chio will not auto-allocate external capital"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.mixed_currency_book {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::MixedCurrencyBook,
            description:
                "matching governed history spans multiple currencies, which Chio does not auto-net"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::MixedCurrencyBook,
            ),
        });
    }
    if underwriting_input
        .runtime_assurance
        .as_ref()
        .is_some_and(|runtime| runtime.observed_verifier_families.len() > 1)
    {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::MixedRuntimeAssuranceProvenance,
            description:
                "runtime assurance history spans multiple verifier families, so Chio requires manual provider review before auto-allocation"
                    .to_string(),
            evidence_refs: credit_facility_receipt_refs_from_underwriting(underwriting_input),
        });
    }
    if !prerequisites.runtime_assurance_met {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::MissingRuntimeAssurance,
            description: format!(
                "runtime assurance evidence did not satisfy the {:?} minimum required for this score band",
                prerequisites.minimum_runtime_assurance_tier
            ),
            evidence_refs: credit_facility_receipt_refs_from_underwriting(underwriting_input),
        });
    }
    if prerequisites.certification_required && !prerequisites.certification_met {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::CertificationNotActive,
            description:
                "tool-server-scoped facility allocation requires an active certification record"
                    .to_string(),
            evidence_refs: Vec::new(),
        });
    }
    if credit_facility_has_reason(
        scorecard,
        CreditScorecardReasonCode::FailedSettlementBacklog,
    ) {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::FailedSettlementBacklog,
            description:
                "failed settlement exposure remains unresolved in the requested evidence window"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::FailedSettlementBacklog,
            ),
        });
    }
    if credit_facility_has_reason(
        scorecard,
        CreditScorecardReasonCode::PendingSettlementBacklog,
    ) {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::PendingSettlementBacklog,
            description:
                "pending settlement exposure remains open in the requested evidence window"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::PendingSettlementBacklog,
            ),
        });
    }
    if disposition == CreditFacilityDisposition::Grant {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::FacilityGranted,
            description:
                "score, runtime assurance, and bounded exposure satisfied Chio auto-allocation policy"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    findings
}

fn credit_facility_ttl_seconds(report: &CreditFacilityReport) -> u64 {
    report
        .terms
        .as_ref()
        .map(|terms| terms.ttl_seconds)
        .unwrap_or_else(|| match report.disposition {
            CreditFacilityDisposition::Grant => 7 * 86_400,
            CreditFacilityDisposition::ManualReview => 7 * 86_400,
            CreditFacilityDisposition::Deny => 86_400,
        })
}

pub(crate) fn credit_facility_has_reason(
    scorecard: &CreditScorecardReport,
    reason: CreditScorecardReasonCode,
) -> bool {
    scorecard
        .anomalies
        .iter()
        .any(|anomaly| anomaly.code == reason)
}

pub(crate) fn credit_facility_evidence_for_reason(
    scorecard: &CreditScorecardReport,
    reason: CreditScorecardReasonCode,
) -> Vec<CreditScorecardEvidenceReference> {
    scorecard
        .anomalies
        .iter()
        .find(|anomaly| anomaly.code == reason)
        .map(|anomaly| anomaly.evidence_refs.clone())
        .unwrap_or_default()
}

fn credit_facility_reputation_evidence(
    scorecard: &CreditScorecardReport,
) -> Vec<CreditScorecardEvidenceReference> {
    scorecard
        .dimensions
        .iter()
        .find(|dimension| dimension.kind == CreditScorecardDimensionKind::ReputationSupport)
        .map(|dimension| dimension.evidence_refs.clone())
        .unwrap_or_default()
}

pub(crate) fn credit_facility_receipt_refs_from_underwriting(
    underwriting_input: &UnderwritingPolicyInput,
) -> Vec<CreditScorecardEvidenceReference> {
    underwriting_input
        .receipts
        .receipt_refs
        .iter()
        .filter_map(|reference| match reference.kind {
            UnderwritingEvidenceKind::Receipt => Some(CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::Receipt,
                reference_id: reference.reference_id.clone(),
                observed_at: reference.observed_at,
                locator: reference.locator.clone(),
            }),
            UnderwritingEvidenceKind::SettlementReconciliation => {
                Some(CreditScorecardEvidenceReference {
                    kind: CreditScorecardEvidenceKind::SettlementReconciliation,
                    reference_id: reference.reference_id.clone(),
                    observed_at: reference.observed_at,
                    locator: reference.locator.clone(),
                })
            }
            UnderwritingEvidenceKind::ReputationInspection
            | UnderwritingEvidenceKind::CertificationArtifact
            | UnderwritingEvidenceKind::RuntimeAssuranceEvidence
            | UnderwritingEvidenceKind::SharedEvidenceReference
            | UnderwritingEvidenceKind::MeteredBillingReconciliation => None,
        })
        .collect()
}

pub(crate) fn credit_backtest_utilization_bps(
    positions: &[ExposureLedgerCurrencyPosition],
    terms: Option<&CreditFacilityTerms>,
) -> Option<u32> {
    let [position] = positions else {
        return None;
    };
    if terms.is_some_and(|terms| position.currency != terms.credit_limit.currency) {
        return None;
    }
    let denominator = terms.map_or_else(
        || {
            position.governed_max_exposure_units.max(
                position
                    .settled_units
                    .saturating_add(position.pending_units),
            )
        },
        |terms| terms.credit_limit.units,
    );
    if denominator == 0 {
        return None;
    }
    let utilized_units = position
        .reserved_units
        .saturating_add(position.pending_units)
        .saturating_add(position.failed_units)
        .saturating_add(position.provisional_loss_units)
        .saturating_sub(position.recovered_units);
    Some(((utilized_units as u128) * 10_000 / (denominator as u128)).min(u32::MAX as u128) as u32)
}
