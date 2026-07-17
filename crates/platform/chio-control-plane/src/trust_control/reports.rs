use super::*;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_kernel::operator_report::ComptrollerSurfaceReport;

pub type SignedComptrollerSurfaceReport = SignedExportEnvelope<ComptrollerSurfaceReport>;

#[derive(Default)]
pub(crate) struct ResolvedBudgetGrant {
    pub(crate) tool_server: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) max_invocations: Option<u32>,
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) currency: Option<String>,
    pub(crate) scope_resolved: bool,
    pub(crate) scope_resolution_error: Option<String>,
}

pub(crate) fn build_operator_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<OperatorReport, Response> {
    let activity = receipt_store
        .query_receipt_analytics(&query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let cost_attribution = receipt_store
        .query_cost_attribution_report(&query.to_cost_attribution_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let budget_utilization = build_budget_utilization_report(receipt_store, budget_store, query)?;
    let compliance = receipt_store
        .query_compliance_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let settlement_reconciliation = receipt_store
        .query_settlement_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let metered_billing_reconciliation = receipt_store
        .query_metered_billing_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let authorization_context = receipt_store
        .query_authorization_context_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;

    Ok(OperatorReport {
        generated_at: unix_timestamp_now(),
        filters: query.clone(),
        activity,
        cost_attribution,
        budget_utilization,
        compliance,
        settlement_reconciliation,
        metered_billing_reconciliation,
        authorization_context,
        shared_evidence,
    })
}

/// Compose the unified comptroller surface projection from the operator + exposure read models.
/// Fail-closed: a missing read context, exposure-builder errors, and consistency-validation
/// failures all map to 5xx. The exposure half uses the same principal context as the operator
/// half so both halves share the same read boundary.
pub(crate) fn build_comptroller_surface_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<ComptrollerSurfaceReport, Response> {
    let read_context = query.read_context.clone().ok_or_else(|| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "comptroller surface report requires a resolved read context",
        )
    })?;
    let operator = build_operator_report(receipt_store, budget_store, query)?;
    let exposure = build_exposure_ledger_report_with_context(
        receipt_store,
        &query.to_exposure_ledger_query(),
        read_context,
    )
    .map_err(|error| error.into_response())?;
    let report = ComptrollerSurfaceReport::from_parts(&operator, &exposure);
    report.validate_consistency().map_err(|message| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("comptroller surface consistency check failed: {message}"),
        )
            .into_response()
    })?;
    Ok(report)
}

pub fn build_signed_behavioral_feed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
) -> Result<SignedBehavioralFeed, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key anchors the
    // reputation scoring trust set (chio-reputation::receipt_integrity_valid
    // fails closed on an empty set).
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_behavioral_feed_report(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        query,
        &trusted_kernel_keys,
    )
    .map_err(|response| CliError::cli_other_error(response_status_text(&response)))?;
    SignedBehavioralFeed::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_runtime_attestation_appraisal_report(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
    let report = build_runtime_attestation_appraisal_report(runtime_assurance_policy, evidence)
        .map_err(|response| CliError::cli_other_error(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedRuntimeAttestationAppraisalReport::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_runtime_attestation_appraisal_result(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    request: &RuntimeAttestationAppraisalResultExportRequest,
) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
    let result = build_runtime_attestation_appraisal_result(runtime_assurance_policy, request)
        .map_err(|response| CliError::cli_other_error(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedRuntimeAttestationAppraisalResult::sign(result, &keypair).map_err(Into::into)
}

fn build_runtime_attestation_appraisal_report(
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisalReport, Response> {
    let appraisal = derive_runtime_attestation_appraisal(evidence)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let trust_policy =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy.as_ref());
    let policy_outcome = match trust_policy {
        Some(policy) => {
            match evidence.resolve_effective_runtime_assurance(Some(policy), generated_at) {
                Ok(resolved) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: true,
                    effective_tier: resolved.effective_tier,
                    reason: None,
                },
                Err(error) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: false,
                    effective_tier: RuntimeAssuranceTier::None,
                    reason: Some(error.to_string()),
                },
            }
        }
        None => RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: true,
            effective_tier: evidence.tier,
            reason: None,
        },
    };

    Ok(RuntimeAttestationAppraisalReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
        generated_at,
        appraisal,
        policy_outcome,
    })
}

fn build_runtime_attestation_appraisal_result(
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    request: &RuntimeAttestationAppraisalResultExportRequest,
) -> Result<RuntimeAttestationAppraisalResult, Response> {
    let report = build_runtime_attestation_appraisal_report(
        runtime_assurance_policy,
        &request.runtime_attestation,
    )?;
    RuntimeAttestationAppraisalResult::from_report(&request.issuer, &report)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))
}

pub fn build_runtime_attestation_appraisal_import_report(
    request: &RuntimeAttestationAppraisalImportRequest,
    now: u64,
) -> RuntimeAttestationAppraisalImportReport {
    evaluate_imported_runtime_attestation_appraisal(request, now)
}

fn build_behavioral_feed_report(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
    trusted_kernel_keys: &[String],
) -> Result<BehavioralFeedReport, Response> {
    let normalized_query = query.normalized();
    let operator_query = normalized_query.to_operator_report_query();
    let activity = receipt_store
        .query_receipt_analytics(&operator_query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let compliance = receipt_store
        .query_compliance_report(&operator_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&operator_query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let (settlements, governed_actions, metered_billing, selection) = receipt_store
        .query_behavioral_feed_receipts(&normalized_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let reputation = match normalized_query.agent_subject.as_deref() {
        Some(subject_key) => Some(
            reputation::build_behavioral_feed_reputation_summary(
                receipt_db_path,
                budget_db_path,
                subject_key,
                normalized_query.since,
                normalized_query.until,
                generated_at,
                trusted_kernel_keys,
            )
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?,
        ),
        None => None,
    };

    Ok(BehavioralFeedReport {
        schema: BEHAVIORAL_FEED_SCHEMA.to_string(),
        generated_at,
        filters: normalized_query,
        privacy: BehavioralFeedPrivacyBoundary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: selection.receipts.len() as u64,
            direct_evidence_export_supported: compliance.direct_evidence_export_supported,
            child_receipt_scope: compliance.child_receipt_scope,
            proofs_complete: compliance.proofs_complete,
            export_query: compliance.export_query,
            export_scope_note: compliance.export_scope_note,
        },
        decisions: BehavioralFeedDecisionSummary {
            allow_count: activity.summary.allow_count,
            deny_count: activity.summary.deny_count,
            cancelled_count: activity.summary.cancelled_count,
            incomplete_count: activity.summary.incomplete_count,
        },
        settlements,
        governed_actions,
        metered_billing,
        reputation,
        shared_evidence: shared_evidence.summary,
        receipts: selection.receipts,
    })
}

/// Sign an already-built comptroller surface projection with the behavioral-feed signing authority.
pub fn build_signed_comptroller_surface_report(
    report: ComptrollerSurfaceReport,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<SignedComptrollerSurfaceReport, CliError> {
    report
        .validate_consistency()
        .map_err(CliError::cli_other_error)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedComptrollerSurfaceReport::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_exposure_ledger_report(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedExposureLedgerReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_exposure_ledger_report(&receipt_store, query).map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedExposureLedgerReport::sign(report, &keypair).map_err(Into::into)
}

pub(crate) fn build_economic_completion_flow_report(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
    read_context: chio_kernel::ReceiptReadContext,
) -> Result<EconomicCompletionFlowReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    receipt_store
        .query_economic_completion_flow_report(&normalized_query, read_context)
        .map_err(trust_http_error_from_receipt_store)
}

pub(crate) fn build_exposure_ledger_report(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
) -> Result<ExposureLedgerReport, TrustHttpError> {
    build_exposure_ledger_report_with_context(
        receipt_store,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
    )
}

pub(crate) fn build_exposure_ledger_report_with_context(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
    read_context: chio_kernel::ReceiptReadContext,
) -> Result<ExposureLedgerReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
        read_context: Some(read_context),
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let decision_report = receipt_store
        .query_underwriting_decisions(&UnderwritingDecisionQuery {
            decision_id: None,
            capability_id: normalized_query.capability_id.clone(),
            agent_subject: normalized_query.agent_subject.clone(),
            tool_server: normalized_query.tool_server.clone(),
            tool_name: normalized_query.tool_name.clone(),
            outcome: None,
            lifecycle_state: None,
            appeal_status: None,
            limit: normalized_query.decision_limit,
        })
        .map_err(trust_http_error_from_receipt_store)?;

    let mut positions_by_currency = BTreeMap::<String, ExposureLedgerCurrencyPosition>::new();
    let mut receipts = Vec::with_capacity(selection.receipts.len());
    let mut actionable_receipts = 0_u64;
    let mut pending_settlement_receipts = 0_u64;
    let mut failed_settlement_receipts = 0_u64;

    for receipt in &selection.receipts {
        let entry = build_exposure_ledger_receipt_entry(receipt)?;
        let settlement_status = entry.settlement_status.clone();
        if entry.action_required {
            actionable_receipts += 1;
        }
        match &settlement_status {
            SettlementStatus::Pending => pending_settlement_receipts += 1,
            SettlementStatus::Failed => failed_settlement_receipts += 1,
            SettlementStatus::NotApplicable | SettlementStatus::Settled => {}
        }
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.governed_max_amount.as_ref(),
            |position, amount| {
                position.governed_max_exposure_units = position
                    .governed_max_exposure_units
                    .saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.reserve_required_amount.as_ref(),
            |position, amount| {
                position.reserved_units = position.reserved_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.provisional_loss_amount.as_ref(),
            |position, amount| {
                position.provisional_loss_units =
                    position.provisional_loss_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.recovered_amount.as_ref(),
            |position, amount| {
                position.recovered_units = position.recovered_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.financial_amount.as_ref(),
            |position, amount| match settlement_status {
                SettlementStatus::Settled => {
                    position.settled_units = position.settled_units.saturating_add(amount.units);
                }
                SettlementStatus::Pending => {
                    position.pending_units = position.pending_units.saturating_add(amount.units);
                }
                SettlementStatus::Failed => {
                    position.failed_units = position.failed_units.saturating_add(amount.units);
                }
                SettlementStatus::NotApplicable => {}
            },
        );
        receipts.push(entry);
    }

    let mut decisions = Vec::with_capacity(decision_report.decisions.len());
    for row in &decision_report.decisions {
        let entry = build_exposure_ledger_decision_entry(row);
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.quoted_premium_amount.as_ref(),
            |position, amount| {
                position.quoted_premium_units =
                    position.quoted_premium_units.saturating_add(amount.units);
                if entry.lifecycle_state == chio_kernel::UnderwritingDecisionLifecycleState::Active
                {
                    position.active_quoted_premium_units = position
                        .active_quoted_premium_units
                        .saturating_add(amount.units);
                }
            },
        );
        decisions.push(entry);
    }

    let currencies = positions_by_currency.keys().cloned().collect::<Vec<_>>();
    Ok(ExposureLedgerReport {
        schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: normalized_query,
        support_boundary: ExposureLedgerSupportBoundary::default(),
        summary: ExposureLedgerSummary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: receipts.len() as u64,
            matching_decisions: decision_report.summary.matching_decisions,
            returned_decisions: decisions.len() as u64,
            active_decisions: decision_report.summary.active_decisions,
            superseded_decisions: decision_report.summary.superseded_decisions,
            actionable_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
            currencies: currencies.clone(),
            mixed_currency_book: currencies.len() > 1,
            truncated_receipts: selection.matching_receipts > receipts.len() as u64,
            truncated_decisions: decision_report.summary.matching_decisions
                > decisions.len() as u64,
        },
        positions: positions_by_currency.into_values().collect(),
        receipts,
        decisions,
    })
}

pub fn build_signed_credit_scorecard_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedCreditScorecardReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key anchors the
    // reputation scoring trust set.
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_credit_scorecard_report(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        None,
        query,
        &trusted_kernel_keys,
    )
    .map_err(CliError::from)?;
    SignedCreditScorecardReport::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_capital_book_report(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &CapitalBookQuery,
) -> Result<SignedCapitalBookReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_capital_book_report_from_store(&receipt_store, query).map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCapitalBookReport::sign(report, &keypair).map_err(Into::into)
}

pub fn issue_signed_capital_execution_instruction(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CapitalExecutionInstructionRequest,
) -> Result<SignedCapitalExecutionInstruction, CliError> {
    issue_signed_capital_execution_instruction_detailed(
        receipt_db_path,
        authority_seed_path,
        authority_db_path,
        request,
    )
    .map_err(CliError::from)
}

pub(crate) fn issue_signed_capital_execution_instruction_detailed(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CapitalExecutionInstructionRequest,
) -> Result<SignedCapitalExecutionInstruction, TrustHttpError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let artifact =
        build_capital_execution_instruction_artifact_from_store(&receipt_store, request)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCapitalExecutionInstruction::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))
}

pub fn issue_signed_capital_allocation_decision(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
) -> Result<SignedCapitalAllocationDecision, CliError> {
    issue_signed_capital_allocation_decision_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        request,
    )
    .map_err(CliError::from)
}

pub(crate) fn issue_signed_capital_allocation_decision_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
) -> Result<SignedCapitalAllocationDecision, TrustHttpError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key anchors the
    // reputation scoring trust set, then reuse it to sign the artifact.
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let artifact = build_capital_allocation_decision_artifact_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        request,
        &trusted_kernel_keys,
    )?;
    SignedCapitalAllocationDecision::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))
}

#[allow(clippy::too_many_lines)]
fn build_capital_allocation_decision_artifact_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
    trusted_kernel_keys: &[String],
) -> Result<CapitalAllocationDecisionArtifact, TrustHttpError> {
    let issued_at = unix_timestamp_now();
    let normalized_query = request.query.normalized();
    normalized_query
        .validate()
        .map_err(TrustHttpError::bad_request)?;
    validate_capital_execution_envelope(
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        issued_at,
    )?;

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let governed_receipt =
        select_capital_allocation_receipt(&selection.receipts, request.receipt_id.as_deref())?;
    let governed_metadata = governed_receipt.governed.as_ref().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital allocation receipt `{}` is missing governed metadata",
                governed_receipt.receipt_id
            ),
        )
    })?;
    let requested_amount = governed_metadata.max_amount.clone().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital allocation receipt `{}` is missing governed max_amount",
                governed_receipt.receipt_id
            ),
        )
    })?;
    let exposure_receipt = build_exposure_ledger_receipt_entry(governed_receipt)?;
    let exposure = build_exposure_ledger_report(receipt_store, &normalized_query.exposure_query())?;
    let capital_book = build_capital_book_report_from_store(receipt_store, &normalized_query)?;
    let active_facility = latest_active_granted_credit_facility(
        receipt_store,
        normalized_query.capability_id.as_deref(),
        normalized_query.agent_subject.as_deref(),
        normalized_query.tool_server.as_deref(),
        normalized_query.tool_name.as_deref(),
    )?;
    let fallback_facility_report = if active_facility.is_none() {
        Some(build_credit_facility_report_from_store(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            None,
            &normalized_query.exposure_query(),
            trusted_kernel_keys,
        )?)
    } else {
        None
    };
    let facility_disposition = active_facility.as_ref().map_or_else(
        || {
            fallback_facility_report
                .as_ref()
                .map(|report| report.disposition)
                .unwrap_or(CreditFacilityDisposition::ManualReview)
        },
        |_| CreditFacilityDisposition::Grant,
    );
    let facility_source = capital_book
        .sources
        .iter()
        .find(|source| source.kind == CapitalBookSourceKind::FacilityCommitment);
    let reserve_source = capital_book
        .sources
        .iter()
        .find(|source| source.kind == CapitalBookSourceKind::ReserveBook);

    ensure_capital_execution_custodian_authority(&request.authority_chain, &request.rail)?;
    if let Some(source) = facility_source {
        ensure_capital_execution_owner_authority(
            &request.authority_chain,
            capital_execution_role_from_book_role(source.owner_role),
        )?;
    }

    let position = exposure
        .positions
        .iter()
        .find(|position| position.currency == requested_amount.currency);
    let current_outstanding_units = position.map(credit_bond_outstanding_units).unwrap_or(0);
    let current_outstanding_amount =
        amount_if_nonzero(current_outstanding_units, &requested_amount.currency);

    let facility_terms = active_facility
        .as_ref()
        .and_then(|facility| facility.body.report.terms.as_ref())
        .or_else(|| {
            fallback_facility_report
                .as_ref()
                .and_then(|report| report.terms.as_ref())
        });
    let utilization_ceiling_units = facility_terms
        .map(|terms| {
            capital_allocation_ceiling_units(
                terms.credit_limit.units,
                terms.utilization_ceiling_bps,
            )
        })
        .unwrap_or(0);
    let concentration_cap_units = facility_terms
        .map(|terms| {
            capital_allocation_ceiling_units(terms.credit_limit.units, terms.concentration_cap_bps)
        })
        .unwrap_or(0);
    let current_reserve_units = reserve_source
        .and_then(|source| source.held_amount.as_ref().map(|amount| amount.units))
        .unwrap_or(0);
    let required_reserve_units = facility_terms
        .map(|terms| credit_bond_reserve_units(current_outstanding_units, terms.reserve_ratio_bps))
        .unwrap_or(0);
    let reserve_delta_units = required_reserve_units.saturating_sub(current_reserve_units);

    let mut evidence_refs =
        capital_book_evidence_from_exposure_refs(&exposure_receipt.evidence_refs);
    if let Some(source) = facility_source {
        if let Some(facility_id) = source.facility_id.as_ref() {
            push_unique_capital_book_evidence(
                &mut evidence_refs,
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditFacility,
                    reference_id: facility_id.clone(),
                    observed_at: Some(issued_at),
                    locator: Some(format!("credit-facility:{facility_id}")),
                },
            );
        }
    }
    if let Some(source) = reserve_source {
        if let Some(bond_id) = source.bond_id.as_ref() {
            push_unique_capital_book_evidence(
                &mut evidence_refs,
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditBond,
                    reference_id: bond_id.clone(),
                    observed_at: Some(issued_at),
                    locator: Some(format!("credit-bond:{bond_id}")),
                },
            );
        }
    }

    let mut findings = Vec::new();
    let mut instruction_drafts = Vec::new();
    let outcome = match facility_disposition {
        CreditFacilityDisposition::Deny => {
            findings.push(CapitalAllocationDecisionFinding {
                code: CapitalAllocationDecisionReasonCode::FacilityDenied,
                description:
                    "facility policy denied live capital allocation for the governed action"
                        .to_string(),
                evidence_refs: evidence_refs.clone(),
            });
            CapitalAllocationDecisionOutcome::Deny
        }
        CreditFacilityDisposition::ManualReview => {
            findings.push(CapitalAllocationDecisionFinding {
                code: CapitalAllocationDecisionReasonCode::FacilityManualReview,
                description:
                    "facility policy requires manual review before Chio can allocate live capital"
                        .to_string(),
                evidence_refs: evidence_refs.clone(),
            });
            CapitalAllocationDecisionOutcome::ManualReview
        }
        CreditFacilityDisposition::Grant => {
            let facility_terms = facility_terms.ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "capital allocation requires facility grant terms when disposition is grant",
                )
            })?;
            if facility_terms.credit_limit.currency != requested_amount.currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital allocation facility currency `{}` does not match requested currency `{}`",
                        facility_terms.credit_limit.currency, requested_amount.currency
                    ),
                ));
            }
            if facility_terms.capital_source == CreditFacilityCapitalSource::ManualProviderReview {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ManualCapitalSource,
                    description:
                        "the granted facility still resolves to manual provider review rather than operator-internal live allocation"
                            .to_string(),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::ManualReview
            } else if requested_amount.units > concentration_cap_units {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ConcentrationCapExceeded,
                    description: format!(
                        "requested governed amount {} exceeds the single-allocation concentration cap {}",
                        requested_amount.units, concentration_cap_units
                    ),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::Deny
            } else if current_outstanding_units > utilization_ceiling_units {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::UtilizationCeilingExceeded,
                    description: format!(
                        "current outstanding exposure {} exceeds the live utilization ceiling {}",
                        current_outstanding_units, utilization_ceiling_units
                    ),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::Queue
            } else if reserve_delta_units > 0 && reserve_source.is_none() {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ReserveBookMissing,
                    description:
                        "allocation would require additional reserve backing, but no current reserve book is available for custody-neutral execution"
                            .to_string(),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::ManualReview
            } else {
                let facility_source = facility_source.ok_or_else(|| {
                    TrustHttpError::new(
                        StatusCode::CONFLICT,
                        "capital allocation requires a current facility source after facility grant",
                    )
                })?;
                instruction_drafts.push(CapitalAllocationInstructionDraft {
                    source_id: facility_source.source_id.clone(),
                    source_kind: CapitalBookSourceKind::FacilityCommitment,
                    action: CapitalExecutionInstructionAction::TransferFunds,
                    amount: requested_amount.clone(),
                    description:
                        "transfer the governed amount from the selected committed capital source"
                            .to_string(),
                });
                if reserve_delta_units > 0 {
                    let reserve_source = reserve_source.ok_or_else(|| {
                        TrustHttpError::new(
                            StatusCode::CONFLICT,
                            "capital allocation requires a current reserve source for additional reserve movement",
                        )
                    })?;
                    instruction_drafts.push(CapitalAllocationInstructionDraft {
                        source_id: reserve_source.source_id.clone(),
                        source_kind: CapitalBookSourceKind::ReserveBook,
                        action: CapitalExecutionInstructionAction::LockReserve,
                        amount: MonetaryAmount {
                            units: reserve_delta_units,
                            currency: requested_amount.currency.clone(),
                        },
                        description:
                            "lock incremental reserve required by the selected governed action"
                                .to_string(),
                    });
                }
                CapitalAllocationDecisionOutcome::Allocate
            }
        }
    };

    let description = request.description.clone().unwrap_or_else(|| {
        format!(
            "{:?} live capital allocation for governed receipt `{}`",
            outcome, governed_receipt.receipt_id
        )
    });
    let allocation_id_input = canonical_json_bytes(&(
        CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA,
        &normalized_query,
        &governed_receipt.receipt_id,
        &requested_amount,
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        &outcome,
        &instruction_drafts,
        &description,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let allocation_id = format!("cad-{}", sha256_hex(&allocation_id_input));

    Ok(CapitalAllocationDecisionArtifact {
        schema: CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA.to_string(),
        allocation_id,
        issued_at,
        query: normalized_query,
        subject_key: governed_receipt
            .subject_key
            .clone()
            .or_else(|| request.query.agent_subject.clone())
            .ok_or_else(|| {
                TrustHttpError::bad_request(
                    "capital allocation requires --agent-subject for subject-scoped capital truth",
                )
            })?,
        governed_receipt_id: governed_receipt.receipt_id.clone(),
        intent_id: governed_metadata.intent_id.clone(),
        approval_token_id: governed_metadata
            .approval
            .as_ref()
            .map(|approval| approval.token_id.clone()),
        capability_id: governed_receipt.capability_id.clone(),
        tool_server: governed_receipt.tool_server.clone(),
        tool_name: governed_receipt.tool_name.clone(),
        requested_amount: requested_amount.clone(),
        facility_id: facility_source.and_then(|source| source.facility_id.clone()),
        bond_id: reserve_source
            .and_then(|source| source.bond_id.clone())
            .or_else(|| facility_source.and_then(|source| source.bond_id.clone())),
        source_id: facility_source.map(|source| source.source_id.clone()),
        source_kind: facility_source.map(|source| source.kind),
        reserve_source_id: reserve_source.map(|source| source.source_id.clone()),
        outcome,
        authority_chain: request.authority_chain.clone(),
        execution_window: request.execution_window.clone(),
        rail: request.rail.clone(),
        current_outstanding_amount: current_outstanding_amount.clone(),
        projected_outstanding_amount: current_outstanding_amount,
        current_reserve_amount: amount_if_nonzero(
            current_reserve_units,
            &requested_amount.currency,
        ),
        required_reserve_amount: amount_if_nonzero(
            required_reserve_units,
            &requested_amount.currency,
        ),
        reserve_delta_amount: amount_if_nonzero(reserve_delta_units, &requested_amount.currency),
        utilization_ceiling_amount: amount_if_nonzero(
            utilization_ceiling_units,
            &requested_amount.currency,
        ),
        concentration_cap_amount: amount_if_nonzero(
            concentration_cap_units,
            &requested_amount.currency,
        ),
        instruction_drafts,
        support_boundary: CapitalAllocationDecisionSupportBoundary::default(),
        findings,
        evidence_refs,
        description,
    })
}

#[cfg(test)]
mod reports_tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn signed_comptroller_surface_report_verifies_and_is_canonical() {
        use chio_kernel::operator_report::{
            ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
            OperatorReportQuery, COMPTROLLER_SURFACE_REPORT_SCHEMA,
        };

        let dir = std::env::temp_dir().join(format!("chio-signed-cs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).test_expect("create temp dir");
        let authority_seed_path = dir.join("authority.seed");

        let report = ComptrollerSurfaceReport {
            schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_000,
            filters: OperatorReportQuery::default(),
            exposure_positions: vec![ExposureLedgerCurrencyPosition {
                currency: "USD".to_string(),
                governed_max_exposure_units: 4200,
                reserved_units: 1000,
                settled_units: 0,
                pending_units: 0,
                failed_units: 0,
                provisional_loss_units: 0,
                recovered_units: 0,
                quoted_premium_units: 0,
                active_quoted_premium_units: 0,
            }],
            decision_summary: ComptrollerDecisionSummary {
                allow_count: 1,
                deny_count: 1,
                cancelled_count: 0,
                incomplete_count: 0,
            },
            settlement_reconciliation: Default::default(),
            budget_utilization: Default::default(),
            source_refs: ComptrollerSurfaceSourceRefs::default(),
            execution_nonce_ref: None,
            hold_ref: None,
        };

        let signed =
            build_signed_comptroller_surface_report(report, Some(&authority_seed_path), None)
                .test_expect("build signed comptroller surface");
        assert!(
            signed.verify_signature().test_expect("verify"),
            "signature must verify"
        );
        assert_eq!(signed.body.schema, "chio.comptroller.surface-report.v1");
        let reserialized = serde_json::to_vec(&signed).test_expect("serialize envelope");
        let parsed: SignedComptrollerSurfaceReport =
            serde_json::from_slice(&reserialized).test_expect("parse");
        assert!(parsed.verify_signature().test_expect("verify parsed"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
