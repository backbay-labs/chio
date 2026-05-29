//! HTTP handlers for the risk-and-finance surface: exposure, credit, and
//! capital reports and issuance; the liability insurance market and claims
//! workflows; underwriting; runtime-attestation appraisal; and reputation.

use super::*;

pub(crate) async fn handle_exposure_ledger_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "exposure ledger report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    match build_exposure_ledger_report_with_context(&receipt_store, &query, read_context) {
        Ok(report) => match SignedExposureLedgerReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedExposureLedgerReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_credit_scorecard_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context =
        match resolve_admin_report_read_context(&headers, &state.config, "credit scorecard report")
        {
            Ok(context) => context,
            Err(response) => return response,
        };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit scorecard export requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    match build_credit_scorecard_report_with_context(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
        read_context,
        &trusted_kernel_keys,
    ) {
        Ok(report) => match SignedCreditScorecardReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditScorecardReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_capital_book_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CapitalBookQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "capital book report")
    {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    match build_capital_book_report_from_store(&receipt_store, &query) {
        Ok(report) => match SignedCapitalBookReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCapitalBookReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_capital_execution_instruction(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CapitalExecutionInstructionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "capital instruction issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_capital_execution_instruction_detailed(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(signed) => Json::<SignedCapitalExecutionInstruction>(signed).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_capital_allocation_decision(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CapitalAllocationDecisionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "capital allocation issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_capital_allocation_decision_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
    ) {
        Ok(signed) => Json::<SignedCapitalAllocationDecision>(signed).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_credit_facility_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit facility report")
    {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit facility evaluation requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<CreditFacilityReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_credit_facility(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditFacilityIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit facility issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_facility_detailed(CreditIssuanceArgs {
        receipt_db_path,
        budget_db_path: state.config.budget_db_path.as_deref(),
        authority_seed_path: state.config.authority_seed_path.as_deref(),
        authority_db_path: state.config.authority_db_path.as_deref(),
        certification_registry_file: state.config.certification_registry_file.as_deref(),
        issuance_policy: state.config.issuance_policy.as_ref(),
        query: &request.query,
        supersedes_artifact_id: request.supersedes_facility_id.as_deref(),
    }) {
        Ok(facility) => Json::<SignedCreditFacility>(facility).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_query_credit_facilities(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditFacilityListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit facility listing")
    {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_facilities(&query) {
        Ok(report) => Json::<CreditFacilityListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_credit_bond_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit bond report")
    {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit bond evaluation requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<CreditBondReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_credit_bond(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditBondIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit bond issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_bond_detailed(CreditIssuanceArgs {
        receipt_db_path,
        budget_db_path: state.config.budget_db_path.as_deref(),
        authority_seed_path: state.config.authority_seed_path.as_deref(),
        authority_db_path: state.config.authority_db_path.as_deref(),
        certification_registry_file: state.config.certification_registry_file.as_deref(),
        issuance_policy: state.config.issuance_policy.as_ref(),
        query: &request.query,
        supersedes_artifact_id: request.supersedes_bond_id.as_deref(),
    }) {
        Ok(bond) => Json::<SignedCreditBond>(bond).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_query_credit_bonds(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBondListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit bond listing")
    {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_bonds(&query) {
        Ok(report) => Json::<CreditBondListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_credit_bonded_execution_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditBondedExecutionSimulationRequest>,
) -> Response {
    if let Err(response) = resolve_admin_report_read_context(
        &headers,
        &state.config,
        "credit bonded execution simulation report",
    ) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_bonded_execution_simulation_report_from_store(&receipt_store, &request) {
        Ok(report) => Json::<CreditBondedExecutionSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_credit_loss_lifecycle_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit loss lifecycle report")
    {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_loss_lifecycle_report_from_store(&receipt_store, &query) {
        Ok(report) => Json::<CreditLossLifecycleReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_credit_loss_lifecycle(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditLossLifecycleIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit loss lifecycle issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_loss_lifecycle_detailed(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(event) => Json::<SignedCreditLossLifecycle>(event).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_query_credit_loss_lifecycle(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit loss lifecycle listing")
    {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_loss_lifecycle(&query) {
        Ok(report) => Json::<CreditLossLifecycleListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_credit_backtest_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBacktestQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "credit backtest report")
    {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit backtests require --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_credit_backtest_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<CreditBacktestReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_credit_provider_risk_package_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditProviderRiskPackageQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "credit provider risk package report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "provider risk package export requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    match build_credit_provider_risk_package_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &keypair,
        &query,
        read_context,
    ) {
        Ok(report) => match SignedCreditProviderRiskPackage::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditProviderRiskPackage>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_liability_provider(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityProviderIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability provider issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_provider(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request.report,
        request.supersedes_provider_record_id.as_deref(),
    ) {
        Ok(provider) => Json::<SignedLiabilityProvider>(provider).into_response(),
        Err(error @ CliError::Chio(_)) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_query_liability_providers(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityProviderListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_providers(&query) {
        Ok(report) => Json::<LiabilityProviderListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_resolve_liability_provider(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityProviderResolutionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.resolve_liability_provider(&query) {
        Ok(report) => Json::<LiabilityProviderResolutionReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

pub(crate) async fn handle_issue_liability_quote_request(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityQuoteRequestIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability quote request issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_quote_request(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityQuoteRequest>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_quote_response(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityQuoteResponseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability quote response issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_quote_response(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityQuoteResponse>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_placement(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityPlacementIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability placement issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_placement(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityPlacement>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_pricing_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityPricingAuthorityIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability pricing authority issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_pricing_authority(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityPricingAuthority>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_bound_coverage(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityBoundCoverageIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability bound coverage issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_bound_coverage(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityBoundCoverage>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_auto_bind(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityAutoBindIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability auto-bind issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_auto_bind(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityAutoBindDecision>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_query_liability_market_workflows(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityMarketWorkflowQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_market_workflows(&query) {
        Ok(report) => Json::<LiabilityMarketWorkflowReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

pub(crate) async fn handle_issue_liability_claim_package(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimPackageIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim package issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_package(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimPackage>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_response(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimResponseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim response issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_response(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimResponse>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_dispute(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimDisputeIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim dispute issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_dispute(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimDispute>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_adjudication(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimAdjudicationIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim adjudication issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_adjudication(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimAdjudication>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_payout_instruction(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimPayoutInstructionIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim payout instruction issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_payout_instruction(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimPayoutInstruction>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_payout_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimPayoutReceiptIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim payout receipt issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_payout_receipt(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimPayoutReceipt>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_settlement_instruction(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimSettlementInstructionIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim settlement instruction issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_settlement_instruction(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimSettlementInstruction>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_liability_claim_settlement_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimSettlementReceiptIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim settlement receipt issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_settlement_receipt(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimSettlementReceipt>(artifact).into_response(),
        Err(error @ CliError::Chio(_)) => liability_market_http_error(&error.to_string()),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_query_liability_claim_workflows(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityClaimWorkflowQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_claim_workflows(&query) {
        Ok(report) => Json::<LiabilityClaimWorkflowReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

pub(crate) async fn handle_runtime_attestation_appraisal_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    match build_signed_runtime_attestation_appraisal_report(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.runtime_assurance_policy.as_ref(),
        &request.runtime_attestation,
    ) {
        Ok(report) => Json::<SignedRuntimeAttestationAppraisalReport>(report).into_response(),
        Err(error @ CliError::Chio(_)) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_runtime_attestation_appraisal_result_export(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalResultExportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    match build_signed_runtime_attestation_appraisal_result(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.runtime_assurance_policy.as_ref(),
        &request,
    ) {
        Ok(result) => Json::<SignedRuntimeAttestationAppraisalResult>(result).into_response(),
        Err(error @ CliError::Chio(_)) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_runtime_attestation_appraisal_import(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalImportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    Json::<RuntimeAttestationAppraisalImportReport>(
        build_runtime_attestation_appraisal_import_report(&request, unix_timestamp_now()),
    )
    .into_response()
}

pub(crate) async fn handle_underwriting_policy_input(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting input queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    match build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
        chio_kernel::ReceiptReadContext::admin_service(),
        &trusted_kernel_keys,
    ) {
        Ok(report) => match SignedUnderwritingPolicyInput::sign(report, &keypair) {
            Ok(signed) => Json::<SignedUnderwritingPolicyInput>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_underwriting_decision_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "underwriting decision report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
        read_context,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<UnderwritingDecisionReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_underwriting_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingSimulationRequest>,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "underwriting simulation report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting simulation queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
        read_context,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<UnderwritingSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_query_underwriting_decisions(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingDecisionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_underwriting_decisions(&query) {
        Ok(report) => Json::<UnderwritingDecisionListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_underwriting_decision(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingDecisionIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision issuance",
            );
        }
    };

    match issue_signed_underwriting_decision_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request.query,
        request.supersedes_decision_id.as_deref(),
        chio_kernel::ReceiptReadContext::admin_service(),
    ) {
        Ok(decision) => Json::<SignedUnderwritingDecision>(decision).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_create_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealCreateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.create_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_resolve_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealResolveRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.resolve_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_local_reputation(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<LocalReputationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for local reputation queries",
        );
    }

    let read_context = ReceiptReadContext::admin_service();
    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match issuance::inspect_local_reputation_with_read_context(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        query.since,
        query.until,
        state.config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &read_context,
    ) {
        Ok(mut inspection) => {
            if let Some(receipt_db_path) = state.config.receipt_db_path.as_deref() {
                match reputation::build_imported_trust_report(
                    receipt_db_path,
                    &inspection.subject_key,
                    inspection.since,
                    inspection.until,
                    unix_timestamp_now(),
                    &inspection.scoring,
                ) {
                    Ok(report) => inspection.imported_trust = Some(report),
                    Err(error) => {
                        return plain_http_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &error.to_string(),
                        );
                    }
                }
            }
            Json(inspection).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_reputation_compare(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<ReputationCompareRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for reputation compare queries",
        );
    }

    let read_context = ReceiptReadContext::admin_service();
    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    let local = match issuance::inspect_local_reputation_with_read_context(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        request.since,
        request.until,
        state.config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &read_context,
    ) {
        Ok(local) => local,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let shared_evidence = {
        let store = match open_receipt_store(&state.config) {
            Ok(store) => store,
            Err(response) => return response,
        };
        match store.query_shared_evidence_report(&SharedEvidenceQuery {
            agent_subject: Some(local.subject_key.clone()),
            since: request.since,
            until: request.until,
            read_context: Some(chio_kernel::ReceiptReadContext::admin_service()),
            ..SharedEvidenceQuery::default()
        }) {
            Ok(report) => report,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    };
    let imported_trust = match state.config.receipt_db_path.as_deref() {
        Some(receipt_db_path) => match reputation::build_imported_trust_report(
            receipt_db_path,
            &local.subject_key,
            local.since,
            local.until,
            unix_timestamp_now(),
            &local.scoring,
        ) {
            Ok(report) => Some(report),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        },
        None => None,
    };
    match reputation::build_reputation_comparison(
        local,
        &request.passport,
        request.verifier_policy.as_ref(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        shared_evidence,
        imported_trust,
    ) {
        Ok(comparison) => {
            Json::<reputation::PortableReputationComparison>(comparison).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_portable_reputation_summary(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableReputationSummaryIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_portable_reputation_summary(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_portable_negative_event(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableNegativeEventIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_portable_negative_event(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_evaluate_portable_reputation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableReputationEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match evaluate_portable_reputation_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
