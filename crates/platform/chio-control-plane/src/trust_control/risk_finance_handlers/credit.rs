use super::*;

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
