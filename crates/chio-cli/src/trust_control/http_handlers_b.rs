async fn handle_receipt_analytics(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptAnalyticsQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_receipt_analytics(&query) {
        Ok(response) => Json::<ReceiptAnalyticsResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_evidence_export(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceExportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let prepared = match evidence_export::prepare_evidence_export(
        request.query,
        request.require_proofs,
        request.federation_policy,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let bundle = match store.build_evidence_export_bundle(&prepared.query) {
        Ok(bundle) => bundle,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let transparency = match store.build_evidence_export_transparency_summary(&bundle.checkpoints) {
        Ok(transparency) => transparency,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if let Err(error) =
        evidence_export::validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    Json(evidence_export::RemoteEvidenceExportResponse {
        bundle,
        transparency: Some(transparency),
        federation_policy: prepared.federation_policy,
    })
    .into_response()
}

async fn handle_evidence_import(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceImportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, EVIDENCE_IMPORT_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Err(error) = evidence_export::validate_import_package_data(&request.package) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let share_import = match evidence_export::build_federated_share_import(&request.package) {
        Ok(share) => share,
        Err(error) => {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.import_federated_evidence_share(&share_import) {
        Ok(share) => Json(evidence_export::RemoteEvidenceImportResponse { share }).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_cost_attribution_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CostAttributionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_cost_attribution_report(&query) {
        Ok(report) => Json::<CostAttributionReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_shared_evidence_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<SharedEvidenceQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_shared_evidence_report(&query) {
        Ok(report) => Json::<SharedEvidenceReferenceReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_operator_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let budget_store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_operator_report(&receipt_store, &budget_store, &query) {
        Ok(report) => Json::<OperatorReport>(report).into_response(),
        Err(response) => response,
    }
}

async fn handle_behavioral_feed_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<BehavioralFeedQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "behavioral feed export requires --receipt-db on the trust-control service",
            );
        }
    };

    match build_signed_behavioral_feed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &query,
    ) {
        Ok(feed) => Json::<SignedBehavioralFeed>(feed).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_exposure_ledger_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

    match build_exposure_ledger_report(&receipt_store, &query) {
        Ok(report) => match SignedExposureLedgerReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedExposureLedgerReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_scorecard_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

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

    match build_credit_scorecard_report(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => match SignedCreditScorecardReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditScorecardReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_capital_book_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CapitalBookQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_issue_capital_execution_instruction(
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

async fn handle_issue_capital_allocation_decision(
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

async fn handle_credit_facility_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

    match build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditFacilityReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_credit_facility(
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

async fn handle_query_credit_facilities(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditFacilityListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_credit_bond_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

    match build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditBondReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_credit_bond(
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

async fn handle_query_credit_bonds(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBondListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_credit_bonded_execution_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditBondedExecutionSimulationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_credit_loss_lifecycle_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_issue_credit_loss_lifecycle(
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

async fn handle_query_credit_loss_lifecycle(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

async fn handle_credit_backtest_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBacktestQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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

    match build_credit_backtest_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditBacktestReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_provider_risk_package_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditProviderRiskPackageQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

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
    ) {
        Ok(report) => match SignedCreditProviderRiskPackage::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditProviderRiskPackage>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_liability_provider(
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
        Err(CliError::Other(message)) => plain_http_error(StatusCode::BAD_REQUEST, &message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_providers(
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

async fn handle_resolve_liability_provider(
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

async fn handle_issue_liability_quote_request(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_quote_response(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_placement(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_pricing_authority(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_bound_coverage(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_auto_bind(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_market_workflows(
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

async fn handle_issue_liability_claim_package(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_response(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_dispute(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_adjudication(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_payout_instruction(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_payout_receipt(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_settlement_instruction(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_settlement_receipt(
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
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_claim_workflows(
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

async fn handle_runtime_attestation_appraisal_report(
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
        Err(CliError::Other(message)) => plain_http_error(StatusCode::BAD_REQUEST, &message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_runtime_attestation_appraisal_result_export(
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
        Err(CliError::Other(message)) => plain_http_error(StatusCode::BAD_REQUEST, &message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_runtime_attestation_appraisal_import(
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

async fn handle_settlement_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_settlement_reconciliation_report(&query) {
        Ok(report) => Json::<SettlementReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_record_settlement_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<SettlementReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.upsert_settlement_reconciliation(
        &request.receipt_id,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(SettlementReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_metered_billing_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_metered_billing_reconciliation_report(&query) {
        Ok(report) => Json::<MeteredBillingReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_economic_receipt_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_economic_receipt_projection_report(&query) {
        Ok(report) => Json::<EconomicReceiptProjectionReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_economic_completion_flow_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_economic_completion_flow_report(&receipt_store, &query) {
        Ok(report) => Json::<EconomicCompletionFlowReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_authorization_context_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_context_report(&query) {
        Ok(report) => Json::<AuthorizationContextReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_authorization_profile_metadata_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    Json::<ChioOAuthAuthorizationMetadataReport>(
        receipt_store.authorization_profile_metadata_report(),
    )
    .into_response()
}

async fn handle_authorization_review_pack_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_review_pack(&query) {
        Ok(report) => Json::<ChioOAuthAuthorizationReviewPack>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_underwriting_policy_input(
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

    match build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
    ) {
        Ok(report) => match SignedUnderwritingPolicyInput::sign(report, &keypair) {
            Ok(signed) => Json::<SignedUnderwritingPolicyInput>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_underwriting_decision_report(
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
                "trust service is missing receipt_db_path for underwriting decision queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
    ) {
        Ok(report) => Json::<UnderwritingDecisionReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_underwriting_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingSimulationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

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

    match build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
    ) {
        Ok(report) => Json::<UnderwritingSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_query_underwriting_decisions(
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

async fn handle_issue_underwriting_decision(
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
    ) {
        Ok(decision) => Json::<SignedUnderwritingDecision>(decision).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_create_underwriting_appeal(
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

async fn handle_resolve_underwriting_appeal(
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

async fn handle_record_metered_billing_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<MeteredBillingReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(message) = validate_metered_billing_reconciliation_request(&request) {
        return plain_http_error(StatusCode::BAD_REQUEST, &message);
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let evidence = MeteredBillingEvidenceRecord {
        usage_evidence: chio_core::receipt::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: request.adapter_kind.clone(),
            evidence_id: request.evidence_id.clone(),
            observed_units: request.observed_units,
            evidence_sha256: request.evidence_sha256.clone(),
        },
        billed_cost: request.billed_cost.clone(),
        recorded_at: request.recorded_at,
    };

    match receipt_store.upsert_metered_billing_reconciliation(
        &request.receipt_id,
        &evidence,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(MeteredBillingReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            evidence,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_local_reputation(
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

    match issuance::inspect_local_reputation(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        query.since,
        query.until,
        state.config.issuance_policy.as_ref(),
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

async fn handle_reputation_compare(
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

    let local = match issuance::inspect_local_reputation(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        request.since,
        request.until,
        state.config.issuance_policy.as_ref(),
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

async fn handle_issue_portable_reputation_summary(
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

async fn handle_issue_portable_negative_event(
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

async fn handle_evaluate_portable_reputation(
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

async fn handle_record_lineage_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RecordCapabilitySnapshotRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, LINEAGE_RECORD_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if let Err(error) = store
        .record_capability_snapshot(&payload.capability, payload.parent_capability_id.as_deref())
    {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    respond_after_leader_visible_write(
        &state,
        "capability lineage was not visible on the leader after write",
        || {
            let visible = store
                .get_lineage(&payload.capability.id)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?
                .is_some();
            if visible {
                Ok(Some(json!({
                    "stored": true,
                    "capabilityId": payload.capability.id.clone(),
                })))
            } else {
                Ok(None)
            }
        },
    )
}

/// GET /v1/lineage/:capability_id
///
/// Returns the CapabilitySnapshot for the given capability ID, or 404 if not found.
async fn handle_get_lineage(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_lineage(&capability_id) {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("capability not found: {capability_id}"),
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/lineage/:capability_id/chain
///
/// Returns the full delegation chain for the given capability ID, root-first.
async fn handle_get_delegation_chain(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_delegation_chain(&capability_id) {
        Ok(chain) => Json(chain).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/agents/:subject_key/receipts
///
/// Convenience endpoint: returns receipts for a given agent subject key.
/// Delegates to the same query_receipts call as GET /v1/receipts/query with
/// agentSubject set, passing through limit and cursor from query params.
async fn handle_agent_receipts(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<AgentReceiptsHttpQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let kernel_query = ReceiptQuery {
        agent_subject: Some(subject_key),
        cursor: query.cursor,
        limit: list_limit(query.limit),
        ..Default::default()
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}

async fn handle_append_child_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ChildRequestReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, CHILD_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_child_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "child receipt was not visible on the leader after write",
            || {
                let receipts = store
                    .list_child_receipts(
                        MAX_LIST_LIMIT,
                        Some(receipt.session_id.as_str()),
                        Some(receipt.parent_request_id.as_str()),
                        Some(receipt.request_id.as_str()),
                        Some(receipt.operation_kind.as_str()),
                        Some(terminal_state_kind(&receipt.terminal_state)),
                    )
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                if receipts
                    .into_iter()
                    .any(|candidate| candidate.id == receipt.id)
                {
                    Ok(Some(json!({
                        "stored": true,
                        "receiptId": receipt.id.clone(),
                    })))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_list_budgets(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match store.list_usages(list_limit(query.limit), query.capability_id.as_deref()) {
        Ok(usages) => usages,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(BudgetListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id: query.capability_id,
        count: usages.len(),
        usages: usages
            .into_iter()
            .map(|usage| BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
                updated_at: usage.updated_at,
                seq: None,
            })
            .collect(),
    })
    .into_response()
}

async fn handle_try_increment_budget(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryIncrementBudgetRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_INCREMENT_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_increment(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
            if budget_visibility_matches(allowed, invocation_count, payload.max_invocations) {
                Ok(Some(TryIncrementBudgetResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count,
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                }))
            } else {
                Ok(None)
            }
        },
    )
}

async fn handle_try_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_AUTHORIZE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let authority = match current_budget_event_authority(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
        payload.cost_units,
        payload.max_cost_per_invocation,
        payload.max_total_cost_units,
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        authority.as_ref(),
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if allowed {
        let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index)
        {
            Ok(Some(usage)) => Some((
                TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count: Some(usage.invocation_count),
                    total_cost_exposed: Some(usage.total_cost_exposed),
                    total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        Some(usage.seq),
                        budget_authority_guarantee_level(&state, Some(usage.seq)),
                    ),
                    budget_commit: None,
                },
                usage.seq,
            )),
            Ok(None) => None,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        drop(store);
        let Some((response, budget_seq)) = committed_response else {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "budget exposure state was not visible on the leader after write",
            );
        };
        let budget_commit = match wait_for_budget_write_quorum_commit(&state, budget_seq).await {
            Ok(budget_commit) => budget_commit,
            Err(_) => {
                let rollback_result =
                    rollback_budget_authorize_exposure(&state, &payload, authority.as_ref());
                return match rollback_result {
                    Ok(()) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "budget authorize became leader-visible at commit index {budget_seq} but failed quorum commit; local exposure rollback succeeded"
                        ),
                    ),
                    Err(error) => plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(
                            "budget authorize became leader-visible at commit index {budget_seq} but failed quorum commit and local exposure rollback also failed: {error}"
                        ),
                    ),
                };
            }
        };
        json_response_with_leader_visibility_and_budget_commit(&state, response, budget_commit)
    } else {
        respond_after_leader_visible_write(
            &state,
            "budget exposure state was not visible on the leader after write",
            || {
                let usage = store
                    .get_usage(&payload.capability_id, payload.grant_index)
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                Ok(Some(TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count: usage.as_ref().map(|usage| usage.invocation_count),
                    total_cost_exposed: usage.as_ref().map(|usage| usage.total_cost_exposed),
                    total_cost_realized_spend: usage
                        .as_ref()
                        .map(|usage| usage.total_cost_realized_spend),
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                    budget_commit: None,
                }))
            },
        )
    }
}

async fn handle_reverse_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReverseChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_RELEASE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(
        &state,
        &mut store,
        payload.hold_id.as_deref(),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    if let Err(error) = store.reverse_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        authority.as_ref(),
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReverseChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            usage.seq,
        )),
        Ok(None) => None,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "released budget exposure state was not visible on the leader after write",
        committed_response,
    )
    .await
}

async fn handle_reduce_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReduceChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let released_exposure_units = payload.release_units();
    match forward_post_to_leader(&state, BUDGET_RECONCILE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(
        &state,
        &mut store,
        payload.hold_id.as_deref(),
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let reconcile_result = if let (Some(exposure_units), Some(realized_spend_units)) =
        (payload.exposure_units, payload.realized_spend_units)
    {
        store.settle_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            exposure_units,
            realized_spend_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            authority.as_ref(),
        )
    } else {
        store.reduce_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            released_exposure_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            authority.as_ref(),
        )
    };
    if let Err(error) = reconcile_result {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReduceChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                released_exposure_units: Some(released_exposure_units),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            usage.seq,
        )),
        Ok(None) => None,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "reconciled budget spend state was not visible on the leader after write",
        committed_response,
    )
    .await
}

fn resolve_budget_hold_authority(
    state: &TrustServiceState,
    store: &mut SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(Some(authority)) => return Ok(Some(authority)),
            Ok(None) => {}
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ));
            }
        }
    }
    current_budget_event_authority(state)
}
