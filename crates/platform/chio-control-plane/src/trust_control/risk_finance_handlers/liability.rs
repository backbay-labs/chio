use super::*;

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
