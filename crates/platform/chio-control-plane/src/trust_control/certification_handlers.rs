//! HTTP handlers for the certification surface: the certification registry,
//! the public certification discovery/marketplace network, and the generic
//! trust-activation, governance, and open-market artifact endpoints.

use super::report_rendering::forward_post_to_leader;
use super::report_validation::validate_service_auth;
use super::*;

pub(crate) async fn handle_list_certifications(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(CertificationRegistryListResponse {
            configured: true,
            count: registry.artifacts.len(),
            artifacts: registry.artifacts.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_get_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&artifact_id) {
        Some(entry) => Json(entry.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("certification artifact `{artifact_id}` was not found"),
        ),
    }
}

pub(crate) async fn handle_publish_certification(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(artifact): Json<SignedCertificationCheck>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.publish(artifact) {
        Ok(entry) => entry,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

pub(crate) async fn handle_resolve_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.resolve(&tool_server_id)).into_response()
}

pub(crate) async fn handle_public_resolve_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.resolve(&tool_server_id)).into_response()
}

pub(crate) async fn handle_public_certification_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_public_search_certifications(
    State(state): State<TrustServiceState>,
    Query(query): Query<CertificationPublicSearchQuery>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.search_public(&metadata.publisher, metadata.expires_at, &query)).into_response()
}

pub(crate) async fn handle_public_certification_transparency(
    State(state): State<TrustServiceState>,
    Query(query): Query<CertificationTransparencyQuery>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.transparency(&metadata.publisher, &query)).into_response()
}

pub(crate) async fn handle_public_generic_namespace(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_signed_generic_namespace(&state.config) {
        Ok(namespace) => Json(namespace).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

pub(crate) async fn handle_public_generic_listings(
    State(state): State<TrustServiceState>,
    Query(query): Query<GenericListingQuery>,
) -> Response {
    match build_public_generic_listing_report(&state.config, &query) {
        Ok(report) => Json(report).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

pub(crate) async fn handle_issue_generic_trust_activation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericTrustActivationIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::issue_signed_generic_trust_activation(&state.config, &request)
    {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_evaluate_generic_trust_activation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericTrustActivationEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::evaluate_generic_trust_activation_request(
        &state.config,
        &request,
    ) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_generic_governance_charter(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCharterIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::issue_signed_generic_governance_charter(
        &state.config,
        &request,
    ) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_generic_governance_case(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCaseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::issue_signed_generic_governance_case(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_evaluate_generic_governance_case(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCaseEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::evaluate_generic_governance_case_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_open_market_fee_schedule(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketFeeScheduleIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    // Governed issuance binds the legacy schedule under the local fiscal fence, so
    // it has to run on the leader. Ungoverned issuance stays local and keeps signing
    // with this node's authority key.
    if state.fiscal_runtime.is_some() {
        match forward_post_to_leader(&state, OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH, &request).await {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    match service_runtime::issuance::issue_signed_open_market_fee_schedule(
        &state.config,
        &request,
        state.fiscal_runtime.as_deref(),
    ) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_open_market_penalty(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketPenaltyIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    // A fiscal penalty is authoritative against the active fee-schedule binding.
    // Followers can hold a stale resolver or still be in fallback, so governed
    // issuance must run on the leader before any validation or signing occurs.
    if state.fiscal_runtime.is_some() {
        match forward_post_to_leader(&state, OPEN_MARKET_PENALTY_ISSUE_PATH, &request).await {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    match service_runtime::issuance::issue_signed_open_market_penalty(
        &state.config,
        &request,
        state.fiscal_runtime.as_deref(),
    ) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_evaluate_open_market_penalty(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketPenaltyEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::issuance::evaluate_open_market_penalty_request(
        &state.config,
        &request,
        state.fiscal_runtime.as_deref(),
    ) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_publish_certification_network(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CertificationNetworkPublishRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match crate::certify::network::publish_certification_across_network(
        &network,
        &request.artifact,
        &request.operator_ids,
    ) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_discover_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let response =
        crate::certify::network::discover_certifications_across_network(&network, &tool_server_id);
    Json(response).into_response()
}

pub(crate) async fn handle_search_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Query(query): Query<CertificationMarketplaceSearchQuery>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(crate::certify::network::search_public_certifications_across_network(&network, &query))
        .into_response()
}

pub(crate) async fn handle_transparency_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Query(query): Query<CertificationMarketplaceTransparencyQuery>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(
        crate::certify::network::transparency_public_certifications_across_network(
            &network, &query,
        ),
    )
    .into_response()
}

pub(crate) async fn handle_consume_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CertificationConsumptionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(crate::certify::network::consume_public_certification_across_network(&network, &request))
        .into_response()
}

pub(crate) async fn handle_revoke_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CertificationRevocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.revoke(&artifact_id, request.reason.as_deref(), request.revoked_at) {
        Ok(entry) => entry,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

pub(crate) async fn handle_dispute_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CertificationDisputeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.dispute(&artifact_id, &request) {
        Ok(entry) => entry,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}
