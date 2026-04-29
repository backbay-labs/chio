async fn handle_authority_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_authority_status(&state.config) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

async fn handle_rotate_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_authority_mutation_auth(&headers, &state, AUTHORITY_PATH) {
        return response;
    }
    match forward_authority_post_to_leader(&state, AUTHORITY_PATH, &json!({})).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Err(response) = enforce_authority_mutation_fence(&state) {
        return response;
    }
    match rotate_authority(&state.config) {
        Ok(status) => {
            if let Err(response) = refresh_authority_mutation_fence(&state) {
                return response;
            }
            respond_after_leader_visible_write(
                &state,
                "rotated authority was not visible on the leader after write",
                || {
                    let visible_status = load_authority_status(&state.config)?;
                    if visible_status.generation == status.generation
                        && visible_status.public_key == status.public_key
                    {
                        Ok(Some(visible_status))
                    } else {
                        Ok(None)
                    }
                },
            )
        }
        Err(response) => response,
    }
}

async fn handle_issue_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<IssueCapabilityRequest>,
) -> Response {
    if let Err(response) =
        validate_authority_mutation_auth(&headers, &state, ISSUE_CAPABILITY_PATH)
    {
        return response;
    }
    match forward_authority_post_to_leader(&state, ISSUE_CAPABILITY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Err(response) = enforce_authority_mutation_fence(&state) {
        return response;
    }
    let subject = match PublicKey::from_hex(&payload.subject_public_key) {
        Ok(subject) => subject,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(runtime_attestation) = payload.runtime_attestation.as_ref() {
        if let Err(error) = runtime_attestation.validate_workload_identity_binding() {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                &format!("runtime attestation workload identity is invalid: {error}"),
            );
        }
    }
    match load_capability_authority(&state.config) {
        Ok(authority) => {
            match authority.issue_capability_with_attestation(
                &subject,
                payload.scope,
                payload.ttl_seconds,
                payload.runtime_attestation,
            ) {
                Ok(capability) => Json(IssueCapabilityResponse { capability }).into_response(),
                Err(chio_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    plain_http_error(StatusCode::FORBIDDEN, &error)
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

async fn handle_scim_create_user(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserResource>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_scim_post_to_leader(&state, SCIM_USERS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let provider = match validated_scim_provider_for_request(&state.config, &payload) {
        Ok(provider) => provider,
        Err(error) => return scim_error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let (path, mut registry) = match load_scim_lifecycle_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = unix_timestamp_now();
    let mut record = match build_scim_user_record(&provider, payload, now, None) {
        Ok(record) => record,
        Err(error) => return scim_error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    record.scim_user.meta = Some(crate::scim_lifecycle::ScimMeta {
        resource_type: Some("User".to_string()),
        location: Some(scim_user_location(&record.user_id)),
    });
    if let Err(error) = registry.insert(record.clone()) {
        return scim_error_response(StatusCode::CONFLICT, &error.to_string());
    }
    if let Err(error) = registry.save(&path) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    scim_json_response(StatusCode::CREATED, &record.scim_user)
}

async fn handle_scim_delete_user(
    State(state): State<TrustServiceState>,
    AxumPath(user_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_scim_delete_to_leader(&state, &scim_user_location(&user_id)).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (path, mut registry) = match load_scim_lifecycle_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    let Some(record) = registry.get(&user_id).cloned() else {
        return scim_error_response(
            StatusCode::NOT_FOUND,
            &format!("scim user `{user_id}` was not found"),
        );
    };
    if !record.active() {
        return scim_json_response(StatusCode::OK, &record.scim_user);
    }
    let now = unix_timestamp_now();
    let revocation_store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let mut revoked_capability_ids = Vec::new();
    for capability_id in &record.tracked_capability_ids {
        match revocation_store.is_revoked(capability_id) {
            Ok(true) => {}
            Ok(false) => match revocation_store.revoke(capability_id) {
                Ok(_) => revoked_capability_ids.push(capability_id.clone()),
                Err(error) => {
                    return scim_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &error.to_string(),
                    )
                }
            },
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        }
    }
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipt = match build_scim_deprovision_receipt(
        &state.config,
        &record,
        &revoked_capability_ids,
        now,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return scim_error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = receipt_store.append_chio_receipt(&receipt) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let updated =
        match registry.deactivate(&user_id, now, &revoked_capability_ids, Some(&receipt.id)) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return scim_error_response(
                    StatusCode::NOT_FOUND,
                    &format!("scim user `{user_id}` was not found"),
                )
            }
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
    if let Err(error) = registry.save(&path) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    scim_json_response(StatusCode::OK, &updated.scim_user)
}

async fn handle_list_enterprise_providers(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(EnterpriseProviderListResponse {
            configured: true,
            count: registry.providers.len(),
            providers: registry.providers.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.providers.get(&provider_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("enterprise provider `{provider_id}` was not found"),
        ),
    }
}

async fn handle_upsert_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut record): Json<EnterpriseProviderRecord>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    record.provider_id = provider_id.clone();
    registry.upsert(record);
    let Some(saved) = registry.providers.get(&provider_id).cloned() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "enterprise provider upsert did not persist the requested record",
        );
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(saved).into_response()
}

async fn handle_delete_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&provider_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(EnterpriseProviderDeleteResponse {
        provider_id,
        deleted,
    })
    .into_response()
}

async fn handle_list_federation_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_federation_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(FederationAdmissionPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_federation_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&policy_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("federation policy `{policy_id}` was not found"),
        ),
    }
}

async fn handle_upsert_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
    Json(record): Json<FederationAdmissionPolicyRecord>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if record.policy.body.policy_id != policy_id {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "federation policy path id must match the signed policy body policy_id",
        );
    }
    let (path, mut registry) = match load_federation_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = registry.upsert(record.clone()) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let Some(saved) = registry.get(&policy_id).cloned() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "federation policy upsert did not persist the requested record",
        );
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(saved).into_response()
}

async fn handle_delete_federation_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_federation_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&policy_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(FederationAdmissionPolicyDeleteResponse { policy_id, deleted }).into_response()
}

async fn handle_evaluate_federation_policy(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FederationAdmissionEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FEDERATION_POLICY_EVALUATE_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let now = unix_timestamp_now();
    match evaluate_federation_policy_request(&state, &request, now) {
        Ok(response) => Json(response).into_response(),
        Err(error) if error.to_string().contains("was not found") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_list_certifications(
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

async fn handle_get_certification(
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

async fn handle_publish_certification(
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

async fn handle_resolve_certification(
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

async fn handle_public_resolve_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.resolve(&tool_server_id)).into_response()
}

async fn handle_public_certification_metadata(State(state): State<TrustServiceState>) -> Response {
    match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_public_search_certifications(
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

async fn handle_public_certification_transparency(
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

async fn handle_public_generic_namespace(State(state): State<TrustServiceState>) -> Response {
    match build_signed_generic_namespace(&state.config) {
        Ok(namespace) => Json(namespace).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

async fn handle_public_generic_listings(
    State(state): State<TrustServiceState>,
    Query(query): Query<GenericListingQuery>,
) -> Response {
    match build_public_generic_listing_report(&state.config, &query) {
        Ok(report) => Json(report).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

async fn handle_issue_generic_trust_activation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericTrustActivationIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_generic_trust_activation(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_evaluate_generic_trust_activation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericTrustActivationEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match evaluate_generic_trust_activation_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_issue_generic_governance_charter(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCharterIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_generic_governance_charter(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_issue_generic_governance_case(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCaseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_generic_governance_case(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_evaluate_generic_governance_case(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<GenericGovernanceCaseEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match evaluate_generic_governance_case_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_issue_open_market_fee_schedule(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketFeeScheduleIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_open_market_fee_schedule(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_issue_open_market_penalty(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketPenaltyIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match issue_signed_open_market_penalty(&state.config, &request) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_evaluate_open_market_penalty(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<OpenMarketPenaltyEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match evaluate_open_market_penalty_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_passport_issuer_metadata(State(state): State<TrustServiceState>) -> Response {
    match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_public_passport_issuer_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_issuer_discovery(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

async fn handle_public_passport_verifier_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_verifier_discovery(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

async fn handle_public_passport_discovery_transparency(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_discovery_transparency(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

async fn handle_oid4vp_verifier_metadata(State(state): State<TrustServiceState>) -> Response {
    match build_oid4vp_verifier_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_passport_issuer_jwks(State(state): State<TrustServiceState>) -> Response {
    match build_oid4vp_verifier_jwks(&state.config) {
        Ok(jwks) => Json(jwks).into_response(),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("configured authority")
                || message.contains("did not publish any signing keys")
                || message.contains("--authority-seed-file or --authority-db")
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            };
            plain_http_error(status, &message)
        }
    }
}

fn public_discovery_error_response(error: &CliError) -> Response {
    let message = error.to_string();
    let status = if message.contains("configured authority")
        || message.contains("authority signing seed")
        || message.contains("did not publish any signing keys")
        || message.contains("--authority-seed-file or --authority-db")
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::CONFLICT
    };
    plain_http_error(status, &message)
}

async fn handle_passport_sd_jwt_type_metadata(State(state): State<TrustServiceState>) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_chio_passport_sd_jwt_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_passport_jwt_vc_json_type_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_chio_passport_jwt_vc_json_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_create_passport_issuance_offer(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportIssuanceOfferRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_ISSUANCE_OFFERS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if state.config.passport_statuses_file.is_some() {
        if let Err(error) = portable_passport_status_reference_for_service(
            &state.config,
            &payload.passport,
            unix_timestamp_now(),
        ) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    }
    let record = match registry.issue_offer(
        &metadata,
        payload.passport,
        payload.credential_configuration_id.as_deref(),
        payload.ttl_seconds,
        unix_timestamp_now(),
    ) {
        Ok(record) => record,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_redeem_passport_issuance_token(
    State(state): State<TrustServiceState>,
    Json(payload): Json<Oid4vciTokenRequest>,
) -> Response {
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let response =
        match registry.redeem_pre_authorized_code(&metadata, &payload, unix_timestamp_now(), 300) {
            Ok(response) => response,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(response).into_response()
}

async fn handle_redeem_passport_issuance_credential(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<Oid4vciCredentialRequest>,
) -> Response {
    let access_token = match bearer_token_from_headers(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let portable_signing_keypair =
        if state.config.authority_seed_path.is_some() || state.config.authority_db_path.is_some() {
            match resolve_oid4vp_verifier_signing_key(&state.config) {
                Ok(keypair) => Some(keypair),
                Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
            }
        } else {
            None
        };
    let portable_status_registry = match state.config.passport_statuses_file.as_deref() {
        Some(path) => match PassportStatusRegistry::load(path) {
            Ok(registry) => Some(registry),
            Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        },
        None => None,
    };
    let response = match registry.redeem_credential(
        &metadata,
        &access_token,
        &payload,
        unix_timestamp_now(),
        portable_signing_keypair.as_ref(),
        portable_status_registry.as_ref(),
    ) {
        Ok(response) => response,
        Err(error) if error.to_string().contains("access token") => {
            return plain_http_error(StatusCode::UNAUTHORIZED, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(response).into_response()
}

async fn handle_publish_certification_network(
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
    match crate::certify::publish_certification_across_network(
        &network,
        &request.artifact,
        &request.operator_ids,
    ) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_discover_certification(
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
        crate::certify::discover_certifications_across_network(&network, &tool_server_id);
    Json(response).into_response()
}

async fn handle_search_certification_marketplace(
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
    Json(crate::certify::search_public_certifications_across_network(
        &network, &query,
    ))
    .into_response()
}

async fn handle_transparency_certification_marketplace(
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
    Json(crate::certify::transparency_public_certifications_across_network(&network, &query))
        .into_response()
}

async fn handle_consume_certification_marketplace(
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
    Json(crate::certify::consume_public_certification_across_network(
        &network, &request,
    ))
    .into_response()
}

async fn handle_revoke_certification(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

async fn handle_dispute_certification(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

async fn handle_list_passport_statuses(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(PassportStatusListResponse {
            configured: true,
            count: registry.passports.len(),
            passports: registry.passports.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&passport_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("passport `{passport_id}` was not found in the lifecycle registry"),
        ),
    }
}

async fn handle_publish_passport_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(mut request): Json<PublishPassportStatusRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_passport_status_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if request.distribution.resolve_urls.is_empty() {
        request.distribution = default_passport_status_distribution(&state.config);
    }
    let record = match registry.publish(
        &request.passport,
        unix_timestamp_now(),
        request.distribution,
    ) {
        Ok(record) => record,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, unix_timestamp_now());
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_public_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
) -> Response {
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, unix_timestamp_now());
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_revoke_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<PassportStatusRevocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_passport_status_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let record = match registry.revoke(&passport_id, request.reason.as_deref(), request.revoked_at)
    {
        Ok(record) => record,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_list_verifier_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(VerifierPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.policies.get(&policy_id) {
        Some(document) => Json(document.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("verifier policy `{policy_id}` was not found"),
        ),
    }
}

async fn handle_upsert_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut document): Json<SignedPassportVerifierPolicy>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    document.body.policy_id = policy_id.clone();
    if let Err(error) = verify_signed_passport_verifier_policy(&document) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) = registry.upsert(document.clone()) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(document).into_response()
}

async fn handle_delete_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&policy_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(VerifierPolicyDeleteResponse { policy_id, deleted }).into_response()
}

async fn handle_create_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportChallengeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGES_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if payload.policy_id.is_some() && payload.policy.is_some() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "challenge creation accepts either policy_id or policy, not both",
        );
    }
    let now = unix_timestamp_now();
    let (policy_ref, policy) = if let Some(policy_id) = payload.policy_id.as_deref() {
        let Some(registry) = state.verifier_policy_registry() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "trust service is missing --verifier-policies-file for policy references",
            );
        };
        let document = match registry.active_policy(policy_id, now) {
            Ok(document) => document,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        if document.body.verifier != payload.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "stored verifier policy verifier must match the requested challenge verifier",
            );
        }
        (
            Some(PassportVerifierPolicyReference {
                policy_id: document.body.policy_id.clone(),
            }),
            None,
        )
    } else {
        (None, payload.policy.clone())
    };
    let challenge = match create_passport_presentation_challenge_with_reference(
        chio_credentials::PassportPresentationChallengeArgs {
            verifier: payload.verifier,
            challenge_id: Some(Keypair::generate().public_key().to_hex()),
            nonce: Keypair::generate().public_key().to_hex(),
            issued_at: now,
            expires_at: now.saturating_add(payload.ttl_seconds),
            options: chio_credentials::PassportPresentationOptions {
                issuer_allowlist: payload.issuers.into_iter().collect::<BTreeSet<_>>(),
                max_credentials: payload.max_credentials,
            },
            policy_ref,
            policy,
        },
    ) {
        Ok(challenge) => challenge,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&challenge) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let transport = match passport_presentation_transport_for_service(&state.config, &challenge) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(CreatePassportChallengeResponse {
        challenge,
        transport,
    })
    .into_response()
}

fn verify_passport_challenge_payload(
    state: &TrustServiceState,
    payload: &VerifyPassportChallengeRequest,
    expected_challenge: Option<&PassportPresentationChallenge>,
    consume: bool,
) -> Result<PassportPresentationVerification, Response> {
    if let Err(error) = configured_verifier_challenge_db_path(&state.config) {
        return Err(plain_http_error(StatusCode::CONFLICT, &error.to_string()));
    }
    let now = unix_timestamp_now();
    let challenge = expected_challenge.unwrap_or(&payload.presentation.challenge);
    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => {
            return Err(plain_http_error(
                StatusCode::BAD_REQUEST,
                &error.to_string(),
            ))
        }
    };
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        ));
    }
    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        expected_challenge,
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    }
    if consume {
        match consume_challenge_if_configured(&state.config, challenge, now) {
            Ok(replay_state) => verification.replay_state = replay_state,
            Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
        }
    }
    Ok(verification)
}

async fn handle_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGE_VERIFY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    match verify_passport_challenge_payload(
        &state,
        &payload,
        payload.expected_challenge.as_ref(),
        true,
    ) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

async fn handle_public_get_passport_challenge(
    State(state): State<TrustServiceState>,
    AxumPath(challenge_id): AxumPath<String>,
) -> Response {
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match store.fetch_active(&challenge_id, unix_timestamp_now()) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(error) if error.to_string().contains("not registered") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_public_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    match forward_post_to_leader(&state, PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let challenge_id = match payload
        .presentation
        .challenge
        .challenge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(challenge_id) => challenge_id.to_string(),
        None => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "public holder submission requires a non-empty challenge_id",
            )
        }
    };
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let stored_challenge = match store.fetch_active(&challenge_id, unix_timestamp_now()) {
        Ok(challenge) => challenge,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(expected_challenge) = payload.expected_challenge.as_ref() {
        if canonical_json_bytes(expected_challenge).ok()
            != canonical_json_bytes(&stored_challenge).ok()
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "provided expected challenge does not match the stored verifier challenge",
            );
        }
    }
    match verify_passport_challenge_payload(&state, &payload, Some(&stored_challenge), true) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

async fn handle_create_oid4vp_request(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOid4vpRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_OID4VP_REQUESTS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = unix_timestamp_now();
    let request = match build_oid4vp_request_for_service(&state.config, &payload, now) {
        Ok(request) => request,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let signing_key = match resolve_oid4vp_verifier_signing_key(&state.config) {
        Ok(keypair) => keypair,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut transport = match build_oid4vp_request_transport(&request, &signing_key) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    transport.same_device_url = oid4vp_same_device_url(&request.request_uri);
    transport.cross_device_url =
        match oid4vp_cross_device_url(&state.config, &request.jti, &request.request_uri) {
            Ok(url) => url,
            Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&request, &transport.request_jwt) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let wallet_exchange = match build_oid4vp_wallet_exchange_response(
        &state.config,
        &request,
        &transport.request_jwt,
        WalletExchangeTransactionState::issued(
            &request.jti,
            &request.jti,
            request.iat,
            request.exp,
        ),
        &transport.same_device_url,
        &transport.cross_device_url,
    ) {
        Ok(wallet_exchange) => wallet_exchange,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(CreateOid4vpRequestResponse {
        request,
        transport,
        wallet_exchange,
    })
    .into_response()
}

async fn handle_public_get_wallet_exchange(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let snapshot = match store.snapshot(&request_id, unix_timestamp_now()) {
        Ok(snapshot) => snapshot,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let same_device_url = oid4vp_same_device_url(&snapshot.request.request_uri);
    let cross_device_url = match oid4vp_cross_device_url(
        &state.config,
        &snapshot.request.jti,
        &snapshot.request.request_uri,
    ) {
        Ok(url) => url,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match build_oid4vp_wallet_exchange_response(
        &state.config,
        &snapshot.request,
        &snapshot.request_jwt,
        snapshot.transaction,
        &same_device_url,
        &cross_device_url,
    ) {
        Ok(response) => Json::<WalletExchangeStatusResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_public_get_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, request_jwt) = match store.fetch_active(&request_id, unix_timestamp_now()) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let trusted_public_keys = match resolve_oid4vp_verifier_trusted_public_keys(&state.config) {
        Ok(keys) => keys,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = verify_signed_oid4vp_request_object_with_any_key(
        &request_jwt,
        &trusted_public_keys,
        unix_timestamp_now(),
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    if request.jti != request_id {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored OID4VP request payload did not match its request_id",
        );
    }
    let mut response = request_jwt.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    response
}

async fn handle_public_launch_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, _) = match store.fetch_active(&request_id, unix_timestamp_now()) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    Redirect::temporary(&oid4vp_same_device_url(&request.request_uri)).into_response()
}

async fn handle_public_submit_oid4vp_response(
    State(state): State<TrustServiceState>,
    Form(payload): Form<Oid4vpDirectPostForm>,
) -> Response {
    let unverified_response = match inspect_oid4vp_direct_post_response(&payload.response) {
        Ok(response) => response,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let request_id = unverified_response.presentation_submission.id.clone();
    if request_id.trim().is_empty() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "OID4VP direct-post response requires a non-empty presentation_submission.id",
        );
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = unix_timestamp_now();
    let (request, request_jwt) = match store.fetch_active(&request_id, now) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let credential = match inspect_chio_passport_sd_jwt_vc_unverified(&unverified_response.vp_token)
    {
        Ok(credential) => credential,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let issuer_public_keys =
        match resolve_portable_issuer_public_keys(&state.config, &credential.issuer) {
            Ok(keys) => keys,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
    let mut verification = match verify_oid4vp_direct_post_response_with_any_issuer_key(
        &payload.response,
        &request,
        &issuer_public_keys,
        now,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    let lifecycle = match resolve_oid4vp_passport_lifecycle(
        &state.config,
        &verification.passport_id,
        verification.passport_status.as_ref(),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(lifecycle) = lifecycle.as_ref() {
        if lifecycle.state != PassportLifecycleState::Active {
            return plain_http_error(StatusCode::FORBIDDEN, &passport_lifecycle_reason(lifecycle));
        }
    }
    if let Err(error) = store.consume(&request, &request_jwt, now) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    verification.exchange_transaction = Some(WalletExchangeTransactionState::consumed(
        &request.jti,
        &request.jti,
        request.iat,
        request.exp,
        now,
    ));
    verification.identity_assertion = request.identity_assertion.clone();
    Json(verification).into_response()
}

async fn handle_federated_issue(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<FederatedIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FEDERATED_ISSUE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Some(advertise_url) = state.config.advertise_url.as_deref() {
        if payload.expected_challenge.verifier != advertise_url {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "expected challenge verifier must match the trust-control service advertise URL",
            );
        }
    }
    let now = unix_timestamp_now();
    if let Some(policy) = payload.delegation_policy.as_ref() {
        if let Err(error) = verify_federated_delegation_policy(policy)
            .and_then(|_| ensure_federated_delegation_policy_active(policy, now))
        {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        if policy.body.verifier != payload.expected_challenge.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "federated delegation policy verifier must match the expected passport challenge verifier",
            );
        }
        if let Some(advertise_url) = state.config.advertise_url.as_deref() {
            if policy.body.verifier != advertise_url {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "federated delegation policy verifier must match the trust-control service advertise URL",
                );
            }
        }
        if let Err(error) =
            ensure_requested_capability_within_delegation_policy(&payload.capability, policy, now)
        {
            return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
        }
    }
    if let Some(upstream_capability_id) = payload.upstream_capability_id.as_deref() {
        match payload
            .delegation_policy
            .as_ref()
            .and_then(|policy| policy.body.parent_capability_id.as_deref())
        {
            Some(parent_capability_id) if parent_capability_id == upstream_capability_id => {}
            _ => {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "multi-hop federated issuance requires a delegation policy bound to the exact upstream capability id",
                );
            }
        }
    } else if payload
        .delegation_policy
        .as_ref()
        .and_then(|policy| policy.body.parent_capability_id.as_deref())
        .is_some()
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "delegation policy parent_capability_id requires --upstream-capability-id on the issuance request",
        );
    }

    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        &payload.expected_challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if resolved_policy.is_none() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "federated issuance requires an embedded or stored verifier policy",
        );
    }
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        );
    }

    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        Some(&payload.expected_challenge),
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    match consume_challenge_if_configured(&state.config, &payload.expected_challenge, now) {
        Ok(replay_state) => verification.replay_state = replay_state,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    if !verification.accepted {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "passport presentation did not satisfy the verifier policy",
        );
    }
    let subject_did = match DidChio::from_str(&verification.subject) {
        Ok(subject_did) => subject_did,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let subject_public_key = subject_did.public_key();
    let subject_public_key_hex = subject_public_key.to_hex();
    let mut enterprise_audit = None;
    let mut scim_lifecycle_record = None;
    if let Some(identity) = payload.enterprise_identity.as_ref() {
        let validated_provider = identity
            .provider_record_id
            .as_deref()
            .and_then(|provider_id| state.validated_enterprise_provider(provider_id));
        let lane_active = identity.provider_record_id.is_some();
        let mut audit =
            build_enterprise_admission_audit(identity, &subject_public_key_hex, validated_provider);
        if identity.provider_id.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing provider_id".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires provider_id",
                &audit,
            );
        }
        if identity.principal.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing principal".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires principal",
                &audit,
            );
        }
        if identity.subject_key.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing subject_key".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires subject_key",
                &audit,
            );
        }
        if lane_active {
            let Some(provider) = validated_provider else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but provider_record_id is not validated"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires a validated provider record",
                    &audit,
                );
            };
            let Some(policy) = payload.admission_policy.as_ref() else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but no admission policy was provided"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires an admission policy with enterprise origin rules",
                    &audit,
                );
            };
            let Some(profile_id) = chio_policy::selected_origin_profile_id(
                policy,
                &enterprise_origin_context(identity),
            ) else {
                audit.decision_reason = Some(
                    "enterprise identity did not match any configured enterprise origin profile"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise identity did not satisfy any configured origin profile",
                    &audit,
                );
            };
            audit.matched_origin_profile = Some(profile_id);
            if matches!(provider.kind, EnterpriseProviderKind::Scim) {
                match resolve_scim_lifecycle_record_for_federated_issue(
                    &state.config,
                    provider,
                    identity,
                ) {
                    Ok(Some(record)) => {
                        scim_lifecycle_record = Some(record);
                        audit.decision_reason = Some(
                            "enterprise-provider lane matched the configured enterprise origin profile and active scim lifecycle identity"
                                .to_string(),
                        );
                    }
                    Ok(None) => {
                        audit.decision_reason = Some(
                            "enterprise-provider lane matched the configured enterprise origin profile"
                                .to_string(),
                        );
                    }
                    Err(error) => {
                        audit.decision_reason = Some(error.to_string());
                        return enterprise_admission_response(
                            StatusCode::FORBIDDEN,
                            &error.to_string(),
                            &audit,
                        );
                    }
                }
            } else {
                audit.decision_reason = Some(
                    "enterprise-provider lane matched the configured enterprise origin profile"
                        .to_string(),
                );
            }
        } else {
            audit.decision_reason = Some(
                "enterprise observability is present but no validated provider-admin record activated the enterprise-provider lane"
                    .to_string(),
            );
        }
        enterprise_audit = Some(audit);
    }
    let mut store =
        if payload.delegation_policy.is_some() || payload.upstream_capability_id.is_some() {
            match open_receipt_store(&state.config) {
                Ok(store) => Some(store),
                Err(response) => return response,
            }
        } else {
            None
        };
    let upstream_parent = if let Some(upstream_capability_id) =
        payload.upstream_capability_id.as_deref()
    {
        let Some(store) = store.as_ref() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "multi-hop federated issuance requires --receipt-db so imported upstream evidence can be resolved",
            );
        };
        match store.get_federated_share_for_capability(upstream_capability_id) {
            Ok(Some((share, snapshot))) => {
                if let Some(policy) = payload.delegation_policy.as_ref() {
                    if share.signer_public_key != policy.body.signer_public_key.to_hex() {
                        return plain_http_error(
                            StatusCode::FORBIDDEN,
                            "delegation policy signer must match the signer that shared the imported upstream evidence package",
                        );
                    }
                }
                if let Err(error) = ensure_requested_capability_within_parent_snapshot(
                    &payload.capability,
                    &snapshot,
                    now,
                ) {
                    return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
                }
                Some((share.share_id, snapshot))
            }
            Ok(None) => {
                return plain_http_error(
                    StatusCode::NOT_FOUND,
                    "imported upstream capability was not found in the local federated evidence-share index",
                );
            }
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    } else {
        None
    };
    match load_capability_authority(&state.config) {
        Ok(authority) => {
            if let Some(policy) = payload.delegation_policy.as_ref() {
                if !authority
                    .trusted_public_keys()
                    .iter()
                    .any(|key| key == &policy.body.signer_public_key)
                {
                    return plain_http_error(
                        StatusCode::FORBIDDEN,
                        "federated delegation policy signer is not trusted by the local capability authority",
                    );
                }
            }
            match authority.issue_capability(
                subject_public_key,
                payload.capability.scope.clone(),
                payload.capability.ttl,
            ) {
                Ok(capability) => {
                    if let Some(record) = scim_lifecycle_record.as_ref() {
                        if let Err(error) = bind_scim_capability_to_identity(
                            &state.config,
                            &record.provider_id,
                            &record.enterprise_identity.subject_key,
                            &capability.id,
                            now,
                        ) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                    }
                    let mut delegation_anchor_capability_id = None;
                    if let Some(policy) = payload.delegation_policy.as_ref() {
                        let Some(store) = store.as_mut() else {
                            return plain_http_error(
                                StatusCode::CONFLICT,
                                "federated delegation issuance requires --receipt-db so the lineage anchor can be persisted",
                            );
                        };
                        let anchor_snapshot = match build_federated_delegation_anchor_snapshot(
                            policy,
                            &subject_public_key_hex,
                            &payload.expected_challenge,
                            now,
                            upstream_parent.as_ref().map(|(_, snapshot)| snapshot),
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                )
                            }
                        };
                        let child_snapshot = match build_capability_snapshot(
                            &capability,
                            anchor_snapshot.delegation_depth.saturating_add(1),
                            Some(anchor_snapshot.capability_id.clone()),
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                )
                            }
                        };
                        if let Err(error) = store.upsert_capability_snapshot(&anchor_snapshot) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                        if let Some((share_id, parent_snapshot)) = upstream_parent.as_ref() {
                            if let Err(error) = store.record_federated_lineage_bridge(
                                &anchor_snapshot.capability_id,
                                &parent_snapshot.capability_id,
                                Some(share_id.as_str()),
                            ) {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                );
                            }
                        }
                        if let Err(error) = store.upsert_capability_snapshot(&child_snapshot) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                        delegation_anchor_capability_id = Some(anchor_snapshot.capability_id);
                    }
                    Json(FederatedIssueResponse {
                        subject: verification.subject.clone(),
                        subject_public_key: subject_public_key_hex,
                        verification,
                        capability,
                        enterprise_identity_provenance: payload
                            .enterprise_identity
                            .as_ref()
                            .map(EnterpriseIdentityProvenance::from),
                        enterprise_audit,
                        delegation_anchor_capability_id,
                    })
                    .into_response()
                }
                Err(chio_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    if let Some(audit) = enterprise_audit.as_ref() {
                        enterprise_admission_response(StatusCode::FORBIDDEN, &error, audit)
                    } else {
                        plain_http_error(StatusCode::FORBIDDEN, &error)
                    }
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

async fn handle_list_revocations(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let revocations =
        match store.list_revocations(list_limit(query.limit), query.capability_id.as_deref()) {
            Ok(revocations) => revocations,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
    let revoked = query
        .capability_id
        .as_deref()
        .map(|capability_id| store.is_revoked(capability_id))
        .transpose();
    let revoked = match revoked {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(revocation_list_response(
        query.capability_id,
        revoked,
        revocations,
    ))
    .into_response()
}

async fn handle_revoke_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, REVOCATIONS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.revoke(&payload.capability_id) {
        Ok(newly_revoked) => respond_after_leader_visible_write(
            &state,
            "revocation was not visible on the leader after write",
            || {
                let revoked = store.is_revoked(&payload.capability_id).map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
                if revoked {
                    Ok(Some(RevokeCapabilityResponse {
                        capability_id: payload.capability_id.clone(),
                        revoked: true,
                        newly_revoked,
                    }))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_list_tool_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_tool_receipts(
        list_limit(query.limit),
        query.capability_id.as_deref(),
        query.tool_server.as_deref(),
        query.tool_name.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "tool".to_string(),
        count: receipts.len(),
        filters: json!({
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        }),
        receipts,
    })
    .into_response()
}

async fn handle_append_tool_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ChioReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, TOOL_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_chio_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "tool receipt was not visible on the leader after write",
            || {
                let receipts = store
                    .list_tool_receipts(
                        MAX_LIST_LIMIT,
                        Some(&receipt.capability_id),
                        Some(&receipt.tool_server),
                        Some(&receipt.tool_name),
                        Some(decision_kind(&receipt.decision)),
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

async fn handle_list_child_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_child_receipts(
        list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "child".to_string(),
        count: receipts.len(),
        filters: json!({
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        }),
        receipts,
    })
    .into_response()
}

async fn handle_query_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptQueryHttpQuery>,
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
        capability_id: query.capability_id.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        outcome: query.outcome.clone(),
        since: query.since,
        until: query.until,
        min_cost: query.min_cost,
        max_cost: query.max_cost,
        cursor: query.cursor,
        limit: list_limit(query.limit),
        agent_subject: query.agent_subject.clone(),
        // Phase 1.5: tenant_filter must be derived from the operator's
        // authenticated tenant claim, not a query parameter. Left None
        // here pending the auth-context plumb-through; strict-isolation
        // mode at the store level guards against leakage during rollout.
        tenant_filter: None,
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}
