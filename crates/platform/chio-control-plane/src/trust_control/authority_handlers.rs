//! HTTP handlers for the capability-authority admin surface: authority status
//! and rotation, capability issuance and revocation, SCIM user lifecycle,
//! enterprise-provider records, and federation admission policies.

use super::cluster::respond_after_leader_visible_write;
use super::report_rendering::{
    forward_authority_post_to_leader, forward_post_to_leader, forward_scim_delete_to_leader,
    forward_scim_post_to_leader,
};
use super::report_validation::{
    enforce_authority_mutation_fence, load_authority_status, load_capability_authority,
    refresh_authority_mutation_fence, rotate_authority, validate_authority_mutation_auth,
    validate_service_auth,
};
use super::*;

pub(crate) async fn handle_authority_status(
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

pub(crate) async fn handle_rotate_authority(
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

pub(crate) async fn handle_issue_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<IssueCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_authority_mutation_auth(&headers, &state, ISSUE_CAPABILITY_PATH)
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

pub(crate) async fn handle_scim_create_user(
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

pub(crate) async fn handle_scim_delete_user(
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
                    );
                }
            },
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
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
                );
            }
            Err(error) => {
                return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
    if let Err(error) = registry.save(&path) {
        return scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    scim_json_response(StatusCode::OK, &updated.scim_user)
}

pub(crate) async fn handle_list_enterprise_providers(
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

pub(crate) async fn handle_get_enterprise_provider(
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

pub(crate) async fn handle_upsert_enterprise_provider(
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

pub(crate) async fn handle_delete_enterprise_provider(
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

pub(crate) async fn handle_list_federation_policies(
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

pub(crate) async fn handle_get_federation_policy(
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

pub(crate) async fn handle_upsert_federation_policy(
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

pub(crate) async fn handle_delete_federation_policy(
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

pub(crate) async fn handle_evaluate_federation_policy(
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
    match service_runtime::issuance::evaluate_federation_policy_request(&state, &request, now) {
        Ok(response) => Json(response).into_response(),
        Err(error) if error.to_string().contains("was not found") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

pub(crate) async fn handle_list_revocations(
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
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(revocation_list_response(
        query.capability_id,
        revoked,
        revocations,
    ))
    .into_response()
}

pub(crate) async fn handle_revoke_capability(
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
        Ok(newly_revoked) => {
            if newly_revoked {
                // A locally originated capability revoke: the revoke instant is
                // now, so the propagation lag is ~0. Emit so the
                // capability-revocation SLO reflects real capability revokes.
                let revoked_now = i64::try_from(unix_timestamp_now()).unwrap_or(0);
                super::cluster::observe_capability_revocation_lag(revoked_now);
            }
            respond_after_leader_visible_write(
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
            )
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
