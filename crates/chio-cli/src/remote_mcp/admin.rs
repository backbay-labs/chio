use super::*;
use subtle::ConstantTimeEq;

pub(super) fn install_admin_routes(router: Router<RemoteAppState>) -> Router<RemoteAppState> {
    router
        .route(ADMIN_HEALTH_PATH, get(handle_admin_health))
        .route(
            ADMIN_AUTHORITY_PATH,
            get(handle_admin_authority).post(handle_admin_rotate_authority),
        )
        .route(ADMIN_TOOL_RECEIPTS_PATH, get(handle_admin_tool_receipts))
        .route(ADMIN_CHILD_RECEIPTS_PATH, get(handle_admin_child_receipts))
        .route(ADMIN_BUDGETS_PATH, get(handle_admin_budgets))
        .route(
            ADMIN_REVOCATIONS_PATH,
            get(handle_admin_revocations).post(handle_admin_revoke_capability),
        )
        .route(
            ADMIN_SESSION_TRUST_PATH,
            get(handle_admin_session_trust).post(handle_admin_revoke_session_trust),
        )
        .route(ADMIN_SESSIONS_PATH, get(handle_admin_sessions))
        .route(ADMIN_SESSION_DRAIN_PATH, post(handle_admin_session_drain))
        .route(
            ADMIN_SESSION_SHUTDOWN_PATH,
            post(handle_admin_session_shutdown),
        )
}

async fn handle_admin_authority(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    match load_authority_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

async fn handle_admin_health(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    state.sessions.cleanup_due_sessions().await;
    let (active, terminal) = state.sessions.snapshot().await;
    let authority = match load_authority_status(&state) {
        Ok(status) => status,
        Err(response) => return response,
    };

    let enterprise_provider_summary = state
        .enterprise_provider_registry
        .as_deref()
        .map(|registry| {
            let validated_count = registry
                .providers
                .values()
                .filter(|record| record.is_validated_enabled())
                .count();
            let invalid_count = registry
                .providers
                .values()
                .filter(|record| !record.validation_errors.is_empty())
                .count();
            json!({
                "configured": true,
                "count": registry.providers.len(),
                "validatedCount": validated_count,
                "invalidCount": invalid_count,
            })
        })
        .unwrap_or_else(|| {
            json!({
                "configured": false,
                "count": 0,
                "validatedCount": 0,
                "invalidCount": 0,
            })
        });
    let shared_hosted_owner_stats =
        state
            .factory
            .shared_upstream_owner
            .lock()
            .ok()
            .and_then(|owner| {
                owner
                    .as_ref()
                    .map(|owner| owner.notification_stats_snapshot())
            });

    Json(json!({
        "ok": true,
        "server": {
            "serverId": &state.factory.config.server_id,
            "serverName": &state.factory.config.server_name,
            "serverVersion": &state.factory.config.server_version,
            "sharedHostedOwner": state.factory.config.shared_hosted_owner,
            "sharedHostedOwnerStats": shared_hosted_owner_stats,
        },
        "auth": {
            "mode": remote_auth_mode_label(&state.auth_mode),
            "scopes": &state.factory.config.auth_scopes,
            "issuerConfigured": state.factory.config.auth_jwt_issuer.is_some(),
            "audienceConfigured": state.factory.config.auth_jwt_audience.is_some(),
            "adminTokenConfigured": state.admin_token.is_some(),
        },
        "controlPlane": {
            "proxied": state.factory.config.control_url.is_some(),
            "controlUrl": &state.factory.config.control_url,
            "controlTokenConfigured": state.factory.config.control_token.is_some(),
        },
        "stores": {
            "receiptsConfigured": state.factory.config.receipt_db_path.is_some(),
            "revocationsConfigured": state.factory.config.revocation_db_path.is_some(),
            "authorityDbConfigured": state.factory.config.authority_db_path.is_some(),
            "authoritySeedConfigured": state.factory.config.authority_seed_path.is_some(),
            "budgetsConfigured": state.factory.config.budget_db_path.is_some(),
            "sessionTombstonesConfigured": state.factory.config.session_db_path.is_some(),
        },
        "sessions": {
            "activeCount": active.len(),
            "terminalCount": terminal.len(),
            "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
            "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
            "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
            "tombstoneRetentionMillis": state.factory.lifecycle_policy.tombstone_retention_millis,
        },
        "authority": authority,
        "federation": {
            "identityFederationConfigured": state.factory.config.identity_federation_seed_path.is_some(),
            "enterpriseProviders": enterprise_provider_summary,
        },
        "oauth": {
            "protectedResourceMetadata": state.protected_resource_metadata.is_some(),
            "authorizationServerMetadata": state.authorization_server_metadata.is_some(),
            "localAuthorizationServer": state.local_auth_server.is_some(),
        },
    }))
    .into_response()
}

async fn handle_admin_rotate_authority(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.rotate_authority() {
            Ok(status) => Json(json!({
                "configured": status.configured,
                "backend": status.backend,
                "rotated": true,
                "publicKey": status.public_key,
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
                "trustedPublicKeys": status.trusted_public_keys,
            }))
            .into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        return match chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
        {
            Ok(status) => Json(json!({
                "configured": true,
                "backend": "sqlite",
                "rotated": true,
                "publicKey": status.public_key.to_hex(),
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": true,
                "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
            }))
            .into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "remote authority admin requires --authority-seed-file or --authority-db",
        );
    };

    match rotate_authority_keypair(path) {
        Ok(public_key) => Json(json!({
            "configured": true,
            "backend": "seed_file",
            "rotated": true,
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_admin_tool_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_tool_receipts(&ToolReceiptQuery {
            capability_id: query.capability_id.clone(),
            tool_server: query.tool_server.clone(),
            tool_name: query.tool_name.clone(),
            decision: query.decision.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_tool_receipts(
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
        query.tool_server.as_deref(),
        query.tool_name.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "tool",
        "count": receipts.len(),
        "filters": {
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_child_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_child_receipts(&ChildReceiptQuery {
            session_id: query.session_id.clone(),
            parent_request_id: query.parent_request_id.clone(),
            request_id: query.request_id.clone(),
            operation_kind: query.operation_kind.clone(),
            terminal_state: query.terminal_state.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_child_receipts(
        admin_list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "child",
        "count": receipts.len(),
        "filters": {
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_budgets(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminBudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_budgets(&trust_control::BudgetQuery {
            capability_id: query.capability_id.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    let store = match open_budget_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match chio_kernel::BudgetStore::list_usages(
        &store,
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
    ) {
        Ok(usages) => usages,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": query.capability_id,
        "count": usages.len(),
        "usages": usages.into_iter().map(|usage| json!({
            "capabilityId": usage.capability_id,
            "grantIndex": usage.grant_index,
            "invocationCount": usage.invocation_count,
            "updatedAt": usage.updated_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_revocations(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminRevocationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_revocations(&RevocationQuery {
            capability_id: query.capability_id.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let revocations = match store.list_revocations(
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
    ) {
        Ok(revocations) => revocations,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let revoked = query
        .capability_id
        .as_deref()
        .map(|capability_id| store.is_revoked(capability_id))
        .transpose()
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()));
    let revoked = match revoked {
        Ok(revoked) => revoked,
        Err(response) => return response,
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": query.capability_id,
        "revoked": revoked,
        "count": revocations.len(),
        "revocations": revocations.iter().map(|entry| {
            json!({
                "capabilityId": entry.capability_id,
                "revokedAt": entry.revoked_at,
            })
        }).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_revoke_capability(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRevokeCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.revoke_capability(&payload.capability_id) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let newly_revoked = match store.revoke(&payload.capability_id) {
        Ok(revoked) => revoked,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "capabilityId": payload.capability_id,
        "revoked": true,
        "newlyRevoked": newly_revoked,
    }))
    .into_response()
}

async fn handle_admin_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let (record, statuses) = match entry {
        RemoteSessionEntry::Active(session) => {
            let record = session.diagnostic_record();
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            (record, statuses)
        }
        RemoteSessionEntry::Terminal(record) => {
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            ((*record).clone(), statuses)
        }
    };

    Json(json!({
        "sessionId": session_id,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": statuses,
    }))
    .into_response()
}

async fn handle_admin_revoke_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => session.diagnostic_record(),
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    let mut newly_revoked_count = 0usize;
    for capability in &record.capabilities {
        let newly_revoked = if let Some(client) = match control_client(&state) {
            Ok(client) => client,
            Err(response) => return response,
        } {
            client
                .revoke_capability(&capability.id)
                .map(|response| response.newly_revoked)
                .unwrap_or(false)
        } else {
            let store = match open_revocation_store(&state) {
                Ok(store) => store,
                Err(response) => return response,
            };
            store.revoke(&capability.id).unwrap_or(false)
        };
        if newly_revoked {
            newly_revoked_count += 1;
        }
    }

    let statuses = match load_session_revocation_status(&state, &record.capabilities) {
        Ok(statuses) => statuses,
        Err(response) => return response,
    };

    Json(json!({
        "sessionId": session_id,
        "revoked": true,
        "newlyRevokedCount": newly_revoked_count,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": statuses,
    }))
    .into_response()
}

async fn handle_admin_sessions(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    state.sessions.cleanup_due_sessions().await;
    let (active, terminal) = state.sessions.snapshot().await;
    Json(json!({
        "configured": true,
        "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
        "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
        "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
        "activeCount": active.len(),
        "terminalCount": terminal.len(),
        "activeSessions": active.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
        "terminalSessions": terminal.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_session_drain(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            if let Err(error) = state.sessions.mark_draining(&session).await {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "failed to drain MCP session without resumable-state risk"
                );
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to drain MCP session safely",
                );
            }
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "draining": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

async fn handle_admin_session_shutdown(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            if let Err(error) = state.sessions.mark_closed(&session).await {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "failed to shut down MCP session without resumable-state risk"
                );
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to shut down MCP session safely",
                );
            }
            state.sessions.remove_active(&session_id).await;
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "shutdown": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

fn validate_admin_auth(headers: &HeaderMap, admin_token: Option<&str>) -> Result<(), Response> {
    let Some(expected_token) = admin_token else {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "remote admin API is disabled",
        ));
    };
    let token = extract_bearer_token(headers, None)?;
    if token.as_bytes().ct_eq(expected_token.as_bytes()).into() {
        Ok(())
    } else {
        Err(unauthorized_bearer_response(
            "missing or invalid admin bearer token",
            None,
        ))
    }
}

fn admin_list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_ADMIN_LIST_LIMIT)
        .clamp(1, MAX_ADMIN_LIST_LIMIT)
}

fn control_client(
    state: &RemoteAppState,
) -> Result<Option<trust_control::TrustControlClient>, Response> {
    let Some(url) = state.factory.config.control_url.as_deref() else {
        return Ok(None);
    };
    let Some(token) = state.factory.config.control_token.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote trust admin requires --control-token when --control-url is configured",
        ));
    };
    trust_control::build_client(url, token)
        .map(Some)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_receipt_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteReceiptStore, Response> {
    let Some(path) = state.factory.config.receipt_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote receipt admin requires --receipt-db",
        ));
    };
    chio_store_sqlite::SqliteReceiptStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_revocation_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteRevocationStore, Response> {
    let Some(path) = state.factory.config.revocation_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote trust admin requires --revocation-db",
        ));
    };
    chio_store_sqlite::SqliteRevocationStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_budget_store(
    state: &RemoteAppState,
) -> Result<chio_store_sqlite::SqliteBudgetStore, Response> {
    let Some(path) = state.factory.config.budget_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote budget admin requires --budget-db",
        ));
    };
    chio_store_sqlite::SqliteBudgetStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn load_authority_status(state: &RemoteAppState) -> Result<Value, Response> {
    if let Some(client) = control_client(state)? {
        let status = client.authority_status().map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        return Ok(json!({
            "configured": status.configured,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedPublicKeys": status.trusted_public_keys,
        }));
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        let status = chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(json!({
            "configured": true,
            "backend": "sqlite",
            "publicKey": status.public_key.to_hex(),
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
        }));
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return Ok(json!({
            "configured": false,
            "backend": Value::Null,
            "publicKey": Value::Null,
            "appliesToFutureSessionsOnly": true,
        }));
    };

    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        })),
        Ok(None) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": Value::Null,
            "materialized": false,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": Vec::<String>::new(),
        })),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn load_session_revocation_status(
    state: &RemoteAppState,
    capabilities: &[RemoteSessionCapability],
) -> Result<Vec<Value>, Response> {
    if let Some(client) = control_client(state)? {
        return capabilities
            .iter()
            .map(|capability| {
                client
                    .list_revocations(&RevocationQuery {
                        capability_id: Some(capability.id.clone()),
                        limit: Some(1),
                    })
                    .map(|response| {
                        json!({
                            "capabilityId": capability.id,
                            "issuerPublicKey": capability.issuer_public_key,
                            "subjectPublicKey": capability.subject_public_key,
                            "revoked": response.revoked.unwrap_or(false),
                        })
                    })
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })
            })
            .collect();
    }

    let store = open_revocation_store(state)?;
    capabilities
        .iter()
        .map(|capability| {
            store
                .is_revoked(&capability.id)
                .map(|revoked| {
                    json!({
                        "capabilityId": capability.id,
                        "issuerPublicKey": capability.issuer_public_key,
                        "subjectPublicKey": capability.subject_public_key,
                        "revoked": revoked,
                    })
                })
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })
        })
        .collect()
}
