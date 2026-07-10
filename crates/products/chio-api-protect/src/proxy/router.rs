use super::*;

pub(crate) fn build_app(state: Arc<ProxyState>) -> Router {
    let approval_routes = Router::new()
        .route("/approvals/pending", get(list_pending_approvals_handler))
        .route("/approvals/submit", post(submit_approval_handler))
        .route(
            "/approvals/batch/respond",
            post(batch_respond_approvals_handler),
        )
        .route(
            "/approvals/{id}/operator-respond",
            post(operator_respond_approval_handler),
        )
        .route("/approvals/{id}/respond", post(respond_approval_handler))
        .route("/approvals/{id}", get(get_approval_handler))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_sidecar_control_middleware,
        ));

    Router::new()
        .route("/chio/evaluate", post(sidecar_evaluate_handler))
        .route("/chio/verify", post(sidecar_verify_handler))
        .route("/chio/health", get(sidecar_health_handler))
        .merge(approval_routes)
        .route("/v1/capabilities/mint", post(sidecar_mint_handler))
        // Path alias for `chio-sdk-python`'s `ChioClient.create_capability`,
        // which posts to `/v1/capabilities`. Accepts both the canonical
        // mint body shape (`scopes: [strings]`, `job_uid`) and the SDK's
        // shape (`scope: ChioScope`-object) so the SDK works without a
        // concurrent release.
        .route("/v1/capabilities", post(sidecar_capabilities_alias_handler))
        .route("/v1/capabilities/release", post(sidecar_release_handler))
        // Capability validation route the SDK calls. Validate verifies the
        // embedded Ed25519 signature and checks the local revocation set and
        // `expires_at`. Attenuation is a fail-closed boundary because the
        // sidecar must not hold the parent subject's private key.
        .route(
            "/v1/capabilities/validate",
            post(sidecar_validate_capability_handler),
        )
        .route(
            "/v1/capabilities/attenuate",
            post(sidecar_attenuate_capability_handler),
        )
        .route("/v1/receipts", post(sidecar_submit_receipt_handler))
        // Verify a `ChioReceipt` signature against the embedded kernel
        // public key.
        .route("/v1/receipts/verify", post(sidecar_verify_receipt_handler))
        // Advisory tool-call evaluation. The SDK posts a
        // `{capability_id, tool_server, tool_name, parameters,
        // parameter_hash}` body and receives an explicit advisory wrapper
        // with `authorization: false`. The kernel-driven evaluation that
        // `/chio/evaluate` performs for HTTP requests is not wired for
        // tool-call bodies; callers must not treat this as authorization.
        .route(
            "/v1/evaluate/advisory",
            post(sidecar_evaluate_tool_call_handler),
        )
        .route("/v1/evaluate", post(sidecar_removed_evaluate_handler))
        // Admin-gated Prometheus scrape endpoint. Mounted before the catch-all
        // so axum prefers this specific route, and gated by the same
        // sidecar-control posture as the approval routes.
        .route(
            "/metrics",
            get(handle_metrics).route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                require_sidecar_control_middleware,
            )),
        )
        .route("/{*path}", any(proxy_handler))
        .route("/", any(proxy_handler))
        .with_state(state)
}

/// Compose the Prometheus scrape body from the kernel guard families, the
/// http-core mediation-edge families, and the alert-pack families.
async fn handle_metrics() -> impl axum::response::IntoResponse {
    let alert_pack = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut out);
        out
    };
    let body = chio_metrics_spec::runtime::compose_metrics_body(&[
        &chio_kernel::render_guard_metrics_prometheus,
        &chio_http_core::metrics::render_http_core_metrics_prometheus,
        &alert_pack,
    ]);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

pub(crate) async fn require_sidecar_control_middleware(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }

    next.run(request).await
}

/// Axum handler that evaluates the request and proxies to upstream.
pub(crate) async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let uri = request.uri().clone();
    let raw_headers = request.headers().clone();
    let method = match request.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => {
            return (StatusCode::METHOD_NOT_ALLOWED, "unsupported method").into_response();
        }
    };

    let path = uri.path().to_string();
    if let Some(key) = duplicate_query_key(uri.query()) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "chio_bad_request",
                "message": format!("duplicate query parameter `{key}`"),
            })),
        )
            .into_response();
    }
    let query = parse_query_params(uri.query());
    let forwarded_query = forwarded_query_string(uri.query());

    let mut headers = HashMap::new();
    for (name, value) in &raw_headers {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!("failed to read request body: {e}");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };
    let body_length = body_bytes.len() as u64;
    let body_hash = if body_bytes.is_empty() {
        None
    } else {
        Some(chio_core_types::sha256_hex(&body_bytes))
    };
    let execution_nonce = match extract_execution_nonce_from_maps(&headers) {
        Ok(nonce) => nonce,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": message,
                })),
            )
                .into_response();
        }
    };

    if let Some(response) =
        revoked_proxy_response(&state, method, &path, &query, &headers, body_hash.clone()).await
    {
        return response;
    }

    let result = match state.evaluator.evaluate_with_execution_nonce(
        method,
        &path,
        &query,
        &headers,
        body_hash,
        body_length,
        execution_nonce.as_ref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("evaluation error: {e}");
            return evaluation_error_response(&e);
        }
    };

    if result.verdict.is_denied() {
        let denied_status = StatusCode::from_u16(verdict_http_status(&result.verdict))
            .unwrap_or(StatusCode::FORBIDDEN);
        let final_receipt = match finalize_and_record_receipt(
            &state,
            &result.receipt,
            denied_status.as_u16(),
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(response) => return response,
        };
        let error_body = serde_json::json!({
            "error": "chio_access_denied",
            "message": match &result.verdict {
                Verdict::Deny { reason, .. } => reason.clone(),
                _ => "access denied".to_string(),
            },
            "receipt_id": final_receipt.id,
            "suggestion": "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
        });
        return Response::builder()
            .status(denied_status)
            .header("content-type", "application/json")
            .header("X-Chio-Receipt-Id", &final_receipt.id)
            .body(Body::from(
                serde_json::to_string(&error_body).unwrap_or_default(),
            ))
            .unwrap_or_else(|_| denied_status.into_response());
    }

    if !result.verdict.is_allowed() {
        let status = match &result.verdict {
            Verdict::Incomplete { .. } => StatusCode::PRECONDITION_REQUIRED,
            _ => StatusCode::from_u16(verdict_http_status(&result.verdict))
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        };
        let final_receipt =
            match finalize_and_record_receipt(&state, &result.receipt, status.as_u16()).await {
                Ok(receipt) => receipt,
                Err(response) => return response,
            };
        return (
            status,
            [("X-Chio-Receipt-Id", final_receipt.id.clone())],
            axum::Json(EvaluateResponse {
                verdict: result.verdict,
                receipt: final_receipt,
                evidence: result.evidence,
                execution_nonce: result.execution_nonce,
            }),
        )
            .into_response();
    }

    let mut upstream_url = format!("{}{}", state.upstream.trim_end_matches('/'), &path);
    if let Some(raw_query) = forwarded_query {
        upstream_url.push('?');
        upstream_url.push_str(&raw_query);
    }

    let mut upstream_req = state.http_client.request(
        match method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        },
        &upstream_url,
    );

    // Forward end-to-end request headers while keeping Chio transport and
    // hop-by-hop connection details local to the proxy.
    for (name, value) in &raw_headers {
        if should_forward_request_header(name.as_str()) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    let upstream_req = match upstream_req.build() {
        Ok(request) => request,
        Err(error) => {
            return finalize_bad_gateway(
                &state,
                &result.receipt,
                format!("failed to build upstream request: {error}"),
            )
            .await;
        }
    };

    match send_with_contract(&state.egress_contract, &state.http_client, upstream_req).await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let response_headers = resp.headers().clone();
            let response_body = resp.body().to_vec();
            let final_receipt =
                match finalize_and_record_receipt(&state, &result.receipt, status.as_u16()).await {
                    Ok(receipt) => receipt,
                    Err(response) => return response,
                };

            let mut response_builder = Response::builder().status(status);

            for (name, value) in &response_headers {
                response_builder = response_builder.header(name.as_str(), value.as_bytes());
            }

            response_builder = response_builder.header("X-Chio-Receipt-Id", &final_receipt.id);

            response_builder
                .body(Body::from(response_body))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "bad gateway").into_response())
        }
        Err(e) => {
            warn!("upstream error: {e}");
            finalize_bad_gateway(&state, &result.receipt, format!("upstream error: {e}")).await
        }
    }
}

pub(crate) async fn find_revoked_capability_id(
    state: &Arc<ProxyState>,
    raw_capability: Option<&str>,
    capability_id_hint: Option<&str>,
) -> Option<String> {
    let capability_id = presented_capability_id(raw_capability)
        .or_else(|| capability_id_hint.map(ToOwned::to_owned))?;
    let revoked_capability_ids = state.revoked_capability_ids.lock().await;
    revoked_capability_ids
        .contains(&capability_id)
        .then_some(capability_id)
}

pub(crate) async fn revoked_proxy_response(
    state: &Arc<ProxyState>,
    method: HttpMethod,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HashMap<String, String>,
    body_hash: Option<String>,
) -> Option<Response> {
    let capability_id = find_revoked_capability_id(
        state,
        extract_presented_capability_from_maps(headers, query),
        None,
    )
    .await?;
    let caller = extract_caller_identity(headers);
    let caller_identity_hash = match caller.identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash caller identity for revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    let mut request = ChioHttpRequest::new(
        uuid::Uuid::now_v7().to_string(),
        method,
        path.to_string(),
        path.to_string(),
        caller,
    );
    request.query = query.clone();
    request.body_hash = body_hash;

    let content_hash = match request.content_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to compute revocation request content hash: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    let verdict = revoked_capability_verdict();
    let receipt = match build_manual_receipt(
        state,
        request.request_id.clone(),
        request.route_pattern.clone(),
        request.method,
        caller_identity_hash,
        None,
        verdict.clone(),
        StatusCode::FORBIDDEN.as_u16(),
        request.timestamp,
        content_hash,
        Some(capability_id),
        Some(http_status_metadata_final(None)),
        "chio_api_protect_revoked_capability",
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    if let Err(error) = record_receipt(state, &receipt).await {
        warn!("failed to persist revocation receipt: {error}");
        return Some(internal_json_error_response(
            "chio_receipt_persistence_failed",
            &error.to_string(),
        ));
    }

    let denied_status =
        StatusCode::from_u16(verdict_http_status(&verdict)).unwrap_or(StatusCode::FORBIDDEN);
    let error_body = serde_json::json!({
        "error": "chio_access_denied",
        "message": "capability token has been revoked",
        "receipt_id": receipt.id,
        "suggestion": "request a fresh capability token before retrying",
    });

    Some(
        Response::builder()
            .status(denied_status)
            .header("content-type", "application/json")
            .header("X-Chio-Receipt-Id", &receipt.id)
            .body(Body::from(
                serde_json::to_string(&error_body).unwrap_or_default(),
            ))
            .unwrap_or_else(|_| denied_status.into_response()),
    )
}

pub(crate) async fn revoked_sidecar_evaluate_response(
    state: &Arc<ProxyState>,
    request: &ChioHttpRequest,
    presented_capability: Option<&str>,
) -> Option<Response> {
    let capability_id = find_revoked_capability_id(
        state,
        presented_capability,
        request.capability_id.as_deref(),
    )
    .await?;
    let caller_identity_hash = match request.caller.identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash caller identity for sidecar revocation: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };
    let content_hash = match request.content_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to compute sidecar revocation content hash: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };
    let route_pattern = if request.route_pattern.is_empty() {
        request.path.clone()
    } else {
        request.route_pattern.clone()
    };
    let verdict = revoked_capability_verdict();
    let receipt = match build_manual_receipt(
        state,
        request.request_id.clone(),
        route_pattern,
        request.method,
        caller_identity_hash,
        request.session_id.clone(),
        verdict.clone(),
        StatusCode::FORBIDDEN.as_u16(),
        request.timestamp,
        content_hash,
        Some(capability_id),
        Some(http_status_metadata_decision()),
        "chio_api_protect_revoked_capability",
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign sidecar revocation receipt: {error}");
            return Some(internal_json_error_response(
                "chio_receipt_sign_failed",
                &error.to_string(),
            ));
        }
    };

    if let Err(error) = record_receipt(state, &receipt).await {
        warn!("failed to persist sidecar revocation receipt: {error}");
        return Some(internal_json_error_response(
            "chio_receipt_persistence_failed",
            &error.to_string(),
        ));
    }

    Some(
        (
            StatusCode::OK,
            axum::Json(EvaluateResponse {
                verdict,
                receipt,
                evidence: Vec::new(),
                // Revocation-only HTTP evaluation does not authorize
                // execution and never mints a dispatch nonce.
                execution_nonce: None,
            }),
        )
            .into_response(),
    )
}

pub(crate) async fn record_receipt(
    state: &Arc<ProxyState>,
    receipt: &HttpReceipt,
) -> Result<(), ProtectError> {
    if let Some(store) = &state.receipt_store {
        let mut store = store.lock().await;
        store.append(receipt)?;
    }

    let mut log = state.receipt_log.lock().await;
    log.receipts.push(receipt.clone());
    Ok(())
}

pub(crate) async fn record_tool_receipt(
    state: &Arc<ProxyState>,
    receipt: &ChioReceipt,
) -> Result<(), ProtectError> {
    if let Some(store) = &state.receipt_store {
        let mut store = store.lock().await;
        store.append_tool_receipt(receipt)?;
    }

    let mut log = state.tool_receipt_log.lock().await;
    log.receipts.push(receipt.clone());
    Ok(())
}

pub(crate) async fn finalize_and_record_receipt(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    response_status: u16,
) -> Result<HttpReceipt, Response> {
    let receipt = state
        .evaluator
        .finalize_receipt(decision_receipt, response_status)
        .map_err(|error| {
            warn!("failed to finalize receipt: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to finalize receipt",
            )
                .into_response()
        })?;

    record_receipt(state, &receipt).await.map_err(|error| {
        warn!("failed to persist receipt: {error}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist receipt",
        )
            .into_response()
    })?;

    Ok(receipt)
}

pub(crate) async fn finalize_bad_gateway(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    message: String,
) -> Response {
    match finalize_and_record_receipt(state, decision_receipt, StatusCode::BAD_GATEWAY.as_u16())
        .await
    {
        Ok(receipt) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("X-Chio-Receipt-Id", &receipt.id)
            .body(Body::from(message))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
        Err(response) => response,
    }
}
