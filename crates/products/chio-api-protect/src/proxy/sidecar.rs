use super::*;

pub(crate) async fn sidecar_evaluate_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let transport_query = parse_query_params(parts.uri.query());
    let presented_capability = extract_transport_capability(&parts.headers, &transport_query);
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read evaluation body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": "failed to read evaluation body",
                })),
            )
                .into_response();
        }
    };

    let chio_request: ChioHttpRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode ChioHttpRequest: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": format!("invalid ChioHttpRequest payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    if let Some(response) =
        revoked_sidecar_evaluate_response(&state, &chio_request, presented_capability.as_deref())
            .await
    {
        return response;
    }

    let result = match state
        .evaluator
        .evaluate_chio_request(chio_request, presented_capability.as_deref())
    {
        Ok(result) => result,
        Err(error) => {
            warn!("sidecar evaluation error: {error}");
            return evaluation_error_response(&error);
        }
    };

    if let Err(error) = record_receipt(&state, &result.receipt).await {
        warn!("failed to persist receipt: {error}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "chio_receipt_persistence_failed",
                "message": error.to_string(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        axum::Json(EvaluateResponse {
            verdict: result.verdict,
            receipt: result.receipt,
            evidence: result.evidence,
            execution_nonce: result.execution_nonce,
        }),
    )
        .into_response()
}

pub(crate) async fn sidecar_verify_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read verify body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": "failed to read receipt verification body",
                })),
            )
                .into_response();
        }
    };

    let receipt: HttpReceipt = match serde_json::from_slice(&body_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to decode HttpReceipt: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_bad_request",
                    "message": format!("invalid HttpReceipt payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    let signer_trusted = receipt.kernel_key.to_hex() == state.signer_keypair.public_key().to_hex();
    let verification = VerifyReceiptResponse::from_http_receipt(&receipt, signer_trusted);
    (StatusCode::OK, axum::Json(verification)).into_response()
}

/// Process-only liveness. Returns `200` while the process runs. A dependency blip
/// must not trip liveness, or an orchestrator would restart a container that is
/// serving correctly; dependency health is reported by `/chio/health` instead.
pub(crate) async fn sidecar_liveness_handler() -> Response {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: SidecarStatus::Healthy,
            version: env!("CARGO_PKG_VERSION").to_string(),
            // Liveness is process-only and stateless, so it does not inspect the
            // embedded kernel's storage backends; readiness reports those.
            receipt_backend: String::new(),
            revocation_backend: String::new(),
        }),
    )
        .into_response()
}

/// Dependency-aware readiness. Consults the proxy state instead of reporting a
/// constant healthy, so a broken runtime dependency yields a non-200 that pulls the
/// instance from routing. Also surfaces the embedded kernel's receipt and revocation
/// backends so operators can confirm durable-by-default storage is in effect.
pub(crate) async fn sidecar_health_handler(State(state): State<Arc<ProxyState>>) -> Response {
    let status = state.readiness_status().await;
    let code = match status {
        SidecarStatus::Healthy => StatusCode::OK,
        SidecarStatus::Degraded | SidecarStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        code,
        axum::Json(HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            receipt_backend: state.receipt_backend.to_string(),
            revocation_backend: state.revocation_backend.to_string(),
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct SidecarMintRequest {
    subject: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    ttl_nanos: Option<u64>,
    #[serde(default)]
    job_uid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SidecarMintResponse {
    pub(crate) capability: CapabilityToken,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SidecarReleaseRequest {
    capability_id: String,
    #[serde(default)]
    job_uid: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SidecarReleaseResponse {
    released: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SidecarSubmitReceiptRequest {
    job_name: String,
    namespace: String,
    job_uid: String,
    #[serde(default)]
    capability_id: Option<String>,
    outcome: String,
    #[serde(default)]
    started_at: Option<String>,
    #[serde(default)]
    completed_at: Option<String>,
    #[serde(default)]
    steps: Vec<SidecarSubmitStepReceipt>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SidecarSubmitStepReceipt {
    pod_name: String,
    phase: String,
    payload: String,
    observed_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SidecarSubmitReceiptResponse {
    pub(crate) receipt_id: String,
    pub(crate) accepted: bool,
}

pub(crate) async fn sidecar_mint_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability mint body: {error}");
            return sidecar_bad_request("failed to read capability mint body").into_response();
        }
    };

    let mint_request: SidecarMintRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode capability mint request: {error}");
            return sidecar_bad_request(&format!("invalid capability mint payload: {error}"))
                .into_response();
        }
    };

    if mint_request.subject.trim().is_empty() {
        return sidecar_bad_request("subject must not be empty").into_response();
    }

    let scope = match build_sidecar_scope(&mint_request.scopes) {
        Ok(scope) => scope,
        Err(error) => return sidecar_bad_request(&error).into_response(),
    };

    let issued_at = chrono::Utc::now().timestamp() as u64;
    let ttl_seconds = ttl_seconds_from_wire(mint_request.ttl_seconds, mint_request.ttl_nanos);
    let expires_at = issued_at.saturating_add(ttl_seconds);
    let subject = derive_sidecar_subject_key(&mint_request.subject, &mint_request.job_uid);
    let capability_id = match derive_sidecar_capability_id(
        &mint_request.subject,
        &mint_request.job_uid,
        ttl_seconds,
        &scope,
    ) {
        Ok(capability_id) => capability_id,
        Err(error) => {
            warn!("failed to derive deterministic capability id: {error}");
            return internal_json_error_response(
                "chio_capability_mint_failed",
                "failed to derive deterministic capability id",
            );
        }
    };

    let capability = match CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id,
            issuer: state.signer_keypair.public_key(),
            subject,
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
        },
        &state.signer_keypair,
    ) {
        Ok(capability) => capability,
        Err(error) => {
            warn!("failed to sign compatibility capability token: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "chio_capability_mint_failed",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        axum::Json(SidecarMintResponse { capability }),
    )
        .into_response()
}

pub(crate) async fn sidecar_release_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability release body: {error}");
            return sidecar_bad_request("failed to read capability release body").into_response();
        }
    };

    let release_request: SidecarReleaseRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode capability release request: {error}");
            return sidecar_bad_request(&format!("invalid capability release payload: {error}"))
                .into_response();
        }
    };

    if release_request.capability_id.trim().is_empty() {
        return sidecar_bad_request("capability_id must not be empty").into_response();
    }

    let capability_id = release_request.capability_id.trim().to_string();

    // Record the release in the receipt store's revoked-capabilities table when
    // a durable receipt database is configured, so a restart reloads it into the
    // in-memory validate set. In ephemeral mode there is no such table; the
    // shared revocation store below still makes the release effective in-process.
    if let Some(store) = &state.receipt_store {
        let mut store = store.lock().await;
        if let Err(error) = store.revoke_capability(&capability_id) {
            warn!("failed to persist capability revocation: {error}");
            return internal_json_error_response(
                "chio_capability_release_failed",
                &error.to_string(),
            );
        }
    }

    // Record in the revocation store shared with the embedded kernel. It is
    // present in every serving mode (the durable sibling database, or an
    // in-memory store in ephemeral mode), so a release takes effect for mediated
    // dispatch in-process and, when durable, for a sibling replica sharing the
    // volume without waiting for a restart. Fail closed: a release that cannot be
    // recorded must not report success.
    let Some(revocation_store) = &state.revocation_store else {
        return internal_json_error_response(
            "chio_capability_release_failed",
            "no revocation store is configured for capability release",
        );
    };
    if let Err(error) = revocation_store.revoke(&capability_id) {
        warn!("failed to record capability revocation: {error}");
        return internal_json_error_response("chio_capability_release_failed", &error.to_string());
    }
    state
        .revoked_capability_ids
        .lock()
        .await
        .insert(capability_id);
    let _ = (release_request.job_uid, release_request.reason);

    (
        StatusCode::OK,
        axum::Json(SidecarReleaseResponse { released: true }),
    )
        .into_response()
}

pub(crate) async fn sidecar_submit_receipt_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read receipt submission body: {error}");
            return sidecar_bad_request("failed to read receipt submission body").into_response();
        }
    };

    let receipt_request: SidecarSubmitReceiptRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode receipt submission payload: {error}");
            return sidecar_bad_request(&format!("invalid receipt submission payload: {error}"))
                .into_response();
        }
    };

    if receipt_request.job_name.trim().is_empty()
        || receipt_request.namespace.trim().is_empty()
        || receipt_request.job_uid.trim().is_empty()
        || receipt_request.outcome.trim().is_empty()
    {
        return sidecar_bad_request("job_name, namespace, job_uid, and outcome are required")
            .into_response();
    }

    for step in &receipt_request.steps {
        if step.pod_name.trim().is_empty()
            || step.phase.trim().is_empty()
            || step.payload.trim().is_empty()
            || step.observed_at.trim().is_empty()
        {
            return sidecar_bad_request(
                "receipt steps must include pod_name, phase, payload, and observed_at",
            )
            .into_response();
        }
    }

    let caller_identity_hash = match CallerIdentity::anonymous().identity_hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("failed to hash synthetic receipt caller identity: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    let receipt_id = uuid::Uuid::now_v7().to_string();
    let capability_id = receipt_request
        .capability_id
        .clone()
        .filter(|value| !value.trim().is_empty());
    let receipt = match HttpReceipt::sign(
        HttpReceiptBody {
            id: receipt_id.clone(),
            request_id: format!("job-receipt-submission:{}", receipt_request.job_uid),
            route_pattern: "/v1/receipts".to_string(),
            method: HttpMethod::Post,
            caller_identity_hash,
            session_id: None,
            verdict: Verdict::Allow,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status: StatusCode::OK.as_u16(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: chio_core_types::sha256_hex(&body_bytes),
            policy_hash: manual_receipt_policy_hash("chio_api_protect_sidecar_receipt_submission"),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id,
            metadata: Some(sidecar_submit_receipt_metadata(&receipt_request)),
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign submitted sidecar receipt: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    if let Err(error) = record_receipt(&state, &receipt).await {
        warn!("failed to persist submitted sidecar receipt: {error}");
        return internal_json_error_response("chio_receipt_persistence_failed", &error.to_string());
    }

    (
        StatusCode::OK,
        axum::Json(SidecarSubmitReceiptResponse {
            receipt_id: receipt.id.clone(),
            accepted: true,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// SDK-shape capability mint alias
// ---------------------------------------------------------------------------

/// Body shape posted by `chio-sdk-python`'s `ChioClient.create_capability`.
///
/// Differs from [`SidecarMintRequest`] in two ways:
/// 1. The scope arrives as a structured `ChioScope` object instead of the
///    flat `scopes: Vec<String>` shorthand.
/// 2. There is no `job_uid`; the alias derives one deterministically.
///
/// The alias accepts both shapes via `serde(untagged)` so existing callers
/// of `/v1/capabilities/mint` keep working when they happen to call the
/// alias path.
#[derive(Debug, Deserialize)]
pub(crate) struct SdkMintRequest {
    subject: String,
    scope: ChioScope,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    ttl_nanos: Option<u64>,
    #[serde(default)]
    job_uid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum SidecarCapabilitiesAliasRequest {
    /// SDK-shape body: `scope` is a structured `ChioScope` object.
    Sdk(SdkMintRequest),
    /// Canonical mint body: `scopes` is a flat `Vec<String>` shorthand.
    Canonical(SidecarMintRequest),
}

pub(crate) async fn sidecar_capabilities_alias_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability mint body: {error}");
            return sidecar_bad_request("failed to read capability mint body").into_response();
        }
    };

    let alias_request: SidecarCapabilitiesAliasRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode capability alias mint request: {error}");
            return sidecar_bad_request(&format!("invalid capability mint payload: {error}"))
                .into_response();
        }
    };

    let (subject, scope, job_uid, ttl_seconds_wire, ttl_nanos_wire) = match alias_request {
        SidecarCapabilitiesAliasRequest::Sdk(sdk) => {
            if sdk.subject.trim().is_empty() {
                return sidecar_bad_request("subject must not be empty").into_response();
            }
            let job_uid = sdk.job_uid.unwrap_or_default();
            (
                sdk.subject,
                sdk.scope,
                job_uid,
                sdk.ttl_seconds,
                sdk.ttl_nanos,
            )
        }
        SidecarCapabilitiesAliasRequest::Canonical(mint_request) => {
            if mint_request.subject.trim().is_empty() {
                return sidecar_bad_request("subject must not be empty").into_response();
            }
            let scope = match build_sidecar_scope(&mint_request.scopes) {
                Ok(scope) => scope,
                Err(error) => return sidecar_bad_request(&error).into_response(),
            };
            (
                mint_request.subject,
                scope,
                mint_request.job_uid,
                mint_request.ttl_seconds,
                mint_request.ttl_nanos,
            )
        }
    };

    let issued_at = chrono::Utc::now().timestamp() as u64;
    let ttl_seconds = ttl_seconds_from_wire(ttl_seconds_wire, ttl_nanos_wire);
    let expires_at = issued_at.saturating_add(ttl_seconds);
    let subject_key = derive_sidecar_subject_key(&subject, &job_uid);
    let capability_id = match derive_sidecar_capability_id(&subject, &job_uid, ttl_seconds, &scope)
    {
        Ok(capability_id) => capability_id,
        Err(error) => {
            warn!("failed to derive deterministic capability id: {error}");
            return internal_json_error_response(
                "chio_capability_mint_failed",
                "failed to derive deterministic capability id",
            );
        }
    };

    let capability = match CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id,
            issuer: state.signer_keypair.public_key(),
            subject: subject_key,
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
        },
        &state.signer_keypair,
    ) {
        Ok(capability) => capability,
        Err(error) => {
            warn!("failed to sign capability token from alias mint: {error}");
            return internal_json_error_response("chio_capability_mint_failed", &error.to_string());
        }
    };

    // The SDK expects the `CapabilityToken` itself as the response body,
    // not a `{capability: ...}` envelope. Returning the token directly
    // matches `chio-sdk-python`'s `CapabilityToken.model_validate(data)`
    // call site at `client.py:141`.
    (StatusCode::OK, axum::Json(capability)).into_response()
}

// ---------------------------------------------------------------------------
// Capability validation
// ---------------------------------------------------------------------------

/// `POST /v1/capabilities/validate` request shape.
///
/// The SDK posts the full `CapabilityToken` JSON; the optional
/// `expected_subject` and `expected_scope` fields are accepted for forward
/// compatibility but not enforced today (the route reports them in the
/// response so callers can audit if they were ignored).
#[derive(Debug, Deserialize)]
pub(crate) struct SidecarValidateCapabilityRequest {
    #[serde(flatten)]
    token: CapabilityToken,
    #[serde(default)]
    expected_subject: Option<String>,
    #[serde(default)]
    expected_scope: Option<ChioScope>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SidecarValidateCapabilityResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    capability_id: String,
}

pub(crate) async fn sidecar_validate_capability_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read capability validate body: {error}");
            return sidecar_bad_request("failed to read capability validate body").into_response();
        }
    };

    let validate_request: SidecarValidateCapabilityRequest =
        match serde_json::from_slice(&body_bytes) {
            Ok(request) => request,
            Err(error) => {
                warn!("failed to decode capability validate request: {error}");
                return sidecar_bad_request(&format!(
                    "invalid capability validate payload: {error}"
                ))
                .into_response();
            }
        };

    let token = validate_request.token;
    let capability_id = token.id.clone();
    let expires_at = Some(token.expires_at);

    // Fail-closed: revoked capabilities are invalid even if the signature
    // verifies and `expires_at` is in the future. Consult the durable store as
    // well so a revocation a sibling replica recorded is honored here too.
    let revoked = state.capability_is_revoked(&capability_id).await;
    if revoked {
        return (
            StatusCode::OK,
            axum::Json(SidecarValidateCapabilityResponse {
                valid: false,
                reason: Some("capability has been revoked".to_string()),
                expires_at,
                capability_id,
            }),
        )
            .into_response();
    }

    if !state.trusted_capability_issuers.contains(&token.issuer) {
        return (
            StatusCode::OK,
            axum::Json(SidecarValidateCapabilityResponse {
                valid: false,
                reason: Some("capability issuer is not trusted".to_string()),
                expires_at,
                capability_id,
            }),
        )
            .into_response();
    }

    let signature_valid = token.verify_signature().unwrap_or(false);
    if !signature_valid {
        return (
            StatusCode::OK,
            axum::Json(SidecarValidateCapabilityResponse {
                valid: false,
                reason: Some("capability signature did not verify".to_string()),
                expires_at,
                capability_id,
            }),
        )
            .into_response();
    }

    let now = chrono::Utc::now().timestamp() as u64;
    if token.expires_at <= now {
        return (
            StatusCode::OK,
            axum::Json(SidecarValidateCapabilityResponse {
                valid: false,
                reason: Some("capability has expired".to_string()),
                expires_at,
                capability_id,
            }),
        )
            .into_response();
    }

    // A delegated token is only as live as its lineage: revoking a parent must
    // invalidate every attenuated child minted beneath it. Consult the durable
    // store for each delegation-chain ancestor so this freshness signal matches
    // the mediated request path, which also rejects a token when any chain
    // ancestor is revoked.
    //
    // This walk runs only after the issuer, signature, and expiry gates above,
    // so an untrusted or unverified token cannot force one durable revocation
    // lookup per fabricated ancestor: a caller must present a trusted, signed,
    // unexpired token before its chain is weighed.
    for ancestor in &token.delegation_chain {
        if state.capability_is_revoked(&ancestor.capability_id).await {
            return (
                StatusCode::OK,
                axum::Json(SidecarValidateCapabilityResponse {
                    valid: false,
                    reason: Some(
                        "a delegated capability in the chain has been revoked".to_string(),
                    ),
                    expires_at,
                    capability_id,
                }),
            )
                .into_response();
        }
    }

    if let Some(expected_subject) = validate_request.expected_subject.as_deref() {
        let expected = expected_subject.trim();
        if !expected.is_empty() && token.subject.to_hex() != expected {
            return (
                StatusCode::OK,
                axum::Json(SidecarValidateCapabilityResponse {
                    valid: false,
                    reason: Some("capability subject does not match expected_subject".to_string()),
                    expires_at,
                    capability_id,
                }),
            )
                .into_response();
        }
    }

    if let Some(expected_scope) = validate_request.expected_scope.as_ref() {
        if !is_scope_subset(expected_scope, &token.scope) {
            return (
                StatusCode::OK,
                axum::Json(SidecarValidateCapabilityResponse {
                    valid: false,
                    reason: Some("expected_scope is not a subset of capability scope".to_string()),
                    expires_at,
                    capability_id,
                }),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        axum::Json(SidecarValidateCapabilityResponse {
            valid: true,
            reason: None,
            expires_at,
            capability_id,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Receipt verification (`ChioReceipt`-shaped, distinct from `/chio/verify`
// which is `HttpReceipt`-shaped)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct SidecarVerifyReceiptRequest {
    #[serde(flatten)]
    receipt: ChioReceipt,
    #[serde(default)]
    expected_decision: Option<String>,
    #[serde(default)]
    expected_capability_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SidecarVerifyReceiptResponse {
    #[serde(flatten)]
    report: VerifyReceiptResponse,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_at: Option<u64>,
    receipt_id: String,
}

fn sidecar_chio_receipt_report(
    receipt: &ChioReceipt,
    signer_trusted: bool,
) -> VerifyReceiptResponse {
    let signature_valid = receipt.verify_signature().unwrap_or(false);
    let receipt_id_valid = chio_core_types::receipt::body::chio_receipt_id(&receipt.body())
        .map(|expected_id| expected_id == receipt.id)
        .unwrap_or(false);
    let parameter_hash_valid = receipt.action.verify_hash().unwrap_or(false);
    let content_hash_valid = is_lower_hex_64(&receipt.content_hash);
    let policy_hash_valid = is_lower_hex_64(&receipt.policy_hash);
    let semantic_valid = receipt.receipt_kind == ReceiptKind::MediatedDecision
        && receipt.boundary_class == BoundaryClass::Prevent
        && receipt.observation_outcome.is_none()
        && receipt.trust_level == TrustLevel::Mediated;
    let ok = signature_valid
        && signer_trusted
        && receipt_id_valid
        && parameter_hash_valid
        && content_hash_valid
        && policy_hash_valid
        && semantic_valid;
    let authorized = ok && receipt.is_allowed();

    VerifyReceiptResponse {
        signature_valid,
        signer_trusted,
        receipt_id_valid,
        parameter_hash_valid,
        receipt_kind: receipt.receipt_kind.as_str().to_string(),
        boundary_class: receipt.boundary_class.as_str().to_string(),
        trust_level: receipt.trust_level.as_str().to_string(),
        result: decision_label(&receipt.decision),
        authorized,
        signer_key_hex: receipt.kernel_key.to_hex(),
        ok,
    }
}

fn sidecar_verify_receipt_response(
    receipt: &ChioReceipt,
    report: VerifyReceiptResponse,
    valid: bool,
    reason: Option<String>,
) -> SidecarVerifyReceiptResponse {
    SidecarVerifyReceiptResponse {
        valid,
        reason,
        decision: Some(report.result.clone()),
        signed_at: Some(receipt.timestamp),
        receipt_id: receipt.id.clone(),
        report,
    }
}

fn sidecar_receipt_report_reason(report: &VerifyReceiptResponse) -> Option<String> {
    if !report.receipt_id_valid {
        return Some("receipt id does not match body".to_string());
    }
    if !report.parameter_hash_valid {
        return Some("receipt action parameter_hash does not match parameters".to_string());
    }
    if report.receipt_kind != ReceiptKind::MediatedDecision.as_str()
        || report.boundary_class != BoundaryClass::Prevent.as_str()
        || report.trust_level != TrustLevel::Mediated.as_str()
    {
        return Some("receipt semantics are not authoritative".to_string());
    }
    None
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) async fn sidecar_verify_receipt_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read receipt verify body: {error}");
            return sidecar_bad_request("failed to read receipt verify body").into_response();
        }
    };

    let verify_request: SidecarVerifyReceiptRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode ChioReceipt verify request: {error}");
            return sidecar_bad_request(&format!("invalid receipt verify payload: {error}"))
                .into_response();
        }
    };

    let receipt = verify_request.receipt;
    let decision_label = decision_label(&receipt.decision);
    let signer_trusted = state.trusted_receipt_signers.contains(&receipt.kernel_key);
    let mut report = sidecar_chio_receipt_report(&receipt, signer_trusted);
    if !report.signature_valid {
        return (
            StatusCode::OK,
            axum::Json(sidecar_verify_receipt_response(
                &receipt,
                report,
                false,
                Some("receipt signature did not verify".to_string()),
            )),
        )
            .into_response();
    }

    if !report.signer_trusted {
        report.ok = false;
        report.authorized = false;
        return (
            StatusCode::OK,
            axum::Json(sidecar_verify_receipt_response(
                &receipt,
                report,
                false,
                Some("receipt signer is not trusted".to_string()),
            )),
        )
            .into_response();
    }

    if let Some(expected_decision) = verify_request.expected_decision.as_deref() {
        let expected = expected_decision.trim();
        if !expected.is_empty() && expected != decision_label {
            report.ok = false;
            report.authorized = false;
            return (
                StatusCode::OK,
                axum::Json(sidecar_verify_receipt_response(
                    &receipt,
                    report,
                    false,
                    Some(format!(
                        "decision {decision_label} does not match expected {expected}"
                    )),
                )),
            )
                .into_response();
        }
    }

    if let Some(expected_capability_id) = verify_request.expected_capability_id.as_deref() {
        let expected = expected_capability_id.trim();
        if !expected.is_empty() && expected != receipt.capability_id {
            report.ok = false;
            report.authorized = false;
            return (
                StatusCode::OK,
                axum::Json(sidecar_verify_receipt_response(
                    &receipt,
                    report,
                    false,
                    Some("receipt capability_id does not match expected_capability_id".to_string()),
                )),
            )
                .into_response();
        }
    }

    let valid = report.ok;
    let reason = if valid {
        None
    } else {
        sidecar_receipt_report_reason(&report)
    };
    (
        StatusCode::OK,
        axum::Json(sidecar_verify_receipt_response(
            &receipt, report, valid, reason,
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Tool-call advisory evaluation
// ---------------------------------------------------------------------------
//
// `POST /v1/evaluate/advisory` is NOT kernel-mediated authorization. It
// records cap-revocation and parameter-hash checks only, signs an
// `AdvisoryEvaluation` receipt (`TrustLevel::Advisory`), sets the
// `chio-trust-level: advisory` response header, and returns
// `authorization: false`.

/// `POST /v1/evaluate/advisory` body shape posted by `chio-sdk-python`'s
/// `ChioClient.evaluate_tool_call`. Distinct from `/chio/evaluate`'s
/// `ChioHttpRequest` shape because the SDK does not synthesize an HTTP
/// substrate request for direct tool calls.
#[derive(Debug, Deserialize)]
pub(crate) struct SidecarEvaluateToolCallRequest {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    parameter_hash: Option<String>,
}

pub(crate) async fn sidecar_evaluate_tool_call_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if !state.allow_advisory {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "chio_advisory_disabled",
                "authorization": false,
                "message": "advisory tool-call evaluation is disabled; use the kernel-mediated route",
                "replacement": "/v1/evaluate",
            })),
        )
            .into_response();
    }
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read evaluate body: {error}");
            return sidecar_bad_request("failed to read evaluate body").into_response();
        }
    };

    let evaluate_request: SidecarEvaluateToolCallRequest = match serde_json::from_slice(&body_bytes)
    {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode evaluate tool-call request: {error}");
            return sidecar_bad_request(&format!("invalid evaluate payload: {error}"))
                .into_response();
        }
    };

    if evaluate_request.capability_id.trim().is_empty() {
        return sidecar_bad_request("capability_id must not be empty").into_response();
    }
    if evaluate_request.tool_server.trim().is_empty() {
        return sidecar_bad_request("tool_server must not be empty").into_response();
    }
    if evaluate_request.tool_name.trim().is_empty() {
        return sidecar_bad_request("tool_name must not be empty").into_response();
    }

    // Recompute the parameter hash deterministically; if the client
    // supplied one, treat a mismatch as a denied receipt rather than a
    // 400 so the audit log captures the discrepancy.
    let parameter_hash = match chio_core_types::canonical_json_bytes(&evaluate_request.parameters) {
        Ok(canonical) => chio_core_types::sha256_hex(&canonical),
        Err(error) => {
            warn!("failed to canonicalise tool-call parameters: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    let claimed_hash = evaluate_request
        .parameter_hash
        .as_ref()
        .map(|hash| hash.trim().to_ascii_lowercase());

    let revoked = state
        .capability_is_revoked(&evaluate_request.capability_id)
        .await;

    let hash_mismatch = match claimed_hash.as_ref() {
        Some(claimed) => !claimed.is_empty() && *claimed != parameter_hash,
        None => false,
    };

    let advisory_check_outcome = if revoked {
        "capability_revoked"
    } else if hash_mismatch {
        "parameter_hash_mismatch"
    } else {
        "advisory_checks_passed"
    };

    // `Dropped` signals "the advisory-side checks would refuse to proceed";
    // `Evaluated` signals "the advisory route evaluated the call but did not
    // synchronously authorize anything". Neither implies the kernel mediated
    // the tool call.
    let observation_outcome = if revoked || hash_mismatch {
        ObservationOutcome::Dropped
    } else {
        ObservationOutcome::Evaluated
    };

    let action = ToolCallAction {
        parameters: evaluate_request.parameters,
        parameter_hash,
    };

    let receipt = match ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: evaluate_request.capability_id,
            tool_server: evaluate_request.tool_server,
            tool_name: evaluate_request.tool_name,
            action,
            decision: None,
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(observation_outcome),
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(&body_bytes),
            policy_hash: manual_receipt_policy_hash(
                "chio_api_protect_sidecar_tool_call_evaluation_v1",
            ),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "evaluation_kind": "sidecar_tool_call_advisory",
                "advisory_check_outcome": advisory_check_outcome,
                "execution_nonce": "not_minted",
                "limitation": "advisory evaluation is explicitly non-authoritative; kernel-mediated tool-call authorization is available at /v1/evaluate. This receipt records cap-revocation and parameter-hash checks only and must not be treated as kernel-mediated authorization.",
            })),
            trust_level: TrustLevel::Advisory,
            tenant_id: None,
            kernel_key: state.signer_keypair.public_key(),
            bbs_projection_version: None,
        },
        &state.signer_keypair,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to sign tool-call evaluation receipt: {error}");
            return internal_json_error_response("chio_receipt_sign_failed", &error.to_string());
        }
    };

    if let Err(error) = record_tool_receipt(&state, &receipt).await {
        warn!("failed to persist tool-call evaluation receipt: {error}");
        return internal_json_error_response("chio_receipt_persistence_failed", &error.to_string());
    }

    sidecar_advisory_tool_call_evaluate_response(receipt)
}

#[allow(clippy::result_large_err)]
pub(crate) fn require_sidecar_control_request(
    request: &Request<Body>,
    expected_bearer_token: Option<&str>,
) -> Result<(), Response> {
    if let Some(expected_bearer_token) = expected_bearer_token.map(str::trim) {
        if expected_bearer_token.is_empty() {
            warn!("rejecting sidecar control request with blank bearer token configuration");
            return Err(sidecar_control_forbidden_response(true));
        }
        if sidecar_control_bearer_token_matches(request, expected_bearer_token) {
            return Ok(());
        }
        if let Some(peer) = request.extensions().get::<ConnectInfo<CappedPeerAddr>>() {
            warn!(
                peer = %peer.0,
                "rejecting sidecar control request without valid bearer token"
            );
        } else {
            warn!("rejecting sidecar control request without valid bearer token");
        }
        return Err(sidecar_control_forbidden_response(true));
    }

    if let Some(peer) = request.extensions().get::<ConnectInfo<CappedPeerAddr>>() {
        if peer.0.ip().is_loopback() {
            return Ok(());
        }
    }

    if let Some(peer) = request.extensions().get::<ConnectInfo<CappedPeerAddr>>() {
        warn!(
            peer = %peer.0,
            "rejecting non-loopback sidecar control request without configured bearer token"
        );
    } else {
        warn!("rejecting sidecar control request without peer address");
    }
    Err(sidecar_control_forbidden_response(false))
}

pub(crate) fn sidecar_control_bearer_token_matches(
    request: &Request<Body>,
    expected_bearer_token: &str,
) -> bool {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            if scheme.eq_ignore_ascii_case("bearer") {
                Some(token)
            } else {
                None
            }
        })
        // Constant-time compare so callers cannot recover the configured token
        // through response timing differences.
        .is_some_and(|token| {
            token
                .as_bytes()
                .ct_eq(expected_bearer_token.as_bytes())
                .into()
        })
}

pub(crate) fn sidecar_control_forbidden_response(remote_auth_configured: bool) -> Response {
    let message = if remote_auth_configured {
        "sidecar control endpoints require a loopback caller or valid bearer token"
    } else {
        "sidecar control endpoints require a loopback caller"
    };
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "chio_control_forbidden",
            "message": message,
        })),
    )
        .into_response()
}

pub(crate) fn ttl_seconds_from_wire(
    ttl_seconds_wire: Option<u64>,
    ttl_nanos_wire: Option<u64>,
) -> u64 {
    const DEFAULT_TTL_SECONDS: u64 = 3600;
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    if let Some(ttl_seconds) = ttl_seconds_wire {
        return match ttl_seconds {
            0 => DEFAULT_TTL_SECONDS,
            ttl_seconds => ttl_seconds,
        };
    }

    if let Some(ttl_nanos) = ttl_nanos_wire {
        return match ttl_nanos {
            0 => DEFAULT_TTL_SECONDS,
            ttl_nanos => std::cmp::max(
                1,
                ttl_nanos.saturating_add(NANOS_PER_SECOND - 1) / NANOS_PER_SECOND,
            ),
        };
    }

    DEFAULT_TTL_SECONDS
}

pub(crate) fn derive_sidecar_subject_key(
    subject: &str,
    job_uid: &str,
) -> chio_core_types::crypto::PublicKey {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    hasher.update([0]);
    hasher.update(job_uid.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    Keypair::from_seed(&seed).public_key()
}

pub(crate) fn derive_sidecar_capability_id(
    subject: &str,
    job_uid: &str,
    ttl_seconds: u64,
    scope: &ChioScope,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct SidecarCapabilityIdMaterial<'a> {
        subject: &'a str,
        job_uid: &'a str,
        ttl_seconds: u64,
        tool_grants: Vec<String>,
        resource_grants: Vec<String>,
        prompt_grants: Vec<String>,
    }

    fn sorted_grant_encodings<T: Serialize>(
        grants: &[T],
    ) -> Result<Vec<String>, serde_json::Error> {
        let mut encodings = grants
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?;
        encodings.sort_unstable();
        Ok(encodings)
    }

    let id_material = SidecarCapabilityIdMaterial {
        subject,
        job_uid,
        ttl_seconds,
        tool_grants: sorted_grant_encodings(&scope.grants)?,
        resource_grants: sorted_grant_encodings(&scope.resource_grants)?,
        prompt_grants: sorted_grant_encodings(&scope.prompt_grants)?,
    };
    let encoded = serde_json::to_vec(&id_material)?;
    Ok(format!("sidecar-{}", chio_core_types::sha256_hex(&encoded)))
}

pub(crate) fn build_sidecar_scope(scopes: &[String]) -> Result<ChioScope, String> {
    let mut tool_grants = Vec::new();
    let mut resource_grants = Vec::new();
    let mut prompt_grants = Vec::new();

    for scope in scopes {
        match parse_sidecar_scope(scope)? {
            SidecarScopeGrant::Tool(grant) => tool_grants.push(grant),
            SidecarScopeGrant::Resource(grant) => resource_grants.push(grant),
            SidecarScopeGrant::Prompt(grant) => prompt_grants.push(grant),
        }
    }

    Ok(ChioScope {
        grants: tool_grants,
        resource_grants,
        prompt_grants,
    })
}

pub(crate) enum SidecarScopeGrant {
    Tool(ToolGrant),
    Resource(ResourceGrant),
    Prompt(PromptGrant),
}

pub(crate) fn parse_sidecar_scope(raw: &str) -> Result<SidecarScopeGrant, String> {
    let parts: Vec<&str> = raw
        .split(':')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();

    if parts.first() == Some(&"tools") && parts.len() >= 2 {
        return Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: "*".to_string(),
            tool_name: parts[1..].join(":"),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }));
    }

    match parts.as_slice() {
        [tool_name, operation] => Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: "*".to_string(),
            tool_name: (*tool_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, true)?],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })),
        ["tool", server_id, tool_name, operation] => Ok(SidecarScopeGrant::Tool(ToolGrant {
            server_id: (*server_id).to_string(),
            tool_name: (*tool_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })),
        ["resource", uri_pattern, operation] => Ok(SidecarScopeGrant::Resource(ResourceGrant {
            uri_pattern: (*uri_pattern).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
        })),
        ["prompt", prompt_name, operation] => Ok(SidecarScopeGrant::Prompt(PromptGrant {
            prompt_name: (*prompt_name).to_string(),
            operations: vec![parse_sidecar_operation(operation, false)?],
        })),
        _ => Err(format!("unsupported controller scope syntax: {raw}")),
    }
}

pub(crate) fn parse_sidecar_operation(raw: &str, shorthand: bool) -> Result<Operation, String> {
    match raw.to_ascii_lowercase().as_str() {
        "invoke" | "call" | "exec" | "execute" => Ok(Operation::Invoke),
        "write" if shorthand => Ok(Operation::Invoke),
        "read_result" | "result" => Ok(Operation::ReadResult),
        "read" if shorthand => Ok(Operation::Read),
        "read" => Ok(Operation::Read),
        "subscribe" | "watch" => Ok(Operation::Subscribe),
        "get" => Ok(Operation::Get),
        "delegate" => Ok(Operation::Delegate),
        _ => Err(format!("unsupported controller scope operation: {raw}")),
    }
}

pub(crate) fn sidecar_submit_receipt_metadata(
    receipt_request: &SidecarSubmitReceiptRequest,
) -> serde_json::Value {
    let mut metadata = match http_status_metadata_final(None) {
        serde_json::Value::Object(object) => object,
        _ => serde_json::Map::new(),
    };
    metadata.insert(
        "submission_kind".to_string(),
        serde_json::Value::String("job_receipt".to_string()),
    );
    metadata.insert(
        "job_name".to_string(),
        serde_json::Value::String(receipt_request.job_name.clone()),
    );
    metadata.insert(
        "namespace".to_string(),
        serde_json::Value::String(receipt_request.namespace.clone()),
    );
    metadata.insert(
        "job_uid".to_string(),
        serde_json::Value::String(receipt_request.job_uid.clone()),
    );
    metadata.insert(
        "outcome".to_string(),
        serde_json::Value::String(receipt_request.outcome.clone()),
    );
    if let Some(started_at) = &receipt_request.started_at {
        metadata.insert(
            "started_at".to_string(),
            serde_json::Value::String(started_at.clone()),
        );
    }
    if let Some(completed_at) = &receipt_request.completed_at {
        metadata.insert(
            "completed_at".to_string(),
            serde_json::Value::String(completed_at.clone()),
        );
    }
    metadata.insert(
        "steps".to_string(),
        serde_json::Value::Array(
            receipt_request
                .steps
                .iter()
                .map(|step| {
                    serde_json::json!({
                        "pod_name": step.pod_name,
                        "phase": step.phase,
                        "payload": step.payload,
                        "observed_at": step.observed_at,
                    })
                })
                .collect(),
        ),
    );
    serde_json::Value::Object(metadata)
}
