//! HTTP handlers for the portable-passport surface: OID4VCI issuance, OID4VP
//! presentation and wallet exchange, passport status lifecycle, verifier
//! policies, presentation challenges, and federated issuance.

use super::report_rendering::forward_post_to_leader;
use super::report_validation::{
    bearer_token_from_headers, load_capability_authority,
    load_capability_authority_with_deferred_lineage, validate_service_auth,
};
use super::*;

pub(crate) async fn handle_passport_issuer_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_public_passport_issuer_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_issuer_discovery(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

pub(crate) async fn handle_public_passport_verifier_discovery(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_verifier_discovery(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

pub(crate) async fn handle_public_passport_discovery_transparency(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_public_discovery_transparency(&state.config) {
        Ok(document) => Json(document).into_response(),
        Err(error) => public_discovery_error_response(&error),
    }
}

pub(crate) async fn handle_oid4vp_verifier_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    match build_oid4vp_verifier_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

pub(crate) async fn handle_passport_issuer_jwks(
    State(state): State<TrustServiceState>,
) -> Response {
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

pub(crate) fn public_discovery_error_response(error: &CliError) -> Response {
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

pub(crate) async fn handle_passport_sd_jwt_type_metadata(
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
    match build_chio_passport_sd_jwt_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_passport_jwt_vc_json_type_metadata(
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

pub(crate) async fn handle_create_passport_issuance_offer(
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

pub(crate) async fn handle_redeem_passport_issuance_token(
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

pub(crate) async fn handle_redeem_passport_issuance_credential(
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
            return plain_http_error(StatusCode::UNAUTHORIZED, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(response).into_response()
}

pub(crate) async fn handle_list_passport_statuses(
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

pub(crate) async fn handle_get_passport_status(
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

pub(crate) async fn handle_publish_passport_status(
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

pub(crate) async fn handle_resolve_passport_status(
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

pub(crate) async fn handle_public_resolve_passport_status(
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

pub(crate) async fn handle_revoke_passport_status(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

pub(crate) async fn handle_list_verifier_policies(
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

pub(crate) async fn handle_get_verifier_policy(
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

pub(crate) async fn handle_upsert_verifier_policy(
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

pub(crate) async fn handle_delete_verifier_policy(
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

pub(crate) async fn handle_create_passport_challenge(
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
            ));
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

pub(crate) async fn handle_verify_passport_challenge(
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

pub(crate) async fn handle_public_get_passport_challenge(
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

pub(crate) async fn handle_public_verify_passport_challenge(
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
            );
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
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

pub(crate) async fn handle_create_oid4vp_request(
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(CreateOid4vpRequestResponse {
        request,
        transport,
        wallet_exchange,
    })
    .into_response()
}

pub(crate) async fn handle_public_get_wallet_exchange(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
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

pub(crate) async fn handle_public_get_oid4vp_request(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
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

pub(crate) async fn handle_public_launch_oid4vp_request(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    Redirect::temporary(&oid4vp_same_device_url(&request.request_uri)).into_response()
}

pub(crate) async fn handle_public_submit_oid4vp_response(
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
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string());
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

pub(crate) async fn handle_federated_issue(
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
    let authority = if payload.delegation_policy.is_some() {
        load_capability_authority_with_deferred_lineage(&state.config)
    } else {
        load_capability_authority(&state.config)
    };
    match authority {
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
                                );
                            }
                        };
                        let signed_parent_capability_id = capability
                            .delegation_chain
                            .last()
                            .map(|link| link.capability_id.clone());
                        let mut child_snapshot = match build_capability_snapshot(
                            &capability,
                            capability.delegation_chain.len() as u64,
                            signed_parent_capability_id,
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                );
                            }
                        };
                        child_snapshot.federated_parent_capability_id =
                            Some(anchor_snapshot.capability_id.clone());
                        let upstream_bridge =
                            upstream_parent.as_ref().map(|(share_id, parent_snapshot)| {
                                (parent_snapshot.capability_id.as_str(), share_id.as_str())
                            });
                        if let Err(error) = store.persist_federated_delegation_lineage(
                            &anchor_snapshot,
                            upstream_bridge,
                            &child_snapshot,
                        ) {
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
