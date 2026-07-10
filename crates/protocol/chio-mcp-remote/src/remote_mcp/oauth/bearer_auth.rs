use super::*;

impl ProtectedResourceMetadata {
    pub(super) fn bearer_challenge(&self) -> String {
        let mut challenge = format!(
            "Bearer resource_metadata=\"{}\"",
            self.resource_metadata_url
        );
        if !self.scopes_supported.is_empty() {
            challenge.push_str(&format!(", scope=\"{}\"", self.scopes_supported.join(" ")));
        }
        challenge
    }
}

pub(super) async fn authenticate_session_request(
    headers: &HeaderMap,
    auth_mode: &RemoteAuthMode,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    expected_method: &str,
    expected_target: &str,
) -> Result<SessionAuthContext, Response> {
    let token = extract_bearer_token(headers, protected_resource_metadata)?;
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    match auth_mode {
        RemoteAuthMode::StaticBearer {
            token: expected_token,
        } => {
            if token != expected_token.as_ref() {
                return Err(unauthorized_bearer_response(
                    "missing or invalid bearer token",
                    protected_resource_metadata,
                ));
            }
            Ok(build_static_bearer_session_auth_context(
                headers,
                expected_token.as_ref(),
            ))
        }
        RemoteAuthMode::JwtBearer { verifier } => verifier.authenticate_token(
            &token,
            headers,
            origin,
            protected_resource_metadata,
            expected_method,
            expected_target,
        ),
        RemoteAuthMode::IntrospectionBearer { verifier } => {
            verifier
                .authenticate_token(
                    &token,
                    headers,
                    origin,
                    protected_resource_metadata,
                    expected_method,
                    expected_target,
                )
                .await
        }
    }
}

pub(super) fn remote_auth_mode_label(auth_mode: &RemoteAuthMode) -> &'static str {
    match auth_mode {
        RemoteAuthMode::StaticBearer { .. } => "static_bearer",
        RemoteAuthMode::JwtBearer { .. } => "jwt_bearer",
        RemoteAuthMode::IntrospectionBearer { .. } => "introspection_bearer",
    }
}

pub(super) fn validate_session_auth_context(
    request_auth_context: &SessionAuthContext,
    session_auth_context: &SessionAuthContext,
) -> Result<(), Response> {
    if request_auth_context.transport != session_auth_context.transport {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated transport does not match session",
        ));
    }
    if request_auth_context.origin != session_auth_context.origin {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated origin does not match session",
        ));
    }

    let matches = match (&request_auth_context.method, &session_auth_context.method) {
        (
            SessionAuthMethod::StaticBearer {
                principal: request_principal,
                token_fingerprint: request_fingerprint,
            },
            SessionAuthMethod::StaticBearer {
                principal: session_principal,
                token_fingerprint: session_fingerprint,
            },
        ) => request_principal == session_principal && request_fingerprint == session_fingerprint,
        (
            SessionAuthMethod::OAuthBearer {
                principal: request_principal,
                issuer: request_issuer,
                subject: request_subject,
                audience: request_audience,
                scopes: request_scopes,
                federated_claims: request_federated_claims,
                enterprise_identity: request_enterprise_identity,
                token_fingerprint: request_fingerprint,
                ..
            },
            SessionAuthMethod::OAuthBearer {
                principal: session_principal,
                issuer: session_issuer,
                subject: session_subject,
                audience: session_audience,
                scopes: session_scopes,
                federated_claims: session_federated_claims,
                enterprise_identity: session_enterprise_identity,
                token_fingerprint: session_fingerprint,
                ..
            },
        ) => {
            request_principal == session_principal
                && request_issuer == session_issuer
                && request_subject == session_subject
                && request_audience == session_audience
                && request_scopes == session_scopes
                && request_federated_claims == session_federated_claims
                && request_enterprise_identity == session_enterprise_identity
                && session_fingerprint
                    .as_ref()
                    .is_none_or(|session_fingerprint| {
                        request_fingerprint.as_ref() == Some(session_fingerprint)
                    })
        }
        (SessionAuthMethod::Anonymous, SessionAuthMethod::Anonymous) => true,
        _ => false,
    };

    if matches {
        Ok(())
    } else {
        Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated authorization context does not match session",
        ))
    }
}

pub(super) fn validate_session_lifecycle(session: &RemoteSession) -> Result<(), Response> {
    match session.lifecycle_snapshot().state {
        RemoteSessionState::Ready => Ok(()),
        RemoteSessionState::Initializing => Err(plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is still initializing",
        )),
        RemoteSessionState::Draining => Err(plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is draining and must not be resumed",
        )),
        RemoteSessionState::Deleted => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session was deleted and must be re-initialized",
        )),
        RemoteSessionState::Expired => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session expired and must be re-initialized",
        )),
        RemoteSessionState::Closed => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session was shut down and must be re-initialized",
        )),
    }
}

pub(super) fn serialize_session_lifecycle(
    lifecycle: &RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
) -> Value {
    json!({
        "state": lifecycle.state.as_str(),
        "createdAt": lifecycle.created_at,
        "lastSeenAt": lifecycle.last_seen_at,
        "idleExpiresAt": lifecycle.idle_expires_at,
        "drainDeadlineAt": lifecycle.drain_deadline_at,
        "protocolVersion": protocol_version,
        "reconnect": {
            "mode": "post-session-reuse-only",
            "resumable": lifecycle.state == RemoteSessionState::Ready,
            "requiresAuthContinuity": true,
            "terminalStates": ["draining", "deleted", "expired", "closed"],
        }
    })
}

pub(super) fn serialize_session_diagnostic_record(record: &RemoteSessionDiagnosticRecord) -> Value {
    json!({
        "sessionId": record.session_id,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": record.capabilities.iter().map(|capability| json!({
            "id": capability.id,
            "issuerPublicKey": capability.issuer_public_key,
            "subjectPublicKey": capability.subject_public_key,
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn extract_bearer_token(
    headers: &HeaderMap,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    header
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            unauthorized_bearer_response(
                "missing or invalid bearer token",
                protected_resource_metadata,
            )
        })
}

pub(super) fn unauthorized_bearer_response(
    message: &str,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Response {
    let mut response = plain_http_error(StatusCode::UNAUTHORIZED, message);
    let challenge = protected_resource_metadata
        .map(ProtectedResourceMetadata::bearer_challenge)
        .unwrap_or_else(|| "Bearer".to_string());
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
    );
    response
}

pub(super) fn validate_origin(headers: &HeaderMap) -> Result<(), Response> {
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return Ok(());
    };
    let parsed = Url::parse(origin)
        .map_err(|_| plain_http_error(StatusCode::FORBIDDEN, "invalid Origin header"))?;
    let Some(host) = parsed.host_str() else {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "invalid Origin header",
        ));
    };
    let host = host.trim_matches('[').trim_matches(']');
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::FORBIDDEN,
        "origin not allowed",
    ))
}

pub(super) fn validate_post_accept_header(headers: &HeaderMap) -> Result<(), Response> {
    let accept = headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if accept.contains("application/json") && accept.contains("text/event-stream") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::NOT_ACCEPTABLE,
        "POST requests must advertise both application/json and text/event-stream in Accept",
    ))
}

pub(super) fn validate_get_accept_header(headers: &HeaderMap) -> Result<(), Response> {
    let accept = headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if accept.contains("text/event-stream") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::NOT_ACCEPTABLE,
        "GET requests must advertise text/event-stream in Accept",
    ))
}

pub(super) fn validate_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.starts_with("application/json") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "POST requests must use Content-Type: application/json",
    ))
}

pub(super) fn validate_protocol_version(headers: &HeaderMap, session: &RemoteSession) -> Result<(), Response> {
    let Some(expected) = session.protocol_version() else {
        return Ok(());
    };
    let Some(actual) = headers
        .get(HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER))
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };

    if actual == expected {
        Ok(())
    } else {
        Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "invalid MCP-Protocol-Version for session",
        ))
    }
}

pub(super) fn build_static_bearer_session_auth_context(
    headers: &HeaderMap,
    expected_token: &str,
) -> SessionAuthContext {
    let token_fingerprint = sha256_hex(expected_token.as_bytes());
    let principal = format!(
        "static-bearer:{}",
        &token_fingerprint[..token_fingerprint.len().min(16)]
    );
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    SessionAuthContext::streamable_http_static_bearer(principal, token_fingerprint, origin)
}

impl JwtBearerVerifier {
    pub(super) fn authenticate_token(
        &self,
        token: &str,
        headers: &HeaderMap,
        origin: Option<String>,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
        expected_method: &str,
        expected_target: &str,
    ) -> Result<SessionAuthContext, Response> {
        let (header, claims, signed_input, signature) =
            decode_jwt_parts(token, protected_resource_metadata)?;
        let alg = JwtSignatureAlgorithm::from_header(&header, protected_resource_metadata)?;
        if !self.key_source.verify(
            alg,
            &header,
            signed_input.as_bytes(),
            &signature,
            protected_resource_metadata,
        )? {
            return Err(unauthorized_bearer_response(
                "invalid JWT bearer signature",
                protected_resource_metadata,
            ));
        }

        let now = unix_now();
        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(unauthorized_bearer_response(
                    "JWT bearer token not yet valid",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(exp) = claims.exp {
            if now >= exp {
                return Err(unauthorized_bearer_response(
                    "JWT bearer token expired",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_issuer) = self.issuer.as_deref() {
            if claims.iss.as_deref() != Some(expected_issuer) {
                return Err(unauthorized_bearer_response(
                    "JWT bearer issuer mismatch",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_audience) = self
            .audience
            .as_deref()
            .or_else(|| protected_resource_metadata.map(|metadata| metadata.resource.as_str()))
        {
            if !claims.includes_audience_or_resource(expected_audience) {
                return Err(unauthorized_bearer_response(
                    "JWT bearer audience mismatch",
                    protected_resource_metadata,
                ));
            }
        }
        let scopes = claims.scopes();
        if !self.required_scopes.is_empty()
            && !self
                .required_scopes
                .iter()
                .all(|scope| scopes.iter().any(|granted| granted == scope))
        {
            return Err(unauthorized_bearer_response(
                "JWT bearer token is missing required scope",
                protected_resource_metadata,
            ));
        }
        if let Some(value) = claims.authorization_details.clone() {
            let _ = parse_request_time_authorization_details_from_value(value).map_err(|_| {
                unauthorized_bearer_response(
                    "JWT bearer authorization_details claim is invalid",
                    protected_resource_metadata,
                )
            })?;
        }
        if let Some(value) = claims.chio_transaction_context.clone() {
            let context =
                parse_request_time_transaction_context_from_value(value).map_err(|_| {
                    unauthorized_bearer_response(
                        "JWT bearer chio_transaction_context claim is invalid",
                        protected_resource_metadata,
                    )
                })?;
            if context.identity_assertion.is_some() {
                let expected_client_id = claims.client_id.as_deref().ok_or_else(|| {
                    unauthorized_bearer_response(
                        "JWT bearer chio_transaction_context.identityAssertion requires client_id",
                        protected_resource_metadata,
                    )
                })?;
                validate_request_time_transaction_context_binding(
                    Some(&context),
                    expected_client_id,
                    None,
                )
                .map_err(|_| {
                    unauthorized_bearer_response(
                        "JWT bearer chio_transaction_context claim is invalid",
                        protected_resource_metadata,
                    )
                })?;
            }
        }
        validate_sender_constraint_runtime(
            claims.cnf.as_ref(),
            headers,
            claims.jti.as_deref(),
            expected_target,
            expected_method,
            &self.sender_dpop_nonce_store,
            &self.sender_dpop_config,
        )
        .map_err(|message| unauthorized_bearer_response(&message, protected_resource_metadata))?;

        let principal = Some(build_federated_principal(
            &claims,
            self.issuer.as_deref(),
            protected_resource_metadata,
            self.provider_profile,
        )?);
        let federated_claims = build_federated_claims(&claims, self.provider_profile);
        let matched_provider = matched_bearer_enterprise_provider(
            self.enterprise_provider_registry.as_deref(),
            claims.iss.as_deref().or(self.issuer.as_deref()),
            EnterpriseProviderKind::OidcJwks,
        );
        let enterprise_identity = principal.as_deref().map(|principal| {
            build_enterprise_identity_context(
                &claims,
                &federated_claims,
                principal,
                self.provider_profile,
                EnterpriseProviderKind::OidcJwks,
                matched_provider,
            )
        });
        let audience = self.audience.clone().or_else(|| {
            protected_resource_metadata
                .map(|metadata| metadata.resource.clone())
                .or_else(|| {
                    claims
                        .primary_audience()
                        .or_else(|| claims.resource.clone())
                })
        });
        Ok(
            SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                chio_core::OAuthBearerSessionAuthInput {
                    principal,
                    issuer: claims.iss.clone(),
                    subject: claims.sub.clone(),
                    audience,
                    scopes,
                    federated_claims,
                    enterprise_identity,
                    token_fingerprint: Some(sha256_hex(token.as_bytes())),
                    origin,
                },
            ),
        )
    }
}

pub(super) struct IntrospectionSessionAuthInput<'a> {
    pub(super) token: &'a str,
    pub(super) headers: &'a HeaderMap,
    pub(super) introspection: OAuthIntrospectionResponse,
    pub(super) origin: Option<String>,
    pub(super) protected_resource_metadata: Option<&'a ProtectedResourceMetadata>,
    pub(super) expected_method: &'a str,
    pub(super) expected_target: &'a str,
}

impl IntrospectionBearerVerifier {
    pub(super) async fn authenticate_token(
        &self,
        token: &str,
        headers: &HeaderMap,
        origin: Option<String>,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
        expected_method: &str,
        expected_target: &str,
    ) -> Result<SessionAuthContext, Response> {
        let mut request = self
            .client
            .post(self.introspection_url.clone())
            .form(&[("token", token)]);
        if let (Some(client_id), Some(client_secret)) =
            (self.client_id.as_deref(), self.client_secret.as_deref())
        {
            request = request.basic_auth(client_id, Some(client_secret));
        }
        let contract = self.egress_contract.as_ref().ok_or_else(|| {
            plain_http_error(
                StatusCode::BAD_GATEWAY,
                "token introspection requires an HttpEgressContract",
            )
        })?;
        let raw_request = request.build().map_err(|error| {
            plain_http_error(
                StatusCode::BAD_GATEWAY,
                &format!("failed to build token introspection request: {error}"),
            )
        })?;
        let response = send_with_contract(contract, &self.client, raw_request)
            .await
            .map_err(|error| {
            plain_http_error(
                StatusCode::BAD_GATEWAY,
                &format!("token introspection endpoint unavailable: {error}"),
            )
        })?;
        if !response.status().is_success() {
            return Err(plain_http_error(
                StatusCode::BAD_GATEWAY,
                "token introspection endpoint returned an error",
            ));
        }
        let introspection = response
            .json::<OAuthIntrospectionResponse>()
            .await
            .map_err(|error| {
                plain_http_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("token introspection endpoint returned invalid JSON: {error}"),
                )
            })?;
        self.session_auth_context_from_introspection(IntrospectionSessionAuthInput {
            token,
            headers,
            introspection,
            origin,
            protected_resource_metadata,
            expected_method,
            expected_target,
        })
    }

    pub(super) fn session_auth_context_from_introspection(
        &self,
        input: IntrospectionSessionAuthInput<'_>,
    ) -> Result<SessionAuthContext, Response> {
        if !input.introspection.active {
            return Err(unauthorized_bearer_response(
                "bearer token is inactive",
                input.protected_resource_metadata,
            ));
        }
        if let Some(token_type) = input.introspection.token_type.as_deref() {
            if !matches!(
                token_type,
                "Bearer"
                    | "bearer"
                    | "access_token"
                    | "urn:ietf:params:oauth:token-type:access_token"
            ) {
                return Err(unauthorized_bearer_response(
                    "introspection returned unsupported token_type",
                    input.protected_resource_metadata,
                ));
            }
        }

        let claims = input.introspection.claims;
        let now = unix_now();
        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(unauthorized_bearer_response(
                    "bearer token not yet valid",
                    input.protected_resource_metadata,
                ));
            }
        }
        if let Some(exp) = claims.exp {
            if now >= exp {
                return Err(unauthorized_bearer_response(
                    "bearer token expired",
                    input.protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_issuer) = self.issuer.as_deref() {
            if let Some(actual_issuer) = claims.iss.as_deref() {
                if actual_issuer != expected_issuer {
                    return Err(unauthorized_bearer_response(
                        "bearer token issuer mismatch",
                        input.protected_resource_metadata,
                    ));
                }
            }
        }
        if let Some(expected_audience) = self.audience.as_deref().or_else(|| {
            input
                .protected_resource_metadata
                .map(|metadata| metadata.resource.as_str())
        }) {
            if !claims.includes_audience_or_resource(expected_audience) {
                return Err(unauthorized_bearer_response(
                    "bearer token audience mismatch",
                    input.protected_resource_metadata,
                ));
            }
        }
        let scopes = claims.scopes();
        if !self.required_scopes.is_empty()
            && !self
                .required_scopes
                .iter()
                .all(|scope| scopes.iter().any(|granted| granted == scope))
        {
            return Err(unauthorized_bearer_response(
                "bearer token is missing required scope",
                input.protected_resource_metadata,
            ));
        }
        if let Some(value) = claims.authorization_details.clone() {
            let _ = parse_request_time_authorization_details_from_value(value).map_err(|_| {
                unauthorized_bearer_response(
                    "bearer authorization_details claim is invalid",
                    input.protected_resource_metadata,
                )
            })?;
        }
        if let Some(value) = claims.chio_transaction_context.clone() {
            let context =
                parse_request_time_transaction_context_from_value(value).map_err(|_| {
                    unauthorized_bearer_response(
                        "bearer chio_transaction_context claim is invalid",
                        input.protected_resource_metadata,
                    )
                })?;
            if context.identity_assertion.is_some() {
                let expected_client_id = claims.client_id.as_deref().ok_or_else(|| {
                    unauthorized_bearer_response(
                        "bearer chio_transaction_context.identityAssertion requires client_id",
                        input.protected_resource_metadata,
                    )
                })?;
                validate_request_time_transaction_context_binding(
                    Some(&context),
                    expected_client_id,
                    None,
                )
                .map_err(|_| {
                    unauthorized_bearer_response(
                        "bearer chio_transaction_context claim is invalid",
                        input.protected_resource_metadata,
                    )
                })?;
            }
        }
        validate_sender_constraint_runtime(
            claims.cnf.as_ref(),
            input.headers,
            claims.jti.as_deref(),
            input.expected_target,
            input.expected_method,
            &self.sender_dpop_nonce_store,
            &self.sender_dpop_config,
        )
        .map_err(|message| {
            unauthorized_bearer_response(&message, input.protected_resource_metadata)
        })?;

        let principal = Some(build_federated_principal(
            &claims,
            self.issuer.as_deref(),
            input.protected_resource_metadata,
            self.provider_profile,
        )?);
        let federated_claims = build_federated_claims(&claims, self.provider_profile);
        let matched_provider = matched_bearer_enterprise_provider(
            self.enterprise_provider_registry.as_deref(),
            claims.iss.as_deref().or(self.issuer.as_deref()),
            EnterpriseProviderKind::OauthIntrospection,
        );
        let enterprise_identity = principal.as_deref().map(|principal| {
            build_enterprise_identity_context(
                &claims,
                &federated_claims,
                principal,
                self.provider_profile,
                EnterpriseProviderKind::OauthIntrospection,
                matched_provider,
            )
        });
        let audience = self.audience.clone().or_else(|| {
            input
                .protected_resource_metadata
                .map(|metadata| metadata.resource.clone())
                .or_else(|| {
                    claims
                        .primary_audience()
                        .or_else(|| claims.resource.clone())
                })
        });
        Ok(
            SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                chio_core::OAuthBearerSessionAuthInput {
                    principal,
                    issuer: claims.iss.clone().or_else(|| self.issuer.clone()),
                    subject: claims.sub.clone(),
                    audience,
                    scopes,
                    federated_claims,
                    enterprise_identity,
                    token_fingerprint: Some(sha256_hex(input.token.as_bytes())),
                    origin: input.origin,
                },
            ),
        )
    }
}
