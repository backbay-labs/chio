use super::*;

struct TokenResponseInput {
    subject: String,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    authorization_details: Option<Vec<GovernedAuthorizationDetail>>,
    transaction_context: Option<GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
    grant_type: Option<String>,
}

struct SignedAccessTokenInput<'a> {
    subject: &'a str,
    client_id: &'a str,
    resource: &'a str,
    scopes: &'a [String],
    authorization_details: Option<&'a [GovernedAuthorizationDetail]>,
    transaction_context: Option<&'a GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<&'a ChioSenderConstraintClaims>,
}

impl LocalAuthorizationServer {
    pub(super) fn token_endpoint_url(&self) -> String {
        format!("{}/token", self.issuer.trim_end_matches('/'))
    }

    pub(super) fn authorization_page(&self, request: &AuthorizationRequest) -> Result<String, Response> {
        let resource = validate_authorization_request(
            request,
            &self.supported_scopes,
            &self.default_audience,
        )?;
        let scopes = resolve_requested_scopes(request.scope.as_deref(), &self.supported_scopes)?;
        let authorization_details =
            parse_request_time_authorization_details(request.authorization_details.as_deref())?;
        let transaction_context =
            parse_request_time_transaction_context(request.chio_transaction_context.as_deref())?;
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &request.client_id,
            None,
        )?;
        let sender_constraint = build_request_sender_constraint(
            request.chio_sender_dpop_public_key.as_deref(),
            request.chio_sender_mtls_thumbprint_sha256.as_deref(),
            request.chio_sender_attestation_sha256.as_deref(),
            transaction_context.as_ref(),
        )?;
        let state = request.state.clone().unwrap_or_default();
        let scopes_display = scopes.join(" ");
        let authorization_details_hidden =
            request.authorization_details.clone().unwrap_or_default();
        let transaction_context_hidden =
            request.chio_transaction_context.clone().unwrap_or_default();
        let sender_dpop_hidden = request
            .chio_sender_dpop_public_key
            .clone()
            .unwrap_or_default();
        let sender_mtls_hidden = request
            .chio_sender_mtls_thumbprint_sha256
            .clone()
            .unwrap_or_default();
        let sender_attestation_hidden = request
            .chio_sender_attestation_sha256
            .clone()
            .unwrap_or_default();
        let details_display = authorization_details
            .as_ref()
            .map_or("none".to_string(), |details| {
                format!("{} detail(s)", details.len())
            });
        let transaction_display = transaction_context
            .as_ref()
            .map_or("none".to_string(), |ctx| {
                let continuity = ctx
                    .identity_assertion
                    .as_ref()
                    .map(|assertion| {
                        format!(" / {} / {}", assertion.subject, assertion.continuity_id)
                    })
                    .unwrap_or_default();
                format!("{} / {}{}", ctx.intent_id, ctx.intent_hash, continuity)
            });
        let sender_constraint_display = sender_constraint.as_ref().map_or_else(
            || "none".to_string(),
            |constraint| {
                let mut parts = Vec::new();
                if constraint.chio_sender_key.is_some() {
                    parts.push("dpop");
                }
                if constraint.mtls_thumbprint_sha256.is_some() {
                    parts.push("mtls");
                }
                if constraint.chio_attestation_sha256.is_some() {
                    parts.push("attestation");
                }
                parts.join(" + ")
            },
        );
        Ok(format!(
            "<!doctype html><html><body><h1>Authorize MCP Access</h1><p>Client: {client}</p><p>Resource: {resource}</p><p>Subject: {subject}</p><p>Scopes: {scopes}</p><p>Chio Authorization Details: {details_display}</p><p>Chio Transaction Context: {transaction_display}</p><p>Sender Constraint: {sender_constraint_display}</p><form method=\"post\" action=\"{path}\"><input type=\"hidden\" name=\"response_type\" value=\"code\"><input type=\"hidden\" name=\"client_id\" value=\"{client}\"><input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect}\"><input type=\"hidden\" name=\"state\" value=\"{state}\"><input type=\"hidden\" name=\"scope\" value=\"{scope}\"><input type=\"hidden\" name=\"resource\" value=\"{resource}\"><input type=\"hidden\" name=\"authorization_details\" value=\"{authorization_details}\"><input type=\"hidden\" name=\"chio_transaction_context\" value=\"{transaction_context}\"><input type=\"hidden\" name=\"chio_sender_dpop_public_key\" value=\"{sender_dpop}\"><input type=\"hidden\" name=\"chio_sender_mtls_thumbprint_sha256\" value=\"{sender_mtls}\"><input type=\"hidden\" name=\"chio_sender_attestation_sha256\" value=\"{sender_attestation}\"><input type=\"hidden\" name=\"code_challenge\" value=\"{challenge}\"><input type=\"hidden\" name=\"code_challenge_method\" value=\"{method}\"><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></body></html>",
            client = html_escape(&request.client_id),
            redirect = html_escape(&request.redirect_uri),
            state = html_escape(&state),
            scope = html_escape(&scopes.join(" ")),
            resource = html_escape(&resource),
            subject = html_escape(&self.subject),
            scopes = html_escape(&scopes_display),
            details_display = html_escape(&details_display),
            transaction_display = html_escape(&transaction_display),
            sender_constraint_display = html_escape(&sender_constraint_display),
            authorization_details = html_escape(&authorization_details_hidden),
            transaction_context = html_escape(&transaction_context_hidden),
            sender_dpop = html_escape(&sender_dpop_hidden),
            sender_mtls = html_escape(&sender_mtls_hidden),
            sender_attestation = html_escape(&sender_attestation_hidden),
            challenge = html_escape(request.code_challenge.as_deref().unwrap_or_default()),
            method = html_escape(request.code_challenge_method.as_deref().unwrap_or_default()),
            path = LOCAL_AUTHORIZATION_PATH,
        ))
    }

    pub(super) fn approve_authorization(&self, form: AuthorizationApprovalForm) -> Result<Redirect, Response> {
        let request = AuthorizationRequest {
            response_type: form.response_type.clone(),
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            state: form.state.clone(),
            scope: form.scope.clone(),
            resource: form.resource.clone(),
            authorization_details: form.authorization_details.clone(),
            chio_transaction_context: form.chio_transaction_context.clone(),
            code_challenge: Some(form.code_challenge.clone()),
            code_challenge_method: Some(form.code_challenge_method.clone()),
            chio_sender_dpop_public_key: form.chio_sender_dpop_public_key.clone(),
            chio_sender_mtls_thumbprint_sha256: form.chio_sender_mtls_thumbprint_sha256.clone(),
            chio_sender_attestation_sha256: form.chio_sender_attestation_sha256.clone(),
        };
        let resource = validate_authorization_request(
            &request,
            &self.supported_scopes,
            &self.default_audience,
        )?;
        let authorization_details =
            parse_request_time_authorization_details(form.authorization_details.as_deref())?;
        let transaction_context =
            parse_request_time_transaction_context(form.chio_transaction_context.as_deref())?;
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &form.client_id,
            None,
        )?;
        let sender_constraint = build_request_sender_constraint(
            form.chio_sender_dpop_public_key.as_deref(),
            form.chio_sender_mtls_thumbprint_sha256.as_deref(),
            form.chio_sender_attestation_sha256.as_deref(),
            transaction_context.as_ref(),
        )?;
        if form.decision != "approve" {
            return Err(redirect_oauth_error(
                &form.redirect_uri,
                "access_denied",
                "authorization request denied",
                form.state.as_deref(),
            ));
        }

        let scopes = resolve_requested_scopes(form.scope.as_deref(), &self.supported_scopes)?;
        let code = generate_authorization_code();
        let grant = AuthorizationCodeGrant {
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            resource: resource.clone(),
            scopes,
            subject: self.subject.clone(),
            code_challenge: form.code_challenge,
            code_challenge_method: form.code_challenge_method,
            expires_at: unix_now().saturating_add(self.code_ttl_secs),
            authorization_details,
            transaction_context,
            sender_constraint,
        };
        match self.codes.lock() {
            Ok(mut guard) => {
                guard.insert(code.clone(), grant);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(code.clone(), grant);
            }
        }

        let mut redirect_uri = Url::parse(&form.redirect_uri)
            .map_err(|_| plain_http_error(StatusCode::BAD_REQUEST, "invalid redirect_uri"))?;
        {
            let mut pairs = redirect_uri.query_pairs_mut();
            pairs.append_pair("code", &code);
            if let Some(state) = form.state.as_deref() {
                pairs.append_pair("state", state);
            }
        }
        Ok(Redirect::to(redirect_uri.as_str()))
    }

    pub(super) fn exchange_token(
        &self,
        headers: &HeaderMap,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        match form.grant_type.as_str() {
            "authorization_code" => self.exchange_authorization_code(headers, form),
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                self.exchange_subject_token(headers, form)
            }
            _ => Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "unsupported grant_type",
            )),
        }
    }

    pub(super) fn exchange_authorization_code(
        &self,
        headers: &HeaderMap,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        let code = form.code.as_deref().ok_or_else(|| {
            oauth_token_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code")
        })?;
        let redirect_uri = form.redirect_uri.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            )
        })?;
        let client_id = form.client_id.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            )
        })?;
        let code_verifier = form.code_verifier.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing code_verifier",
            )
        })?;

        let grant = match self.codes.lock() {
            Ok(mut guard) => guard.remove(code),
            Err(poisoned) => poisoned.into_inner().remove(code),
        }
        .ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown authorization code",
            )
        })?;

        if unix_now() >= grant.expires_at {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code expired",
            ));
        }
        if grant.client_id != client_id || grant.redirect_uri != redirect_uri {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "client_id or redirect_uri mismatch",
            ));
        }
        if grant.code_challenge_method != "S256" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unsupported code_challenge_method",
            ));
        }
        if pkce_s256(code_verifier) != grant.code_challenge {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            ));
        }
        let resource = form.resource.unwrap_or(grant.resource.clone());
        if resource != grant.resource {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource parameter mismatch",
            ));
        }
        validate_sender_constraint_runtime(
            grant.sender_constraint.as_ref(),
            headers,
            Some(code),
            &self.token_endpoint_url(),
            "POST",
            &self.sender_dpop_nonce_store,
            &self.sender_dpop_config,
        )
        .map_err(|message| oauth_token_error(StatusCode::BAD_REQUEST, "invalid_grant", &message))?;

        Ok(self.issue_token_response(TokenResponseInput {
            subject: grant.subject,
            client_id: grant.client_id,
            resource,
            scopes: grant.scopes,
            authorization_details: grant.authorization_details,
            transaction_context: grant.transaction_context,
            sender_constraint: grant.sender_constraint,
            grant_type: Some("authorization_code".to_string()),
        }))
    }

    pub(super) fn exchange_subject_token(
        &self,
        headers: &HeaderMap,
        form: TokenRequestForm,
    ) -> Result<Value, Response> {
        let subject_token = form.subject_token.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing subject_token",
            )
        })?;
        let subject_token_type = form.subject_token_type.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing subject_token_type",
            )
        })?;
        if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "unsupported subject_token_type",
            ));
        }
        let resource = form
            .resource
            .unwrap_or_else(|| self.default_audience.clone());
        if resource != self.default_audience {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource parameter must match the advertised protected resource",
            ));
        }
        let (claims, _) = self.validate_subject_token(subject_token)?;
        validate_sender_constraint_runtime(
            claims.cnf.as_ref(),
            headers,
            claims.jti.as_deref(),
            &self.token_endpoint_url(),
            "POST",
            &self.sender_dpop_nonce_store,
            &self.sender_dpop_config,
        )
        .map_err(|message| oauth_token_error(StatusCode::BAD_REQUEST, "invalid_grant", &message))?;
        let subject = claims.sub.clone().unwrap_or_else(|| self.subject.clone());
        let client_id = claims
            .client_id
            .clone()
            .unwrap_or_else(|| "token-exchange".to_string());
        let scopes = resolve_exchange_scopes(
            form.scope.as_deref(),
            &claims.scopes(),
            &self.supported_scopes,
        )?;
        let authorization_details = match claims.authorization_details {
            Some(value) => Some(parse_request_time_authorization_details_from_value(value)?),
            None => None,
        };
        let transaction_context = match claims.chio_transaction_context {
            Some(value) => Some(parse_request_time_transaction_context_from_value(value)?),
            None => None,
        };
        validate_request_time_transaction_context_binding(
            transaction_context.as_ref(),
            &client_id,
            None,
        )?;

        Ok(self.issue_token_response(TokenResponseInput {
            subject,
            client_id,
            resource,
            scopes,
            authorization_details,
            transaction_context,
            sender_constraint: claims.cnf,
            grant_type: Some("urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
        }))
    }

    fn validate_subject_token(&self, token: &str) -> Result<(JwtClaims, String), Response> {
        let (header, claims, signed_input, signature) = decode_jwt_parts(token, None)?;
        let alg = JwtSignatureAlgorithm::from_header(&header, None)?;
        if alg != JwtSignatureAlgorithm::EdDsa
            || !verify_ed25519_jwt_signature(
                &self.signing_key.public_key(),
                signed_input.as_bytes(),
                &signature,
            )
        {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject token signature is invalid",
            ));
        }
        if claims.iss.as_deref() != Some(self.issuer.as_str()) {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject token issuer mismatch",
            ));
        }
        if let Some(exp) = claims.exp {
            if unix_now() >= exp {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "subject token expired",
                ));
            }
        }
        if let Some(value) = claims.authorization_details.clone() {
            let _ = parse_request_time_authorization_details_from_value(value)?;
        }
        if let Some(value) = claims.chio_transaction_context.clone() {
            let context = parse_request_time_transaction_context_from_value(value)?;
            if context.identity_assertion.is_some() {
                let expected_client_id = claims.client_id.as_deref().ok_or_else(|| {
                    oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "subject token chio_transaction_context.identityAssertion requires client_id",
                    )
                })?;
                validate_request_time_transaction_context_binding(
                    Some(&context),
                    expected_client_id,
                    None,
                )?;
            }
        }
        Ok((claims, signed_input))
    }

    fn issue_token_response(&self, input: TokenResponseInput) -> Value {
        let access_token = self.sign_access_token(SignedAccessTokenInput {
            subject: &input.subject,
            client_id: &input.client_id,
            resource: &input.resource,
            scopes: &input.scopes,
            authorization_details: input.authorization_details.as_deref(),
            transaction_context: input.transaction_context.as_ref(),
            sender_constraint: input.sender_constraint.as_ref(),
        });
        json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl_secs,
            "scope": input.scopes.join(" "),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "grant_type": input.grant_type,
        })
    }

    fn sign_access_token(&self, input: SignedAccessTokenInput<'_>) -> String {
        let now = unix_now();
        let issued_at_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let mut claims = json!({
            "iss": self.issuer,
            "sub": input.subject,
            "aud": input.resource,
            "scope": input.scopes.join(" "),
            "client_id": input.client_id,
            "resource": input.resource,
            "iat": now,
            "exp": now.saturating_add(self.access_token_ttl_secs),
            "jti": format!(
                "atk-{}",
                sha256_hex(
                    format!(
                        "{issued_at_nanos}:{}:{}:{}",
                        input.subject, input.client_id, input.resource
                    )
                        .as_bytes()
                )
            ),
        });
        if let Some(details) = input.authorization_details {
            claims[CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM] = json!(details);
        }
        if let Some(context) = input.transaction_context {
            claims[CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM] = json!(context);
        }
        if let Some(sender_constraint) = input
            .sender_constraint
            .filter(|sender_constraint| !sender_constraint.is_empty())
        {
            claims["cnf"] = json!(sender_constraint);
        }
        sign_jwt(&self.signing_key, &claims)
    }

    pub(super) fn jwks(&self) -> Value {
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": jwk_key_id(&self.signing_key.public_key()),
                "x": URL_SAFE_NO_PAD.encode(self.signing_key.public_key().as_bytes()),
            }]
        })
    }
}
