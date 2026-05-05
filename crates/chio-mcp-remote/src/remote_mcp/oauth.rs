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
    fn token_endpoint_url(&self) -> String {
        format!("{}/token", self.issuer.trim_end_matches('/'))
    }

    fn authorization_page(&self, request: &AuthorizationRequest) -> Result<String, Response> {
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

    fn approve_authorization(&self, form: AuthorizationApprovalForm) -> Result<Redirect, Response> {
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
        let code = format!(
            "code-{}",
            sha256_hex(
                format!("{}:{}:{}", form.client_id, form.redirect_uri, unix_now()).as_bytes()
            )
        );
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

    fn exchange_token(
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

    fn exchange_authorization_code(
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

    fn exchange_subject_token(
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

    fn jwks(&self) -> Value {
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

fn validate_authorization_request(
    request: &AuthorizationRequest,
    supported_scopes: &[String],
    expected_resource: &str,
) -> Result<String, Response> {
    if request.response_type != "code" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if request.client_id.trim().is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id must not be empty",
        ));
    }
    validate_redirect_uri(&request.redirect_uri)?;
    let resource = request.resource.clone().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "missing resource parameter",
        )
    })?;
    if resource != expected_resource {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource parameter must match the advertised protected resource",
        ));
    }
    let code_challenge = request.code_challenge.as_deref().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing code_challenge",
        )
    })?;
    if code_challenge.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "empty code_challenge",
        ));
    }
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    let _ = parse_request_time_authorization_details(request.authorization_details.as_deref())?;
    let _ = parse_request_time_transaction_context(request.chio_transaction_context.as_deref())?;
    let _ = resolve_requested_scopes(request.scope.as_deref(), supported_scopes)?;
    Ok(resource)
}

fn validate_redirect_uri(redirect_uri: &str) -> Result<(), Response> {
    let redirect = Url::parse(redirect_uri).map_err(|_| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        )
    })?;
    let Some(host) = redirect.host_str() else {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        ));
    };
    let is_localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if redirect.scheme() == "https" || (redirect.scheme() == "http" && is_localhost) {
        Ok(())
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri must use https or localhost",
        ))
    }
}

fn resolve_requested_scopes(
    requested_scope: Option<&str>,
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = requested_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if supported_scopes.is_empty() {
        return Ok(requested);
    }
    let scopes = if requested.is_empty() {
        supported_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| supported_scopes.iter().any(|supported| supported == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested scope is not supported",
        ))
    }
}

fn resolve_exchange_scopes(
    requested_scope: Option<&str>,
    subject_scopes: &[String],
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = resolve_requested_scopes(requested_scope, supported_scopes)?;
    let scopes = if requested.is_empty() {
        subject_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| subject_scopes.iter().any(|granted| granted == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested exchange scope exceeds subject token scope",
        ))
    }
}

fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": jwk_key_id(&keypair.public_key()),
        }))
        .unwrap_or_default(),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap_or_default());
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    format!("{signing_input}.{signature}")
}

fn jwk_key_id(public_key: &PublicKey) -> String {
    let hex = public_key.to_hex();
    format!("chio-{}", &hex[..hex.len().min(16)])
}

fn redirect_oauth_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut redirect = match Url::parse(redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_token_error(StatusCode::BAD_REQUEST, error, description),
    };
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    Redirect::to(redirect.as_str()).into_response()
}

fn oauth_token_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl ProtectedResourceMetadata {
    fn bearer_challenge(&self) -> String {
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

async fn authenticate_session_request(
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

fn remote_auth_mode_label(auth_mode: &RemoteAuthMode) -> &'static str {
    match auth_mode {
        RemoteAuthMode::StaticBearer { .. } => "static_bearer",
        RemoteAuthMode::JwtBearer { .. } => "jwt_bearer",
        RemoteAuthMode::IntrospectionBearer { .. } => "introspection_bearer",
    }
}

fn validate_session_auth_context(
    request_auth_context: &SessionAuthContext,
    session_auth_context: &SessionAuthContext,
) -> Result<(), Response> {
    if request_auth_context.transport != session_auth_context.transport {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated transport does not match session",
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

fn validate_session_lifecycle(session: &RemoteSession) -> Result<(), Response> {
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

fn serialize_session_lifecycle(
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

fn serialize_session_diagnostic_record(record: &RemoteSessionDiagnosticRecord) -> Value {
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

fn extract_bearer_token(
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

fn unauthorized_bearer_response(
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

fn validate_origin(headers: &HeaderMap) -> Result<(), Response> {
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

fn validate_post_accept_header(headers: &HeaderMap) -> Result<(), Response> {
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

fn validate_get_accept_header(headers: &HeaderMap) -> Result<(), Response> {
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

fn validate_content_type(headers: &HeaderMap) -> Result<(), Response> {
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

fn validate_protocol_version(headers: &HeaderMap, session: &RemoteSession) -> Result<(), Response> {
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

fn build_static_bearer_session_auth_context(
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
    fn authenticate_token(
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

struct IntrospectionSessionAuthInput<'a> {
    token: &'a str,
    headers: &'a HeaderMap,
    introspection: OAuthIntrospectionResponse,
    origin: Option<String>,
    protected_resource_metadata: Option<&'a ProtectedResourceMetadata>,
    expected_method: &'a str,
    expected_target: &'a str,
}

impl IntrospectionBearerVerifier {
    async fn authenticate_token(
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
        let response = request.send().await.map_err(|error| {
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

    fn session_auth_context_from_introspection(
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

impl JwtVerificationKeySource {
    fn verify(
        &self,
        alg: JwtSignatureAlgorithm,
        header: &JwtHeader,
        signed_input: &[u8],
        signature: &[u8],
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<bool, Response> {
        match self {
            Self::Static(public_key) => {
                if alg != JwtSignatureAlgorithm::EdDsa {
                    return Err(unauthorized_bearer_response(
                        "JWT bearer token uses unsupported alg for configured static key",
                        protected_resource_metadata,
                    ));
                }
                Ok(verify_ed25519_jwt_signature(
                    public_key,
                    signed_input,
                    signature,
                ))
            }
            Self::Jwks(keys) => {
                let public_key =
                    keys.resolve(header.kid.as_deref(), alg, protected_resource_metadata)?;
                Ok(public_key.verify(alg, signed_input, signature))
            }
        }
    }
}

impl JwtJwksKeySet {
    fn resolve<'a>(
        &'a self,
        kid: Option<&str>,
        alg: JwtSignatureAlgorithm,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<&'a JwtResolvedJwkPublicKey, Response> {
        if let Some(kid) = kid {
            let key = self.keys_by_kid.get(kid).ok_or_else(|| {
                unauthorized_bearer_response(
                    "JWT bearer kid is not trusted",
                    protected_resource_metadata,
                )
            })?;
            if key.supports_alg(alg) {
                return Ok(key);
            }
            return Err(unauthorized_bearer_response(
                "trusted JWT key does not support the requested alg",
                protected_resource_metadata,
            ));
        }
        let mut compatible = self
            .keys_by_kid
            .values()
            .chain(self.anonymous_keys.iter())
            .filter(|key| key.supports_alg(alg));
        let Some(first) = compatible.next() else {
            return Err(unauthorized_bearer_response(
                "identity provider exposes no trusted key for the requested alg",
                protected_resource_metadata,
            ));
        };
        if compatible.next().is_none() {
            return Ok(first);
        }
        Err(unauthorized_bearer_response(
            "JWT bearer token missing kid for multi-key identity provider",
            protected_resource_metadata,
        ))
    }
}

impl JwtResolvedJwkPublicKey {
    fn supports_alg(&self, alg: JwtSignatureAlgorithm) -> bool {
        if let Some(alg_hint) = self.alg_hint.as_deref() {
            if alg_hint != alg.as_str() {
                return false;
            }
        }
        matches!(
            (&self.key, alg),
            (
                JwtResolvedPublicKey::Ed25519(_),
                JwtSignatureAlgorithm::EdDsa
            ) | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs512)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps512)
                | (JwtResolvedPublicKey::P256(_), JwtSignatureAlgorithm::Es256)
                | (JwtResolvedPublicKey::P384(_), JwtSignatureAlgorithm::Es384)
        )
    }

    fn verify(&self, alg: JwtSignatureAlgorithm, signed_input: &[u8], signature: &[u8]) -> bool {
        if !self.supports_alg(alg) {
            return false;
        }
        match (&self.key, alg) {
            (JwtResolvedPublicKey::Ed25519(public_key), JwtSignatureAlgorithm::EdDsa) => {
                verify_ed25519_jwt_signature(public_key, signed_input, signature)
            }
            (JwtResolvedPublicKey::P256(public_key), JwtSignatureAlgorithm::Es256) => {
                P256Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::P384(public_key), JwtSignatureAlgorithm::Es384) => {
                P384Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs256) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs384) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs512) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps256) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps384) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps512) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            _ => false,
        }
    }
}

impl JwtClaims {
    fn scopes(&self) -> Vec<String> {
        let mut scopes = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        scopes.extend(self.scp.iter().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }

    fn includes_audience(&self, expected: &str) -> bool {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => audience == expected,
            Some(JwtAudience::Multiple(audiences)) => audiences.iter().any(|aud| aud == expected),
            None => false,
        }
    }

    fn includes_audience_or_resource(&self, expected: &str) -> bool {
        self.includes_audience(expected) || self.resource.as_deref() == Some(expected)
    }

    fn primary_audience(&self) -> Option<String> {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => Some(audience.clone()),
            Some(JwtAudience::Multiple(audiences)) => audiences.first().cloned(),
            None => None,
        }
    }
}

fn decode_jwt_parts(
    token: &str,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<(JwtHeader, JwtClaims, String, Vec<u8>), Response> {
    let mut parts = token.split('.');
    let Some(header_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(payload_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(signature_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    if parts.next().is_some() {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    }

    let header: JwtHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?;
    let claims: JwtClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| {
        unauthorized_bearer_response("invalid JWT signature", protected_resource_metadata)
    })?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{payload_b64}"),
        signature_bytes,
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn session_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn read_session_lifecycle_policy() -> SessionLifecyclePolicy {
    SessionLifecyclePolicy {
        idle_expiry_millis: read_env_u64(
            SESSION_IDLE_EXPIRY_ENV,
            Some(LEGACY_SESSION_IDLE_EXPIRY_ENV),
            DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
        ),
        drain_grace_millis: read_env_u64(
            SESSION_DRAIN_GRACE_ENV,
            Some(LEGACY_SESSION_DRAIN_GRACE_ENV),
            DEFAULT_SESSION_DRAIN_GRACE_MILLIS,
        ),
        reaper_interval_millis: read_env_u64(
            SESSION_REAPER_INTERVAL_ENV,
            Some(LEGACY_SESSION_REAPER_INTERVAL_ENV),
            DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
        ),
        tombstone_retention_millis: read_env_u64(
            SESSION_TOMBSTONE_RETENTION_ENV,
            Some(LEGACY_SESSION_TOMBSTONE_RETENTION_ENV),
            DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
        ),
    }
}

fn read_env_u64(name: &str, legacy_name: Option<&str>, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .or_else(|| legacy_name.and_then(|legacy_name| std::env::var(legacy_name).ok()))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn terminal_session_response(state: RemoteSessionState) -> Response {
    match state {
        RemoteSessionState::Initializing => {
            plain_http_error(StatusCode::CONFLICT, "MCP session is still initializing")
        }
        RemoteSessionState::Ready => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "active session was resolved as terminal",
        ),
        RemoteSessionState::Draining => plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is draining and must not be resumed",
        ),
        RemoteSessionState::Deleted => plain_http_error(
            StatusCode::GONE,
            "MCP session was deleted and must be re-initialized",
        ),
        RemoteSessionState::Expired => plain_http_error(
            StatusCode::GONE,
            "MCP session expired and must be re-initialized",
        ),
        RemoteSessionState::Closed => plain_http_error(
            StatusCode::GONE,
            "MCP session was shut down and must be re-initialized",
        ),
    }
}

fn plain_http_error(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

fn jsonrpc_http_error(status: StatusCode, code: i64, message: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
