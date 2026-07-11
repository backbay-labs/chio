fn should_emit_post_stream_event(
    event: &RemoteSessionEvent,
    request_id: Option<&Value>,
    notification_stream_attached: bool,
) -> bool {
    match event.kind {
        RemoteSessionEventKind::Notification => !notification_stream_attached,
        RemoteSessionEventKind::RequestCorrelated => {
            request_id.is_none_or(|request_id| {
                is_terminal_response_for_request(&event.message, request_id)
            }) || event.message.get("method").is_some()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum McpSessionIdHeader {
    Missing,
    Invalid,
    Valid(String),
}

fn mcp_session_id_header(headers: &HeaderMap) -> McpSessionIdHeader {
    let Some(value) = headers.get(HeaderName::from_static(MCP_SESSION_ID_HEADER)) else {
        return McpSessionIdHeader::Missing;
    };
    let Ok(session_id) = value.to_str() else {
        return McpSessionIdHeader::Invalid;
    };
    if session_id.is_empty() || session_id.trim() != session_id {
        return McpSessionIdHeader::Invalid;
    }
    McpSessionIdHeader::Valid(session_id.to_owned())
}

fn jsonrpc_session_id_from_headers(
    headers: &HeaderMap,
    missing_message: &str,
) -> Result<String, Response> {
    match mcp_session_id_header(headers) {
        McpSessionIdHeader::Valid(session_id) => Ok(session_id),
        McpSessionIdHeader::Missing => Err(jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            missing_message,
        )),
        McpSessionIdHeader::Invalid => Err(jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "invalid MCP-Session-Id",
        )),
    }
}

fn plain_session_id_from_headers(
    headers: &HeaderMap,
    missing_message: &str,
) -> Result<String, Response> {
    match mcp_session_id_header(headers) {
        McpSessionIdHeader::Valid(session_id) => Ok(session_id),
        McpSessionIdHeader::Missing => {
            Err(plain_http_error(StatusCode::BAD_REQUEST, missing_message))
        }
        McpSessionIdHeader::Invalid => {
            Err(plain_http_error(StatusCode::BAD_REQUEST, "invalid MCP-Session-Id"))
        }
    }
}

async fn resolve_session_entry(
    state: &RemoteAppState,
    session_id: &str,
) -> Option<RemoteSessionEntry> {
    state.sessions.cleanup_due_sessions().await;
    state.sessions.lookup(session_id).await
}

async fn session_reaper_loop(
    state: RemoteAppState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval =
        std::time::Duration::from_millis(state.factory.lifecycle_policy.reaper_interval_millis);
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        // Race the reaper interval against the shutdown signal so the loop stops
        // promptly during a drain rather than after a full interval.
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
        state.sessions.cleanup_due_sessions().await;
    }
}

fn build_remote_auth_state(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
) -> Result<(RemoteAuthMode, Option<Arc<str>>), CliError> {
    let auth_mode = build_remote_auth_mode(
        config,
        Some(local_addr),
        discovered_identity_provider,
        enterprise_provider_registry.clone(),
    )?;

    let admin_token = if let Some(token) = config.admin_token.as_deref() {
        Some(validated_static_bearer_token(token, "--admin-token")?)
    } else if let Some(token) = config.auth_token.as_deref() {
        Some(validated_static_bearer_token(token, "--auth-token")?)
    } else {
        return Err(CliError::cli_other_error(
            "bearer-authenticated remote MCP edge requires --admin-token for admin APIs"
                .to_string(),
        ));
    };

    Ok((auth_mode, admin_token))
}

fn validated_static_bearer_token(token: &str, flag: &str) -> Result<Arc<str>, CliError> {
    if token.trim().is_empty() || token.trim() != token || token.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "{flag} must be non-empty, unpadded, and control-free"
        )));
    }
    Ok(Arc::<str>::from(token.to_string()))
}

fn build_chio_oauth_authorization_profile_metadata() -> Result<Value, CliError> {
    let mut value =
        serde_json::to_value(ChioOAuthAuthorizationProfile::default()).map_err(|error| {
            CliError::cli_other_error(format!(
                "serialize Chio authorization profile metadata: {error}"
            ))
        })?;
    value["discoveryInformationalOnly"] = json!(true);
    Ok(value)
}

fn validate_chio_oauth_authorization_profile_metadata(
    value: &Value,
    source: &str,
) -> Result<(), CliError> {
    let expected_profile = ChioOAuthAuthorizationProfile::default();
    let profile: ChioOAuthAuthorizationProfile =
        serde_json::from_value(value.clone()).map_err(|error| {
            CliError::cli_other_error(format!(
                "{source} contains invalid Chio authorization profile metadata: {error}"
            ))
        })?;
    if profile.schema != CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio authorization profile schema `{CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA}`"
        )));
    }
    if profile.id != CHIO_OAUTH_AUTHORIZATION_PROFILE_ID {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio authorization profile id `{CHIO_OAUTH_AUTHORIZATION_PROFILE_ID}`"
        )));
    }
    if profile.sender_constraints.subject_binding != CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise subject binding `{CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT}`"
        )));
    }
    if !profile
        .sender_constraints
        .proof_types_supported
        .iter()
        .any(|proof| proof == CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP)
    {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio sender proof type `{CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP}`"
        )));
    }
    if profile.portable_claim_catalog != expected_profile.portable_claim_catalog {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's supported portable claim catalog"
        )));
    }
    if profile.portable_identity_binding != expected_profile.portable_identity_binding {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's supported portable identity binding contract"
        )));
    }
    if profile.governed_auth_binding != expected_profile.governed_auth_binding {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's governed authorization binding contract"
        )));
    }
    if profile.request_time_contract != expected_profile.request_time_contract {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's request-time authorization contract"
        )));
    }
    if profile.resource_binding != expected_profile.resource_binding {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's resource indicator binding contract"
        )));
    }
    if profile.artifact_boundary != expected_profile.artifact_boundary {
        return Err(CliError::cli_other_error(format!(
            "{source} must advertise Chio's runtime artifact boundary contract"
        )));
    }
    Ok(())
}

fn validate_chio_oauth_discovery_metadata_pair(
    protected_resource_metadata: &ProtectedResourceMetadata,
    authorization_server_metadata: &AuthorizationServerMetadata,
) -> Result<(), CliError> {
    validate_chio_oauth_authorization_profile_metadata(
        &protected_resource_metadata.chio_authorization_profile,
        "protected-resource metadata",
    )?;
    let authorization_profile = authorization_server_metadata
        .document
        .get("chio_authorization_profile")
        .ok_or_else(|| {
            CliError::cli_other_error(
                "authorization-server metadata must publish chio_authorization_profile".to_string(),
            )
        })?;
    validate_chio_oauth_authorization_profile_metadata(
        authorization_profile,
        "authorization-server metadata",
    )?;
    if authorization_profile != &protected_resource_metadata.chio_authorization_profile {
        return Err(CliError::cli_other_error(
            "authorization-server metadata chio_authorization_profile must match protected-resource metadata"
                .to_string(),
        ));
    }
    let issuer = authorization_server_metadata
        .document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::cli_other_error(
                "authorization-server metadata must include an issuer for Chio discovery validation"
                    .to_string(),
            )
        })?;
    if !protected_resource_metadata
        .authorization_servers
        .iter()
        .any(|server| server == issuer)
    {
        return Err(CliError::cli_other_error(format!(
            "protected-resource metadata does not advertise authorization server issuer `{issuer}`"
        )));
    }
    Ok(())
}

fn build_protected_resource_metadata(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
) -> Result<Option<ProtectedResourceMetadata>, CliError> {
    if matches!(
        build_remote_auth_mode(config, Some(local_addr), discovered_identity_provider, None,)?,
        RemoteAuthMode::StaticBearer { .. }
    ) {
        return Ok(None);
    }

    let authorization_servers = if !config.auth_servers.is_empty() {
        config.auth_servers.clone()
    } else if let Some(issuer) = resolve_local_auth_issuer(config, local_addr)? {
        vec![issuer]
    } else if let Some(discovered) = discovered_identity_provider {
        vec![discovered.issuer.clone()]
    } else if let Some(issuer) = config.auth_jwt_issuer.clone() {
        vec![issuer]
    } else {
        return Err(CliError::cli_other_error(
            "bearer-authenticated remote MCP edge requires --auth-server or --auth-jwt-issuer so protected-resource metadata can advertise an authorization server".to_string(),
        ));
    };

    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    let chio_authorization_profile = build_chio_oauth_authorization_profile_metadata()?;
    Ok(Some(ProtectedResourceMetadata {
        resource: effective_resource_indicator(config, &base_url),
        resource_metadata_url: format!("{base_url}{PROTECTED_RESOURCE_METADATA_MCP_PATH}"),
        authorization_servers,
        scopes_supported: config.auth_scopes.clone(),
        chio_authorization_profile,
    }))
}

fn build_authorization_server_metadata(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
) -> Result<Option<AuthorizationServerMetadata>, CliError> {
    if matches!(
        build_remote_auth_mode(config, Some(local_addr), discovered_identity_provider, None,)?,
        RemoteAuthMode::StaticBearer { .. }
    ) {
        return Ok(None);
    }

    if let Some(issuer) = resolve_local_auth_issuer(config, local_addr)? {
        let issuer = Url::parse(&issuer)
            .map_err(|error| CliError::cli_other_error(format!("invalid local auth issuer: {error}")))?;
        let metadata_path = metadata_path_for_issuer(&issuer);
        let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
        let chio_authorization_profile = build_chio_oauth_authorization_profile_metadata()?;
        let mut document = json!({
            "issuer": issuer.as_str(),
            "authorization_endpoint": format!("{base_url}{LOCAL_AUTHORIZATION_PATH}"),
            "token_endpoint": format!("{base_url}{LOCAL_TOKEN_PATH}"),
            "jwks_uri": format!("{base_url}{LOCAL_JWKS_PATH}"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "chio_authorization_profile": chio_authorization_profile,
        });
        if !config.auth_scopes.is_empty() {
            document["scopes_supported"] = json!(config.auth_scopes);
        }
        return Ok(Some(AuthorizationServerMetadata {
            metadata_path,
            document,
        }));
    }

    let issuer = config
        .auth_jwt_issuer
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| discovered_identity_provider.map(|provider| provider.issuer.clone()));
    let authorization_endpoint = config
        .auth_authorization_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider
                .and_then(|provider| provider.authorization_endpoint.clone())
        });
    let token_endpoint = config
        .auth_token_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider.and_then(|provider| provider.token_endpoint.clone())
        });

    let (Some(issuer), Some(authorization_endpoint), Some(token_endpoint)) = (
        issuer.as_deref(),
        authorization_endpoint.as_deref(),
        token_endpoint.as_deref(),
    ) else {
        return Ok(None);
    };

    let issuer = Url::parse(issuer).map_err(|error| {
        CliError::cli_other_error(format!(
            "invalid --auth-jwt-issuer for authorization-server metadata: {error}"
        ))
    })?;
    let public_base_url = Url::parse(&normalize_public_base_url(
        config.public_base_url.as_deref(),
        local_addr,
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "invalid public base URL for authorization-server metadata: {error}"
        ))
    })?;

    if !same_origin(&issuer, &public_base_url) {
        return Ok(None);
    }

    let metadata_path = metadata_path_for_issuer(&issuer);
    let chio_authorization_profile = build_chio_oauth_authorization_profile_metadata()?;
    let mut document = json!({
        "issuer": issuer.as_str(),
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "chio_authorization_profile": chio_authorization_profile,
    });
    if !config.auth_scopes.is_empty() {
        document["scopes_supported"] = json!(config.auth_scopes);
    }
    if let Some(registration_endpoint) = config
        .auth_registration_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider.and_then(|provider| provider.registration_endpoint.clone())
        })
    {
        document["registration_endpoint"] = json!(registration_endpoint);
    }
    if let Some(jwks_uri) = config
        .auth_jwks_uri
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| discovered_identity_provider.and_then(|provider| provider.jwks_uri.clone()))
    {
        document["jwks_uri"] = json!(jwks_uri);
    }

    Ok(Some(AuthorizationServerMetadata {
        metadata_path,
        document,
    }))
}

fn build_remote_auth_mode(
    config: &RemoteServeHttpConfig,
    local_addr: Option<SocketAddr>,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
) -> Result<RemoteAuthMode, CliError> {
    let has_external_discovery = discovered_identity_provider.is_some()
        || config.auth_jwt_discovery_url.is_some()
        || config.auth_jwt_provider_profile.is_some();
    let has_introspection = config.auth_introspection_url.is_some();
    let provider_profile = config
        .auth_jwt_provider_profile
        .unwrap_or(JwtProviderProfile::Generic);
    let (sender_dpop_nonce_store, sender_dpop_config) = build_sender_dpop_runtime();

    if config.auth_token.is_some()
        && (config.auth_jwt_public_key.is_some()
            || config.auth_server_seed_path.is_some()
            || has_external_discovery
            || has_introspection)
    {
        return Err(CliError::cli_other_error(
            "use either --auth-token or OAuth bearer auth flags, not both".to_string(),
        ));
    }
    if config.auth_server_seed_path.is_some()
        && (config.auth_jwt_public_key.is_some() || has_external_discovery || has_introspection)
    {
        return Err(CliError::cli_other_error(
            "use either --auth-jwt-public-key / discovery flags or --auth-server-seed-file, not both"
                .to_string(),
        ));
    }
    if config.auth_introspection_client_id.is_some()
        != config.auth_introspection_client_secret.is_some()
    {
        return Err(CliError::cli_other_error(
            "--auth-introspection-client-id and --auth-introspection-client-secret must be provided together"
                .to_string(),
        ));
    }
    if has_introspection && config.auth_jwt_public_key.is_some() {
        return Err(CliError::cli_other_error(
            "use either JWT verification flags or --auth-introspection-url, not both".to_string(),
        ));
    }

    if let Some(token) = config.auth_token.as_deref() {
        return Ok(RemoteAuthMode::StaticBearer {
            token: validated_static_bearer_token(token, "--auth-token")?,
        });
    }

    if let Some(seed_path) = config.auth_server_seed_path.as_deref() {
        return Ok(RemoteAuthMode::JwtBearer {
            verifier: Arc::new(JwtBearerVerifier {
                key_source: JwtVerificationKeySource::Static(
                    load_or_create_authority_keypair(seed_path)?.public_key(),
                ),
                issuer: config.auth_jwt_issuer.clone().or_else(|| {
                    local_addr
                        .map(|addr| {
                            normalize_public_base_url(config.public_base_url.as_deref(), addr)
                        })
                        .transpose()
                        .ok()
                        .flatten()
                        .map(|base_url| format!("{base_url}/oauth"))
                }),
                audience: config.auth_jwt_audience.clone(),
                required_scopes: config.auth_scopes.clone(),
                provider_profile,
                enterprise_provider_registry: enterprise_provider_registry.clone(),
                sender_dpop_nonce_store,
                sender_dpop_config,
            }),
        });
    }

    if let Some(introspection_url) = config.auth_introspection_url.as_deref() {
        // HttpEgressContract: every introspection-endpoint dispatch must run
        // through the typed egress contract. We thread the kernel-level
        // contract here; without one the verifier substrate fails closed at
        // dispatch time.
        let parsed_introspection_url =
            parse_identity_provider_url(introspection_url, "--auth-introspection-url")?;
        let egress_contract = config.egress_contract.clone().ok_or_else(|| {
            CliError::cli_other_error(
                "--auth-introspection-url requires an HttpEgressContract; substrate fails closed"
                    .to_string(),
            )
        })?;
        egress_contract
            .enforce_url_with_dns(parsed_introspection_url.as_str(), 0)
            .map_err(|err| {
                CliError::cli_other_error(format!(
                    "HttpEgressContract rejects introspection URL: {err}"
                ))
            })?;
        return Ok(RemoteAuthMode::IntrospectionBearer {
            verifier: Arc::new(IntrospectionBearerVerifier {
                client: client_builder_with_contract(&egress_contract)
                    .timeout(Duration::from_secs(TOKEN_INTROSPECTION_TIMEOUT_SECS))
                    .build()
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to build token introspection client: {error}"
                        ))
                    })?,
                introspection_url: parsed_introspection_url,
                client_id: config.auth_introspection_client_id.clone(),
                client_secret: config.auth_introspection_client_secret.clone(),
                issuer: config
                    .auth_jwt_issuer
                    .clone()
                    .or_else(|| {
                        discovered_identity_provider.map(|provider| provider.issuer.clone())
                    })
                    .or_else(|| {
                        local_addr
                            .map(|addr| {
                                normalize_public_base_url(config.public_base_url.as_deref(), addr)
                            })
                            .transpose()
                            .ok()
                            .flatten()
                            .map(|base_url| format!("{base_url}/oauth"))
                    }),
                audience: config.auth_jwt_audience.clone(),
                required_scopes: config.auth_scopes.clone(),
                provider_profile,
                enterprise_provider_registry: enterprise_provider_registry.clone(),
                sender_dpop_nonce_store,
                sender_dpop_config,
                egress_contract: Some(egress_contract),
            }),
        });
    }

    let key_source = if let Some(public_key_hex) = config.auth_jwt_public_key.as_deref() {
        JwtVerificationKeySource::Static(PublicKey::from_hex(public_key_hex)?)
    } else if let Some(discovered) = discovered_identity_provider {
        JwtVerificationKeySource::Jwks(discovered.jwks_keys.clone().ok_or_else(|| {
            CliError::cli_other_error(
                "OIDC discovery did not resolve any compatible signing keys for JWT verification"
                    .to_string(),
            )
        })?)
    } else {
        return Err(CliError::cli_other_error(
            "remote MCP edge requires either --auth-token, --auth-jwt-public-key, --auth-jwt-discovery-url, --auth-introspection-url, or --auth-server-seed-file"
                .to_string(),
        ));
    };

    Ok(RemoteAuthMode::JwtBearer {
        verifier: Arc::new(JwtBearerVerifier {
            key_source,
            issuer: config
                .auth_jwt_issuer
                .clone()
                .or_else(|| discovered_identity_provider.map(|provider| provider.issuer.clone()))
                .or_else(|| {
                    local_addr
                        .map(|addr| {
                            normalize_public_base_url(config.public_base_url.as_deref(), addr)
                        })
                        .transpose()
                        .ok()
                        .flatten()
                        .map(|base_url| format!("{base_url}/oauth"))
                }),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile,
            enterprise_provider_registry,
            sender_dpop_nonce_store,
            sender_dpop_config,
        }),
    })
}

fn build_sender_dpop_runtime() -> (Arc<DpopNonceStore>, DpopConfig) {
    let config = DpopConfig::default();
    let store = Arc::new(DpopNonceStore::new(
        config.nonce_store_capacity,
        Duration::from_secs(config.proof_ttl_secs),
    ));
    (store, config)
}

fn resolve_local_auth_issuer(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
) -> Result<Option<String>, CliError> {
    if config.auth_server_seed_path.is_none() {
        return Ok(None);
    }
    if let Some(issuer) = config.auth_jwt_issuer.as_deref() {
        return Ok(Some(issuer.to_string()));
    }
    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    Ok(Some(format!("{base_url}/oauth")))
}

fn build_local_auth_server(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
) -> Result<Option<LocalAuthorizationServer>, CliError> {
    let Some(seed_path) = config.auth_server_seed_path.as_deref() else {
        return Ok(None);
    };
    let signing_key = load_or_create_authority_keypair(seed_path)?;
    let issuer = resolve_local_auth_issuer(config, local_addr)?
        .ok_or_else(|| CliError::cli_other_error("failed to resolve local auth issuer".to_string()))?;
    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    let default_audience = effective_resource_indicator(config, &base_url);
    let (sender_dpop_nonce_store, sender_dpop_config) = build_sender_dpop_runtime();
    Ok(Some(LocalAuthorizationServer {
        signing_key,
        issuer,
        default_audience,
        supported_scopes: config.auth_scopes.clone(),
        subject: config.auth_subject.clone(),
        code_ttl_secs: config.auth_code_ttl_secs,
        access_token_ttl_secs: config.auth_access_token_ttl_secs,
        codes: Arc::new(StdMutex::new(HashMap::new())),
        sender_dpop_nonce_store,
        sender_dpop_config,
    }))
}

fn normalize_public_base_url(
    public_base_url: Option<&str>,
    local_addr: SocketAddr,
) -> Result<String, CliError> {
    let base_url = public_base_url
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("http://{local_addr}"));
    let parsed = Url::parse(&base_url).map_err(|error| {
        CliError::cli_other_error(format!(
            "invalid --public-base-url for remote MCP edge: {error}"
        ))
    })?;
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn metadata_path_for_issuer(issuer: &Url) -> String {
    let issuer_path = issuer.path().trim_matches('/');
    if issuer_path.is_empty() {
        AUTHORIZATION_SERVER_METADATA_PATH.to_string()
    } else {
        format!("{AUTHORIZATION_SERVER_METADATA_PATH}/{issuer_path}")
    }
}

fn effective_resource_indicator(config: &RemoteServeHttpConfig, base_url: &str) -> String {
    config
        .auth_jwt_audience
        .clone()
        .unwrap_or_else(|| format!("{base_url}{MCP_ENDPOINT_PATH}"))
}

fn parse_request_time_authorization_details_from_value(
    value: Value,
) -> Result<Vec<GovernedAuthorizationDetail>, Response> {
    let details: Vec<GovernedAuthorizationDetail> =
        serde_json::from_value(value).map_err(|error| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!(
                    "{} must be a JSON array of Chio governed authorization details: {error}",
                    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER
                ),
            )
        })?;
    validate_request_time_authorization_details(&details)?;
    Ok(details)
}

fn parse_request_time_authorization_details(
    raw: Option<&str>,
) -> Result<Option<Vec<GovernedAuthorizationDetail>>, Response> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!(
                "{} must be valid JSON: {error}",
                CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER
            ),
        )
    })?;
    parse_request_time_authorization_details_from_value(value).map(Some)
}

fn parse_request_time_transaction_context_from_value(
    value: Value,
) -> Result<GovernedAuthorizationTransactionContext, Response> {
    let context: GovernedAuthorizationTransactionContext =
        serde_json::from_value(value).map_err(|error| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!(
                    "{} must be a JSON object matching Chio transaction context: {error}",
                    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER
                ),
            )
        })?;
    validate_request_time_transaction_context(&context)?;
    Ok(context)
}

fn parse_request_time_transaction_context(
    raw: Option<&str>,
) -> Result<Option<GovernedAuthorizationTransactionContext>, Response> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!(
                "{} must be valid JSON: {error}",
                CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER
            ),
        )
    })?;
    parse_request_time_transaction_context_from_value(value).map(Some)
}

fn validate_request_time_authorization_details(
    details: &[GovernedAuthorizationDetail],
) -> Result<(), Response> {
    if details.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details must include at least one Chio governed detail",
        ));
    }

    let mut saw_tool_detail = false;
    for detail in details {
        match detail.detail_type.as_str() {
            CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE => {
                if detail.locations.is_empty() || detail.actions.is_empty() {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_tool authorization detail requires non-empty locations and actions",
                    ));
                }
                if detail.locations.iter().any(|value| value.trim().is_empty())
                    || detail.actions.iter().any(|value| value.trim().is_empty())
                {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_tool authorization detail locations and actions must not be empty",
                    ));
                }
                if detail.commerce.is_some() || detail.metered_billing.is_some() {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_tool authorization detail must not include commerce or meteredBilling sidecars",
                    ));
                }
                saw_tool_detail = true;
            }
            CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE => {
                let Some(commerce) = detail.commerce.as_ref() else {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_commerce authorization detail requires commerce fields",
                    ));
                };
                if commerce.seller.trim().is_empty()
                    || commerce.shared_payment_token_id.trim().is_empty()
                {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_commerce seller and sharedPaymentTokenId must not be empty",
                    ));
                }
                if detail.metered_billing.is_some() {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_commerce authorization detail must not include meteredBilling detail",
                    ));
                }
            }
            CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE => {
                let Some(metered) = detail.metered_billing.as_ref() else {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_metered_billing authorization detail requires meteredBilling fields",
                    ));
                };
                if metered.provider.trim().is_empty()
                    || metered.quote_id.trim().is_empty()
                    || metered.billing_unit.trim().is_empty()
                {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_metered_billing provider, quoteId, and billingUnit must not be empty",
                    ));
                }
                if detail.commerce.is_some() {
                    return Err(oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "chio_governed_metered_billing authorization detail must not include commerce detail",
                    ));
                }
            }
            unsupported => {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    &format!("unsupported authorization_details.type `{unsupported}`"),
                ));
            }
        }
    }

    if !saw_tool_detail {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details must include one chio_governed_tool detail",
        ));
    }
    Ok(())
}

fn validate_request_time_transaction_context(
    context: &GovernedAuthorizationTransactionContext,
) -> Result<(), Response> {
    if context.intent_id.trim().is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "chio_transaction_context.intentId must not be empty",
        ));
    }
    if context.intent_hash.trim().is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "chio_transaction_context.intentHash must not be empty",
        ));
    }
    if let Some(token_id) = context.approval_token_id.as_deref() {
        if token_id.trim().is_empty() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.approvalTokenId must not be empty",
            ));
        }
        let Some(approver_key) = context.approver_key.as_deref() else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.approvalTokenId requires approverKey",
            ));
        };
        if approver_key.trim().is_empty() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.approverKey must not be empty",
            ));
        }
        if context.approval_approved.is_none() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.approvalTokenId requires approvalApproved",
            ));
        }
    }
    if context.runtime_assurance_tier.is_some() {
        let Some(verifier) = context.runtime_assurance_verifier.as_deref() else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.runtimeAssuranceTier requires runtimeAssuranceVerifier",
            ));
        };
        if verifier.trim().is_empty() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.runtimeAssuranceVerifier must not be empty",
            ));
        }
        let Some(evidence_sha) = context.runtime_assurance_evidence_sha256.as_deref() else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.runtimeAssuranceTier requires runtimeAssuranceEvidenceSha256",
            ));
        };
        if evidence_sha.trim().is_empty() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.runtimeAssuranceEvidenceSha256 must not be empty",
            ));
        }
    }
    if let Some(call_chain) = context.call_chain.as_ref() {
        if call_chain.chain_id.trim().is_empty()
            || call_chain.parent_request_id.trim().is_empty()
            || call_chain.origin_subject.trim().is_empty()
            || call_chain.delegator_subject.trim().is_empty()
        {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_transaction_context.callChain requires non-empty chainId, parentRequestId, originSubject, and delegatorSubject",
            ));
        }
        if let Some(parent_receipt_id) = call_chain.parent_receipt_id.as_deref() {
            if parent_receipt_id.trim().is_empty() {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "chio_transaction_context.callChain.parentReceiptId must not be empty when present",
                ));
            }
        }
    }
    if let Some(identity_assertion) = context.identity_assertion.as_ref() {
        identity_assertion
            .validate_at(unix_now())
            .map_err(|message| {
                oauth_token_error(StatusCode::BAD_REQUEST, "invalid_request", &message)
            })?;
    }
    Ok(())
}

fn validate_identity_assertion_binding(
    identity_assertion: &ChioIdentityAssertion,
    expected_verifier_id: &str,
    expected_bound_request_id: Option<&str>,
) -> Result<(), Response> {
    if identity_assertion.verifier_id != expected_verifier_id {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "chio_transaction_context.identityAssertion.verifierId must match client_id",
        ));
    }
    if let Some(expected_request_id) = expected_bound_request_id {
        match identity_assertion.bound_request_id.as_deref() {
            Some(bound_request_id) if bound_request_id == expected_request_id => {}
            Some(_) => {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "chio_transaction_context.identityAssertion.boundRequestId must match the enclosing request",
                ))
            }
            None => {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "chio_transaction_context.identityAssertion requires boundRequestId for request-bound continuity",
                ))
            }
        }
    }
    Ok(())
}

fn validate_request_time_transaction_context_binding(
    context: Option<&GovernedAuthorizationTransactionContext>,
    expected_verifier_id: &str,
    expected_bound_request_id: Option<&str>,
) -> Result<(), Response> {
    let Some(identity_assertion) = context.and_then(|context| context.identity_assertion.as_ref())
    else {
        return Ok(());
    };
    validate_identity_assertion_binding(
        identity_assertion,
        expected_verifier_id,
        expected_bound_request_id,
    )
}

fn normalize_optional_sender_value(
    value: Option<&str>,
    field: &str,
) -> Result<Option<String>, Response> {
    match value {
        Some(raw) if raw.trim().is_empty() => Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} must not be empty"),
        )),
        Some(raw) => Ok(Some(raw.trim().to_string())),
        None => Ok(None),
    }
}

fn build_request_sender_constraint(
    dpop_public_key: Option<&str>,
    mtls_thumbprint_sha256: Option<&str>,
    attestation_sha256: Option<&str>,
    transaction_context: Option<&GovernedAuthorizationTransactionContext>,
) -> Result<Option<ChioSenderConstraintClaims>, Response> {
    let chio_sender_key =
        normalize_optional_sender_value(dpop_public_key, CHIO_SENDER_DPOP_PUBLIC_KEY_PARAMETER)?;
    if let Some(sender_key) = chio_sender_key.as_deref() {
        PublicKey::from_hex(sender_key).map_err(|error| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!(
                    "{CHIO_SENDER_DPOP_PUBLIC_KEY_PARAMETER} must be an Ed25519 public key hex string: {error}"
                ),
            )
        })?;
    }
    let mtls_thumbprint_sha256 = normalize_optional_sender_value(
        mtls_thumbprint_sha256,
        CHIO_SENDER_MTLS_THUMBPRINT_PARAMETER,
    )?;
    let chio_attestation_sha256 =
        normalize_optional_sender_value(attestation_sha256, CHIO_SENDER_ATTESTATION_PARAMETER)?;
    if let Some(attestation_sha256) = chio_attestation_sha256.as_deref() {
        let Some(context) = transaction_context else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "attestation-bound sender semantics require chio_transaction_context runtime assurance fields",
            ));
        };
        if context.runtime_assurance_evidence_sha256.as_deref() != Some(attestation_sha256) {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "chio_sender_attestation_sha256 must match chio_transaction_context.runtimeAssuranceEvidenceSha256",
            ));
        }
        if chio_sender_key.is_none() && mtls_thumbprint_sha256.is_none() {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "attestation-bound sender semantics require either chio_sender_dpop_public_key or chio_sender_mtls_thumbprint_sha256",
            ));
        }
    }
    let claims = ChioSenderConstraintClaims {
        chio_sender_key,
        mtls_thumbprint_sha256,
        chio_attestation_sha256,
    };
    if claims.is_empty() {
        Ok(None)
    } else {
        Ok(Some(claims))
    }
}

fn decode_sender_dpop_proof(raw: &str) -> Result<DpopProof, String> {
    let encoded = raw.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("DPoP proof header is not valid base64url: {error}"))?;
    serde_json::from_slice::<DpopProof>(&bytes)
        .map_err(|error| format!("DPoP proof header is not valid JSON: {error}"))
}

fn verify_sender_dpop_proof(
    proof: &DpopProof,
    expected_binding_id: &str,
    expected_target: &str,
    expected_method: &str,
    expected_agent_key: &PublicKey,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), String> {
    if !is_supported_dpop_schema(&proof.body.schema) {
        return Err(format!("unsupported DPoP schema `{}`", proof.body.schema));
    }
    if proof.body.agent_key != *expected_agent_key {
        return Err("DPoP proof agent_key did not match the bound sender key".to_string());
    }
    let expected_action_hash = sha256_hex(HTTP_DPOP_ACTION_HASH_EMPTY);
    if proof.body.capability_id != expected_binding_id
        || proof.body.tool_server != expected_target
        || proof.body.tool_name != expected_method
        || proof.body.action_hash != expected_action_hash
    {
        return Err(
            "DPoP proof did not match the expected binding id, target, method, or action hash"
                .to_string(),
        );
    }
    if proof.body.nonce.trim().is_empty() {
        return Err("DPoP proof nonce must not be empty".to_string());
    }

    let now = unix_now();
    if proof.body.issued_at > now.saturating_add(config.max_clock_skew_secs) {
        return Err("DPoP proof is too far in the future".to_string());
    }
    if now > proof.body.issued_at.saturating_add(config.proof_ttl_secs) {
        return Err("DPoP proof is stale".to_string());
    }

    let message = canonical_json_bytes(&proof.body)
        .map_err(|error| format!("failed to canonicalize DPoP proof body: {error}"))?;
    if !proof.body.agent_key.verify(&message, &proof.signature) {
        return Err("DPoP proof signature is invalid".to_string());
    }
    match nonce_store.check_and_insert(&proof.body.nonce, expected_binding_id) {
        Ok(true) => Ok(()),
        Ok(false) => Err("DPoP proof nonce was already used".to_string()),
        Err(error) => Err(format!("DPoP nonce verification failed: {error}")),
    }
}

fn validate_sender_constraint_runtime(
    sender_constraint: Option<&ChioSenderConstraintClaims>,
    headers: &HeaderMap,
    expected_binding_id: Option<&str>,
    expected_target: &str,
    expected_method: &str,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), String> {
    let Some(sender_constraint) = sender_constraint else {
        return Ok(());
    };
    if let Some(sender_key) = sender_constraint.chio_sender_key.as_deref() {
        let binding_id = expected_binding_id.ok_or_else(|| {
            "sender-constrained token is missing the binding identifier".to_string()
        })?;
        let proof = headers
            .get(DPOP_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "missing DPoP proof header".to_string())
            .and_then(decode_sender_dpop_proof)?;
        let sender_key = PublicKey::from_hex(sender_key)
            .map_err(|error| format!("token cnf.chioSenderKey is invalid: {error}"))?;
        verify_sender_dpop_proof(
            &proof,
            binding_id,
            expected_target,
            expected_method,
            &sender_key,
            nonce_store,
            config,
        )?;
    }
    if let Some(expected_thumbprint) = sender_constraint.mtls_thumbprint_sha256.as_deref() {
        let actual_thumbprint = headers
            .get(CHIO_MTLS_THUMBPRINT_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "missing mTLS thumbprint header".to_string())?;
        if actual_thumbprint != expected_thumbprint {
            return Err("mTLS thumbprint did not match the sender-bound token".to_string());
        }
    }
    if let Some(expected_attestation) = sender_constraint.chio_attestation_sha256.as_deref() {
        let actual_attestation = headers
            .get(CHIO_RUNTIME_ATTESTATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "missing runtime attestation binding header".to_string())?;
        if actual_attestation != expected_attestation {
            return Err(
                "runtime attestation binding did not match the sender-bound token".to_string(),
            );
        }
    }
    Ok(())
}
