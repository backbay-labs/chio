pub fn serve_http(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| CliError::cli_other_error(format!("failed to start async runtime: {error}")))?;
    runtime.block_on(async move { serve_http_async(config).await })
}

const MCP_RATE_LIMIT_MAX_REQUESTS: u32 = 600;
const MCP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MCP_RATE_LIMIT_MAX_KEYS: usize = 4_096;

#[derive(Clone)]
struct McpRateLimiter {
    windows: Arc<StdMutex<HashMap<String, McpRateWindow>>>,
}

#[derive(Clone, Copy)]
struct McpRateWindow {
    window_start: u64,
    count: u32,
}

impl McpRateLimiter {
    fn new() -> Self {
        Self {
            windows: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    fn check(&self, key: String, now: u64) -> Result<(), u64> {
        let window_secs = MCP_RATE_LIMIT_WINDOW.as_secs().max(1);
        let window_start = now.saturating_sub(now % window_secs);
        let retry_after = window_start
            .saturating_add(window_secs)
            .saturating_sub(now)
            .max(1);
        let mut windows = self.windows.lock().map_err(|_| retry_after)?;
        if windows.len() >= MCP_RATE_LIMIT_MAX_KEYS && !windows.contains_key(&key) {
            windows.retain(|_, window| window.window_start == window_start);
            if windows.len() >= MCP_RATE_LIMIT_MAX_KEYS {
                return Err(retry_after);
            }
        }
        match windows.get_mut(&key) {
            Some(window) if window.window_start == window_start => {
                if window.count >= MCP_RATE_LIMIT_MAX_REQUESTS {
                    return Err(retry_after);
                }
                window.count = window.count.saturating_add(1);
            }
            _ => {
                windows.insert(
                    key,
                    McpRateWindow {
                        window_start,
                        count: 1,
                    },
                );
            }
        }
        Ok(())
    }
}

async fn rate_limit_mcp_request(
    axum::extract::ConnectInfo(remote_addr): axum::extract::ConnectInfo<SocketAddr>,
    State(limiter): State<McpRateLimiter>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let key = mcp_rate_limit_key(remote_addr);
    if let Err(retry_after) = limiter.check(key, mcp_rate_limit_now()) {
        let mut response =
            (StatusCode::TOO_MANY_REQUESTS, "MCP request rate limit exceeded").into_response();
        if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("retry-after"), value);
        }
        return response;
    }
    next.run(request).await
}

fn mcp_rate_limit_key(remote_addr: SocketAddr) -> String {
    format!("ip:{}", remote_addr.ip())
}

fn mcp_rate_limit_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn load_enterprise_provider_registry(
    path: Option<&FsPath>,
    surface: &str,
) -> Result<Option<Arc<EnterpriseProviderRegistry>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let registry = EnterpriseProviderRegistry::load(path)?;
    for record in registry.providers.values() {
        if !record.validation_errors.is_empty() {
            warn!(
                surface,
                provider_id = %record.provider_id,
                errors = ?record.validation_errors,
                "enterprise provider record is invalid and will stay unavailable for admission"
            );
        }
    }
    Ok(Some(Arc::new(registry)))
}

async fn serve_http_async(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "remote_mcp",
    )?;
    let discovered_identity_provider = resolve_discovered_identity_provider(&config)?;
    let (auth_mode, admin_token) = build_remote_auth_state(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
        enterprise_provider_registry.clone(),
    )?;
    let protected_resource_metadata = build_protected_resource_metadata(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
    )?;
    let authorization_server_metadata = build_authorization_server_metadata(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
    )?;
    if let (Some(protected_resource_metadata), Some(authorization_server_metadata)) = (
        protected_resource_metadata.as_ref(),
        authorization_server_metadata.as_ref(),
    ) {
        validate_chio_oauth_discovery_metadata_pair(
            protected_resource_metadata,
            authorization_server_metadata,
        )?;
    }
    let local_auth_server = build_local_auth_server(&config, local_addr)?;

    let sessions = Arc::new(RemoteSessionLedger::new(
        SessionLifecyclePolicy::from_env(),
        config.session_db_path.clone(),
    )?);
    let factory = Arc::new(RemoteSessionFactory::new(config.clone()));
    if let Some(path) = config.session_db_path.as_deref() {
        let loaded_records = load_active_session_records(path)?;
        for session_id in loaded_records.invalid_session_ids {
            if let Err(delete_error) = delete_active_session_record(path, &session_id) {
                warn!(
                    session_id = %session_id,
                    error = %delete_error,
                    "failed to delete malformed persisted MCP session record"
                );
            }
        }
        for record in loaded_records.records {
            match factory.restore_session(&record) {
                Ok(session) => sessions.insert_active(session).await,
                Err(error) => {
                    warn!(
                        session_id = %record.session_id,
                        error = %error,
                        "dropping persisted MCP session record that could not be restored"
                    );
                    if let Err(delete_error) =
                        delete_active_session_record(path, &record.session_id)
                    {
                        warn!(
                            session_id = %record.session_id,
                            error = %delete_error,
                            "failed to delete unrestorable MCP session record"
                        );
                    }
                }
            }
        }
    }
    sessions.cleanup_due_sessions().await;

    let state = RemoteAppState {
        sessions,
        factory,
        auth_mode: Arc::new(auth_mode),
        enterprise_provider_registry,
        admin_token,
        protected_resource_metadata: protected_resource_metadata.map(Arc::new),
        authorization_server_metadata: authorization_server_metadata.map(Arc::new),
        local_auth_server: local_auth_server.map(Arc::new),
    };

    let reaper_state = state.clone();
    tokio::spawn(async move {
        session_reaper_loop(reaper_state).await;
    });

    let mcp_routes = Router::new()
        .route(
            MCP_ENDPOINT_PATH,
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            McpRateLimiter::new(),
            rate_limit_mcp_request,
        ));

    let router = remote_mcp_admin::install_admin_routes(mcp_routes)
        .route(
            PROTECTED_RESOURCE_METADATA_ROOT_PATH,
            get(handle_protected_resource_metadata),
        )
        .route(
            PROTECTED_RESOURCE_METADATA_MCP_PATH,
            get(handle_protected_resource_metadata),
        )
        .route(
            AUTHORIZATION_SERVER_METADATA_PATH,
            get(handle_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/{*rest}",
            get(handle_authorization_server_metadata),
        )
        .route(
            LOCAL_AUTHORIZATION_PATH,
            get(handle_authorization_endpoint).post(handle_authorization_approval),
        )
        .route(LOCAL_TOKEN_PATH, post(handle_token_endpoint))
        .route(LOCAL_JWKS_PATH, get(handle_local_jwks))
        .with_state(state);

    info!(
        listen_addr = %local_addr,
        endpoint = %MCP_ENDPOINT_PATH,
        "serving remote MCP edge"
    );
    eprintln!("remote MCP edge listening on http://{local_addr}{MCP_ENDPOINT_PATH}");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
        .await
        .map_err(|error| CliError::cli_other_error(format!("remote MCP edge server failed: {error}")))
}

async fn handle_post(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let expected_target = state
        .protected_resource_metadata
        .as_deref()
        .map(|metadata| metadata.resource.as_str())
        .unwrap_or(MCP_ENDPOINT_PATH)
        .to_string();
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
        "POST",
        &expected_target,
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };
    if let Err(response) = validate_post_accept_header(request.headers()) {
        return response;
    }
    if let Err(response) = validate_content_type(request.headers()) {
        return response;
    }

    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32700,
                &format!("failed to read request body: {error}"),
            );
        }
    };
    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32700,
                &format!("invalid JSON: {error}"),
            );
        }
    };

    let is_initialize = is_initialize_request(&message);
    let is_request = message.get("id").is_some() && message.get("method").is_some();
    if is_initialize {
        if !is_request {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "initialize must be a JSON-RPC request with an id",
            );
        }
        return handle_initialize_post(state, request_auth_context, &headers, message).await;
    }

    let session = {
        let Some(session_id) = session_id_from_headers(&headers) else {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "request requires MCP-Session-Id",
            );
        };
        let Some(entry) = resolve_session_entry(&state, &session_id).await else {
            return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
        };
        match entry {
            RemoteSessionEntry::Active(session) => {
                if let Err(response) = validate_protocol_version(&headers, &session) {
                    return response;
                }
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, session.auth_context())
                {
                    return response;
                }
                if let Err(response) = validate_session_lifecycle(&session) {
                    return response;
                }
                session.touch();
                session
            }
            RemoteSessionEntry::Terminal(record) => {
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, &record.auth_context)
                {
                    return response;
                }
                return terminal_session_response(record.lifecycle.state);
            }
        }
    };
    if !is_request {
        let mut event_rx = session.subscribe();
        let stream_lock = session.active_request_stream.clone().try_lock_owned().ok();
        if let Err(error) = session.send(message) {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
        let Some(stream_lock) = stream_lock else {
            return response_with_mode(
                StatusCode::ACCEPTED.into_response(),
                "post_notification_accepted",
            );
        };

        let buffered_events = match collect_session_events_until_idle(&session, &mut event_rx).await
        {
            Ok(buffered_events) => buffered_events,
            Err(response) => return response,
        };
        let buffered_events = buffered_events
            .into_iter()
            .filter(|event| {
                should_emit_post_stream_event(event, None, session.has_active_notification_stream())
            })
            .collect::<Vec<_>>();
        if buffered_events.is_empty() {
            drop(stream_lock);
            return response_with_mode(
                StatusCode::ACCEPTED.into_response(),
                "post_notification_accepted",
            );
        }

        return sse_response_from_buffered_events(
            session.clone(),
            buffered_events,
            stream_lock,
            "post_notification_sse",
        );
    }

    let request_id = message.get("id").cloned().unwrap_or(Value::Null);
    let mut event_rx = session.subscribe();
    let stream_lock = session.active_request_stream.clone().lock_owned().await;
    if let Err(error) = session.send(message) {
        drop(stream_lock);
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }

    let session_for_stream = session.clone();
    let stream = stream! {
        let _stream_lock = stream_lock;
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(session_for_stream.next_stream_event_id())
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    if is_successful_initialize_response(&event.message, &request_id) {
                        session_for_stream.set_protocol_version(
                            event.message
                                .get("result")
                                .and_then(|result| result.get("protocolVersion"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned),
                        );
                    }

                    let should_emit = should_emit_post_stream_event(
                        &event,
                        Some(&request_id),
                        session_for_stream.has_active_notification_stream(),
                    );
                    if should_emit {
                        let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                        yield Ok(Event::default().id(event.event_id).data(data));
                    }
                    if is_terminal_response_for_request(&event.message, &request_id) {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, session_id = %session_for_stream.session_id, "remote SSE consumer lagged behind session output");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    response_with_mode(Sse::new(stream).into_response(), "post_request_sse")
}

async fn handle_initialize_post(
    state: RemoteAppState,
    auth_context: SessionAuthContext,
    headers: &HeaderMap,
    message: Value,
) -> Response {
    if session_id_from_headers(headers).is_some() {
        return jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "initialize request must not include MCP-Session-Id",
        );
    }

    let session = match state.factory.spawn_session(auth_context) {
        Ok(session) => session,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    let request_id = message.get("id").cloned().unwrap_or(Value::Null);
    let initialize_params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let peer_capabilities = parse_remote_session_peer_capabilities(&initialize_params);
    let mut event_rx = session.subscribe();
    if let Err(error) = session.send(message) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }

    let mut buffered_events = Vec::new();
    loop {
        match event_rx.recv().await {
            Ok(event) => {
                let is_terminal = is_terminal_response_for_request(&event.message, &request_id);
                let is_success = is_successful_initialize_response(&event.message, &request_id);
                if is_success {
                    session.mark_ready(
                        event
                            .message
                            .get("result")
                            .and_then(|result| result.get("protocolVersion"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        initialize_params.clone(),
                        peer_capabilities.clone(),
                    );
                }
                buffered_events.push(event);

                if is_terminal {
                    if is_success {
                        state.sessions.insert_active(session.clone()).await;
                    }
                    return sse_response_from_events(
                        &session,
                        buffered_events,
                        is_success.then_some(session.session_id.as_str()),
                        "initialize_sse",
                    );
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    session_id = %session.session_id,
                    "remote initialize SSE consumer lagged behind session output"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "remote MCP session worker closed during initialize",
                );
            }
        }
    }
}

fn sse_response_from_events(
    session: &RemoteSession,
    buffered_events: Vec<RemoteSessionEvent>,
    session_header: Option<&str>,
    response_mode: &'static str,
) -> Response {
    let priming_event_id = session.next_stream_event_id();
    let stream = stream! {
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(priming_event_id)
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        for event in buffered_events {
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok(Event::default().id(event.event_id).data(data));
        }
    };

    let mut response = Sse::new(stream).into_response();
    if let Some(session_id) = session_header {
        if let Ok(value) = HeaderValue::from_str(session_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static(MCP_SESSION_ID_HEADER), value);
        }
    }
    response_with_mode(response, response_mode)
}

fn sse_response_from_buffered_events(
    session: Arc<RemoteSession>,
    buffered_events: Vec<RemoteSessionEvent>,
    stream_lock: tokio::sync::OwnedMutexGuard<()>,
    response_mode: &'static str,
) -> Response {
    let priming_event_id = session.next_stream_event_id();
    let stream = stream! {
        let _stream_lock = stream_lock;
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(priming_event_id)
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        for event in buffered_events {
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok(Event::default().id(event.event_id).data(data));
        }
    };

    response_with_mode(Sse::new(stream).into_response(), response_mode)
}

async fn collect_session_events_until_idle(
    session: &RemoteSession,
    event_rx: &mut broadcast::Receiver<RemoteSessionEvent>,
) -> Result<Vec<RemoteSessionEvent>, Response> {
    let mut buffered_events = Vec::new();

    loop {
        match tokio::time::timeout(
            std::time::Duration::from_millis(DEFAULT_NOTIFICATION_STREAM_IDLE_MILLIS),
            event_rx.recv(),
        )
        .await
        {
            Ok(Ok(event)) => buffered_events.push(event),
            Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                warn!(
                    skipped,
                    session_id = %session.session_id,
                    "remote notification SSE consumer lagged behind session output"
                );
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                if buffered_events.is_empty() {
                    return Err(plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "remote MCP session worker closed while processing notification",
                    ));
                }
                break;
            }
            Err(_) => break,
        }
    }

    Ok(buffered_events)
}

async fn handle_get(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let expected_target = state
        .protected_resource_metadata
        .as_deref()
        .map(|metadata| metadata.resource.as_str())
        .unwrap_or(MCP_ENDPOINT_PATH)
        .to_string();
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
        "GET",
        &expected_target,
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };
    if let Err(response) = validate_get_accept_header(request.headers()) {
        return response;
    }

    let Some(session_id) = session_id_from_headers(request.headers()) else {
        return jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "GET stream requires MCP-Session-Id",
        );
    };
    let session = {
        let Some(entry) = resolve_session_entry(&state, &session_id).await else {
            return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
        };
        match entry {
            RemoteSessionEntry::Active(session) => {
                if let Err(response) = validate_protocol_version(request.headers(), &session) {
                    return response;
                }
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, session.auth_context())
                {
                    return response;
                }
                if let Err(response) = validate_session_lifecycle(&session) {
                    return response;
                }
                session.touch();
                session
            }
            RemoteSessionEntry::Terminal(record) => {
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, &record.auth_context)
                {
                    return response;
                }
                return terminal_session_response(record.lifecycle.state);
            }
        }
    };

    let Some(last_event_id) = request
        .headers()
        .get(HeaderName::from_static("last-event-id"))
        .and_then(|value| value.to_str().ok())
    else {
        if !session.try_attach_notification_stream() {
            return plain_http_error(
                StatusCode::CONFLICT,
                "an MCP GET notification stream is already active for this session",
            );
        }
        let mut event_rx = session.subscribe();
        let session_for_stream = session.clone();
        let stream = stream! {
            let _attachment = NotificationStreamAttachment {
                session: session_for_stream.clone(),
            };
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        if event.kind != RemoteSessionEventKind::Notification {
                            continue;
                        }
                        let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                        yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, session_id = %session_for_stream.session_id, "remote GET notification consumer lagged behind session output");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };

        return response_with_mode(Sse::new(stream).into_response(), "get_sse_live");
    };

    let (mut delivered_through, replay_events) =
        match session.replay_notifications_after(Some(last_event_id)) {
            Ok(result) => result,
            Err(response) => return response,
        };
    if !session.try_attach_notification_stream() {
        return plain_http_error(
            StatusCode::CONFLICT,
            "an MCP GET notification stream is already active for this session",
        );
    }
    let mut event_rx = session.subscribe();
    let session_for_stream = session.clone();
    let stream = stream! {
        let _attachment = NotificationStreamAttachment {
            session: session_for_stream.clone(),
        };
        for event in replay_events {
            delivered_through = delivered_through.max(event.seq);
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
        }
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    if event.kind != RemoteSessionEventKind::Notification || event.seq <= delivered_through {
                        continue;
                    }
                    delivered_through = event.seq;
                    let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                    yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, session_id = %session_for_stream.session_id, "remote GET notification consumer lagged behind session output");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    response_with_mode(Sse::new(stream).into_response(), "get_sse_replay")
}

async fn handle_protected_resource_metadata(State(state): State<RemoteAppState>) -> Response {
    let Some(metadata) = state.protected_resource_metadata.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "protected resource metadata is not configured for this edge",
        );
    };

    Json(json!({
        "resource": metadata.resource,
        "authorization_servers": metadata.authorization_servers,
        "scopes_supported": metadata.scopes_supported,
        "bearer_methods_supported": ["header"],
        "chio_authorization_profile": metadata.chio_authorization_profile.clone(),
    }))
    .into_response()
}

async fn handle_authorization_server_metadata(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    let Some(metadata) = state.authorization_server_metadata.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "authorization server metadata is not configured for this edge",
        );
    };
    if request.uri().path() != metadata.metadata_path {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "authorization server metadata path does not match the configured issuer",
        );
    }

    Json(metadata.document.clone()).into_response()
}

async fn handle_authorization_endpoint(
    State(state): State<RemoteAppState>,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.authorization_page(&request) {
        Ok(page) => Html(page).into_response(),
        Err(response) => response,
    }
}

async fn handle_authorization_approval(
    State(state): State<RemoteAppState>,
    Form(form): Form<AuthorizationApprovalForm>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.approve_authorization(form) {
        Ok(redirect) => redirect.into_response(),
        Err(response) => response,
    }
}

async fn handle_token_endpoint(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequestForm>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.exchange_token(&headers, form) {
        Ok(token_response) => Json(token_response).into_response(),
        Err(response) => response,
    }
}

async fn handle_local_jwks(State(state): State<RemoteAppState>) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    Json(auth_server.jwks()).into_response()
}

async fn handle_delete(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let expected_target = state
        .protected_resource_metadata
        .as_deref()
        .map(|metadata| metadata.resource.as_str())
        .unwrap_or(MCP_ENDPOINT_PATH)
        .to_string();
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
        "DELETE",
        &expected_target,
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };

    let Some(session_id) = session_id_from_headers(request.headers()) else {
        return plain_http_error(StatusCode::BAD_REQUEST, "missing MCP-Session-Id");
    };
    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let session = match entry {
        RemoteSessionEntry::Active(session) => session,
        RemoteSessionEntry::Terminal(record) => {
            if let Err(response) =
                validate_session_auth_context(&request_auth_context, &record.auth_context)
            {
                return response;
            }
            return terminal_session_response(record.lifecycle.state);
        }
    };
    if let Err(response) =
        validate_session_auth_context(&request_auth_context, session.auth_context())
    {
        return response;
    }
    if let Err(error) = state.sessions.mark_deleted(&session).await {
        warn!(
            session_id = %session_id,
            error = %error,
            "failed to delete MCP session without resumable-state risk"
        );
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to delete MCP session safely",
        );
    }
    state.sessions.remove_active(&session_id).await;

    StatusCode::NO_CONTENT.into_response()
}

fn is_initialize_request(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("initialize")
}

fn is_terminal_response_for_request(message: &Value, request_id: &Value) -> bool {
    message.get("id") == Some(request_id) && message.get("method").is_none()
}

fn is_successful_initialize_response(message: &Value, request_id: &Value) -> bool {
    is_terminal_response_for_request(message, request_id) && message.get("result").is_some()
}

fn classify_remote_session_event(message: &Value) -> RemoteSessionEventKind {
    if message.get("method").is_some() && message.get("id").is_none() {
        RemoteSessionEventKind::Notification
    } else {
        RemoteSessionEventKind::RequestCorrelated
    }
}

fn parse_session_event_id(event_id: &str, expected_session_id: &str) -> Result<u64, String> {
    let Some((session_id, seq)) = event_id.rsplit_once('-') else {
        return Err("invalid Last-Event-ID format for MCP session".to_string());
    };
    if session_id != expected_session_id {
        return Err("Last-Event-ID does not belong to this MCP session".to_string());
    }
    seq.parse::<u64>()
        .map_err(|_| "invalid Last-Event-ID sequence for MCP session".to_string())
}

fn response_with_mode(mut response: Response, response_mode: &'static str) -> Response {
    response.headers_mut().insert(
        HeaderName::from_static(CHIO_RESPONSE_MODE_HEADER),
        HeaderValue::from_static(response_mode),
    );
    response
}

fn restored_kernel_session_id(session_id: &str) -> SessionId {
    let fingerprint = sha256_hex(session_id.as_bytes());
    SessionId::new(format!("sess-restore-{}", &fingerprint[..16]))
}

fn declared_peer_capability(capabilities: Option<&Value>, key: &str) -> bool {
    match capabilities.and_then(|value| value.get(key)) {
        Some(Value::Bool(enabled)) => *enabled,
        Some(Value::Object(_)) => true,
        _ => false,
    }
}

fn parse_remote_session_peer_capabilities(params: &Value) -> PeerCapabilities {
    let capabilities = params.get("capabilities");
    let experimental = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("experimental"));
    let resources = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("resources"));
    let roots = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("roots"));
    let sampling = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("sampling"));
    let elicitation = params
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("elicitation"));
    let elicitation_form = elicitation.is_some_and(|value| {
        value.as_object().is_some_and(|object| object.is_empty()) || value.get("form").is_some()
    });
    let elicitation_url = elicitation
        .is_some_and(|value| value.get("url").is_some() || value.get("openUrl").is_some());

    PeerCapabilities {
        supports_progress: declared_peer_capability(capabilities, "progress"),
        supports_cancellation: declared_peer_capability(capabilities, "cancellation"),
        supports_subscriptions: resources
            .and_then(|value| value.get("subscribe"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_chio_tool_streaming: experimental
            .and_then(|value| value.get(CHIO_TOOL_STREAMING_CAPABILITY_KEY))
            .and_then(|value| value.get("toolCallChunkNotifications"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_roots: declared_peer_capability(capabilities, "roots"),
        roots_list_changed: roots
            .and_then(|value| value.get("listChanged"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        supports_sampling: declared_peer_capability(capabilities, "sampling"),
        sampling_context: sampling
            .and_then(|value| value.get("context"))
            .is_some_and(Value::is_object),
        sampling_tools: sampling
            .and_then(|value| value.get("tools"))
            .is_some_and(Value::is_object),
        supports_elicitation: declared_peer_capability(capabilities, "elicitation"),
        elicitation_form,
        elicitation_url,
    }
}

#[cfg(test)]
mod http_service_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_remote_session_peer_capabilities_honors_progress_and_cancellation_declarations() {
        let omitted = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {}
        }));
        assert!(!omitted.supports_progress);
        assert!(!omitted.supports_cancellation);

        let declared = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "progress": {},
                "cancellation": true
            }
        }));
        assert!(declared.supports_progress);
        assert!(declared.supports_cancellation);

        let explicitly_disabled = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "progress": false,
                "cancellation": false
            }
        }));
        assert!(!explicitly_disabled.supports_progress);
        assert!(!explicitly_disabled.supports_cancellation);

        let null_and_string = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "progress": null,
                "cancellation": "yes"
            }
        }));
        assert!(!null_and_string.supports_progress);
        assert!(!null_and_string.supports_cancellation);
    }

    #[test]
    fn parse_remote_session_peer_capabilities_honors_explicitly_disabled_roots() {
        let explicitly_disabled = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "roots": false
            }
        }));
        assert!(!explicitly_disabled.supports_roots);
        assert!(!explicitly_disabled.roots_list_changed);

        let declared = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "roots": {
                    "listChanged": true
                }
            }
        }));
        assert!(declared.supports_roots);
        assert!(declared.roots_list_changed);
    }

    #[test]
    fn parse_remote_session_peer_capabilities_honors_explicitly_disabled_sampling() {
        let explicitly_disabled = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "sampling": false
            }
        }));
        assert!(!explicitly_disabled.supports_sampling);
        assert!(!explicitly_disabled.sampling_context);
        assert!(!explicitly_disabled.sampling_tools);

        let declared = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "sampling": {
                    "context": {},
                    "tools": {}
                }
            }
        }));
        assert!(declared.supports_sampling);
        assert!(declared.sampling_context);
        assert!(declared.sampling_tools);

        let null_declaration = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "sampling": null
            }
        }));
        assert!(!null_declaration.supports_sampling);
        assert!(!null_declaration.sampling_context);
        assert!(!null_declaration.sampling_tools);
    }

    #[test]
    fn parse_remote_session_peer_capabilities_honors_explicitly_disabled_elicitation() {
        let explicitly_disabled = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "elicitation": false
            }
        }));
        assert!(!explicitly_disabled.supports_elicitation);
        assert!(!explicitly_disabled.elicitation_form);
        assert!(!explicitly_disabled.elicitation_url);

        let declared = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "elicitation": {
                    "form": {}
                }
            }
        }));
        assert!(declared.supports_elicitation);
        assert!(declared.elicitation_form);
        assert!(!declared.elicitation_url);

        let null_declaration = parse_remote_session_peer_capabilities(&json!({
            "capabilities": {
                "elicitation": null
            }
        }));
        assert!(!null_declaration.supports_elicitation);
        assert!(!null_declaration.elicitation_form);
        assert!(!null_declaration.elicitation_url);
    }
}

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

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HeaderName::from_static(MCP_SESSION_ID_HEADER))
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn resolve_session_entry(
    state: &RemoteAppState,
    session_id: &str,
) -> Option<RemoteSessionEntry> {
    state.sessions.cleanup_due_sessions().await;
    state.sessions.lookup(session_id).await
}

async fn session_reaper_loop(state: RemoteAppState) {
    let interval =
        std::time::Duration::from_millis(state.factory.lifecycle_policy.reaper_interval_millis);
    loop {
        tokio::time::sleep(interval).await;
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
        Some(Arc::<str>::from(token.to_string()))
    } else if let Some(token) = config.auth_token.as_deref() {
        Some(Arc::<str>::from(token.to_string()))
    } else {
        return Err(CliError::cli_other_error(
            "bearer-authenticated remote MCP edge requires --admin-token for admin APIs"
                .to_string(),
        ));
    };

    Ok((auth_mode, admin_token))
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
            token: Arc::<str>::from(token.to_string()),
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
        return Ok(RemoteAuthMode::IntrospectionBearer {
            verifier: Arc::new(IntrospectionBearerVerifier {
                client: HttpClient::builder()
                    .timeout(Duration::from_secs(TOKEN_INTROSPECTION_TIMEOUT_SECS))
                    .build()
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "failed to build token introspection client: {error}"
                        ))
                    })?,
                introspection_url: parse_identity_provider_url(
                    introspection_url,
                    "--auth-introspection-url",
                )?,
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
