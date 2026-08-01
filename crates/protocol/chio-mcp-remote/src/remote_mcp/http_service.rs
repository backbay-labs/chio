pub fn serve_http(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| CliError::cli_other_error(format!("failed to start async runtime: {error}")))?;
    runtime.block_on(async move { serve_http_async(config).await })
}

const MCP_RATE_LIMIT_MAX_REQUESTS: u32 = 600;
const MCP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MCP_RATE_LIMIT_MAX_KEYS: usize = 4_096;
const MCP_MAX_POST_BODY_BYTES: usize = 8 * 1024 * 1024;

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
    axum::extract::ConnectInfo(chio_http_serve::CappedPeerAddr(remote_addr)): axum::extract::ConnectInfo<
        chio_http_serve::CappedPeerAddr,
    >,
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
    let discovered_identity_provider = resolve_discovered_identity_provider(&config).await?;
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

    let factory = Arc::new(RemoteSessionFactory::new(config.clone())?);
    let sessions = Arc::new(RemoteSessionLedger::new(
        SessionLifecyclePolicy::from_env(),
        config.session_db_path.clone(),
    )?);
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

    let controller = chio_http_serve::ShutdownController::install();
    let reaper_state = state.clone();
    let reaper_shutdown = controller.subscribe();
    tokio::spawn(async move {
        session_reaper_loop(reaper_state, reaper_shutdown).await;
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

    // The generic per-request timeout is left off here. The edge's GET and POST
    // routes return Server-Sent Event streams that stay open indefinitely while a
    // session waits for notifications, so a blanket request timeout would close a
    // healthy idle stream with 408 and force resumable clients into reconnect
    // churn. Request bodies are already bounded by `read_limited_mcp_post_body`,
    // per-IP request rate is capped by the rate limiter, and the drain deadline
    // bounds any stream still open at shutdown.
    let hygiene = chio_http_serve::ServeHygieneConfig {
        request_timeout: None,
        ..chio_http_serve::ServeHygieneConfig::default()
    };
    let router = chio_http_serve::apply_server_hygiene(router, &hygiene);
    // Cap simultaneously accepted connections at the accept loop so a slow or idle
    // connection flood cannot exhaust file descriptors before any request reaches
    // the concurrency limit. The peer address stays available to the per-IP rate
    // limiter via `CappedPeerAddr`.
    let listener = chio_http_serve::MaxConnListener::new(
        listener,
        hygiene.max_connections.unwrap_or(usize::MAX),
    );
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<chio_http_serve::CappedPeerAddr>(),
    )
    .with_graceful_shutdown(controller.signalled());

    // Draining the in-flight requests is the primary durability guarantee here:
    // the receipt commit actor acknowledges an append only after the batch
    // reaches WAL, so every acknowledged receipt is already durable once the
    // request that wrote it finishes. Each session kernel runs behind its own
    // worker thread reachable only through its message channel, so there is no
    // in-process handle to flush after the drain.
    chio_http_serve::run_until_drained(
        server,
        controller.subscribe(),
        hygiene.drain_timeout,
        async { Ok::<(), String>(()) },
    )
    .await
    .map(|_outcome| ())
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

    let (headers, body) = match read_limited_mcp_post_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
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
        let session_id = match jsonrpc_session_id_from_headers(
            &headers,
            "request requires MCP-Session-Id",
        ) {
            Ok(session_id) => session_id,
            Err(response) => return response,
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
    if mcp_session_id_header(headers) != McpSessionIdHeader::Missing {
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

    let session_id = match jsonrpc_session_id_from_headers(
        request.headers(),
        "GET stream requires MCP-Session-Id",
    ) {
        Ok(session_id) => session_id,
        Err(response) => return response,
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

    let session_id =
        match plain_session_id_from_headers(request.headers(), "missing MCP-Session-Id") {
        Ok(session_id) => session_id,
        Err(response) => return response,
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

async fn read_limited_mcp_post_body(
    request: Request,
) -> Result<(HeaderMap, axum::body::Bytes), Response> {
    let headers = request.headers().clone();
    validate_mcp_post_content_length(&headers)?;
    match axum::body::to_bytes(request.into_body(), MCP_MAX_POST_BODY_BYTES).await {
        Ok(body) => Ok((headers, body)),
        Err(error) if error.to_string().contains("length limit") => Err(jsonrpc_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            -32600,
            &format!("request body exceeds {MCP_MAX_POST_BODY_BYTES}-byte limit"),
        )),
        Err(error) => Err(jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32700,
            &format!("failed to read request body: {error}"),
        )),
    }
}

fn validate_mcp_post_content_length(headers: &HeaderMap) -> Result<(), Response> {
    let Some(value) = headers.get(axum::http::header::CONTENT_LENGTH) else {
        return Ok(());
    };
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            jsonrpc_http_error(StatusCode::BAD_REQUEST, -32600, "invalid Content-Length")
        })?;
    if length > MCP_MAX_POST_BODY_BYTES as u64 {
        return Err(jsonrpc_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            -32600,
            &format!("request body exceeds {MCP_MAX_POST_BODY_BYTES}-byte limit"),
        ));
    }
    Ok(())
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

    #[tokio::test]
    async fn read_limited_mcp_post_body_rejects_oversized_content_length() {
        let request = match Request::builder()
            .method("POST")
            .uri(MCP_ENDPOINT_PATH)
            .header(
                axum::http::header::CONTENT_LENGTH,
                (MCP_MAX_POST_BODY_BYTES + 1).to_string(),
            )
            .body(axum::body::Body::empty())
        {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };

        let Err(response) = read_limited_mcp_post_body(request).await else {
            panic!("oversized Content-Length should be rejected");
        };
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn read_limited_mcp_post_body_rejects_streaming_body_over_limit() {
        let request = match Request::builder()
            .method("POST")
            .uri(MCP_ENDPOINT_PATH)
            .body(axum::body::Body::from(vec![
                b'a';
                MCP_MAX_POST_BODY_BYTES + 1
            ])) {
            Ok(request) => request,
            Err(error) => panic!("failed to build request: {error}"),
        };

        let Err(response) = read_limited_mcp_post_body(request).await else {
            panic!("oversized streaming body should be rejected");
        };
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

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
