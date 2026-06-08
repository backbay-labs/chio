#[tokio::test]
async fn adapter_discovers_jsonrpc_and_invokes_skill() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_bearer_token("secret-token")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    assert_eq!(adapter.tool_names(), vec!["research".to_string()]);
    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "Find recent results on treatment-resistant depression",
                "metadata": { "trace_id": "trace-1" },
                "message_metadata": { "priority": "high" },
                "history_length": 3
            }),
            None,
        )
        .await
        .expect("invoke research skill");

    assert_eq!(
        result["message"]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("GET /.well-known/agent-card.json HTTP/1.1"));
    assert!(requests[1].contains("POST /rpc HTTP/1.1"));
    assert!(requests[1].contains("Authorization: Bearer secret-token"));
    assert!(requests[1].contains("A2A-Version: 1.0"));
    assert!(requests[1].contains("\"method\":\"SendMessage\""));
    assert!(requests[1].contains("\"targetSkillId\":\"research\""));
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_send_message_missing_result_names_method() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_missing_send_message_result() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let error = adapter
        .invoke("research", json!({ "message": "hello" }), None)
        .await
        .expect_err("missing SendMessage result should fail closed");

    assert!(
        error
            .to_string()
            .contains("A2A JSON-RPC SendMessage response omitted `result`"),
        "unexpected missing-result error: {error}"
    );
    server.join();
}

#[tokio::test]
async fn adapter_rejects_json_tool_body_on_cross_origin_redirect() {
    let Some(target_listener) = bind_fake_a2a_listener("redirect target A2A listener") else {
        return;
    };
    let target_address = target_listener.local_addr().expect("target listener address");
    let target_base_url = format!("http://{target_address}");

    let Some(initial_listener) = bind_fake_a2a_listener("redirect initial A2A listener") else {
        return;
    };
    let initial_address = initial_listener
        .local_addr()
        .expect("initial listener address");
    let initial_base_url = format!("http://{initial_address}");
    let initial_base_url_for_thread = initial_base_url.clone();
    let target_base_url_for_thread = target_base_url.clone();
    let initial_handle = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = initial_listener.accept().expect("accept initial request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set initial read timeout");
            let request = read_http_request(&mut stream);
            let first_line = request.lines().next().unwrap_or_default();
            if first_line.starts_with("GET /.well-known/agent-card.json") {
                write_http_json_response(
                    &mut stream,
                    200,
                    &json!({
                        "name": "Research Agent",
                        "description": "Answers research questions over A2A",
                        "supportedInterfaces": [{
                            "url": format!("{initial_base_url_for_thread}/rpc"),
                            "protocolBinding": "JSONRPC",
                            "protocolVersion": "1.0"
                        }],
                        "version": "1.0.0",
                        "capabilities": {
                            "streaming": false,
                            "pushNotifications": false,
                            "stateTransitionHistory": true
                        },
                        "defaultInputModes": ["text/plain", "application/json"],
                        "defaultOutputModes": ["application/json"],
                        "skills": [{
                            "id": "research",
                            "name": "Research",
                            "description": "Search and synthesize results",
                            "tags": ["search"],
                            "inputModes": ["text/plain", "application/json"],
                            "outputModes": ["application/json"]
                        }]
                    }),
                );
            } else if first_line.starts_with("POST /rpc") {
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {target_base_url_for_thread}/rpc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write redirect response");
            } else {
                write_http_json_response(
                    &mut stream,
                    500,
                    &json!({"error": format!("unexpected request: {first_line}")}),
                );
            }
        }
    });

    let manifest_key = Keypair::generate();
    let mut contract = test_egress_contract(&initial_base_url);
    insert_test_egress_authority(&mut contract, &target_base_url);
    let adapter = A2aAdapter::discover(
        A2aAdapterConfig::new(&initial_base_url, manifest_key.public_key().to_hex())
            .with_egress_contract(contract)
            .with_bearer_token("secret-token")
            .with_request_cookie("partner_session", "cookie-alpha")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover redirecting JSONRPC adapter");

    let error = adapter
        .invoke(
            "research",
            json!({"message": "do not replay this tool body"}),
            None,
        )
        .await
        .expect_err("JSON tool body must not be replayed to cross-origin redirect target");

    initial_handle.join().expect("join initial redirect server");
    let message = error.to_string();
    assert!(
        message.contains("body-bearing request rejected cross-origin redirect"),
        "expected body-bearing redirect rejection, got: {message}"
    );
}

#[tokio::test]
async fn adapter_rejects_http_json_tool_body_on_cross_origin_redirect() {
    let Some(target_listener) = bind_fake_a2a_listener("api key redirect target A2A listener")
    else {
        return;
    };
    let target_address = target_listener.local_addr().expect("target listener address");
    let target_base_url = format!("http://{target_address}");

    let Some(initial_listener) =
        bind_fake_a2a_listener("api key redirect initial A2A listener")
    else {
        return;
    };
    let initial_address = initial_listener
        .local_addr()
        .expect("initial listener address");
    let initial_base_url = format!("http://{initial_address}");
    let initial_base_url_for_thread = initial_base_url.clone();
    let target_base_url_for_thread = target_base_url.clone();
    let initial_handle = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = initial_listener.accept().expect("accept initial request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set initial read timeout");
            let request = read_http_request(&mut stream);
            let first_line = request.lines().next().unwrap_or_default();
            if first_line.starts_with("GET /.well-known/agent-card.json") {
                let (security_schemes, security_requirements) =
                    agent_card_security_metadata(TestScenario::ApiKeyRequired, &initial_base_url_for_thread);
                write_http_json_response(
                    &mut stream,
                    200,
                    &json!({
                        "name": "Research Agent",
                        "description": "Answers research questions over A2A",
                        "supportedInterfaces": [{
                            "url": initial_base_url_for_thread,
                            "protocolBinding": "HTTP+JSON",
                            "protocolVersion": "1.0"
                        }],
                        "version": "1.0.0",
                        "capabilities": {
                            "streaming": false,
                            "pushNotifications": false,
                            "stateTransitionHistory": true
                        },
                        "defaultInputModes": ["text/plain", "application/json"],
                        "defaultOutputModes": ["application/json"],
                        "securitySchemes": security_schemes,
                        "securityRequirements": security_requirements,
                        "skills": [{
                            "id": "research",
                            "name": "Research",
                            "description": "Search and synthesize results",
                            "tags": ["search"],
                            "inputModes": ["text/plain", "application/json"],
                            "outputModes": ["application/json"]
                        }]
                    }),
                );
            } else if first_line.starts_with("POST /message:send") {
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {target_base_url_for_thread}/message:send\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write redirect response");
            } else {
                write_http_json_response(
                    &mut stream,
                    500,
                    &json!({"error": format!("unexpected request: {first_line}")}),
                );
            }
        }
    });

    let manifest_key = Keypair::generate();
    let mut contract = test_egress_contract(&initial_base_url);
    insert_test_egress_authority(&mut contract, &target_base_url);
    let adapter = A2aAdapter::discover(
        A2aAdapterConfig::new(&initial_base_url, manifest_key.public_key().to_hex())
            .with_egress_contract(contract)
            .with_api_key_header("X-A2A-Key", "secret-key")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover API key redirecting HTTP+JSON adapter");

    let error = adapter
        .invoke(
            "research",
            json!({"message": "do not replay this HTTP JSON body"}),
            None,
        )
        .await
        .expect_err("HTTP+JSON tool body must not be replayed cross-origin");

    initial_handle.join().expect("join initial redirect server");
    let message = error.to_string();
    assert!(
        message.contains("body-bearing request rejected cross-origin redirect"),
        "expected body-bearing redirect rejection, got: {message}"
    );
}

#[tokio::test]
async fn adapter_rejects_json_tool_body_before_cross_origin_redirect_chain() {
    let Some(initial_listener) =
        bind_fake_a2a_listener("multi-hop redirect initial A2A listener")
    else {
        return;
    };
    let Some(middle_listener) =
        bind_fake_a2a_listener("multi-hop redirect middle A2A listener")
    else {
        return;
    };

    let initial_address = initial_listener
        .local_addr()
        .expect("initial listener address");
    let initial_base_url = format!("http://{initial_address}");
    let middle_address = middle_listener
        .local_addr()
        .expect("middle listener address");
    let middle_base_url = format!("http://{middle_address}");

    let initial_base_url_for_thread = initial_base_url.clone();
    let middle_base_url_for_thread = middle_base_url.clone();
    let initial_handle = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = initial_listener.accept().expect("accept initial request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set initial read timeout");
            let request = read_http_request(&mut stream);
            let first_line = request.lines().next().unwrap_or_default();
            if first_line.starts_with("GET /.well-known/agent-card.json") {
                write_http_json_response(
                    &mut stream,
                    200,
                    &json!({
                        "name": "Research Agent",
                        "description": "Answers research questions over A2A",
                        "supportedInterfaces": [{
                            "url": format!("{initial_base_url_for_thread}/rpc"),
                            "protocolBinding": "JSONRPC",
                            "protocolVersion": "1.0"
                        }],
                        "version": "1.0.0",
                        "capabilities": {
                            "streaming": false,
                            "pushNotifications": false,
                            "stateTransitionHistory": true
                        },
                        "defaultInputModes": ["text/plain", "application/json"],
                        "defaultOutputModes": ["application/json"],
                        "skills": [{
                            "id": "research",
                            "name": "Research",
                            "description": "Search and synthesize results",
                            "tags": ["search"],
                            "inputModes": ["text/plain", "application/json"],
                            "outputModes": ["application/json"]
                        }]
                    }),
                );
            } else if first_line.starts_with("POST /rpc") {
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {middle_base_url_for_thread}/relay\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write cross-origin redirect response");
            } else {
                write_http_json_response(
                    &mut stream,
                    500,
                    &json!({"error": format!("unexpected request: {first_line}")}),
                );
            }
        }
    });

    let manifest_key = Keypair::generate();
    let mut contract = test_egress_contract(&initial_base_url);
    insert_test_egress_authority(&mut contract, &middle_base_url);
    let adapter = A2aAdapter::discover(
        A2aAdapterConfig::new(&initial_base_url, manifest_key.public_key().to_hex())
            .with_egress_contract(contract)
            .with_bearer_token("secret-token")
            .with_request_cookie("partner_session", "cookie-alpha")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover multi-hop redirecting JSONRPC adapter");

    let error = adapter
        .invoke(
            "research",
            json!({"message": "do not replay across redirect chain"}),
            None,
        )
        .await
        .expect_err("JSON tool body must not enter cross-origin redirect chain");

    initial_handle
        .join()
        .expect("join initial redirect server");
    let message = error.to_string();
    assert!(
        message.contains("body-bearing request rejected cross-origin redirect"),
        "expected body-bearing redirect rejection, got: {message}"
    );
}

#[tokio::test]
async fn adapter_generic_request_auth_surfaces_apply_to_discovery_and_invoke() {
    let Some(server) = FakeA2aServer::spawn_http_json() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_request_header("X-Partner", "partner-alpha")
            .with_request_query_param("partner", "alpha")
            .with_request_cookie("partner_session", "cookie-alpha")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "Find recent results on treatment-resistant depression"
            }),
            None,
        )
        .await
        .expect("invoke research skill");

    assert_eq!(
        result["task"]["artifacts"][0]["parts"][0]["text"],
        "completed research request"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /.well-known/agent-card.json?partner=alpha "));
    assert!(requests[0].contains("X-Partner: partner-alpha"));
    assert!(requests[0].contains("Cookie: partner_session=cookie-alpha"));
    assert!(requests[1].starts_with("POST /message:send?partner=alpha "));
    assert!(requests[1].contains("X-Partner: partner-alpha"));
    assert!(requests[1].contains("Cookie: partner_session=cookie-alpha"));
    server.join();
}

#[tokio::test]
async fn adapter_rejects_malformed_request_auth_material_before_discovery() {
    let public_key = Keypair::generate().public_key().to_hex();
    let base_url = "http://127.0.0.1:9";
    let cases = vec![
        (
            "bad header name",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header(" X-Partner", "secret-header"),
            "request header",
        ),
        (
            "bad header name separator",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header("X=Partner", "secret-header"),
            "request header",
        ),
        (
            "bad header value",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header("X-Partner", "secret\r\nInjected: yes"),
            "request header value",
        ),
        (
            "bad query name",
            test_adapter_config(base_url, public_key.clone())
                .with_request_query_param(" partner", "secret-query"),
            "request query parameter",
        ),
        (
            "bad API key query value",
            test_adapter_config(base_url, public_key.clone())
                .with_api_key_query_param("partner", " secret-query"),
            "request query parameter value",
        ),
        (
            "bad bearer token",
            test_adapter_config(base_url, public_key.clone()).with_bearer_token(" secret"),
            "bearer token",
        ),
        (
            "bad bearer token internal whitespace",
            test_adapter_config(base_url, public_key.clone()).with_bearer_token("abc def"),
            "bearer token",
        ),
        (
            "bad authorization bearer token internal whitespace",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header("Authorization", "Bearer abc def"),
            "bearer token",
        ),
        (
            "bad authorization scheme",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header("Authorization", "\u{e9}\u{e9}\u{e9}\u{e9}"),
            "authorization scheme",
        ),
        (
            "bad authorization scheme separator",
            test_adapter_config(base_url, public_key.clone())
                .with_request_header("Authorization", "Bearer=opaque"),
            "authorization scheme",
        ),
        (
            "bad cookie name",
            test_adapter_config(base_url, public_key.clone())
                .with_request_cookie("partner session", "secret-cookie"),
            "request cookie name",
        ),
        (
            "bad cookie name separator",
            test_adapter_config(base_url, public_key.clone())
                .with_request_cookie("partner=session", "secret-cookie"),
            "request cookie name",
        ),
        (
            "bad cookie value",
            test_adapter_config(base_url, public_key.clone())
                .with_request_cookie("partner_session", "secret-cookie; injected=yes"),
            "request cookie value",
        ),
        (
            "bad OAuth client id",
            test_adapter_config(base_url, public_key.clone())
                .with_oauth_client_credentials("", "client-secret"),
            "OAuth client id",
        ),
        (
            "bad OAuth client id padding",
            test_adapter_config(base_url, public_key.clone())
                .with_oauth_client_credentials(" client-id", "client-secret"),
            "OAuth client id",
        ),
        (
            "bad OAuth client secret padding",
            test_adapter_config(base_url, public_key.clone())
                .with_oauth_client_credentials("client-id", " client-secret"),
            "OAuth client credential",
        ),
        (
            "bad OAuth client secret control",
            test_adapter_config(base_url, public_key)
                .with_oauth_client_credentials("client-id", "client\nsecret"),
            "OAuth client credential",
        ),
    ];

    for (label, config, expected) in cases {
        let error = A2aAdapter::discover(config.with_timeout(Duration::from_millis(10)))
            .expect_err(label);
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "{label}: expected `{expected}`, got `{message}`"
        );
        assert!(
            !message.contains("secret") && !message.contains("Injected"),
            "{label}: auth material leaked in `{message}`"
        );
    }
}

#[tokio::test]
async fn partner_policy_rejects_wrong_tenant_on_discovery() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let error = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_partner_policy(
                A2aPartnerPolicy::new("partner-alpha").with_required_tenant("tenant-required"),
            )
            .with_timeout(Duration::from_secs(2)),
    )
    .expect_err("partner policy should fail closed on tenant mismatch");

    assert!(error
        .to_string()
        .contains("requires tenant `tenant-required`"));
    server.join();
}

#[tokio::test]
async fn partner_policy_rejects_required_skill_filtered_by_input_modes() {
    let mut adapter = local_test_adapter(
        A2aAgentCapabilities::default(),
        A2aProtocolBinding::JsonRpc,
        None,
    );
    adapter.agent_card.skills[0].input_modes = Some(vec!["image/png".to_string()]);
    let policy = A2aPartnerPolicy::new("partner-alpha").require_skill("research");

    let error = validate_partner_policy(
        &policy,
        &adapter.agent_card,
        &adapter.selected_interface,
    )
    .expect_err("required non-projectable skill should fail partner admission");

    assert!(error
        .to_string()
        .contains("does not expose a Chio-projectable input mode"));
}

#[tokio::test]
async fn task_registry_allows_follow_up_after_restart_and_rejects_unknown_tasks() {
    let registry_path = unique_path("chio-a2a-task-registry", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover adapter");

    let initial = adapter
        .invoke(
            "research",
            json!({
                "message": "Begin longer research task",
                "return_immediately": true
            }),
            None,
        )
        .await
        .expect("initial invoke");
    assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

    let adapter_after_restart = A2aAdapter {
        manifest: adapter.manifest.clone(),
        agent_card: adapter.agent_card.clone(),
        agent_card_url: adapter.agent_card_url.clone(),
        selected_interface: adapter.selected_interface.clone(),
        selected_binding: adapter.selected_binding,
        configured_headers: adapter.configured_headers.clone(),
        configured_query_params: adapter.configured_query_params.clone(),
        configured_cookies: adapter.configured_cookies.clone(),
        oauth_client_credentials: adapter.oauth_client_credentials.clone(),
        oauth_scopes: adapter.oauth_scopes.clone(),
        oauth_token_endpoint_override: adapter.oauth_token_endpoint_override.clone(),
        transport_config: adapter.transport_config.clone(),
        token_cache: Mutex::new(Vec::new()),
        timeout: adapter.timeout,
        request_counter: AtomicU64::new(0),
        partner_policy: adapter.partner_policy.clone(),
        task_registry: Some(A2aTaskRegistry::open(&registry_path).expect("reopen registry")),
    };
    let follow_up = adapter_after_restart
        .invoke(
            "research",
            json!({
                "get_task": {
                    "id": "task-1",
                    "history_length": 1
                }
            }),
            None,
        )
        .await
        .expect("follow-up invoke after restart");
    assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");

    let unknown_error = adapter_after_restart
        .invoke(
            "research",
            json!({
                "get_task": {
                    "id": "task-unknown"
                }
            }),
            None,
        )
        .await
        .expect_err("unknown follow-up should fail closed");
    assert!(unknown_error
        .to_string()
        .contains("requires a previously recorded A2A task"));

    let _ = fs::remove_file(registry_path);
    server.join();
}

#[tokio::test]
async fn task_registry_rejects_follow_up_from_different_partner() {
    let registry_path = unique_path("chio-a2a-task-registry-partner", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_partner_policy(A2aPartnerPolicy::new("partner-alpha"))
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover adapter");

    adapter
        .invoke(
            "research",
            json!({
                "message": "Begin partner-bound research task",
                "return_immediately": true
            }),
            None,
        )
        .await
        .expect("initial invoke");

    let adapter_for_other_partner = A2aAdapter {
        manifest: adapter.manifest.clone(),
        agent_card: adapter.agent_card.clone(),
        agent_card_url: adapter.agent_card_url.clone(),
        selected_interface: adapter.selected_interface.clone(),
        selected_binding: adapter.selected_binding,
        configured_headers: adapter.configured_headers.clone(),
        configured_query_params: adapter.configured_query_params.clone(),
        configured_cookies: adapter.configured_cookies.clone(),
        oauth_client_credentials: adapter.oauth_client_credentials.clone(),
        oauth_scopes: adapter.oauth_scopes.clone(),
        oauth_token_endpoint_override: adapter.oauth_token_endpoint_override.clone(),
        transport_config: adapter.transport_config.clone(),
        token_cache: Mutex::new(Vec::new()),
        timeout: adapter.timeout,
        request_counter: AtomicU64::new(0),
        partner_policy: Some(A2aPartnerPolicy::new("partner-beta")),
        task_registry: Some(A2aTaskRegistry::open(&registry_path).expect("reopen registry")),
    };
    let error = adapter_for_other_partner
        .invoke(
            "research",
            json!({
                "get_task": {
                    "id": "task-1"
                }
            }),
            None,
        )
        .await
        .expect_err("partner mismatch must fail closed before remote follow-up");

    let agent_card_url = format!("{}/.well-known/agent-card.json", server.base_url());
    let _ = ureq::get(&agent_card_url).call().expect("unblock fake server");
    assert!(
        error.to_string().contains("partner `partner-alpha`"),
        "unexpected partner-mismatch error: {error}"
    );
    let requests = server.requests();
    assert_eq!(
        requests.len(),
        3,
        "mismatched partner must not dispatch a follow-up request"
    );
    assert!(
        requests[2].starts_with("GET /.well-known/agent-card.json"),
        "third request should only unblock the fake server, got: {}",
        requests[2].lines().next().unwrap_or_default()
    );

    let _ = fs::remove_file(registry_path);
    server.join();
}

#[test]
fn task_registry_rejects_conflicting_reobserved_task_binding() {
    let registry_path = unique_path("chio-a2a-task-registry-conflict", ".json");
    let registry = A2aTaskRegistry::open(&registry_path).expect("open task registry");
    let selected_interface = A2aAgentInterface {
        url: "http://localhost:9000/rpc".to_string(),
        protocol_binding: "JSONRPC".to_string(),
        protocol_version: "1.0".to_string(),
        tenant: Some("tenant-alpha".to_string()),
    };
    let selected_binding = A2aProtocolBinding::JsonRpc;
    let first_context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "research",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };
    registry
        .record_from_value(
            &json!({
                "task": {
                    "id": "task-1",
                    "status": { "state": "TASK_STATE_WORKING" }
                }
            }),
            &first_context,
        )
        .expect("record initial task binding");

    let conflicting_context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "clinical_search",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };
    let error = registry
        .record_from_value(
            &json!({
                "task": {
                    "id": "task-1",
                    "status": { "state": "TASK_STATE_WORKING" }
                }
            }),
            &conflicting_context,
        )
        .expect_err("conflicting task ownership must fail closed");

    assert!(error.to_string().contains("attempted to rebind"));
    let reloaded = registry.load().expect("reload task registry");
    let record = reloaded.tasks.get("task-1").expect("task remains recorded");
    assert_eq!(record.tool_name, "research");

    let _ = fs::remove_file(registry_path);
}

#[test]
fn task_registry_persists_valid_batch_records_before_rebind_conflict() {
    let registry_path = unique_path("chio-a2a-task-registry-batch-conflict", ".json");
    let registry = A2aTaskRegistry::open(&registry_path).expect("open task registry");
    let selected_interface = A2aAgentInterface {
        url: "http://localhost:9000/rpc".to_string(),
        protocol_binding: "JSONRPC".to_string(),
        protocol_version: "1.0".to_string(),
        tenant: Some("tenant-alpha".to_string()),
    };
    let selected_binding = A2aProtocolBinding::JsonRpc;
    let first_context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "clinical_search",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };
    registry
        .record_from_value(
            &json!({
                "task": {
                    "id": "task-conflict",
                    "status": { "state": "TASK_STATE_WORKING" }
                }
            }),
            &first_context,
        )
        .expect("record initial task binding");

    let research_context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "research",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };
    let error = registry
        .record_from_value(
            &json!({
                "task": {
                    "id": "task-new",
                    "status": { "state": "TASK_STATE_WORKING" }
                },
                "statusUpdate": {
                    "taskId": "task-conflict",
                    "status": { "state": "TASK_STATE_COMPLETED" }
                }
            }),
            &research_context,
        )
        .expect_err("rebind conflict should still be reported");

    assert!(error.to_string().contains("attempted to rebind"));
    let reloaded = registry.load().expect("reload task registry");
    let new_record = reloaded
        .tasks
        .get("task-new")
        .expect("non-conflicting task from same batch should persist");
    assert_eq!(new_record.tool_name, "research");
    assert_eq!(
        new_record.last_state.as_deref(),
        Some("TASK_STATE_WORKING")
    );
    let conflict_record = reloaded
        .tasks
        .get("task-conflict")
        .expect("conflicting task remains recorded");
    assert_eq!(conflict_record.tool_name, "clinical_search");
    assert_eq!(
        conflict_record.last_state.as_deref(),
        Some("TASK_STATE_WORKING")
    );

    let _ = fs::remove_file(registry_path);
}

#[test]
fn task_registry_rejects_malformed_task_observation_before_persisting() {
    let registry_path = unique_path("chio-a2a-task-registry-malformed", ".json");
    let registry = A2aTaskRegistry::open(&registry_path).expect("open task registry");
    let selected_interface = A2aAgentInterface {
        url: "http://localhost:9000/rpc".to_string(),
        protocol_binding: "JSONRPC".to_string(),
        protocol_version: "1.0".to_string(),
        tenant: Some("tenant-alpha".to_string()),
    };
    let selected_binding = A2aProtocolBinding::JsonRpc;
    let context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "research",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };

    let error = registry
        .record_from_value(
            &json!({
                "task": {
                    "id": "",
                    "status": { "state": "TASK_STATE_WORKING" }
                }
            }),
            &context,
        )
        .expect_err("malformed task observation must fail closed");

    assert!(
        error.to_string().contains("id` must not be empty"),
        "unexpected malformed-observation error: {error}"
    );
    let reloaded = registry.load().expect("reload task registry");
    assert!(
        reloaded.tasks.is_empty(),
        "malformed observations must not be persisted"
    );

    let _ = fs::remove_file(registry_path);
}

#[test]
fn task_registry_preserves_observed_task_ids_exactly() {
    let registry_path = unique_path("chio-a2a-task-registry-observed-task-id", ".json");
    let registry = A2aTaskRegistry::open(&registry_path).expect("open task registry");
    let selected_interface = A2aAgentInterface {
        url: "http://localhost:9000/rpc".to_string(),
        protocol_binding: "JSONRPC".to_string(),
        protocol_version: "1.0".to_string(),
        tenant: Some("tenant-alpha".to_string()),
    };
    let selected_binding = A2aProtocolBinding::JsonRpc;
    let context = A2aTaskRecordContext {
        source: "send_message",
        tool_name: "research",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };

    registry
        .record_from_value(
            &json!({
                "task": {
                    "id": " task-1 ",
                    "status": { "state": "TASK_STATE_WORKING" }
                },
                "statusUpdate": {
                    "taskId": "\ttask-1\n",
                    "status": { "state": "TASK_STATE_COMPLETED" }
                },
                "artifactUpdate": {
                    "taskId": " task-1 ",
                    "artifact": { "artifactId": "artifact-1" }
                }
            }),
            &context,
        )
        .expect("record padded task observations");

    let reloaded = registry.load().expect("reload task registry");
    assert_eq!(
        reloaded.tasks.len(),
        2,
        "distinct observed task ids must not be collapsed before follow-up lookup"
    );
    let record = reloaded
        .tasks
        .get(" task-1 ")
        .expect("exact task response id is recorded");
    assert_eq!(record.task_id, " task-1 ");
    assert_eq!(record.last_state.as_deref(), Some("TASK_STATE_WORKING"));
    assert!(reloaded.tasks.contains_key("\ttask-1\n"));
    let follow_up_context = A2aTaskFollowUpContext {
        operation: "get_task.id",
        tool_name: "research",
        server_id: "srv-a2a",
        selected_interface: &selected_interface,
        selected_binding: &selected_binding,
        partner: "partner-alpha",
    };
    registry
        .validate_follow_up(" task-1 ", &follow_up_context)
        .expect("exact follow-up id should match exact observation");

    let _ = fs::remove_file(registry_path);
}
