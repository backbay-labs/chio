#[tokio::test]
async fn adapter_oauth2_client_credentials_fetches_token_and_caches_it() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_oauth_client_credentials("client-id", "client-secret")
            .with_oauth_scope("offline_access")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let first = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("first OAuth-backed invoke");
    assert_eq!(
        first["message"]["parts"][0]["text"],
        "completed research request"
    );

    let second = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question again"
            }),
            None,
        )
        .await
        .expect("second OAuth-backed invoke");
    assert_eq!(
        second["message"]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].starts_with("POST /oauth/token HTTP/1.1"));
    assert!(requests[1].contains("grant_type=client_credentials"));
    assert!(requests[1].contains("a2a.invoke"));
    assert!(requests[1].contains("offline_access"));
    assert!(requests[2].contains("Authorization: Bearer oauth-access-token"));
    assert!(requests[3].contains("Authorization: Bearer oauth-access-token"));
    server.join();
}

#[tokio::test]
async fn oauth_client_credentials_form_fallback_rejects_cross_origin_redirect() {
    let Some(target_listener) = bind_fake_a2a_listener("OAuth redirect target listener") else {
        return;
    };
    let target_address = target_listener.local_addr().expect("target listener address");
    let target_base_url = format!("http://{target_address}");

    let Some(initial_listener) = bind_fake_a2a_listener("OAuth redirect initial listener")
    else {
        return;
    };
    let initial_address = initial_listener
        .local_addr()
        .expect("initial listener address");
    let initial_base_url = format!("http://{initial_address}");
    let target_base_url_for_thread = target_base_url.clone();
    let initial_handle = thread::spawn(move || {
        for request_index in 0..2 {
            let (mut stream, _) = initial_listener.accept().expect("accept token request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set token read timeout");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
            if request_index == 0 {
                assert!(request.contains("Authorization: Basic "));
                assert!(!request.contains("client_secret=client-secret"));
                write!(
                    stream,
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write 401 token response");
            } else {
                assert!(request.contains("client_id=client-id"));
                assert!(request.contains("client_secret=client-secret"));
                write!(
                    stream,
                    "HTTP/1.1 302 Found\r\nLocation: {target_base_url_for_thread}/oauth/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write cross-origin token redirect");
            }
        }
    });

    let mut contract = test_egress_contract(&initial_base_url);
    insert_test_egress_authority(&mut contract, &target_base_url);
    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(contract),
    };
    let token_endpoint =
        Url::parse(&format!("{initial_base_url}/oauth/token")).expect("token endpoint URL");
    let credentials = A2aOAuthClientCredentials {
        client_id: "client-id".to_string(),
        client_secret: "client-secret".to_string(),
    };

    let error = request_client_credentials_token(
        &token_endpoint,
        &credentials,
        &["a2a.invoke".to_string()],
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("OAuth form secret body must not be replayed cross-origin");

    initial_handle.join().expect("join OAuth redirect server");
    let message = error.to_string();
    assert!(
        message.contains("body-bearing request rejected cross-origin redirect"),
        "expected body-bearing redirect rejection, got: {message}"
    );
}

#[test]
fn oauth_client_credentials_rejects_token_response_without_bearer_type() {
    let Some(listener) = bind_fake_a2a_listener("OAuth token type listener") else {
        return;
    };
    let address = listener.local_addr().expect("token listener address");
    let base_url = format!("http://{address}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept token request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set token read timeout");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(request.contains("grant_type=client_credentials"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 49\r\nConnection: close\r\n\r\n{{\"access_token\":\"opaque-token\",\"expires_in\":3600}}"
        )
        .expect("write token response");
    });

    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(&base_url)),
    };
    let token_endpoint =
        Url::parse(&format!("{base_url}/oauth/token")).expect("token endpoint URL");
    let credentials = A2aOAuthClientCredentials {
        client_id: "client-id".to_string(),
        client_secret: "client-secret".to_string(),
    };

    let error = request_client_credentials_token(
        &token_endpoint,
        &credentials,
        &["a2a.invoke".to_string()],
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("token response without bearer token_type must fail closed");

    handle.join().expect("join token type server");
    assert!(
        error.to_string().contains("token_type"),
        "unexpected token response error: {error}"
    );
}

#[test]
fn oauth_client_credentials_rejects_padded_access_token() {
    let Some(listener) = bind_fake_a2a_listener("OAuth padded access token listener") else {
        return;
    };
    let address = listener.local_addr().expect("token listener address");
    let base_url = format!("http://{address}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept token request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set token read timeout");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(request.contains("grant_type=client_credentials"));
        let body =
            r#"{"access_token":" opaque-token ","token_type":"bearer","expires_in":3600}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write token response");
    });

    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(&base_url)),
    };
    let token_endpoint =
        Url::parse(&format!("{base_url}/oauth/token")).expect("token endpoint URL");
    let credentials = A2aOAuthClientCredentials {
        client_id: "client-id".to_string(),
        client_secret: "client-secret".to_string(),
    };

    let error = request_client_credentials_token(
        &token_endpoint,
        &credentials,
        &["a2a.invoke".to_string()],
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("padded access_token must fail closed");

    handle.join().expect("join padded access token server");
    assert!(
        error.to_string().contains("surrounding whitespace"),
        "unexpected token response error: {error}"
    );
}

#[test]
fn oauth_client_credentials_rejects_control_access_token() {
    let Some(listener) = bind_fake_a2a_listener("OAuth control access token listener") else {
        return;
    };
    let address = listener.local_addr().expect("token listener address");
    let base_url = format!("http://{address}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept token request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set token read timeout");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(request.contains("grant_type=client_credentials"));
        let body =
            r#"{"access_token":"opaque\n-token","token_type":"bearer","expires_in":3600}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write token response");
    });

    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(&base_url)),
    };
    let token_endpoint =
        Url::parse(&format!("{base_url}/oauth/token")).expect("token endpoint URL");
    let credentials = A2aOAuthClientCredentials {
        client_id: "client-id".to_string(),
        client_secret: "client-secret".to_string(),
    };

    let error = request_client_credentials_token(
        &token_endpoint,
        &credentials,
        &["a2a.invoke".to_string()],
        Duration::from_secs(2),
        &transport_config,
    )
    .expect_err("control access_token must fail closed");

    handle.join().expect("join control access token server");
    assert!(
        error.to_string().contains("whitespace or control"),
        "unexpected token response error: {error}"
    );
}

#[test]
fn oauth_client_credentials_accepts_padded_bearer_token_type() {
    let Some(listener) = bind_fake_a2a_listener("OAuth padded token type listener") else {
        return;
    };
    let address = listener.local_addr().expect("token listener address");
    let base_url = format!("http://{address}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept token request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set token read timeout");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(request.contains("grant_type=client_credentials"));
        let body =
            r#"{"access_token":"opaque-token","token_type":"  bEaReR  ","expires_in":3600}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write token response");
    });

    let transport_config = A2aTransportConfig {
        default_tls_config: None,
        mutual_tls_config: None,
        egress_contract: Some(test_egress_contract(&base_url)),
    };
    let token_endpoint =
        Url::parse(&format!("{base_url}/oauth/token")).expect("token endpoint URL");
    let credentials = A2aOAuthClientCredentials {
        client_id: "client-id".to_string(),
        client_secret: "client-secret".to_string(),
    };

    let token = request_client_credentials_token(
        &token_endpoint,
        &credentials,
        &["a2a.invoke".to_string()],
        Duration::from_secs(2),
        &transport_config,
    )
    .expect("padded bearer token_type is accepted");

    handle.join().expect("join padded token type server");
    assert_eq!(token.access_token, "opaque-token");
    assert_eq!(token.token_type.as_deref(), Some("  bEaReR  "));
}

#[tokio::test]
async fn adapter_openid_client_credentials_fetches_discovery_and_token() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_openid_client_credentials_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_oauth_client_credentials("client-id", "client-secret")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("OpenID-backed invoke");
    assert_eq!(
        result["message"]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].starts_with("GET /openid/.well-known/openid-configuration HTTP/1.1"));
    assert!(requests[2].starts_with("POST /oauth/token HTTP/1.1"));
    assert!(requests[2].contains("grant_type=client_credentials"));
    assert!(requests[2].contains("openid"));
    assert!(requests[2].contains("profile"));
    assert!(requests[3].contains("Authorization: Bearer oidc-access-token"));
    server.join();
}

#[tokio::test]
async fn adapter_required_bearer_security_without_configured_token_fails_closed() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(test_adapter_config(
        server.base_url(),
        manifest_key.public_key().to_hex(),
    ))
    .expect("discover JSONRPC adapter");

    let error = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect_err("missing bearer token should fail closed");
    assert!(error.to_string().contains("missing bearer token"));
    assert_eq!(server.requests().len(), 1);
    server.join();
}

#[tokio::test]
async fn adapter_http_basic_security_is_negotiated_from_agent_card() {
    let Some(server) = FakeA2aServer::spawn_http_json_basic_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_http_basic_auth("a2a-user", "secret-pass")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("HTTP Basic auth should satisfy requirement");
    assert_eq!(
        result["task"]["artifacts"][0]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains(&basic_request_header_value(
        "a2a-user".to_string(),
        "secret-pass".to_string()
    )));
    server.join();
}

#[tokio::test]
async fn adapter_http_basic_security_without_configured_credentials_fails_closed() {
    let (security_schemes, security_requirements) =
        agent_card_security_metadata(TestScenario::BasicRequired, "http://localhost");
    let agent_card = A2aAgentCard {
        name: "Research Agent".to_string(),
        description: "Answers research questions over A2A".to_string(),
        version: "1.0.0".to_string(),
        supported_interfaces: vec![A2aAgentInterface {
            url: "http://localhost:9000".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: None,
        }],
        security_schemes: Some(security_schemes),
        security_requirements: Some(security_requirements),
        capabilities: A2aAgentCapabilities {
            streaming: false,
            push_notifications: false,
            state_transition_history: false,
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![A2aAgentSkill {
            id: "research".to_string(),
            name: "Research".to_string(),
            description: "Search and synthesize results".to_string(),
            tags: vec!["search".to_string()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        documentation_url: None,
        icon_url: None,
    };
    let manifest = build_manifest(
        "basic-auth-test",
        "0.1.0",
        &Keypair::generate().public_key().to_hex(),
        &agent_card,
        &A2aProtocolBinding::HttpJson,
    )
    .expect("build manifest");
    let adapter = A2aAdapter {
        manifest,
        agent_card,
        agent_card_url: normalize_agent_card_url("http://localhost:9000")
            .expect("normalize agent card URL"),
        selected_interface: A2aAgentInterface {
            url: "http://localhost:9000".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: None,
        },
        selected_binding: A2aProtocolBinding::HttpJson,
        configured_headers: Vec::new(),
        configured_query_params: Vec::new(),
        configured_cookies: Vec::new(),
        oauth_client_credentials: None,
        oauth_scopes: Vec::new(),
        oauth_token_endpoint_override: None,
        transport_config: A2aTransportConfig {
            default_tls_config: None,
            mutual_tls_config: None,
            egress_contract: None,
        },
        token_cache: Mutex::new(Vec::new()),
        timeout: Duration::from_secs(2),
        request_counter: AtomicU64::new(0),
        partner_policy: None,
        task_registry: None,
    };

    let error = adapter
        .resolve_request_auth(&adapter.agent_card.skills[0])
        .expect_err("missing HTTP Basic credentials should fail closed");
    assert!(error.to_string().contains("missing HTTP Basic credentials"));
}

#[tokio::test]
async fn adapter_api_key_header_security_is_negotiated_from_agent_card() {
    let Some(server) = FakeA2aServer::spawn_http_json_api_key_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_api_key_header("X-A2A-Key", "secret-key")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("API key header should satisfy requirement");
    assert_eq!(
        result["task"]["artifacts"][0]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("X-A2A-Key: secret-key"));
    assert!(!requests[1].contains("Authorization: Bearer"));
    server.join();
}

#[tokio::test]
async fn adapter_api_key_query_security_is_negotiated_from_agent_card() {
    let Some(server) = FakeA2aServer::spawn_http_json_api_key_query_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_api_key_query_param("a2a_key", "secret-key")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("API key query param should satisfy requirement");
    assert_eq!(
        result["task"]["artifacts"][0]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /message:send?a2a_key=secret-key "));
    assert!(!requests[1].contains("Authorization: Bearer"));
    server.join();
}

#[test]
fn adapter_api_key_query_security_rejects_empty_value_before_dispatch() {
    let mut adapter = local_test_adapter(
        A2aAgentCapabilities::default(),
        A2aProtocolBinding::HttpJson,
        None,
    );
    let (security_schemes, security_requirements) =
        agent_card_security_metadata(TestScenario::ApiKeyQueryRequired, "http://localhost");
    adapter.agent_card.security_schemes = Some(security_schemes);
    adapter.agent_card.security_requirements = Some(security_requirements);
    adapter.configured_query_params = vec![A2aRequestQueryParam {
        name: "a2a_key".to_string(),
        value: String::new(),
        sensitive: false,
    }];

    let error = adapter
        .resolve_request_auth(&adapter.agent_card.skills[0])
        .expect_err("empty API key query value should fail closed before dispatch");
    assert!(error
        .to_string()
        .contains("request query parameter value"));
}

#[tokio::test]
async fn adapter_api_key_cookie_security_is_negotiated_from_agent_card() {
    let Some(server) = FakeA2aServer::spawn_http_json_api_key_cookie_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_api_key_cookie("a2a_session", "secret-cookie")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("API key cookie should satisfy requirement");
    assert_eq!(
        result["task"]["artifacts"][0]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("Cookie: a2a_session=secret-cookie"));
    assert!(!requests[1].contains("Authorization: Bearer"));
    server.join();
}

#[tokio::test]
async fn adapter_api_key_query_security_without_configured_value_fails_closed() {
    let (security_schemes, security_requirements) =
        agent_card_security_metadata(TestScenario::ApiKeyQueryRequired, "http://localhost");
    let agent_card = A2aAgentCard {
        name: "Research Agent".to_string(),
        description: "Answers research questions over A2A".to_string(),
        version: "1.0.0".to_string(),
        supported_interfaces: vec![A2aAgentInterface {
            url: "http://localhost:9000".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: None,
        }],
        security_schemes: Some(security_schemes),
        security_requirements: Some(security_requirements),
        capabilities: A2aAgentCapabilities {
            streaming: false,
            push_notifications: false,
            state_transition_history: false,
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![A2aAgentSkill {
            id: "research".to_string(),
            name: "Research".to_string(),
            description: "Search and synthesize results".to_string(),
            tags: vec!["search".to_string()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        documentation_url: None,
        icon_url: None,
    };
    let manifest = build_manifest(
        "query-auth-test",
        "0.1.0",
        &Keypair::generate().public_key().to_hex(),
        &agent_card,
        &A2aProtocolBinding::HttpJson,
    )
    .expect("build manifest");
    let adapter = A2aAdapter {
        manifest,
        agent_card,
        agent_card_url: normalize_agent_card_url("http://localhost:9000")
            .expect("normalize agent card URL"),
        selected_interface: A2aAgentInterface {
            url: "http://localhost:9000".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: None,
        },
        selected_binding: A2aProtocolBinding::HttpJson,
        configured_headers: Vec::new(),
        configured_query_params: Vec::new(),
        configured_cookies: Vec::new(),
        oauth_client_credentials: None,
        oauth_scopes: Vec::new(),
        oauth_token_endpoint_override: None,
        transport_config: A2aTransportConfig {
            default_tls_config: None,
            mutual_tls_config: None,
            egress_contract: None,
        },
        token_cache: Mutex::new(Vec::new()),
        timeout: Duration::from_secs(2),
        request_counter: AtomicU64::new(0),
        partner_policy: None,
        task_registry: None,
    };

    let error = adapter
        .resolve_request_auth(&adapter.agent_card.skills[0])
        .expect_err("missing API key query param should fail closed");
    assert!(error
        .to_string()
        .contains("missing API key query parameter"));
}

#[tokio::test]
async fn adapter_mtls_security_without_configured_identity_fails_closed() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_mtls_required() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(test_adapter_config(
        server.base_url(),
        manifest_key.public_key().to_hex(),
    ))
    .expect("discover JSONRPC adapter");

    let error = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect_err("unsupported auth should fail closed");
    assert!(error.to_string().contains("mutual TLS"));
    assert_eq!(server.requests().len(), 1);
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_mtls_security_uses_client_certificate_for_discovery_and_invoke() {
    ensure_rustls_crypto_provider();
    let Some(server) = FakeMtlsA2aServer::spawn_jsonrpc() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_tls_root_ca_pem(server.root_ca_pem())
            .with_mtls_client_auth_pem(
                server.client_cert_chain_pem(),
                server.client_private_key_pem(),
            )
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC mTLS adapter");

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "answer the question"
            }),
            None,
        )
        .await
        .expect("mTLS-backed invoke");
    assert_eq!(
        result["message"]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /.well-known/agent-card.json HTTP/1.1"));
    assert!(requests[1].starts_with("POST /rpc HTTP/1.1"));
    server.join();
}
