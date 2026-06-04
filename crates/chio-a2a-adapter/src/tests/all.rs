#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Once;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

    use chio_core::capability::{
        CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_core::receipt::Decision;
    use chio_kernel::{
        ChioKernel, KernelConfig, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair as RcgenKeyPair,
    };

    fn ensure_rustls_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = ureq::rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
    }

    fn bind_fake_a2a_listener(label: &str) -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::AddrNotAvailable
                        | std::io::ErrorKind::Unsupported
                ) =>
            {
                eprintln!("skipping {label}: loopback TCP bind unavailable: {err}");
                None
            }
            Err(err) => panic!("bind {label}: {err}"),
        }
    }

    fn test_adapter_config(base_url: &str, public_key: String) -> A2aAdapterConfig {
        A2aAdapterConfig::new(base_url, public_key)
            .with_egress_contract(test_egress_contract(base_url))
    }

    fn test_egress_contract(base_url: &str) -> HttpEgressContract {
        let url = Url::parse(base_url).expect("test base URL parses");
        let host = url.host_str().expect("test base URL has host");
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        HttpEgressContract::permissive_for_tests(&authority)
    }

    fn seed_a2a_task(adapter: &A2aAdapter, tool_name: &str, task_id: &str) {
        adapter
            .record_task_activity(
                tool_name,
                &json!({
                    "task": {
                        "id": task_id,
                        "status": { "state": "TASK_STATE_WORKING" }
                    }
                }),
                "test_seed",
            )
            .expect("seed A2A task registry");
    }

    fn insert_test_egress_authority(contract: &mut HttpEgressContract, base_url: &str) {
        let url = Url::parse(base_url).expect("test base URL parses");
        let host = url.host_str().expect("test base URL has host");
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        contract.allowed_authority_set.insert(authority);
    }

    #[tokio::test]
    async fn a2a_contract_resolver_rejects_loopback_answers() {
        let mut contract = HttpEgressContract::permissive_for_tests("127.0.0.1:80");
        contract.deny_loopback = true;
        let resolver = A2aContractResolver { contract };

        let error = ureq::Resolver::resolve(&resolver, "127.0.0.1:80")
            .expect_err("loopback DNS answers are rejected at resolver time");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("loopback"),
            "unexpected resolver error: {error}"
        );
    }

    #[test]
    fn jsonrpc_result_decoder_preserves_fail_closed_error_precedence() {
        let version_error = decode_jsonrpc_result(
            A2aJsonRpcResponse::<Value> {
                jsonrpc: "1.0".to_string(),
                result: None,
                error: Some(A2aJsonRpcError {
                    code: -32000,
                    message: "remote denied".to_string(),
                }),
            },
            "GetTask",
        )
        .expect_err("unexpected protocol version should fail before remote error");
        assert!(
            version_error
                .to_string()
                .contains("unexpected JSON-RPC version 1.0"),
            "unexpected version error: {version_error}"
        );

        let remote_error = decode_jsonrpc_result(
            A2aJsonRpcResponse::<Value> {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(A2aJsonRpcError {
                    code: -32001,
                    message: "remote denied".to_string(),
                }),
            },
            "GetTask",
        )
        .expect_err("remote JSON-RPC error should fail before missing result");
        assert!(
            remote_error
                .to_string()
                .contains("A2A JSON-RPC error -32001: remote denied"),
            "unexpected remote error: {remote_error}"
        );

        let missing_result = decode_jsonrpc_result(
            A2aJsonRpcResponse::<Value> {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
            },
            "GetTask",
        )
        .expect_err("missing result should fail closed");
        assert!(
            missing_result
                .to_string()
                .contains("A2A JSON-RPC GetTask response omitted `result`"),
            "unexpected missing-result error: {missing_result}"
        );

        let missing_unlabeled_result = decode_jsonrpc_result(
            A2aJsonRpcResponse::<Value> {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
            },
            "",
        )
        .expect_err("unlabeled response without result should fail closed");
        assert!(
            missing_unlabeled_result
                .to_string()
                .contains("A2A JSON-RPC response omitted `result`"),
            "unexpected unlabeled missing-result error: {missing_unlabeled_result}"
        );
    }

    #[test]
    fn jsonrpc_result_decoder_returns_present_result() {
        let value = decode_jsonrpc_result(
            A2aJsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(json!({ "ok": true })),
                error: None,
            },
            "GetTask",
        )
        .expect("present result should decode");

        assert_eq!(value, json!({ "ok": true }));
    }

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

    #[tokio::test]
    async fn adapter_invokes_http_json_binding() {
        let Some(server) = FakeA2aServer::spawn_http_json() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "data": { "query": "hypertension staging guidelines" },
                    "return_immediately": true
                }),
                None,
            )
            .await
            .expect("invoke research skill over HTTP+JSON");

        assert_eq!(result["task"]["id"], "task-1");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /message:send HTTP/1.1"));
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_insecure_non_localhost_urls() {
        let manifest_key = Keypair::generate();
        let error = A2aAdapter::discover(A2aAdapterConfig::new(
            "http://example.com",
            manifest_key.public_key().to_hex(),
        ))
        .expect_err("insecure remote URL should fail");
        assert!(error.to_string().contains("https"));
    }

    #[tokio::test]
    async fn adapter_jsonrpc_get_task_follow_up() {
        let registry_path = unique_path("chio-a2a-jsonrpc-follow-up", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let initial = adapter
            .invoke(
                "research",
                json!({
                    "message": "Start a long-running research task",
                    "return_immediately": true
                }),
                None,
            )
            .await
            .expect("start follow-up task");
        assert_eq!(initial["task"]["id"], "task-1");
        assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

        let follow_up = adapter
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 2
                    }
                }),
                None,
            )
            .await
            .expect("poll A2A task");
        assert_eq!(follow_up["task"]["id"], "task-1");
        assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");
        assert_eq!(
            follow_up["task"]["artifacts"][0]["parts"][0]["text"],
            "completed research request"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].contains("\"method\":\"SendMessage\""));
        assert!(requests[2].contains("\"method\":\"GetTask\""));
        assert!(requests[2].contains("\"historyLength\":2"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_http_json_get_task_follow_up() {
        let registry_path = unique_path("chio-a2a-http-follow-up", ".json");
        let Some(server) = FakeA2aServer::spawn_http_json_task_follow_up() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let initial = adapter
            .invoke(
                "research",
                json!({
                    "message": "Start a long-running research task",
                    "return_immediately": true
                }),
                None,
            )
            .await
            .expect("start follow-up task");
        assert_eq!(initial["task"]["id"], "task-1");
        assert_eq!(initial["task"]["status"]["state"], "TASK_STATE_WORKING");

        let follow_up = adapter
            .invoke(
                "research",
                json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 2
                    }
                }),
                None,
            )
            .await
            .expect("poll A2A task");
        assert_eq!(follow_up["task"]["id"], "task-1");
        assert_eq!(follow_up["task"]["status"]["state"], "TASK_STATE_COMPLETED");

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].contains("POST /message:send HTTP/1.1"));
        assert!(
            requests[2].starts_with("GET /tasks/task-1?historyLength=2 HTTP/1.1"),
            "unexpected follow-up request: {}",
            requests[2].lines().next().unwrap_or_default()
        );
        assert!(requests[2].contains("A2A-Version: 1.0"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_mixed_send_and_get_task_input() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "get_task": { "id": "task-1" }
        }))
        .expect_err("mixed invocation modes should fail");
        assert!(error
            .to_string()
            .contains("mutually exclusive with SendMessage fields"));
    }

    #[tokio::test]
    async fn adapter_rejects_mixed_send_and_subscribe_task_input() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "subscribe_task": { "id": "task-1" }
        }))
        .expect_err("mixed subscribe invocation should fail");
        assert!(error
            .to_string()
            .contains("mutually exclusive with SendMessage and `get_task` fields"));
    }

    #[test]
    fn parse_tool_input_rejects_unknown_top_level_fields() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "typoed_field": true
        }))
        .expect_err("unknown top-level tool input fields must fail closed");

        let message = error.to_string();
        assert!(
            message.contains("unknown field") && message.contains("typoed_field"),
            "unexpected unknown-field error: {message}"
        );
    }

    #[test]
    fn parse_tool_input_rejects_unknown_follow_up_fields() {
        let error = parse_tool_input(json!({
            "get_task": {
                "id": "task-1",
                "extra": true
            }
        }))
        .expect_err("unknown follow-up fields must fail closed");

        let message = error.to_string();
        assert!(
            message.contains("unknown field") && message.contains("extra"),
            "unexpected unknown-field error: {message}"
        );
    }

    #[test]
    fn parse_tool_input_rejects_unknown_push_authentication_fields() {
        let error = parse_tool_input(json!({
            "create_push_notification_config": {
                "task_id": "task-1",
                "url": "https://callback.example/hook",
                "authentication": {
                    "scheme": "bearer",
                    "extra": true
                }
            }
        }))
        .expect_err("unknown nested push authentication fields must fail closed");

        let message = error.to_string();
        assert!(
            message.contains("unknown field") && message.contains("extra"),
            "unexpected unknown-field error: {message}"
        );
    }

    #[tokio::test]
    async fn build_send_message_request_propagates_interface_tenant() {
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            supported_interfaces: vec![],
            version: "1.0.0".to_string(),
            capabilities: A2aAgentCapabilities::default(),
            security_schemes: None,
            security_requirements: None,
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
        let selected_interface = A2aAgentInterface {
            url: "http://localhost:9000/rpc".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            protocol_version: "1.0".to_string(),
            tenant: Some("tenant-alpha".to_string()),
        };
        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("build manifest");
        let adapter = A2aAdapter {
            manifest,
            agent_card: agent_card.clone(),
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface,
            selected_binding: A2aProtocolBinding::JsonRpc,
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

        let request = adapter
            .build_send_message_request(
                &agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: None,
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect("build send message request");

        assert_eq!(request.tenant.as_deref(), Some("tenant-alpha"));
    }

    #[tokio::test]
    async fn build_send_message_request_rejects_history_length_without_capability() {
        let adapter = local_test_adapter(
            A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            A2aProtocolBinding::JsonRpc,
            Some("tenant-alpha"),
        );
        let error = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: None,
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: Some(2),
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect_err("history_length without capability should fail");
        assert!(error
            .to_string()
            .contains("state transition history support"));
    }

    #[tokio::test]
    async fn build_send_message_request_rejects_text_when_skill_declares_json_only_input() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes = Some(vec!["application/json".to_string()]);

        let error = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: None,
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect_err("JSON-only A2A skill must reject text parts");
        assert!(
            error.to_string().contains("text input mode"),
            "unexpected input-mode error: {error}"
        );
    }

    #[tokio::test]
    async fn build_send_message_request_rejects_data_when_skill_declares_text_only_input() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes = Some(vec!["text/plain".to_string()]);

        let error = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: None,
                    data: Some(json!({ "query": "hello" })),
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect_err("text-only A2A skill must reject JSON data parts");
        assert!(
            error.to_string().contains("JSON input mode"),
            "unexpected input-mode error: {error}"
        );
    }

    #[tokio::test]
    async fn build_manifest_projects_skill_input_modes_into_tool_schema() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes = Some(vec!["application/json".to_string()]);

        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &adapter.agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("build manifest");
        let properties = manifest.tools[0]
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("manifest input schema exposes properties");

        assert!(!properties.contains_key("message"));
        assert!(properties.contains_key("data"));
    }

    #[tokio::test]
    async fn build_manifest_accepts_parameterized_json_input_mode() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes =
            Some(vec!["application/json; charset=utf-8".to_string()]);

        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &adapter.agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("parameterized JSON mode should project to manifest data input");
        let properties = manifest.tools[0]
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("manifest input schema exposes properties");

        assert!(!properties.contains_key("message"));
        assert!(properties.contains_key("data"));
    }

    #[tokio::test]
    async fn build_manifest_skips_non_projectable_skills() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        let mut image_skill = adapter.agent_card.skills[0].clone();
        image_skill.id = "image-only".to_string();
        image_skill.name = "Image Only".to_string();
        image_skill.input_modes = Some(vec!["image/png".to_string()]);
        adapter.agent_card.skills.push(image_skill);

        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &adapter.agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("mixed projectable and non-projectable skills should build manifest");

        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "research");
    }

    #[tokio::test]
    async fn build_manifest_rejects_when_no_skills_are_projectable() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes = Some(vec!["image/png".to_string()]);

        let error = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &adapter.agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect_err("non-projectable skills should fail manifest construction");

        assert!(matches!(error, AdapterError::NoProjectableSkillsAdvertised));
        assert!(error
            .to_string()
            .contains("none expose a Chio-projectable input mode"));
    }

    #[tokio::test]
    async fn invoke_rejects_raw_skill_filtered_from_manifest() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        let mut image_skill = adapter.agent_card.skills[0].clone();
        image_skill.id = "image-only".to_string();
        image_skill.name = "Image Only".to_string();
        image_skill.input_modes = Some(vec!["image/png".to_string()]);
        adapter.agent_card.skills.push(image_skill);

        assert_eq!(adapter.tool_names(), vec!["research".to_string()]);

        let error = adapter
            .invoke(
                "image-only",
                json!({
                    "get_task": { "id": "task-1" }
                }),
                None,
            )
            .await
            .expect_err("non-manifest skill should not be invokable");

        assert!(matches!(
            error,
            KernelError::ToolNotRegistered(ref tool_name) if tool_name == "image-only"
        ));
    }

    #[tokio::test]
    async fn invoke_stream_rejects_raw_skill_filtered_from_manifest() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities {
                streaming: true,
                push_notifications: false,
                state_transition_history: false,
            },
            A2aProtocolBinding::JsonRpc,
            None,
        );
        let mut image_skill = adapter.agent_card.skills[0].clone();
        image_skill.id = "image-only".to_string();
        image_skill.name = "Image Only".to_string();
        image_skill.input_modes = Some(vec!["image/png".to_string()]);
        adapter.agent_card.skills.push(image_skill);

        assert_eq!(adapter.tool_names(), vec!["research".to_string()]);

        let error = adapter
            .invoke_stream(
                "image-only",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .await
            .expect_err("non-manifest skill should not be stream-invokable");

        assert!(matches!(
            error,
            KernelError::ToolNotRegistered(ref tool_name) if tool_name == "image-only"
        ));
    }

    #[tokio::test]
    async fn build_send_message_request_accepts_parameterized_text_and_json_input_modes() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.skills[0].input_modes = Some(vec![
            "text/plain; charset=utf-8".to_string(),
            "application/json; charset=utf-8".to_string(),
        ]);

        let request = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: Some(json!({ "query": "hello" })),
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect("parameterized text and JSON modes should admit both part shapes");

        assert_eq!(request.message.parts.len(), 2);
        assert_eq!(
            request.message.parts[0].media_type.as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            request.message.parts[1].media_type.as_deref(),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn empty_default_input_modes_accept_text_and_json() {
        let mut adapter = local_test_adapter(
            A2aAgentCapabilities::default(),
            A2aProtocolBinding::JsonRpc,
            None,
        );
        adapter.agent_card.default_input_modes.clear();
        adapter.agent_card.skills[0].input_modes = None;

        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &adapter.agent_card,
            &A2aProtocolBinding::JsonRpc,
        )
        .expect("empty default input modes should fall back to text and JSON");
        let properties = manifest.tools[0]
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("manifest input schema exposes properties");
        assert!(properties.contains_key("message"));
        assert!(properties.contains_key("data"));

        let request = adapter
            .build_send_message_request(
                &adapter.agent_card.skills[0],
                A2aSendToolInput {
                    message: Some("hello".to_string()),
                    data: Some(json!({ "query": "hello" })),
                    context_id: None,
                    task_id: None,
                    reference_task_ids: None,
                    metadata: None,
                    message_metadata: None,
                    history_length: None,
                    return_immediately: None,
                    stream: false,
                },
            )
            .expect("empty default input modes should admit text and JSON parts");

        assert_eq!(request.message.parts.len(), 2);
    }

    #[test]
    fn send_message_schema_requirement_rejects_empty_surface() {
        let mut one_of = Vec::new();
        let error = append_send_message_schema_requirement(
            &mut one_of,
            A2aSkillInputSurface {
                accepts_text: false,
                accepts_json: false,
            },
        )
        .expect_err("empty send surface must not emit an empty anyOf schema");

        assert!(
            error.to_string().contains("SendMessage schema requires"),
            "unexpected schema invariant error: {error}"
        );
        assert!(one_of.is_empty());
    }

    #[tokio::test]
    async fn get_task_rejects_history_length_without_capability() {
        let adapter = local_test_adapter(
            A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            A2aProtocolBinding::HttpJson,
            None,
        );
        let error = adapter
            .get_task_http_json(
                A2aGetTaskToolInput {
                    id: "task-1".to_string(),
                    history_length: Some(1),
                },
                &A2aResolvedRequestAuth {
                    headers: Vec::new(),
                    query_params: Vec::new(),
                    cookies: Vec::new(),
                    tls_mode: A2aTlsMode::Default,
                },
            )
            .expect_err("history_length without capability should fail");
        assert!(error
            .to_string()
            .contains("state transition history support"));
    }

    fn local_test_adapter(
        capabilities: A2aAgentCapabilities,
        selected_binding: A2aProtocolBinding,
        tenant: Option<&str>,
    ) -> A2aAdapter {
        let agent_card = A2aAgentCard {
            name: "Research Agent".to_string(),
            description: "Answers research questions over A2A".to_string(),
            supported_interfaces: vec![],
            version: "1.0.0".to_string(),
            capabilities,
            security_schemes: None,
            security_requirements: None,
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
        let selected_interface = A2aAgentInterface {
            url: match selected_binding {
                A2aProtocolBinding::JsonRpc => "http://localhost:9000/rpc".to_string(),
                A2aProtocolBinding::HttpJson => "http://localhost:9000".to_string(),
            },
            protocol_binding: match selected_binding {
                A2aProtocolBinding::JsonRpc => "JSONRPC".to_string(),
                A2aProtocolBinding::HttpJson => "HTTP+JSON".to_string(),
            },
            protocol_version: "1.0".to_string(),
            tenant: tenant.map(ToString::to_string),
        };
        let manifest = build_manifest(
            "tenant-test",
            "0.1.0",
            &Keypair::generate().public_key().to_hex(),
            &agent_card,
            &selected_binding,
        )
        .expect("build manifest");
        A2aAdapter {
            manifest,
            agent_card,
            agent_card_url: normalize_agent_card_url("http://localhost:9000")
                .expect("normalize agent card URL"),
            selected_interface,
            selected_binding,
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
        }
    }

    #[tokio::test]
    async fn validate_send_message_response_rejects_task_without_status_state() {
        let error = validate_send_message_response(A2aSendMessageResponse {
            task: Some(json!({
                "id": "task-1"
            })),
            message: None,
        })
        .expect_err("task without status.state should fail");
        assert!(error.to_string().contains("status.state"));
    }

    #[tokio::test]
    async fn validate_stream_response_rejects_status_update_without_task_id() {
        let error = validate_stream_response(json!({
            "statusUpdate": {
                "status": { "state": "TASK_STATE_COMPLETED" }
            }
        }))
        .expect_err("statusUpdate without taskId should fail");
        assert!(error.to_string().contains("taskId"));
    }

    #[tokio::test]
    async fn validate_stream_response_rejects_artifact_update_without_task_id() {
        let error = validate_stream_response(json!({
            "artifactUpdate": {
                "artifact": {
                    "artifactId": "artifact-1"
                }
            }
        }))
        .expect_err("artifactUpdate without taskId should fail");
        assert!(error.to_string().contains("taskId"));
    }

    #[tokio::test]
    async fn build_get_task_url_appends_tenant_and_history_length() {
        let url = build_get_task_url(
            "http://localhost:9000",
            "task-1",
            Some("tenant-alpha"),
            Some(2),
        )
        .expect("build get task URL");

        assert_eq!(
            url.as_str(),
            "http://localhost:9000/tenant-alpha/tasks/task-1?historyLength=2"
        );
    }

    #[tokio::test]
    async fn build_send_message_url_appends_tenant_path_segment() {
        let send_url =
            build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), false)
                .expect("build send message URL");
        let stream_url =
            build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), true)
                .expect("build stream message URL");

        assert_eq!(
            send_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/message:send"
        );
        assert_eq!(
            stream_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/message:stream"
        );
    }

    #[tokio::test]
    async fn build_cancel_task_url_appends_tenant_path_segment() {
        let url =
            build_cancel_task_url("http://localhost:9000/api", "task-1", Some("tenant-alpha"))
                .expect("build cancel task URL");

        assert_eq!(
            url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1:cancel"
        );
    }

    #[tokio::test]
    async fn build_push_notification_urls_append_tenant_path_segment() {
        let collection_url = build_push_notification_configs_url(
            "http://localhost:9000/api",
            "task-1",
            Some("tenant-alpha"),
        )
        .expect("build push notification configs URL");
        let config_url = build_push_notification_config_url(
            "http://localhost:9000/api",
            "task-1",
            "config-1",
            Some("tenant-alpha"),
        )
        .expect("build push notification config URL");
        let list_url = build_list_push_notification_configs_url(
            "http://localhost:9000/api",
            "task-1",
            Some("tenant-alpha"),
            Some(25),
            Some("page-2"),
        )
        .expect("build list push notification configs URL");

        assert_eq!(
            collection_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs"
        );
        assert_eq!(
            config_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs/config-1"
        );
        assert_eq!(
            list_url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"
        );
    }

    #[tokio::test]
    async fn adapter_invoke_stream_returns_none_without_stream_flag() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Do not stream this"
                }),
                None,
            )
            .await
            .expect("invoke_stream should not fail");
        assert!(stream.is_none());
        let _ = adapter
            .invoke(
                "research",
                json!({
                    "message": "finish request log"
                }),
                None,
            )
            .await
            .expect("invoke blocking request");
        server.join();
    }

    #[tokio::test]
    async fn adapter_jsonrpc_streaming_invocation_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[0].data["task"]["status"]["state"],
            "TASK_STATE_WORKING"
        );
        assert_eq!(
            stream.chunks[1].data["artifactUpdate"]["artifact"]["parts"][0]["text"],
            "partial research result"
        );
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"SendStreamingMessage\""));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_blocking_registry_conflict_rejects_rebound_task_response() {
        let registry_path = unique_path("chio-a2a-http-blocking-conflict", ".json");
        let Some(server) = FakeA2aServer::spawn_http_json() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");
        seed_a2a_task(&adapter, "clinical_search", "task-1");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "data": { "query": "hypertension staging guidelines" },
                    "return_immediately": true
                }),
                None,
            )
            .await
            .expect_err("registry conflict should fail the blocking response");
        server.join();

        assert!(error.to_string().contains("attempted to rebind"));
        assert!(
            adapter
                .validate_task_binding("research", "task-1", "test_follow_up")
                .is_err(),
            "conflicting registry binding must still deny future follow-up"
        );

        let _ = fs::remove_file(registry_path);
    }

    #[tokio::test]
    async fn adapter_streaming_registry_conflict_rejects_rebound_stream() {
        let registry_path = unique_path("chio-a2a-jsonrpc-stream-conflict", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "clinical_search", "task-1");

        let error = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await
            .expect_err("registry conflict should fail the stream response");
        server.join();

        assert!(error.to_string().contains("attempted to rebind"));
        assert!(
            adapter
                .validate_task_binding("research", "task-1", "test_follow_up")
                .is_err(),
            "conflicting registry binding must still deny future follow-up"
        );

        let _ = fs::remove_file(registry_path);
    }

    #[tokio::test]
    async fn adapter_streaming_registry_corruption_fails_closed() {
        let registry_path = unique_path("chio-a2a-jsonrpc-stream-corrupt", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        fs::write(&registry_path, b"{not-json").expect("corrupt task registry");

        let stream_result = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await;
        server.join();

        let error = stream_result.expect_err("corrupt stream registry should fail closed");
        assert!(
            error
                .to_string()
                .contains("failed to parse A2A task registry"),
            "unexpected stream error: {error}"
        );

        let _ = fs::remove_file(registry_path);
    }

    #[tokio::test]
    async fn adapter_streaming_registry_corruption_with_rebind_phrase_fails_closed() {
        let registry_path = unique_path(
            "chio-a2a-jsonrpc-stream-attempted to rebind-corrupt",
            ".json",
        );
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        fs::write(&registry_path, b"{not-json").expect("corrupt task registry");

        let stream_result = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await;
        server.join();

        let error = stream_result
            .expect_err("corrupt stream registry path text must not bypass fail-closed handling");
        assert!(
            error
                .to_string()
                .contains("failed to parse A2A task registry"),
            "unexpected stream error: {error}"
        );

        let _ = fs::remove_file(registry_path);
    }

    #[tokio::test]
    async fn adapter_http_json_streaming_invocation_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_http_json_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /message:stream HTTP/1.1"));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_streaming_closure_without_terminal_state_is_incomplete() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_incomplete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                None,
            )
            .await
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[tokio::test]
    async fn sse_parser_stops_after_terminal_task_state() {
        let terminal = json!({
            "task": task_payload("TASK_STATE_COMPLETED", true)
        });
        let body = format!(
            "data: {}\n\ndata: {{not-json}}\n\n",
            serde_json::to_string(&terminal).unwrap()
        );

        let parsed = parse_sse_stream(body.as_bytes(), Ok).unwrap();

        let ToolServerStreamResult::Complete(stream) = parsed else {
            panic!("expected terminal stream to complete");
        };
        assert_eq!(stream.chunk_count(), 1);
    }

    #[tokio::test]
    async fn sse_parser_rejects_oversized_line() {
        let huge_text = "a".repeat(20_000);
        let event = json!({
            "message": {
                "messageId": "msg-huge",
                "role": "agent",
                "parts": [{ "text": huge_text }]
            }
        });
        let body = format!("data: {}\n\n", serde_json::to_string(&event).unwrap());

        let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

        assert!(error.to_string().contains("line"));
    }

    #[tokio::test]
    async fn sse_parser_rejects_oversized_delimiterless_line() {
        let body = format!("data: {}", "x".repeat(MAX_SSE_LINE_BYTES + 1));

        let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

        assert!(error.to_string().contains("line"));
    }

    #[tokio::test]
    async fn sse_parser_charges_oversized_line_against_response_limit() {
        let body = format!("data: {}\n", "x".repeat(MAX_SSE_LINE_BYTES + 1));

        let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("response bytes"));
        assert!(!message.contains("line"));
    }

    #[tokio::test]
    async fn sse_parser_charges_delimiterless_line_against_response_limit() {
        let body = format!("data: {}", "x".repeat(MAX_SSE_LINE_BYTES + 1));

        let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("response bytes"));
        assert!(!message.contains("line"));
    }

    #[tokio::test]
    async fn sse_line_reader_consumes_chunk_on_response_limit_error() {
        let body = b"data: overflow\nnext: event\n";
        let mut reader = BufReader::new(body.as_slice());
        let mut line = String::new();
        let mut total_bytes = 0;

        let error = read_sse_line(&mut reader, &mut line, &mut total_bytes, 8).unwrap_err();

        assert!(error.to_string().contains("response bytes"));
        assert!(line.is_empty());
        assert_eq!(total_bytes, "data: overflow\n".len() as u64);
        assert_eq!(reader.fill_buf().unwrap(), b"next: event\n");
    }

    #[tokio::test]
    async fn sse_line_reader_consumes_chunk_on_byte_counter_overflow_error() {
        let body = b"data: overflow\nnext: event\n";
        let mut reader = BufReader::new(body.as_slice());
        let mut line = String::new();
        let mut total_bytes = u64::MAX;

        let error =
            read_sse_line(&mut reader, &mut line, &mut total_bytes, u64::MAX).unwrap_err();

        assert!(error.to_string().contains("byte counter overflowed"));
        assert!(line.is_empty());
        assert_eq!(total_bytes, u64::MAX);
        assert_eq!(reader.fill_buf().unwrap(), b"next: event\n");
    }

    #[tokio::test]
    async fn sse_parser_preserves_utf8_split_across_reads() {
        struct OneByteReader {
            bytes: Vec<u8>,
            offset: usize,
        }

        impl Read for OneByteReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.offset >= self.bytes.len() || output.is_empty() {
                    return Ok(0);
                }
                output[0] = self.bytes[self.offset];
                self.offset += 1;
                Ok(1)
            }
        }

        let text = "caf\u{00e9}";
        let terminal = json!({
            "message": {
                "messageId": "msg-utf8",
                "role": "agent",
                "parts": [{ "text": text }]
            }
        });
        let body = format!("data: {}\n\n", serde_json::to_string(&terminal).unwrap());

        let parsed = parse_sse_stream(
            OneByteReader {
                bytes: body.into_bytes(),
                offset: 0,
            },
            Ok,
        )
        .unwrap();

        let ToolServerStreamResult::Complete(stream) = parsed else {
            panic!("expected terminal stream to complete");
        };
        assert_eq!(stream.chunks[0].data["message"]["parts"][0]["text"], text);
    }

    #[tokio::test]
    async fn sse_parser_enforces_contract_response_limit() {
        let working = json!({
            "task": task_payload("TASK_STATE_WORKING", false)
        });
        let body = format!("data: {}\n\n", serde_json::to_string(&working).unwrap());

        let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();

        assert!(error.to_string().contains("response bytes"));
    }

    #[tokio::test]
    async fn sse_parser_rejects_too_many_chunks() {
        let working = json!({
            "task": task_payload("TASK_STATE_WORKING", false)
        });
        let mut body = String::new();
        for _ in 0..1_100 {
            body.push_str("data: ");
            body.push_str(&serde_json::to_string(&working).unwrap());
            body.push_str("\n\n");
        }

        let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

        assert!(error.to_string().contains("chunk"));
    }

    #[tokio::test]
    async fn adapter_jsonrpc_subscribe_task_returns_complete_stream() {
        let registry_path = unique_path("chio-a2a-jsonrpc-subscribe", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .await
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"SubscribeToTask\""));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_http_json_subscribe_task_returns_complete_stream() {
        let registry_path = unique_path("chio-a2a-http-subscribe", ".json");
        let Some(server) = FakeA2aServer::spawn_http_json_subscribe_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .await
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Complete(stream) = stream else {
            panic!("expected complete stream");
        };
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("GET /tasks/task-1:subscribe HTTP/1.1"));
        assert!(requests[1].contains("Accept: text/event-stream"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_subscribe_task_closure_without_terminal_state_is_incomplete() {
        let registry_path = unique_path("chio-a2a-jsonrpc-subscribe-incomplete", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .await
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_jsonrpc_cancel_task_returns_cancelled_task() {
        let registry_path = unique_path("chio-a2a-jsonrpc-cancel", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_cancel_task() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                None,
            )
            .await
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"CancelTask\""));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[tokio::test]
    async fn adapter_http_json_cancel_task_returns_cancelled_task() {
        let registry_path = unique_path("chio-a2a-http-cancel", ".json");
        let Some(server) = FakeA2aServer::spawn_http_json_cancel_task() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let result = adapter
            .invoke(
                "research",
                json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                None,
            )
            .await
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /tasks/task-1:cancel HTTP/1.1"));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[tokio::test]
    async fn adapter_jsonrpc_push_notification_config_crud_roundtrip() {
        let registry_path = unique_path("chio-a2a-jsonrpc-push", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_crud() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let created = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://callbacks.example.com/chio",
                        "token": "notify-token",
                        "authentication": {
                            "scheme": "bearer",
                            "credentials": "callback-secret"
                        }
                    }
                }),
                None,
            )
            .await
            .expect("create push notification config");
        assert_eq!(
            created["push_notification_config"]["id"],
            Value::String("config-1".to_string())
        );

        let fetched = adapter
            .invoke(
                "research",
                json!({
                    "get_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .await
            .expect("get push notification config");
        assert_eq!(
            fetched["push_notification_config"]["url"],
            "https://callbacks.example.com/chio"
        );

        let listed = adapter
            .invoke(
                "research",
                json!({
                    "list_push_notification_configs": {
                        "task_id": "task-1",
                        "page_size": 25,
                        "page_token": "page-2"
                    }
                }),
                None,
            )
            .await
            .expect("list push notification configs");
        assert_eq!(
            listed["push_notification_configs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(listed["next_page_token"], "next-page");

        let deleted = adapter
            .invoke(
                "research",
                json!({
                    "delete_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .await
            .expect("delete push notification config");
        assert_eq!(deleted["deleted"], Value::Bool(true));

        let requests = server.requests();
        assert_eq!(requests.len(), 5);
        assert!(requests[1].contains("\"method\":\"CreateTaskPushNotificationConfig\""));
        assert!(requests[2].contains("\"method\":\"GetTaskPushNotificationConfig\""));
        assert!(requests[3].contains("\"method\":\"ListTaskPushNotificationConfigs\""));
        assert!(requests[4].contains("\"method\":\"DeleteTaskPushNotificationConfig\""));
        server.join();
    }

    #[tokio::test]
    async fn adapter_http_json_push_notification_config_crud_roundtrip() {
        let registry_path = unique_path("chio-a2a-http-push", ".json");
        let Some(server) = FakeA2aServer::spawn_http_json_push_notification_crud() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let created = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://callbacks.example.com/chio",
                        "token": "notify-token",
                        "authentication": {
                            "scheme": "bearer",
                            "credentials": "callback-secret"
                        }
                    }
                }),
                None,
            )
            .await
            .expect("create push notification config");
        assert_eq!(
            created["push_notification_config"]["authentication"]["scheme"],
            "bearer"
        );

        let fetched = adapter
            .invoke(
                "research",
                json!({
                    "get_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .await
            .expect("get push notification config");
        assert_eq!(
            fetched["push_notification_config"]["id"],
            Value::String("config-1".to_string())
        );

        let listed = adapter
            .invoke(
                "research",
                json!({
                    "list_push_notification_configs": {
                        "task_id": "task-1",
                        "page_size": 25,
                        "page_token": "page-2"
                    }
                }),
                None,
            )
            .await
            .expect("list push notification configs");
        assert_eq!(
            listed["push_notification_configs"][0]["authentication"]["credentials"],
            "callback-secret"
        );

        let deleted = adapter
            .invoke(
                "research",
                json!({
                    "delete_push_notification_config": {
                        "task_id": "task-1",
                        "id": "config-1"
                    }
                }),
                None,
            )
            .await
            .expect("delete push notification config");
        assert_eq!(deleted["deleted"], Value::Bool(true));

        let requests = server.requests();
        assert_eq!(requests.len(), 5);
        assert!(requests[1].starts_with("POST /tasks/task-1/pushNotificationConfigs HTTP/1.1"));
        assert!(
            requests[2].starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1")
        );
        assert!(requests[3].starts_with(
            "GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2 HTTP/1.1"
        ));
        assert!(requests[4]
            .starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1"));
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_insecure_push_notification_callback_url() {
        let registry_path = unique_path("chio-a2a-insecure-push", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "http://example.com/callback"
                    }
                }),
                None,
            )
            .await
            .expect_err("insecure callback URL should fail closed");
        assert!(error
            .to_string()
            .contains("push notification URL must use https"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_push_notification_callback_url_userinfo_before_dispatch() {
        let registry_path = unique_path("chio-a2a-userinfo-push", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://user:secret@callbacks.example.com/chio"
                    }
                }),
                None,
            )
            .await
            .expect_err("callback URL userinfo should fail closed");
        assert!(error
            .to_string()
            .contains("push notification URL must not include userinfo"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_push_notification_callback_url_fragment_before_dispatch() {
        let registry_path = unique_path("chio-a2a-fragment-push", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        let error = adapter
            .invoke(
                "research",
                json!({
                    "create_push_notification_config": {
                        "task_id": "task-1",
                        "url": "https://callbacks.example.com/chio#secret"
                    }
                }),
                None,
            )
            .await
            .expect_err("callback URL fragment should fail closed");
        assert!(error
            .to_string()
            .contains("push notification URL must not include a fragment"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[tokio::test]
    async fn adapter_rejects_malformed_push_notification_auth_material_before_dispatch() {
        let registry_path = unique_path("chio-a2a-push-auth-material", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");
        seed_a2a_task(&adapter, "research", "task-1");

        for (input, expected_error) in [
            (
                json!({
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio",
                    "token": " "
                }),
                "`create_push_notification_config.token` must be a non-empty unpadded string without control characters",
            ),
            (
                json!({
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio",
                    "authentication": {
                        "scheme": "bearer\n",
                        "credentials": "callback-secret"
                    }
                }),
                "`authentication.scheme` must be a non-empty HTTP token",
            ),
            (
                json!({
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio",
                    "authentication": {
                        "scheme": "bearer",
                        "credentials": " callback-secret "
                    }
                }),
                "`authentication.credentials` must be a non-empty unpadded string without control characters",
            ),
        ] {
            let error = adapter
                .invoke(
                    "research",
                    json!({ "create_push_notification_config": input }),
                    None,
                )
                .await
                .expect_err("malformed push notification auth material should fail closed");
            assert!(
                error.to_string().contains(expected_error),
                "unexpected push auth material error: {error}"
            );
            assert_eq!(server.requests().len(), 1);
        }
        server.join();
    }

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

    #[tokio::test]
    async fn kernel_e2e_a2a_invocation_produces_allow_receipt() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-a2a".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.clone(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .expect("sign capability");

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Summarize the current blood pressure guidance",
                    "metadata": { "origin": "kernel-test" }
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(response.receipt.body().tool_name, "research");
        assert_eq!(response.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_query_api_key_invocation_produces_allow_receipt() {
        let Some(server) = FakeA2aServer::spawn_http_json_api_key_query_required() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_api_key_query_param("a2a_key", "secret-key")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover query-auth adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-query-auth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-query-auth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate query-auth A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(
            response.output.expect("tool output").into_value()["task"]["artifacts"][0]["parts"][0]
                ["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /message:send?a2a_key=secret-key "));
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_basic_auth_invocation_produces_allow_receipt() {
        let Some(server) = FakeA2aServer::spawn_http_json_basic_required() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_http_basic_auth("a2a-user", "secret-pass")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover basic-auth adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-basic-auth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-basic-auth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate basic-auth A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(
            response.output.expect("tool output").into_value()["task"]["artifacts"][0]["parts"][0]
                ["text"],
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
    async fn kernel_e2e_a2a_mtls_invocation_produces_allow_receipt() {
        ensure_rustls_crypto_provider();
        let Some(server) = FakeMtlsA2aServer::spawn_jsonrpc() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
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
        .expect("discover mTLS adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-mtls");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-mtls".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Summarize the current blood pressure guidance"
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate mTLS A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(response.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_get_task_follow_up_produces_allow_receipt() {
        let registry_path = unique_path("chio-a2a-kernel-follow-up", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        let expected_server_id = server_id.clone();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-a2a-follow-up".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.clone(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .expect("sign capability");

        let initial = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-start".to_string(),
                capability: capability.clone(),
                tool_name: "research".to_string(),
                server_id: server_id.clone(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Begin longer research task",
                    "return_immediately": true
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate initial A2A tool call");
        assert_eq!(initial.verdict, Verdict::Allow);
        assert_eq!(initial.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(initial.receipt.body().tool_server, expected_server_id);
        assert_eq!(
            initial.output.expect("initial task output").into_value()["task"]["status"]["state"],
            "TASK_STATE_WORKING"
        );

        let follow_up = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-poll".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "get_task": {
                        "id": "task-1",
                        "history_length": 1
                    }
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate follow-up A2A tool call");

        assert_eq!(follow_up.verdict, Verdict::Allow);
        assert_eq!(follow_up.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(follow_up.receipt.body().tool_name, "research");
        assert_eq!(
            follow_up
                .output
                .expect("follow-up task output")
                .into_value()["task"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].contains("\"method\":\"GetTask\""));
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_cancel_task_produces_allow_receipt() {
        let registry_path = unique_path("chio-a2a-kernel-cancel", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_cancel_task() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        seed_a2a_task(&adapter, "research", "task-1");

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-cancel");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-cancel".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "cancel_task": {
                        "id": "task-1",
                        "metadata": { "reason": "user-request" }
                    }
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate cancel-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(
            response.output.expect("cancel task output").into_value()["task"]["status"]["state"],
            "TASK_STATE_CANCELED"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"CancelTask\""));
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_streaming_invocation_produces_allow_receipt() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-stream");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-stream".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate streaming A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        let stream = response.output.expect("stream output").into_stream();
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_incomplete_streaming_invocation_produces_incomplete_receipt() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_incomplete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability =
            test_capability(&issuer, &subject, &server_id, "cap-a2a-stream-incomplete");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-stream-incomplete".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "Stream the answer",
                    "stream": true
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate incomplete streaming A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(matches!(
            response.receipt.body().decision,
            Some(Decision::Incomplete { .. })
        ));
        let stream = response
            .output
            .expect("partial stream output")
            .into_stream();
        assert_eq!(stream.chunk_count(), 2);
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_subscribe_task_produces_allow_receipt() {
        let registry_path = unique_path("chio-a2a-kernel-subscribe", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_complete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        seed_a2a_task(&adapter, "research", "task-1");

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-subscribe");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-subscribe".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate subscribe-to-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        let stream = response.output.expect("stream output").into_stream();
        assert_eq!(stream.chunk_count(), 3);
        assert_eq!(
            stream.chunks[2].data["statusUpdate"]["status"]["state"],
            "TASK_STATE_COMPLETED"
        );
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_a2a_incomplete_subscribe_task_produces_incomplete_receipt() {
        let registry_path = unique_path("chio-a2a-kernel-subscribe-incomplete", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_task_registry_file(&registry_path)
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();
        seed_a2a_task(&adapter, "research", "task-1");

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(
            &issuer,
            &subject,
            &server_id,
            "cap-a2a-subscribe-incomplete",
        );
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-subscribe-incomplete".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate incomplete subscribe-to-task A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(matches!(
            response.receipt.body().decision,
            Some(Decision::Incomplete { .. })
        ));
        let stream = response
            .output
            .expect("partial stream output")
            .into_stream();
        assert_eq!(stream.chunk_count(), 2);
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_missing_required_bearer_security_denies_request() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(test_adapter_config(
            server.base_url(),
            manifest_key.public_key().to_hex(),
        ))
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-auth-deny");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-auth-deny".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate A2A tool call");

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("missing bearer token"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[tokio::test]
    async fn kernel_e2e_oauth_client_credentials_allows_request() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_single_invoke()
        else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
                .with_oauth_client_credentials("client-id", "client-secret")
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover adapter");
        let server_id = adapter.server_id().to_string();

        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![issuer.public_key()],
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(adapter));

        let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-oauth");
        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-a2a-oauth".to_string(),
                capability,
                tool_name: "research".to_string(),
                server_id,
                agent_id: subject.public_key().to_hex(),
                arguments: json!({
                    "message": "answer the question"
                }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .await
            .expect("evaluate OAuth-backed A2A tool call");

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.body().decision, Some(Decision::Allow));
        assert_eq!(
            response.output.expect("tool output").into_value()["message"]["parts"][0]["text"],
            "completed research request"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].starts_with("POST /oauth/token HTTP/1.1"));
        assert!(requests[2].contains("Authorization: Bearer oauth-access-token"));
        server.join();
    }

    #[derive(Clone, Copy)]
    enum TestBinding {
        JsonRpc,
        HttpJson,
    }

    #[derive(Clone, Copy)]
    enum TestScenario {
        BlockingMessage,
        TaskFollowUp,
        CancelTask,
        PushNotificationCrud,
        PushNotificationCapabilityOnly,
        OAuthClientCredentialsRequired,
        OAuthClientCredentialsSingleInvoke,
        OpenIdClientCredentialsRequired,
        MissingSendMessageResult,
        StreamingComplete,
        StreamingIncomplete,
        SubscribeComplete,
        SubscribeIncomplete,
        BearerRequired,
        BasicRequired,
        ApiKeyRequired,
        ApiKeyQueryRequired,
        ApiKeyCookieRequired,
        MutualTlsRequired,
    }

    enum TestResponse {
        Json(Value),
        EventStream(String),
    }

    struct FakeA2aServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl FakeA2aServer {
        fn spawn_jsonrpc() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::BlockingMessage)
        }

        fn spawn_jsonrpc_task_follow_up() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::TaskFollowUp)
        }

        fn spawn_jsonrpc_missing_send_message_result() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::MissingSendMessageResult)
        }

        fn spawn_http_json() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::BlockingMessage)
        }

        fn spawn_http_json_task_follow_up() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::TaskFollowUp)
        }

        fn spawn_jsonrpc_cancel_task() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::CancelTask)
        }

        fn spawn_http_json_cancel_task() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::CancelTask)
        }

        fn spawn_jsonrpc_push_notification_crud() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::PushNotificationCrud)
        }

        fn spawn_http_json_push_notification_crud() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::PushNotificationCrud)
        }

        fn spawn_jsonrpc_push_notification_capability_only() -> Option<Self> {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::PushNotificationCapabilityOnly,
            )
        }

        fn spawn_jsonrpc_oauth_client_credentials_required() -> Option<Self> {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OAuthClientCredentialsRequired,
            )
        }

        fn spawn_jsonrpc_oauth_client_credentials_single_invoke() -> Option<Self> {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OAuthClientCredentialsSingleInvoke,
            )
        }

        fn spawn_jsonrpc_openid_client_credentials_required() -> Option<Self> {
            Self::spawn(
                TestBinding::JsonRpc,
                TestScenario::OpenIdClientCredentialsRequired,
            )
        }

        fn spawn_jsonrpc_streaming_complete() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingComplete)
        }

        fn spawn_http_json_streaming_complete() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::StreamingComplete)
        }

        fn spawn_jsonrpc_streaming_incomplete() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingIncomplete)
        }

        fn spawn_jsonrpc_subscribe_complete() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeComplete)
        }

        fn spawn_http_json_subscribe_complete() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::SubscribeComplete)
        }

        fn spawn_jsonrpc_subscribe_incomplete() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeIncomplete)
        }

        fn spawn_jsonrpc_bearer_required() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::BearerRequired)
        }

        fn spawn_http_json_basic_required() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::BasicRequired)
        }

        fn spawn_http_json_api_key_required() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyRequired)
        }

        fn spawn_http_json_api_key_query_required() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyQueryRequired)
        }

        fn spawn_http_json_api_key_cookie_required() -> Option<Self> {
            Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyCookieRequired)
        }

        fn spawn_jsonrpc_mtls_required() -> Option<Self> {
            Self::spawn(TestBinding::JsonRpc, TestScenario::MutualTlsRequired)
        }

        fn spawn(binding: TestBinding, scenario: TestScenario) -> Option<Self> {
            let listener = bind_fake_a2a_listener("fake A2A listener")?;
            let address = listener.local_addr().expect("listener address");
            let base_url = format!("http://{address}");
            let base_url_for_thread = base_url.clone();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let (ready_tx, ready_rx) = mpsc::channel();

            let handle = thread::spawn(move || {
                ready_tx.send(()).expect("server ready");
                let expected_requests = match scenario {
                    TestScenario::BlockingMessage => 2,
                    TestScenario::TaskFollowUp => 3,
                    TestScenario::CancelTask => 2,
                    TestScenario::PushNotificationCrud => 5,
                    TestScenario::PushNotificationCapabilityOnly => 1,
                    TestScenario::OAuthClientCredentialsRequired => 4,
                    TestScenario::OAuthClientCredentialsSingleInvoke => 3,
                    TestScenario::OpenIdClientCredentialsRequired => 4,
                    TestScenario::MissingSendMessageResult => 2,
                    TestScenario::StreamingComplete
                    | TestScenario::StreamingIncomplete
                    | TestScenario::SubscribeComplete
                    | TestScenario::SubscribeIncomplete
                    | TestScenario::BasicRequired
                    | TestScenario::ApiKeyRequired
                    | TestScenario::ApiKeyQueryRequired
                    | TestScenario::ApiKeyCookieRequired => 2,
                    TestScenario::BearerRequired | TestScenario::MutualTlsRequired => 1,
                };
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("accept request");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set read timeout");
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .expect("lock request log")
                        .push(request.clone());
                    let first_line = request.lines().next().unwrap_or_default();
                    let response_body = if first_line
                        .starts_with("GET /.well-known/agent-card.json")
                    {
                        let interface = match binding {
                            TestBinding::JsonRpc => json!([{
                                "url": format!("{base_url_for_thread}/rpc"),
                                "protocolBinding": "JSONRPC",
                                "protocolVersion": "1.0"
                            }]),
                            TestBinding::HttpJson => json!([{
                                "url": base_url_for_thread,
                                "protocolBinding": "HTTP+JSON",
                                "protocolVersion": "1.0"
                            }]),
                        };
                        let (security_schemes, security_requirements) =
                            agent_card_security_metadata(scenario, &base_url_for_thread);
                        json!({
                                "name": "Research Agent",
                                "description": "Answers research questions over A2A",
                                "supportedInterfaces": interface,
                                "version": "1.0.0",
                                "capabilities": {
                                    "streaming": matches!(scenario, TestScenario::StreamingComplete | TestScenario::StreamingIncomplete | TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete),
                                    "pushNotifications": matches!(scenario, TestScenario::PushNotificationCrud | TestScenario::PushNotificationCapabilityOnly),
                                    "stateTransitionHistory": matches!(scenario, TestScenario::BlockingMessage | TestScenario::TaskFollowUp)
                                },
                                "defaultInputModes": ["text/plain", "application/json"],
                                "defaultOutputModes": ["application/json"],
                                "skills": [{
                                    "id": "research",
                                    "name": "Research",
                                    "description": "Search and synthesize results",
                                    "tags": ["search", "synthesis"],
                                    "examples": ["Summarize recent cardiology evidence"],
                                    "inputModes": ["text/plain", "application/json"],
                                    "outputModes": ["application/json"]
                                }],
                                "securitySchemes": security_schemes,
                                "securityRequirements": security_requirements
                            })
                            .into()
                    } else if first_line.starts_with("POST /rpc") {
                        response_for_jsonrpc(&request, scenario)
                    } else if first_line.starts_with("GET /openid/.well-known/openid-configuration")
                    {
                        response_for_openid_configuration(&request, scenario, &base_url_for_thread)
                    } else if first_line.starts_with("POST /oauth/token") {
                        response_for_oauth_token(&request, scenario)
                    } else if first_line.starts_with("POST /tasks/")
                        && first_line.contains(":cancel ")
                    {
                        response_for_http_cancel_task(&request, scenario)
                    } else if first_line.starts_with("POST /tasks/")
                        && first_line.contains("/pushNotificationConfigs ")
                    {
                        response_for_http_create_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("POST /message:stream") {
                        response_for_http_stream(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains(":subscribe ")
                    {
                        response_for_http_subscribe(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains("/pushNotificationConfigs/")
                    {
                        response_for_http_get_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/")
                        && first_line.contains("/pushNotificationConfigs")
                    {
                        response_for_http_list_push_notification_configs(&request, scenario)
                    } else if first_line.starts_with("POST /message:send") {
                        response_for_http_send(&request, scenario)
                    } else if first_line.starts_with("DELETE /tasks/")
                        && first_line.contains("/pushNotificationConfigs/")
                    {
                        response_for_http_delete_push_notification_config(&request, scenario)
                    } else if first_line.starts_with("GET /tasks/") {
                        response_for_http_get_task(&request, scenario)
                    } else {
                        json!({
                            "error": format!("unexpected request: {first_line}")
                        })
                        .into()
                    };
                    match response_body {
                        TestResponse::Json(body) => {
                            write_http_json_response(&mut stream, 200, &body)
                        }
                        TestResponse::EventStream(body) => {
                            write_http_event_stream_response(&mut stream, 200, &body)
                        }
                    }
                }
            });

            ready_rx.recv().expect("server should start");
            Some(Self {
                base_url,
                requests,
                handle,
            })
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("lock requests").clone()
        }

        fn join(self) {
            self.handle.join().expect("join fake A2A server");
        }
    }

    struct MtlsTestMaterials {
        root_ca_pem: String,
        client_cert_chain_pem: String,
        client_private_key_pem: String,
        server_cert_chain_pem: String,
        server_private_key_pem: String,
    }

    struct FakeMtlsA2aServer {
        base_url: String,
        requests: Arc<Mutex<Vec<String>>>,
        root_ca_pem: String,
        client_cert_chain_pem: String,
        client_private_key_pem: String,
        handle: thread::JoinHandle<()>,
    }

    impl FakeMtlsA2aServer {
        fn spawn_jsonrpc() -> Option<Self> {
            ensure_rustls_crypto_provider();
            let materials = generate_mtls_test_materials();
            let listener = bind_fake_a2a_listener("fake mTLS A2A listener")?;
            let address = listener.local_addr().expect("listener address");
            let base_url = format!("https://localhost:{}", address.port());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_for_thread = Arc::clone(&requests);
            let server_tls_config = build_test_server_tls_config(&materials);
            let base_url_for_thread = base_url.clone();
            let (ready_tx, ready_rx) = mpsc::channel();

            let handle = thread::spawn(move || {
                ready_tx.send(()).expect("server ready");
                for _ in 0..2 {
                    let (tcp_stream, _) = listener.accept().expect("accept request");
                    tcp_stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set read timeout");
                    let connection =
                        ureq::rustls::ServerConnection::new(Arc::clone(&server_tls_config))
                            .expect("create rustls server connection");
                    let mut stream = ureq::rustls::StreamOwned::new(connection, tcp_stream);
                    let request = read_http_request(&mut stream);
                    requests_for_thread
                        .lock()
                        .expect("lock request log")
                        .push(request.clone());
                    let first_line = request.lines().next().unwrap_or_default();
                    let response = if first_line.starts_with("GET /.well-known/agent-card.json") {
                        mtls_agent_card_payload(&base_url_for_thread)
                    } else if first_line.starts_with("POST /rpc") {
                        assert!(request.contains("\"method\":\"SendMessage\""));
                        assert!(request.contains("\"targetSkillId\":\"research\""));
                        assert!(!request.contains("Authorization: Bearer"));
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "message": {
                                    "messageId": "msg-out",
                                    "contextId": "ctx-1",
                                    "taskId": "task-1",
                                    "role": "ROLE_AGENT",
                                    "parts": [{
                                        "text": "completed research request",
                                        "mediaType": "text/plain"
                                    }]
                                }
                            }
                        })
                    } else {
                        json!({
                            "error": format!("unexpected request: {first_line}")
                        })
                    };
                    write_http_json_response(&mut stream, 200, &response);
                    stream.flush().expect("flush response");
                }
            });

            ready_rx.recv().expect("server should start");
            Some(Self {
                base_url,
                requests,
                root_ca_pem: materials.root_ca_pem,
                client_cert_chain_pem: materials.client_cert_chain_pem,
                client_private_key_pem: materials.client_private_key_pem,
                handle,
            })
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn root_ca_pem(&self) -> &str {
            &self.root_ca_pem
        }

        fn client_cert_chain_pem(&self) -> &str {
            &self.client_cert_chain_pem
        }

        fn client_private_key_pem(&self) -> &str {
            &self.client_private_key_pem
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("lock requests").clone()
        }

        fn join(self) {
            self.handle.join().expect("join fake mTLS A2A server");
        }
    }

    fn generate_mtls_test_materials() -> MtlsTestMaterials {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Chio Test Root CA");
        let ca_key_pair = RcgenKeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .expect("self-sign CA certificate");

        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        server_params.distinguished_name = DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key_pair = RcgenKeyPair::generate().expect("generate server key");
        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
            .expect("sign server certificate");

        let mut client_params =
            CertificateParams::new(Vec::<String>::new()).expect("client params");
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "Chio Test Client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key_pair = RcgenKeyPair::generate().expect("generate client key");
        let client_cert = client_params
            .signed_by(&client_key_pair, &ca_cert, &ca_key_pair)
            .expect("sign client certificate");

        let root_ca_pem = ca_cert.pem();
        MtlsTestMaterials {
            root_ca_pem: root_ca_pem.clone(),
            client_cert_chain_pem: format!("{}{}", client_cert.pem(), root_ca_pem.clone()),
            client_private_key_pem: client_key_pair.serialize_pem(),
            server_cert_chain_pem: format!("{}{}", server_cert.pem(), root_ca_pem),
            server_private_key_pem: server_key_pair.serialize_pem(),
        }
    }

    fn build_test_server_tls_config(
        materials: &MtlsTestMaterials,
    ) -> Arc<ureq::rustls::ServerConfig> {
        let mut client_root_store = ureq::rustls::RootCertStore::empty();
        for certificate in
            parse_pem_certificates(materials.root_ca_pem.as_str(), "mTLS test root CA")
                .expect("parse test root CA")
        {
            client_root_store
                .add(certificate)
                .expect("add test root CA to verifier store");
        }
        let verifier =
            ureq::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
                .build()
                .expect("build client cert verifier");
        let server_cert_chain = parse_pem_certificates(
            materials.server_cert_chain_pem.as_str(),
            "mTLS test server certificate chain",
        )
        .expect("parse server certificate chain");
        let server_private_key = parse_pem_private_key(
            materials.server_private_key_pem.as_str(),
            "mTLS test server private key",
        )
        .expect("parse server private key");
        Arc::new(
            ureq::rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(server_cert_chain, server_private_key)
                .expect("build test mTLS server config"),
        )
    }

    fn mtls_agent_card_payload(base_url: &str) -> Value {
        json!({
            "name": "Research Agent",
            "description": "Answers research questions over A2A",
            "supportedInterfaces": [{
                "url": format!("{base_url}/rpc"),
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0"
            }],
            "version": "1.0.0",
            "capabilities": {
                "streaming": false,
                "pushNotifications": false
            },
            "defaultInputModes": ["text/plain", "application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [{
                "id": "research",
                "name": "Research",
                "description": "Search and synthesize results",
                "tags": ["search", "synthesis"],
                "examples": ["Summarize recent cardiology evidence"],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json"]
            }],
            "securitySchemes": {
                "mtlsAuth": {
                    "mtlsSecurityScheme": {}
                }
            },
            "securityRequirements": [{
                "schemes": {
                    "mtlsAuth": []
                }
            }]
        })
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_text(status),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn write_http_event_stream_response<W: Write>(stream: &mut W, status: u16, body: &str) {
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_text(status),
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            _ => "Error",
        }
    }

    fn response_for_jsonrpc(request: &str, scenario: TestScenario) -> TestResponse {
        if request.contains("\"method\":\"SendMessage\"") {
            assert!(request.contains("\"targetSkillId\":\"research\""));
            match scenario {
                TestScenario::BlockingMessage | TestScenario::BearerRequired => {
                    if matches!(scenario, TestScenario::BearerRequired) {
                        assert!(request.contains("Authorization: Bearer secret-token"));
                    }
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                        })
                    .into()
                }
                TestScenario::MissingSendMessageResult => json!({
                    "jsonrpc": "2.0",
                    "id": 1
                })
                .into(),
                TestScenario::OAuthClientCredentialsRequired
                | TestScenario::OAuthClientCredentialsSingleInvoke => {
                    assert!(request.contains("Authorization: Bearer oauth-access-token"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                    .into()
                }
                TestScenario::OpenIdClientCredentialsRequired => {
                    assert!(request.contains("Authorization: Bearer oidc-access-token"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                    .into()
                }
                TestScenario::TaskFollowUp => {
                    assert!(request.contains("\"returnImmediately\":true"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "task": task_payload("TASK_STATE_WORKING", false)
                        }
                    })
                    .into()
                }
                TestScenario::CancelTask
                | TestScenario::PushNotificationCrud
                | TestScenario::PushNotificationCapabilityOnly => {
                    panic!("unexpected SendMessage for task-management scenario")
                }
                TestScenario::StreamingComplete
                | TestScenario::StreamingIncomplete
                | TestScenario::SubscribeComplete
                | TestScenario::SubscribeIncomplete
                | TestScenario::BasicRequired
                | TestScenario::MutualTlsRequired
                | TestScenario::ApiKeyRequired
                | TestScenario::ApiKeyQueryRequired
                | TestScenario::ApiKeyCookieRequired => {
                    panic!("unexpected SendMessage for streaming scenario")
                }
            }
        } else if request.contains("\"method\":\"SendStreamingMessage\"") {
            assert!(matches!(
                scenario,
                TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
            ));
            TestResponse::EventStream(jsonrpc_stream_body(scenario))
        } else if request.contains("\"method\":\"SubscribeToTask\"") {
            assert!(matches!(
                scenario,
                TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
            ));
            assert!(request.contains("\"id\":\"task-1\""));
            TestResponse::EventStream(jsonrpc_stream_body(scenario))
        } else if request.contains("\"method\":\"GetTask\"") {
            assert!(matches!(scenario, TestScenario::TaskFollowUp));
            assert!(request.contains("\"id\":\"task-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "result": task_payload("TASK_STATE_COMPLETED", true)
            })
            .into()
        } else if request.contains("\"method\":\"CancelTask\"") {
            assert!(matches!(scenario, TestScenario::CancelTask));
            assert!(request.contains("\"id\":\"task-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": task_payload("TASK_STATE_CANCELED", false)
            })
            .into()
        } else if request.contains("\"method\":\"CreateTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"url\":\"https://callbacks.example.com/chio\""));
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "result": push_notification_config_payload()
            })
            .into()
        } else if request.contains("\"method\":\"GetTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"id\":\"config-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "result": push_notification_config_payload()
            })
            .into()
        } else if request.contains("\"method\":\"ListTaskPushNotificationConfigs\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"pageSize\":25"));
            assert!(request.contains("\"pageToken\":\"page-2\""));
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "result": {
                    "configs": [push_notification_config_payload()],
                    "nextPageToken": "next-page"
                }
            })
            .into()
        } else if request.contains("\"method\":\"DeleteTaskPushNotificationConfig\"") {
            assert!(matches!(scenario, TestScenario::PushNotificationCrud));
            assert!(request.contains("\"taskId\":\"task-1\""));
            assert!(request.contains("\"id\":\"config-1\""));
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {}
            })
            .into()
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": 99,
                "error": {
                    "code": -32601,
                    "message": "unexpected method"
                }
            })
            .into()
        }
    }

    fn response_for_http_send(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(request.contains("\"targetSkillId\":\"research\""));
        match scenario {
            TestScenario::BlockingMessage => json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            }),
            TestScenario::BasicRequired => {
                assert!(request.contains("Authorization: Basic "));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyRequired => {
                assert!(request.contains("X-A2A-Key: secret-key"));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyQueryRequired => {
                assert!(request.starts_with("POST /message:send?a2a_key=secret-key "));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::ApiKeyCookieRequired => {
                assert!(request.contains("Cookie: a2a_session=secret-cookie"));
                assert!(!request.contains("Authorization: Bearer"));
                json!({
                    "task": task_payload("TASK_STATE_COMPLETED", true)
                })
            }
            TestScenario::TaskFollowUp => {
                assert!(request.contains("\"returnImmediately\":true"));
                json!({
                    "task": task_payload("TASK_STATE_WORKING", false)
                })
            }
            TestScenario::CancelTask
            | TestScenario::PushNotificationCrud
            | TestScenario::PushNotificationCapabilityOnly => {
                panic!("unexpected blocking send for task-management scenario")
            }
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke
            | TestScenario::OpenIdClientCredentialsRequired => {
                panic!("unexpected blocking send for OAuth/OpenID scenario")
            }
            TestScenario::MissingSendMessageResult => {
                panic!("unexpected HTTP send for JSON-RPC malformed-result scenario")
            }
            TestScenario::StreamingComplete
            | TestScenario::StreamingIncomplete
            | TestScenario::SubscribeComplete
            | TestScenario::SubscribeIncomplete
            | TestScenario::BearerRequired
            | TestScenario::MutualTlsRequired => {
                panic!("unexpected blocking send for streaming scenario")
            }
        }
        .into()
    }

    fn response_for_http_stream(_request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
        ));
        TestResponse::EventStream(http_stream_body(scenario))
    }

    fn response_for_http_subscribe(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
        ));
        assert!(request.starts_with("GET /tasks/task-1:subscribe"));
        TestResponse::EventStream(http_stream_body(scenario))
    }

    fn response_for_http_get_task(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(scenario, TestScenario::TaskFollowUp));
        assert!(request.starts_with("GET /tasks/task-1"));
        json!(task_payload("TASK_STATE_COMPLETED", true)).into()
    }

    fn response_for_http_cancel_task(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(scenario, TestScenario::CancelTask));
        assert!(request.starts_with("POST /tasks/task-1:cancel"));
        assert!(request.contains("\"reason\":\"user-request\""));
        json!(task_payload("TASK_STATE_CANCELED", false)).into()
    }

    fn response_for_http_create_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("POST /tasks/task-1/pushNotificationConfigs"));
        assert!(request.contains("\"url\":\"https://callbacks.example.com/chio\""));
        json!(push_notification_config_payload()).into()
    }

    fn response_for_http_get_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1"));
        json!(push_notification_config_payload()).into()
    }

    fn response_for_http_list_push_notification_configs(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request
            .starts_with("GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"));
        json!({
            "configs": [push_notification_config_payload()],
            "nextPageToken": "next-page"
        })
        .into()
    }

    fn response_for_http_delete_push_notification_config(
        request: &str,
        scenario: TestScenario,
    ) -> TestResponse {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1"));
        json!({}).into()
    }

    fn response_for_openid_configuration(
        request: &str,
        scenario: TestScenario,
        base_url: &str,
    ) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::OpenIdClientCredentialsRequired
        ));
        assert!(request.starts_with("GET /openid/.well-known/openid-configuration"));
        json!({
            "token_endpoint": format!("{base_url}/oauth/token")
        })
        .into()
    }

    fn response_for_oauth_token(request: &str, scenario: TestScenario) -> TestResponse {
        assert!(matches!(
            scenario,
            TestScenario::OAuthClientCredentialsRequired
                | TestScenario::OAuthClientCredentialsSingleInvoke
                | TestScenario::OpenIdClientCredentialsRequired
        ));
        assert!(request.starts_with("POST /oauth/token"));
        assert!(request.contains("grant_type=client_credentials"));
        assert!(
            request.contains("Authorization: Basic")
                || (request.contains("client_id=client-id")
                    && request.contains("client_secret=client-secret"))
        );
        match scenario {
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke => {
                assert!(request.contains("a2a.invoke"));
                json!({
                    "access_token": "oauth-access-token",
                    "token_type": "  Bearer  ",
                    "expires_in": 3600
                })
                .into()
            }
            TestScenario::OpenIdClientCredentialsRequired => {
                assert!(request.contains("openid"));
                assert!(request.contains("profile"));
                json!({
                    "access_token": "oidc-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })
                .into()
            }
            _ => unreachable!("unexpected token response scenario"),
        }
    }

    fn agent_card_security_metadata(scenario: TestScenario, base_url: &str) -> (Value, Value) {
        match scenario {
            TestScenario::BearerRequired => (
                json!({
                    "bearerAuth": {
                        "httpAuthSecurityScheme": {
                            "scheme": "bearer"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "bearerAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::BasicRequired => (
                json!({
                    "basicAuth": {
                        "httpAuthSecurityScheme": {
                            "scheme": "basic"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "basicAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "X-A2A-Key",
                            "location": "header"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyQueryRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "a2a_key",
                            "location": "query"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::ApiKeyCookieRequired => (
                json!({
                    "apiKeyAuth": {
                        "apiKeySecurityScheme": {
                            "name": "a2a_session",
                            "location": "cookie"
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "apiKeyAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke => (
                json!({
                    "oauthAuth": {
                        "oauth2SecurityScheme": {
                            "flows": {
                                "clientCredentials": {
                                    "tokenUrl": format!("{base_url}/oauth/token")
                                }
                            }
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "oauthAuth": ["a2a.invoke"]
                        }
                    }
                ]),
            ),
            TestScenario::OpenIdClientCredentialsRequired => (
                json!({
                    "oidcAuth": {
                        "openIdConnectSecurityScheme": {
                            "openIdConnectUrl": format!("{base_url}/openid/.well-known/openid-configuration")
                        }
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "oidcAuth": ["openid", "profile"]
                        }
                    }
                ]),
            ),
            TestScenario::MutualTlsRequired => (
                json!({
                    "mtlsAuth": {
                        "mtlsSecurityScheme": {}
                    }
                }),
                json!([
                    {
                        "schemes": {
                            "mtlsAuth": []
                        }
                    }
                ]),
            ),
            TestScenario::BlockingMessage
            | TestScenario::TaskFollowUp
            | TestScenario::CancelTask
            | TestScenario::PushNotificationCrud
            | TestScenario::PushNotificationCapabilityOnly
            | TestScenario::MissingSendMessageResult
            | TestScenario::StreamingComplete
            | TestScenario::StreamingIncomplete
            | TestScenario::SubscribeComplete
            | TestScenario::SubscribeIncomplete => (Value::Null, Value::Null),
        }
    }

    fn task_payload(state: &str, include_artifacts: bool) -> Value {
        let mut task = json!({
            "id": "task-1",
            "contextId": "ctx-1",
            "status": {
                "state": state
            },
            "createdAt": "2026-03-24T00:00:00.000Z",
            "lastModified": "2026-03-24T00:00:01.000Z"
        });
        if include_artifacts {
            task["artifacts"] = json!([{
                "artifactId": "artifact-1",
                "parts": [{
                    "text": "completed research request",
                    "mediaType": "text/plain"
                }]
            }]);
        }
        task
    }

    fn push_notification_config_payload() -> Value {
        json!({
            "id": "config-1",
            "taskId": "task-1",
            "url": "https://callbacks.example.com/chio",
            "token": "notify-token",
            "authentication": {
                "scheme": "bearer",
                "credentials": "callback-secret"
            }
        })
    }

    fn jsonrpc_stream_body(scenario: TestScenario) -> String {
        sse_body(match scenario {
            TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "task": task_payload("TASK_STATE_WORKING", false) }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "artifactUpdate": {
                            "taskId": "task-1",
                            "artifact": {
                                "artifactId": "artifact-1",
                                "parts": [{
                                    "text": "partial research result",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "statusUpdate": {
                            "taskId": "task-1",
                            "status": { "state": "TASK_STATE_COMPLETED" }
                        }
                    }
                }),
            ],
            TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "task": task_payload("TASK_STATE_WORKING", false) }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "artifactUpdate": {
                            "taskId": "task-1",
                            "artifact": {
                                "artifactId": "artifact-1",
                                "parts": [{
                                    "text": "partial research result",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    }
                }),
            ],
            _ => panic!("unexpected streaming scenario"),
        })
    }

    fn http_stream_body(scenario: TestScenario) -> String {
        sse_body(match scenario {
            TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
                json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
                json!({
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }),
                json!({
                    "statusUpdate": {
                        "taskId": "task-1",
                        "status": { "state": "TASK_STATE_COMPLETED" }
                    }
                }),
            ],
            TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
                json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
                json!({
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }),
            ],
            _ => panic!("unexpected streaming scenario"),
        })
    }

    fn sse_body(events: Vec<Value>) -> String {
        events
            .into_iter()
            .map(|event| format!("data: {}\n\n", event))
            .collect()
    }

    fn test_capability(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        capability_id: &str,
    ) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: capability_id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: "research".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(5),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            issuer,
        )
        .expect("sign capability")
    }

    impl From<Value> for TestResponse {
        fn from(value: Value) -> Self {
            Self::Json(value)
        }
    }

    trait ToolCallOutputExt {
        fn into_value(self) -> Value;
        fn into_stream(self) -> ToolCallStream;
    }

    impl ToolCallOutputExt for chio_kernel::ToolCallOutput {
        fn into_value(self) -> Value {
            match self {
                chio_kernel::ToolCallOutput::Value(value) => value,
                chio_kernel::ToolCallOutput::Stream(_) => panic!("expected value output"),
            }
        }

        fn into_stream(self) -> ToolCallStream {
            match self {
                chio_kernel::ToolCallOutput::Value(_) => panic!("expected stream output"),
                chio_kernel::ToolCallOutput::Stream(stream) => stream,
            }
        }
    }
}
