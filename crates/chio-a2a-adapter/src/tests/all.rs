#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Once;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

    use chio_core::capability::{
        ChioScope, CapabilityToken, CapabilityTokenBody, Operation, ToolGrant,
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

    #[test]
    fn adapter_discovers_jsonrpc_and_invokes_skill() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_generic_request_auth_surfaces_apply_to_discovery_and_invoke() {
        let Some(server) = FakeA2aServer::spawn_http_json() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn partner_policy_rejects_wrong_tenant_on_discovery() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let error = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn task_registry_allows_follow_up_after_restart_and_rejects_unknown_tasks() {
        let registry_path = unique_path("chio-a2a-task-registry", ".json");
        let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            .expect_err("unknown follow-up should fail closed");
        assert!(unknown_error
            .to_string()
            .contains("requires a previously recorded A2A task"));

        let _ = fs::remove_file(registry_path);
        server.join();
    }

    #[test]
    fn adapter_invokes_http_json_binding() {
        let Some(server) = FakeA2aServer::spawn_http_json() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            .expect("invoke research skill over HTTP+JSON");

        assert_eq!(result["task"]["id"], "task-1");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /message:send HTTP/1.1"));
        assert!(requests[1].contains("\"targetSkillId\":\"research\""));
        server.join();
    }

    #[test]
    fn adapter_rejects_insecure_non_localhost_urls() {
        let manifest_key = Keypair::generate();
        let error = A2aAdapter::discover(A2aAdapterConfig::new(
            "http://example.com",
            manifest_key.public_key().to_hex(),
        ))
        .expect_err("insecure remote URL should fail");
        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn adapter_jsonrpc_get_task_follow_up() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_http_json_get_task_follow_up() {
        let Some(server) = FakeA2aServer::spawn_http_json_task_follow_up() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_rejects_mixed_send_and_get_task_input() {
        let error = parse_tool_input(json!({
            "message": "hello",
            "get_task": { "id": "task-1" }
        }))
        .expect_err("mixed invocation modes should fail");
        assert!(error
            .to_string()
            .contains("mutually exclusive with SendMessage fields"));
    }

    #[test]
    fn adapter_rejects_mixed_send_and_subscribe_task_input() {
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
    fn build_send_message_request_propagates_interface_tenant() {
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

    #[test]
    fn build_send_message_request_rejects_history_length_without_capability() {
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

    #[test]
    fn get_task_rejects_history_length_without_capability() {
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
            },
            token_cache: Mutex::new(Vec::new()),
            timeout: Duration::from_secs(2),
            request_counter: AtomicU64::new(0),
            partner_policy: None,
            task_registry: None,
        }
    }

    #[test]
    fn validate_send_message_response_rejects_task_without_status_state() {
        let error = validate_send_message_response(A2aSendMessageResponse {
            task: Some(json!({
                "id": "task-1"
            })),
            message: None,
        })
        .expect_err("task without status.state should fail");
        assert!(error.to_string().contains("status.state"));
    }

    #[test]
    fn validate_stream_response_rejects_status_update_without_task_id() {
        let error = validate_stream_response(json!({
            "statusUpdate": {
                "status": { "state": "TASK_STATE_COMPLETED" }
            }
        }))
        .expect_err("statusUpdate without taskId should fail");
        assert!(error.to_string().contains("taskId"));
    }

    #[test]
    fn validate_stream_response_rejects_artifact_update_without_task_id() {
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

    #[test]
    fn build_get_task_url_appends_tenant_and_history_length() {
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

    #[test]
    fn build_send_message_url_appends_tenant_path_segment() {
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

    #[test]
    fn build_cancel_task_url_appends_tenant_path_segment() {
        let url =
            build_cancel_task_url("http://localhost:9000/api", "task-1", Some("tenant-alpha"))
                .expect("build cancel task URL");

        assert_eq!(
            url.as_str(),
            "http://localhost:9000/api/tenant-alpha/tasks/task-1:cancel"
        );
    }

    #[test]
    fn build_push_notification_urls_append_tenant_path_segment() {
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

    #[test]
    fn adapter_invoke_stream_returns_none_without_stream_flag() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            .expect("invoke blocking request");
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_streaming_invocation_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_http_json_streaming_invocation_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_http_json_streaming_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_streaming_closure_without_terminal_state_is_incomplete() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_incomplete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            .expect("invoke stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_subscribe_task_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
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

    #[test]
    fn adapter_http_json_subscribe_task_returns_complete_stream() {
        let Some(server) = FakeA2aServer::spawn_http_json_subscribe_complete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
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

    #[test]
    fn adapter_subscribe_task_closure_without_terminal_state_is_incomplete() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

        let stream = adapter
            .invoke_stream(
                "research",
                json!({
                    "subscribe_task": { "id": "task-1" }
                }),
                None,
            )
            .expect("invoke subscribe stream")
            .expect("stream result");

        let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
            panic!("expected incomplete stream");
        };
        assert_eq!(stream.chunk_count(), 2);
        assert!(reason.contains("terminal or interrupted"));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_cancel_task_returns_cancelled_task() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_cancel_task() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

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
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\"method\":\"CancelTask\""));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[test]
    fn adapter_http_json_cancel_task_returns_cancelled_task() {
        let Some(server) = FakeA2aServer::spawn_http_json_cancel_task() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

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
            .expect("cancel task");

        assert_eq!(result["task"]["id"], "task-1");
        assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with("POST /tasks/task-1:cancel HTTP/1.1"));
        assert!(requests[1].contains("\"reason\":\"user-request\""));
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_push_notification_config_crud_roundtrip() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_crud() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

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

    #[test]
    fn adapter_http_json_push_notification_config_crud_roundtrip() {
        let Some(server) = FakeA2aServer::spawn_http_json_push_notification_crud() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover HTTP+JSON adapter");

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

    #[test]
    fn adapter_rejects_insecure_push_notification_callback_url() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
                .with_timeout(Duration::from_secs(2)),
        )
        .expect("discover JSONRPC adapter");

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
            .expect_err("insecure callback URL should fail closed");
        assert!(error
            .to_string()
            .contains("push notification URL must use https"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_oauth2_client_credentials_fetches_token_and_caches_it() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_openid_client_credentials_fetches_discovery_and_token() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_openid_client_credentials_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_required_bearer_security_without_configured_token_fails_closed() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
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
            .expect_err("missing bearer token should fail closed");
        assert!(error.to_string().contains("missing bearer token"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_http_basic_security_is_negotiated_from_agent_card() {
        let Some(server) = FakeA2aServer::spawn_http_json_basic_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_http_basic_security_without_configured_credentials_fails_closed() {
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

    #[test]
    fn adapter_api_key_header_security_is_negotiated_from_agent_card() {
        let Some(server) = FakeA2aServer::spawn_http_json_api_key_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_api_key_query_security_is_negotiated_from_agent_card() {
        let Some(server) = FakeA2aServer::spawn_http_json_api_key_query_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
    fn adapter_api_key_cookie_security_is_negotiated_from_agent_card() {
        let Some(server) = FakeA2aServer::spawn_http_json_api_key_cookie_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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

    #[test]
    fn adapter_api_key_query_security_without_configured_value_fails_closed() {
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

    #[test]
    fn adapter_mtls_security_without_configured_identity_fails_closed() {
        let Some(server) = FakeA2aServer::spawn_jsonrpc_mtls_required() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
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
            .expect_err("unsupported auth should fail closed");
        assert!(error.to_string().contains("mutual TLS"));
        assert_eq!(server.requests().len(), 1);
        server.join();
    }

    #[test]
    fn adapter_jsonrpc_mtls_security_uses_client_certificate_for_discovery_and_invoke() {
        ensure_rustls_crypto_provider();
        let Some(server) = FakeMtlsA2aServer::spawn_jsonrpc() else {
            return;
        };
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
        let Some(server) = FakeA2aServer::spawn_jsonrpc_task_follow_up() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(initial.receipt.body().decision, Decision::Allow);
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
        assert_eq!(follow_up.receipt.body().decision, Decision::Allow);
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
        let Some(server) = FakeA2aServer::spawn_jsonrpc_cancel_task() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            Decision::Incomplete { .. }
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
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_complete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
        let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
            Decision::Incomplete { .. }
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
        let adapter = A2aAdapter::discover(A2aAdapterConfig::new(
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
        let Some(server) = FakeA2aServer::spawn_jsonrpc_oauth_client_credentials_single_invoke() else {
            return;
        };
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let manifest_key = Keypair::generate();
        let adapter = A2aAdapter::discover(
            A2aAdapterConfig::new(server.base_url(), manifest_key.public_key().to_hex())
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
        assert_eq!(response.receipt.body().decision, Decision::Allow);
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
                    "token_type": "Bearer",
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
