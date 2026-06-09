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
