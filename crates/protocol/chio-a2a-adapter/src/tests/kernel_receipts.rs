use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook};

struct DenyingA2aRuntimeAdmissionHook;

impl RuntimeAdmissionHook for DenyingA2aRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "a2a-denying-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, chio_kernel::KernelError> {
        Ok(RuntimeAdmissionDecision::deny(
            "a2a runtime admission denied",
            Some(json!({
                "chio_runtime": {
                    "accepted": false,
                    "failure_code": "a2a_runtime_admission_denied"
                }
            })),
        ))
    }
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
async fn kernel_e2e_a2a_runtime_admission_denies_before_send_message() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_bearer_required() else {
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel.set_runtime_admission_hook(Arc::new(DenyingA2aRuntimeAdmissionHook));
    kernel.register_tool_server(Box::new(adapter));

    let response = kernel
        .evaluate_tool_call(&ToolCallRequest {
            request_id: "req-a2a-runtime-denied".to_string(),
            capability: test_capability(&issuer, &subject, &server_id, "cap-a2a-runtime-denied"),
            tool_name: "research".to_string(),
            server_id,
            agent_id: subject.public_key().to_hex(),
            arguments: json!({
                "message": "this must not reach the remote A2A server"
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .await
        .expect("evaluate A2A tool call");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/failure_code"))
            .and_then(Value::as_str),
        Some("a2a_runtime_admission_denied")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("\"method\":\"SendMessage\""));
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
            execution_nonce: None,
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
async fn kernel_e2e_a2a_deferred_get_task_runtime_admission_denies_before_remote_follow_up() {
    let registry_path = unique_path("chio-a2a-kernel-follow-up-denied", ".json");
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel.register_tool_server(Box::new(adapter));

    let capability = test_capability(&issuer, &subject, &server_id, "cap-a2a-follow-up-denied");
    let initial = kernel
        .evaluate_tool_call(&ToolCallRequest {
            request_id: "req-a2a-follow-up-denied-start".to_string(),
            capability: capability.clone(),
            tool_name: "research".to_string(),
            server_id: server_id.clone(),
            agent_id: subject.public_key().to_hex(),
            arguments: json!({
                "message": "Begin longer research task",
                "return_immediately": true
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .await
        .expect("evaluate initial A2A tool call");
    assert_eq!(initial.verdict, Verdict::Allow);
    assert_eq!(
        initial.output.expect("initial task output").into_value()["task"]["status"]["state"],
        "TASK_STATE_WORKING"
    );

    kernel.set_runtime_admission_hook(Arc::new(DenyingA2aRuntimeAdmissionHook));
    let denied = kernel
        .evaluate_tool_call(&ToolCallRequest {
            request_id: "req-a2a-follow-up-denied-poll".to_string(),
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .await
        .expect("evaluate denied follow-up A2A tool call");

    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(
        denied
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/failure_code"))
            .and_then(Value::as_str),
        Some("a2a_runtime_admission_denied")
    );
    let requests_before_unblock = server.requests();
    assert_eq!(requests_before_unblock.len(), 2);
    assert!(requests_before_unblock[1].contains("\"method\":\"SendMessage\""));
    assert!(
        requests_before_unblock
            .iter()
            .all(|request| !request.contains("\"method\":\"GetTask\""))
    );

    let agent_card_url = format!("{}/.well-known/agent-card.json", server.base_url());
    let _ = ureq::get(&agent_card_url)
        .call()
        .expect("unblock fake A2A server");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("\"method\":\"GetTask\""))
    );
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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
            execution_nonce: None,
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
