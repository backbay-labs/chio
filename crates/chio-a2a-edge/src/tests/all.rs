#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream,
        ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_manifest::LatencyHint;

    static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn metrics_test_guard() -> MutexGuard<'static, ()> {
        match METRICS_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    struct MockToolServer {
        server_id: String,
        tools: Vec<String>,
        response: Value,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            &self.server_id
        }

        fn tool_names(&self) -> Vec<String> {
            self.tools.clone()
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(self.response.clone())
        }
    }

    struct FailingToolServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for FailingToolServer {
        fn server_id(&self) -> &str {
            "fail-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["fail_tool".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::ToolServerError("simulated failure".into()))
        }
    }

    struct StreamingToolServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for StreamingToolServer {
        fn server_id(&self) -> &str {
            "stream-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["stream".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(json!({"result": "fallback"}))
        }

        async fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: vec![
                    ToolCallChunk {
                        data: json!("chunk-1"),
                    },
                    ToolCallChunk {
                        data: json!({"content": [{"type": "text", "text": "chunk-2"}]}),
                    },
                ],
            })))
        }
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test Server".to_string(),
            description: Some("Test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "echo".to_string(),
                    description: "Echo input".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write".to_string(),
                    description: "Write data".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
            ],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec!["echo".to_string(), "write".to_string()],
            response: json!({"result": "ok"}),
        }
    }

    fn stream_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "stream-srv".to_string(),
            name: "Stream Server".to_string(),
            description: Some("Streaming test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "stream".to_string(),
                description: "Stream output".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-streaming": true,
                    "x-chio-partial-output": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "stream".to_string(),
        }
    }

    fn approval_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "approve-srv".to_string(),
            name: "Approval Server".to_string(),
            description: Some("Approval test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "approve".to_string(),
                description: "Approval-gated operation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-approval-required": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "approve".to_string(),
        }
    }

    fn cancellation_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "cancel-srv".to_string(),
            name: "Cancellation Server".to_string(),
            description: Some("Cancel test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "cancel_me".to_string(),
                description: "Requires cancellation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-cancellation": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "cancel".to_string(),
        }
    }

    fn mcp_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "MCP Target Server".to_string(),
            description: Some("MCP target binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Echo via MCP target executor".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "mcp"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "mcp-target".to_string(),
        }
    }

    fn openai_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "OpenAI Target Server".to_string(),
            description: Some("OpenAI target binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Echo via OpenAI target executor".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "open_ai"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "openai-target".to_string(),
        }
    }

    fn invalid_target_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Invalid Target Server".to_string(),
            description: Some("Invalid protocol binding".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Invalid binding".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-target-protocol": "smtp"
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "invalid-target".to_string(),
        }
    }

    fn hidden_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "hidden-srv".to_string(),
            name: "Hidden Server".to_string(),
            description: Some("Hidden test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "hidden".to_string(),
                description: "Hidden from publication".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-publish": false
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "hidden".to_string(),
        }
    }

    fn text_message(text: &str) -> SendMessageRequest {
        SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![A2aPart::Text {
                    text: text.to_string(),
                }],
                metadata: None,
            },
            metadata: None,
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("system time should be after unix epoch")
            .as_secs()
    }

    fn test_kernel_config() -> KernelConfig {
        let keypair = Keypair::generate();
        KernelConfig {
            ca_public_keys: vec![keypair.public_key()],
            keypair,
            max_delegation_depth: 8,
            policy_hash: "policy-a2a-test".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> chio_core::capability::CapabilityToken {
        let now = unix_now();
        chio_core::capability::CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{server_id}-{tool_name}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: now.saturating_sub(30),
                expires_at: now + 300,
                delegation_chain: vec![],
            },
            issuer,
        )
        .test_expect("capability should sign")
    }

    fn assert_receipt_write_prometheus_sample_at_least(outcome: &str, minimum: u64) {
        let body = render_a2a_edge_metrics_prometheus();
        let prefix = format!("{CHIO_RECEIPT_WRITE_TOTAL}{{outcome=\"{outcome}\"}} ");
        let sample = body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .test_expect("Prometheus sample should exist")
            .parse::<u64>()
            .test_expect("Prometheus sample should be an integer");
        assert!(
            sample >= minimum,
            "Prometheus sample for {outcome} must include the pending projection counter"
        );
    }

    // ---- Agent Card tests ----

    #[test]
    fn agent_card_has_correct_name() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "Chio A2A Edge");
    }

    #[test]
    fn agent_card_has_correct_version() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.version, "0.1.0");
    }

    #[test]
    fn agent_card_includes_all_skills() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.skills.len(), 2);
        assert!(card.skills.iter().any(|s| s.id == "echo"));
        assert!(card.skills.iter().any(|s| s.id == "write"));
    }

    #[test]
    fn agent_card_has_interface() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

    #[test]
    fn agent_card_json_serializes() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let json_str = edge.agent_card_json().test_unwrap();
        let parsed: Value = serde_json::from_str(&json_str).test_unwrap();
        assert_eq!(parsed["name"], "Chio A2A Edge");
    }

    #[test]
    fn agent_card_custom_config() {
        let config = A2aEdgeConfig {
            agent_name: "My Agent".to_string(),
            agent_description: "Custom agent".to_string(),
            agent_version: "2.0.0".to_string(),
            endpoint_url: "https://myagent.com".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
        };
        let edge = ChioA2aEdge::new(config, vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "My Agent");
        assert_eq!(card.description, "Custom agent");
        assert!(card.capabilities.streaming);
        assert_eq!(card.supported_interfaces[0].url, "https://myagent.com");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn read_only_tool_has_lossless_fidelity() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let skill = edge.skill("echo").test_unwrap();
        assert_eq!(skill.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn side_effect_tool_has_adapted_fidelity_with_permission_caveat() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let skill = edge.skill("write").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("permission prompts") || c.contains("capability enforcement")));
    }

    #[test]
    fn approval_required_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![approval_manifest()]).test_unwrap();
        assert!(edge.skill("approve").is_none());
        assert_eq!(
            edge.bridge_fidelity("approve"),
            Some(&BridgeFidelity::Unsupported {
                reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string()
            })
        );
    }

    #[test]
    fn cancellation_tool_is_adapted_with_truthful_caveats() {
        let edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![cancellation_manifest()]).test_unwrap();
        let skill = edge.skill("cancel_me").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c
                .contains("cancellation is available only for deferred `message/stream` tasks")));
    }

    #[test]
    fn hidden_tool_is_not_auto_published() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![hidden_manifest()]).test_unwrap();
        assert!(edge.skill("hidden").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    #[test]
    fn streaming_tool_is_adapted_with_truthful_caveats() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let skill = edge.skill("stream").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats.iter().any(|c| c.contains("deferred tasks")));
        assert!(caveats.iter().any(|c| c.contains("terminal task payload")));
    }

    // ---- Skill lookup tests ----

    #[test]
    fn skill_ids_returns_all() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let ids = edge.skill_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn skill_returns_none_for_unknown() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        assert!(edge.skill("nonexistent").is_none());
    }

    // ---- SendMessage tests ----

    #[test]
    fn send_message_completes_successfully() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();
        let request = text_message("hello");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        assert!(response.message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_returns_task_id() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();
        let request = text_message("test");
        let r1 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        let r2 = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_unwrap();
        assert_ne!(r1.id, r2.id);
        assert!(r1.id.starts_with("a2a-task-"));
    }

    #[test]
    fn send_message_unknown_skill_errors() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();
        let request = text_message("test");
        let err = edge
            .compatibility()
            .handle_send_message_compatibility("nonexistent", &request, &server)
            .unwrap_err();
        assert!(matches!(err, A2aEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn send_message_server_failure_returns_failed_task() {
        let server = FailingToolServer;
        // Need a manifest for the failing server
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).test_unwrap();
        let request = text_message("test");
        let response = edge
            .compatibility()
            .handle_send_message_compatibility("fail_tool", &request, &server)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        assert!(response.status_message.is_some());
        assert_eq!(
            response
                .metadata
                .as_ref()
                .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn send_message_with_kernel_emits_signed_receipt_metadata() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        let metadata = response
            .metadata
            .test_expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("a2a")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["lifecycle"]["messageSend"].as_str(),
            Some("blocking_terminal_task")
        );
        assert_eq!(
            metadata["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("deferred_task_poll")
        );
        assert_eq!(
            metadata["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_authoritative")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-echo")
        );
    }

    #[test]
    fn send_message_with_kernel_denial_still_returns_receipt_metadata() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("write", &text_message("blocked"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response.metadata.test_expect("deny path should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    }

    #[test]
    fn pending_approval_is_not_reported_as_completed() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let request = text_message("blocked pending approval");
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let response = edge
            .project_pending_approval_for_test(
                "echo",
                &request,
                &kernel,
                &A2aKernelExecutionContext {
                    capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
                    agent_id: subject.public_key().to_hex(),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
                "approval required",
            )
            .test_unwrap();
        let metadata = response
            .metadata
            .test_expect("pending approval should attach metadata");

        assert_eq!(response.status, TaskStatus::Failed);
        assert_eq!(
            response.status_message.as_deref(),
            Some("approval required")
        );
        assert!(response.message.is_none());
        assert_eq!(
            metadata["chio"]["decision"].as_str(),
            Some("pending_approval")
        );
        let pending_total = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        assert!(pending_total > before_pending);
        assert_receipt_write_prometheus_sample_at_least(
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
            pending_total,
        );
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error
        );
    }

    #[test]
    fn send_message_kernel_error_records_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let mut config = test_kernel_config();
        config.require_web3_evidence = true;
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .handle_send_message("echo", &text_message("boom"), &kernel, &execution)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("web3 evidence prerequisites unavailable"));
        assert!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
            "a2a orchestrator error path must advance receipt write error"
        );
    }

    #[test]
    fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let capability_ref = CrossProtocolCapabilityRef {
            chio_capability_id: "wrong-capability".to_string(),
            origin_protocol: DiscoveryProtocol::A2a,
            protocol_context: Some(json!({ "targetSkillId": "echo" })),
            parent_capability_hash: "wrong-parent-hash".to_string(),
        };
        let mut request = text_message("boom");
        request.metadata = Some(json!({
            "chio": {
                "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
            }
        }));
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .handle_send_message("echo", &request, &kernel, &execution)
            .unwrap_err();

        assert!(error.to_string().contains("capability reference mismatch"));
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error,
            "pre-kernel A2A bridge errors must not advance receipt write error"
        );
    }

    #[test]
    fn send_message_kernel_failure_still_returns_receipt_metadata() {
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(FailingToolServer));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "fail-srv", "fail_tool"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message("fail_tool", &text_message("boom"), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        let metadata = response
            .metadata
            .test_expect("kernel failure should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
    }

    // ---- Message extraction tests ----

    #[test]
    fn extract_text_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: "hello world".to_string(),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["message"], "hello world");
    }

    #[test]
    fn extract_data_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!({"key": "value"}),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn extract_prefers_data_over_text() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![
                A2aPart::Text {
                    text: "hello".to_string(),
                },
                A2aPart::Data {
                    data: json!({"priority": "high"}),
                },
            ],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["priority"], "high");
    }

    // ---- Result conversion tests ----

    #[test]
    fn result_text_to_parts() {
        let parts = result_to_parts(&json!("hello"));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text part"),
        }
    }

    #[test]
    fn result_object_to_data_parts() {
        let parts = result_to_parts(&json!({"key": "value"}));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Data { data } => assert_eq!(data["key"], "value"),
            _ => panic!("expected data part"),
        }
    }

    #[test]
    fn result_content_array_to_text_parts() {
        let parts = result_to_parts(&json!({
            "content": [
                {"type": "text", "text": "part1"},
                {"type": "text", "text": "part2"},
            ]
        }));
        assert_eq!(parts.len(), 2);
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_send_message_single_skill() {
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1); // Only "echo"
                m
            }],
        )
        .test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_send_message_with_skill_id() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    },
                    "metadata": {
                        "chio": {"targetSkillId": "echo"}
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_missing_skill_id_with_multiple_skills_errors() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("error").is_some());
    }

    #[test]
    fn jsonrpc_unknown_method_returns_error() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "unknown/method",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn jsonrpc_passthrough_marks_compatibility_path() {
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
                m
            }],
        )
        .test_unwrap();
        let server = test_server();
        let response = edge.compatibility().handle_jsonrpc_compatibility(
            // This explicit compatibility wrapper remains available for bounded
            // migrations, but it is not the receipt-bearing trust path.
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &server,
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["messageStream"].as_str(),
            Some("unsupported")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("a2a_compatibility")
        );
    }

    #[test]
    fn jsonrpc_send_with_streaming_tool_collates_output_into_final_message() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            response["result"]["metadata"]["chio"]["streamProjection"].as_str(),
            Some("collated_final_message")
        );
        let parts = response["result"]["message"]["parts"]
            .as_array()
            .test_expect("stream response should contain parts");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0]["text"], "chunk-1");
        assert_eq!(parts[1]["text"], "chunk-2");
    }

    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_task_get_resolves_result() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(response["result"]["status"].as_str(), Some("working"));
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"].as_str(),
            Some("message/stream")
        );
        let task_id = response["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();
        assert_eq!(
            response["result"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
        assert_eq!(
            resolved["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        let parts = resolved["result"]["message"]["parts"]
            .as_array()
            .test_expect("resolved task should contain parts");
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn jsonrpc_task_get_removes_completed_deferred_task() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["id"].as_str().test_unwrap().to_string();

        let resolved = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "task/get",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(resolved["result"]["status"].as_str(), Some("completed"));
        assert!(!edge.tasks.contains_key(&task_id));
    }

    #[test]
    fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        for index in 0..1_024 {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "message/stream",
                    "params": {
                        "message": {
                            "role": "user",
                            "parts": [{"type": "text", "text": "start"}]
                        }
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(response["result"]["status"].as_str(), Some("working"));
        }

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_000,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert!(rejected["error"]["message"]
            .as_str()
            .test_unwrap()
            .contains("too many deferred tasks"));
    }

    #[test]
    fn jsonrpc_task_cancel_marks_stream_task_cancelled() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "message/stream",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "start"}]
                    }
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = response["result"]["id"].as_str().test_unwrap().to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 13,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));
        assert_eq!(
            cancelled["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn authoritative_send_uses_protocol_aware_target_binding() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![mcp_target_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_unwrap();

        let metadata = response.metadata.test_unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["a2a", "mcp", "native"])
        );
    }

    #[test]
    fn authoritative_send_supports_openai_target_binding() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![openai_target_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge
            .handle_send_message(
                "echo",
                &SendMessageRequest {
                    message: A2aMessage {
                        role: "user".to_string(),
                        parts: vec![A2aPart::Data {
                            data: json!({"message": "hello"}),
                        }],
                        metadata: None,
                    },
                    metadata: None,
                },
                &kernel,
                &execution,
            )
            .test_unwrap();

        let metadata = response.metadata.test_unwrap();
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn invalid_target_protocol_metadata_fails_closed() {
        let error =
            match ChioA2aEdge::new(A2aEdgeConfig::default(), vec![invalid_target_manifest()]) {
                Ok(_) => panic!("expected invalid target protocol metadata to fail"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- Error type tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = A2aEdgeError::ToolNotFound("missing".into());
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = A2aEdgeError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = A2aEdgeError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Duplicate skill handling ----

    #[test]
    fn duplicate_skills_across_manifests_receive_qualified_ids() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).test_unwrap();
        assert_eq!(edge.skill_ids().len(), 4);
        assert!(edge.skill("test-srv::echo").is_some());
        assert!(edge.skill("test-srv::echo#2").is_some());
        assert!(edge.skill("test-srv::write").is_some());
        assert!(edge.skill("test-srv::write#2").is_some());
        assert_eq!(
            edge.bridge_fidelity("echo"),
            Some(&BridgeFidelity::Unsupported {
                reason: "skill id collides across manifests; use one of the qualified ids: test-srv::echo, test-srv::echo#2".to_string()
            })
        );
    }

    #[test]
    fn ambiguous_unqualified_skill_id_returns_guidance() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).test_unwrap();
        let server = test_server();
        let error = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &text_message("hello"), &server)
            .unwrap_err();

        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request");
        };
        assert!(message.contains("ambiguous"));
        assert!(message.contains("test-srv::echo"));
        assert!(message.contains("test-srv::echo#2"));
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_has_reasonable_values() {
        let config = A2aEdgeConfig::default();
        assert!(!config.agent_name.is_empty());
        assert_eq!(config.protocol_binding, "JSONRPC");
    }

    // ---- TaskStatus serde ----

    #[test]
    fn task_status_serializes_correctly() {
        let json = serde_json::to_value(TaskStatus::Completed).test_unwrap();
        assert_eq!(json, "completed");
        let json = serde_json::to_value(TaskStatus::Failed).test_unwrap();
        assert_eq!(json, "failed");
    }

    #[test]
    fn bridge_fidelity_serializes_correctly() {
        let json = serde_json::to_value(BridgeFidelity::Lossless).test_unwrap();
        assert_eq!(json, json!({"kind": "lossless"}));
        let json = serde_json::to_value(BridgeFidelity::Adapted {
            caveats: vec!["stream collated".to_string()],
        })
        .test_unwrap();
        assert_eq!(
            json,
            json!({"kind": "adapted", "caveats": ["stream collated"]})
        );
        let json = serde_json::to_value(BridgeFidelity::Unsupported {
            reason: "needs cancellation".to_string(),
        })
        .test_unwrap();
        assert_eq!(
            json,
            json!({"kind": "unsupported", "reason": "needs cancellation"})
        );
    }
}
