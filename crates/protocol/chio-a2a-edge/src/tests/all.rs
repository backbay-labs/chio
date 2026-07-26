#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
            ThresholdApprovalProposal, ThresholdApprovalProposalBody,
            THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
        },
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityTokenBody,
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, RuntimeAdmissionContext,
        RuntimeAdmissionDecision, RuntimeAdmissionHook, ToolCallChunk, ToolCallStream,
        ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_manifest::LatencyHint;

    static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());
    fn metrics_test_guard() -> MutexGuard<'static, ()> {
        match METRICS_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn manifest_public_key(seed: u8) -> String {
        Keypair::from_seed(&[seed; 32]).public_key().to_hex()
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

    struct CountingStreamingToolServer {
        invocations: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for CountingStreamingToolServer {
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
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"result": "fallback"}))
        }

        async fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: json!("should-not-dispatch"),
                }],
            })))
        }
    }

    struct DenyingRuntimeAdmissionHook;

    impl RuntimeAdmissionHook for DenyingRuntimeAdmissionHook {
        fn name(&self) -> &str {
            "a2a-edge-denying-runtime-admission"
        }

        fn evaluate(
            &self,
            _context: &RuntimeAdmissionContext<'_>,
        ) -> Result<RuntimeAdmissionDecision, KernelError> {
            Ok(RuntimeAdmissionDecision::deny(
                "a2a edge runtime admission denied",
                Some(json!({
                    "chio_runtime": {
                        "accepted": false,
                        "failure_code": "a2a_edge_runtime_admission_denied"
                    }
                })),
            ))
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
            public_key: manifest_public_key(1),
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
            public_key: manifest_public_key(2),
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
            public_key: manifest_public_key(3),
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
            public_key: manifest_public_key(4),
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
            public_key: manifest_public_key(5),
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
            public_key: manifest_public_key(6),
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
            public_key: manifest_public_key(7),
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
            public_key: manifest_public_key(8),
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
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        }
    }

    fn capability_for_tool(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> chio_core::capability::token::CapabilityToken {
        let now = unix_now();
        chio_core::capability::token::CapabilityToken::sign(
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
                aggregate_invocation_budget: None,
            },
            issuer,
        )
        .test_expect("capability should sign")
    }

    fn threshold_artifacts(
        subject: &Keypair,
        request_id: &str,
    ) -> (Vec<GovernedApprovalToken>, ThresholdApprovalProposal) {
        let policy_authority = Keypair::generate();
        let approvers = [Keypair::generate(), Keypair::generate()];
        let intent_hash = "a".repeat(64);
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: format!("proposal-{request_id}"),
                request_id: request_id.to_string(),
                governed_intent_hash: intent_hash.clone(),
                subject: subject.public_key(),
                authorizing_capability_digest: "b".repeat(64),
                policy_hash: "c".repeat(64),
                threshold: 2,
                eligible_set_digest: "d".repeat(64),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: policy_authority.public_key(),
            },
            &policy_authority,
        )
        .test_expect("threshold proposal should sign");
        let proposal_hash = proposal
            .artifact_digest()
            .test_expect("threshold proposal should hash");
        let approvals = approvers
            .iter()
            .enumerate()
            .map(|(index, approver)| {
                GovernedApprovalToken::sign(
                    GovernedApprovalTokenBody {
                        id: format!("approval-{request_id}-{index}"),
                        approver: approver.public_key(),
                        subject: subject.public_key(),
                        governed_intent_hash: intent_hash.clone(),
                        request_id: request_id.to_string(),
                        threshold_proposal_hash: Some(proposal_hash.clone()),
                        issued_at: 100,
                        expires_at: 200,
                        decision: GovernedApprovalDecision::Approved,
                    },
                    approver,
                )
                .test_expect("approval should sign")
            })
            .collect();
        (approvals, proposal)
    }

    #[test]
    fn a2a_projection_preserves_complete_approval_set_and_opaque_extension() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_for_tool(&issuer, &subject, "srv", "run");
        let (approvals, proposal) = threshold_artifacts(&subject, "a2a-auth-set");
        let supplemental =
            chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                signed_extension: "opaque-a2a-extension".to_string(),
            };
        let execution = A2aKernelExecutionContext {
            capability,
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: approvals.clone(),
            threshold_approval_proposal: Some(proposal.clone()),
            supplemental_authorization: Some(supplemental.clone()),
            model_metadata: None,
        };
        let source = SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![A2aPart::Data {
                    data: serde_json::json!({"value": 7}),
                }],
                metadata: None,
            },
            metadata: None,
        };

        let projected = ChioA2aEdge::build_execution_request(
            SkillBinding {
                target_protocol: DiscoveryProtocol::Native,
                server_id: "srv".to_string(),
                tool_name: "run".to_string(),
            },
            "run",
            &source,
            serde_json::json!({"value": 7}),
            &execution,
            "a2a-auth-set".to_string(),
            "a2a-kernel-auth-set".to_string(),
        )
        .test_expect("A2A request should project");

        assert_eq!(projected.approval_tokens, approvals);
        assert_eq!(projected.threshold_approval_proposal, Some(proposal));
        assert_eq!(projected.supplemental_authorization, Some(supplemental));
    }

    fn assert_receipt_write_prometheus_sample_at_least(outcome: &str, minimum: u64) {
        let body = render_a2a_edge_metrics_prometheus(chio_kernel::ReceiptWriterLiveness::Healthy);
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

    // ---- Constructor and Agent Card tests ----

    fn assert_invalid_agent_card_config_rejected(config: A2aEdgeConfig, expected: &str) {
        let error = match ChioA2aEdge::new(config, vec![test_manifest()]) {
            Ok(_) => panic!("A2A edge must reject invalid Agent Card config"),
            Err(error) => error,
        };

        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, expected);
    }

    #[test]
    fn edge_rejects_manifest_with_unsupported_schema_version() {
        let mut manifest = test_manifest();
        manifest.schema = "chio.manifest.v0".to_string();
        manifest.public_key = manifest_public_key(99);

        let error = match ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]) {
            Ok(_) => panic!("A2A edge must reject unsupported manifest schema versions"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            A2aEdgeError::Manifest(chio_manifest::ManifestError::UnsupportedSchema(schema))
                if schema == "chio.manifest.v0"
        ));
    }

    #[test]
    fn edge_rejects_blank_agent_card_name_before_publication() {
        let config = A2aEdgeConfig {
            agent_name: "  ".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card name must not be empty",
        );
    }

    #[test]
    fn edge_rejects_blank_agent_card_version_before_publication() {
        let config = A2aEdgeConfig {
            agent_version: String::new(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card version must not be empty",
        );
    }

    #[test]
    fn edge_rejects_blank_agent_card_endpoint_before_publication() {
        let config = A2aEdgeConfig {
            endpoint_url: "\t".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card endpoint URL must not be empty",
        );
    }

    #[test]
    fn edge_rejects_padded_agent_card_endpoint_before_publication() {
        let config = A2aEdgeConfig {
            endpoint_url: " https://agent.example/a2a".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card endpoint URL must not include leading or trailing whitespace",
        );
    }

    #[test]
    fn edge_rejects_blank_agent_card_protocol_binding_before_publication() {
        let config = A2aEdgeConfig {
            protocol_binding: "\n".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card protocol binding must not be empty",
        );
    }

    #[test]
    fn edge_rejects_padded_agent_card_protocol_binding_before_publication() {
        let config = A2aEdgeConfig {
            protocol_binding: "JSONRPC ".to_string(),
            ..A2aEdgeConfig::default()
        };

        assert_invalid_agent_card_config_rejected(
            config,
            "agent card protocol binding must not include leading or trailing whitespace",
        );
    }

    #[test]
    fn agent_card_default_config_fields_stay_stable() {
        let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let card = edge.agent_card();

        assert_eq!(card.name, "Chio A2A Edge");
        assert_eq!(card.description, "Chio-governed tools exposed as A2A skills");
        assert_eq!(card.version, "0.1.0");
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].url, "http://localhost:8080");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

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
            .test_expect_err("unknown A2A skill must fail");
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
            public_key: manifest_public_key(9),
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
    fn send_message_rejects_blank_execution_agent_id_before_dispatch() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: "\t".to_string(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let error = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_expect_err("blank A2A execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A execution agent_id must not be empty"
        );
    }

    #[test]
    fn send_message_rejects_supplemental_authorization_without_stable_request_id() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: Some(
                chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                    signed_extension: "opaque-extension".to_string(),
                },
            ),
            model_metadata: None,
        };

        let error = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_expect_err("supplemental authorization must require a stable request id");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A request-bound authorization artifacts and execution nonces \
             require handle_send_message_with_request_id or handle_stream_message_with_request_id"
        );
    }

    #[test]
    fn send_message_rejects_singular_approval_token_without_stable_request_id() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let (approvals, _proposal) = threshold_artifacts(&subject, "a2a-singular-auth");
        let approval_token = approvals
            .into_iter()
            .next()
            .test_expect("threshold artifacts must yield at least one approval token");
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: Some(approval_token.clone()),
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let error = edge
            .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
            .test_expect_err("a singular approval token must require a stable request id");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A request-bound authorization artifacts and execution nonces \
             require handle_send_message_with_request_id or handle_stream_message_with_request_id"
        );
    }

    #[test]
    fn send_message_with_request_id_accepts_request_bound_artifacts() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: Some(
                chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                    signed_extension: "opaque-extension".to_string(),
                },
            ),
            model_metadata: None,
        };

        edge.handle_send_message_with_request_id(
            "caller-chosen-request",
            "echo",
            &text_message("hello"),
            &kernel,
            &execution,
        )
        .test_expect("stable request id path must accept request-bound artifacts");
    }

    #[test]
    fn execution_context_rejects_oversized_threshold_approval_set() {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "approval-oversize".to_string(),
                approver: approver.public_key(),
                subject: subject.public_key(),
                governed_intent_hash: "a".repeat(64),
                request_id: "a2a-request".to_string(),
                threshold_proposal_hash: Some("b".repeat(64)),
                issued_at: 1,
                expires_at: 2,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .test_unwrap();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&Keypair::generate(), &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: vec![
                token;
                chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
                    + 1
            ],
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let error = validate_execution_context(&execution)
            .test_expect_err("oversized A2A threshold approval set must fail");

        assert_eq!(
            error.to_string(),
            format!(
                "invalid request: A2A threshold approval set exceeds {} tokens",
                chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
            )
        );
    }

    #[test]
    fn execution_context_rejects_control_character_agent_id() {
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&Keypair::generate(), &subject, "test-srv", "echo"),
            agent_id: format!("{}{}suffix", subject.public_key().to_hex(), '\u{7}'),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let error = validate_execution_context(&execution)
            .test_expect_err("control character A2A execution agent_id must fail");

        assert_eq!(
            error.to_string(),
            "invalid request: A2A execution agent_id must not include control characters"
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
                    execution_nonce: None,
                    governed_intent: None,
                    approval_token: None,
                    approval_tokens: Vec::new(),
                    threshold_approval_proposal: None,
                    supplemental_authorization: None,
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .handle_send_message("echo", &text_message("boom"), &kernel, &execution)
            .test_expect_err("A2A web3 evidence prerequisite failure must reject");

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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            .test_expect_err("A2A capability reference mismatch must reject");

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
            public_key: manifest_public_key(10),
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
        let args = extract_arguments_from_message(&msg).test_unwrap();
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
        let args = extract_arguments_from_message(&msg).test_unwrap();
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn extract_rejects_scalar_data_part_arguments() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!("not-an-argument-object"),
            }],
            metadata: None,
        };

        let error = extract_arguments_from_message(&msg)
            .test_expect_err("scalar data parts must fail before dispatch");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("data part must be a JSON object"));
    }

    #[test]
    fn extract_rejects_array_data_part_arguments() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!(["not", "an", "argument", "object"]),
            }],
            metadata: None,
        };

        let error = extract_arguments_from_message(&msg)
            .test_expect_err("array data parts must fail before dispatch");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("data part must be a JSON object"));
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
        let args = extract_arguments_from_message(&msg).test_unwrap();
        assert_eq!(args["priority"], "high");
    }

    #[test]
    fn compatibility_send_rejects_multiple_data_parts() {
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
        let request = SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![
                    A2aPart::Data {
                        data: json!({"first": true}),
                    },
                    A2aPart::Data {
                        data: json!({"second": true}),
                    },
                ],
                metadata: None,
            },
            metadata: None,
        };

        let error = edge
            .compatibility()
            .handle_send_message_compatibility("echo", &request, &server)
            .test_expect_err("multiple A2A data parts must fail");
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("at most one data part"));
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
    fn jsonrpc_send_message_param_parser_infers_single_skill_and_labels_stream_errors() {
        let edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let (skill_id, request) = edge
            .parse_jsonrpc_send_message_params(
                serde_json::to_value(text_message("hi")).test_unwrap(),
                "SendMessage",
            )
            .test_unwrap();
        assert_eq!(skill_id, "echo");
        assert_eq!(request.message.role, "user");

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": "bad"
                }
            }),
            "SendStreamingMessage",
        ) {
            Ok(_) => panic!("expected invalid request error"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert!(message.contains("invalid SendStreamingMessage request:"));
    }

    #[test]
    fn jsonrpc_send_message_param_parser_requires_skill_id_for_multiple_skills() {
        let edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected missing target skill error"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "metadata.chio.targetSkillId is required when multiple skills are exposed"
        );
    }

    #[test]
    fn jsonrpc_single_skill_rejects_malformed_chio_metadata() {
        let edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": "not-an-object"
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected malformed metadata.chio to fail"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio must be a JSON object");
    }

    #[test]
    fn jsonrpc_single_skill_rejects_non_string_target_skill_id() {
        let edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": 123}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected non-string targetSkillId to fail"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio.targetSkillId must be a string");
    }

    #[test]
    fn jsonrpc_single_skill_rejects_empty_target_skill_id_before_lookup() {
        let edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut manifest = test_manifest();
                manifest.tools.truncate(1);
                manifest
            }],
        )
        .test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": "   "}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected empty targetSkillId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(message, "metadata.chio.targetSkillId must not be empty");
    }

    #[test]
    fn jsonrpc_rejects_padded_target_skill_id_before_lookup() {
        let edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();

        let error = match edge.parse_jsonrpc_send_message_params(
            json!({
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "hi"}]
                },
                "metadata": {
                    "chio": {"targetSkillId": " echo "}
                }
            }),
            "SendMessage",
        ) {
            Ok(_) => panic!("expected padded targetSkillId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "metadata.chio.targetSkillId must not include leading or trailing whitespace"
        );
    }

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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
    fn jsonrpc_send_message_rejects_empty_parts() {
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1);
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
                        "parts": []
                    }
                }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "message.parts must contain at least one part"
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
    fn jsonrpc_send_rejects_non_object_params_before_skill_resolution() {
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "message/send",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["message"], "message/send params must be an object");
    }

    #[test]
    fn jsonrpc_task_get_rejects_non_object_params_before_lookup() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "task/get",
                "params": []
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["message"], "task/get params must be an object");
    }

    #[test]
    fn jsonrpc_rejects_non_scalar_request_ids_before_method_dispatch() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        for invalid_id in [json!(true), json!({"nested": 1}), json!([1])] {
            let response = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": invalid_id,
                    "method": "unknown/method",
                    "params": {}
                }),
                &kernel,
                &execution,
            );

            assert_eq!(response["id"], Value::Null);
            assert_eq!(response["error"]["code"], -32600);
            assert_eq!(
                response["error"]["message"],
                "request id must be string, number, or null"
            );
        }
    }

    #[test]
    fn jsonrpc_invalid_version_preserves_scalar_request_id() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "1.0",
                "id": "request-7",
                "method": "message/send",
                "params": {}
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["id"], "request-7");
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["error"]["message"], "invalid jsonrpc envelope");
    }

    #[test]
    fn jsonrpc_compatibility_send_rejects_non_object_params_before_passthrough() {
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
            json!({
                "jsonrpc": "2.0",
                "id": 43,
                "method": "message/send",
                "params": []
            }),
            &server,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["message"], "message/send params must be an object");
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
    fn jsonrpc_task_get_runtime_admission_denies_before_deferred_dispatch() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        let invocations = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingStreamingToolServer {
            invocations: Arc::clone(&invocations),
        }));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let accepted = edge.handle_jsonrpc(
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
        assert_eq!(accepted["result"]["status"].as_str(), Some("working"));
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        let task_id = accepted["result"]["id"]
            .as_str()
            .test_expect("message/stream should return task id")
            .to_string();

        kernel.set_runtime_admission_hook(Arc::new(DenyingRuntimeAdmissionHook));
        let denied = edge.handle_jsonrpc(
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

        assert_eq!(denied["result"]["status"].as_str(), Some("failed"));
        assert_eq!(
            denied["result"]["statusMessage"].as_str(),
            Some("a2a edge runtime admission denied")
        );
        assert_eq!(
            denied["result"]["metadata"]
                .pointer("/chio/receipt/metadata/chio_runtime/failure_code")
                .and_then(Value::as_str),
            Some("a2a_edge_runtime_admission_denied")
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn jsonrpc_stream_notification_creates_task_without_response() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
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

        assert!(response.is_notification());
        assert_eq!(edge.tasks.len(), 1);
    }

    #[test]
    fn jsonrpc_task_get_retains_completed_deferred_task_result() {
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
        assert!(edge.tasks.contains_key(&task_id));

        let repeated = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "task/get",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(repeated["result"]["status"].as_str(), Some("completed"));
        assert_eq!(
            repeated["result"]["metadata"]["chio"]["receiptId"],
            resolved["result"]["metadata"]["chio"]["receiptId"]
        );
    }

    #[test]
    fn jsonrpc_task_get_rejects_empty_task_id_before_lookup() {
        let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 32,
                "method": "task/get",
                "params": { "taskId": "" }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "task/get params.taskId must not be empty"
        );
    }

    #[test]
    fn jsonrpc_task_id_params_reject_surrounding_whitespace_before_lookup() {
        let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
            &json!({ "taskId": " task-1 " }),
            "task/cancel",
        ) {
            Ok(_) => panic!("expected padded taskId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "task/cancel params.taskId must not include leading or trailing whitespace"
        );
    }

    #[test]
    fn jsonrpc_task_id_params_reject_control_characters_before_lookup() {
        let error = match ChioA2aEdge::parse_jsonrpc_task_id_params(
            &json!({ "taskId": "a2a-task-1\na2a-task-2" }),
            "task/get",
        ) {
            Ok(_) => panic!("expected control-character taskId to fail before lookup"),
            Err(error) => error,
        };
        let A2aEdgeError::InvalidRequest(message) = error else {
            panic!("expected invalid request error");
        };
        assert_eq!(
            message,
            "task/get params.taskId must not include control characters"
        );
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
    fn jsonrpc_stream_rejects_padded_execution_agent_id_before_task_retention() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: format!(" {} ", subject.public_key().to_hex()),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_500,
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

        assert_eq!(rejected["error"]["code"], -32602);
        assert_eq!(
            rejected["error"]["message"].as_str(),
            Some("A2A execution agent_id must not include leading or trailing whitespace")
        );
        assert!(edge.tasks.is_empty());
    }

    #[test]
    fn jsonrpc_stream_capacity_ignores_retained_terminal_deferred_tasks() {
        for terminal_status in [TaskStatus::Cancelled, TaskStatus::Completed] {
            let mut edge =
                ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
            let config = test_kernel_config();
            let kernel_issuer = config.keypair.clone();
            let kernel = ChioKernel::new(config);
            let subject = Keypair::generate();
            let execution = A2aKernelExecutionContext {
                capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
                agent_id: subject.public_key().to_hex(),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
            };

            for index in 0..MAX_DEFERRED_A2A_TASKS {
                let created = edge.handle_jsonrpc(
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
                assert_eq!(created["result"]["status"].as_str(), Some("working"));
                let task_id = created["result"]["id"]
                    .as_str()
                    .test_expect("message/stream should return task id")
                    .to_string();
                let task = edge
                    .tasks
                    .get_mut(&task_id)
                    .test_expect("stream task should be retained");
                task.response.status = terminal_status;
            }

            assert_eq!(edge.tasks.len(), MAX_DEFERRED_A2A_TASKS);

            let accepted = edge.handle_jsonrpc(
                json!({
                    "jsonrpc": "2.0",
                    "id": 3_000,
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

            assert_eq!(accepted["result"]["status"].as_str(), Some("working"));
        }
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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

        let cancelled_again = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 14,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled_again["result"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled_again["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn complete_task_preserves_cancelled_deferred_task() {
        let mut edge =
            ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let kernel_issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(StreamingToolServer));
        let subject = Keypair::generate();
        let execution = A2aKernelExecutionContext {
            capability: capability_for_tool(&kernel_issuer, &subject, "stream-srv", "stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
        };

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 15,
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

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 16,
                "method": "task/cancel",
                "params": {
                    "taskId": task_id.clone()
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(cancelled["result"]["status"].as_str(), Some("cancelled"));

        let completed_after_cancel = edge.complete_task(&task_id, &kernel, &execution, json!(17));
        assert_eq!(
            completed_after_cancel["result"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            completed_after_cancel["result"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );

        let repeated = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 18,
                "method": "task/get",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(repeated["result"]["status"].as_str(), Some("cancelled"));
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            .test_expect_err("ambiguous unqualified A2A skill id must fail");

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
