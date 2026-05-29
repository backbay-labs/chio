#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    use chio_core::capability::{CapabilityTokenBody, ChioScope, Operation, ToolGrant};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, DEFAULT_CHECKPOINT_BATCH_SIZE,
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

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test Server".to_string(),
            description: Some("Test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "exec_command".to_string(),
                    description: "Execute a shell command".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "search".to_string(),
                    description: "Search documents".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
            ],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn browser_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "browser-srv".to_string(),
            name: "Browser Server".to_string(),
            description: Some("Browser test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "browser_navigate".to_string(),
                description: "Navigate browser".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "browser".to_string(),
        }
    }

    fn generic_side_effect_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "tool-srv".to_string(),
            name: "Generic Tool Server".to_string(),
            description: Some("Generic side effect test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "mutate_records".to_string(),
                description: "Mutate records".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "mutate".to_string(),
        }
    }

    fn approval_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "approval-srv".to_string(),
            name: "Approval Server".to_string(),
            description: Some("Approval test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "read_secret".to_string(),
                description: "Read secret".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-approval-required": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "approval".to_string(),
        }
    }

    fn streaming_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "streaming-srv".to_string(),
            name: "Streaming Server".to_string(),
            description: Some("Streaming test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_stream".to_string(),
                description: "Stream search results".to_string(),
                input_schema: json!({
                    "type": "object",
                    "x-chio-streaming": true,
                    "x-chio-partial-output": true,
                    "x-chio-cancellation": true
                }),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "streaming".to_string(),
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
                name: "read_file".to_string(),
                description: "Read file via MCP target executor".to_string(),
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
                name: "read_file".to_string(),
                description: "Read file via OpenAI target executor".to_string(),
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
                name: "read_file".to_string(),
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
                name: "hidden_tool".to_string(),
                description: "Hidden tool".to_string(),
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

    fn colliding_search_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "other-srv".to_string(),
            name: "Other Search Server".to_string(),
            description: Some("Collision test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search".to_string(),
                description: "Search somewhere else".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "other-search".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "exec_command".to_string(),
                "search".to_string(),
            ],
            response: json!({"result": "ok"}),
        }
    }

    fn test_kernel_config() -> KernelConfig {
        let keypair = Keypair::generate();
        KernelConfig {
            ca_public_keys: vec![keypair.public_key()],
            keypair,
            max_delegation_depth: 8,
            policy_hash: "policy-acp-test".to_string(),
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
        let now = current_unix_timestamp();
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
        let body = render_acp_edge_metrics_prometheus();
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

    // ---- Capability generation tests ----

    #[test]
    fn edge_generates_capabilities_from_manifest() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn edge_capability_ids_match_tool_names() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let ids = edge.capability_ids();
        assert!(ids.contains(&"read_file".to_string()));
        assert!(ids.contains(&"write_file".to_string()));
        assert!(ids.contains(&"exec_command".to_string()));
        assert!(ids.contains(&"search".to_string()));
    }

    #[test]
    fn edge_capability_lookup() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.description, "Read a file");
    }

    #[test]
    fn edge_unknown_capability_returns_none() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        assert!(edge.capability("nonexistent").is_none());
    }

    // ---- Category inference tests ----

    #[test]
    fn read_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn write_file_gets_filesystem_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("write_file").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn exec_command_gets_terminal_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("exec_command").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Terminal);
    }

    #[test]
    fn search_gets_default_tool_category() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("search").test_unwrap();
        assert_eq!(cap.category, AcpCategory::Tool);
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn filesystem_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("read_file").test_unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn terminal_tools_have_lossless_fidelity() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("exec_command").test_unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Lossless);
    }

    #[test]
    fn generic_readonly_tool_is_adapted_with_category_caveat() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("search").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("tool category") || c.contains("native ACP primitive")));
    }

    #[test]
    fn browser_tools_are_not_auto_published() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![browser_manifest()]).test_unwrap();
        assert!(edge.capability("browser_navigate").is_none());
        assert_eq!(
            edge.bridge_fidelity("browser_navigate"),
            Some(&BridgeFidelity::Unsupported {
                reason: "browser/session automation semantics are not yet truthfully projected on the ACP edge".to_string()
            })
        );
    }

    #[test]
    fn generic_side_effectful_tools_are_not_auto_published() {
        let edge = ChioAcpEdge::new(
            AcpEdgeConfig::default(),
            vec![generic_side_effect_manifest()],
        )
        .test_unwrap();
        assert!(edge.capability("mutate_records").is_none());
        assert_eq!(
            edge.bridge_fidelity("mutate_records"),
            Some(&BridgeFidelity::Unsupported {
                reason: "generic side-effectful tools do not map honestly to ACP capability classes on this edge".to_string()
            })
        );
    }

    #[test]
    fn approval_required_capability_is_adapted_with_permission_caveat() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![approval_manifest()]).test_unwrap();
        let cap = edge.capability("read_secret").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("permission preview is advisory")));
    }

    #[test]
    fn streaming_capability_is_adapted_with_stream_and_cancellation_caveats() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let cap = edge.capability("search_stream").test_unwrap();
        let BridgeFidelity::Adapted { caveats } = &cap.bridge_fidelity else {
            panic!("expected adapted fidelity");
        };
        assert!(caveats
            .iter()
            .any(|c| c.contains("deferred `tool/stream` tasks")));
        assert!(caveats
            .iter()
            .any(|c| c.contains("partial output is preserved")));
        assert!(caveats
            .iter()
            .any(|c| c.contains("cancellation is available")));
    }

    #[test]
    fn hidden_capability_is_not_auto_published() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![hidden_manifest()]).test_unwrap();
        assert!(edge.capability("hidden_tool").is_none());
        assert_eq!(
            edge.bridge_fidelity("hidden_tool"),
            Some(&BridgeFidelity::Unsupported {
                reason: "publication disabled by x-chio-publish=false".to_string()
            })
        );
    }

    // ---- Permission tests ----

    #[test]
    fn side_effect_tools_require_permission() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let cap = edge.capability("write_file").test_unwrap();
        assert!(cap.requires_permission);
    }

    #[test]
    fn permission_denied_by_default_for_required_caps() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_denied_for_unknown_capability() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let request = PermissionRequest {
            capability_id: "nonexistent".to_string(),
            arguments: json!({}),
        };
        assert_eq!(
            edge.compatibility().preview_permission(&request),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn permission_not_required_when_config_disabled() {
        let config = AcpEdgeConfig {
            require_permission: false,
            default_category: AcpCategory::Tool,
        };
        let edge = ChioAcpEdge::new(config, vec![test_manifest()]).test_unwrap();
        // read_file has no side effects and require_permission is false
        let cap = edge.capability("read_file").test_unwrap();
        assert!(!cap.requires_permission);
    }

    #[test]
    fn permission_with_capability_allows_matching_scope() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let request = PermissionRequest {
            capability_id: "read_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Allow
        );
    }

    #[test]
    fn permission_with_capability_denies_out_of_scope_request() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({"path": "/tmp"}),
        };

        assert_eq!(
            edge.evaluate_permission(&request, &execution),
            PermissionDecision::Deny
        );
    }

    // ---- Invocation tests ----

    #[test]
    fn invoke_succeeds() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();
        let result = edge
            .compatibility()
            .invoke("read_file", json!({"path": "/tmp"}), &server)
            .test_unwrap();
        assert!(result.success);
        assert_eq!(result.data["result"], "ok");
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_unknown_tool_errors() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();
        let err = edge
            .compatibility()
            .invoke("nonexistent", json!({}), &server)
            .unwrap_err();
        assert!(matches!(err, AcpEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn invoke_server_failure_returns_unsuccessful() {
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
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![manifest]).test_unwrap();
        let server = FailingToolServer;
        let result = edge
            .compatibility()
            .invoke("fail_tool", json!({}), &server)
            .test_unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(
            result
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio"]["authorityPath"].as_str()),
            Some("passthrough_compatibility")
        );
    }

    #[test]
    fn invoke_with_kernel_emits_signed_receipt_metadata() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();
        assert!(result.success);
        let metadata = result.metadata.test_expect("kernel path should attach metadata");
        assert!(metadata["chio"]["receiptId"].as_str().is_some());
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("native")
        );
        assert_eq!(
            metadata["chio"]["receipt"]["capability_id"].as_str(),
            Some("cap-test-srv-read_file")
        );
    }

    #[test]
    fn invoke_with_kernel_denial_still_emits_receipt_metadata() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("write_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();
        assert!(!result.success);
        let metadata = result.metadata.test_expect("deny path should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
        assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    }

    #[test]
    fn pending_approval_is_not_reported_as_success() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let result = edge
            .project_pending_approval_for_test(
                "read_file",
                json!({"path": "/tmp"}),
                &kernel,
                &AcpKernelExecutionContext {
                    capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
                    agent_id: subject.public_key().to_hex(),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                    model_metadata: None,
                },
                "approval required",
            )
            .test_unwrap();
        let metadata = result
            .metadata
            .test_expect("pending approval should attach metadata");

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("approval required"));
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
    fn invoke_kernel_error_records_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let mut config = test_kernel_config();
        config.require_web3_evidence = true;
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("web3 evidence prerequisites unavailable"));
        assert!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
            "acp orchestrator error path must advance receipt write error"
        );
    }

    #[test]
    fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
        let _metrics_guard = metrics_test_guard();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let capability = capability_for_tool(&issuer, &subject, "test-srv", "read_file");
        let capability_ref = CrossProtocolCapabilityRef {
            chio_capability_id: "wrong-capability".to_string(),
            origin_protocol: DiscoveryProtocol::Acp,
            protocol_context: Some(json!({ "capabilityId": "read_file" })),
            parent_capability_hash: "wrong-parent-hash".to_string(),
        };
        let arguments = json!({ "path": "/tmp" });
        let request = CrossProtocolExecutionRequest {
            origin_request_id: "acp-pre-kernel-mismatch".to_string(),
            kernel_request_id: "acp-pre-kernel-mismatch-kernel".to_string(),
            target_protocol: DiscoveryProtocol::Native,
            target_server_id: "test-srv".to_string(),
            target_tool_name: "read_file".to_string(),
            agent_id: subject.public_key().to_hex(),
            arguments: arguments.clone(),
            capability,
            source_envelope: json!({
                "capabilityId": "read_file",
                "arguments": arguments,
                "metadata": {
                    "chio": {
                        "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
                    }
                }
            }),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };
        let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

        let error = execute_orchestrated_acp_request(&kernel, request).unwrap_err();

        assert!(error.to_string().contains("capability reference mismatch"));
        assert_eq!(
            receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
            before_error,
            "pre-kernel ACP bridge errors must not advance receipt write error"
        );
    }

    #[test]
    fn invoke_with_mcp_target_emits_receipt_metadata_and_mcp_projection() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke_with_mcp_target("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        assert!(result.success);
        assert_eq!(result.data["isError"], Value::Bool(false));
        assert_eq!(
            result.data["structuredContent"]["result"].as_str(),
            Some("ok")
        );
        let metadata = result.metadata.test_expect("MCP target should attach metadata");
        assert_eq!(
            metadata["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
            Some("acp")
        );
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["multiHop"].as_bool(),
            Some(true)
        );
        assert_eq!(
            metadata["chio"]["bridge"]["route"]["selectedProtocols"],
            json!(["acp", "mcp", "native"])
        );
    }

    #[test]
    fn default_invoke_honors_protocol_aware_target_binding() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![mcp_target_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        let metadata = result
            .metadata
            .test_expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("mcp")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
    }

    #[test]
    fn default_invoke_supports_openai_target_binding() {
        let edge =
            ChioAcpEdge::new(AcpEdgeConfig::default(), vec![openai_target_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));

        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &kernel, &execution)
            .test_unwrap();

        let metadata = result
            .metadata
            .test_expect("protocol-aware invoke should attach metadata");
        assert_eq!(
            metadata["chio"]["bridge"]["targetProtocol"].as_str(),
            Some("open_ai")
        );
        assert_eq!(
            metadata["chio"]["targetExecution"]["projectedResult"],
            Value::Bool(true)
        );
        assert_eq!(result.data["type"].as_str(), Some("function_call_output"));
    }

    #[test]
    fn invalid_target_protocol_metadata_is_rejected() {
        let error =
            match ChioAcpEdge::new(AcpEdgeConfig::default(), vec![invalid_target_manifest()]) {
                Ok(_) => panic!("expected invalid target protocol metadata to fail"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("unsupported x-chio-target-protocol value"));
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_list_capabilities() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
                "method": "session/list_capabilities",
                "params": {}
            }),
            &kernel,
            &execution,
        );
        let caps = response["result"]["capabilities"].as_array().test_unwrap();
        assert_eq!(caps.len(), 4);
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeMode"].as_str(),
            Some("blocking_or_deferred_task")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["lifecycle"]["toolStream"].as_str(),
            Some("deferred_task_resume")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["runtimeLifecycle"]["surface"].as_str(),
            Some("acp_authoritative")
        );
    }

    #[test]
    fn jsonrpc_request_permission() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response.get("result").is_some());
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("capability_preview")
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(false)
        );
        assert_eq!(
            response["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_tool_invoke() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(test_server()));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "search"),
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
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert!(response["result"]["success"].as_bool().unwrap_or(false));
        assert_eq!(
            response["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("cross_protocol_orchestrator")
        );
    }

    #[test]
    fn jsonrpc_unknown_method() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
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
    fn jsonrpc_passthrough_marks_non_authoritative_paths() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let server = test_server();

        let listed = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "session/list_capabilities",
                "params": {}
            }),
            &server,
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            listed["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );

        let permission = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &server,
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("config_preview")
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["previewOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
        assert_eq!(
            permission["result"]["metadata"]["chio"]["invokeAuthorityPath"].as_str(),
            Some("passthrough_compatibility")
        );

        let invoke = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &server,
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["authoritative"].as_bool(),
            Some(false)
        );
        assert_eq!(
            invoke["result"]["metadata"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn jsonrpc_stream_creates_deferred_task_and_resume_resolves_result() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}, {"text": "chunk-2"}]}),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            response["result"]["task"]["status"].as_str(),
            Some("working")
        );
        let task_id = response["result"]["task"]["id"]
            .as_str()
            .test_expect("tool/stream should create task")
            .to_string();
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["receiptPending"].as_bool(),
            Some(true)
        );
        assert_eq!(
            response["result"]["task"]["metadata"]["chio"]["runtimeLifecycle"]["streamEntrypoint"]
                .as_str(),
            Some("tool/stream")
        );

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/resume",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert_eq!(
            resumed["result"]["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .map(|value| !value.is_empty()),
            Some(true)
        );
        assert!(resumed["result"]["result"]["data"]["content"].is_array());
    }

    #[test]
    fn jsonrpc_resume_removes_completed_deferred_task() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let mut kernel = ChioKernel::new(config);
        kernel.register_tool_server(Box::new(MockToolServer {
            server_id: "streaming-srv".to_string(),
            tools: vec!["search_stream".to_string()],
            response: json!({"content": [{"text": "chunk-1"}]}),
        }));
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_unwrap()
            .to_string();

        let resumed = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tool/resume",
                "params": { "taskId": task_id.clone() }
            }),
            &kernel,
            &execution,
        );

        assert_eq!(
            resumed["result"]["task"]["status"].as_str(),
            Some("completed")
        );
        assert!(!edge.tasks.borrow().contains_key(&task_id));
    }

    #[test]
    fn jsonrpc_stream_rejects_deferred_task_map_over_cap() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
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
                    "method": "tool/stream",
                    "params": {
                        "capabilityId": "search_stream",
                        "arguments": {"query": "test"}
                    }
                }),
                &kernel,
                &execution,
            );
            assert_eq!(
                response["result"]["task"]["status"].as_str(),
                Some("working")
            );
        }

        let rejected = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 2_000,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
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
    fn jsonrpc_cancel_marks_deferred_stream_task_cancelled() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel = ChioKernel::new(config);
        let subject = Keypair::generate();
        let execution = AcpKernelExecutionContext {
            capability: capability_for_tool(&issuer, &subject, "streaming-srv", "search_stream"),
            agent_id: subject.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let created = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tool/stream",
                "params": {
                    "capabilityId": "search_stream",
                    "arguments": {"query": "test"}
                }
            }),
            &kernel,
            &execution,
        );
        let task_id = created["result"]["task"]["id"]
            .as_str()
            .test_unwrap()
            .to_string();

        let cancelled = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tool/cancel",
                "params": {
                    "taskId": task_id
                }
            }),
            &kernel,
            &execution,
        );
        assert_eq!(
            cancelled["result"]["task"]["status"].as_str(),
            Some("cancelled")
        );
        assert_eq!(
            cancelled["result"]["task"]["metadata"]["chio"]["decision"].as_str(),
            Some("cancelled")
        );
    }

    #[test]
    fn compatibility_jsonrpc_explicitly_rejects_unimplemented_lifecycle_methods() {
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![streaming_manifest()]).test_unwrap();
        let server = test_server();

        let response = edge.compatibility().handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tool/cancel",
                "params": {
                    "capabilityId": "search_stream"
                }
            }),
            &server,
        );
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(
            response["error"]["data"]["chio"]["authorityPath"].as_str(),
            Some("passthrough_compatibility")
        );
        assert_eq!(
            response["error"]["data"]["chio"]["compatibilityOnly"].as_bool(),
            Some(true)
        );
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![m1, m2]).test_unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn colliding_capability_ids_are_withheld_deterministically() {
        let edge = ChioAcpEdge::new(
            AcpEdgeConfig::default(),
            vec![test_manifest(), colliding_search_manifest()],
        )
        .test_unwrap();

        assert!(edge.capability("search").is_none());
        assert_eq!(edge.capabilities().len(), 3);

        let fidelity = edge
            .bridge_fidelity("search")
            .test_expect("collision should still have fidelity classification");
        let BridgeFidelity::Unsupported { reason } = fidelity else {
            panic!("colliding capability should be unsupported");
        };
        assert!(reason.contains("withheld from discovery"));
        assert!(reason.contains("other-srv/search"));
        assert!(reason.contains("test-srv/search"));
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = AcpEdgeError::ToolNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_access_denied() {
        let err = AcpEdgeError::AccessDenied("no cap".into());
        assert!(format!("{err}").contains("no cap"));
    }

    #[test]
    fn error_display_kernel() {
        let err = AcpEdgeError::Kernel("internal".into());
        assert!(format!("{err}").contains("internal"));
    }

    // ---- Serde tests ----

    #[test]
    fn bridge_fidelity_serializes() {
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Lossless).test_unwrap(),
            json!({"kind": "lossless"})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Adapted {
                caveats: vec!["preview only".to_string()]
            })
            .test_unwrap(),
            json!({"kind": "adapted", "caveats": ["preview only"]})
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Unsupported {
                reason: "not publishable".to_string()
            })
            .test_unwrap(),
            json!({"kind": "unsupported", "reason": "not publishable"})
        );
    }

    #[test]
    fn acp_category_serializes() {
        assert_eq!(serde_json::to_value(AcpCategory::Tool).test_unwrap(), "tool");
        assert_eq!(
            serde_json::to_value(AcpCategory::Filesystem).test_unwrap(),
            "filesystem"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Terminal).test_unwrap(),
            "terminal"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Browser).test_unwrap(),
            "browser"
        );
    }

    #[test]
    fn permission_decision_serializes() {
        assert_eq!(
            serde_json::to_value(PermissionDecision::Allow).test_unwrap(),
            "allow"
        );
        assert_eq!(
            serde_json::to_value(PermissionDecision::Deny).test_unwrap(),
            "deny"
        );
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_requires_permission() {
        let config = AcpEdgeConfig::default();
        assert!(config.require_permission);
        assert_eq!(config.default_category, AcpCategory::Tool);
    }
}
