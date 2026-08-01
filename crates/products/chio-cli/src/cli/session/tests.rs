    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::OnceLock,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn load_test_policy_runtime(policy: &policy::ChioPolicy) -> policy::LoadedPolicy {
        let default_capabilities = policy::build_runtime_default_capabilities(policy).unwrap();

        policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: chio_core::crypto::sha256_hex(b"test-source-policy"),
                runtime_hash: chio_core::crypto::sha256_hex(b"test-runtime-policy"),
            },
            kernel: policy.kernel.clone(),
            default_capabilities,
            guard_pipeline: policy::build_guard_pipeline(&policy.guards).unwrap(),
            post_invocation_pipeline: policy::build_post_invocation_pipeline(&policy.guards)
                .unwrap(),
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval: None,
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/policies")
            .join(name)
    }

    fn session_store_dir() -> &'static Path {
        static STORE_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        STORE_DIR
            .get_or_init(|| {
                let directory = tempfile::Builder::new()
                    .prefix("chio-cli-session-stores-")
                    .tempdir()
                    .expect("create private session store directory");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                        .expect("secure private session store directory");
                }
                directory
            })
            .path()
    }

    fn unique_db_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        session_store_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn unique_seed_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        session_store_dir().join(format!("{prefix}-{nonce}.seed"))
    }

    fn loopback_bind_available() -> bool {
        std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok()
    }

    // Mirror production (cli/runtime.rs): install durable receipt and admission
    // stores from one authority owner.
    fn build_kernel_with_receipt_store(
        loaded_policy: policy::LoadedPolicy,
        _kernel_kp: &Keypair,
    ) -> ChioKernel {
        let session_db_path = unique_db_path("chio-cli-session-admission");
        build_kernel_with_admission_db(loaded_policy, &session_db_path)
    }

    fn build_kernel_with_admission_db(
        loaded_policy: policy::LoadedPolicy,
        session_db_path: &Path,
    ) -> ChioKernel {
        let durable_admission = open_durable_admission_runtime(
            loaded_policy.kernel.durable_admission_mode,
            Some(session_db_path),
        )
        .expect("open durable admission runtime")
        .expect("enabled durable admission runtime");
        let mut kernel = build_kernel(loaded_policy, &durable_admission.kernel_keypair());
        let receipt_db_path = unique_db_path("chio-cli-session-receipts");
        configure_receipt_store(&mut kernel, Some(&receipt_db_path), None, None)
            .expect("configure receipt store for session test");
        durable_admission
            .attach(&mut kernel)
            .expect("attach durable admission runtime");
        kernel
    }

    fn first_default_capability(
        kernel: &ChioKernel,
        policy: &policy::ChioPolicy,
        agent_kp: &Keypair,
    ) -> chio_core::capability::token::CapabilityToken {
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        issue_default_capabilities(kernel, &agent_kp.public_key(), &default_capabilities)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    fn open_ready_session(
        kernel: &mut ChioKernel,
        agent_id: &str,
        capabilities: Vec<chio_core::capability::token::CapabilityToken>,
    ) -> SessionId {
        let session_id = kernel.open_session(agent_id.to_string(), capabilities).unwrap();
        kernel.activate_session(&session_id).unwrap();
        session_id
    }

    fn only_message(messages: Vec<KernelMessage>) -> KernelMessage {
        assert_eq!(messages.len(), 1, "expected exactly one kernel message");
        messages.into_iter().next().unwrap()
    }

    #[test]
    fn check_builds_kernel_with_guards() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
guards:
  forbidden_path:
    enabled: true
  shell_command:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        assert_eq!(kernel.guard_count(), 4); // default profile + configured pipeline
    }

    #[tokio::test]
    async fn configure_revocation_store_survives_restart() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let revocation_db_path = unique_db_path("chio-cli-revocations");
        let admission_db_path = unique_db_path("chio-cli-revocation-admission");

        let agent_kp = Keypair::generate();
        let cap = {
            let mut kernel = build_kernel_with_admission_db(
                load_test_policy_runtime(&policy),
                &admission_db_path,
            );
            configure_revocation_store(&mut kernel, Some(&revocation_db_path), None, None).unwrap();
            kernel.register_tool_server(Box::new(StubToolServer {
                id: "*".to_string(),
            }));

            let cap = first_default_capability(&kernel, &policy, &agent_kp);
            kernel.revoke_capability(&cap.id).unwrap();
            cap
        };

        let mut restarted = build_kernel_with_admission_db(
            load_test_policy_runtime(&policy),
            &admission_db_path,
        );
        configure_revocation_store(&mut restarted, Some(&revocation_db_path), None, None).unwrap();
        restarted.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let request = KernelToolCallRequest {
            request_id: "revoked-after-restart".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
                execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let response = restarted.evaluate_tool_call(&request).await.unwrap();
        assert_eq!(response.verdict, chio_kernel::Verdict::Deny);
        assert!(
            response.reason.as_deref().unwrap_or("").contains("revoked"),
            "unexpected denial reason: {:?}",
            response.reason
        );

        let _ = std::fs::remove_file(revocation_db_path);
    }

    #[test]
    fn authority_seed_file_persists_public_key_across_loads_and_rotation() {
        let seed_path = unique_seed_path("chio-cli-authority");
        let original = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        let reloaded = load_or_create_authority_keypair(&seed_path)
            .unwrap()
            .public_key();
        assert_eq!(original, reloaded);

        let rotated = rotate_authority_keypair(&seed_path).unwrap();
        assert_ne!(original, rotated);
        assert_eq!(
            authority_public_key_from_seed_file(&seed_path).unwrap(),
            Some(rotated)
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_changes_issued_capability_issuer() {
        let seed_path = unique_seed_path("chio-cli-configure-authority");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        configure_capability_authority(
            &mut kernel,
            &kp,
            Some(&seed_path),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let agent_kp = Keypair::generate();
        let capability =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();

        assert_eq!(
            capability.issuer,
            authority_public_key_from_seed_file(&seed_path)
                .unwrap()
                .expect("authority public key")
        );

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn configure_capability_authority_supports_shared_sqlite_backend() {
        let authority_db_path = unique_db_path("chio-cli-authority-db");
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let first_kp = Keypair::generate();
        let mut first_kernel = build_kernel(load_test_policy_runtime(&policy), &first_kp);
        configure_capability_authority(
            &mut first_kernel,
            &first_kp,
            None,
            Some(&authority_db_path),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let first_capability = issue_default_capabilities(
            &first_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let original_issuer = first_capability.issuer.clone();

        let authority =
            chio_store_sqlite::SqliteCapabilityAuthority::open(&authority_db_path).unwrap();
        let rotated = authority.rotate().unwrap();

        let second_kp = Keypair::generate();
        let mut second_kernel = build_kernel(load_test_policy_runtime(&policy), &second_kp);
        configure_capability_authority(
            &mut second_kernel,
            &second_kp,
            None,
            Some(&authority_db_path),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let second_capability = issue_default_capabilities(
            &second_kernel,
            &Keypair::generate().public_key(),
            &default_capabilities,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

        assert_ne!(original_issuer, second_capability.issuer);
        assert_eq!(second_capability.issuer, rotated.public_key);

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[tokio::test]
    async fn check_command_allow() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-1".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
                execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let response = kernel.evaluate_tool_call(&request).await.unwrap();
        assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
    }

    #[tokio::test]
    async fn check_command_deny_forbidden_path() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);

        let request = KernelToolCallRequest {
            request_id: "test-2".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/home/user/.ssh/id_rsa"}),
            dpop_proof: None,
                execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let response = kernel.evaluate_tool_call(&request).await.unwrap();
        assert_eq!(response.verdict, chio_kernel::Verdict::Deny);
    }

    fn mcp_edge_kernel(
        policy: &policy::ChioPolicy,
        _kernel_kp: &Keypair,
    ) -> (ChioKernel, PathBuf) {
        // Mirror `chio mcp serve`: durable receipts plus one fenced admission
        // authority for operation, outcome, budget, and revocation state.
        let receipt_db_path = unique_db_path("chio-cli-mcp-edge-receipts");
        let loaded_policy = load_test_policy_runtime(policy);
        let admission_db_path = unique_db_path("chio-cli-mcp-edge-admission");
        let durable_admission = open_durable_admission_runtime(
            loaded_policy.kernel.durable_admission_mode,
            Some(&admission_db_path),
        )
        .expect("open mcp edge admission runtime")
        .expect("enabled mcp edge admission runtime");
        let kernel = crate::runtime_cli::build_mcp_edge_kernel(
            loaded_policy,
            &durable_admission.kernel_keypair(),
            &crate::runtime_cli::McpEdgeStores {
                receipt_db_path: Some(&receipt_db_path),
                revocation_db_path: None,
                authority_seed_path: None,
                authority_db_path: None,
                budget_db_path: None,
                durable_admission: Some(&durable_admission),
                control_url: None,
                control_token: None,
            },
        )
        .expect("build mcp edge kernel");
        (kernel, receipt_db_path)
    }

    fn mcp_edge_tool_call(
        agent_kp: &Keypair,
        cap: chio_core::capability::token::CapabilityToken,
    ) -> KernelToolCallRequest {
        KernelToolCallRequest {
            request_id: "mcp-edge-dispatch".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "*".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    const MCP_EDGE_TOOL_POLICY: &str = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;

    #[tokio::test]
    async fn mcp_edge_uses_the_durable_admission_revocation_authority() {
        let yaml = format!(
            "kernel:\n  max_capability_ttl: 3600\n  allow_ephemeral_revocation_store: false\n{MCP_EDGE_TOOL_POLICY}"
        );
        let policy = policy::parse_policy(&yaml).unwrap();
        let kp = Keypair::generate();
        let (mut kernel, receipt_db_path) = mcp_edge_kernel(&policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let mut first_request = mcp_edge_tool_call(&agent_kp, cap.clone());
        first_request.request_id = "mcp-edge-before-revocation".to_owned();
        let first = kernel
            .evaluate_tool_call(&first_request)
            .await
            .unwrap();
        assert_eq!(first.verdict, chio_kernel::Verdict::Allow);

        kernel
            .revoke_capability(&cap.id)
            .expect("revoke through durable admission authority");
        assert!(kernel
            .is_capability_revoked(&cap.id.to_string())
            .expect("query durable revocation authority"));
        let mut revoked_request = mcp_edge_tool_call(&agent_kp, cap);
        revoked_request.request_id = "mcp-edge-after-revocation".to_owned();
        let revoked = kernel
            .evaluate_tool_call(&revoked_request)
            .await
            .unwrap();
        assert_eq!(revoked.verdict, chio_kernel::Verdict::Deny);
        let _ = std::fs::remove_file(receipt_db_path);
    }

    #[tokio::test]
    async fn mcp_edge_durable_admission_authority_enforces_invocation_budget() {
        let yaml = format!(
            "kernel:\n  max_capability_ttl: 3600\n  allow_ephemeral_revocation_store: false\n{MCP_EDGE_TOOL_POLICY}"
        );
        let policy = policy::parse_policy(&yaml).unwrap();
        let kp = Keypair::generate();
        let (mut kernel, receipt_db_path) = mcp_edge_kernel(&policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "*".to_owned(),
                        tool_name: "read_file".to_owned(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: Some(1),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                300,
            )
            .expect("issue invocation-limited capability");
        let mut first_request = mcp_edge_tool_call(&agent_kp, cap.clone());
        first_request.request_id = "mcp-edge-budget-first".to_owned();
        let first = kernel
            .evaluate_tool_call(&first_request)
            .await
            .unwrap();
        assert_eq!(first.verdict, chio_kernel::Verdict::Allow);

        let mut second_request = mcp_edge_tool_call(&agent_kp, cap);
        second_request.request_id = "mcp-edge-budget-second".to_owned();
        let second = kernel
            .evaluate_tool_call(&second_request)
            .await
            .unwrap();
        assert_eq!(second.verdict, chio_kernel::Verdict::Deny);
        let _ = std::fs::remove_file(receipt_db_path);
    }

    #[test]
    fn handle_heartbeat() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::Heartbeat,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        assert!(matches!(response, KernelMessage::Heartbeat));
        assert_eq!(stats.requests, 0);
    }

    #[test]
    fn handle_list_capabilities() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &AgentMessage::ListCapabilities,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        match response {
            KernelMessage::CapabilityList { capabilities } => {
                assert_eq!(capabilities.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_uses_explicit_server_id() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
      - server: "srv-b"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-b".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let cap = caps[0].clone();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "srv-b".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/app/src/main.rs"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn session_transport_round_trips_strict_execution_nonce_retry() {
        let yaml = r#"
kernel:
  allow_ephemeral_receipt_log: true
  allow_ephemeral_revocation_store: true
  durable_admission_mode: off
  allow_unsafe_durable_admission_off: true
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-a".to_string(),
        }));
        let mut nonce_config = chio_kernel::ExecutionNonceConfig::default();
        nonce_config.require_nonce = true;
        kernel.set_execution_nonce_store(
            nonce_config.clone(),
            Box::new(chio_kernel::InMemoryExecutionNonceStore::from_config(
                &nonce_config,
            )),
        );

        let agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());
        let mut message = AgentMessage::ToolCallRequest {
            id: "req-strict-session-nonce".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "srv-a".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/app/src/main.rs"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };
        let mut stats = SessionStats::default();

        let preflight = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let nonce = match preflight {
            KernelMessage::ToolCallResponse {
                result: ToolCallResult::Ok { value },
                execution_nonce: Some(nonce),
                ..
            } => {
                assert_eq!(value, serde_json::Value::Null);
                nonce
            }
            other => panic!("expected nonce preflight response, got {other:?}"),
        };
        let AgentMessage::ToolCallRequest {
            execution_nonce, ..
        } = &mut message
        else {
            panic!("expected tool-call request");
        };
        *execution_nonce = Some(nonce);

        let retry = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        match retry {
            KernelMessage::ToolCallResponse {
                result: ToolCallResult::Ok { value },
                ..
            } => assert_eq!(value["tool"], "read_file"),
            other => panic!("expected executed retry response, got {other:?}"),
        }
    }

    #[test]
    fn handle_tool_call_uses_session_agent_id_not_presented_subject() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "srv-a"
        tool: "read_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "srv-a".to_string(),
        }));

        let session_agent_kp = Keypair::generate();
        let stolen_agent_kp = Keypair::generate();
        let default_capabilities = policy::build_default_capabilities(
            &policy.capabilities,
            policy.kernel.max_capability_ttl,
        )
        .unwrap();
        let caps = issue_default_capabilities(
            &kernel,
            &session_agent_kp.public_key(),
            &default_capabilities,
        )
        .unwrap();
        let session_agent_id = session_agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &session_agent_id, caps.clone());
        let stolen_capability = first_default_capability(&kernel, &policy, &stolen_agent_kp);

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(stolen_capability),
            server_id: "srv-a".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/app/src/main.rs"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &session_agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hushspec_policy_drives_tool_access_via_session_runtime_path() {
        let loaded_policy = policy::load_policy(&fixture_path("hushspec-tool-allow.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md", "content": "nope"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hushspec_threat_intel_compiles_into_runtime_guard_path() {
        let dir = tempfile::tempdir().unwrap();
        let pattern_db_path = dir.path().join("pattern-db.json");
        fs::write(
            &pattern_db_path,
            r#"
[
  {
    "id": "known-prompt-injection",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "Known malicious prompt embedding",
    "embedding": [1.0, 0.0, 0.0]
  }
]
"#,
        )
        .unwrap();

        let policy_path = dir.path().join("hushspec-threat-intel.yaml");
        fs::write(
            &policy_path,
            format!(
                r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
"#,
                pattern_db_path.display()
            ),
        )
        .unwrap();

        let loaded_policy = policy::load_policy(&policy_path).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({
                "path": "/workspace/README.md",
                "embedding": [1.0, 0.0, 0.0]
            }),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-threat-intel".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({
                "path": "/workspace/README.md",
                "embedding": [1.0, 0.0, 0.0]
            })),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 1);
    }

    #[test]
    fn yaml_tool_access_drives_tool_access_via_session_runtime_path() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - list_directory
"#,
        )
        .unwrap();

        let loaded_policy = load_test_policy_runtime(&policy);
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let allowed_cap = select_capability_for_request(
            &caps,
            "read_file",
            "*",
            &serde_json::json!({"path": "/workspace/README.md"}),
        )
        .unwrap();

        let allowed = AgentMessage::ToolCallRequest {
            id: "req-allow".to_string(),
            capability_token: Box::new(allowed_cap),
            server_id: "*".to_string(),
            tool: "read_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let denied = AgentMessage::ToolCallRequest {
            id: "req-deny".to_string(),
            capability_token: Box::new(caps[0].clone()),
            server_id: "*".to_string(),
            tool: "write_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md", "content": "nope"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let allowed_response = only_message(handle_agent_message(
            &mut kernel,
            &allowed,
            &session_id,
            &agent_id,
            &mut stats,
        ));
        let denied_response = only_message(handle_agent_message(
            &mut kernel,
            &denied,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match allowed_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Ok { .. }));
            }
            _ => panic!("wrong variant"),
        }

        match denied_response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handle_tool_call_streams_chunks_before_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: false,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        assert!(matches!(
            &messages[0],
            KernelMessage::ToolCallChunk { chunk_index: 0, .. }
        ));
        assert!(matches!(
            &messages[1],
            KernelMessage::ToolCallChunk { chunk_index: 1, .. }
        ));
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::StreamComplete { total_chunks: 2 }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn handle_tool_call_surfaces_incomplete_stream_terminal_response() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "*"
        tool: "stream_file"
        operations: [invoke]
        ttl: 300
"#;
        let policy = policy::parse_policy(yaml).unwrap();
        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubStreamingToolServer {
            id: "*".to_string(),
            incomplete: true,
        }));

        let agent_kp = Keypair::generate();
        let cap = first_default_capability(&kernel, &policy, &agent_kp);
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, vec![cap.clone()]);

        let message = AgentMessage::ToolCallRequest {
            id: "stream-2".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "stream_file".to_string(),
            params: Box::new(serde_json::json!({"path": "/workspace/README.md"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let messages =
            handle_agent_message(&mut kernel, &message, &session_id, &agent_id, &mut stats);

        assert_eq!(messages.len(), 3);
        match &messages[2] {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(
                    result,
                    ToolCallResult::Incomplete {
                        chunks_received: 2,
                        ..
                    }
                ));
            }
            other => panic!("unexpected terminal message: {other:?}"),
        }
    }

    #[test]
    fn hushspec_policy_compiles_shell_guard_into_runtime_path() {
        let loaded_policy =
            policy::load_policy(&fixture_path("hushspec-guard-heavy.yaml")).unwrap();
        let default_capabilities = loaded_policy.default_capabilities.clone();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "bash",
            "*",
            &serde_json::json!({"command": "rm -rf /"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-1".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "bash".to_string(),
            params: Box::new(serde_json::json!({"command": "rm -rf /"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn chio_yaml_sql_query_guard_drives_session_runtime_path() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - sql
  sql_query:
    operation_allowlist: [select]
    table_allowlist: [orders]
"#,
        )
        .unwrap();
        let default_capabilities = policy::build_runtime_default_capabilities(&policy).unwrap();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "sql",
            "*",
            &serde_json::json!({"database": "postgres", "query": "DELETE FROM orders"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-sql-guard".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "sql".to_string(),
            params: Box::new(serde_json::json!({"database": "postgres", "query": "DELETE FROM orders"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 1);
    }

    #[test]
    fn chio_yaml_query_result_guard_redacts_runtime_output() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - sql
  query_result:
    redact_pii_patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
"#,
        )
        .unwrap();
        let default_capabilities = policy::build_runtime_default_capabilities(&policy).unwrap();

        let kp = Keypair::generate();
        let mut kernel = build_kernel_with_receipt_store(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubSqlResultToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "sql",
            "*",
            &serde_json::json!({"database": "postgres", "query": "SELECT email FROM orders"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-query-result".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "sql".to_string(),
            params: Box::new(serde_json::json!({"database": "postgres", "query": "SELECT email FROM orders"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => match result {
                ToolCallResult::Ok { value } => {
                    assert_eq!(value["rows"][0]["email"], "[REDACTED]");
                    assert_eq!(value["rows"][0]["id"], 1);
                }
                other => panic!("unexpected result: {other:?}"),
            },
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.denied, 0);
    }

    #[test]
    fn chio_yaml_content_review_guard_drives_session_runtime_path() {
        let policy = policy::parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - slack_send_message
  content_review:
    enabled: true
    default_rules:
      banned_words:
        - "classified"
"#,
        )
        .unwrap();
        let default_capabilities = policy::build_runtime_default_capabilities(&policy).unwrap();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "slack_send_message",
            "*",
            &serde_json::json!({"text": "classified incident details"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-content-review".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "slack_send_message".to_string(),
            params: Box::new(serde_json::json!({"text": "classified incident details"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chio_yaml_azure_content_safety_guard_drives_session_runtime_path() {
        if !loopback_bind_available() {
            eprintln!("skipping Azure content safety session runtime test: loopback bind denied");
            return;
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/contentsafety/text:analyze"))
            .and(query_param("api-version", "2023-10-01"))
            .and(header("Ocp-Apim-Subscription-Key", "azure-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "categoriesAnalysis": [
                    {"category": "Violence", "severity": 6}
                ]
            })))
            .mount(&server)
            .await;

        let policy = policy::parse_policy(&format!(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - slack_send_message
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "{endpoint}"
      api_key: "azure-key"
      severity_threshold: 4
      tool_patterns:
        - slack_*
"#,
            endpoint = server.uri()
        ))
        .unwrap();
        let default_capabilities = policy::build_runtime_default_capabilities(&policy).unwrap();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "slack_send_message",
            "*",
            &serde_json::json!({"text": "violent escalation details"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-azure-content-safety".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "slack_send_message".to_string(),
            params: Box::new(serde_json::json!({"text": "violent escalation details"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chio_yaml_safe_browsing_guard_drives_session_runtime_path() {
        if !loopback_bind_available() {
            eprintln!("skipping Safe Browsing session runtime test: loopback bind denied");
            return;
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/threatMatches:find"))
            .and(query_param("key", "sb-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "matches": [
                    {
                        "threatType": "MALWARE",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {"url": "https://malicious.example/bad"}
                    }
                ]
            })))
            .mount(&server)
            .await;

        let policy = policy::parse_policy(&format!(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - fetch_url
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "{base_url}"
      tool_patterns:
        - fetch_url
"#,
            base_url = server.uri()
        ))
        .unwrap();
        let default_capabilities = policy::build_runtime_default_capabilities(&policy).unwrap();

        let kp = Keypair::generate();
        let mut kernel = build_kernel(load_test_policy_runtime(&policy), &kp);
        kernel.register_tool_server(Box::new(StubToolServer {
            id: "*".to_string(),
        }));

        let agent_kp = Keypair::generate();
        let caps =
            issue_default_capabilities(&kernel, &agent_kp.public_key(), &default_capabilities)
                .unwrap();
        let agent_id = agent_kp.public_key().to_hex();
        let session_id = open_ready_session(&mut kernel, &agent_id, caps.clone());

        let cap = select_capability_for_request(
            &caps,
            "fetch_url",
            "*",
            &serde_json::json!({"url": "https://malicious.example/bad"}),
        )
        .unwrap();

        let message = AgentMessage::ToolCallRequest {
            id: "req-safe-browsing".to_string(),
            capability_token: Box::new(cap),
            server_id: "*".to_string(),
            tool: "fetch_url".to_string(),
            params: Box::new(serde_json::json!({"url": "https://malicious.example/bad"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let mut stats = SessionStats::default();
        let response = only_message(handle_agent_message(
            &mut kernel,
            &message,
            &session_id,
            &agent_id,
            &mut stats,
        ));

        match response {
            KernelMessage::ToolCallResponse { result, .. } => {
                assert!(matches!(result, ToolCallResult::Err { .. }));
            }
            _ => panic!("wrong variant"),
        }
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied, 1);
    }
