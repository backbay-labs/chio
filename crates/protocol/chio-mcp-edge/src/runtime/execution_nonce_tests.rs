#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ExecutionNonceConfig, InMemoryExecutionNonceStore, KernelConfig, KernelError,
    ToolServerConnection, Verdict,
};
use chio_manifest::{LatencyHint, ToolDefinition};

struct NonceEchoServer;

#[async_trait::async_trait]
impl ToolServerConnection for NonceEchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

fn make_nonce_kernel() -> ChioKernel {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(NonceEchoServer));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    kernel
}

fn issue_nonce_capability(kernel: &ChioKernel, agent: &Keypair) -> Vec<CapabilityToken> {
    vec![issue_nonce_capability_token(kernel, agent)]
}

fn issue_nonce_capability_token(kernel: &ChioKernel, agent: &Keypair) -> CapabilityToken {
    kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "read_file".to_string(),
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
            300,
        )
        .unwrap()
}

fn make_bridge_nonce_request(kernel: &ChioKernel, agent: &Keypair) -> BridgeMcpToolCallRequest {
    BridgeMcpToolCallRequest {
        request_id: "req-mcp-strict-nonce".to_string(),
        capability: issue_nonce_capability_token(kernel, agent),
        server_id: "srv".to_string(),
        tool_name: "read_file".to_string(),
        arguments: json!({}),
        agent_id: agent.public_key().to_hex(),
        execution_nonce: None,
        governed_intent: None,
        model_metadata: None,
        route_selection_metadata: None,
        peer_supports_chio_tool_streaming: false,
    }
}

fn nonce_manifest() -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: "srv".into(),
        name: "Nonce Test Server".into(),
        description: Some("nonce test".into()),
        version: "0.1.0".into(),
        tools: vec![ToolDefinition {
            name: "read_file".into(),
            description: "Read a file".into(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: Some(LatencyHint::Fast),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: Keypair::from_seed(&[7u8; 32]).public_key().to_hex(),
    }
}

#[test]
fn execute_bridge_mcp_tool_call_presents_execution_nonce_in_strict_mode() {
    let kernel = make_nonce_kernel();
    let agent = Keypair::generate();
    let mut request = make_bridge_nonce_request(&kernel, &agent);

    let preflight = execute_bridge_mcp_tool_call(&kernel, request.clone()).unwrap();
    assert_eq!(preflight.response.verdict, Verdict::Allow);
    assert!(
        preflight.response.output.is_none(),
        "strict MCP preflight must not execute the target tool"
    );
    assert!(
        preflight.mcp_result["_meta"]["chioExecutionNonce"].is_object(),
        "strict MCP preflight must surface the nonce in MCP result metadata"
    );
    let nonce = *preflight
        .response
        .execution_nonce
        .expect("strict MCP preflight must return an execution nonce");

    request.execution_nonce = Some(nonce);
    let allowed = execute_bridge_mcp_tool_call(&kernel, request.clone()).unwrap();
    assert_eq!(allowed.response.verdict, Verdict::Allow);
    assert!(allowed.response.output.is_some());
    assert!(allowed.response.execution_nonce.is_none());

    let replay = execute_bridge_mcp_tool_call(&kernel, request).unwrap();
    assert_eq!(replay.response.verdict, Verdict::Deny);
    assert!(
        replay
            .response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("execution nonce")),
        "expected replay denial, got {:?}",
        replay.response.reason
    );
}

#[test]
fn tools_call_round_trips_execution_nonce_through_meta() {
    let kernel = make_nonce_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_nonce_capability(&kernel, &agent);
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size: 10,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![nonce_manifest()],
    )
    .unwrap();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let preflight = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();
    assert_eq!(preflight["result"]["isError"], true);
    let nonce = preflight["result"]["_meta"]["chioExecutionNonce"].clone();
    assert!(
        nonce.is_object(),
        "preflight nonce metadata missing: {preflight}"
    );

    let allowed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "chioExecutionNonce": nonce.clone()
                }
            }
        }))
        .unwrap();
    assert_eq!(allowed["result"]["isError"], false);

    let replay = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "executionNonce": nonce
                }
            }
        }))
        .unwrap();
    assert_eq!(replay["result"]["isError"], true);
    assert!(
        replay["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("execution nonce")),
        "expected replay denial, got {replay}"
    );
}
