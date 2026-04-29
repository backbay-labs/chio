#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig, KernelError, ToolServerConnection};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig};
use serde_json::{json, Value};

struct EchoServer;

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo_json".to_string()]
    }

    fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "temperature": 22.5,
            "conditions": "Partly cloudy",
        }))
    }
}

fn make_edge() -> ChioMcpEdge {
    let authority = Keypair::generate();
    let config = KernelConfig {
        keypair: authority.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer));

    let agent = Keypair::generate();
    let capabilities = vec![kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo_json".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .expect("issue capability")];
    let manifest_key = Keypair::generate();

    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "srv".to_string(),
            name: "Echo Server".to_string(),
            description: Some("loopback echo server".to_string()),
            version: "0.1.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo_json".to_string(),
                description: "Echo structured weather data".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "temperature": { "type": "number" },
                        "conditions": { "type": "string" }
                    }
                })),
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: manifest_key.public_key().to_hex(),
        }],
    )
    .expect("create MCP edge")
}

#[test]
fn edge_handles_initialize_list_and_call_round_trip() {
    let mut edge = make_edge();

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .expect("initialize response");
    assert!(initialize.get("error").is_none());

    assert!(edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))
        .is_none());

    let listed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .expect("tools/list response");
    assert_eq!(listed["result"]["tools"][0]["name"], "echo_json");
    assert_eq!(
        listed["result"]["tools"][0]["inputSchema"]["type"],
        "object"
    );

    let called = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": { "city": "Boston" }
            }
        }))
        .expect("tools/call response");
    assert_eq!(called["result"]["isError"], false);
    assert_eq!(called["result"]["structuredContent"]["temperature"], 22.5);
    assert!(called["result"]["content"][0]["text"]
        .as_str()
        .expect("text content")
        .contains("temperature"));
}
