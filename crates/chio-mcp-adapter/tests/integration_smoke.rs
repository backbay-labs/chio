use std::sync::Mutex;

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig, KernelError, ToolServerConnection};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_adapter::{
    AdapterError, ChioMcpEdge, McpAdapter, McpAdapterConfig, McpEdgeConfig, McpServerCapabilities,
    McpToolInfo, McpToolResult, McpTransport,
};
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

struct LoopbackEdgeState {
    edge: ChioMcpEdge,
    next_id: u64,
}

struct LoopbackEdgeTransport {
    state: Mutex<LoopbackEdgeState>,
}

impl LoopbackEdgeTransport {
    fn new() -> Self {
        let mut edge = make_edge();
        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .expect("initialize loopback edge");
        assert!(initialize.get("error").is_none());
        assert!(edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }))
            .is_none());

        Self {
            state: Mutex::new(LoopbackEdgeState { edge, next_id: 1 }),
        }
    }

    fn request(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        let mut state = self.state.lock().map_err(|_| {
            AdapterError::ConnectionFailed("loopback edge mutex poisoned".to_string())
        })?;
        state.next_id += 1;
        let request_id = state.next_id;
        let response = state
            .edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }))
            .ok_or_else(|| {
                AdapterError::ConnectionFailed(format!(
                    "loopback edge returned no response for {method}"
                ))
            })?;

        if let Some(error) = response.get("error").filter(|value| !value.is_null()) {
            return Err(AdapterError::McpError {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(-32000),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown loopback edge error")
                    .to_string(),
                data: error.get("data").cloned(),
            });
        }

        Ok(response["result"].clone())
    }
}

impl McpTransport for LoopbackEdgeTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        McpServerCapabilities::default()
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        let result = self.request("tools/list", json!({}))?;
        serde_json::from_value(result["tools"].clone())
            .map_err(|error| AdapterError::ParseError(error.to_string()))
    }

    fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<McpToolResult, AdapterError> {
        let result = self.request(
            "tools/call",
            json!({
                "name": tool_name,
                "arguments": arguments
            }),
        )?;
        serde_json::from_value(result).map_err(|error| AdapterError::ParseError(error.to_string()))
    }
}

#[test]
fn adapter_generates_manifest_and_invokes_through_real_mcp_jsonrpc() {
    let manifest_key = Keypair::generate();
    let adapter = McpAdapter::new(
        McpAdapterConfig {
            server_id: "loopback.edge".to_string(),
            server_name: "Loopback Edge".to_string(),
            server_version: "0.1.0".to_string(),
            public_key: manifest_key.public_key().to_hex(),
        },
        Box::new(LoopbackEdgeTransport::new()),
    );

    let manifest = adapter.generate_manifest().expect("generate manifest");
    assert_eq!(manifest.tools.len(), 1);
    assert_eq!(manifest.tools[0].name, "echo_json");
    assert!(!manifest.tools[0].has_side_effects);

    let result = adapter
        .invoke("echo_json", json!({ "city": "Boston" }))
        .expect("invoke tool");
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["temperature"], 22.5);
}
