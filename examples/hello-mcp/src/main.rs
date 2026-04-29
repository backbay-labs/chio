use std::error::Error;
use std::io::{self, BufRead, Write};

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, ToolCallOutput, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig};
use serde_json::{json, Value};

struct HelloServer;

impl ToolServerConnection for HelloServer {
    fn server_id(&self) -> &str {
        "hello-mcp-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["hello_tool".to_string()]
    }

    fn invoke(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("world");
        Ok(json!({
            "message": format!("hello from mcp, {name}"),
            "arguments": arguments,
        }))
    }
}

fn kernel_config(authority: Keypair) -> KernelConfig {
    KernelConfig {
        keypair: authority,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "hello-mcp-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    }
}

fn demo_manifest() -> ToolManifest {
    let manifest_key = Keypair::generate();
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "hello-mcp-srv".to_string(),
        name: "Hello MCP Server".to_string(),
        description: Some("Minimal governed MCP hello tool".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: "hello_tool".to_string(),
            description: "Return a greeting payload".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                }
            }),
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "arguments": {"type": "object"}
                }
            })),
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_key.public_key().to_hex(),
    }
}

fn build_demo_state() -> (
    ChioKernel,
    chio_core::capability::CapabilityToken,
    String,
    ToolManifest,
) {
    let authority = Keypair::generate();
    let mut kernel = ChioKernel::new(kernel_config(authority.clone()));
    kernel.register_tool_server(Box::new(HelloServer));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "hello-mcp-srv".to_string(),
                    tool_name: "hello_tool".to_string(),
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
        .expect("issue capability");

    (
        kernel,
        capability,
        agent.public_key().to_hex(),
        demo_manifest(),
    )
}

fn make_edge() -> ChioMcpEdge {
    let (kernel, capability, agent_id, manifest) = build_demo_state();
    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent_id,
        vec![capability],
        vec![manifest],
    )
    .expect("create hello-mcp edge")
}

fn serve() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut edge = make_edge();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = serde_json::from_str(&line)?;
        if let Some(response) = edge.handle_jsonrpc(message) {
            serde_json::to_writer(&mut stdout, &response)?;
            writeln!(&mut stdout)?;
            stdout.flush()?;
        }
    }

    Ok(())
}

fn bridge_call() -> Result<(), Box<dyn Error>> {
    let (kernel, capability, agent_id, _manifest) = build_demo_state();
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &ToolCallRequest {
            request_id: "hello-mcp-bridge".to_string(),
            capability,
            tool_name: "hello_tool".to_string(),
            server_id: "hello-mcp-srv".to_string(),
            agent_id,
            arguments: json!({"name": "world"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        },
        None,
    )?;

    let output = match response.output {
        Some(ToolCallOutput::Value(value)) => value,
        Some(ToolCallOutput::Stream(stream)) => json!({
            "chunks": stream
                .chunks
                .into_iter()
                .map(|chunk| chunk.data)
                .collect::<Vec<_>>(),
        }),
        None => Value::Null,
    };

    serde_json::to_writer_pretty(
        io::stdout(),
        &json!({
            "receipt_id": response.receipt.id,
            "decision": response.receipt.decision,
            "output": output,
        }),
    )?;
    writeln!(io::stdout())?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "serve".to_string());
    match mode.as_str() {
        "serve" => serve(),
        "bridge-call" => bridge_call(),
        other => Err(format!("unknown mode: {other}").into()),
    }
}
