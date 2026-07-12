use std::error::Error;
use std::io::{self, BufRead, Write};

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, ToolCallOutput, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig};
use serde_json::{json, Value};

const SERVER_ID: &str = "hello-mcp-srv";
const TOOL_NAME: &str = "hello_tool";

pub type HelloMcpResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

struct HelloServer;

#[async_trait::async_trait]
impl ToolServerConnection for HelloServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        if tool_name != TOOL_NAME {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        }
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

pub struct HelloMcpDemoState {
    kernel: ChioKernel,
    capability: CapabilityToken,
    agent_id: String,
    manifest: ToolManifest,
}

impl HelloMcpDemoState {
    fn into_edge_parts(self) -> (ChioKernel, CapabilityToken, String, ToolManifest) {
        (self.kernel, self.capability, self.agent_id, self.manifest)
    }

    fn into_bridge_parts(self) -> (ChioKernel, CapabilityToken, String) {
        (self.kernel, self.capability, self.agent_id)
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
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

pub fn demo_manifest() -> ToolManifest {
    let manifest_key = Keypair::generate();
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: SERVER_ID.to_string(),
        name: "Hello MCP Server".to_string(),
        description: Some("Minimal governed MCP hello tool".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: TOOL_NAME.to_string(),
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

pub fn build_demo_state() -> HelloMcpResult<HelloMcpDemoState> {
    let authority = Keypair::generate();
    let mut kernel = ChioKernel::new(kernel_config(authority.clone()));
    kernel.register_tool_server(Box::new(HelloServer));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.to_string(),
                    tool_name: TOOL_NAME.to_string(),
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
        .map_err(|error| -> Box<dyn Error + Send + Sync> {
            format!("issue capability: {error}").into()
        })?;

    Ok(HelloMcpDemoState {
        kernel,
        capability,
        agent_id: agent.public_key().to_hex(),
        manifest: demo_manifest(),
    })
}

pub fn make_edge() -> HelloMcpResult<ChioMcpEdge> {
    let (kernel, capability, agent_id, manifest) = build_demo_state()?.into_edge_parts();
    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent_id,
        vec![capability],
        vec![manifest],
    )
    .map_err(|error| -> Box<dyn Error + Send + Sync> {
        format!("create hello-mcp edge: {error}").into()
    })
}

pub fn serve_stdio() -> HelloMcpResult<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_reader(stdin.lock(), stdout.lock())
}

pub fn serve_reader<R, W>(reader: R, mut writer: W) -> HelloMcpResult<()>
where
    R: BufRead,
    W: Write,
{
    let mut edge = make_edge()?;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = serde_json::from_str(&line)?;
        if let Some(response) = edge.handle_jsonrpc(message) {
            serde_json::to_writer(&mut writer, &response)?;
            writeln!(&mut writer)?;
            writer.flush()?;
        }
    }

    Ok(())
}

pub fn bridge_call_value() -> HelloMcpResult<Value> {
    let (kernel, capability, agent_id) = build_demo_state()?.into_bridge_parts();
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &ToolCallRequest {
            request_id: "hello-mcp-bridge".to_string(),
            capability,
            tool_name: TOOL_NAME.to_string(),
            server_id: SERVER_ID.to_string(),
            agent_id,
            arguments: json!({"name": "world"}),
            dpop_proof: None,
            execution_nonce: None,
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

    Ok(json!({
        "receipt_id": response.receipt.id,
        "decision": response.receipt.decision,
        "output": output,
    }))
}

pub fn write_bridge_call<W: Write>(mut writer: W) -> HelloMcpResult<()> {
    serde_json::to_writer_pretty(&mut writer, &bridge_call_value()?)?;
    writeln!(&mut writer)?;
    Ok(())
}

pub fn parse_mode_arg(args: impl IntoIterator<Item = String>) -> HelloMcpResult<String> {
    let mut args = args.into_iter();
    let _program = args.next();
    let mode = args.next().unwrap_or_else(|| "serve".to_string());
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {extra}").into());
    }
    Ok(mode)
}

pub fn run_mode(mode: &str) -> HelloMcpResult<()> {
    match mode {
        "serve" => serve_stdio(),
        "bridge-call" => write_bridge_call(io::stdout()),
        other => Err(format!("unknown mode: {other}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bridge_call_value, make_edge, parse_mode_arg, serve_reader, HelloMcpResult, HelloServer,
        TOOL_NAME,
    };
    use chio_kernel::{KernelError, ToolServerConnection};
    use serde_json::{json, Value};
    use std::io::Cursor;

    fn initialize_edge(edge: &mut chio_mcp_edge::ChioMcpEdge) -> HelloMcpResult<()> {
        let initialize = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .ok_or_else(|| {
                KernelError::ToolServerError("missing initialize response".to_string())
            })?;
        assert!(initialize.get("error").is_none());

        assert!(edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }))
            .is_none());
        Ok(())
    }

    #[test]
    fn parse_mode_arg_rejects_extra_positionals() {
        let result = parse_mode_arg([
            "hello-mcp".to_string(),
            "bridge-call".to_string(),
            "extra".to_string(),
        ]);

        assert!(result.is_err(), "extra positional args should be rejected");
    }

    #[test]
    fn mcp_lifecycle_direct_jsonrpc_lists_and_calls_tool() -> HelloMcpResult<()> {
        let mut edge = make_edge()?;
        initialize_edge(&mut edge)?;

        let listed = edge
            .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }))
            .ok_or_else(|| {
                KernelError::ToolServerError("missing tools/list response".to_string())
            })?;
        assert_eq!(listed["result"]["tools"][0]["name"], TOOL_NAME);
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
                    "name": TOOL_NAME,
                    "arguments": { "name": "world" }
                }
            }))
            .ok_or_else(|| {
                KernelError::ToolServerError("missing tools/call response".to_string())
            })?;
        assert_eq!(called["result"]["isError"], false);
        assert_eq!(
            called["result"]["structuredContent"]["message"],
            "hello from mcp, world"
        );
        Ok(())
    }

    #[test]
    fn stdio_reader_ignores_notifications_and_writes_request_responses() -> HelloMcpResult<()> {
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}).to_string(),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string(),
        ]
        .join("\n");
        let mut output = Vec::new();

        serve_reader(Cursor::new(format!("{input}\n")), &mut output)?;

        let lines = String::from_utf8(output)?;
        let responses = lines
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["tools"][0]["name"], TOOL_NAME);
        Ok(())
    }

    #[test]
    fn bridge_call_value_exposes_receipt_and_output() -> HelloMcpResult<()> {
        let bridge = bridge_call_value()?;

        assert!(bridge["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
        assert_eq!(bridge["decision"]["verdict"], "allow");
        assert_eq!(bridge["output"]["message"], "hello from mcp, world");
        Ok(())
    }

    #[tokio::test]
    async fn hello_server_rejects_unknown_tool_names() -> HelloMcpResult<()> {
        let error = match HelloServer.invoke("not_hello_tool", json!({}), None).await {
            Ok(value) => {
                return Err(KernelError::ToolServerError(format!(
                    "unknown tool must fail closed, got {value}"
                ))
                .into());
            }
            Err(error) => error,
        };

        assert!(matches!(error, KernelError::ToolNotRegistered(tool) if tool == "not_hello_tool"));
        Ok(())
    }
}
