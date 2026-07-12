use std::error::Error;
use std::io::{self, BufRead, Write};

use chio_acp_edge::{AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream,
    ToolServerConnection, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

const SERVER_ID: &str = "hello-acp-srv";
const TOOL_NAME: &str = "hello_tool";

pub type HelloAcpResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

struct HelloToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for HelloToolServer {
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
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        if tool_name != TOOL_NAME {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        }
        Ok(json!({
            "message": "hello from acp",
            "arguments": arguments,
        }))
    }

    async fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        if tool_name != TOOL_NAME {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        }
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("world");
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({"content": [{"type": "text", "text": format!("hello from acp, {name}")}]}),
                },
                ToolCallChunk {
                    data: json!({"content": [{"type": "text", "text": "resume complete"}]}),
                },
            ],
        })))
    }
}

pub struct HelloAcpDemoState {
    pub edge: ChioAcpEdge,
    pub kernel: ChioKernel,
    pub execution: AcpKernelExecutionContext,
}

fn kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "hello-acp-policy".to_string(),
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
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: SERVER_ID.to_string(),
        name: "Hello ACP Server".to_string(),
        description: Some("A tiny receipt-bearing ACP hello surface".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: TOOL_NAME.to_string(),
            description: "Return a greeting payload".to_string(),
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
        public_key: "hello-acp-manifest".to_string(),
    }
}

pub fn build_demo_state() -> HelloAcpResult<HelloAcpDemoState> {
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(HelloToolServer));

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

    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: agent.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };

    Ok(HelloAcpDemoState {
        edge: ChioAcpEdge::new(AcpEdgeConfig::default(), vec![demo_manifest()]).map_err(
            |error| -> Box<dyn Error + Send + Sync> { format!("create edge: {error}").into() },
        )?,
        kernel,
        execution,
    })
}

pub fn serve_stdio() -> HelloAcpResult<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_reader(stdin.lock(), stdout.lock())
}

pub fn serve_reader<R, W>(reader: R, mut writer: W) -> HelloAcpResult<()>
where
    R: BufRead,
    W: Write,
{
    let state = build_demo_state()?;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = serde_json::from_str(&line)?;
        let response = state
            .edge
            .handle_jsonrpc(message, &state.kernel, &state.execution);
        if let Some(response) = response.as_value() {
            serde_json::to_writer(&mut writer, response)?;
            writeln!(&mut writer)?;
            writer.flush()?;
        }
    }

    Ok(())
}

pub fn parse_mode_arg(args: impl IntoIterator<Item = String>) -> HelloAcpResult<String> {
    let mut args = args.into_iter();
    let _program = args.next();
    let mode = args.next().unwrap_or_else(|| "serve".to_string());
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {extra}").into());
    }
    Ok(mode)
}

pub fn run_mode(mode: &str) -> HelloAcpResult<()> {
    match mode {
        "serve" => serve_stdio(),
        other => Err(format!("unknown mode: {other}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_demo_state, parse_mode_arg, serve_reader, HelloAcpResult, HelloToolServer, TOOL_NAME,
    };
    use chio_kernel::{KernelError, ToolServerConnection};
    use serde_json::{json, Value};
    use std::io::Cursor;

    fn list_capabilities_frame(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/list_capabilities",
            "params": {}
        })
    }

    fn invoke_frame(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tool/invoke",
            "params": {
                "capabilityId": TOOL_NAME,
                "arguments": {"name": "world"}
            }
        })
    }

    fn stream_frame(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tool/stream",
            "params": {
                "capabilityId": TOOL_NAME,
                "arguments": {"name": "world"}
            }
        })
    }

    #[test]
    fn parse_mode_arg_rejects_extra_positionals() {
        let result = parse_mode_arg([
            "hello-acp".to_string(),
            "serve".to_string(),
            "extra".to_string(),
        ]);

        assert!(result.is_err(), "extra positional args should be rejected");
    }

    #[test]
    fn list_capabilities_advertises_hello_tool() -> HelloAcpResult<()> {
        let state = build_demo_state()?;

        let response =
            state
                .edge
                .handle_jsonrpc(list_capabilities_frame(1), &state.kernel, &state.execution);

        assert_eq!(response["result"]["capabilities"][0]["id"], TOOL_NAME);
        assert_eq!(
            response["result"]["capabilities"][0]["bridgeFidelity"]["kind"],
            "adapted"
        );
        Ok(())
    }

    #[test]
    fn direct_jsonrpc_invoke_stream_and_resume_carry_receipts() -> HelloAcpResult<()> {
        let state = build_demo_state()?;

        let invoke_response =
            state
                .edge
                .handle_jsonrpc(invoke_frame(2), &state.kernel, &state.execution);
        assert_eq!(invoke_response["result"]["success"], true);
        assert_eq!(
            invoke_response["result"]["metadata"]["chio"]["authorityPath"],
            "cross_protocol_orchestrator"
        );
        assert!(invoke_response["result"]["metadata"]["chio"]["receiptId"]
            .as_str()
            .is_some_and(|receipt_id| !receipt_id.is_empty()));

        let stream_response =
            state
                .edge
                .handle_jsonrpc(stream_frame(3), &state.kernel, &state.execution);
        assert_eq!(stream_response["result"]["task"]["status"], "working");
        assert_eq!(
            stream_response["result"]["task"]["metadata"]["chio"]["receiptPending"],
            true
        );
        let task_id = stream_response["result"]["task"]["id"]
            .as_str()
            .ok_or_else(|| KernelError::ToolServerError("missing stream task id".to_string()))?;

        let resume_response = state.edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tool/resume",
                "params": {"taskId": task_id}
            }),
            &state.kernel,
            &state.execution,
        );
        assert_eq!(resume_response["result"]["task"]["status"], "completed");
        assert!(
            resume_response["result"]["result"]["metadata"]["chio"]["receiptId"]
                .as_str()
                .is_some_and(|receipt_id| !receipt_id.is_empty())
        );
        Ok(())
    }

    #[test]
    fn stdio_reader_writes_one_response_per_request_line() -> HelloAcpResult<()> {
        let input = [
            list_capabilities_frame(1).to_string(),
            invoke_frame(2).to_string(),
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
        assert_eq!(responses[0]["result"]["capabilities"][0]["id"], TOOL_NAME);
        assert_eq!(responses[1]["result"]["success"], true);
        Ok(())
    }

    #[tokio::test]
    async fn hello_server_rejects_unknown_tool_names() -> HelloAcpResult<()> {
        let blocking_error = match HelloToolServer
            .invoke("not_hello_tool", json!({}), None)
            .await
        {
            Ok(value) => {
                return Err(KernelError::ToolServerError(format!(
                    "unknown blocking tool must fail closed, got {value}"
                ))
                .into());
            }
            Err(error) => error,
        };
        assert!(
            matches!(blocking_error, KernelError::ToolNotRegistered(tool) if tool == "not_hello_tool")
        );

        let streaming_error = match HelloToolServer
            .invoke_stream("not_hello_tool", json!({}), None)
            .await
        {
            Ok(value) => {
                return Err(KernelError::ToolServerError(format!(
                    "unknown streaming tool must fail closed, got {value:?}"
                ))
                .into());
            }
            Err(error) => error,
        };
        assert!(
            matches!(streaming_error, KernelError::ToolNotRegistered(tool) if tool == "not_hello_tool")
        );
        Ok(())
    }
}
