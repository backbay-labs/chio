use std::error::Error;
use std::io::{self, BufRead, Write};

use chio_a2a_edge::{A2aEdgeConfig, A2aKernelExecutionContext, ChioA2aEdge};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream,
    ToolServerConnection, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

const SERVER_ID: &str = "hello-a2a-srv";
const TOOL_NAME: &str = "hello_task";

pub type HelloA2aResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

struct HelloStreamServer;

#[async_trait::async_trait]
impl ToolServerConnection for HelloStreamServer {
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
        Ok(json!({"message": "hello from a2a", "arguments": arguments}))
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
        let text = arguments
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("world");
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({
                        "type": "text",
                        "text": format!("hello from a2a, {text}")
                    }),
                },
                ToolCallChunk {
                    data: json!({
                        "content": [{
                            "type": "text",
                            "text": "stream complete"
                        }]
                    }),
                },
            ],
        })))
    }
}

pub struct HelloA2aDemoState {
    pub edge: ChioA2aEdge,
    pub kernel: ChioKernel,
    pub execution: A2aKernelExecutionContext,
}

fn kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "hello-a2a-policy".to_string(),
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
        name: "Hello A2A Server".to_string(),
        description: Some("A tiny receipt-bearing A2A hello surface".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: TOOL_NAME.to_string(),
            description: "Return a collated greeting".to_string(),
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
        public_key: "hello-a2a-manifest".to_string(),
    }
}

pub fn build_demo_state() -> HelloA2aResult<HelloA2aDemoState> {
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(HelloStreamServer));

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

    let execution = A2aKernelExecutionContext {
        capability,
        agent_id: agent.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };

    Ok(HelloA2aDemoState {
        edge: ChioA2aEdge::new(A2aEdgeConfig::default(), vec![demo_manifest()]).map_err(
            |error| -> Box<dyn Error + Send + Sync> { format!("create edge: {error}").into() },
        )?,
        kernel,
        execution,
    })
}

pub fn agent_card_value() -> HelloA2aResult<Value> {
    let state = build_demo_state()?;
    serde_json::to_value(state.edge.agent_card()).map_err(Into::into)
}

pub fn write_agent_card<W: Write>(mut writer: W) -> HelloA2aResult<()> {
    serde_json::to_writer_pretty(&mut writer, &agent_card_value()?)?;
    writeln!(&mut writer)?;
    Ok(())
}

pub fn serve_stdio() -> HelloA2aResult<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_reader(stdin.lock(), stdout.lock())
}

pub fn serve_reader<R, W>(reader: R, mut writer: W) -> HelloA2aResult<()>
where
    R: BufRead,
    W: Write,
{
    let mut state = build_demo_state()?;

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

pub fn parse_mode_arg(args: impl IntoIterator<Item = String>) -> HelloA2aResult<String> {
    let mut args = args.into_iter();
    let _program = args.next();
    let mode = args.next().unwrap_or_else(|| "serve".to_string());
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {extra}").into());
    }
    Ok(mode)
}

pub fn run_mode(mode: &str) -> HelloA2aResult<()> {
    match mode {
        "serve" => serve_stdio(),
        "agent-card" => write_agent_card(io::stdout()),
        other => Err(format!("unknown mode: {other}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        agent_card_value, build_demo_state, parse_mode_arg, serve_reader, HelloA2aResult,
        HelloStreamServer, TOOL_NAME,
    };
    use chio_kernel::{KernelError, ToolServerConnection};
    use serde_json::{json, Value};
    use std::io::Cursor;

    fn send_message_frame(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "world"}]
                }
            }
        })
    }

    fn stream_message_frame(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "world"}]
                }
            }
        })
    }

    #[test]
    fn parse_mode_arg_rejects_extra_positionals() {
        let result = parse_mode_arg([
            "hello-a2a".to_string(),
            "agent-card".to_string(),
            "extra".to_string(),
        ]);

        assert!(result.is_err(), "extra positional args should be rejected");
    }

    #[test]
    fn agent_card_advertises_hello_task() -> HelloA2aResult<()> {
        let card = agent_card_value()?;

        assert_eq!(card["skills"][0]["id"], TOOL_NAME);
        assert_eq!(card["capabilities"]["streaming"], true);
        assert_eq!(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC");
        Ok(())
    }

    #[test]
    fn direct_jsonrpc_send_stream_and_task_get_carry_receipts() -> HelloA2aResult<()> {
        let mut state = build_demo_state()?;

        let send_response =
            state
                .edge
                .handle_jsonrpc(send_message_frame(1), &state.kernel, &state.execution);
        assert_eq!(send_response["result"]["status"], "completed");
        assert_eq!(
            send_response["result"]["metadata"]["chio"]["authorityPath"],
            "cross_protocol_orchestrator"
        );
        assert!(send_response["result"]["metadata"]["chio"]["receiptId"]
            .as_str()
            .is_some_and(|receipt_id| !receipt_id.is_empty()));

        let stream_response =
            state
                .edge
                .handle_jsonrpc(stream_message_frame(2), &state.kernel, &state.execution);
        assert_eq!(stream_response["result"]["status"], "working");
        assert_eq!(
            stream_response["result"]["metadata"]["chio"]["receiptPending"],
            true
        );
        let task_id = stream_response["result"]["id"]
            .as_str()
            .ok_or_else(|| KernelError::ToolServerError("missing stream task id".to_string()))?;

        let task_response = state.edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "task/get",
                "params": { "taskId": task_id }
            }),
            &state.kernel,
            &state.execution,
        );
        assert_eq!(task_response["result"]["status"], "completed");
        assert!(task_response["result"]["metadata"]["chio"]["receiptId"]
            .as_str()
            .is_some_and(|receipt_id| !receipt_id.is_empty()));
        Ok(())
    }

    #[test]
    fn stdio_reader_writes_one_response_per_request_line() -> HelloA2aResult<()> {
        let input = [
            send_message_frame(1).to_string(),
            stream_message_frame(2).to_string(),
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
        assert_eq!(responses[0]["result"]["status"], "completed");
        assert_eq!(responses[1]["result"]["status"], "working");
        Ok(())
    }

    #[tokio::test]
    async fn hello_server_rejects_unknown_tool_names() -> HelloA2aResult<()> {
        let blocking_error = match HelloStreamServer
            .invoke("not_hello_task", json!({}), None)
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
            matches!(blocking_error, KernelError::ToolNotRegistered(tool) if tool == "not_hello_task")
        );

        let streaming_error = match HelloStreamServer
            .invoke_stream("not_hello_task", json!({}), None)
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
            matches!(streaming_error, KernelError::ToolNotRegistered(tool) if tool == "not_hello_task")
        );
        Ok(())
    }
}
