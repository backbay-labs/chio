//! Stdio-based MCP transport.
//!
//! Spawns an MCP server as a subprocess and communicates via newline-delimited
//! JSON-RPC over stdin/stdout. This is the standard MCP transport mechanism.

mod handlers;
mod nested_flow;
mod stdio;
mod utils;

pub use stdio::StdioMcpTransport;

#[cfg(test)]
use std::io::BufReader;
#[cfg(test)]
use std::process::Command;

#[cfg(test)]
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult,
};
#[cfg(test)]
use chio_kernel::{KernelError, NestedFlowBridge};
#[cfg(test)]
use serde_json::json;

#[cfg(test)]
use crate::edge::{AdapterError, McpTransport};
#[cfg(test)]
use nested_flow::{NestedFlowTaskRuntime, RequestedTask};
#[cfg(test)]
use utils::{
    proxy_client_capabilities, read_line, remove_chio_auth_env, send_line, CHIO_AUTH_ENV_VARS,
    RELATED_TASK_META_KEY,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::framing::MAX_STDIO_MCP_FRAME_BYTES;
    use chio_core::session::ElicitationAction;
    use chio_core::RequestId;

    fn command_env(command: &Command, key: &str) -> Option<Option<String>> {
        command.get_envs().find_map(|(name, value)| {
            if name == std::ffi::OsStr::new(key) {
                Some(value.map(|value| value.to_string_lossy().into_owned()))
            } else {
                None
            }
        })
    }

    struct MockNestedFlowBridge;

    impl NestedFlowBridge for MockNestedFlowBridge {
        fn parent_request_id(&self) -> &RequestId {
            static REQUEST_ID: std::sync::OnceLock<RequestId> = std::sync::OnceLock::new();
            REQUEST_ID.get_or_init(|| RequestId::new("parent-1"))
        }

        fn list_roots(&mut self) -> Result<Vec<chio_core::RootDefinition>, KernelError> {
            unreachable!("not used in these tests")
        }

        fn create_message(
            &mut self,
            _operation: CreateMessageOperation,
        ) -> Result<CreateMessageResult, KernelError> {
            Ok(CreateMessageResult {
                role: "assistant".to_string(),
                content: json!({
                    "type": "text",
                    "text": "sampled"
                }),
                model: "gpt-test".to_string(),
                stop_reason: Some("end_turn".to_string()),
            })
        }

        fn create_elicitation(
            &mut self,
            _operation: CreateElicitationOperation,
        ) -> Result<CreateElicitationResult, KernelError> {
            Ok(CreateElicitationResult {
                action: ElicitationAction::Accept,
                content: None,
            })
        }

        fn notify_elicitation_completed(
            &mut self,
            _elicitation_id: &str,
        ) -> Result<(), KernelError> {
            Ok(())
        }

        fn notify_resource_updated(&mut self, _uri: &str) -> Result<(), KernelError> {
            Ok(())
        }

        fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
            Ok(())
        }
    }

    #[test]
    fn send_line_produces_newline_delimited_json() {
        let mut buf: Vec<u8> = Vec::new();
        let value = json!({"jsonrpc": "2.0", "id": 1, "method": "test", "params": {}});
        send_line(&mut buf, &value).unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'), "must end with newline");

        // The line before the newline must be valid JSON.
        let trimmed = output.trim_end();
        let parsed: serde_json::Value = serde_json::from_str(trimmed).unwrap();
        assert_eq!(parsed["method"], "test");
    }

    #[test]
    fn stdio_transport_child_env_removes_chio_auth_tokens() {
        let mut command = Command::new("mock-mcp-server");
        for key in CHIO_AUTH_ENV_VARS {
            command.env(key, format!("parent-{key}"));
        }

        remove_chio_auth_env(&mut command);

        for key in CHIO_AUTH_ENV_VARS {
            assert_eq!(command_env(&command, key), Some(None));
        }
    }

    #[test]
    fn read_line_parses_json() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
        let mut reader = BufReader::new(&input[..]);
        let value = read_line(&mut reader).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ok"], true);
    }

    #[test]
    fn read_line_skips_blank_lines_before_json_frame() {
        let input = b"\n  \r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
        let mut reader = BufReader::new(&input[..]);
        let value = read_line(&mut reader).unwrap();
        assert_eq!(value["id"], 1);
        assert_eq!(value["result"]["ok"], true);
    }

    #[test]
    fn read_line_eof_returns_error() {
        let input = b"";
        let mut reader = BufReader::new(&input[..]);
        let err = read_line(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConnectionFailed(_)),
            "expected ConnectionFailed, got: {err}"
        );
    }

    #[test]
    fn read_line_invalid_json_returns_error() {
        let input = b"not json\n";
        let mut reader = BufReader::new(&input[..]);
        let err = read_line(&mut reader).unwrap_err();
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError, got: {err}"
        );
    }

    #[test]
    fn read_line_rejects_oversized_frame() {
        let input = format!("{}\n", "x".repeat(MAX_STDIO_MCP_FRAME_BYTES + 1));
        let mut reader = BufReader::new(input.as_bytes());
        let err = match read_line(&mut reader) {
            Ok(value) => panic!("oversized frame must fail closed, got: {value}"),
            Err(err) => err,
        };
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError for oversized frame, got: {err}"
        );
    }

    #[test]
    fn read_line_rejects_eof_before_newline_delimiter() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}";
        let mut reader = BufReader::new(&input[..]);
        let err = match read_line(&mut reader) {
            Ok(value) => panic!("unterminated frame must fail closed, got: {value}"),
            Err(err) => err,
        };
        assert!(
            matches!(err, AdapterError::ParseError(_)),
            "expected ParseError for unterminated frame, got: {err}"
        );
    }

    #[test]
    fn proxy_client_capabilities_use_object_valued_mcp_capabilities() {
        let capabilities = proxy_client_capabilities();

        assert_eq!(capabilities["roots"]["listChanged"], true);
        assert_eq!(capabilities["sampling"]["context"], json!({}));
        assert_eq!(capabilities["sampling"]["tools"], json!({}));
        assert!(capabilities["sampling"].get("includeContext").is_none());
        assert_eq!(capabilities["elicitation"]["form"], json!({}));
        assert_eq!(capabilities["elicitation"]["url"], json!({}));
        assert_eq!(capabilities["tasks"]["list"], json!({}));
        assert_eq!(
            capabilities["tasks"]["requests"]["sampling"]["createMessage"],
            json!({})
        );
        assert_eq!(
            capabilities["tasks"]["requests"]["elicitation"]["create"],
            json!({})
        );
    }

    /// Full round-trip test using a mock MCP server script.
    ///
    /// The "server" is a small shell pipeline that reads JSON-RPC requests
    /// from stdin and writes canned responses to stdout.
    #[test]
    fn stdio_transport_with_mock_server() {
        // A small Python script that acts as a minimal MCP server.
        let script = r#"
import sys, json

def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)

    # Handle initialize
    if msg.get("method") == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-server", "version": "0.0.1"}
            }
        })
        continue

    # Handle notifications (no id) -- just ignore
    if "id" not in msg:
        continue

    # Handle tools/list
    if msg.get("method") == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": "startup-roots",
            "method": "roots/list",
            "params": {}
        })
        while True:
            nested = json.loads(sys.stdin.readline())
            if nested.get("id") != "startup-roots" or nested.get("method"):
                continue
            assert nested["result"]["roots"] == []
            break
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echoes input",
                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}
                    }
                ]
            }
        })
        continue

    # Handle tools/call
    if msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"]["arguments"]
        respond({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "content": [{"type": "text", "text": f"echo: {args.get('text', '')}"}],
                "isError": False
            }
        })
        continue

    # Unknown method
    respond({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "error": {"code": -32601, "message": f"unknown method: {msg.get('method')}"}
    })
"#;

        // Write the script to a temp file.
        let dir = std::env::temp_dir().join("chio-mcp-test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let script_path = dir.join("mock_mcp_server.py");
        std::fs::write(&script_path, script).expect("write mock script");

        let transport =
            StdioMcpTransport::spawn("python3", &[script_path.to_str().expect("path to str")])
                .expect("spawn mock server");

        let tools = transport.list_tools().expect("list_tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description.as_deref(), Some("Echoes input"));

        let result = transport
            .call_tool("echo", json!({"text": "hello"}))
            .expect("call_tool");
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0]["type"], "text");
        assert_eq!(result.content[0]["text"], "echo: hello");

        transport.shutdown().expect("shutdown");

        let _ = std::fs::remove_file(&script_path);
    }

    #[test]
    fn background_tick_can_complete_multiple_nested_flow_tasks() {
        let mut runtime = NestedFlowTaskRuntime::default();
        let parent_request_id = RequestId::new("parent-1");
        let task_a = runtime.create_message_task(
            "nested-upstream-1".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_b = runtime.create_message_task(
            "2".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_id_a = task_a["task"]["taskId"].as_str().unwrap().to_string();
        let task_id_b = task_b["task"]["taskId"].as_str().unwrap().to_string();
        assert_eq!(task_a["task"]["ownership"]["workOwner"], "task");
        assert_eq!(
            task_a["task"]["ownership"]["resultStreamOwner"],
            "request_stream"
        );
        assert_eq!(
            task_a["task"]["ownership"]["statusNotificationOwner"],
            "session_notification_stream"
        );
        assert_eq!(task_a["task"]["ownership"]["terminalStateOwner"], "task");
        assert_eq!(task_a["task"]["ownerRequestId"], "nested-upstream-1");
        assert_eq!(task_a["task"]["parentRequestId"], "parent-1");
        assert_eq!(task_b["task"]["ownerRequestId"], "2");
        assert_eq!(task_b["task"]["parentRequestId"], "parent-1");

        let mut bridge = MockNestedFlowBridge;
        let mut writer = Vec::new();
        runtime
            .process_background_tasks(&mut bridge, &mut writer)
            .unwrap();

        assert!(runtime.tasks.get(&task_id_a).unwrap().is_terminal());
        assert!(runtime.tasks.get(&task_id_b).unwrap().is_terminal());

        let output = String::from_utf8(writer).unwrap();
        let status_count = output
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| message["method"] == "notifications/tasks/status")
            .count();
        assert_eq!(status_count, 2);
    }

    #[test]
    fn tasks_result_includes_nested_task_lineage_in_related_task_meta() {
        let mut runtime = NestedFlowTaskRuntime::default();
        let parent_request_id = RequestId::new("parent-1");
        let created = runtime.create_message_task(
            "nested-upstream-7".to_string(),
            parent_request_id.to_string(),
            CreateMessageOperation {
                messages: vec![],
                model_preferences: None,
                system_prompt: None,
                include_context: None,
                temperature: None,
                max_tokens: 32,
                stop_sequences: vec![],
                metadata: None,
                tools: vec![],
                tool_choice: None,
            },
            RequestedTask { ttl: None },
        );
        let task_id = created["task"]["taskId"].as_str().unwrap().to_string();

        let mut bridge = MockNestedFlowBridge;
        let mut writer = Vec::new();
        let response = runtime
            .handle_tasks_result(
                json!(9),
                &json!({ "taskId": task_id }),
                &mut bridge,
                &mut writer,
            )
            .unwrap();

        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
            "nested-client-task-1"
        );
        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"],
            "nested-upstream-7"
        );
        assert_eq!(
            response["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"],
            "parent-1"
        );
    }
}
