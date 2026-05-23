use std::collections::BTreeMap;

/// A JSON-RPC 2.0 message envelope used by the ACP protocol.
///
/// This is a loose representation that can hold requests, responses,
/// and notifications. Fields are optional because different message
/// types populate different subsets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRpcMessage {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC error code for access-denied responses.
///
/// Uses the server error range (-32000 to -32099) rather than the
/// standard "invalid request" code (-32600), since the request is
/// syntactically valid but policy-rejected.
const ACP_ERROR_ACCESS_DENIED: i64 = -32000;

/// Discriminated ACP method names that the proxy needs to understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpMethod {
    Initialize,
    Authenticate,
    SessionNew,
    SessionPrompt,
    SessionCancel,
    SessionUpdate,
    SessionRequestPermission,
    SessionLoad,
    SessionList,
    SessionSetConfigOption,
    SessionSetMode,
    FsReadTextFile,
    FsWriteTextFile,
    TerminalCreate,
    TerminalKill,
    TerminalRelease,
    TerminalOutput,
    TerminalWaitForExit,
    Unknown(String),
}

impl AcpMethod {
    /// Parse a JSON-RPC method string into a typed discriminator.
    pub fn from_method_str(s: &str) -> Self {
        match s {
            "initialize" => Self::Initialize,
            "authenticate" => Self::Authenticate,
            "session/new" => Self::SessionNew,
            "session/prompt" => Self::SessionPrompt,
            "session/cancel" => Self::SessionCancel,
            "session/update" => Self::SessionUpdate,
            "session/request_permission" => Self::SessionRequestPermission,
            "session/load" => Self::SessionLoad,
            "session/list" => Self::SessionList,
            "session/set_config_option" => Self::SessionSetConfigOption,
            "session/set_mode" => Self::SessionSetMode,
            "fs/read_text_file" => Self::FsReadTextFile,
            "fs/write_text_file" => Self::FsWriteTextFile,
            "terminal/create" => Self::TerminalCreate,
            "terminal/kill" => Self::TerminalKill,
            "terminal/release" => Self::TerminalRelease,
            "terminal/output" => Self::TerminalOutput,
            "terminal/wait_for_exit" => Self::TerminalWaitForExit,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// Parameters for `session/request_permission`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPermissionParams {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call: Option<Value>,
    #[serde(default)]
    pub options: Vec<PermissionOption>,
}

/// A single permission option presented to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionOption {
    pub option_id: String,
    pub name: String,
    pub kind: String,
}

/// Parameters for `fs/read_text_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadTextFileParams {
    pub session_id: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// Parameters for `fs/write_text_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteTextFileParams {
    pub session_id: String,
    pub path: String,
    pub content: String,
}

/// Parameters for `terminal/create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTerminalParams {
    pub session_id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Parameters for `terminal/kill`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillTerminalParams {
    pub session_id: String,
    pub terminal_id: String,
}

/// Parameters for `terminal/release`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseTerminalParams {
    pub session_id: String,
    pub terminal_id: String,
}

/// A `session/update` notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUpdateNotification {
    pub session_id: String,
    pub update: Value,
}

/// Typed session update events that the proxy cares about.
///
/// Security-critical variants (`ToolCall`, `ToolCallUpdate`) are fully
/// parsed. The remaining ACP update types are captured as raw `Value`s
/// since they do not require guard enforcement, but are still
/// discriminated for logging and future extensibility.
#[derive(Debug, Clone)]
pub enum SessionUpdate {
    ToolCall(ToolCallEvent),
    ToolCallUpdate(ToolCallUpdateEvent),
    AgentMessageChunk(Value),
    AgentThoughtChunk(Value),
    Plan(Value),
    AvailableCommandsUpdate(Value),
    CurrentModeUpdate(Value),
    ConfigOptionUpdate(Value),
    SessionInfoUpdate(Value),
    Other(Value),
}

/// A tool call event observed in a session update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallEvent {
    pub tool_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A tool call update event observed in a session update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallUpdateEvent {
    pub tool_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Attempt to parse a session update `Value` into a typed `SessionUpdate`.
pub fn parse_session_update(value: &Value) -> SessionUpdate {
    // Check for a discriminator field "type" used by non-tool-call updates.
    if let Some(update_type) = value.get("type").and_then(|v| v.as_str()) {
        match update_type {
            "agent_message_chunk" => return SessionUpdate::AgentMessageChunk(value.clone()),
            "agent_thought_chunk" => return SessionUpdate::AgentThoughtChunk(value.clone()),
            "plan" => return SessionUpdate::Plan(value.clone()),
            "available_commands_update" => {
                return SessionUpdate::AvailableCommandsUpdate(value.clone())
            }
            "current_mode_update" => return SessionUpdate::CurrentModeUpdate(value.clone()),
            "config_option_update" => return SessionUpdate::ConfigOptionUpdate(value.clone()),
            "session_info_update" => return SessionUpdate::SessionInfoUpdate(value.clone()),
            _ => {}
        }
    }

    // Try tool_call first (has title field)
    if value.get("toolCallId").is_some() && value.get("title").is_some() {
        if let Ok(event) = serde_json::from_value::<ToolCallEvent>(value.clone()) {
            return SessionUpdate::ToolCall(event);
        }
    }
    // Try tool_call_update (has toolCallId but no title)
    if value.get("toolCallId").is_some() {
        if let Ok(event) = serde_json::from_value::<ToolCallUpdateEvent>(value.clone()) {
            return SessionUpdate::ToolCallUpdate(event);
        }
    }
    SessionUpdate::Other(value.clone())
}

/// Extract the method string from a raw JSON-RPC message value.
pub fn extract_method(msg: &Value) -> Option<AcpMethod> {
    msg.get("method")
        .and_then(|v| v.as_str())
        .map(AcpMethod::from_method_str)
}

/// Build a JSON-RPC error response for a given request id.
pub fn json_rpc_error(id: Option<&Value>, code: i64, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message
        }
    })
}
