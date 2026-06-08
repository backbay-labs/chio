#[test]
fn protocol_malformed_json_rpc_missing_jsonrpc_field() {
    // A JSON-RPC message that is missing the required "jsonrpc" field
    // should fail to deserialize into JsonRpcMessage.
    let raw = json!({
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(
        result.is_err(),
        "missing jsonrpc field should fail deserialization"
    );
}

#[test]
fn protocol_json_rpc_with_null_id_notification() {
    // serde_json deserializes `"id": null` for Option<Value> as None.
    // This is effectively the same as omitting the id entirely.
    let raw = json!({
        "jsonrpc": "2.0",
        "id": null,
        "method": "session/update",
        "params": {}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok(), "null id should be valid JSON-RPC");
    if let Ok(msg) = result {
        assert!(
            msg.id.is_none(),
            "explicit null id deserializes as None for Option<Value>"
        );
    }
}

#[test]
fn protocol_json_rpc_with_string_id() {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": "abc-123",
        "method": "initialize",
        "params": {}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok(), "string id should be valid JSON-RPC");
    if let Ok(msg) = result {
        let id_str = msg.id.as_ref().and_then(|v| v.as_str());
        assert_eq!(id_str, Some("abc-123"));
    }
}

#[test]
fn protocol_json_rpc_with_numeric_id() {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "initialize",
        "params": {}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok(), "numeric id should be valid JSON-RPC");
    if let Ok(msg) = result {
        let id_num = msg.id.as_ref().and_then(|v| v.as_i64());
        assert_eq!(id_num, Some(42));
    }
}

#[test]
fn protocol_unknown_method_maps_to_unknown_variant() {
    let method = AcpMethod::from_method_str("some/future/method");
    assert_eq!(method, AcpMethod::Unknown("some/future/method".to_string()));
}

#[test]
fn protocol_empty_method_string_maps_to_unknown() {
    let method = AcpMethod::from_method_str("");
    assert_eq!(method, AcpMethod::Unknown(String::new()));
}

#[test]
fn protocol_session_update_with_unknown_type_maps_to_other() {
    let raw = json!({"type": "some_new_update_type", "payload": 42});
    match parse_session_update(&raw) {
        SessionUpdate::Other(_) => {}
        other => panic!(
            "expected Other for unknown session update type, got {:?}",
            other
        ),
    }
}

#[test]
fn protocol_empty_params_object() {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok(), "empty params object should be valid");
    if let Ok(msg) = result {
        assert!(msg.params.is_some());
        let params = msg.params.as_ref();
        assert!(
            params.map(|p| p.is_object()).unwrap_or(false),
            "params should be an object"
        );
    }
}

#[test]
fn protocol_params_as_array() {
    // JSON-RPC 2.0 allows params as array. Our struct should handle
    // it since params is typed as Option<Value>.
    let raw = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": [1, 2, 3]
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok(), "array params should be deserializable");
    if let Ok(msg) = result {
        assert!(msg.params.is_some());
        let is_array = msg.params.as_ref().map(|p| p.is_array()).unwrap_or(false);
        assert!(is_array, "params should be an array");
    }
}

#[test]
fn protocol_extract_method_returns_none_for_no_method_field() {
    let msg = json!({"jsonrpc": "2.0", "id": 1});
    assert_eq!(extract_method(&msg), None);
}

#[test]
fn protocol_extract_method_returns_none_for_non_string_method() {
    let msg = json!({"jsonrpc": "2.0", "method": 123});
    assert_eq!(extract_method(&msg), None);
}

#[test]
fn protocol_json_rpc_notification_no_id() {
    // A notification has method but no id.
    let raw = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {"sessionId": "s1", "update": {}}
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok());
    if let Ok(msg) = result {
        assert!(msg.id.is_none(), "notification should have no id");
        assert_eq!(msg.method.as_deref(), Some("session/update"));
    }
}

#[test]
fn protocol_json_rpc_error_response() {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32600,
            "message": "Invalid Request"
        }
    });
    let result = serde_json::from_value::<JsonRpcMessage>(raw);
    assert!(result.is_ok());
    if let Ok(msg) = result {
        assert!(msg.error.is_some());
        if let Some(ref err) = msg.error {
            assert_eq!(err.code, -32600);
            assert_eq!(err.message, "Invalid Request");
        }
    }
}

#[test]
fn protocol_json_rpc_error_builder_uses_correct_structure() {
    let error = json_rpc_error(Some(&json!(42)), -32000, "access denied");
    assert_eq!(error["jsonrpc"], "2.0");
    assert_eq!(error["id"], 42);
    assert_eq!(error["error"]["code"], -32000);
    assert_eq!(error["error"]["message"], "access denied");
}

#[test]
fn protocol_json_rpc_error_builder_with_none_id() {
    let error = json_rpc_error(None, -32000, "access denied");
    assert_eq!(error["id"], serde_json::Value::Null);
}

#[test]
fn protocol_json_rpc_error_builder_replaces_non_scalar_ids_with_null() {
    for invalid_id in [json!(true), json!({"nested": 1}), json!([1])] {
        let error = json_rpc_error(Some(&invalid_id), -32000, "access denied");
        assert_eq!(error["id"], serde_json::Value::Null);
    }
}

#[test]
fn protocol_parse_session_update_tool_call_without_title() {
    // toolCallId present but no title -- should match ToolCallUpdate, not ToolCall
    let raw = json!({
        "toolCallId": "tc-no-title",
        "status": "running"
    });
    match parse_session_update(&raw) {
        SessionUpdate::ToolCallUpdate(event) => {
            assert_eq!(event.tool_call_id, "tc-no-title");
            assert_eq!(event.status, Some("running".to_string()));
        }
        other => panic!("expected ToolCallUpdate (no title), got {:?}", other),
    }
}

#[test]
fn protocol_parse_session_update_empty_object() {
    // An empty JSON object has no discriminator fields -- should be Other.
    let raw = json!({});
    match parse_session_update(&raw) {
        SessionUpdate::Other(_) => {}
        other => panic!("expected Other for empty object, got {:?}", other),
    }
}

// ================================================================
// 2. FsGuard Comprehensive Coverage
// ================================================================

#[test]
fn all_acp_methods_have_correct_from_str() {
    let pairs = vec![
        ("initialize", AcpMethod::Initialize),
        ("authenticate", AcpMethod::Authenticate),
        ("session/new", AcpMethod::SessionNew),
        ("session/prompt", AcpMethod::SessionPrompt),
        ("session/cancel", AcpMethod::SessionCancel),
        ("session/update", AcpMethod::SessionUpdate),
        (
            "session/request_permission",
            AcpMethod::SessionRequestPermission,
        ),
        ("session/load", AcpMethod::SessionLoad),
        ("session/list", AcpMethod::SessionList),
        (
            "session/set_config_option",
            AcpMethod::SessionSetConfigOption,
        ),
        ("session/set_mode", AcpMethod::SessionSetMode),
        ("fs/read_text_file", AcpMethod::FsReadTextFile),
        ("fs/write_text_file", AcpMethod::FsWriteTextFile),
        ("terminal/create", AcpMethod::TerminalCreate),
        ("terminal/kill", AcpMethod::TerminalKill),
        ("terminal/release", AcpMethod::TerminalRelease),
        ("terminal/output", AcpMethod::TerminalOutput),
        ("terminal/wait_for_exit", AcpMethod::TerminalWaitForExit),
    ];
    for (method_str, expected) in pairs {
        assert_eq!(
            AcpMethod::from_method_str(method_str),
            expected,
            "method string '{method_str}' should map correctly"
        );
    }
}

#[test]
fn create_terminal_params_with_no_args() {
    let raw = json!({
        "sessionId": "s1",
        "command": "ls"
    });
    let result = serde_json::from_value::<CreateTerminalParams>(raw);
    assert!(result.is_ok());
    if let Ok(params) = result {
        assert_eq!(params.command, "ls");
        assert!(params.args.is_empty());
        assert!(params.cwd.is_none());
        assert!(params.env.is_none());
    }
}

#[test]
fn read_text_file_params_minimal() {
    let raw = json!({
        "sessionId": "s1",
        "path": "/tmp/file.txt"
    });
    let result = serde_json::from_value::<ReadTextFileParams>(raw);
    assert!(result.is_ok());
    if let Ok(params) = result {
        assert_eq!(params.path, "/tmp/file.txt");
        assert!(params.line.is_none());
        assert!(params.limit.is_none());
    }
}

#[test]
fn request_permission_params_with_empty_options() {
    let raw = json!({
        "sessionId": "s1",
        "options": []
    });
    let result = serde_json::from_value::<RequestPermissionParams>(raw);
    assert!(result.is_ok());
    if let Ok(params) = result {
        assert!(params.options.is_empty());
        assert!(params.tool_call.is_none());
    }
}
