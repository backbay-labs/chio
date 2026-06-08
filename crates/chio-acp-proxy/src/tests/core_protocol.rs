#[test]
fn parse_json_rpc_message() {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/home/user/file.txt"
        }
    });
    let msg: JsonRpcMessage = serde_json::from_value(raw).unwrap();
    assert_eq!(msg.method.as_deref(), Some("fs/read_text_file"));
    assert_eq!(msg.id, Some(serde_json::Value::Number(1.into())));
}

#[test]
fn parse_read_text_file_params() {
    let raw = json!({
        "sessionId": "s1",
        "path": "/home/user/file.txt",
        "line": 10,
        "limit": 50
    });
    let params: ReadTextFileParams = serde_json::from_value(raw).unwrap();
    assert_eq!(params.session_id, "s1");
    assert_eq!(params.path, "/home/user/file.txt");
    assert_eq!(params.line, Some(10));
    assert_eq!(params.limit, Some(50));
}

#[test]
fn parse_write_text_file_params() {
    let raw = json!({
        "sessionId": "s1",
        "path": "/home/user/out.txt",
        "content": "hello world"
    });
    let params: WriteTextFileParams = serde_json::from_value(raw).unwrap();
    assert_eq!(params.path, "/home/user/out.txt");
    assert_eq!(params.content, "hello world");
}

#[test]
fn parse_create_terminal_params() {
    let raw = json!({
        "sessionId": "s1",
        "command": "cargo",
        "args": ["build", "--release"],
        "cwd": "/home/user/project"
    });
    let params: CreateTerminalParams = serde_json::from_value(raw).unwrap();
    assert_eq!(params.command, "cargo");
    assert_eq!(params.args, vec!["build", "--release"]);
    assert_eq!(params.cwd, Some("/home/user/project".to_string()));
}

#[test]
fn parse_permission_option() {
    let raw = json!({
        "optionId": "opt-1",
        "name": "Allow once",
        "kind": "allow_once"
    });
    let option: PermissionOption = serde_json::from_value(raw).unwrap();
    assert_eq!(option.option_id, "opt-1");
    assert_eq!(option.kind, "allow_once");
}

#[test]
fn extract_method_returns_correct_variant() {
    let msg = json!({ "jsonrpc": "2.0", "method": "terminal/create" });
    let method = extract_method(&msg);
    assert_eq!(method, Some(AcpMethod::TerminalCreate));
}

#[test]
fn extract_method_returns_none_for_response() {
    let msg = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
    assert_eq!(extract_method(&msg), None);
}

#[test]
fn parse_tool_call_event() {
    let raw = json!({
        "toolCallId": "tc-1",
        "title": "Read file",
        "kind": "read",
        "status": "running"
    });
    let update = parse_session_update(&raw);
    match update {
        SessionUpdate::ToolCall(event) => {
            assert_eq!(event.tool_call_id, "tc-1");
            assert_eq!(event.title, Some("Read file".to_string()));
        }
        other => panic!("expected ToolCall, got {:?}", other),
    }
}

#[test]
fn parse_tool_call_update_event() {
    let raw = json!({
        "toolCallId": "tc-2",
        "status": "completed"
    });
    let update = parse_session_update(&raw);
    match update {
        SessionUpdate::ToolCallUpdate(event) => {
            assert_eq!(event.tool_call_id, "tc-2");
            assert_eq!(event.status, Some("completed".to_string()));
        }
        other => panic!("expected ToolCallUpdate, got {:?}", other),
    }
}

#[test]
fn parse_session_update_malformed_tool_call_id_fails_closed() {
    let raw = json!({
        "toolCallId": 7,
        "status": "completed"
    });

    match parse_session_update(&raw) {
        SessionUpdate::MalformedToolCall(message) => {
            assert!(message.contains("toolCallId"));
            assert!(message.contains("must be a string"));
        }
        other => panic!("expected MalformedToolCall, got {:?}", other),
    }
}

#[test]
fn parse_session_update_tool_call_id_takes_precedence_over_known_type() {
    let raw = json!({
        "type": "agent_message_chunk",
        "content": "hello",
        "toolCallId": 7
    });

    match parse_session_update(&raw) {
        SessionUpdate::MalformedToolCall(message) => {
            assert!(message.contains("toolCallId"));
            assert!(message.contains("must be a string"));
        }
        other => panic!("expected MalformedToolCall, got {:?}", other),
    }
}

// -- New ACP method variants --

#[test]
fn protocol_parses_new_method_variants() {
    assert_eq!(
        AcpMethod::from_method_str("authenticate"),
        AcpMethod::Authenticate
    );
    assert_eq!(
        AcpMethod::from_method_str("session/load"),
        AcpMethod::SessionLoad
    );
    assert_eq!(
        AcpMethod::from_method_str("session/list"),
        AcpMethod::SessionList
    );
    assert_eq!(
        AcpMethod::from_method_str("session/set_config_option"),
        AcpMethod::SessionSetConfigOption
    );
    assert_eq!(
        AcpMethod::from_method_str("session/set_mode"),
        AcpMethod::SessionSetMode
    );
    assert_eq!(
        AcpMethod::from_method_str("terminal/output"),
        AcpMethod::TerminalOutput
    );
    assert_eq!(
        AcpMethod::from_method_str("terminal/wait_for_exit"),
        AcpMethod::TerminalWaitForExit
    );
}

// -- Session update variant parsing --

#[test]
fn protocol_parses_all_session_update_variants() {
    // agent_message_chunk
    let raw = json!({"type": "agent_message_chunk", "content": "hello"});
    match parse_session_update(&raw) {
        SessionUpdate::AgentMessageChunk(_) => {}
        other => panic!("expected AgentMessageChunk, got {:?}", other),
    }

    // agent_thought_chunk
    let raw = json!({"type": "agent_thought_chunk", "content": "thinking..."});
    match parse_session_update(&raw) {
        SessionUpdate::AgentThoughtChunk(_) => {}
        other => panic!("expected AgentThoughtChunk, got {:?}", other),
    }

    // plan
    let raw = json!({"type": "plan", "steps": []});
    match parse_session_update(&raw) {
        SessionUpdate::Plan(_) => {}
        other => panic!("expected Plan, got {:?}", other),
    }

    // available_commands_update
    let raw = json!({"type": "available_commands_update", "commands": []});
    match parse_session_update(&raw) {
        SessionUpdate::AvailableCommandsUpdate(_) => {}
        other => panic!("expected AvailableCommandsUpdate, got {:?}", other),
    }

    // current_mode_update
    let raw = json!({"type": "current_mode_update", "mode": "code"});
    match parse_session_update(&raw) {
        SessionUpdate::CurrentModeUpdate(_) => {}
        other => panic!("expected CurrentModeUpdate, got {:?}", other),
    }

    // config_option_update
    let raw = json!({"type": "config_option_update", "key": "theme", "value": "dark"});
    match parse_session_update(&raw) {
        SessionUpdate::ConfigOptionUpdate(_) => {}
        other => panic!("expected ConfigOptionUpdate, got {:?}", other),
    }

    // session_info_update
    let raw = json!({"type": "session_info_update", "session_id": "s1"});
    match parse_session_update(&raw) {
        SessionUpdate::SessionInfoUpdate(_) => {}
        other => panic!("expected SessionInfoUpdate, got {:?}", other),
    }

    // unknown type falls through to Other
    let raw = json!({"type": "unknown_future_type", "data": 42});
    match parse_session_update(&raw) {
        SessionUpdate::Other(_) => {}
        other => panic!("expected Other, got {:?}", other),
    }
}

// -- MessageInterceptor tests --
