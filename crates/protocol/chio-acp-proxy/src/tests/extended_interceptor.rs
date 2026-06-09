#[test]
fn interceptor_client_to_agent_always_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "session/prompt",
        "params": {"sessionId": "s1", "message": "hello"}
    });
    let result = interceptor.intercept(Direction::ClientToAgent, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for client->agent, got {:?}", other),
    }
}

#[test]
fn interceptor_fs_read_blocked_returns_correct_error_json() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/etc/shadow"
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Block(v)) => {
            assert_eq!(v["jsonrpc"], "2.0");
            assert_eq!(v["id"], 99);
            assert!(v.get("error").is_some());
            assert_eq!(v["error"]["code"], -32000);
            let msg_str = v["error"]["message"].as_str().unwrap_or("");
            assert!(
                msg_str.contains("denied"),
                "error message should contain 'denied', got: {msg_str}"
            );
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn interceptor_fs_write_blocked_returns_correct_error_json() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/etc/crontab",
            "content": "malicious"
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Block(v)) => {
            assert_eq!(v["id"], 100);
            assert_eq!(v["error"]["code"], -32000);
        }
        other => panic!(
            "expected Block for fs write outside prefix, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_terminal_create_blocked_returns_correct_error_json() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "rm",
            "args": ["-rf", "/"]
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Block(v)) => {
            assert_eq!(v["id"], 101);
            assert_eq!(v["error"]["code"], -32000);
            let msg_str = v["error"]["message"].as_str().unwrap_or("");
            assert!(
                msg_str.contains("denied"),
                "error message should contain 'denied', got: {msg_str}"
            );
        }
        other => panic!(
            "expected Block for unlisted terminal command, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_session_update_tool_call_generates_receipt() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s1",
            "update": {
                "toolCallId": "tc-200",
                "title": "Compile",
                "kind": "execute",
                "status": "running"
            }
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::ForwardWithReceipt(_, receipt)) => {
            assert_eq!(receipt.tool_call_id, "tc-200");
            assert_eq!(receipt.title, "Compile");
            assert_eq!(receipt.status, "running");
            assert_eq!(receipt.session_id, "s1");
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }
}

#[test]
fn interceptor_session_update_agent_message_chunk_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s1",
            "update": {
                "type": "agent_message_chunk",
                "content": "Hello, I am an agent."
            }
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for agent_message_chunk, got {:?}", other),
    }
}

#[test]
fn interceptor_response_message_forwarded_unchanged() {
    // A response (has "result" but no "method") should be forwarded.
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"status": "ok"}
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for response message, got {:?}", other),
    }
}

#[test]
fn interceptor_message_without_method_forwarded() {
    // A notification without a method field should be forwarded.
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 5
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!(
            "expected Forward for message without method, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_fs_read_missing_params_returns_protocol_error() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "fs/read_text_file"
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(
        result.is_err(),
        "missing params should produce a protocol error"
    );
}

#[test]
fn interceptor_fs_read_rejects_empty_session_id_before_forwarding() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 105,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "  ",
            "path": "/home/user/project/src/lib.rs"
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("empty sessionId must fail at the ACP request boundary");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid fs/read_text_file params: sessionId must be a non-empty string"
    );
}

#[test]
fn interceptor_fs_read_rejects_padded_session_id_before_forwarding() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 106,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": " s1 ",
            "path": "/home/user/project/src/lib.rs"
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("padded sessionId must fail at the ACP request boundary");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid fs/read_text_file params: sessionId must be a non-empty unpadded string"
    );
}

#[test]
fn interceptor_fs_write_missing_params_returns_protocol_error() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "fs/write_text_file"
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(
        result.is_err(),
        "missing params should produce a protocol error"
    );
}

#[test]
fn interceptor_session_update_rejects_empty_tool_call_id_before_receipt() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-empty-tool-id",
            "update": {
                "toolCallId": " ",
                "title": "Read file",
                "kind": "read",
                "status": "running"
            }
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("empty toolCallId must not produce an ACP audit receipt");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid session/update params: update.toolCallId must be a non-empty string"
    );
}

#[test]
fn interceptor_session_update_rejects_padded_tool_call_id_before_receipt() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-padded-tool-id",
            "update": {
                "toolCallId": " tc-1 ",
                "title": "Read file",
                "kind": "read",
                "status": "running"
            }
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("padded toolCallId must not produce an ACP audit receipt");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid session/update params: update.toolCallId must be a non-empty unpadded string"
    );
}

#[test]
fn interceptor_session_update_rejects_malformed_tool_call_shape_before_forwarding() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-malformed-tool-call",
            "update": {
                "toolCallId": "tc-malformed",
                "status": 7
            }
        }
    });

    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("malformed tool-call update must fail before forwarding");

    assert!(err.to_string().contains("malformed tool call update"));
}

#[test]
fn interceptor_terminal_create_missing_params_returns_protocol_error() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 104,
        "method": "terminal/create"
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(
        result.is_err(),
        "missing params should produce a protocol error"
    );
}

#[test]
fn interceptor_fs_write_allowed_in_prefix() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 105,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/home/user/project/output.txt",
            "content": "hello"
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(_)) => {}
        other => panic!("expected Forward for allowed fs write, got {:?}", other),
    }
}

#[test]
fn interceptor_terminal_create_with_injection_arg_blocked() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 106,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "cargo",
            "args": ["build; rm -rf /"]
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Block(v)) => {
            assert!(v.get("error").is_some());
        }
        other => panic!("expected Block for injection arg, got {:?}", other),
    }
}

#[test]
fn interceptor_session_update_tool_call_update_with_status_generates_receipt() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s2",
            "update": {
                "toolCallId": "tc-300",
                "status": "completed"
            }
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::ForwardWithReceipt(_, receipt)) => {
            assert_eq!(receipt.tool_call_id, "tc-300");
            assert_eq!(receipt.status, "completed");
            assert_eq!(receipt.session_id, "s2");
        }
        other => panic!(
            "expected ForwardWithReceipt for tool_call_update, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_session_update_tool_call_update_without_status_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s3",
            "update": {
                "toolCallId": "tc-400"
            }
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(_)) => {}
        other => panic!(
            "expected Forward for tool_call_update without status, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_permission_request_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "session/request_permission",
        "params": {
            "sessionId": "s1",
            "toolCall": {"name": "fs_read"},
            "options": [
                {"optionId": "opt-1", "name": "Allow", "kind": "allow_once"},
                {"optionId": "opt-2", "name": "Deny", "kind": "reject_once"}
            ]
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for permission request, got {:?}", other),
    }
}

#[test]
fn interceptor_permission_request_rejects_empty_boundary_ids() {
    let interceptor = MessageInterceptor::new(test_config());
    let empty_session = json!({
        "jsonrpc": "2.0",
        "id": 202,
        "method": "session/request_permission",
        "params": {
            "sessionId": " ",
            "options": [
                {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"}
            ]
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &empty_session)
        .expect_err("empty permission sessionId must fail at the ACP boundary");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid session/request_permission params: sessionId must be a non-empty string"
    );

    let empty_option = json!({
        "jsonrpc": "2.0",
        "id": 203,
        "method": "session/request_permission",
        "params": {
            "sessionId": "s1",
            "options": [
                {"optionId": " ", "name": "Allow once", "kind": "allow_once"}
            ]
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &empty_option)
        .expect_err("empty permission optionId must fail at the ACP boundary");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid session/request_permission params: options[0].optionId must be a non-empty string"
    );
}

#[test]
fn interceptor_unknown_method_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 201,
        "method": "some/future/method",
        "params": {}
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for unknown method, got {:?}", other),
    }
}

// ================================================================
// 5. Permission Mapper
// ================================================================

#[test]
fn interceptor_session_update_rejects_bad_params_before_forwarding() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": "not an object"
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("malformed session/update params must fail at the ACP boundary");
    assert!(
        err.to_string()
            .contains("protocol error: invalid session/update params:"),
        "unexpected malformed session/update error: {err}"
    );
}

#[test]
fn interceptor_session_update_rejects_missing_params_before_forwarding() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update"
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .expect_err("missing session/update params must fail at the ACP boundary");
    assert_eq!(
        err.to_string(),
        "protocol error: missing params in session/update"
    );
}

#[test]
fn interceptor_permission_request_with_empty_options() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 300,
        "method": "session/request_permission",
        "params": {
            "sessionId": "s1",
            "options": []
        }
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!("expected Forward for empty options, got {:?}", other),
    }
}

#[test]
fn interceptor_permission_request_with_no_params_forwarded() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 301,
        "method": "session/request_permission"
    });
    let result = interceptor.intercept(Direction::AgentToClient, &msg);
    assert!(result.is_ok());
    match result {
        Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
        other => panic!(
            "expected Forward for permission without params, got {:?}",
            other
        ),
    }
}
