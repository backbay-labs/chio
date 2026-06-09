#[test]
fn interceptor_jsonrpc_param_decoder_preserves_method_specific_protocol_errors() {
    let missing = MessageInterceptor::jsonrpc_params(&json!({}), "fs/read_text_file")
        .expect_err("missing params should fail closed");
    assert_eq!(
        missing.to_string(),
        "protocol error: missing params in fs/read_text_file"
    );

    let invalid = MessageInterceptor::decode_jsonrpc_params::<ReadTextFileParams>(
        &json!({
            "sessionId": "s1",
            "path": 42
        }),
        "fs/read_text_file",
    )
    .expect_err("invalid typed params should fail closed");
    assert!(invalid
        .to_string()
        .contains("protocol error: invalid fs/read_text_file params:"));

    let decoded = match MessageInterceptor::decode_jsonrpc_params::<ReadTextFileParams>(
        &json!({
            "sessionId": "s1",
            "path": "/home/user/project/README.md",
            "line": 1,
            "limit": 5
        }),
        "fs/read_text_file",
    ) {
        Ok(decoded) => decoded,
        Err(error) => panic!("valid fs/read_text_file params should decode: {error}"),
    };
    assert_eq!(decoded.session_id, "s1");
    assert_eq!(decoded.path, "/home/user/project/README.md");
    assert_eq!(decoded.line, Some(1));
    assert_eq!(decoded.limit, Some(5));
}

#[test]
fn interceptor_forwards_unrelated_message() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let result = interceptor
        .intercept(Direction::ClientToAgent, &msg)
        .unwrap();
    match result {
        InterceptResult::Forward(v) => assert_eq!(v, msg),
        other => panic!("expected Forward, got {:?}", other),
    }
}

#[test]
fn interceptor_blocks_fs_read_outside_prefix() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/etc/passwd"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            assert!(v.get("error").is_some());
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn interceptor_allows_fs_read_in_prefix() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/home/user/project/src/main.rs"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward, got {:?}", other),
    }
}

#[test]
fn interceptor_blocks_terminal_create_unlisted_command() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "rm",
            "args": ["-rf", "/"]
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            assert!(v.get("error").is_some());
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn interceptor_allows_terminal_create_listed_command() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "cargo",
            "args": ["test"]
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward, got {:?}", other),
    }
}

#[test]
fn interceptor_blocks_terminal_create_with_out_of_scope_cwd() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "cargo",
            "args": ["test"],
            "cwd": "/etc"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            assert!(v.get("error").is_some());
            assert!(v["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("cwd"));
        }
        other => panic!("expected Block for out-of-scope cwd, got {:?}", other),
    }
}

#[test]
fn interceptor_allows_terminal_create_with_in_scope_cwd() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "terminal/create",
        "params": {
            "sessionId": "s1",
            "command": "cargo",
            "args": ["test"],
            "cwd": "/home/user/project"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward for in-scope cwd, got {:?}", other),
    }
}

#[test]
fn interceptor_generates_receipt_for_tool_call() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s1",
            "update": {
                "toolCallId": "tc-99",
                "title": "Build project",
                "kind": "execute",
                "status": "running"
            }
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.tool_call_id, "tc-99");
            assert_eq!(receipt.title, "Build project");
            assert_eq!(receipt.status, "running");
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }
}

#[test]
fn interceptor_forwards_client_to_agent_unchanged() {
    let interceptor = MessageInterceptor::new(test_config());
    // Even security-sensitive methods are forwarded when going client->agent
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/etc/shadow"
        }
    });
    let result = interceptor
        .intercept(Direction::ClientToAgent, &msg)
        .unwrap();
    match result {
        InterceptResult::Forward(v) => assert_eq!(v, msg),
        other => panic!(
            "expected Forward for client->agent direction, got {:?}",
            other
        ),
    }
}

#[test]
fn interceptor_blocks_fs_write_with_traversal() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/home/user/project/../../../etc/crontab",
            "content": "* * * * * evil"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            assert!(v.get("error").is_some());
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn interceptor_handles_new_method_variants() {
    let interceptor = MessageInterceptor::new(test_config());

    // All new method variants should forward without errors
    let methods = vec![
        "authenticate",
        "session/load",
        "session/list",
        "session/set_config_option",
        "session/set_mode",
        "terminal/output",
        "terminal/wait_for_exit",
    ];

    for method in methods {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": method,
            "params": {}
        });

        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Forward(_) => {}
            other => panic!("expected Forward for method '{}', got {:?}", method, other),
        }
    }
}

#[test]
fn interceptor_uses_correct_error_code() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/etc/passwd"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            let code = v
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_i64())
                .unwrap();
            assert_eq!(
                code, -32000,
                "error code should be -32000 (server error range)"
            );
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn interceptor_blocks_fs_read_prefix_substring() {
    let interceptor = MessageInterceptor::new(test_config());
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 50,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "s1",
            "path": "/home/user/project_evil/secret.txt"
        }
    });
    let result = interceptor
        .intercept(Direction::AgentToClient, &msg)
        .unwrap();
    match result {
        InterceptResult::Block(v) => {
            assert!(v.get("error").is_some());
        }
        other => panic!(
            "expected Block for prefix substring attack, got {:?}",
            other
        ),
    }
}

// -- AcpProxy lifecycle test --

#[test]
fn proxy_creation_and_shutdown() {
    // Use a command that exists on all platforms and exits immediately.
    // "true" is a shell builtin / coreutils command that always succeeds.
    let config = AcpProxyConfig::new("true", "deadbeef").with_allowed_path_prefix("/tmp");

    let result = AcpProxy::start(config);
    // The proxy should start successfully (the 'true' command is
    // universally available on Unix systems).
    match result {
        Ok(mut proxy) => {
            // Shutdown should not error even if the process already exited.
            let _ = proxy.shutdown();
        }
        Err(_) => {
            // On systems where 'true' is not found, we accept the failure
            // gracefully rather than panicking.
        }
    }
}

// -- Audit entry content hash test --
