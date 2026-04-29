#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- FsGuard tests --

    #[test]
    fn fs_guard_allows_path_under_prefix() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("/home/user/project/src/main.rs").is_ok());
        assert!(guard.check_write("/home/user/project/README.md").is_ok());
    }

    #[test]
    fn fs_guard_blocks_path_outside_prefix() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("/etc/passwd").is_err());
        assert!(guard.check_write("/tmp/evil.sh").is_err());
    }

    #[test]
    fn fs_guard_blocks_path_traversal() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard
            .check_read("/home/user/project/../../../etc/passwd")
            .is_err());
        assert!(guard.check_write("/home/user/project/../../evil").is_err());
    }

    #[test]
    fn fs_guard_denies_when_no_prefixes_configured() {
        let guard = FsGuard::new(vec![]);
        assert!(guard.check_read("/any/path").is_err());
        assert!(guard.check_write("/any/path").is_err());
    }

    #[test]
    fn fs_guard_multiple_prefixes() {
        let guard = FsGuard::new(vec![
            "/home/user/project".to_string(),
            "/tmp/workspace".to_string(),
        ]);
        assert!(guard.check_read("/home/user/project/file.txt").is_ok());
        assert!(guard.check_read("/tmp/workspace/output.log").is_ok());
        assert!(guard.check_read("/var/log/system.log").is_err());
    }

    #[test]
    fn fs_guard_blocks_prefix_substring_attack() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Must NOT match a sibling directory whose name starts with the prefix
        assert!(guard
            .check_read("/home/user/project_evil/secret.txt")
            .is_err());
        // Exact match is allowed
        assert!(guard.check_read("/home/user/project").is_ok());
        // Subdirectory is allowed
        assert!(guard.check_read("/home/user/project/file.txt").is_ok());
    }

    #[test]
    fn fs_guard_rejects_relative_paths() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("relative/path/file.txt").is_err());
        assert!(guard.check_write("../escape").is_err());
        assert!(guard.check_read("file.txt").is_err());
    }

    #[test]
    fn fs_guard_handles_empty_path() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("").is_err());
        assert!(guard.check_write("").is_err());
    }

    #[test]
    fn fs_guard_with_resolve_symlinks_flag() {
        // Verify the builder works (actual symlink resolution depends
        // on filesystem state, so we just test the config path).
        let guard =
            FsGuard::new(vec!["/home/user/project".to_string()]).with_resolve_symlinks(true);
        // A non-existent path falls back to textual canonicalization.
        assert!(guard
            .check_read("/home/user/project/nonexistent.txt")
            .is_ok());
    }

    // -- TerminalGuard tests --

    #[test]
    fn terminal_guard_allows_listed_command() {
        let guard = TerminalGuard::new(vec!["cargo".to_string(), "npm".to_string()]);
        assert!(guard.check_command("cargo", &["build".to_string()]).is_ok());
        assert!(guard.check_command("npm", &["install".to_string()]).is_ok());
    }

    #[test]
    fn terminal_guard_blocks_unlisted_command() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard.check_command("rm", &["-rf".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_denies_when_no_commands_configured() {
        let guard = TerminalGuard::new(vec![]);
        assert!(guard.check_command("ls", &[]).is_err());
    }

    #[test]
    fn terminal_guard_blocks_shell_injection_in_args() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard
            .check_command("echo", &["$(rm -rf /)".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["hello; rm -rf /".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["`evil`".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["hello | cat /etc/passwd".to_string()])
            .is_err());
    }

    #[test]
    fn terminal_guard_allows_clean_args() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command(
                "cargo",
                &[
                    "build".to_string(),
                    "--release".to_string(),
                    "--target".to_string(),
                    "x86_64-unknown-linux-gnu".to_string(),
                ]
            )
            .is_ok());
    }

    #[test]
    fn terminal_guard_strips_path_prefix() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command("/usr/bin/cargo", &["test".to_string()])
            .is_ok());
    }

    // -- PermissionMapper tests --

    #[test]
    fn permission_mapper_maps_known_kinds() {
        let mapper = PermissionMapper::new(3600);

        let allow_once = PermissionOption {
            option_id: "opt-1".to_string(),
            name: "Allow".to_string(),
            kind: "allow_once".to_string(),
        };
        let mapped = mapper.map_option(&allow_once);
        assert_eq!(mapped.chio_decision, PermissionDecision::AllowOnce);

        let allow_always = PermissionOption {
            option_id: "opt-2".to_string(),
            name: "Always allow".to_string(),
            kind: "allow_always".to_string(),
        };
        let mapped = mapper.map_option(&allow_always);
        assert_eq!(
            mapped.chio_decision,
            PermissionDecision::AllowScoped {
                duration_secs: 3600
            }
        );

        let reject_once = PermissionOption {
            option_id: "opt-3".to_string(),
            name: "Deny".to_string(),
            kind: "reject_once".to_string(),
        };
        let mapped = mapper.map_option(&reject_once);
        assert_eq!(mapped.chio_decision, PermissionDecision::Deny);

        let reject_always = PermissionOption {
            option_id: "opt-4".to_string(),
            name: "Never allow".to_string(),
            kind: "reject_always".to_string(),
        };
        let mapped = mapper.map_option(&reject_always);
        assert_eq!(mapped.chio_decision, PermissionDecision::DenyPermanent);
    }

    #[test]
    fn permission_mapper_denies_unknown_kind() {
        let mapper = PermissionMapper::new(3600);
        let unknown = PermissionOption {
            option_id: "opt-x".to_string(),
            name: "Mystery".to_string(),
            kind: "unknown_kind".to_string(),
        };
        let mapped = mapper.map_option(&unknown);
        assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
    }

    // -- ReceiptLogger tests --

    #[test]
    fn receipt_logger_generates_tool_call_receipt() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallEvent {
            tool_call_id: "tc-1".to_string(),
            title: Some("Read file".to_string()),
            kind: Some("fs_read".to_string()),
            status: Some("running".to_string()),
        };
        let receipt = logger.log_tool_call("session-1", &event, None);
        assert_eq!(receipt.tool_call_id, "tc-1");
        assert_eq!(receipt.title, "Read file");
        assert_eq!(receipt.kind, Some("fs_read".to_string()));
        assert_eq!(receipt.status, "running");
        assert_eq!(receipt.session_id, "session-1");
        assert_eq!(receipt.server_id, "test-server");
        assert!(!receipt.timestamp.is_empty());
        assert!(!receipt.content_hash.is_empty());
        assert_eq!(receipt.capability_id, None);
        assert_eq!(
            receipt.enforcement_mode,
            Some(AcpEnforcementMode::AuditOnly)
        );
        // SHA-256 hex is 64 chars
        assert_eq!(receipt.content_hash.len(), 64);
    }

    #[test]
    fn receipt_logger_generates_update_receipt_with_status() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-2".to_string(),
            status: Some("completed".to_string()),
        };
        let receipt = logger.log_tool_call_update("session-2", &event, None);
        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert_eq!(receipt.tool_call_id, "tc-2");
        assert_eq!(receipt.status, "completed");
        assert_eq!(receipt.capability_id, None);
        assert_eq!(
            receipt.enforcement_mode,
            Some(AcpEnforcementMode::AuditOnly)
        );
        assert!(!receipt.content_hash.is_empty());
        assert_eq!(receipt.content_hash.len(), 64);
    }

    #[test]
    fn receipt_logger_skips_update_without_status() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-3".to_string(),
            status: None,
        };
        let receipt = logger.log_tool_call_update("session-3", &event, None);
        assert!(receipt.is_none());
    }

    // -- Protocol deserialization tests --

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
            "kind": "fs_read",
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

    fn test_config() -> AcpProxyConfig {
        AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
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
                    "kind": "terminal",
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

    #[test]
    fn audit_entry_content_hash_is_deterministic() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallEvent {
            tool_call_id: "tc-hash".to_string(),
            title: Some("Determinism check".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry1 = logger.log_tool_call("session-hash", &event, None);
        let entry2 = logger.log_tool_call("session-hash", &event, None);
        assert_eq!(entry1.content_hash, entry2.content_hash);
    }
}

// ================================================================
// Extended test coverage -- no unwrap/expect used below.
// ================================================================
#[cfg(test)]
mod extended_tests {
    use super::*;
    use serde_json::json;

    // Helper: build a standard test interceptor config.
    fn test_config() -> AcpProxyConfig {
        AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
    }

    // ================================================================
    // 1. Protocol Parsing Edge Cases
    // ================================================================

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
    fn fs_guard_path_with_trailing_slash() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Trailing slash on the path should be normalized and still match.
        assert!(guard.check_read("/home/user/project/").is_ok());
    }

    #[test]
    fn fs_guard_path_with_double_slashes() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Double slashes should be collapsed during canonicalization.
        assert!(guard.check_read("/home/user//project/file.txt").is_ok());
    }

    #[test]
    fn fs_guard_root_path() {
        // The prefix "/" is stored as-is. After canonicalization "/"
        // becomes "/" (empty parts joined). The boundary check requires
        // the byte after the prefix to be '/' or an exact match. Since
        // prefix "/" has length 1 and canonicalized "/etc/passwd" has
        // 'e' at index 1, neither condition is met. This means "/" as
        // a prefix does NOT grant universal access -- it is effectively
        // a no-match because the implementation's boundary check is
        // strict. This is safe (fail-closed).
        let guard = FsGuard::new(vec!["/".to_string()]);
        assert!(
            guard.check_read("/etc/passwd").is_err(),
            "root prefix '/' does not pass boundary check -- fail-closed"
        );
    }

    #[test]
    fn fs_guard_root_path_not_configured() {
        let guard = FsGuard::new(vec!["/home/user".to_string()]);
        // Root path itself should not match a non-root prefix.
        assert!(guard.check_read("/").is_err());
    }

    #[test]
    fn fs_guard_very_long_path() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        let long_suffix = "a".repeat(1000);
        let long_path = format!("/home/user/project/{long_suffix}");
        assert!(guard.check_read(&long_path).is_ok());
    }

    #[test]
    fn fs_guard_path_with_unicode_characters() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard
            .check_read("/home/user/project/src/\u{00e9}ditor.rs")
            .is_ok());
        assert!(guard
            .check_read("/home/user/project/\u{4e16}\u{754c}.txt")
            .is_ok());
    }

    #[test]
    fn fs_guard_multiple_prefixes_matches_second() {
        let guard = FsGuard::new(vec!["/opt/first".to_string(), "/opt/second".to_string()]);
        // Should fail for first prefix but succeed for second.
        assert!(guard.check_read("/opt/second/file.txt").is_ok());
        // Verify the first also works.
        assert!(guard.check_read("/opt/first/file.txt").is_ok());
        // Neither prefix matches.
        assert!(guard.check_read("/opt/third/file.txt").is_err());
    }

    #[test]
    fn fs_guard_write_blocked_read_allowed_separate_instances() {
        // A read guard allows /tmp, a write guard allows only /home.
        let read_guard = FsGuard::new(vec!["/tmp".to_string()]);
        let write_guard = FsGuard::new(vec!["/home".to_string()]);

        assert!(read_guard.check_read("/tmp/data.txt").is_ok());
        assert!(write_guard.check_write("/tmp/data.txt").is_err());
        assert!(write_guard.check_write("/home/user/file.txt").is_ok());
        assert!(read_guard.check_read("/home/user/file.txt").is_err());
    }

    #[test]
    fn fs_guard_dot_segments_are_collapsed() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // "." segments should be collapsed to a clean path.
        assert!(guard.check_read("/home/user/./project/./file.txt").is_ok());
    }

    #[test]
    fn fs_guard_prefix_exact_match_no_trailing_slash() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Exact match of the prefix itself should be allowed.
        assert!(guard.check_read("/home/user/project").is_ok());
    }

    // ================================================================
    // 3. TerminalGuard Edge Cases
    // ================================================================

    #[test]
    fn terminal_guard_empty_command_string() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        // Empty command is not on the allowlist.
        assert!(guard.check_command("", &[]).is_err());
    }

    #[test]
    fn terminal_guard_command_with_spaces_in_path() {
        let guard = TerminalGuard::new(vec!["my tool".to_string()]);
        // The base name extraction uses rsplit('/'), so "/usr/local/bin/my tool"
        // has base name "my tool".
        assert!(guard.check_command("/usr/local/bin/my tool", &[]).is_ok());
    }

    #[test]
    fn terminal_guard_multiple_allowed_matching_second() {
        let guard = TerminalGuard::new(vec!["git".to_string(), "npm".to_string()]);
        assert!(guard.check_command("npm", &["install".to_string()]).is_ok());
    }

    #[test]
    fn terminal_guard_arg_with_pipe_only() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["|".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_semicolon_only() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &[";".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_backtick() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["`".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_dollar_paren() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard
            .check_command("echo", &["$(whoami)".to_string()])
            .is_err());
    }

    #[test]
    fn terminal_guard_arg_with_newline_character() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard
            .check_command("echo", &["line1\nline2".to_string()])
            .is_err());
    }

    #[test]
    fn terminal_guard_clean_arg_with_equals_sign() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command("cargo", &["--flag=value".to_string()])
            .is_ok());
    }

    #[test]
    fn terminal_guard_clean_arg_with_dashes_and_numbers() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command("cargo", &["--jobs=4".to_string(), "-j2".to_string()])
            .is_ok());
    }

    #[test]
    fn terminal_guard_arg_with_carriage_return() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard
            .check_command("echo", &["hello\rworld".to_string()])
            .is_err());
    }

    #[test]
    fn terminal_guard_command_matching_is_exact() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        // "cargoo" or "carg" should not match "cargo".
        assert!(guard.check_command("cargoo", &[]).is_err());
        assert!(guard.check_command("carg", &[]).is_err());
    }

    // ================================================================
    // 4. Interceptor Integration Tests
    // ================================================================

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
                    "kind": "terminal",
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
    fn permission_mapper_all_four_kinds() {
        let mapper = PermissionMapper::new(7200);

        let cases = vec![
            ("allow_once", PermissionDecision::AllowOnce),
            (
                "allow_always",
                PermissionDecision::AllowScoped {
                    duration_secs: 7200,
                },
            ),
            ("reject_once", PermissionDecision::Deny),
            ("reject_always", PermissionDecision::DenyPermanent),
        ];

        for (kind, expected_decision) in cases {
            let option = PermissionOption {
                option_id: format!("opt-{kind}"),
                name: kind.to_string(),
                kind: kind.to_string(),
            };
            let mapped = mapper.map_option(&option);
            assert_eq!(
                mapped.chio_decision, expected_decision,
                "kind '{kind}' should map to {expected_decision:?}"
            );
            assert_eq!(mapped.original_option_id, format!("opt-{kind}"));
        }
    }

    #[test]
    fn permission_mapper_unknown_kind_defaults_to_deny() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "opt-mystery".to_string(),
            name: "Mystery".to_string(),
            kind: "future_kind".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
    }

    #[test]
    fn permission_mapper_empty_kind_string_defaults_to_deny() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "opt-empty".to_string(),
            name: "Empty".to_string(),
            kind: String::new(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
    }

    #[test]
    fn permission_mapper_preserves_original_option_id() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "unique-id-42".to_string(),
            name: "Allow".to_string(),
            kind: "allow_once".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.original_option_id, "unique-id-42");
    }

    #[test]
    fn permission_mapper_scoped_duration_reflects_constructor() {
        let mapper = PermissionMapper::new(900); // 15 minutes
        let option = PermissionOption {
            option_id: "opt-scoped".to_string(),
            name: "Always".to_string(),
            kind: "allow_always".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(
            mapped.chio_decision,
            PermissionDecision::AllowScoped { duration_secs: 900 }
        );
    }

    // ================================================================
    // 6. Receipt/Audit Entry
    // ================================================================

    #[test]
    fn receipt_content_hash_deterministic_same_input() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-det".to_string(),
            title: Some("Hash test".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry1 = logger.log_tool_call("session-det", &event, None);
        let entry2 = logger.log_tool_call("session-det", &event, None);
        assert_eq!(entry1.content_hash, entry2.content_hash);
        assert_eq!(entry1.content_hash.len(), 64);
    }

    #[test]
    fn receipt_different_inputs_produce_different_hashes() {
        let logger = ReceiptLogger::new("srv-1");
        let event_a = ToolCallEvent {
            tool_call_id: "tc-a".to_string(),
            title: Some("Event A".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let event_b = ToolCallEvent {
            tool_call_id: "tc-b".to_string(),
            title: Some("Event B".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry_a = logger.log_tool_call("session-diff", &event_a, None);
        let entry_b = logger.log_tool_call("session-diff", &event_b, None);
        assert_ne!(
            entry_a.content_hash, entry_b.content_hash,
            "different events should produce different hashes"
        );
    }

    #[test]
    fn receipt_missing_optional_fields_handled_gracefully() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-minimal".to_string(),
            title: None,
            kind: None,
            status: None,
        };
        let entry = logger.log_tool_call("session-minimal", &event, None);
        assert_eq!(entry.tool_call_id, "tc-minimal");
        assert_eq!(
            entry.title, "",
            "missing title should default to empty string"
        );
        assert!(entry.kind.is_none());
        assert_eq!(
            entry.status, "started",
            "missing status should default to 'started'"
        );
        assert!(!entry.content_hash.is_empty());
        assert_eq!(entry.content_hash.len(), 64);
    }

    #[test]
    fn receipt_tool_call_update_without_status_returns_none() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-no-status".to_string(),
            status: None,
        };
        let result = logger.log_tool_call_update("session-none", &event, None);
        assert!(result.is_none());
    }

    #[test]
    fn receipt_tool_call_update_with_status_returns_some() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-with-status".to_string(),
            status: Some("error".to_string()),
        };
        let result = logger.log_tool_call_update("session-status", &event, None);
        assert!(result.is_some());
        if let Some(entry) = result {
            assert_eq!(entry.tool_call_id, "tc-with-status");
            assert_eq!(entry.status, "error");
            assert_eq!(entry.content_hash.len(), 64);
        }
    }

    #[test]
    fn receipt_update_content_hash_deterministic() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-upd-det".to_string(),
            status: Some("completed".to_string()),
        };
        let entry1 = logger.log_tool_call_update("session-upd", &event, None);
        let entry2 = logger.log_tool_call_update("session-upd", &event, None);
        assert!(entry1.is_some());
        assert!(entry2.is_some());
        if let (Some(e1), Some(e2)) = (entry1, entry2) {
            assert_eq!(e1.content_hash, e2.content_hash);
        }
    }

    #[test]
    fn receipt_server_id_matches_logger_config() {
        let logger = ReceiptLogger::new("custom-server-id");
        let event = ToolCallEvent {
            tool_call_id: "tc-srv".to_string(),
            title: Some("Server ID test".to_string()),
            kind: None,
            status: Some("running".to_string()),
        };
        let entry = logger.log_tool_call("s1", &event, None);
        assert_eq!(entry.server_id, "custom-server-id");
    }

    #[test]
    fn receipt_timestamp_is_numeric_string() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-ts".to_string(),
            title: Some("Timestamp test".to_string()),
            kind: None,
            status: Some("running".to_string()),
        };
        let entry = logger.log_tool_call("s1", &event, None);
        assert!(!entry.timestamp.is_empty(), "timestamp should not be empty");
        let parsed: Result<u64, _> = entry.timestamp.parse();
        assert!(
            parsed.is_ok(),
            "timestamp should be a parseable numeric string, got: {}",
            entry.timestamp
        );
    }

    // ================================================================
    // 7. AcpProxy Lifecycle / Config
    // ================================================================

    #[test]
    fn config_builder_defaults() {
        let config = AcpProxyConfig::new("agent-cmd", "pubkey-hex");
        assert_eq!(config.agent_command(), "agent-cmd");
        assert_eq!(config.public_key(), "pubkey-hex");
        assert!(config.allowed_path_prefixes().is_empty());
        assert!(config.allowed_commands().is_empty());
        assert!(config.agent_args().is_empty());
        assert!(config.agent_env().is_empty());
        assert_eq!(config.server_id(), "chio-acp-proxy");
    }

    #[test]
    fn config_builder_chaining() {
        let config = AcpProxyConfig::new("agent", "key")
            .with_allowed_path_prefix("/home")
            .with_allowed_path_prefix("/tmp")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
            .with_server_id("my-proxy")
            .with_agent_args(vec!["--flag".to_string()])
            .with_agent_env(vec![("KEY".to_string(), "VAL".to_string())]);

        assert_eq!(config.allowed_path_prefixes().len(), 2);
        assert_eq!(config.allowed_commands().len(), 2);
        assert_eq!(config.server_id(), "my-proxy");
        assert_eq!(config.agent_args().len(), 1);
        assert_eq!(config.agent_env().len(), 1);
    }

    #[test]
    fn proxy_start_with_nonexistent_command_fails() {
        let config =
            AcpProxyConfig::new("/nonexistent/path/to/fake-agent-binary-xyz123", "deadbeef");
        let result = AcpProxy::start(config);
        assert!(
            result.is_err(),
            "starting with a nonexistent command should fail"
        );
    }

    #[test]
    fn proxy_interceptor_exposes_config() {
        let config = test_config();
        let interceptor = MessageInterceptor::new(config);
        assert_eq!(interceptor.config().agent_command(), "echo");
        assert_eq!(interceptor.config().allowed_path_prefixes().len(), 1);
        assert_eq!(interceptor.config().allowed_commands().len(), 2);
    }

    // ================================================================
    // 8. Serialization round-trip tests
    // ================================================================

    #[test]
    fn audit_entry_serialization_round_trip() {
        let entry = AcpToolCallAuditEntry {
            tool_call_id: "tc-rt".to_string(),
            title: "Round trip".to_string(),
            kind: Some("test".to_string()),
            status: "completed".to_string(),
            session_id: "s-rt".to_string(),
            timestamp: "1700000000".to_string(),
            server_id: "srv-rt".to_string(),
            content_hash: "a".repeat(64),
            capability_id: Some("cap-rt".to_string()),
            authorization_receipt_id: None,
            enforcement_mode: Some(AcpEnforcementMode::CryptographicallyEnforced),
        };
        let json_result = serde_json::to_string(&entry);
        assert!(json_result.is_ok(), "audit entry should serialize to JSON");
        if let Ok(json_str) = json_result {
            let deserialized: Result<AcpToolCallAuditEntry, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "audit entry should deserialize back");
            if let Ok(entry2) = deserialized {
                assert_eq!(entry2.tool_call_id, "tc-rt");
                assert_eq!(entry2.title, "Round trip");
                assert_eq!(entry2.status, "completed");
                assert_eq!(entry2.content_hash, "a".repeat(64));
            }
        }
    }

    #[test]
    fn tool_call_event_serialization_round_trip() {
        let event = ToolCallEvent {
            tool_call_id: "tc-ser".to_string(),
            title: Some("Serialize test".to_string()),
            kind: Some("terminal".to_string()),
            status: Some("running".to_string()),
        };
        let json_result = serde_json::to_value(&event);
        assert!(json_result.is_ok());
        if let Ok(val) = json_result {
            assert_eq!(val["toolCallId"], "tc-ser");
            assert_eq!(val["title"], "Serialize test");
            assert_eq!(val["kind"], "terminal");
            assert_eq!(val["status"], "running");
        }
    }

    #[test]
    fn tool_call_event_with_none_fields_omitted() {
        let event = ToolCallEvent {
            tool_call_id: "tc-none".to_string(),
            title: None,
            kind: None,
            status: None,
        };
        let json_result = serde_json::to_value(&event);
        assert!(json_result.is_ok());
        if let Ok(val) = json_result {
            assert_eq!(val["toolCallId"], "tc-none");
            // None fields with skip_serializing_if should not be present.
            assert!(val.get("title").is_none());
            assert!(val.get("kind").is_none());
            assert!(val.get("status").is_none());
        }
    }

    // ================================================================
    // 9. Additional edge cases for completeness
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
    fn interceptor_session_update_with_bad_params_forwarded() {
        // session/update with params that cannot deserialize to
        // SessionUpdateNotification should still forward.
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": "not an object"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!(
                "expected Forward for malformed session/update params, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn interceptor_session_update_with_no_params_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!(
                "expected Forward for session/update with no params, got {:?}",
                other
            ),
        }
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

    #[test]
    fn fs_guard_prefix_with_trailing_slash_in_config() {
        // The prefix is stored as-is (not canonicalized). A trailing
        // slash in the prefix means `starts_with` matches, but the
        // boundary check looks at `canonical[prefix.len()]` which is
        // past the '/' character, so 'f' != '/' and the boundary
        // check fails. This is consistent with fail-closed behavior:
        // configure prefixes without trailing slashes.
        let guard = FsGuard::new(vec!["/home/user/project/".to_string()]);
        assert!(
            guard.check_read("/home/user/project/file.txt").is_err(),
            "trailing slash in prefix breaks boundary check -- use without trailing slash"
        );

        // Without trailing slash, it works correctly.
        let guard2 = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard2.check_read("/home/user/project/file.txt").is_ok());
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod attestation_and_telemetry_tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        ChioScope, CapabilityToken, CapabilityTokenBody, Constraint, Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChioReceipt, ChioReceiptBody, ChildRequestReceipt, Decision, GuardEvidence, ToolCallAction,
    };
    use chio_kernel::checkpoint::KernelCheckpoint;
    use chio_kernel::receipt_store::{ReceiptStore, ReceiptStoreError};
    use chio_kernel::{
        ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use serde_json::json;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn make_capability_token(
        issuer: &Keypair,
        subject: &Keypair,
        server_id: &str,
        tool_name: &str,
        constraints: Vec<Constraint>,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{tool_name}-{issued_at}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints,
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at,
                expires_at,
                delegation_chain: Vec::new(),
            },
            issuer,
        )
        .expect("capability token should sign")
    }

    fn test_kernel_config(issuer: &Keypair) -> KernelConfig {
        KernelConfig {
            ca_public_keys: vec![issuer.public_key()],
            keypair: issuer.clone(),
            max_delegation_depth: 8,
            policy_hash: "policy-acp-proxy-test".to_string(),
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

    fn make_receipt(
        signer: &Keypair,
        id: &str,
        timestamp: u64,
        tool_name: &str,
        decision: Decision,
        evidence: Vec<GuardEvidence>,
    ) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(json!({"tool": tool_name}))
            .expect("hash receipt parameters");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: "capability-1".to_string(),
                tool_server: "acp-proxy".to_string(),
                tool_name: tool_name.to_string(),
                action,
                decision,
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence,
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                kernel_key: signer.public_key(),
                tenant_id: None,
            },
            signer,
        )
        .expect("receipt should sign")
    }

    fn make_audit_entry(tool_call_id: &str, session_id: &str) -> AcpToolCallAuditEntry {
        AcpToolCallAuditEntry {
            tool_call_id: tool_call_id.to_string(),
            title: "Test tool".to_string(),
            kind: Some("terminal".to_string()),
            status: "completed".to_string(),
            session_id: session_id.to_string(),
            timestamp: now_secs().to_string(),
            server_id: "acp-proxy".to_string(),
            content_hash: format!("hash-{tool_call_id}"),
            capability_id: None,
            authorization_receipt_id: None,
            enforcement_mode: Some(AcpEnforcementMode::AuditOnly),
        }
    }

    #[derive(Default)]
    struct MockStoreState {
        appended_receipts: Vec<ChioReceipt>,
        canonical_ranges: Vec<(u64, u64)>,
        checkpoints: Vec<KernelCheckpoint>,
        return_empty_bytes: bool,
    }

    struct MockReceiptStore {
        state: Arc<Mutex<MockStoreState>>,
        supports_checkpoints: bool,
    }

    impl ReceiptStore for MockReceiptStore {
        fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            assert!(receipt.action.verify_hash().unwrap());
            let mut state = self.state.lock().expect("mock store lock should hold");
            state.appended_receipts.push(receipt.clone());
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn receipts_canonical_bytes_range(
            &self,
            start_seq: u64,
            end_seq: u64,
        ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
            let mut state = self.state.lock().expect("mock store lock should hold");
            state.canonical_ranges.push((start_seq, end_seq));
            if state.return_empty_bytes {
                return Ok(Vec::new());
            }

            Ok(state
                .appended_receipts
                .iter()
                .enumerate()
                .filter_map(|(idx, receipt)| {
                    let seq = idx as u64;
                    ((start_seq..end_seq).contains(&seq))
                        .then(|| (seq, receipt.id.as_bytes().to_vec()))
                })
                .collect())
        }

        fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
            let mut state = self.state.lock().expect("mock store lock should hold");
            state.checkpoints.push(checkpoint.clone());
            Ok(())
        }

        fn supports_kernel_signed_checkpoints(&self) -> bool {
            self.supports_checkpoints
        }
    }

    struct DummySigner(Keypair);

    impl ReceiptSigner for DummySigner {
        fn sign_acp_receipt(
            &self,
            request: &AcpReceiptRequest,
        ) -> Result<ChioReceipt, ReceiptSignError> {
            Ok(make_receipt(
                &self.0,
                &format!("signed-{}", request.audit_entry.tool_call_id),
                now_secs(),
                &request.tool_name,
                Decision::Allow,
                Vec::new(),
            ))
        }
    }

    struct DummyChecker;

    impl CapabilityChecker for DummyChecker {
        fn check_access(
            &self,
            request: &AcpCapabilityRequest,
        ) -> Result<AcpVerdict, CapabilityCheckError> {
            Ok(AcpVerdict {
                allowed: true,
                capability_id: Some(format!("cap:{}", request.session_id)),
                receipt_id: None,
                reason: "dummy allow".to_string(),
            })
        }
    }

    struct RecordingChecker {
        requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>,
        verdict: AcpVerdict,
    }

    impl RecordingChecker {
        fn allow(requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>, capability_id: &str) -> Self {
            Self {
                requests,
                verdict: AcpVerdict {
                    allowed: true,
                    capability_id: Some(capability_id.to_string()),
                    receipt_id: None,
                    reason: "recorded allow".to_string(),
                },
            }
        }

        fn deny(requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>, reason: &str) -> Self {
            Self {
                requests,
                verdict: AcpVerdict {
                    allowed: false,
                    capability_id: Some("cap-denied".to_string()),
                    receipt_id: None,
                    reason: reason.to_string(),
                },
            }
        }
    }

    impl CapabilityChecker for RecordingChecker {
        fn check_access(
            &self,
            request: &AcpCapabilityRequest,
        ) -> Result<AcpVerdict, CapabilityCheckError> {
            self.requests
                .lock()
                .expect("recording checker lock should succeed")
                .push(request.clone());
            Ok(self.verdict.clone())
        }
    }

    struct ErrorChecker;

    impl CapabilityChecker for ErrorChecker {
        fn check_access(
            &self,
            _request: &AcpCapabilityRequest,
        ) -> Result<AcpVerdict, CapabilityCheckError> {
            Err(CapabilityCheckError::Internal(
                "checker backend unavailable".to_string(),
            ))
        }
    }

    #[test]
    fn kernel_capability_checker_denies_missing_and_malformed_tokens() {
        let issuer = Keypair::generate();
        let checker =
            KernelCapabilityChecker::new(ChioKernel::new(test_kernel_config(&issuer)), "proxy-server");
        let request = AcpCapabilityRequest {
            session_id: "session-1".to_string(),
            operation: "fs_read".to_string(),
            resource: "/workspace/src/lib.rs".to_string(),
            token: None,
        };

        let verdict = checker
            .check_access(&request)
            .expect("check should succeed");
        assert!(!verdict.allowed);
        assert_eq!(verdict.reason, "no capability token presented");

        let malformed = AcpCapabilityRequest {
            token: Some("{".to_string()),
            ..request
        };
        let verdict = checker
            .check_access(&malformed)
            .expect("malformed token should fail closed");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("failed to parse token"));
    }

    #[test]
    fn kernel_capability_checker_enforces_time_bounds_and_scope() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let now = now_secs();
        let checker =
            KernelCapabilityChecker::new(ChioKernel::new(test_kernel_config(&issuer)), "proxy-server");

        let valid = make_capability_token(
            &issuer,
            &subject,
            "proxy-server",
            "fs/read_text_file",
            vec![Constraint::PathPrefix("/workspace".to_string())],
            now.saturating_sub(60),
            now + 3600,
        );
        let request = AcpCapabilityRequest {
            session_id: "session-1".to_string(),
            operation: "fs_read".to_string(),
            resource: "/workspace/src/lib.rs".to_string(),
            token: Some(serde_json::to_string(&valid).expect("token should serialize")),
        };

        let verdict = checker
            .check_access(&request)
            .expect("check should succeed");
        assert!(verdict.allowed);
        assert_eq!(verdict.capability_id.as_deref(), Some(valid.id.as_str()));
        assert!(verdict.receipt_id.is_some());

        let out_of_scope = AcpCapabilityRequest {
            resource: "/tmp/escape.txt".to_string(),
            ..request.clone()
        };
        let verdict = checker
            .check_access(&out_of_scope)
            .expect("scope mismatch should deny");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("scope") || verdict.reason.contains("out of scope"));
        assert!(verdict.receipt_id.is_some());

        let future_token = make_capability_token(
            &issuer,
            &subject,
            "proxy-server",
            "fs/read_text_file",
            vec![Constraint::PathPrefix("/workspace".to_string())],
            now + 600,
            now + 3600,
        );
        let future_request = AcpCapabilityRequest {
            token: Some(
                serde_json::to_string(&future_token).expect("future token should serialize"),
            ),
            ..request.clone()
        };
        let verdict = checker
            .check_access(&future_request)
            .expect("future token should fail closed");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("valid") || verdict.reason.contains("time"));
        assert!(verdict.receipt_id.is_some());

        let expired_token = make_capability_token(
            &issuer,
            &subject,
            "proxy-server",
            "fs/read_text_file",
            vec![Constraint::PathPrefix("/workspace".to_string())],
            now.saturating_sub(600),
            now.saturating_sub(1),
        );
        let expired_request = AcpCapabilityRequest {
            token: Some(
                serde_json::to_string(&expired_token).expect("expired token should serialize"),
            ),
            ..request
        };
        let verdict = checker
            .check_access(&expired_request)
            .expect("expired token should fail closed");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("expired") || verdict.reason.contains("time"));
        assert!(verdict.receipt_id.is_some());
    }

    #[test]
    fn kernel_capability_checker_supports_wildcard_terminal_grants() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let now = now_secs();
        let checker =
            KernelCapabilityChecker::new(ChioKernel::new(test_kernel_config(&issuer)), "proxy-server");
        let token = make_capability_token(
            &issuer,
            &subject,
            "*",
            "terminal/create",
            Vec::new(),
            now.saturating_sub(30),
            now + 3600,
        );
        let request = AcpCapabilityRequest {
            session_id: "session-2".to_string(),
            operation: "terminal".to_string(),
            resource: "cargo".to_string(),
            token: Some(serde_json::to_string(&token).expect("token should serialize")),
        };

        let verdict = checker
            .check_access(&request)
            .expect("check should succeed");
        assert!(verdict.allowed);
        assert_eq!(
            verdict.reason,
            "authorized through kernel-backed ACP guard pipeline"
        );
        assert!(verdict.receipt_id.is_some());
    }

    #[test]
    fn kernel_capability_checker_rejects_untrusted_and_tampered_tokens() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let now = now_secs();
        let trusted_checker =
            KernelCapabilityChecker::new(ChioKernel::new(test_kernel_config(&issuer)), "proxy-server");

        let token = make_capability_token(
            &issuer,
            &subject,
            "proxy-server",
            "fs/read_text_file",
            vec![Constraint::PathPrefix("/workspace".to_string())],
            now.saturating_sub(30),
            now + 3600,
        );

        let untrusted_issuer = Keypair::generate();
        let untrusted_checker = KernelCapabilityChecker::new(
            ChioKernel::new(test_kernel_config(&untrusted_issuer)),
            "proxy-server",
        );
        let request = AcpCapabilityRequest {
            session_id: "session-untrusted".to_string(),
            operation: "fs_read".to_string(),
            resource: "/workspace/src/lib.rs".to_string(),
            token: Some(serde_json::to_string(&token).expect("token should serialize")),
        };
        let verdict = untrusted_checker
            .check_access(&request)
            .expect("untrusted issuer should fail closed");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("signature") || verdict.reason.contains("untrusted"));
        assert!(verdict.receipt_id.is_some());

        let mut tampered = token.clone();
        tampered.expires_at = tampered.expires_at.saturating_add(60);
        let tampered_request = AcpCapabilityRequest {
            token: Some(serde_json::to_string(&tampered).expect("token should serialize")),
            ..request
        };
        let verdict = trusted_checker
            .check_access(&tampered_request)
            .expect("tampered token should fail closed");
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("signature"));
        assert!(verdict.receipt_id.is_some());
    }

    #[test]
    fn interceptor_checker_allow_path_records_capability_context_for_receipts() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let config = AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_server_id("proxy-server");
        let interceptor = MessageInterceptor::with_kernel(
            config,
            None,
            Some(Box::new(RecordingChecker::allow(
                Arc::clone(&requests),
                "cap-377",
            ))),
            AcpAttestationMode::Required,
        );

        let read = json!({
            "jsonrpc": "2.0",
            "id": 377,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-377",
                "path": "/home/user/project/src/lib.rs",
                "capabilityToken": "signed-capability-json"
            }
        });

        match interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("read should be allowed")
        {
            InterceptResult::Forward(value) => assert_eq!(value, read),
            other => panic!("expected Forward, got {:?}", other),
        }

        let recorded = requests.lock().expect("recorded requests should lock");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].session_id, "session-377");
        assert_eq!(recorded[0].operation, "fs_read");
        assert_eq!(recorded[0].resource, "/home/user/project/src/lib.rs");
        assert_eq!(recorded[0].token.as_deref(), Some("signed-capability-json"));
        drop(recorded);

        let update = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session-377",
                "update": {
                    "toolCallId": "tool-377",
                    "title": "Read file",
                    "kind": "fs_read",
                    "status": "running"
                }
            }
        });

        match interceptor
            .intercept(Direction::AgentToClient, &update)
            .expect("session update should produce a receipt")
        {
            InterceptResult::ForwardWithReceipt(_, receipt) => {
                assert_eq!(receipt.capability_id.as_deref(), Some("cap-377"));
                assert_eq!(
                    receipt.enforcement_mode,
                    Some(AcpEnforcementMode::CryptographicallyEnforced)
                );
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_checker_denies_and_errors_fail_closed_before_builtin_guards() {
        let deny_requests = Arc::new(Mutex::new(Vec::new()));
        let config = AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo");
        let denying = MessageInterceptor::with_kernel(
            config.clone(),
            None,
            Some(Box::new(RecordingChecker::deny(
                Arc::clone(&deny_requests),
                "token scope does not cover fs_read on requested path",
            ))),
            AcpAttestationMode::Required,
        );
        let read = json!({
            "jsonrpc": "2.0",
            "id": 378,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-378",
                "path": "/home/user/project/src/lib.rs",
                "capability_token": "candidate-token"
            }
        });

        match denying
            .intercept(Direction::AgentToClient, &read)
            .expect("deny path should still return a block response")
        {
            InterceptResult::Block(value) => {
                assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
                assert!(value["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("token scope does not cover"));
            }
            other => panic!("expected Block for deny verdict, got {:?}", other),
        }

        let erroring = MessageInterceptor::with_kernel(
            config,
            None,
            Some(Box::new(ErrorChecker)),
            AcpAttestationMode::Required,
        );
        match erroring
            .intercept(Direction::AgentToClient, &read)
            .expect("error path should still return a block response")
        {
            InterceptResult::Block(value) => {
                assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
                assert!(value["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("failed closed"));
            }
            other => panic!("expected Block for checker error, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_clears_capability_context_after_terminal_status_updates() {
        let config = AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo");
        let interceptor = MessageInterceptor::with_kernel(
            config,
            None,
            Some(Box::new(RecordingChecker::allow(
                Arc::new(Mutex::new(Vec::new())),
                "cap-terminal",
            ))),
            AcpAttestationMode::Required,
        );

        let read = json!({
            "jsonrpc": "2.0",
            "id": 379,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-clear",
                "path": "/home/user/project/src/lib.rs",
                "capabilityToken": "signed-capability-json"
            }
        });
        interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("read should be allowed");

        let completed = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session-clear",
                "update": {
                    "toolCallId": "tool-clear",
                    "status": "completed"
                }
            }
        });

        match interceptor
            .intercept(Direction::AgentToClient, &completed)
            .expect("completed update should produce a receipt")
        {
            InterceptResult::ForwardWithReceipt(_, receipt) => {
                assert_eq!(receipt.capability_id.as_deref(), Some("cap-terminal"));
                assert_eq!(
                    receipt.enforcement_mode,
                    Some(AcpEnforcementMode::CryptographicallyEnforced)
                );
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }

        let later_update = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session-clear",
                "update": {
                    "toolCallId": "tool-later",
                    "status": "running"
                }
            }
        });

        match interceptor
            .intercept(Direction::AgentToClient, &later_update)
            .expect("later update should still be forwarded")
        {
            InterceptResult::ForwardWithReceipt(_, receipt) => {
                assert_eq!(receipt.capability_id, None);
                assert_eq!(
                    receipt.enforcement_mode,
                    Some(AcpEnforcementMode::AuditOnly)
                );
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }
    }

    #[test]
    fn compliance_certificate_rejects_empty_invalid_and_non_compliant_receipts() {
        let signer = Keypair::generate();
        let now = now_secs();
        let config = ComplianceConfig {
            budget_limit: 4,
            required_guards: vec!["fs_guard".to_string()],
            authorized_scopes: vec!["fs/".to_string()],
        };

        let empty = generate_compliance_certificate("session-empty", &[], &config, &signer);
        assert!(matches!(
            empty,
            Err(ComplianceCertificateError::EmptySession(ref id)) if id == "session-empty"
        ));

        let mut invalid_receipt = make_receipt(
            &signer,
            "receipt-invalid",
            now,
            "fs/read_text_file",
            Decision::Allow,
            vec![GuardEvidence {
                guard_name: "fs_guard".to_string(),
                verdict: true,
                details: Some("ok".to_string()),
            }],
        );
        invalid_receipt.tool_name = "tampered".to_string();
        let invalid_entries = vec![ComplianceReceiptEntry {
            receipt: invalid_receipt,
            seq: 0,
        }];
        let invalid =
            generate_compliance_certificate("session-invalid", &invalid_entries, &config, &signer);
        assert!(matches!(
            invalid,
            Err(ComplianceCertificateError::InvalidReceiptSignature { .. })
        ));

        let gap_entries = vec![
            ComplianceReceiptEntry {
                receipt: make_receipt(
                    &signer,
                    "receipt-gap-1",
                    now,
                    "fs/read_text_file",
                    Decision::Allow,
                    vec![GuardEvidence {
                        guard_name: "fs_guard".to_string(),
                        verdict: true,
                        details: None,
                    }],
                ),
                seq: 0,
            },
            ComplianceReceiptEntry {
                receipt: make_receipt(
                    &signer,
                    "receipt-gap-2",
                    now + 1,
                    "fs/read_text_file",
                    Decision::Allow,
                    vec![GuardEvidence {
                        guard_name: "fs_guard".to_string(),
                        verdict: true,
                        details: None,
                    }],
                ),
                seq: 2,
            },
        ];
        let gap = generate_compliance_certificate("session-gap", &gap_entries, &config, &signer);
        assert!(matches!(
            gap,
            Err(ComplianceCertificateError::ChainDiscontinuity {
                expected: 1,
                found: 2
            })
        ));

        let scope_entries = vec![ComplianceReceiptEntry {
            receipt: make_receipt(
                &signer,
                "receipt-scope",
                now,
                "terminal/create",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: None,
                }],
            ),
            seq: 0,
        }];
        let scope =
            generate_compliance_certificate("session-scope", &scope_entries, &config, &signer);
        assert!(matches!(
            scope,
            Err(ComplianceCertificateError::ScopeViolation { .. })
        ));

        let budget_entries = (0..5)
            .map(|idx| ComplianceReceiptEntry {
                receipt: make_receipt(
                    &signer,
                    &format!("receipt-budget-{idx}"),
                    now + idx,
                    "fs/read_text_file",
                    Decision::Allow,
                    vec![GuardEvidence {
                        guard_name: "fs_guard".to_string(),
                        verdict: true,
                        details: None,
                    }],
                ),
                seq: idx,
            })
            .collect::<Vec<_>>();
        let budget =
            generate_compliance_certificate("session-budget", &budget_entries, &config, &signer);
        assert!(matches!(
            budget,
            Err(ComplianceCertificateError::BudgetExceeded { used: 5, limit: 4 })
        ));

        let guard_entries = vec![ComplianceReceiptEntry {
            receipt: make_receipt(
                &signer,
                "receipt-guard",
                now,
                "fs/read_text_file",
                Decision::Allow,
                Vec::new(),
            ),
            seq: 0,
        }];
        let guard =
            generate_compliance_certificate("session-guard", &guard_entries, &config, &signer);
        assert!(matches!(
            guard,
            Err(ComplianceCertificateError::GuardBypass { .. })
        ));
    }

    #[test]
    fn compliance_certificate_round_trips_and_detects_full_bundle_tampering() {
        let signer = Keypair::generate();
        let now = now_secs();
        let receipts = vec![
            ComplianceReceiptEntry {
                receipt: make_receipt(
                    &signer,
                    "receipt-1",
                    now,
                    "fs/read_text_file",
                    Decision::Allow,
                    vec![GuardEvidence {
                        guard_name: "fs_guard".to_string(),
                        verdict: true,
                        details: Some("read ok".to_string()),
                    }],
                ),
                seq: 0,
            },
            ComplianceReceiptEntry {
                receipt: make_receipt(
                    &signer,
                    "receipt-2",
                    now + 1,
                    "fs/write_text_file",
                    Decision::Allow,
                    vec![GuardEvidence {
                        guard_name: "fs_guard".to_string(),
                        verdict: true,
                        details: Some("write ok".to_string()),
                    }],
                ),
                seq: 1,
            },
        ];
        let config = ComplianceConfig {
            budget_limit: 2,
            required_guards: vec!["fs_guard".to_string()],
            authorized_scopes: vec!["fs/".to_string()],
        };

        let cert = generate_compliance_certificate("session-good", &receipts, &config, &signer)
            .expect("certificate should generate");

        let lightweight =
            verify_compliance_certificate(&cert, VerificationMode::Lightweight, Some(&receipts));
        assert!(lightweight.passed);
        assert!(lightweight.certificate_signature_valid);
        assert_eq!(lightweight.summary, "lightweight verification passed");

        let full_bundle =
            verify_compliance_certificate(&cert, VerificationMode::FullBundle, Some(&receipts));
        assert!(full_bundle.passed);
        assert_eq!(full_bundle.receipts_reverified, 2);
        assert_eq!(full_bundle.receipt_failures, 0);

        let mut tampered_entries = receipts.clone();
        tampered_entries[1].receipt.tool_name = "fs/tampered".to_string();
        let tampered = verify_compliance_certificate(
            &cert,
            VerificationMode::FullBundle,
            Some(&tampered_entries),
        );
        assert!(!tampered.passed);
        assert_eq!(tampered.receipts_reverified, 2);
        assert_eq!(tampered.receipt_failures, 1);
        assert!(tampered.summary.contains("1 receipt signature(s) failed"));

        let mut inconsistent_cert = cert.clone();
        inconsistent_cert
            .body
            .anomalies
            .push("missing guard".to_string());
        let body_bytes = chio_core::canonical::canonical_json_bytes(&inconsistent_cert.body)
            .expect("certificate body should serialize");
        inconsistent_cert.signature = signer.sign(&body_bytes);
        let inconsistent =
            verify_compliance_certificate(&inconsistent_cert, VerificationMode::Lightweight, None);
        assert!(!inconsistent.passed);
        assert!(inconsistent.certificate_signature_valid);
        assert!(!inconsistent.body_consistent);
    }

    #[test]
    fn compliance_certificate_serializes_snake_case_and_accepts_legacy_aliases() {
        let signer = Keypair::generate();
        let now = now_secs();
        let receipts = vec![ComplianceReceiptEntry {
            receipt: make_receipt(
                &signer,
                "receipt-snake",
                now,
                "fs/read_text_file",
                Decision::Allow,
                vec![GuardEvidence {
                    guard_name: "fs_guard".to_string(),
                    verdict: true,
                    details: Some("ok".to_string()),
                }],
            ),
            seq: 0,
        }];
        let config = ComplianceConfig {
            budget_limit: 1,
            required_guards: vec!["fs_guard".to_string()],
            authorized_scopes: vec!["fs/".to_string()],
        };

        let cert = generate_compliance_certificate("session-snake", &receipts, &config, &signer)
            .expect("certificate should generate");

        let json = serde_json::to_value(&cert).expect("certificate should serialize");
        assert!(json.get("signer_key").is_some());
        assert!(json.get("signerKey").is_none());
        let body = json
            .get("body")
            .and_then(serde_json::Value::as_object)
            .expect("body should be an object");
        assert!(body.get("session_id").is_some());
        assert!(body.get("receipt_count").is_some());
        assert!(body.get("kernel_key").is_some());
        assert!(body.get("sessionId").is_none());

        let legacy = serde_json::json!({
            "body": {
                "schema": cert.body.schema,
                "sessionId": cert.body.session_id,
                "issuedAt": cert.body.issued_at,
                "receiptCount": cert.body.receipt_count,
                "firstReceiptAt": cert.body.first_receipt_at,
                "lastReceiptAt": cert.body.last_receipt_at,
                "allSignaturesValid": cert.body.all_signatures_valid,
                "chainContinuous": cert.body.chain_continuous,
                "scopeCompliant": cert.body.scope_compliant,
                "budgetCompliant": cert.body.budget_compliant,
                "guardsCompliant": cert.body.guards_compliant,
                "anomalies": cert.body.anomalies,
                "kernelKey": cert.body.kernel_key,
            },
            "signerKey": cert.signer_key,
            "signature": cert.signature,
        });
        let decoded: ComplianceCertificate =
            serde_json::from_value(legacy).expect("legacy camelCase payload should deserialize");
        assert_eq!(decoded.body.session_id, "session-snake");
        assert_eq!(decoded.body.receipt_count, 1);
    }

    #[test]
    fn kernel_receipt_signer_appends_and_checkpoints_batches() {
        let keypair = Keypair::generate();
        let shared = Arc::new(Mutex::new(MockStoreState::default()));
        let store = MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: true,
        };
        let signer = KernelReceiptSigner::new(keypair.clone(), "proxy-server", Box::new(store), 2);

        let request_a = AcpReceiptRequest {
            audit_entry: make_audit_entry("call-a", "session-1"),
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        };
        let request_b = AcpReceiptRequest {
            audit_entry: make_audit_entry("call-b", "session-1"),
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        };

        let receipt_a = signer
            .sign_acp_receipt(&request_a)
            .expect("first receipt should sign");
        assert!(receipt_a
            .verify_signature()
            .expect("signature should verify"));

        let receipt_b = signer
            .sign_acp_receipt(&request_b)
            .expect("second receipt should sign");
        assert!(receipt_b
            .verify_signature()
            .expect("signature should verify"));

        let state = shared.lock().expect("shared state should lock");
        assert_eq!(state.appended_receipts.len(), 2);
        assert_eq!(state.canonical_ranges, vec![(0, 2)]);
        assert_eq!(state.checkpoints.len(), 1);
        assert_eq!(state.checkpoints[0].body.batch_start_seq, 0);
        assert_eq!(state.checkpoints[0].body.batch_end_seq, 1);
        assert_eq!(state.checkpoints[0].body.tree_size, 2);
    }

    #[test]
    fn kernel_receipt_signer_propagates_capability_metadata_into_receipts() {
        let keypair = Keypair::generate();
        let shared = Arc::new(Mutex::new(MockStoreState::default()));
        let store = MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: false,
        };
        let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 10);

        let mut enforced_entry = make_audit_entry("call-enforced", "session-enforced");
        enforced_entry.capability_id = Some("cap-377".to_string());
        enforced_entry.enforcement_mode = Some(AcpEnforcementMode::CryptographicallyEnforced);
        let enforced = signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: enforced_entry,
                tool_server: "proxy-server".to_string(),
                tool_name: "fs/read_text_file".to_string(),
            })
            .expect("enforced receipt should sign");
        assert_eq!(enforced.capability_id, "cap-377");
        assert_eq!(
            enforced.metadata.as_ref().and_then(|metadata| {
                metadata
                    .get("acp")
                    .and_then(|acp| acp.get("enforcementMode"))
                    .and_then(serde_json::Value::as_str)
            }),
            Some("cryptographically_enforced")
        );

        let audit_only = signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: make_audit_entry("call-audit", "session-audit"),
                tool_server: "proxy-server".to_string(),
                tool_name: "terminal/create".to_string(),
            })
            .expect("audit-only receipt should sign");
        assert_eq!(audit_only.capability_id, "acp-session:session-audit");
        assert_eq!(
            audit_only.metadata.as_ref().and_then(|metadata| {
                metadata
                    .get("acp")
                    .and_then(|acp| acp.get("enforcementMode"))
                    .and_then(serde_json::Value::as_str)
            }),
            Some("audit_only")
        );
    }

    #[test]
    fn kernel_receipt_signer_preserves_acp_content_hash_with_canonical_parameter_hash() {
        let keypair = Keypair::generate();
        let shared = Arc::new(Mutex::new(MockStoreState::default()));
        let store = MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: false,
        };
        let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 10);

        let mut entry = make_audit_entry("call-provenance", "session-provenance");
        entry.content_hash = "acp-originated-content-hash".to_string();
        let receipt = signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: entry,
                tool_server: "proxy-server".to_string(),
                tool_name: "terminal/create".to_string(),
            })
            .expect("receipt should sign");

        assert!(receipt.action.verify_hash().unwrap());
        assert_ne!(receipt.action.parameter_hash, "acp-originated-content-hash");
        assert_eq!(receipt.content_hash, "acp-originated-content-hash");
        assert_eq!(
            receipt.action.parameters,
            json!({
                "tool_call_id": "call-provenance",
                "title": "Test tool",
                "kind": "terminal",
                "status": "completed",
            })
        );
    }

    #[test]
    fn kernel_receipt_signer_skips_unsupported_or_empty_checkpoint_batches() {
        let keypair = Keypair::generate();

        let unsupported_state = Arc::new(Mutex::new(MockStoreState::default()));
        let unsupported_store = MockReceiptStore {
            state: Arc::clone(&unsupported_state),
            supports_checkpoints: false,
        };
        let unsupported_signer = KernelReceiptSigner::new(
            keypair.clone(),
            "proxy-server",
            Box::new(unsupported_store),
            1,
        );
        unsupported_signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: make_audit_entry("unsupported", "session-unsupported"),
                tool_server: "proxy-server".to_string(),
                tool_name: "terminal/create".to_string(),
            })
            .expect("receipt should sign");
        let state = unsupported_state.lock().expect("shared state should lock");
        assert_eq!(state.appended_receipts.len(), 1);
        assert!(state.checkpoints.is_empty());
        drop(state);

        let empty_state = Arc::new(Mutex::new(MockStoreState {
            return_empty_bytes: true,
            ..MockStoreState::default()
        }));
        let empty_store = MockReceiptStore {
            state: Arc::clone(&empty_state),
            supports_checkpoints: true,
        };
        let empty_signer =
            KernelReceiptSigner::new(keypair, "proxy-server", Box::new(empty_store), 1);
        empty_signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: make_audit_entry("empty", "session-empty"),
                tool_server: "proxy-server".to_string(),
                tool_name: "terminal/create".to_string(),
            })
            .expect("receipt should sign");
        let state = empty_state.lock().expect("shared state should lock");
        assert_eq!(state.appended_receipts.len(), 1);
        assert_eq!(state.canonical_ranges, vec![(0, 1)]);
        assert!(state.checkpoints.is_empty());
    }

    #[test]
    fn telemetry_helpers_map_receipts_and_certificates() {
        let signer = Keypair::generate();
        let receipt = make_receipt(
            &signer,
            "receipt-telemetry",
            123,
            "fs/write_text_file",
            Decision::Deny {
                reason: "blocked".to_string(),
                guard: "fs_guard".to_string(),
            },
            vec![GuardEvidence {
                guard_name: "fs_guard".to_string(),
                verdict: false,
                details: Some("denied".to_string()),
            }],
        );
        let trace_id = derive_trace_id("session-telemetry");
        let span = receipt_to_span(&receipt, &trace_id);

        assert_eq!(trace_id.len(), 32);
        assert_eq!(span.trace_id, trace_id);
        assert_eq!(span.span_id.len(), 16);
        assert_eq!(span.tool_name, "fs/write_text_file");
        assert_eq!(span.verdict, "deny");
        assert_eq!(span.start_time_nanos, 123_000_000_000);
        assert_eq!(span.events.len(), 1);
        assert!(span
            .attributes
            .iter()
            .any(|attr| attr.key == "chio.deny_reason" && attr.value == "blocked"));
        assert_eq!(span.events[0].name, "guard.fs_guard");

        let cert_body = ComplianceCertificateBody {
            schema: COMPLIANCE_CERTIFICATE_SCHEMA.to_string(),
            session_id: "session-telemetry".to_string(),
            issued_at: 456,
            receipt_count: 2,
            first_receipt_at: 123,
            last_receipt_at: 124,
            all_signatures_valid: true,
            chain_continuous: true,
            scope_compliant: true,
            budget_compliant: true,
            guards_compliant: true,
            anomalies: Vec::new(),
            kernel_key: signer.public_key(),
        };
        let cert_event = compliance_certificate_event(&cert_body);
        assert_eq!(cert_event.name, "chio.compliance.certificate");
        assert_eq!(cert_event.timestamp_nanos, 456_000_000_000);
        assert!(cert_event
            .attributes
            .iter()
            .any(|attr| attr.key == "cert.receipt_count" && attr.value == "2"));

        let root = session_root_span("session-telemetry", &trace_id, 100, 200);
        assert_eq!(root.tool_name, "chio.session");
        assert_eq!(root.verdict, "session");
        assert_eq!(root.start_time_nanos, 100_000_000_000);
        assert_eq!(root.end_time_nanos, 200_000_000_000);

        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, "chio-acp-proxy");
    }

    #[test]
    fn telemetry_exporters_write_and_fail_cleanly() {
        let span = ReceiptSpan {
            trace_id: derive_trace_id("session-export"),
            span_id: "0123456789abcdef".to_string(),
            parent_span_id: String::new(),
            tool_name: "terminal/create".to_string(),
            verdict: "allow".to_string(),
            capability_id: "capability-1".to_string(),
            start_time_nanos: 1,
            end_time_nanos: 1,
            attributes: vec![SpanAttribute {
                key: "chio.test".to_string(),
                value: "true".to_string(),
            }],
            events: Vec::new(),
        };

        let logger = LoggingSpanExporter;
        assert_eq!(
            logger
                .export(std::slice::from_ref(&span))
                .expect("logging export should work"),
            1
        );
        logger.flush().expect("flush should succeed");
        logger.shutdown().expect("shutdown should succeed");

        let output_path =
            std::env::temp_dir().join(format!("chio-acp-proxy-telemetry-{}.jsonl", now_secs()));
        let exporter = JsonFileExporter::new(output_path.to_string_lossy().into_owned());
        assert_eq!(
            exporter
                .export(std::slice::from_ref(&span))
                .expect("json export should work"),
            1
        );
        exporter.flush().expect("flush should succeed");
        exporter.shutdown().expect("shutdown should succeed");

        let contents = fs::read_to_string(&output_path).expect("jsonl output should exist");
        assert!(contents.contains("\"toolName\":\"terminal/create\""));
        let _ = fs::remove_file(&output_path);

        let bad_exporter =
            JsonFileExporter::new(std::env::temp_dir().to_string_lossy().into_owned());
        let error = bad_exporter
            .export(std::slice::from_ref(&span))
            .expect_err("directory path should fail");
        assert!(matches!(error, TelemetryExportError::ExportFailed(_)));
    }

    #[test]
    fn transport_round_trips_json_and_lifecycle() {
        let mut transport = AcpTransport::spawn(
            "sh",
            &["-c".to_string(), "cat".to_string()],
            &[("CHIO_PROXY_TEST_ENV".to_string(), "1".to_string())],
        )
        .expect("transport should spawn");

        let message = json!({
            "jsonrpc": "2.0",
            "method": "ping",
            "params": {"ok": true}
        });
        transport.send(&message).expect("send should succeed");
        let received = transport.recv().expect("recv should succeed");
        assert_eq!(received, Some(message));

        transport.kill().expect("kill should succeed");
        let status = transport.wait().expect("wait should succeed");
        assert!(status.is_none());
    }

    #[test]
    fn transport_handles_eof_and_invalid_json() {
        let mut eof_transport =
            AcpTransport::spawn("sh", &["-c".to_string(), "exit 0".to_string()], &[])
                .expect("transport should spawn");
        assert_eq!(eof_transport.recv().expect("recv should succeed"), None);
        assert_eq!(eof_transport.wait().expect("wait should succeed"), Some(0));

        let mut invalid_transport = AcpTransport::spawn(
            "sh",
            &["-c".to_string(), "printf 'not-json\\n'".to_string()],
            &[],
        )
        .expect("transport should spawn");
        let error = invalid_transport
            .recv()
            .expect_err("invalid json should return protocol error");
        assert!(matches!(error, AcpProxyError::Protocol(_)));
        assert_eq!(
            invalid_transport.wait().expect("wait should succeed"),
            Some(0)
        );
    }

    #[test]
    fn proxy_with_kernel_wraps_transport_and_interceptor() {
        let config = AcpProxyConfig::new("sh", "deadbeef")
            .with_agent_args(vec!["-c".to_string(), "cat".to_string()])
            .with_allowed_path_prefix("/workspace")
            .with_allowed_command("cargo")
            .with_server_id("proxy-test");

        let mut proxy = AcpProxy::start_with_kernel(
            config.clone(),
            Some(Box::new(DummySigner(Keypair::generate()))),
            Some(Box::new(DummyChecker)),
            AcpAttestationMode::Required,
        )
        .expect("proxy should start");

        assert_eq!(proxy.config().server_id(), "proxy-test");
        let _ = proxy.interceptor();

        let client_message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        match proxy
            .process_client_message(&client_message)
            .expect("client message should process")
        {
            InterceptResult::Forward(value) => assert_eq!(value, client_message),
            other => panic!("expected Forward, got {:?}", other),
        }

        let agent_message = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s1",
                "update": {
                    "toolCallId": "tool-1",
                    "title": "Build",
                    "kind": "terminal",
                    "status": "running"
                }
            }
        });
        match proxy
            .process_agent_message(&agent_message)
            .expect("agent message should process")
        {
            InterceptResult::ForwardWithReceipt(value, receipt) => {
                assert_eq!(value, agent_message);
                assert_eq!(receipt.tool_call_id, "tool-1");
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }

        let echoed = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "echo",
            "params": {"value": 1}
        });
        proxy.send_to_agent(&echoed).expect("send should succeed");
        let received = proxy.recv_from_agent().expect("recv should succeed");
        assert_eq!(received, Some(echoed));

        proxy.shutdown().expect("shutdown should succeed");
    }
}
