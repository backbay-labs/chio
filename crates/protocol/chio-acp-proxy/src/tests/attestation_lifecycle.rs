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
        Some(Box::new(RecordingChecker::allow_with_receipt(
            Arc::new(Mutex::new(Vec::new())),
            "cap-terminal",
            "auth-receipt-terminal",
            "auth-request-terminal",
        ))),
        AcpAttestationMode::BestEffort,
    );

    let read = json!({
        "jsonrpc": "2.0",
        "id": 379,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-clear",
            "toolCallId": "tool-clear",
            "path": "/home/user/project/src/lib.rs",
            "capabilityToken": "signed-capability-json"
        }
    });
    interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("read should be allowed");

    let started = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-clear",
            "update": {
                "toolCallId": "tool-clear",
                "title": "Read file",
                "kind": "read",
                "status": "running"
            }
        }
    });
    interceptor
        .intercept(Direction::AgentToClient, &started)
        .expect("started update should bind the live capability context");

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

/// Regression: the canonical ACP `fs/read_text_file` shape does NOT carry
/// a `toolCallId` (the agent picks one and emits it later on the
/// `session/update`). The CryptographicallyEnforced capability context
/// from the live check must therefore be buffered against a stable
/// discriminator (here the per-session pending FIFO keyed by the
/// authorization operation, which carries the kernel request id, the
/// authorization receipt id, the correlation id, and the parameter
/// hash). When the first session/update arrives carrying the resolved
/// tool_call_id and a matching kind, the buffered context binds to it
/// so the receipt is signed as CryptographicallyEnforced rather than
/// silently dropping to AuditOnly.
#[test]
fn cap_context_for_fs_read_links_to_later_session_update_via_request_id() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(RecordingChecker::allow_with_receipt(
            Arc::clone(&requests),
            "cap-fs-read-link",
            "auth-receipt-fs-read-link",
            "auth-request-fs-read-link",
        ))),
        AcpAttestationMode::BestEffort,
    );

    // The ACP fs/read_text_file shape: sessionId + path + capabilityToken
    // only -- no toolCallId. The agent will pick the tool_call_id when
    // it later announces the call.
    let read = json!({
        "jsonrpc": "2.0",
        "id": 421,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-fs-read-link",
            "path": "/home/user/project/src/lib.rs",
            "capabilityToken": "signed-capability-json"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("read without toolCallId should still be allowed")
    {
        InterceptResult::Forward(value) => assert_eq!(value, read),
        other => panic!("expected Forward for toolCallId-less read, got {:?}", other),
    }

    // Sanity: the checker was consulted and the request had no toolCallId.
    let recorded = requests.lock().expect("checker requests should lock");
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].tool_call_id.is_none());
    assert_eq!(recorded[0].operation, "fs_read");
    drop(recorded);

    // The agent now announces the tool call: this is the session/update
    // that carries the chosen tool_call_id. The buffered authorization
    // context must link to it so the receipt is CryptographicallyEnforced.
    let update = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-fs-read-link",
            "update": {
                "toolCallId": "tool-fs-read-link-1",
                "title": "Read /home/user/project/src/lib.rs",
                "kind": "read",
                "status": "running"
            }
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &update)
        .expect("matching session/update should produce a receipt")
    {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.capability_id.as_deref(), Some("cap-fs-read-link"));
            assert_eq!(
                receipt.enforcement_mode,
                Some(AcpEnforcementMode::CryptographicallyEnforced),
                "expected CryptographicallyEnforced, not silent fallback to AuditOnly"
            );
            assert_eq!(
                receipt.authorization_receipt_id.as_deref(),
                Some("auth-receipt-fs-read-link"),
            );
            assert_eq!(
                receipt.authorization_request_id.as_deref(),
                Some("auth-request-fs-read-link"),
            );
            assert_eq!(
                receipt.authorization_tool_call_id.as_deref(),
                Some("tool-fs-read-link-1"),
                "binding should overwrite the pending None tool_call_id",
            );
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }

    // Re-using the same tool_call_id after binding (e.g. for a terminal
    // status update) should also resolve via the direct index.
    let completed = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-fs-read-link",
            "update": {
                "toolCallId": "tool-fs-read-link-1",
                "status": "completed"
            }
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &completed)
        .expect("completed update should still resolve the bound context")
    {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.capability_id.as_deref(), Some("cap-fs-read-link"));
            assert_eq!(
                receipt.enforcement_mode,
                Some(AcpEnforcementMode::CryptographicallyEnforced),
            );
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }
}

// -- Terminal lifecycle (kill/release) gating tests --

/// Capability checker that only authorizes a single, expected
/// (session_id, resource, parameter_hash) tuple. Anything else is
/// denied. Used to verify that the proxy fails closed when an attacker
/// presents a receipt signed for a different session/terminal.
struct ExactBindingChecker {
    expected_session_id: String,
    expected_resource: String,
    expected_parameter_hash: String,
    capability_id: String,
    receipt_id: String,
    receipt_request_id: String,
}

impl CapabilityChecker for ExactBindingChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        if request.session_id == self.expected_session_id
            && request.resource == self.expected_resource
            && request.authorization_parameter_hash == self.expected_parameter_hash
        {
            Ok(AcpVerdict {
                allowed: true,
                capability_id: Some(self.capability_id.clone()),
                receipt_id: Some(self.receipt_id.clone()),
                receipt_request_id: Some(self.receipt_request_id.clone()),
                execution_nonce: None,
                reason: "bound to expected session/terminal".to_string(),
            })
        } else {
            Ok(AcpVerdict {
                allowed: false,
                capability_id: Some(self.capability_id.clone()),
                receipt_id: None,
                receipt_request_id: None,
                execution_nonce: None,
                reason: "authorization receipt parameter hash mismatch".to_string(),
            })
        }
    }
}

fn lifecycle_param_hash(params: &serde_json::Value) -> String {
    let bytes = chio_core::canonical::canonical_json_bytes(params)
        .expect("lifecycle params should canonicalize");
    chio_core::sha256_hex(&bytes)
}

#[test]
fn terminal_kill_without_receipt_fails_closed() {
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    // No capability checker installed: lifecycle ops must fail closed.
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        None,
        AcpAttestationMode::BestEffort,
    );

    let kill = json!({
        "jsonrpc": "2.0",
        "id": 901,
        "method": "terminal/kill",
        "params": {
            "sessionId": "session-kill-no-checker",
            "terminalId": "term-1"
        }
    });

    match interceptor
        .intercept(Direction::AgentToClient, &kill)
        .expect("kill without checker should still return a JSON-RPC response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            let message = value["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("capability checker is required"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected Block for missing checker, got {:?}", other),
    }
}

#[test]
fn terminal_release_without_receipt_fails_closed() {
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        None,
        AcpAttestationMode::BestEffort,
    );

    let release = json!({
        "jsonrpc": "2.0",
        "id": 902,
        "method": "terminal/release",
        "params": {
            "sessionId": "session-release-no-checker",
            "terminalId": "term-2"
        }
    });

    match interceptor
        .intercept(Direction::AgentToClient, &release)
        .expect("release without checker should still return a JSON-RPC response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            let message = value["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("capability checker is required"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected Block for missing checker, got {:?}", other),
    }
}

#[test]
fn terminal_kill_with_authorized_receipt_succeeds() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(RecordingChecker::allow_with_receipt(
            Arc::clone(&requests),
            "cap-kill-ok",
            "auth-receipt-kill",
            "auth-request-kill",
        ))),
        AcpAttestationMode::BestEffort,
    );

    let kill = json!({
        "jsonrpc": "2.0",
        "id": 903,
        "method": "terminal/kill",
        "params": {
            "sessionId": "session-kill-ok",
            "terminalId": "term-kill",
            "toolCallId": "tool-kill",
            "capabilityToken": "signed-capability-json"
        }
    });

    match interceptor
        .intercept(Direction::AgentToClient, &kill)
        .expect("kill with authorized receipt should be forwarded")
    {
        InterceptResult::Forward(value) => assert_eq!(value, kill),
        other => panic!("expected Forward for authorized kill, got {:?}", other),
    }

    let recorded = requests.lock().expect("recording checker should lock");
    assert_eq!(recorded.len(), 1, "checker should be consulted exactly once");
    assert_eq!(recorded[0].session_id, "session-kill-ok");
    assert_eq!(recorded[0].operation, "terminal_kill");
    assert_eq!(recorded[0].resource, "term-kill");
    assert_eq!(recorded[0].tool_call_id.as_deref(), Some("tool-kill"));
    let expected_hash = lifecycle_param_hash(&json!({
        "sessionId": "session-kill-ok",
        "terminalId": "term-kill",
        "toolCallId": "tool-kill"
    }));
    assert_eq!(recorded[0].authorization_parameter_hash, expected_hash);
}

#[test]
fn terminal_release_with_authorized_receipt_succeeds() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(RecordingChecker::allow_with_receipt(
            Arc::clone(&requests),
            "cap-release-ok",
            "auth-receipt-release",
            "auth-request-release",
        ))),
        AcpAttestationMode::BestEffort,
    );

    let release = json!({
        "jsonrpc": "2.0",
        "id": 904,
        "method": "terminal/release",
        "params": {
            "sessionId": "session-release-ok",
            "terminalId": "term-release",
            "toolCallId": "tool-release",
            "capabilityToken": "signed-capability-json"
        }
    });

    match interceptor
        .intercept(Direction::AgentToClient, &release)
        .expect("release with authorized receipt should be forwarded")
    {
        InterceptResult::Forward(value) => assert_eq!(value, release),
        other => panic!("expected Forward for authorized release, got {:?}", other),
    }

    let recorded = requests.lock().expect("recording checker should lock");
    assert_eq!(recorded.len(), 1, "checker should be consulted exactly once");
    assert_eq!(recorded[0].session_id, "session-release-ok");
    assert_eq!(recorded[0].operation, "terminal_release");
    assert_eq!(recorded[0].resource, "term-release");
    assert_eq!(recorded[0].tool_call_id.as_deref(), Some("tool-release"));
}

#[test]
fn terminal_kill_with_mismatched_parameter_hash_fails_closed() {
    let approved_params = json!({
        "sessionId": "session-A",
        "terminalId": "term-A",
        "toolCallId": "tool-A"
    });
    let approved_hash = lifecycle_param_hash(&approved_params);

    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    // Checker is configured to allow ONLY session-A / term-A. Any other
    // (session, terminal) combination is rejected because its parameter
    // hash will not match the signed receipt.
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(ExactBindingChecker {
            expected_session_id: "session-A".to_string(),
            expected_resource: "term-A".to_string(),
            expected_parameter_hash: approved_hash,
            capability_id: "cap-kill-A".to_string(),
            receipt_id: "auth-receipt-kill-A".to_string(),
            receipt_request_id: "auth-request-kill-A".to_string(),
        })),
        AcpAttestationMode::BestEffort,
    );

    // the approved binding is allowed.
    let approved_kill = json!({
        "jsonrpc": "2.0",
        "id": 905,
        "method": "terminal/kill",
        "params": {
            "sessionId": "session-A",
            "terminalId": "term-A",
            "toolCallId": "tool-A",
            "capabilityToken": "signed-capability-json"
        },
    });
    match interceptor
        .intercept(Direction::AgentToClient, &approved_kill)
        .expect("approved kill should evaluate")
    {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward for approved kill, got {:?}", other),
    }

    // Attacker replays the approved receipt context against a DIFFERENT
    // session/terminal. The parameter hash no longer matches what the
    // checker is willing to authorize, so the operation must fail closed.
    let attacker_kill = json!({
        "jsonrpc": "2.0",
        "id": 906,
        "method": "terminal/kill",
        "params": {
            "sessionId": "session-A",
            "terminalId": "term-B",
            "toolCallId": "tool-A",
            "capabilityToken": "signed-capability-json"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &attacker_kill)
        .expect("mismatched kill should still return a JSON-RPC response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            let message = value["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("parameter hash mismatch")
                    || message.contains("authorization"),
                "unexpected message: {message}"
            );
        }
        other => panic!(
            "expected Block for mismatched parameter hash, got {:?}",
            other
        ),
    }

    // Cross-session replay: same terminal id but different session. The
    // parameter hash differs, so this must also be denied.
    let cross_session_kill = json!({
        "jsonrpc": "2.0",
        "id": 907,
        "method": "terminal/kill",
        "params": {
            "sessionId": "session-C",
            "terminalId": "term-A",
            "toolCallId": "tool-A",
            "capabilityToken": "signed-capability-json"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &cross_session_kill)
        .expect("cross-session kill should still return a JSON-RPC response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
        }
        other => panic!(
            "expected Block for cross-session replay, got {:?}",
            other
        ),
    }
}
