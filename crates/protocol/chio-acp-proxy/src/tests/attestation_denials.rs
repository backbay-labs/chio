#[test]
fn interceptor_required_attestation_blocks_when_signer_is_missing_or_fails() {
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let update = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-required-signer",
            "update": {
                "toolCallId": "tool-required-signer",
                "title": "Build project",
                "kind": "execute",
                "status": "running"
            }
        }
    });

    let missing = MessageInterceptor::with_kernel(
        config.clone(),
        None,
        None,
        AcpAttestationMode::Required,
    );
    match missing
        .intercept(Direction::AgentToClient, &update)
        .expect("missing signer should return a JSON-RPC block")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            assert!(value["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("receipt signer is required"));
        }
        other => panic!("expected Block for missing signer, got {:?}", other),
    }

    let failing = MessageInterceptor::with_kernel(
        config,
        Some(Box::new(FailingSigner)),
        None,
        AcpAttestationMode::Required,
    );
    match failing
        .intercept(Direction::AgentToClient, &update)
        .expect("signer failure should return a JSON-RPC block")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            assert!(value["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("receipt signing failed"));
        }
        other => panic!("expected Block for failing signer, got {:?}", other),
    }
}

#[test]
fn kernel_capability_checker_denies_missing_and_malformed_tokens() {
    let issuer = Keypair::generate();
    let checker = KernelCapabilityChecker::new(
        ChioKernel::new(test_kernel_config(&issuer)),
        "proxy-server",
    );
    let request = AcpCapabilityRequest {
        session_id: "session-1".to_string(),
        tool_call_id: None,
        authorization_correlation_id: None,
        operation: "fs_read".to_string(),
        resource: "/workspace/src/lib.rs".to_string(),
        authorization_parameter_hash: "test-authorization-parameter-hash".to_string(),
        operation_payload: json!({
            "sessionId": "session-1",
            "path": "/workspace/src/lib.rs"
        }),
        execution_nonce: None,
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
    let checker = KernelCapabilityChecker::new(
        ChioKernel::new(test_kernel_config(&issuer)),
        "proxy-server",
    );

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
        tool_call_id: Some("call-kernel-checker".to_string()),
        authorization_correlation_id: Some("auth-correlation-session-1".to_string()),
        operation: "fs_read".to_string(),
        resource: "/workspace/src/lib.rs".to_string(),
        authorization_parameter_hash: "test-authorization-parameter-hash".to_string(),
        operation_payload: json!({
            "sessionId": "session-1",
            "toolCallId": "call-kernel-checker",
            "path": "/workspace/src/lib.rs"
        }),
        execution_nonce: None,
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
        operation_payload: json!({
            "sessionId": "session-1",
            "toolCallId": "call-kernel-checker",
            "path": "/tmp/escape.txt"
        }),
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
    let checker = KernelCapabilityChecker::new(
        ChioKernel::new(test_kernel_config(&issuer)),
        "proxy-server",
    );
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
        tool_call_id: Some("call-terminal-checker".to_string()),
        authorization_correlation_id: Some("auth-correlation-session-2".to_string()),
        operation: "terminal".to_string(),
        resource: "cargo".to_string(),
        authorization_parameter_hash: "test-authorization-parameter-hash".to_string(),
        operation_payload: json!({
            "sessionId": "session-2",
            "toolCallId": "call-terminal-checker",
            "command": "cargo",
            "args": ["test"]
        }),
        execution_nonce: None,
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
fn kernel_capability_checker_requires_and_forwards_execution_nonce_in_strict_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = now_secs();
    let mut kernel = ChioKernel::new(test_kernel_config(&issuer));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let checker = KernelCapabilityChecker::new(kernel, "proxy-server");
    let token = make_capability_token(
        &issuer,
        &subject,
        "proxy-server",
        "fs/read_text_file",
        vec![Constraint::PathPrefix("/workspace".to_string())],
        now.saturating_sub(30),
        now + 3600,
    );
    let mut request = AcpCapabilityRequest {
        session_id: "session-strict".to_string(),
        tool_call_id: Some("call-strict-checker".to_string()),
        authorization_correlation_id: Some("auth-correlation-strict".to_string()),
        operation: "fs_read".to_string(),
        resource: "/workspace/src/lib.rs".to_string(),
        authorization_parameter_hash: "test-authorization-parameter-hash".to_string(),
        operation_payload: json!({
            "sessionId": "session-strict",
            "toolCallId": "call-strict-checker",
            "path": "/workspace/src/lib.rs"
        }),
        execution_nonce: None,
        token: Some(serde_json::to_string(&token)?),
    };

    let missing = checker.check_access(&request)?;
    assert!(!missing.allowed);
    assert!(missing.reason.contains("execution nonce"));
    let nonce = missing
        .execution_nonce
        .ok_or_else(|| std::io::Error::other("strict preflight execution nonce missing"))?;

    request.execution_nonce = Some(nonce);
    let allowed = checker.check_access(&request)?;
    assert!(allowed.allowed, "expected allow, got {:?}", allowed);

    let replay = checker.check_access(&request)?;
    assert!(!replay.allowed);
    assert!(replay.reason.contains("execution nonce") || replay.reason.contains("replay"));
    Ok(())
}

#[test]
fn interceptor_strict_nonce_preflight_returns_nonce_then_forwards_once() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = now_secs();
    let mut kernel = ChioKernel::new(test_kernel_config(&issuer));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let checker = KernelCapabilityChecker::new(kernel, "proxy-server");
    let token = make_capability_token(
        &issuer,
        &subject,
        "proxy-server",
        "fs/read_text_file",
        vec![Constraint::PathPrefix("/workspace".to_string())],
        now.saturating_sub(30),
        now + 3600,
    );
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/workspace")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );
    let mut read = json!({
        "jsonrpc": "2.0",
        "id": 917,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-strict-interceptor",
            "toolCallId": "call-strict-interceptor",
            "path": "/workspace/src/lib.rs",
            "capabilityToken": serde_json::to_string(&token)
                .expect("token should serialize")
        }
    });

    let nonce_value = match interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("strict preflight should return a JSON-RPC block")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            let message = value["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("execution nonce"),
                "expected execution nonce preflight block, got {value:?}"
            );
            value
                .pointer("/error/data/chio/executionNonce")
                .expect("preflight block should carry execution nonce")
                .clone()
        }
        other => panic!("expected Block for strict preflight, got {:?}", other),
    };

    read["params"]["chio"] = json!({ "executionNonce": nonce_value });
    match interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("presented nonce should forward once")
    {
        InterceptResult::Forward(value) => assert_eq!(value, read),
        other => panic!("expected Forward with presented nonce, got {:?}", other),
    }

    match interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("replayed nonce should block")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            assert!(value["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("execution nonce"));
            assert!(value.pointer("/error/data/chio/executionNonce").is_none());
        }
        other => panic!("expected Block for replayed nonce, got {:?}", other),
    }
}

#[test]
fn kernel_capability_checker_rejects_untrusted_and_tampered_tokens() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = now_secs();
    let trusted_checker = KernelCapabilityChecker::new(
        ChioKernel::new(test_kernel_config(&issuer)),
        "proxy-server",
    );

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
        tool_call_id: Some("call-untrusted-checker".to_string()),
        authorization_correlation_id: Some("auth-correlation-untrusted".to_string()),
        operation: "fs_read".to_string(),
        resource: "/workspace/src/lib.rs".to_string(),
        authorization_parameter_hash: "test-authorization-parameter-hash".to_string(),
        operation_payload: json!({
            "sessionId": "session-untrusted",
            "toolCallId": "call-untrusted-checker",
            "path": "/workspace/src/lib.rs"
        }),
        execution_nonce: None,
        token: Some(serde_json::to_string(&token).expect("token should serialize")),
    };
    let verdict = untrusted_checker
        .check_access(&request)
        .expect("untrusted issuer should fail closed");
    assert!(!verdict.allowed);
    assert!(
        verdict.reason.contains("signature")
            || verdict.reason.contains("untrusted")
            || verdict.reason.contains("not a trusted")
            || verdict.reason.contains("denied")
    );
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
    assert!(verdict.reason.contains("signature") || verdict.reason.contains("denied"));
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
        Some(Box::new(RecordingChecker::allow_with_receipt(
            Arc::clone(&requests),
            "cap-377",
            "auth-receipt-377",
            "auth-request-377",
        ))),
        AcpAttestationMode::BestEffort,
    );

    let read = json!({
        "jsonrpc": "2.0",
        "id": 377,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-377",
            "toolCallId": "tool-377",
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
    assert_eq!(recorded[0].tool_call_id.as_deref(), Some("tool-377"));
    assert_eq!(recorded[0].operation, "fs_read");
    assert_eq!(recorded[0].resource, "/home/user/project/src/lib.rs");
    assert_eq!(recorded[0].token.as_deref(), Some("signed-capability-json"));
    assert_eq!(
        recorded[0].operation_payload,
        json!({
            "sessionId": "session-377",
            "toolCallId": "tool-377",
            "path": "/home/user/project/src/lib.rs"
        })
    );
    drop(recorded);

    let update = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-377",
            "update": {
                "toolCallId": "tool-377",
                "title": "Read file",
                "kind": "read",
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
fn interceptor_rejects_cryptographic_allow_without_signed_authorization_receipt() {
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
            "cap-without-auth-receipt",
        ))),
        AcpAttestationMode::Required,
    );

    let read = json!({
        "jsonrpc": "2.0",
        "id": 383,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-missing-auth-receipt",
            "toolCallId": "tool-missing-auth-receipt",
            "path": "/home/user/project/src/lib.rs",
            "capabilityToken": "signed-capability-json"
        }
    });

    match interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("missing signed authorization receipt should return a block response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
            assert!(value["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("signed authorization receipt"));
        }
        other => panic!("expected Block, got {:?}", other),
    }
    assert_eq!(requests.lock().expect("requests should lock").len(), 1);
}

#[test]
fn interceptor_rejects_malformed_checker_verdict_evidence() {
    let cases = vec![
        (
            "capability_id",
            AcpVerdict {
                allowed: true,
                capability_id: Some(" cap-padded ".to_string()),
                receipt_id: Some("auth-valid".to_string()),
                receipt_request_id: Some("req-valid".to_string()),
                execution_nonce: None,
                reason: "malformed capability id".to_string(),
            },
            "malformed capability_id",
        ),
        (
            "receipt_id",
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-valid".to_string()),
                receipt_id: Some("auth\ncontrol".to_string()),
                receipt_request_id: Some("req-valid".to_string()),
                execution_nonce: None,
                reason: "malformed receipt id".to_string(),
            },
            "malformed signed authorization receipt id",
        ),
        (
            "receipt_request_id",
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-valid".to_string()),
                receipt_id: Some("auth-valid".to_string()),
                receipt_request_id: Some(" req-padded ".to_string()),
                execution_nonce: None,
                reason: "malformed receipt request id".to_string(),
            },
            "malformed signed authorization request id",
        ),
    ];

    for (index, (field, verdict, expected_message)) in cases.into_iter().enumerate() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let checker = SequencedChecker::new(Arc::clone(&requests), vec![verdict]);
        let config = AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_server_id("proxy-server");
        let interceptor = MessageInterceptor::with_kernel(
            config,
            None,
            Some(Box::new(checker)),
            AcpAttestationMode::BestEffort,
        );
        let id = 384 + index;
        let read = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": format!("session-malformed-{field}"),
                "toolCallId": format!("tool-malformed-{field}"),
                "path": "/home/user/project/src/lib.rs",
                "capabilityToken": "signed-capability-json"
            }
        });

        match interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("malformed checker evidence should return a block response")
        {
            InterceptResult::Block(value) => {
                assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
                assert!(
                    value["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(expected_message),
                    "field {field} returned {value:?}"
                );
            }
            other => panic!("expected Block for {field}, got {:?}", other),
        }
        assert_eq!(requests.lock().expect("requests should lock").len(), 1);
    }
}

#[test]
fn interceptor_does_not_bind_ambiguous_pending_contexts_to_tool_calls() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let checker = SequencedChecker::new(
        Arc::clone(&requests),
        vec![
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-a".to_string()),
                receipt_id: Some("auth-a".to_string()),
                receipt_request_id: Some("req-a".to_string()),
                execution_nonce: None,
                reason: "first allow".to_string(),
            },
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-b".to_string()),
                receipt_id: Some("auth-b".to_string()),
                receipt_request_id: Some("req-b".to_string()),
                execution_nonce: None,
                reason: "second allow".to_string(),
            },
        ],
    );
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );

    // ACP fs/read_text_file requests do not carry a toolCallId in their
    // params, so they cannot be bound to a future tool call at
    // authorization time. The capability gate must allow these requests
    // through (subject to the checker) but the unbound context must NOT
    // attach to an arbitrary later session/update.
    for (id, path) in [
        (380, "/home/user/project/src/a.rs"),
        (381, "/home/user/project/src/b.rs"),
    ] {
        let read = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-ambiguous",
                "path": path,
                "capabilityToken": format!("token-{id}")
            }
        });
        match interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("toolCallId-less fs reads are forwarded after the capability check")
        {
            InterceptResult::Forward(_) => {}
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    let update = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-ambiguous",
            "update": {
                "toolCallId": "tool-b",
                "title": "Read file B",
                "kind": "read",
                "status": "running"
            }
        }
    });

    // Because the fs/read contexts had no toolCallId they were never
    // indexed and the session/update finds no live capability context,
    // dropping the audit entry to AuditOnly.
    match interceptor
        .intercept(Direction::AgentToClient, &update)
        .expect("ambiguous update should still produce an audit receipt")
    {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.capability_id.as_deref(), None);
            assert_eq!(
                receipt.enforcement_mode,
                Some(AcpEnforcementMode::AuditOnly)
            );
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }
}

/// Build a sequenced checker that always allows with a fresh
/// capability/receipt tuple, sized to a target number of authorizations.
fn always_allow_sequenced_checker(
    requests: Arc<Mutex<Vec<AcpCapabilityRequest>>>,
    count: usize,
) -> SequencedChecker {
    let verdicts = (0..count)
        .map(|index| AcpVerdict {
            allowed: true,
            capability_id: Some(format!("cap-{index}")),
            receipt_id: Some(format!("auth-{index}")),
            receipt_request_id: Some(format!("req-{index}")),
            execution_nonce: None,
            reason: format!("allow #{index}"),
        })
        .collect();
    SequencedChecker::new(requests, verdicts)
}

#[test]
fn interceptor_pending_capability_buffer_is_bounded() {
    // Verifies the per-session pending_capability_contexts FIFO cap (32 entries):
    // floods 100 toolCallId-less fs/read_text_file requests and asserts the
    // buffer stays bounded.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let checker = always_allow_sequenced_checker(Arc::clone(&requests), 100);
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );

    for index in 0..100 {
        let read = json!({
            "jsonrpc": "2.0",
            "id": 400 + index,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-flood",
                "path": format!("/home/user/project/src/{index}.rs"),
                "capabilityToken": format!("token-{index}")
            }
        });
        match interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("toolCallId-less fs reads should forward after the capability check")
        {
            InterceptResult::Forward(_) => {}
            other => panic!("expected Forward, got {:?}", other),
        }
        // After every insertion the per-session pending buffer must
        // stay within the documented FIFO cap.
        assert!(
            interceptor.pending_capability_context_count("session-flood") <= 32,
            "pending capability context buffer exceeded cap of 32 after {} reads",
            index + 1
        );
    }

    // After flooding 100 contexts the final cap must hold.
    assert_eq!(
        interceptor.pending_capability_context_count("session-flood"),
        32,
        "pending capability buffer must hold exactly 32 contexts at the cap"
    );
}

#[test]
fn interceptor_blocked_request_preserves_unrelated_capability_contexts() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let checker = SequencedChecker::new(
        Arc::clone(&requests),
        vec![
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-live".to_string()),
                receipt_id: Some("auth-live".to_string()),
                receipt_request_id: Some("req-live".to_string()),
                execution_nonce: None,
                reason: "live allow".to_string(),
            },
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-pending".to_string()),
                receipt_id: Some("auth-pending".to_string()),
                receipt_request_id: Some("req-pending".to_string()),
                execution_nonce: None,
                reason: "pending allow".to_string(),
            },
            AcpVerdict {
                allowed: true,
                capability_id: Some("cap-blocked".to_string()),
                receipt_id: Some("auth-blocked".to_string()),
                receipt_request_id: Some("req-blocked".to_string()),
                execution_nonce: None,
                reason: "checker allowed but built-in guard will block".to_string(),
            },
        ],
    );
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );

    let live_read = json!({
        "jsonrpc": "2.0",
        "id": 610,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-preserve-context",
            "toolCallId": "tool-live-preserve",
            "path": "/home/user/project/src/live.rs",
            "capabilityToken": "token-live"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &live_read)
        .expect("live read should forward after capability and path checks")
    {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward, got {:?}", other),
    }
    assert_eq!(
        interceptor.live_capability_context_count_for_session("session-preserve-context"),
        1,
        "explicit toolCallId should create one live capability context"
    );

    let pending_read = json!({
        "jsonrpc": "2.0",
        "id": 611,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-preserve-context",
            "path": "/home/user/project/src/pending.rs",
            "capabilityToken": "token-pending"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &pending_read)
        .expect("toolCallId-less read should forward and buffer pending context")
    {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward, got {:?}", other),
    }
    assert_eq!(
        interceptor.pending_capability_context_count("session-preserve-context"),
        1,
        "toolCallId-less read should create one pending capability context"
    );

    let blocked_read = json!({
        "jsonrpc": "2.0",
        "id": 612,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-preserve-context",
            "path": "/tmp/out-of-scope.rs",
            "capabilityToken": "token-blocked"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &blocked_read)
        .expect("built-in guard denial should return a block response")
    {
        InterceptResult::Block(value) => {
            assert_eq!(value["error"]["code"], ACP_ERROR_ACCESS_DENIED);
        }
        other => panic!("expected Block, got {:?}", other),
    }

    assert_eq!(
        interceptor.live_capability_context_count_for_session("session-preserve-context"),
        1,
        "blocked request must not erase unrelated live capability context"
    );
    assert_eq!(
        interceptor.pending_capability_context_count("session-preserve-context"),
        1,
        "blocked request must not erase unrelated pending capability context"
    );

    let live_complete = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-preserve-context",
            "update": {
                "toolCallId": "tool-live-preserve",
                "status": "completed"
            }
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &live_complete)
        .expect("live completion should still resolve its authorization context")
    {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.capability_id.as_deref(), Some("cap-live"));
            assert_eq!(
                receipt.enforcement_mode,
                Some(AcpEnforcementMode::CryptographicallyEnforced)
            );
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }

    let pending_start = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "session-preserve-context",
            "update": {
                "toolCallId": "tool-pending-preserve",
                "title": "Read pending file",
                "kind": "read",
                "status": "running"
            }
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &pending_start)
        .expect("pending start should bind its preserved pending context")
    {
        InterceptResult::ForwardWithReceipt(_, receipt) => {
            assert_eq!(receipt.capability_id.as_deref(), Some("cap-pending"));
            assert_eq!(
                receipt.enforcement_mode,
                Some(AcpEnforcementMode::CryptographicallyEnforced)
            );
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }
}

#[test]
fn interceptor_session_cancel_clears_pending_capability_contexts() {
    // Verifies that session/cancel drains the per-session pending FIFO:
    // authorization material must not leak across long-lived sessions.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let checker = always_allow_sequenced_checker(Arc::clone(&requests), 4);
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );

    for index in 0..4 {
        let read = json!({
            "jsonrpc": "2.0",
            "id": 500 + index,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "session-cancel",
                "path": format!("/home/user/project/src/{index}.rs"),
                "capabilityToken": format!("token-{index}")
            }
        });
        interceptor
            .intercept(Direction::AgentToClient, &read)
            .expect("fs/read should forward after the capability check");
    }
    assert_eq!(
        interceptor.pending_capability_context_count("session-cancel"),
        4,
        "expected 4 pending contexts before session/cancel"
    );

    let cancel = json!({
        "jsonrpc": "2.0",
        "id": 599,
        "method": "session/cancel",
        "params": {
            "sessionId": "session-cancel"
        }
    });
    match interceptor
        .intercept(Direction::AgentToClient, &cancel)
        .expect("session/cancel should forward")
    {
        InterceptResult::Forward(_) => {}
        other => panic!("expected Forward for session/cancel, got {:?}", other),
    }
    assert_eq!(
        interceptor.pending_capability_context_count("session-cancel"),
        0,
        "session/cancel must drain pending capability contexts"
    );
    assert_eq!(
        interceptor.live_capability_context_count_for_session("session-cancel"),
        0,
        "session/cancel must drop live capability contexts for the session"
    );
}

#[test]
fn interceptor_session_cancel_rejects_malformed_params_without_draining_contexts() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let checker = always_allow_sequenced_checker(Arc::clone(&requests), 1);
    let config = AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_server_id("proxy-server");
    let interceptor = MessageInterceptor::with_kernel(
        config,
        None,
        Some(Box::new(checker)),
        AcpAttestationMode::BestEffort,
    );

    let read = json!({
        "jsonrpc": "2.0",
        "id": 701,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "session-cancel-invalid",
            "path": "/home/user/project/src/read.rs",
            "capabilityToken": "token-read"
        }
    });
    interceptor
        .intercept(Direction::AgentToClient, &read)
        .expect("fs/read should forward and create pending context");
    assert_eq!(
        interceptor.pending_capability_context_count("session-cancel-invalid"),
        1,
        "expected pending context before malformed session/cancel"
    );

    let missing_params = json!({
        "jsonrpc": "2.0",
        "id": 702,
        "method": "session/cancel"
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &missing_params)
        .expect_err("missing cancel params must fail before forwarding");
    assert_eq!(
        err.to_string(),
        "protocol error: missing params in session/cancel"
    );
    assert_eq!(
        interceptor.pending_capability_context_count("session-cancel-invalid"),
        1,
        "missing cancel params must not drain pending context"
    );

    let empty_session = json!({
        "jsonrpc": "2.0",
        "id": 703,
        "method": "session/cancel",
        "params": {
            "sessionId": " "
        }
    });
    let err = interceptor
        .intercept(Direction::AgentToClient, &empty_session)
        .expect_err("empty cancel sessionId must fail before forwarding");
    assert_eq!(
        err.to_string(),
        "protocol error: invalid session/cancel params: sessionId must be a non-empty string"
    );
    assert_eq!(
        interceptor.pending_capability_context_count("session-cancel-invalid"),
        1,
        "invalid cancel params must not drain pending context"
    );
}
