#[test]
fn session_lifecycle_is_hosted_by_kernel() {
    let kernel = make_kernel(make_config());
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new()).unwrap();

    assert_eq!(kernel.session_count(), 1);
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Initializing)
    );

    kernel.activate_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Ready)
    );

    kernel.begin_draining_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Draining)
    );

    kernel.close_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Closed)
    );
}

#[test]
fn open_session_assigns_unique_ids_across_kernel_instances() {
    let kernel_a = make_kernel(make_config());
    let kernel_b = make_kernel(make_config());

    let session_a = kernel_a.open_session("agent-a".to_string(), Vec::new()).unwrap();
    let session_b = kernel_b.open_session("agent-b".to_string(), Vec::new()).unwrap();

    assert_ne!(session_a, session_b);
}

/// Session ids are minted from the OS CSPRNG: assert structure (sess- prefix,
/// 22 base64url chars, charset) rather than pinning to a literal value.
#[test]
fn open_session_id_has_csprng_structure() {
    let kernel = make_kernel(make_config());
    let session_id = kernel.open_session("agent-a".to_string(), Vec::new()).unwrap();
    let raw = session_id.as_str();

    let suffix = raw
        .strip_prefix("sess-")
        .expect("session id must carry the sess- prefix");
    // 16 bytes encoded as base64url-without-padding => 22 chars.
    assert_eq!(suffix.len(), 22, "unexpected session id suffix length");
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "session id suffix must use the base64url charset",
    );
}

/// Across N=1024 freshly minted ids, none should collide. Sequential ids
/// trivially satisfied this; the property is what keeps the random scheme
/// honest in the face of a regression to a low-entropy generator.
#[test]
fn open_session_ids_do_not_collide_across_many_calls() {
    let kernel = make_kernel(make_config());
    let mut seen = std::collections::HashSet::with_capacity(1024);
    let mut last: Option<SessionId> = None;
    for _ in 0..1024 {
        let id = kernel.open_session("agent-a".to_string(), Vec::new()).unwrap();
        if let Some(previous) = last.as_ref() {
            assert_ne!(
                &id, previous,
                "consecutive session ids must not be equal"
            );
        }
        assert!(seen.insert(id.clone()), "session id collision: {id}");
        last = Some(id);
    }
}

#[test]
fn open_session_with_id_rejects_duplicate_ids() {
    let kernel = make_kernel(make_config());
    let session_id = SessionId::new("sess-restored");

    let opened = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap();
    assert_eq!(opened, session_id);

    let error = kernel
        .open_session_with_id(session_id.clone(), "agent-b".to_string(), Vec::new())
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::SessionAlreadyExists(existing) if existing == session_id
    ));
    assert_eq!(kernel.session_count(), 1);
    assert_eq!(
        kernel
            .session(&session_id)
            .map(|session| session.agent_id().to_string()),
        Some("agent-a".to_string())
    );
}

#[test]
fn open_session_with_id_rolls_back_insert_when_anchor_persistence_fails() {
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(FailingSessionAnchorReceiptStore)).unwrap();
    let session_id = SessionId::new("sess-anchor-fail");

    let error = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "session anchor write failed"
    ));
    assert_eq!(kernel.session_count(), 0);
    assert!(kernel.session(&session_id).is_none());

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    let opened = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap();
    assert_eq!(opened, session_id);
    assert_eq!(kernel.session_count(), 1);
}

#[test]
fn set_session_auth_context_rolls_back_when_anchor_persistence_fails() {
    let mut kernel = make_kernel(make_config());
    let session_id =
        kernel.open_session_with_id(SessionId::new("sess-auth-rollback"), "agent-a".to_string(), Vec::new())
            .unwrap();
    let initial_auth = kernel
        .session(&session_id)
        .map(|session| session.auth_context())
        .unwrap();
    let initial_anchor = kernel
        .session(&session_id)
        .map(|session| session.session_anchor())
        .unwrap();

    kernel.set_receipt_store(Box::new(FailingSessionAnchorReceiptStore)).unwrap();
    let error = kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:rollback",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "session anchor write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert_eq!(session.auth_context(), initial_auth);
    assert_eq!(session.session_anchor(), initial_anchor);
}

#[test]
fn close_session_persists_anonymous_anchor_and_rejects_late_auth_rotation() {
    let store = RecordingSessionAnchorReceiptStore::default();
    let anchors = std::sync::Arc::clone(&store.anchors);
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(store)).unwrap();
    let session_id = kernel
        .open_session_with_id(
            SessionId::new("sess-auth-close"),
            "agent-a".to_string(),
            Vec::new(),
        )
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let initial_anchor_id = kernel
        .session(&session_id)
        .map(|session| session.session_anchor().id().to_string())
        .unwrap();

    kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:close",
                "deadbeef",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap();
    let authenticated_anchor_id = kernel
        .session(&session_id)
        .map(|session| session.session_anchor().id().to_string())
        .unwrap();

    kernel.close_session(&session_id).unwrap();
    let closed = kernel.session(&session_id).unwrap();
    assert_eq!(closed.state(), SessionState::Closed);
    assert!(!closed.auth_context().is_authenticated());

    let closed_anchor_id = closed.session_anchor().id().to_string();
    kernel.close_session(&session_id).unwrap();
    let reclosed = kernel.session(&session_id).unwrap();
    assert_eq!(reclosed.state(), SessionState::Closed);
    assert_eq!(reclosed.session_anchor().id(), closed_anchor_id);

    let records = anchors.lock().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[2].anchor_id, closed_anchor_id);
    assert_ne!(closed_anchor_id, initial_anchor_id);
    assert_ne!(closed_anchor_id, authenticated_anchor_id);
    assert_eq!(
        records[2].supersedes_anchor_id.as_deref(),
        Some(authenticated_anchor_id.as_str())
    );
    drop(records);

    let error = kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:late",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::Session(SessionError::OperationNotAllowed {
            operation: "set_auth_context",
            state: "closed",
            ..
        })
    ));
}

#[test]
fn close_session_with_sqlite_store_reuses_initial_anonymous_anchor() {
    let path = unique_receipt_db_path("session-close-anonymous-anchor");
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    let session_id = kernel
        .open_session_with_id(
            SessionId::new("sess-auth-close-sqlite"),
            "agent-a".to_string(),
            Vec::new(),
        )
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:sqlite-close",
                "deadbeef",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap();

    kernel.close_session(&session_id).unwrap();
    let closed = kernel.session(&session_id).unwrap();
    assert_eq!(closed.state(), SessionState::Closed);
    assert!(!closed.auth_context().is_authenticated());
}

#[test]
fn web3_evidence_required_activation_rejects_missing_receipt_store() {
    let mut config = make_config();
    config.require_web3_evidence = true;
    let kernel = make_kernel(config);
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new()).unwrap();

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error.to_string().contains("durable receipt store"));
}

#[test]
fn web3_evidence_required_activation_rejects_checkpoint_disabled() {
    let path = unique_receipt_db_path("web3-evidence-disabled");
    let mut config = make_config();
    config.require_web3_evidence = true;
    config.checkpoint_batch_size = 0;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new()).unwrap();

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error.to_string().contains("checkpoint_batch_size > 0"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn web3_evidence_required_activation_rejects_append_only_receipt_store() {
    let mut config = make_config();
    config.require_web3_evidence = true;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new()).unwrap();

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error
        .to_string()
        .contains("append-only remote receipt mirrors are unsupported"));
}

#[test]
fn web3_evidence_required_activation_allows_checkpoint_capable_store() {
    let path = unique_receipt_db_path("web3-evidence-capable");
    let mut config = make_config();
    config.require_web3_evidence = true;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new()).unwrap();

    kernel.activate_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Ready)
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn session_operation_tool_call_tracks_and_clears_inflight() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(&session_id, "req-1", &agent_kp.public_key().to_hex());
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    }));

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");
    assert_eq!(response.verdict, Verdict::Allow);

    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn session_operation_tool_call_malformed_nonce_clears_inflight() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "req-malformed-nonce",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        governed_intent: None,
        execution_nonce: Some(serde_json::json!("not-a-signed-nonce")),
        model_metadata: None,
        extra_metadata: None,
    }));

    let error = kernel
        .evaluate_session_operation(&context, &operation)
        .unwrap_err();
    assert!(
        error.to_string().contains("execution_nonce"),
        "expected execution nonce parse error, got: {error}"
    );
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn session_operation_capability_list_uses_session_snapshot() {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]).unwrap();
    let context = make_operation_context(&session_id, "control-1", &agent_kp.public_key().to_hex());

    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListCapabilities)
        .unwrap();

    let capabilities =
        session_capability_list(response).expect("expected capability list response");
    assert_eq!(capabilities.len(), 1);
}

#[test]
fn session_operation_list_roots_uses_session_snapshot() {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let context = make_operation_context(&session_id, "roots-1", &agent_kp.public_key().to_hex());
    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListRoots)
        .unwrap();

    let roots = session_root_list(response).expect("expected root list response");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].uri, "file:///workspace/project");
}

#[test]
fn kernel_exposes_normalized_session_roots_for_later_enforcement() {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![
                RootDefinition {
                    uri: "file:///workspace/project/../project/src".to_string(),
                    name: Some("Code".to_string()),
                },
                RootDefinition {
                    uri: "repo://docs/roadmap".to_string(),
                    name: Some("Roadmap".to_string()),
                },
                RootDefinition {
                    uri: "file://remote-host/workspace/project".to_string(),
                    name: Some("Remote".to_string()),
                },
            ],
        )
        .unwrap();

    let normalized = kernel.normalized_session_roots(&session_id).unwrap();
    assert_eq!(normalized.len(), 3);
    assert!(matches!(
        normalized[0],
        NormalizedRoot::EnforceableFileSystem {
            ref normalized_path,
            ..
        } if normalized_path == "/workspace/project/src"
    ));
    assert!(matches!(
        normalized[1],
        NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
    ));
    assert!(matches!(
        normalized[2],
        NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
            if reason == "non_local_file_authority"
    ));
    assert_eq!(
        kernel
            .enforceable_filesystem_root_paths(&session_id)
            .unwrap(),
        vec!["/workspace/project/src"]
    );
}

#[test]
fn begin_child_request_requires_parent_lineage() {
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-1"),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();

    let session = kernel.session(&session_id).unwrap();
    let child = session.inflight().get(&child_context.request_id).unwrap();
    assert_eq!(child.parent_request_id, Some(RequestId::new("parent-1")));
}

#[test]
fn begin_session_request_clears_inflight_when_lineage_persistence_fails() {
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(FailingRequestLineageReceiptStore)).unwrap();
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "lineage-fail-root",
        &agent_kp.public_key().to_hex(),
    );
    let error = kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "request lineage write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        None,
        "failed non-durable start does not leave terminal state"
    );
    assert_eq!(
        session.request_lineage(&context.request_id),
        None,
        "failed non-durable start does not leave in-memory lineage"
    );

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .unwrap();
}

#[test]
fn begin_child_request_clears_child_inflight_when_lineage_persistence_fails() {
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-ok", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    kernel.set_receipt_store(Box::new(FailingRequestLineageReceiptStore)).unwrap();

    let child_request_id = RequestId::new("lineage-fail-child");
    let error = kernel
        .begin_child_request(
            &parent_context,
            child_request_id.clone(),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "request lineage write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert!(
        session.inflight().get(&parent_context.request_id).is_some(),
        "parent request remains active"
    );
    assert!(
        session.inflight().get(&child_request_id).is_none(),
        "failed child request is removed from active tracking"
    );
    assert_eq!(
        session.terminal().get(&child_request_id),
        None,
        "failed child start does not leave terminal state"
    );
    assert_eq!(
        session.request_lineage(&child_request_id),
        None,
        "failed child start does not leave in-memory lineage"
    );

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    kernel
        .begin_child_request(
            &parent_context,
            child_request_id,
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();
}

#[test]
fn sampling_validation_requires_policy_and_negotiation() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-1"),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();
    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Summarize the diff"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 256,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    };

    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling = true;
    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::SamplingNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: true,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_sampling_request(&child_context, &operation)
        .unwrap();

    let tool_operation = CreateMessageOperation {
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
        ..operation
    };
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling_tool_use = true;
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotNegotiated)
    ));
}

#[test]
fn elicitation_validation_requires_policy_and_form_negotiation() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "parent-elicit-1",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-elicit-1"),
            OperationKind::CreateElicitation,
            None,
            true,
        )
        .unwrap();
    let operation = CreateElicitationOperation::Form {
        meta: None,
        message: "Which environment should this run against?".to_string(),
        requested_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "environment": {
                    "type": "string",
                    "enum": ["staging", "production"]
                }
            },
            "required": ["environment"]
        }),
    };

    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationNotAllowedByPolicy)
    ));

    kernel.config.allow_elicitation = true;
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::ElicitationNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationFormNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &operation)
        .unwrap();

    let url_operation = CreateElicitationOperation::Url {
        meta: None,
        message: "Open the secure enrollment flow".to_string(),
        url: "https://example.test/consent".to_string(),
        elicitation_id: "elicitation-123".to_string(),
    };
    let denied = kernel.validate_elicitation_request(&child_context, &url_operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationUrlNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: true,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &url_operation)
        .unwrap();
}

#[test]
fn tool_call_nested_flow_bridge_roundtrips_sampling() {
    let mut config = make_config();
    config.allow_sampling = true;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: true,
                sampling_context: true,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: vec![RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        }],
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Roadmap summary",
            }),
            model: "gpt-test".to_string(),
            stop_reason: Some("end_turn".to_string()),
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-1",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let value = tool_call_value_output(response.output).expect("expected value output");
    assert_eq!(value["model"], "gpt-test");
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(kernel.child_receipt_log().len(), 1);
    let child_receipt_log = kernel.child_receipt_log();
    let child_receipt = child_receipt_log.get(0).unwrap();
    assert_eq!(child_receipt.parent_request_id, context.request_id);
    assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
    assert_eq!(
        child_receipt.terminal_state,
        OperationTerminalState::Completed
    );
    assert!(child_receipt.verify_signature().unwrap());
    assert_eq!(
        child_receipt.metadata.as_ref().unwrap()["outcome"],
        "result"
    );
}

#[test]
fn tool_call_nested_flow_bridge_roundtrips_elicitation() {
    let mut config = make_config();
    config.allow_elicitation = true;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "elicit_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-elicit-1",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "elicit_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let value = tool_call_value_output(response.output).expect("expected value output");
    assert_eq!(value["action"], "accept");
    assert_eq!(value["content"]["environment"], "staging");
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn tool_call_nested_flow_bridge_updates_session_roots() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "roots_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let expected_roots = vec![RootDefinition {
        uri: "file:///workspace/project".to_string(),
        name: Some("Project".to_string()),
    }];
    let mut client = MockNestedFlowClient {
        roots: expected_roots.clone(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-2",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "roots_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.session(&session_id).unwrap().roots(), expected_roots);
}

#[test]
fn tool_call_nested_flow_bridge_propagates_parent_cancellation() {
    let mut kernel = make_kernel(make_config());
    kernel.config.allow_sampling = true;
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: true,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: true,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-parent-cancel",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();
    let expected_reason = "client cancelled parent request".to_string();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Cancelled {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_cancelled());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: expected_reason,
        })
    );
}

#[test]
fn tool_call_nested_flow_bridge_propagates_child_cancellation() {
    let mut kernel = make_kernel(make_config());
    kernel.config.allow_sampling = true;
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: true,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: true,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-child-cancel",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();
    let expected_reason = "client cancelled nested request".to_string();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Cancelled {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_cancelled());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: expected_reason,
        })
    );
    assert_eq!(kernel.child_receipt_log().len(), 1);
    let child_receipt_log = kernel.child_receipt_log();
    let child_receipt = child_receipt_log.get(0).unwrap();
    assert_eq!(child_receipt.parent_request_id, context.request_id);
    assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
    assert_eq!(
        child_receipt.terminal_state,
        OperationTerminalState::Cancelled {
            reason: "client cancelled nested request".to_string(),
        }
    );
    assert!(child_receipt.verify_signature().unwrap());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&child_receipt.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: "client cancelled nested request".to_string(),
        })
    );
}

#[test]
fn tool_call_nested_flow_rejects_malformed_execution_nonce_without_inflight_leak() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id =
        match kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]) {
            Ok(session_id) => session_id,
            Err(error) => panic!("session should open: {error}"),
        };
    if let Err(error) = kernel.activate_session(&session_id) {
        panic!("session should activate: {error}");
    }

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-malformed-nonce",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: Some(serde_json::json!("not-a-signed-execution-nonce")),
        model_metadata: None,
        extra_metadata: None,
    };

    let error = match kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    ) {
        Ok(_) => panic!("malformed execution_nonce should fail closed"),
        Err(error) => error,
    };
    assert!(
        format!("{error}").contains("session tool call execution_nonce is malformed"),
        "unexpected error: {error}"
    );
    let no_inflight_request = kernel
        .session(&session_id)
        .map(|session| session.inflight().is_empty())
        .unwrap_or(false);
    assert!(
        no_inflight_request,
        "malformed nonce must not leak inflight state"
    );

    let retry_error = match kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    ) {
        Ok(_) => panic!("retry with malformed execution_nonce should still fail closed"),
        Err(error) => error,
    };
    assert!(
        format!("{retry_error}").contains("session tool call execution_nonce is malformed"),
        "unexpected retry error: {retry_error}"
    );
}

#[test]
fn tool_call_nested_flow_bridge_filters_resource_notifications_to_session_subscriptions() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let tool_capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "notify_resources_via_client")]),
        300,
    );
    let resource_capability = make_capability(
        &kernel,
        &agent_kp,
        ChioScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..ChioScope::default()
        },
        300,
    );
    let session_id = kernel.open_session(
        agent_kp.public_key().to_hex(),
        vec![tool_capability.clone(), resource_capability.clone()],
    ).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &resource_capability,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-resource-notify",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: tool_capability,
        server_id: "nested".to_string(),
        tool_name: "notify_resources_via_client".to_string(),
        arguments: serde_json::json!({}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        client.resource_updates,
        vec!["repo://docs/roadmap".to_string()]
    );
    assert_eq!(client.resources_list_changed_count, 1);
}

#[test]
fn session_operation_list_resources_filters_to_session_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    let context =
        make_operation_context(&session_id, "resources-1", &agent_kp.public_key().to_hex());

    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListResources)
        .unwrap();

    let resources = session_resource_list(response).expect("expected resource list response");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].uri, "repo://docs/roadmap");
}

#[test]
fn session_operation_read_resource_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "repo://docs/roadmap".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Roadmap"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "repo://secret/ops".to_string(),
        }),
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));
}

#[test]
fn session_operation_read_resource_enforces_session_roots_for_filesystem_resources() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-file-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Filesystem Roadmap"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-file-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/private/ops.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(receipt.tool_name, "resources/read");
    assert_eq!(receipt.tool_server, "session");
    assert_eq!(
            receipt.decision,
            Some(Decision::Deny {
                reason:
                    "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
                        .to_string(),
                guard: "session_roots".to_string(),
            })
        );
}

#[test]
fn session_operation_read_resource_fails_closed_when_filesystem_roots_are_missing() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "resource-read-file-3",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/project/docs/roadmap.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(
        receipt.decision,
        Some(Decision::Deny {
            reason: "no enforceable filesystem roots are available for this session".to_string(),
            guard: "session_roots".to_string(),
        })
    );
}

#[test]
fn subscribe_session_resource_requires_subscribe_operation() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let read_only_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let read_only_cap = make_capability(&kernel, &agent_kp, read_only_scope, 300);

    let session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![read_only_cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let denied = kernel.subscribe_session_resource(
        &session_id,
        &read_only_cap,
        &agent_kp.public_key().to_hex(),
        "repo://docs/roadmap",
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));

    let subscribe_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let subscribe_cap = make_capability(&kernel, &agent_kp, subscribe_scope, 300);
    kernel
        .subscribe_session_resource(
            &session_id,
            &subscribe_cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    assert!(kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn unsubscribe_session_resource_is_idempotent() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
        .unwrap();
    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
        .unwrap();

    assert!(!kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn session_operation_get_prompt_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let list_context =
        make_operation_context(&session_id, "prompts-1", &agent_kp.public_key().to_hex());
    let list_response = kernel
        .evaluate_session_operation(&list_context, &SessionOperation::ListPrompts)
        .unwrap();
    let prompts = session_prompt_list(list_response).expect("expected prompt list response");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "summarize_docs");

    let get_context =
        make_operation_context(&session_id, "prompts-2", &agent_kp.public_key().to_hex());
    let get_response = kernel
        .evaluate_session_operation(
            &get_context,
            &SessionOperation::GetPrompt(GetPromptOperation {
                capability: cap.clone(),
                prompt_name: "summarize_docs".to_string(),
                arguments: serde_json::json!({"topic": "roadmap"}),
            }),
        )
        .unwrap();
    let prompt = session_prompt_get(get_response).expect("expected prompt get response");
    assert_eq!(prompt.messages[0].content["text"], "Summarize roadmap");

    let denied_context =
        make_operation_context(&session_id, "prompts-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::GetPrompt(GetPromptOperation {
            capability: cap,
            prompt_name: "ops_secret".to_string(),
            arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}

#[test]
fn session_operation_completion_returns_candidates_and_enforces_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let prompt_context =
        make_operation_context(&session_id, "complete-1", &agent_kp.public_key().to_hex());
    let prompt_completion = kernel
        .evaluate_session_operation(
            &prompt_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Prompt {
                    name: "summarize_docs".to_string(),
                },
                argument: CompletionArgument {
                    name: "topic".to_string(),
                    value: "r".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(prompt_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["roadmap", "release-plan"]);

    let resource_context =
        make_operation_context(&session_id, "complete-2", &agent_kp.public_key().to_hex());
    let resource_completion = kernel
        .evaluate_session_operation(
            &resource_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Resource {
                    uri: "repo://docs/{slug}".to_string(),
                },
                argument: CompletionArgument {
                    name: "slug".to_string(),
                    value: "a".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(resource_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["architecture", "api"]);

    let denied_context =
        make_operation_context(&session_id, "complete-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::Complete(CompleteOperation {
            capability: cap,
            reference: CompletionReference::Prompt {
                name: "ops_secret".to_string(),
            },
            argument: CompletionArgument {
                name: "topic".to_string(),
                value: "o".to_string(),
            },
            context_arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}
