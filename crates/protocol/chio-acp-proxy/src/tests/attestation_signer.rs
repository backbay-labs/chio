#[test]
fn kernel_receipt_signer_uses_store_owned_checkpoint_creation() {
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
    assert!(state.canonical_ranges.is_empty());
    assert_eq!(state.checkpoints.len(), 1);
    assert_eq!(state.checkpoints[0].batch_start_seq, Some(1));
    assert_eq!(state.checkpoints[0].batch_end_seq, Some(2));
}

#[test]
fn kernel_receipt_signer_propagates_capability_metadata_into_receipts() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_request_id = "acp-live-guard-auth-377";
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-377",
        authorization_request_id,
        "session-enforced",
        "call-enforced",
        "fs/read_text_file",
        Some("tenant-enforced"),
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-enforced", "session-enforced");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-377",
        &authorization_receipt.id,
        authorization_request_id,
        "fs/read_text_file",
    );
    let enforced = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect("enforced receipt should sign");
    assert!(
        enforced
            .action
            .parameters
            .get("operation_payload")
            .is_some(),
        "enforced ACP receipts must sign the full operation payload"
    );
    assert_eq!(
        enforced
            .action
            .parameters
            .get("authorization_parameter_hash")
            .and_then(serde_json::Value::as_str),
        Some(test_authorization_parameter_hash().as_str())
    );
    assert_eq!(
        authorization_receipt
            .action
            .parameters
            .get("session_id")
            .and_then(serde_json::Value::as_str),
        Some("session-enforced")
    );
    assert_eq!(
        authorization_receipt
            .action
            .parameters
            .get("tool_call_id")
            .and_then(serde_json::Value::as_str),
        Some("call-enforced")
    );
    assert_eq!(
        authorization_receipt
            .action
            .parameters
            .get("authorization_correlation_id")
            .and_then(serde_json::Value::as_str),
        Some(test_authorization_correlation_id("session-enforced", "call-enforced").as_str())
    );
    assert_eq!(
        authorization_receipt
            .action
            .parameters
            .get("operation")
            .and_then(serde_json::Value::as_str),
        Some("fs_read")
    );
    assert_eq!(
        authorization_receipt
            .action
            .parameters
            .get("resource")
            .and_then(serde_json::Value::as_str),
        Some("resource:call-enforced")
    );
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
    assert_eq!(
        enforced.metadata.as_ref().and_then(|metadata| {
            metadata
                .get("acp")
                .and_then(|acp| acp.get("authorizationRequestId"))
                .and_then(serde_json::Value::as_str)
        }),
        Some(authorization_request_id)
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
    let audit_semantics = audit_only.semantic_fields();
    assert_eq!(
        audit_semantics.receipt_kind,
        chio_core::receipt::kinds::ReceiptKind::TraceObservation
    );
    assert_eq!(
        audit_semantics.boundary_class,
        chio_core::receipt::kinds::BoundaryClass::DetectOnly
    );
    assert!(!audit_semantics.is_authorized(audit_only.decision.as_ref()));
    assert!(!audit_only.is_allowed());
}

#[test]
fn kernel_receipt_signer_rejects_enforced_receipt_without_stored_authorization() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-enforced-missing", "session-enforced");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-missing",
        "missing-auth-receipt",
        "acp-live-guard-missing",
        "fs/read_text_file",
    );
    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("missing authorization receipt should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt missing-auth-receipt was not found"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_authorization_request_id_mismatch() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt(
        &keypair,
        "cap-request",
        "auth-request-good",
        "session-request",
        "call-request",
        "fs/read_text_file",
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-request", "session-request");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-request",
        &authorization_receipt.id,
        "auth-request-bad",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("request id mismatch should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt request id mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_authorization_receipt_parameter_hash_mismatch() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt(
        &keypair,
        "cap-hash-mismatch",
        "auth-hash-mismatch",
        "session-hash-mismatch",
        "call-hash-mismatch",
        "fs/read_text_file",
    );
    let mut body = authorization_receipt.body();
    body.action.parameter_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let authorization_receipt =
        ChioReceipt::sign(body, &keypair).expect("hash-mismatch receipt should sign");
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-hash-mismatch", "session-hash-mismatch");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-hash-mismatch",
        &authorization_receipt.id,
        "auth-hash-mismatch",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("hash-mismatch authorization receipt should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt parameter hash mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_stale_authorization_reuse_for_other_tool_call() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt(
        &keypair,
        "cap-stale",
        "auth-stale",
        "session-original",
        "call-original",
        "fs/read_text_file",
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-other", "session-other");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-stale",
        &authorization_receipt.id,
        "auth-stale",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("stale authorization receipt should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt session id mismatch")
            || error
                .to_string()
                .contains("authorization receipt correlation id mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_same_session_authorization_tool_call_id_mismatch() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-tool-call-mismatch",
        "auth-tool-call-mismatch",
        "session-tool-call-mismatch",
        "call-presented",
        "fs/read_text_file",
        Some("tenant-tool-call-mismatch"),
    );
    let authorization_receipt =
        rewrite_authorization_action_parameters(&authorization_receipt, &keypair, |parameters| {
            parameters.insert(
                "tool_call_id".to_string(),
                serde_json::Value::String("call-authorized".to_string()),
            );
        });
    let mut body = authorization_receipt.body();
    body.metadata
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .expect("authorization receipt metadata should be an object")
        .insert(
            "source_receipt_context".to_string(),
            json!({"tool_call_id": "call-presented"}),
        );
    let authorization_receipt = ChioReceipt::sign(body, &keypair)
        .expect("receipt with non-authoritative source context should sign");
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-presented", "session-tool-call-mismatch");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-tool-call-mismatch",
        &authorization_receipt.id,
        "auth-tool-call-mismatch",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("same-session wrong tool call id should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt tool call id mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_missing_or_non_string_authorization_tool_call_id() {
    for (case, malformed_value) in [
        ("missing", None),
        ("non-string", Some(json!({ "unexpected": true }))),
    ] {
        let keypair = Keypair::generate();
        let shared = Arc::new(Mutex::new(MockStoreState::default()));
        let authorization_receipt = make_authorization_receipt_with_tenant(
            &keypair,
            &format!("cap-malformed-tool-call-{case}"),
            &format!("auth-malformed-tool-call-{case}"),
            "session-malformed-tool-call",
            "call-malformed-tool-call",
            "fs/read_text_file",
            Some("tenant-malformed-tool-call"),
        );
        let authorization_receipt = rewrite_authorization_action_parameters(
            &authorization_receipt,
            &keypair,
            |parameters| match malformed_value {
                Some(value) => {
                    parameters.insert("tool_call_id".to_string(), value);
                }
                None => {
                    parameters.remove("tool_call_id");
                }
            },
        );
        shared
            .lock()
            .expect("shared state should lock")
            .appended_receipts
            .push(authorization_receipt.clone());
        let store = MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: false,
        };
        let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

        let mut enforced_entry =
            make_audit_entry("call-malformed-tool-call", "session-malformed-tool-call");
        mark_entry_cryptographically_enforced(
            &mut enforced_entry,
            &format!("cap-malformed-tool-call-{case}"),
            &authorization_receipt.id,
            &format!("auth-malformed-tool-call-{case}"),
            "fs/read_text_file",
        );

        let error = signer
            .sign_acp_receipt(&AcpReceiptRequest {
                audit_entry: enforced_entry,
                tool_server: "proxy-server".to_string(),
                tool_name: "fs/read_text_file".to_string(),
            })
            .expect_err("malformed signed tool call id should fail closed");
        assert!(
            error.to_string().contains("tool call id"),
            "unexpected {case} tool call id error: {error}"
        );
    }
}

#[test]
fn verify_live_authorization_receipt_accepts_deferred_bind_for_fs_operations() {
    // ACP fs/read_text_file, fs/write_text_file, and terminal/create
    // requests do not carry a `toolCallId` at the capability gate.
    // `KernelCapabilityChecker` signs the action with `tool_call_id = ""`.
    // The agent later assigns the real tool call
    // id on a `session/update` notification, at which point the proxy
    // resolves the binding via the per-session-operation FIFO and
    // `bind_pending_capability_context`. The signer's
    // `verify_live_authorization_receipt` must accept this deferred
    // bind: an empty stored `tool_call_id` matches any non-empty
    // resolved `authorization_tool_call_id` provided the other
    // context fields agree.
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-deferred-bind",
        "auth-deferred-bind",
        "session-deferred-bind",
        // The fixture initially writes the supplied tool_call_id into
        // the signed action; we override it to empty below to
        // simulate the deferred-bind shape produced by
        // `KernelCapabilityChecker` for fs and terminal-create
        // operations.
        "ignored-initial-id",
        "fs/read_text_file",
        Some("tenant-deferred-bind"),
    );
    // The correlation id is derived from the placeholder tool call id
    // in the fixture. Realign it with the resolved tool call id we
    // simulate the agent later assigning, so the only field that
    // tests the deferred-bind acceptance is `tool_call_id` itself.
    let resolved_tool_call_id = "call-resolved-by-agent";
    let resolved_correlation_id =
        test_authorization_correlation_id("session-deferred-bind", resolved_tool_call_id);
    let authorization_receipt =
        rewrite_authorization_action_parameters(&authorization_receipt, &keypair, |parameters| {
            parameters.insert(
                "tool_call_id".to_string(),
                serde_json::Value::String(String::new()),
            );
            parameters.insert(
                "authorization_correlation_id".to_string(),
                serde_json::Value::String(resolved_correlation_id),
            );
            parameters.insert(
                "resource".to_string(),
                serde_json::Value::String(test_authorization_resource(resolved_tool_call_id)),
            );
        });
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry(resolved_tool_call_id, "session-deferred-bind");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-deferred-bind",
        &authorization_receipt.id,
        "auth-deferred-bind",
        "fs/read_text_file",
    );

    let consumer_receipt = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect("deferred-bind authorization should be accepted by the verifier");
    assert_eq!(consumer_receipt.tool_name, "fs/read_text_file");
    assert_eq!(
        consumer_receipt.tenant_id.as_deref(),
        Some("tenant-deferred-bind")
    );
}

#[test]
fn kernel_receipt_signer_rejects_trace_authorization_receipt_for_enforced_entry() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_semantics(
        &keypair,
        "cap-trace",
        "auth-trace",
        "session-trace",
        "call-trace",
        "fs/read_text_file",
        Decision::Incomplete {
            reason: "trace-only observation".to_string(),
        },
        chio_core::receipt::kinds::TrustLevel::Verified,
        chio_core::receipt::metadata::ReceiptSemanticFields::trace_detect_only(),
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-trace", "session-trace");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-trace",
        &authorization_receipt.id,
        "auth-trace",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("trace authorization receipt should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt must be a mediated allow"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_forged_authorization_receipt_signature() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let mut authorization_receipt = make_authorization_receipt(
        &keypair,
        "cap-forged",
        "auth-forged",
        "session-forged",
        "call-forged",
        "fs/read_text_file",
    );
    authorization_receipt.content_hash = "tampered-content".to_string();
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-forged", "session-forged");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-forged",
        &authorization_receipt.id,
        "auth-forged",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("forged authorization receipt should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt signature verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_wrong_authorization_signer() {
    let signer_keypair = Keypair::generate();
    let wrong_keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt(
        &wrong_keypair,
        "cap-wrong-signer",
        "auth-wrong-signer",
        "session-wrong-signer",
        "call-wrong-signer",
        "fs/read_text_file",
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(signer_keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-wrong-signer", "session-wrong-signer");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-wrong-signer",
        &authorization_receipt.id,
        "auth-wrong-signer",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("wrong authorization signer should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt signer mismatch"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_copies_tenant_from_live_authorization_receipt() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-tenant",
        "auth-tenant",
        "session-tenant",
        "call-tenant",
        "fs/read_text_file",
        Some("tenant-a"),
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-tenant", "session-tenant");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-tenant",
        &authorization_receipt.id,
        "auth-tenant",
        "fs/read_text_file",
    );

    let receipt = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect("tenant-bound authorization should sign");
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-a"));
}

#[test]
fn kernel_receipt_signer_fails_closed_when_store_cannot_consume_authorization() {
    let keypair = Keypair::generate();
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-unsupported-consume",
        "auth-unsupported-consume",
        "session-unsupported-consume",
        "call-unsupported-consume",
        "fs/read_text_file",
        Some("tenant-unsupported-consume"),
    );
    let signer = KernelReceiptSigner::new(
        keypair,
        "proxy-server",
        Box::new(UnsupportedDurableConsumptionStore {
            authorization_receipt: authorization_receipt.clone(),
        }),
        10,
    );

    let mut enforced_entry =
        make_audit_entry("call-unsupported-consume", "session-unsupported-consume");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-unsupported-consume",
        &authorization_receipt.id,
        "auth-unsupported-consume",
        "fs/read_text_file",
    );

    let error = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: enforced_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect_err("unsupported durable consumption should fail closed");
    assert!(
        error
            .to_string()
            .contains("durable authorization receipt consumption is not supported"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_authorization_receipt_reuse() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-reuse",
        "auth-reuse",
        "session-reuse",
        "call-reuse",
        "fs/read_text_file",
        Some("tenant-reuse"),
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut enforced_entry = make_audit_entry("call-reuse", "session-reuse");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-reuse",
        &authorization_receipt.id,
        "auth-reuse",
        "fs/read_text_file",
    );
    let request = AcpReceiptRequest {
        audit_entry: enforced_entry,
        tool_server: "proxy-server".to_string(),
        tool_name: "fs/read_text_file".to_string(),
    };

    signer
        .sign_acp_receipt(&request)
        .expect("first enforced receipt should sign");
    let error = signer
        .sign_acp_receipt(&request)
        .expect_err("authorization receipt reuse should fail closed");
    assert!(
        error
            .to_string()
            .contains("authorization receipt already consumed"),
        "unexpected error: {error}"
    );
}

#[test]
fn kernel_receipt_signer_rejects_authorization_receipt_reuse_after_restart() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let authorization_receipt = make_authorization_receipt_with_tenant(
        &keypair,
        "cap-restart-reuse",
        "auth-restart-reuse",
        "session-restart-reuse",
        "call-restart-reuse",
        "fs/read_text_file",
        Some("tenant-restart-reuse"),
    );
    shared
        .lock()
        .expect("shared state should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let first_signer = KernelReceiptSigner::new(
        keypair.clone(),
        "proxy-server",
        Box::new(MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: false,
        }),
        0,
    );

    let mut enforced_entry = make_audit_entry("call-restart-reuse", "session-restart-reuse");
    mark_entry_cryptographically_enforced(
        &mut enforced_entry,
        "cap-restart-reuse",
        &authorization_receipt.id,
        "auth-restart-reuse",
        "fs/read_text_file",
    );
    let request = AcpReceiptRequest {
        audit_entry: enforced_entry,
        tool_server: "proxy-server".to_string(),
        tool_name: "fs/read_text_file".to_string(),
    };

    first_signer
        .sign_acp_receipt(&request)
        .expect("first enforced receipt should sign");

    let restarted_signer = KernelReceiptSigner::new(
        keypair,
        "proxy-server",
        Box::new(MockReceiptStore {
            state: Arc::clone(&shared),
            supports_checkpoints: false,
        }),
        0,
    );
    let error = restarted_signer
        .sign_acp_receipt(&request)
        .expect_err("persisted authorization consumption should survive signer restart");
    assert!(
        error
            .to_string()
            .contains("authorization receipt already consumed"),
        "unexpected error: {error}"
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
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

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
            "kind": "execute",
            "status": "completed",
            "authorization_parameter_hash": null,
        })
    );
}

/// Regression: a tool call that emits both a `running` ToolCall event and
/// a terminal `completed` (or `failed`) ToolCallUpdate event must mint
/// two distinct receipt ids. `ChioReceipt::sign` content-addresses receipt
/// ids via `chio_receipt_id`, so the per-event discriminator (status,
/// content_hash, title, kind) must flow into the canonical receipt body for
/// the content hash to diverge. Without it, the store would reject the
/// terminal update as a duplicate.
#[test]
fn tool_call_running_and_terminal_update_produce_distinct_receipt_ids() {
    let keypair = Keypair::generate();
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    // The `running` event has a distinct content hash from the terminal
    // `completed` update because the canonical event payloads differ.
    let mut running_entry = make_audit_entry("call-distinct-ids", "session-distinct-ids");
    running_entry.status = "running".to_string();
    running_entry.content_hash = "content-hash-running".to_string();
    // Pull the timestamp forward so the `chio_receipt_id` content hash is
    // not accidentally identical across the two appends.
    running_entry.timestamp = (now_secs() - 5).to_string();

    let mut completed_entry = make_audit_entry("call-distinct-ids", "session-distinct-ids");
    completed_entry.status = "completed".to_string();
    completed_entry.content_hash = "content-hash-completed".to_string();
    completed_entry.timestamp = now_secs().to_string();

    let running_receipt = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: running_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        })
        .expect("running receipt should sign and persist");
    let completed_receipt = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: completed_entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        })
        .expect("terminal completed update should not collide with the running receipt");

    assert_ne!(
        running_receipt.id, completed_receipt.id,
        "running and terminal-update receipts must have distinct ids"
    );

    // Status flows through the action parameters (which feed the
    // canonical receipt id). The action parameters carry the
    // event-status discriminator that disambiguates running vs.
    // terminal.
    let running_status = running_receipt
        .action
        .parameters
        .get("status")
        .and_then(|v| v.as_str());
    let completed_status = completed_receipt
        .action
        .parameters
        .get("status")
        .and_then(|v| v.as_str());
    assert_eq!(running_status, Some("running"));
    assert_eq!(completed_status, Some("completed"));

    // The on-receipt content_hash also diverges (it is sourced from the
    // canonical ACP audit entry, which differs between the events).
    assert_ne!(running_receipt.content_hash, completed_receipt.content_hash);

    // The store must contain both receipts (i.e. the second sign call
    // didn't crash on a duplicate-id append).
    let appended = shared
        .lock()
        .expect("mock store should lock")
        .appended_receipts
        .clone();
    assert_eq!(
        appended.len(),
        2,
        "both running and terminal-update receipts should be persisted",
    );
    let ids: Vec<_> = appended.iter().map(|r| r.id.clone()).collect();
    assert!(ids.contains(&running_receipt.id));
    assert!(ids.contains(&completed_receipt.id));
}

/// Regression: the kernel-generated `request_id` from the live capability
/// check must round-trip from the authorization receipt to the consumer
/// receipt's metadata, so downstream verifiers can stitch the audit log
/// together. Both receipts expose the same
/// `metadata.receipt_context.request_id` value.
#[test]
fn live_authorization_request_id_uses_kernel_receipt_linkage() {
    let keypair = Keypair::generate();
    let authorization_receipt = make_authorization_receipt(
        &keypair,
        "cap-request-id-round-trip",
        "auth-request-round-trip",
        "session-round-trip",
        "call-round-trip",
        "fs/read_text_file",
    );

    // The authorization receipt written by the kernel carries its trusted
    // request linkage in receipt_context. This is what
    // `verify_live_authorization_receipt` checks at kernel_signer.rs.
    let auth_request_id_in_metadata = authorization_receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("receipt_context"))
        .and_then(|c| c.get("request_id"))
        .and_then(|v| v.as_str())
        .expect("authorization receipt metadata.receipt_context.request_id should be set");
    assert_eq!(auth_request_id_in_metadata, "auth-request-round-trip");

    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    shared
        .lock()
        .expect("mock store should lock")
        .appended_receipts
        .push(authorization_receipt.clone());
    let store = MockReceiptStore {
        state: Arc::clone(&shared),
        supports_checkpoints: false,
    };
    let signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(store), 0);

    let mut entry = make_audit_entry("call-round-trip", "session-round-trip");
    entry.status = "completed".to_string();
    mark_entry_cryptographically_enforced(
        &mut entry,
        "cap-request-id-round-trip",
        &authorization_receipt.id,
        "auth-request-round-trip",
        "fs/read_text_file",
    );

    let consumer_receipt = signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: entry,
            tool_server: "proxy-server".to_string(),
            tool_name: "fs/read_text_file".to_string(),
        })
        .expect("consumer receipt should sign once the authorization receipt is verified");

    // The consumer receipt mirrors the same request_id at the canonical
    // `metadata.receipt_context.request_id` path.
    let consumer_request_id = consumer_receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("receipt_context"))
        .and_then(|c| c.get("request_id"))
        .and_then(|v| v.as_str())
        .expect("consumer receipt metadata.receipt_context.request_id should be set");
    assert_eq!(consumer_request_id, "auth-request-round-trip");
    assert_eq!(consumer_request_id, auth_request_id_in_metadata);

    // The consumer receipt also keeps the authorization linkage at
    // metadata.acp.authorizationRequestId (existing field, unchanged).
    let acp_authorization_request_id = consumer_receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("acp"))
        .and_then(|acp| acp.get("authorizationRequestId"))
        .and_then(|v| v.as_str())
        .expect("consumer receipt metadata.acp.authorizationRequestId should be set");
    assert_eq!(acp_authorization_request_id, "auth-request-round-trip");
}

#[test]
fn kernel_receipt_signer_decouples_checkpoint_errors_from_message_flow() {
    // Contract: once a receipt has been appended to the store, a
    // subsequent checkpoint failure must NOT block the ACP message
    // flow. The signed receipt is returned to the caller, and the
    // checkpoint failure surfaces through `checkpoint_health` for
    // operators to inspect.
    let keypair = Keypair::generate();

    let status_error_receipt = make_authorization_receipt(
        &keypair,
        "cap-status-unsupported",
        "auth-status-unsupported",
        "session-status-unsupported",
        "call-status-unsupported",
        "fs/read_text_file",
    );
    let status_error_signer = KernelReceiptSigner::new(
        keypair.clone(),
        "proxy-server",
        Box::new(UnsupportedDurableConsumptionStore {
            authorization_receipt: status_error_receipt,
        }),
        1,
    );
    let receipt = status_error_signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: make_audit_entry("status-unsupported", "session-status"),
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        })
        .expect("checkpoint failure must not block successful receipt append");
    assert_eq!(receipt.tool_name, "terminal/create");
    let health = status_error_signer.checkpoint_health();
    assert_eq!(health.consecutive_failures, 1);
    let recorded = health
        .last_checkpoint_error
        .as_deref()
        .expect("checkpoint failure should be recorded in health");
    assert!(
        recorded.contains("receipt checkpoint status failed"),
        "unexpected recorded error: {recorded}"
    );

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
    let receipt = unsupported_signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: make_audit_entry("unsupported", "session-unsupported"),
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        })
        .expect("unsupported checkpoint store must not block append");
    assert_eq!(receipt.tool_name, "terminal/create");
    let health = unsupported_signer.checkpoint_health();
    assert_eq!(health.consecutive_failures, 1);
    let recorded = health
        .last_checkpoint_error
        .as_deref()
        .expect("checkpoint failure should be recorded in health");
    assert!(
        recorded.contains("receipt checkpoint status failed")
            || recorded.contains("receipt checkpoint creation failed"),
        "unexpected recorded error: {recorded}"
    );
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
    let empty_signer = KernelReceiptSigner::new(keypair, "proxy-server", Box::new(empty_store), 1);
    let receipt = empty_signer
        .sign_acp_receipt(&AcpReceiptRequest {
            audit_entry: make_audit_entry("empty", "session-empty"),
            tool_server: "proxy-server".to_string(),
            tool_name: "terminal/create".to_string(),
        })
        .expect("missing checkpoint bytes must not block append");
    assert_eq!(receipt.tool_name, "terminal/create");
    let health = empty_signer.checkpoint_health();
    assert_eq!(health.consecutive_failures, 1);
    let recorded = health
        .last_checkpoint_error
        .as_deref()
        .expect("checkpoint failure should be recorded in health");
    assert!(
        recorded.contains("checkpoint canonical bytes are missing"),
        "unexpected recorded error: {recorded}"
    );
    let state = empty_state.lock().expect("shared state should lock");
    assert_eq!(state.appended_receipts.len(), 1);
    assert!(state.canonical_ranges.is_empty());
    assert!(state.checkpoints.is_empty());
}
