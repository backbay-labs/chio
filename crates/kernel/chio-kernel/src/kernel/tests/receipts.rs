#[test]
fn dead_commit_writer_denies_before_the_tool_executes() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel
        .set_receipt_store(Box::new(DeadWriterReceiptStore))
        .unwrap();

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-dead-writer", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    // The pre-dispatch gate reads the writer flag and fails closed: an authorized
    // call is denied because durable persistence can no longer be trusted.
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("commit writer is not serving"),
        "expected a receipt-persistence-degraded deny, got: {reason}"
    );
    // The load-bearing property: the tool never ran, so no evidence-less side
    // effect occurred.
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a degraded commit writer must deny before the tool executes"
    );
}

#[test]
fn serving_closed_store_deny_is_not_masked_by_its_own_receipt_append() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    // A serving-closed store whose appends actually fail, like a real
    // poisoned-head or dead writer (the earlier double still accepts appends).
    kernel
        .set_receipt_store(Box::new(RejectingDeadWriterReceiptStore))
        .unwrap();

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-rejecting-writer", &cap, "read_file", "srv-a");

    // The pre-dispatch gate denies because the writer is serving-closed. Building
    // that deny must NOT try to persist the deny receipt through the same closed
    // store: that append would fail and surface a 500 instead of the clean signed
    // Deny verdict. The verdict is what callers must see.
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("commit writer is not serving"),
        "expected a receipt-persistence-degraded deny, got: {reason}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a serving-closed writer must deny before the tool executes"
    );
}

#[test]
fn serving_closed_store_denies_before_an_early_capability_rejection() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel
        .set_receipt_store(Box::new(RejectingDeadWriterReceiptStore))
        .unwrap();

    // An untrusted-issuer capability is rejected by the very first pre-dispatch
    // check, ahead of the persistence gate. That early rejection records its deny
    // receipt through the receipt writer, and against a serving-closed store the
    // append fails and would surface an opaque error (or a 500) instead of a
    // signed verdict. The writer-health gate must run FIRST so the caller always
    // sees the clean fail-closed persistence Deny.
    let rogue_kp = make_keypair();
    let agent_kp = make_keypair();
    let body = CapabilityTokenBody {
        id: "cap-rogue-serving-closed".to_string(),
        issuer: rogue_kp.public_key(),
        subject: agent_kp.public_key(),
        scope: make_scope(vec![make_grant("srv-a", "read_file")]),
        issued_at: current_unix_timestamp(),
        expires_at: current_unix_timestamp() + 300,
        delegation_chain: vec![],
    };
    let cap = CapabilityToken::sign(body, &rogue_kp).unwrap();
    let request = make_request("req-rogue-serving-closed", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("commit writer is not serving"),
        "expected a receipt-persistence-degraded deny, got: {reason}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a serving-closed writer must deny before the tool executes"
    );
}

#[test]
fn dead_commit_writer_denies_before_the_capability_lineage_write() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let snapshot_attempted = std::sync::Arc::new(AtomicBool::new(false));
    let fail_snapshots = std::sync::Arc::new(AtomicBool::new(false));
    kernel
        .set_receipt_store(Box::new(SnapshotTrackingDeadWriterStore {
            snapshot_attempted: std::sync::Arc::clone(&snapshot_attempted),
            fail_snapshots: std::sync::Arc::clone(&fail_snapshots),
        }))
        .unwrap();

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-dead-writer-lineage", &cap, "read_file", "srv-a");

    // Arm the writer only after issuance: from here a lineage write fails like a
    // poisoned writer, so the evaluation below is what must be gated.
    fail_snapshots.store(true, Ordering::SeqCst);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    // The writer-readiness gate must run BEFORE the capability-lineage write. A
    // serving-closed writer must produce the clean fail-closed persistence deny
    // rather than first attempting a metadata write through the dead writer and
    // surfacing that write's error (or a 500) instead.
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("commit writer is not serving"),
        "expected a receipt-persistence-degraded deny, got: {reason}"
    );
    // The load-bearing property: no writer-backed metadata write is attempted
    // once the gate has denied, so nothing is pushed through the dead writer.
    assert!(
        !snapshot_attempted.load(Ordering::SeqCst),
        "the capability lineage write must not be attempted after the writer gate denies"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a degraded commit writer must deny before the tool executes"
    );
}

#[test]
fn kernel_persists_tool_receipts_to_sqlite_store() {
    let path = unique_receipt_db_path("chio-kernel-tool-receipts");
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-sqlite-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
    drop(kernel);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let (count, distinct_count, receipt_id): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM chio_tool_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let child_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(count, 1);
    assert_eq!(distinct_count, 1);
    assert_eq!(child_count, 0);
    assert_content_addressed_receipt_id(&receipt_id);

    drop(connection);
    let _ = std::fs::remove_file(path);
}

/// Configured retention is a storage/compliance control. Attaching a store
/// that cannot rotate (the default `rotate_receipts` stub) while
/// `retention_config` is set must fail closed: otherwise the kernel would serve
/// traffic while the background worker only logs "not supported" every interval
/// and never archives anything.
#[test]
fn attach_rejects_configured_retention_on_unsupported_store() {
    let mut config = make_config();
    config.retention_config = Some(crate::RetentionConfig::default());
    let mut kernel = make_kernel(config);
    let error = kernel
        .set_receipt_store(Box::new(AppendOnlyReceiptStore))
        .expect_err("attach must reject a retention-configured store that cannot rotate");
    assert!(
        matches!(&error, KernelError::Internal(message) if message.contains("does not support retention")),
        "unexpected error: {error:?}"
    );
}

/// A tenant-scoped retention policy cannot be honored by a prefix-watermark
/// store: rotation archives a contiguous checkpointed prefix of the whole log,
/// not one tenant's rows, so `rotate_receipts` fails closed. Attaching a store
/// that supports retention but not tenant scope under such a policy must fail
/// closed at attach time, not spawn a worker that logs "unsupported" every
/// interval while the kernel serves traffic the policy can never cover.
#[test]
fn attach_rejects_tenant_scoped_retention() {
    let mut config = make_config();
    config.retention_config = Some(crate::RetentionConfig {
        tenant_id: Some("tenant-a".to_string()),
        ..crate::RetentionConfig::default()
    });
    let mut kernel = make_kernel(config);
    let error = kernel
        .set_receipt_store(Box::new(RetentionCapableReceiptStore))
        .expect_err("attach must reject a tenant-scoped retention policy the store cannot honor");
    assert!(
        matches!(&error, KernelError::Internal(message) if message.contains("tenant-scoped retention")),
        "unexpected error: {error:?}"
    );
}

/// Prefix retention only ever archives receipts covered by a kernel checkpoint,
/// so it depends on automatic checkpointing being enabled. Attaching a
/// retention-configured store while `checkpoint_batch_size == 0` installs no
/// background signer, so the checkpoint chain never advances past 0 and the
/// retention worker could never archive anything: the store would silently
/// retain every receipt forever. The attach must fail closed rather than serve
/// under a retention policy that can never advance its watermark.
#[test]
fn attach_rejects_retention_when_checkpointing_disabled() {
    let mut config = make_config();
    config.checkpoint_batch_size = 0;
    config.retention_config = Some(crate::RetentionConfig::default());
    let mut kernel = make_kernel(config);
    let error = kernel
        .set_receipt_store(Box::new(RetentionCapableReceiptStore))
        .expect_err("attach must reject retention when automatic checkpointing is disabled");
    assert!(
        matches!(&error, KernelError::Internal(message) if message.contains("automatic checkpointing is disabled")),
        "unexpected error: {error:?}"
    );
}

#[test]
fn all_calls_produce_verified_receipts() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Allowed call.
    let req = make_request("req-1", &cap, "read_file", "srv-a");
    let _ = kernel.evaluate_tool_call_blocking(&req).unwrap();

    // Denied call (wrong tool).
    let req2 = make_request("req-2", &cap, "write_file", "srv-a");
    let _ = kernel.evaluate_tool_call_blocking(&req2).unwrap();

    assert_eq!(kernel.receipt_log().len(), 2);

    for r in kernel.receipt_log().receipts() {
        assert!(r.verify_signature().unwrap());
    }
}

#[test]
fn receipt_log_basics() {
    let log = ReceiptLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn store_miss_falls_back_to_local_mirror() {
    // A durable store that appends but cannot point-load (an append-only or remote
    // store, like RemoteReceiptStore) must not disable the local mirror. A receipt
    // appended and mirrored locally has to resolve on a store miss.
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore)).unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-store-miss-mirror", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // The receipt is in the local mirror; AppendOnlyReceiptStore's load_* miss.
    let receipt_id = kernel.receipt_log().receipts()[0].id.clone();
    assert!(
        kernel.has_local_receipt_id(&receipt_id).unwrap(),
        "store miss must fall back to the local mirror"
    );
    assert!(
        kernel.local_receipt_artifact(&receipt_id).unwrap().is_some(),
        "store miss must return the mirrored artifact"
    );
}

#[test]
fn store_read_error_propagates_and_is_not_mirror_served() {
    // A durable store READ error must fail closed. A receipt present in the local
    // mirror must NOT mask a store read failure; only a genuine miss (`Ok(None)`)
    // may fall back to the mirror. Here the store appends fine (so the mirror holds
    // the receipt) but errors on every point load, so both lookups must PROPAGATE
    // the error, not serve the mirror copy.
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ErroringReceiptStore)).unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-store-read-error", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let receipt_id = kernel.receipt_log().receipts()[0].id.clone();
    assert!(
        kernel.has_local_receipt_id(&receipt_id).is_err(),
        "store read error must propagate, not fall back to the mirror"
    );
    assert!(
        kernel.local_receipt_artifact(&receipt_id).is_err(),
        "store read error must propagate, not serve the mirrored artifact"
    );
}

#[test]
fn point_load_store_resolves_parent_receipt_after_mirror_eviction() {
    // The receipt mirror is bounded, so it is NOT a durable point-lookup source. A
    // store-authoritative deployment whose store implements point loads (here
    // SqliteReceiptStore) must still resolve a parent receipt by id AFTER the
    // bounded mirror has evicted it, so governed call-chain validation of an older
    // parent_receipt_id does not falsely deny.
    let mut config = make_config();
    config.memory_budget.receipt_mirror_capacity = 2;
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(PointLookupReceiptStore::default()))
        .unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let first = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-evict-1",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({ "path": "/f-1" }),
        ))
        .unwrap();
    let first_id = first.receipt.id.clone();

    // Push more receipts than the mirror cap so the first is evicted from it.
    for i in 2..=5 {
        kernel
            .evaluate_tool_call_blocking(&make_request_with_arguments(
                &format!("req-evict-{i}"),
                &cap,
                "read_file",
                "srv-a",
                serde_json::json!({ "path": format!("/f-{i}") }),
            ))
            .unwrap();
    }

    assert!(
        !kernel
            .receipt_log()
            .receipts()
            .iter()
            .any(|r| r.id == first_id),
        "precondition: first receipt must be evicted from the bounded mirror"
    );
    // A point-load-capable store still resolves the evicted parent receipt.
    assert!(
        kernel.has_local_receipt_id(&first_id).unwrap(),
        "point-load store must resolve an evicted parent receipt by id"
    );
    assert!(kernel.local_receipt_artifact(&first_id).unwrap().is_some());
}

#[test]
fn append_only_store_fails_closed_for_parent_receipt_after_mirror_eviction() {
    // The documented boundary for an append-only or remote store that does NOT
    // implement point loads: it relies entirely on the bounded mirror. Once the
    // mirror evicts a receipt, an older parent_receipt_id resolves in neither the
    // store nor the mirror, so governed call-chain validation fails closed (a safe
    // deny, never a false allow). Deployments that must avoid this MUST implement
    // ReceiptStore::load_chio_receipt.
    let mut config = make_config();
    config.memory_budget.receipt_mirror_capacity = 2;
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(AppendOnlyReceiptStore))
        .unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let first = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-ao-1",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({ "path": "/f-1" }),
        ))
        .unwrap();
    let first_id = first.receipt.id.clone();

    // While still in the mirror, the receipt resolves via the mirror fallback.
    assert!(
        kernel.has_local_receipt_id(&first_id).unwrap(),
        "receipt must resolve from the mirror before eviction"
    );

    // Push more receipts than the mirror cap so the first is evicted.
    for i in 2..=5 {
        kernel
            .evaluate_tool_call_blocking(&make_request_with_arguments(
                &format!("req-ao-{i}"),
                &cap,
                "read_file",
                "srv-a",
                serde_json::json!({ "path": format!("/f-{i}") }),
            ))
            .unwrap();
    }

    assert!(
        !kernel
            .receipt_log()
            .receipts()
            .iter()
            .any(|r| r.id == first_id),
        "precondition: first receipt must be evicted from the bounded mirror"
    );
    // Documented boundary: append-only store cannot point-load and the mirror
    // evicted it, so the lookup fails closed (false = deny of any dependent
    // call-chain claim, never a false allow).
    assert!(
        !kernel.has_local_receipt_id(&first_id).unwrap(),
        "append-only store + mirror eviction must fail closed (no false allow)"
    );
    assert!(kernel.local_receipt_artifact(&first_id).unwrap().is_none());
}

#[test]
fn kernel_bounded_registry_lists_every_labelled_structure() {
    // Every kernel-held bounded structure has a live gauge; the registry enumerates
    // them so the soak harness and a future long-lived-collection lint can read
    // them. Fails if a label is dropped.
    let kernel = make_kernel(make_config());
    let labels: Vec<&'static str> = kernel
        .bounded_structure_gauges()
        .into_iter()
        .map(|(label, _count)| label)
        .collect();
    for expected in [
        "receipt_mirror",
        "child_receipt_mirror",
        "federation_dual_receipts",
        "federation_dsse_envelopes",
    ] {
        assert!(
            labels.contains(&expected),
            "bounded registry is missing the gauge label {expected}: {labels:?}"
        );
    }
}

#[test]
fn receipt_log_ring_caps_and_reports_gauge() {
    // The mirror is a capacity-bounded ring reporting a live gauge; appends past
    // the cap evict the oldest, they never grow the Vec.
    let gauge = chio_bounded::SizeGauge::new();
    let kp = make_keypair();
    let mut log = ReceiptLog::with_capacity(4, gauge.clone());
    // `ChioReceipt::sign` derives the receipt id (content hash), so capture the
    // ids in append order rather than assuming they equal the body label.
    let mut appended_ids: Vec<String> = Vec::new();
    for i in 0..10u32 {
        let receipt = make_signed_receipt(&kp, &format!("r-{i}"));
        appended_ids.push(receipt.id.clone());
        log.append(receipt);
    }
    assert_eq!(log.len(), 4, "ring caps at 4");
    assert_eq!(gauge.get(), 4, "gauge tracks ring len");
    // Only the last four appended survive, in append order (oldest evicted).
    let ids: Vec<String> = log.iter().map(|r| r.id.clone()).collect();
    assert_eq!(ids, appended_ids[6..10].to_vec());

    // Capacity 0 disables the mirror entirely (store-authoritative default).
    let gauge_zero = chio_bounded::SizeGauge::new();
    let mut log_zero = ReceiptLog::with_capacity(0, gauge_zero.clone());
    log_zero.append(make_signed_receipt(&kp, "r-zero"));
    assert_eq!(log_zero.len(), 0, "capacity 0 stores nothing");
    assert_eq!(gauge_zero.get(), 0);
}

#[test]
fn kernel_persists_child_receipts_to_sqlite_store() {
    let path = unique_receipt_db_path("chio-kernel-child-receipts");
    let mut config = make_config();
    config.allow_sampling = true;
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
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
                "text": "sampled via durable store test",
            }),
            model: "gpt-test".to_string(),
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
        "nested-tool-sqlite-1",
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
    drop(kernel);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let tool_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let (child_count, distinct_child_count, child_receipt_id): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM chio_child_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert_eq!(tool_count, 1);
    assert_eq!(child_count, 1);
    assert_eq!(distinct_child_count, 1);
    assert!(child_receipt_id.starts_with("child-rcpt-"));

    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn nested_admission_denied_while_rss_shedding() {
    // The nested-flow admission path must gate on the RSS soft ceiling just like
    // the top-level evaluate, so a nested tool call (sampling/elicitation) cannot
    // allocate and run after the sampler raised the shed flag.
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
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])
        .unwrap();
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
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    // Raise the RSS soft-ceiling shed flag, mirroring the sampler crossing the
    // configured limit.
    kernel.set_rss_shed_for_test(true);

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "must never run" }),
            model: "gpt-test".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context =
        make_operation_context(&session_id, "nested-rss-shed", &agent_kp.public_key().to_hex());
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

    let result = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    );
    assert!(
        matches!(result, Err(KernelError::Overloaded { .. })),
        "nested admission must be denied Overloaded while RSS-shedding, got {result:?}"
    );

    // Receipt totality: the nested shed must still persist a signed deny receipt
    // naming the shed resource, like every other denial.
    let receipts = kernel.receipt_log().receipts();
    let shed_receipt = receipts
        .iter()
        .find(|receipt| {
            matches!(
                receipt.decision.as_ref(),
                Some(Decision::Deny { guard, .. }) if guard == "kernel.overload"
            )
        })
        .expect("nested shed must persist a signed overload deny receipt");
    assert!(
        shed_receipt.verify_signature().unwrap(),
        "nested shed deny receipt must verify"
    );
    match shed_receipt.decision.clone() {
        Some(Decision::Deny { reason, .. }) => assert!(
            reason.contains("memory budget") && reason.contains("Allocation"),
            "nested shed deny reason must name the shed resource, got {reason:?}"
        ),
        other => panic!("expected overload deny decision, got {other:?}"),
    }
}

#[test]
fn rss_shed_persists_signed_overload_deny_receipt() {
    // Receipt totality: an RSS soft-ceiling shed is a denied admission and must
    // persist a signed deny receipt naming the shed resource, exactly like the
    // emergency-stop fast path, even though it also returns Overloaded to the
    // caller for backpressure. error.rs guarantees the OverloadResource appears in
    // a receipt deny reason.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Raise the RSS soft-ceiling shed flag, mirroring the sampler crossing the
    // configured limit.
    kernel.set_rss_shed_for_test(true);

    let request = make_request("req-rss-shed-receipt", &cap, "read_file", "srv-a");
    let result = kernel.evaluate_tool_call_blocking(&request);

    // Backpressure edge preserved: the shed still surfaces as Overloaded.
    assert!(
        matches!(result, Err(KernelError::Overloaded { .. })),
        "shed must return Overloaded, got {result:?}"
    );

    // Receipt-totality: exactly one signed deny receipt naming the shed resource.
    let receipts = kernel.receipt_log().receipts();
    assert_eq!(
        receipts.len(),
        1,
        "shed must persist exactly one deny receipt"
    );
    assert!(
        receipts[0].verify_signature().unwrap(),
        "shed deny receipt must verify"
    );
    match receipts[0].decision.clone() {
        Some(Decision::Deny { reason, guard }) => {
            assert!(
                reason.contains("memory budget") && reason.contains("Allocation"),
                "shed deny reason must name the shed resource, got {reason:?}"
            );
            assert_eq!(guard, "kernel.overload");
        }
        other => panic!("expected overload deny decision, got {other:?}"),
    }
}

#[test]
fn non_tool_admission_denied_while_rss_shedding() {
    // The RSS soft-ceiling shed must also apply to NON-TOOL admissions. Resource
    // reads, prompt gets, and completions all funnel through
    // `validate_non_tool_capability`. Under RSS pressure a large read_resource or
    // prompt completion must not allocate and execute while tool calls are being
    // shed, or the soft ceiling would not shed all new admissions. The helper must
    // shed uniformly (fail-closed Overloaded).
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let agent_id = agent_kp.public_key().to_hex();

    // Sanity: with shedding OFF the non-tool admission helper passes (valid cap).
    kernel
        .validate_non_tool_capability(&cap, &agent_id)
        .expect("non-tool admission should pass when not shedding");

    // Raise the RSS soft-ceiling shed flag, mirroring the sampler crossing the
    // configured limit.
    kernel.set_rss_shed_for_test(true);

    let result = kernel.validate_non_tool_capability(&cap, &agent_id);
    assert!(
        matches!(result, Err(KernelError::Overloaded { .. })),
        "non-tool admission must shed Overloaded while RSS-shedding, got {result:?}"
    );
}

#[test]
fn session_tool_call_records_incomplete_terminal_state() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(IncompleteServer {
        id: "broken".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("broken", "drop_stream")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "incomplete-tool-call",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability,
        server_id: "broken".to_string(),
        tool_name: "drop_stream".to_string(),
        arguments: serde_json::json!({}),
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

    let expected_reason = "upstream stream closed before tool response completed".to_string();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Incomplete {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_incomplete());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Incomplete {
            reason: expected_reason,
        })
    );
}

#[test]
fn streamed_tool_receipt_records_chunk_hash_metadata() {
    let mut kernel = make_kernel(make_config());
    let chunk_a = serde_json::json!({"delta": "hello"});
    let chunk_b = serde_json::json!({"delta": {"path": "/workspace/README.md"}});
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![chunk_a.clone(), chunk_b.clone()],
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("stream", "stream_file")]),
        300,
    );
    let request = make_request_with_arguments(
        "stream-receipt",
        &capability,
        "stream_file",
        "stream",
        serde_json::json!({"path": "/workspace/README.md"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("stream metadata");
    let stream_metadata = metadata.get("stream").expect("stream metadata object");
    assert_eq!(stream_metadata["chunks_expected"].as_u64(), Some(2));
    assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(2));

    let chunk_a_bytes = chio_core::canonical::canonical_json_bytes(&chunk_a).unwrap();
    let chunk_b_bytes = chio_core::canonical::canonical_json_bytes(&chunk_b).unwrap();
    let expected_total_bytes = (chunk_a_bytes.len() + chunk_b_bytes.len()) as u64;
    assert_eq!(
        stream_metadata["total_bytes"].as_u64(),
        Some(expected_total_bytes)
    );

    let chunk_hashes = stream_metadata["chunk_hashes"]
        .as_array()
        .expect("chunk hashes array")
        .iter()
        .map(|value| value.as_str().expect("chunk hash string").to_string())
        .collect::<Vec<_>>();
    let expected_hashes = vec![
        chio_core::crypto::sha256_hex(&chunk_a_bytes),
        chio_core::crypto::sha256_hex(&chunk_b_bytes),
    ];
    assert_eq!(chunk_hashes, expected_hashes);

    let expected_content_hash = chio_core::crypto::sha256_hex(expected_hashes.join("").as_bytes());
    assert_eq!(response.receipt.content_hash, expected_content_hash);
}

#[test]
fn streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete() {
    let mut config = make_config();
    config.max_stream_total_bytes = 20;
    let mut kernel = make_kernel(config);
    let first_chunk = serde_json::json!({"delta": "ok"});
    let second_chunk = serde_json::json!({"delta": "this chunk exceeds the configured byte limit"});
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![first_chunk.clone(), second_chunk],
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("stream", "stream_file")]),
        300,
    );
    let request = make_request_with_arguments(
        "stream-byte-limit",
        &capability,
        "stream_file",
        "stream",
        serde_json::json!({}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.is_incomplete());
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("max total bytes"));

    let output_stream = tool_call_stream_output(response.output).expect("expected stream output");
    assert_eq!(output_stream.chunk_count(), 1);
    assert_eq!(output_stream.chunks[0].data, first_chunk);

    let stream_metadata = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("stream"))
        .expect("stream metadata");
    assert!(stream_metadata["chunks_expected"].is_null());
    assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(1));
}

#[test]
fn redaction_reapplies_stream_chunk_cap() {
    // apply_stream_limits runs on the ORIGINAL tool output, before the
    // post-invocation pipeline. A Redact hook that emits a stream with more chunks
    // than `max_stream_chunks` would otherwise bypass the retained-chunk cap and
    // grow the final signed output and receipt preimage past the configured budget.
    // The redacted stream must be re-capped.
    struct OversizeRedactHook;
    impl crate::post_invocation::PostInvocationHook for OversizeRedactHook {
        fn name(&self) -> &str {
            "oversize-redact"
        }
        fn inspect(
            &self,
            _ctx: &crate::post_invocation::PostInvocationContext<'_>,
            _response: &serde_json::Value,
        ) -> crate::post_invocation::PostInvocationVerdict {
            // Redact to a 5-chunk COMPLETE stream regardless of the input.
            crate::post_invocation::PostInvocationVerdict::Redact(serde_json::json!({
                "kind": "stream",
                "stream": {
                    "complete": true,
                    "chunks": [ {"n": 0}, {"n": 1}, {"n": 2}, {"n": 3}, {"n": 4} ],
                }
            }))
        }
    }

    let mut config = make_config();
    config.max_stream_total_bytes = 0; // unlimited bytes: isolate the chunk cap
    config.memory_budget.max_stream_chunks = 2;
    let mut kernel = make_kernel(config);
    kernel.add_post_invocation_hook(Box::new(OversizeRedactHook));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-redact-recap", &cap, "read_file", "srv-a");

    // The ORIGINAL output is a small 1-chunk stream that passes the first cap pass.
    let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
        chunks: vec![ToolCallChunk {
            data: serde_json::json!({"orig": true}),
        }],
    }));

    let response = kernel
        .finalize_tool_output_with_metadata(
            &request,
            output,
            std::time::Duration::from_secs(0),
            100,
            0,
            None,
        )
        .unwrap();

    // The redacted 5-chunk stream must be truncated to the 2-chunk cap and marked
    // incomplete, not signed and receipted verbatim.
    let output_stream = tool_call_stream_output(response.output).expect("expected stream output");
    assert!(
        output_stream.chunk_count() <= 2,
        "redacted stream bypassed the chunk cap: {} chunks",
        output_stream.chunk_count()
    );
    assert!(
        response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("max chunk count of 2"),
        "unexpected reason: {:?}",
        response.reason
    );
    // The receipt preimage is bounded to the same retained-chunk count.
    let stream_metadata = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("stream"))
        .expect("stream metadata");
    assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(2));
}

#[test]
fn apply_stream_limits_marks_duration_exceeded_stream_incomplete() {
    let mut config = make_config();
    config.max_stream_duration_secs = 1;
    let kernel = make_kernel(config);
    let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
        chunks: vec![ToolCallChunk {
            data: serde_json::json!({"delta": "slow"}),
        }],
    }));

    let limited = kernel
        .apply_stream_limits(output, std::time::Duration::from_secs(2))
        .unwrap();

    let (stream, reason) = match limited {
        ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
            Some((stream, reason))
        }
        _ => None,
    }
    .expect("expected limited incomplete stream");
    assert_eq!(stream.chunk_count(), 1);
    assert!(reason.contains("max duration of 1s"));
}

#[test]
fn apply_stream_limits_marks_chunk_count_exceeded_stream_incomplete() {
    // The retained-chunk count is bounded as well as the total bytes. With a huge
    // byte cap but `max_stream_chunks = 1`, a 3-tiny-chunk stream (well under the
    // byte cap) is TRUNCATED to one chunk and the receipt is marked incomplete with
    // a chunk-count reason.
    let mut config = make_config();
    config.max_stream_total_bytes = 10_000_000; // never reached by tiny chunks
    config.memory_budget.max_stream_chunks = 1;
    let kernel = make_kernel(config);
    let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
        chunks: vec![
            ToolCallChunk {
                data: serde_json::json!({"delta": "a"}),
            },
            ToolCallChunk {
                data: serde_json::json!({"delta": "b"}),
            },
            ToolCallChunk {
                data: serde_json::json!({"delta": "c"}),
            },
        ],
    }));

    let limited = kernel
        .apply_stream_limits(output, std::time::Duration::from_secs(0))
        .unwrap();

    let (stream, reason) = match limited {
        ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
            Some((stream, reason))
        }
        _ => None,
    }
    .expect("expected chunk-limited incomplete stream");
    assert_eq!(
        stream.chunk_count(),
        1,
        "stream must be truncated to the chunk cap"
    );
    assert!(
        reason.contains("max chunk count of 1"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn checkpoint_triggers_at_100_receipts() {
    let path = unique_receipt_db_path("chio-checkpoint-trigger");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 10; // Use 10 for speed.

    let mut kernel = make_kernel(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    for i in 0..10 {
        kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    // Flush barrier: background checkpoints are built on the writer thread
    // after the batch commits; a flush drains the actor past that point.
    kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    // Verify a checkpoint was stored in the database.
    let store2 = SqliteReceiptStore::open(&path).unwrap();
    let checkpoint = store2.load_checkpoint_by_seq(1).unwrap();
    assert!(
        checkpoint.is_some(),
        "checkpoint should have been stored after 10 receipts"
    );
    let cp = checkpoint.unwrap();
    assert_eq!(cp.body.checkpoint_seq, 1);
    assert_eq!(cp.body.batch_start_seq, 1);
    assert_eq!(cp.body.batch_end_seq, 10);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn concurrent_receipt_checkpointing_keeps_contiguous_batches() {
    let path = unique_receipt_db_path("chio-checkpoint-concurrent");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 2;

    let mut kernel = make_kernel(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let kernel = std::sync::Arc::new(kernel);
    let agent_id = agent_kp.public_key().to_hex();

    let handles = (0..12)
        .map(|i| {
            let kernel = std::sync::Arc::clone(&kernel);
            let cap = cap.clone();
            let agent_id = agent_id.clone();
            std::thread::spawn(move || {
                kernel
                    .evaluate_tool_call_blocking(&ToolCallRequest {
                        request_id: format!("req-concurrent-{i}"),
                        capability: cap,
                        tool_name: "echo".to_string(),
                        server_id: "srv".to_string(),
                        agent_id,
                        arguments: serde_json::json!({ "i": i }),
                        dpop_proof: None,
                        execution_nonce: None,
                        governed_intent: None,
                        approval_token: None,
                        model_metadata: None,
                        federated_origin_kernel_id: None,
                    })
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().unwrap();
    }

    kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    let store2 = SqliteReceiptStore::open(&path).unwrap();
    for checkpoint_seq in 1..=6 {
        let checkpoint = store2
            .load_checkpoint_by_seq(checkpoint_seq)
            .unwrap()
            .unwrap_or_else(|| panic!("checkpoint {checkpoint_seq} should exist"));
        assert_eq!(checkpoint.body.checkpoint_seq, checkpoint_seq);
        assert_eq!(checkpoint.body.batch_start_seq, (checkpoint_seq - 1) * 2 + 1);
        assert_eq!(checkpoint.body.batch_end_seq, checkpoint_seq * 2);
    }
    assert!(store2.load_checkpoint_by_seq(7).unwrap().is_none());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_counters_restore_when_store_is_reattached() {
    let path = unique_receipt_db_path("chio-checkpoint-restart");
    let kernel_kp = make_keypair();
    let mut first_config = make_monetary_config();
    first_config.keypair = kernel_kp.clone();
    first_config.checkpoint_batch_size = 2;
    let mut second_config = make_monetary_config();
    second_config.keypair = kernel_kp;
    second_config.checkpoint_batch_size = 2;

    let agent_kp = Keypair::generate();
    let grant = make_grant("srv", "echo");
    let mut first_kernel = make_kernel(first_config);
    first_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    first_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    let cap = first_kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let agent_id = agent_kp.public_key().to_hex();

    for i in 0..2 {
        first_kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-before-restart-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_id.clone(),
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    first_kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    let mut restarted_kernel = make_kernel(second_config);
    restarted_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    restarted_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    assert_eq!(
        restarted_kernel
            .checkpoint_seq_counter
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        restarted_kernel
            .last_checkpoint_seq
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    for i in 2..4 {
        restarted_kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-after-restart-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_id.clone(),
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    restarted_kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    let store = SqliteReceiptStore::open(&path).unwrap();
    let first_checkpoint = store
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("checkpoint 1 should exist before restart");
    let second_checkpoint = store
        .load_checkpoint_by_seq(2)
        .unwrap()
        .expect("checkpoint 2 should exist after restart");
    assert_eq!(first_checkpoint.body.batch_start_seq, 1);
    assert_eq!(first_checkpoint.body.batch_end_seq, 2);
    assert_eq!(second_checkpoint.body.batch_start_seq, 3);
    assert_eq!(second_checkpoint.body.batch_end_seq, 4);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_counters_refresh_across_kernels_sharing_store() {
    let path = unique_receipt_db_path("chio-checkpoint-two-kernels");
    let kernel_kp = make_keypair();
    let mut first_config = make_monetary_config();
    first_config.keypair = kernel_kp.clone();
    first_config.checkpoint_batch_size = 1;
    let mut second_config = make_monetary_config();
    second_config.keypair = kernel_kp;
    second_config.checkpoint_batch_size = 1;

    let agent_kp = Keypair::generate();
    let grant = make_grant("srv", "echo");
    let mut first_kernel = make_kernel(first_config);
    let mut second_kernel = make_kernel(second_config);
    first_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    second_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    first_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    second_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();

    let cap = first_kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let agent_id = agent_kp.public_key().to_hex();

    first_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-two-kernels-1".to_string(),
            capability: cap.clone(),
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({ "i": 1 }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    first_kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();
    second_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-two-kernels-2".to_string(),
            capability: cap,
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id,
            arguments: serde_json::json!({ "i": 2 }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    second_kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    let store = SqliteReceiptStore::open(&path).unwrap();
    let first_checkpoint = store
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("first kernel checkpoint should exist");
    let second_checkpoint = store
        .load_checkpoint_by_seq(2)
        .unwrap()
        .expect("second kernel checkpoint should extend the chain");
    assert_eq!(first_checkpoint.body.batch_start_seq, 1);
    assert_eq!(first_checkpoint.body.batch_end_seq, 1);
    assert_eq!(second_checkpoint.body.batch_start_seq, 2);
    assert_eq!(second_checkpoint.body.batch_end_seq, 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn receipt_store_install_fails_closed_on_checkpoint_hydration_error() {
    let mut kernel = make_kernel(make_monetary_config());
    let result =
        kernel.try_set_receipt_store_handle(std::sync::Arc::new(
            FailingCheckpointHydrationReceiptStore,
        ));

    assert!(result.is_err());
    assert!(kernel.receipt_store.is_none());
    assert_eq!(
        kernel
            .checkpoint_seq_counter
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        kernel
            .last_checkpoint_seq
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn inclusion_proof_verifies_against_stored_checkpoint() {
    let path = unique_receipt_db_path("chio-checkpoint-proof");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 5;

    let mut kernel = make_kernel(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    for i in 0..5 {
        kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    // Load checkpoint and receipts, build and verify an inclusion proof.
    let store2 = SqliteReceiptStore::open(&path).unwrap();
    let checkpoint = store2
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("checkpoint should exist");

    let bytes_range = store2.receipts_canonical_bytes_range(1, 5).unwrap();
    assert_eq!(bytes_range.len(), 5, "should have 5 receipts in range");

    let all_bytes: Vec<Vec<u8>> = bytes_range.iter().map(|(_, b)| b.clone()).collect();
    let tree = chio_core::merkle::MerkleTree::from_leaves(&all_bytes).expect("tree build failed");

    // Build proof for receipt at leaf index 2 (seq 3).
    let proof = build_inclusion_proof(&tree, 2, 1, 3).expect("proof build failed");
    assert!(
        proof.verify(&all_bytes[2], &checkpoint.body.merkle_root),
        "inclusion proof for receipt #3 should verify against checkpoint"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn background_checkpoints_are_installed_at_store_attach_and_fire_off_the_request_path() {
    let path = unique_receipt_db_path("chio-bg-install");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 2;

    let mut kernel = make_kernel(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    for i in 0..2 {
        kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-bg-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }
    // Flush barrier: background checkpoints are built on the writer thread
    // after the batch commits; a flush drains the actor past that point.
    kernel
        .with_receipt_store(|store| Ok(store.flush_receipt_writes()?))
        .unwrap();

    let store2 = SqliteReceiptStore::open(&path).unwrap();
    let checkpoint = store2
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("background checkpoint must exist after threshold crossing");
    assert_eq!(checkpoint.body.batch_start_seq, 1);
    assert_eq!(checkpoint.body.batch_end_seq, 2);

    let _ = std::fs::remove_file(&path);
}

/// Fail-closed attach: a receipt store that reports
/// `supports_kernel_signed_checkpoints() = true` but relies on the DEFAULT
/// `enable_background_checkpoints` hook (which returns `Ok(false)`, i.e. never
/// installs a background signer) would append forever without producing
/// kernel-signed Web3 checkpoints now that the synchronous checkpoint trigger
/// is gone. Attaching such a store must fail closed.
struct CheckpointCapableWithoutBackgroundStore;

impl ReceiptStore for CheckpointCapableWithoutBackgroundStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }
    // `enable_background_checkpoints` intentionally uses the trait default,
    // which returns `Ok(false)` (no background signer installed).
}

#[test]
fn checkpoint_capable_store_without_background_fails_setup() {
    let mut kernel = make_kernel(make_config());
    let error = kernel
        .set_receipt_store(Box::new(CheckpointCapableWithoutBackgroundStore))
        .expect_err("checkpoint-capable store without a background signer must fail setup");
    match error {
        KernelError::Internal(message) => assert!(
            message.contains("did not install a background checkpoint signer"),
            "unexpected fail-closed error: {message}"
        ),
        other => panic!("expected KernelError::Internal, got {other:?}"),
    }
}

/// Positive-install analogue of `CheckpointCapableWithoutBackgroundStore`: a
/// store that both reports `supports_kernel_signed_checkpoints() = true` AND
/// genuinely installs a background signer (returns `Ok(true)` from
/// `enable_background_checkpoints`). Attaching such a store must succeed.
struct CheckpointCapableWithBackgroundStore;

impl ReceiptStore for CheckpointCapableWithBackgroundStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn enable_background_checkpoints(
        &self,
        _keypair: Keypair,
        _max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        // Genuinely installs a signer.
        Ok(true)
    }
}

/// With the synchronous request-path checkpoint
/// trigger removed, a background signer installed at store attach is the ONLY
/// producer of kernel-signed checkpoints. So when checkpointing is enabled
/// (`checkpoint_batch_size > 0`) and the store claims checkpoint support, the
/// attach path MUST require that `enable_background_checkpoints` actually
/// installed a signer; a `false`/no-op return is a misconfiguration and must
/// fail closed rather than attach a silently-checkpointless store. This test
/// locks all three branches of that invariant in one place.
#[test]
fn attach_requires_checkpoint_install_when_supported() {
    // Branch 1: claims support but relies on the default no-op
    // `enable_background_checkpoints` (returns `Ok(false)`) -> fail closed.
    let mut config = make_config();
    config.checkpoint_batch_size = 2;
    let mut kernel = make_kernel(config);
    let error = kernel
        .set_receipt_store(Box::new(CheckpointCapableWithoutBackgroundStore))
        .expect_err("store claiming checkpoint support without an installed signer must fail closed");
    match error {
        KernelError::Internal(message) => assert!(
            message.contains("did not install a background checkpoint signer"),
            "unexpected fail-closed error: {message}"
        ),
        other => panic!("expected KernelError::Internal, got {other:?}"),
    }

    // Branch 2: claims support AND genuinely installs the signer
    // (`enable_background_checkpoints` returns `Ok(true)`) -> attaches.
    let mut config = make_config();
    config.checkpoint_batch_size = 2;
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(CheckpointCapableWithBackgroundStore))
        .expect("store that genuinely installs a background signer must attach");

    // Branch 3: checkpointing disabled (`checkpoint_batch_size == 0`) -> the
    // requirement is skipped even for a checkpoint-capable store that installs
    // no signer.
    let mut config = make_config();
    config.checkpoint_batch_size = 0;
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(CheckpointCapableWithoutBackgroundStore))
        .expect("batch_size 0 disables checkpointing; attach must not require a signer");
}

/// KernelConfig documents `checkpoint_batch_size = 0` as DISABLING automatic
/// checkpointing (non-web3 deployments). The attach-time fail-closed check must
/// not reject such a configuration: with batch_size 0 the store attaches
/// without requiring a background signer, while batch_size > 0 still enforces
/// the check.
#[test]
fn attach_honors_disabled_checkpointing() {
    // Disabled (batch_size 0): attach must succeed even though the store is
    // checkpoint-capable but installs no background signer.
    let mut config = make_config();
    config.checkpoint_batch_size = 0;
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(CheckpointCapableWithoutBackgroundStore))
        .expect("batch_size 0 disables checkpointing; attach must not require a signer");

    // Enabled (batch_size > 0): the fail-closed check still applies.
    let mut config = make_config();
    config.checkpoint_batch_size = 2;
    let mut kernel = make_kernel(config);
    let error = kernel
        .set_receipt_store(Box::new(CheckpointCapableWithoutBackgroundStore))
        .expect_err("batch_size > 0 must still require a background checkpoint signer");
    match error {
        KernelError::Internal(message) => assert!(
            message.contains("did not install a background checkpoint signer"),
            "unexpected fail-closed error: {message}"
        ),
        other => panic!("expected KernelError::Internal, got {other:?}"),
    }
}
