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
