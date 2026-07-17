use super::super::*;
use super::support::*;

#[test]
fn append_chio_receipt_rejects_invalid_signature() {
    let path = unique_db_path("chio-receipts-invalid-signature");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut receipt = sample_receipt_with_id("rcpt-invalid-signature");
    receipt.tool_name = "sh".to_string();

    let error = store.append_chio_receipt(&receipt).test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("invalid signature")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_operation_reports_keep_stable_null_json_fields() {
    let report = chio_kernel::ReceiptFlushReport::default();
    let value = serde_json::to_value(&report).test_unwrap();

    assert!(value.get("latestCheckpointSeq").test_unwrap().is_null());
    assert!(value.get("uncheckpointedStartSeq").test_unwrap().is_null());
    assert!(value.get("uncheckpointedEndSeq").test_unwrap().is_null());
    assert!(value.get("walCheckpoint").test_unwrap().is_null());
    assert!(value.get("dbSizeBytes").test_unwrap().is_null());
    assert!(value["writer"]
        .get("lastCommitUnixMs")
        .test_unwrap()
        .is_null());
    assert!(value["writer"].get("lastError").test_unwrap().is_null());
}

#[test]
fn append_chio_receipt_canonical_rejects_unsigned_extra_fields() {
    let path = unique_db_path("chio-receipts-canonical-extra-fields");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-canonical-extra-fields");
    let mut value = serde_json::to_value(&receipt).test_unwrap();
    value
        .as_object_mut()
        .test_unwrap()
        .insert("unsigned_extra".to_string(), serde_json::json!("ignored"));
    let canonical = Arc::new(CanonicalBytes::from_value(&value).test_unwrap());

    let error = store
        .append_chio_receipt_canonical_returning_seq(canonical)
        .test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Canonical(message)
            if message.contains("do not match ChioReceipt serialization")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_rejects_mismatched_parameter_hash() {
    let path = unique_db_path("chio-receipts-invalid-parameter-hash");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let keypair = Keypair::generate();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-invalid-parameter-hash".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({ "cmd": "echo changed" }),
                parameter_hash: "bad-parameter-hash".to_string(),
            },
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap();

    let error = store.append_chio_receipt(&receipt).test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("mismatched action parameter hash")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn append_child_receipt_rejects_invalid_signature() {
    let path = unique_db_path("chio-child-receipts-invalid-signature");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut receipt = sample_child_receipt_with_id_and_timestamp("child-invalid-signature", 2);
    receipt.outcome_hash = "outcome-mutated".to_string();

    let error = store.append_child_receipt(&receipt).test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("child-invalid-signature")
                && message.contains("has invalid signature")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn evidence_export_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-evidence-export-tamper");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("tampered-export-receipt");
    store.append_chio_receipt(&receipt).test_unwrap();
    tamper_persisted_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store
        .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
        .test_unwrap_err();
    let message = error.to_string();
    assert!(message.contains("persisted tool receipt seq"));
    assert!(message.contains(&receipt.id));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn behavioral_feed_report_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-behavioral-feed-tamper");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("tampered-report-receipt");
    store.append_chio_receipt(&receipt).test_unwrap();
    tamper_persisted_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let query = BehavioralFeedQuery {
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        ..BehavioralFeedQuery::default()
    };
    let error = store
        .query_behavioral_feed_receipts(&query)
        .test_unwrap_err();
    let message = error.to_string();
    assert!(message.contains("persisted tool receipt seq"));
    assert!(message.contains(&receipt.id));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn claim_log_replay_rejects_tampered_persisted_tool_receipt() {
    let path = unique_db_path("chio-claim-log-tamper");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("tampered-claim-log-receipt");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    tamper_claim_log_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store
        .receipts_canonical_bytes_range(seq, seq)
        .test_unwrap_err();
    let message = error.to_string();
    assert!(message.contains("claim-log tool receipt seq"));
    assert!(message.contains(&receipt.id));
    assert!(message.contains("invalid signature"));

    let _ = fs::remove_file(path);
}

#[test]
fn append_child_receipt_fails_closed_on_existing_claim_log_projection_drift() {
    let path = unique_db_path("chio-claim-log-child-append-drift");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("tampered-claim-log-before-child-append");
    store.append_chio_receipt(&receipt).test_unwrap();
    tamper_claim_log_tool_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    // The default incremental append fast path uses an O(1) checkpoint-
    // predecessor check plus an O(b) delta cross-check instead of an O(N)
    // claim-log content re-derive-and-compare on every append; neither rescans
    // an existing row's content. An append that does not touch the tampered row
    // therefore succeeds; the store still fails closed on the drift, just
    // observed through the audit surfaces (`receipt_store_health` /
    // `receipt_checkpoint_status`), which keep the full per-row verification on
    // purpose.
    store
        .append_child_receipt(&sample_child_receipt_with_id_and_timestamp(
            "child-after-claim-log-drift",
            2,
        ))
        .test_unwrap();

    let error = store.receipt_store_health().test_unwrap_err();
    assert!(
        error.to_string().contains("claim receipt log entry")
            && error.to_string().contains("diverges"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_base_tables_reject_update_and_delete() {
    let path = unique_db_path("chio-receipts-base-immutable");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let tool = sample_receipt_with_id("base-immutable-tool");
    let child = sample_child_receipt_with_id_and_timestamp("base-immutable-child", 2);
    store.append_chio_receipt(&tool).test_unwrap();
    store.append_child_receipt(&child).test_unwrap();

    let connection = store.connection().test_unwrap();
    let error = connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = raw_json WHERE receipt_id = ?1",
            rusqlite::params![tool.id],
        )
        .test_unwrap_err();
    assert!(
        error.to_string().contains("tool receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "DELETE FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![tool.id],
        )
        .test_unwrap_err();
    assert!(
        error.to_string().contains("tool receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "UPDATE chio_child_receipts SET raw_json = raw_json WHERE receipt_id = ?1",
            rusqlite::params![child.id],
        )
        .test_unwrap_err();
    assert!(
        error.to_string().contains("child receipts are immutable"),
        "unexpected error: {error}"
    );

    let error = connection
        .execute(
            "DELETE FROM chio_child_receipts WHERE receipt_id = ?1",
            rusqlite::params![child.id],
        )
        .test_unwrap_err();
    assert!(
        error.to_string().contains("child receipts are immutable"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn claim_log_projection_uses_capability_lineage_when_receipt_lacks_attribution() {
    let path = unique_db_path("chio-claim-log-lineage-projection");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-claim-log-lineage".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
        },
        &issuer_kp,
    )
    .test_unwrap();
    store
        .record_capability_snapshot(&capability, None)
        .test_unwrap();

    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-claim-log-lineage".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo projection" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-claim-log-lineage".to_string(),
            policy_hash: "policy-claim-log-lineage".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 10,
                    currency: "USD".to_string(),
                    budget_remaining: 990,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status: SettlementStatus::Settled,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &receipt_kp,
    )
    .test_unwrap();

    store.append_chio_receipt(&receipt).test_unwrap();
    drop(store);

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    let (projected_subject_key, projected_issuer_key) =
        load_claim_log_identity(&reopened, &receipt.id);
    assert_eq!(projected_subject_key.as_deref(), Some(subject_hex.as_str()));
    assert_eq!(projected_issuer_key.as_deref(), Some(issuer_hex.as_str()));

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_merkle_root_mismatch_with_claim_log() {
    let path = unique_db_path("chio-receipts-cp-merkle-mismatch");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-merkle-mismatch");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(1, seq, seq, &[b"wrong-bytes".to_vec()], &kp).test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("merkle_root does not match claim receipt log range"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn append_receipt_fails_closed_when_earlier_checkpoint_row_is_corrupted() {
    let path = unique_db_path("chio-receipts-cp-fail-closed");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let kp = receipt_test_keypair();

    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
    )
    .test_unwrap();
    let third = build_checkpoint_with_previous(
        3,
        5,
        6,
        &[b"five".to_vec(), b"six".to_vec()],
        &kp,
        Some(&second),
    )
    .test_unwrap();

    let mut corrupted_first_body = first.body.clone();
    corrupted_first_body.batch_end_seq += 1;
    let corrupted_first_json = serde_json::to_string(&corrupted_first_body).test_unwrap();
    insert_checkpoint_row_with_statement_json(
        &store,
        &first,
        first.body.batch_end_seq,
        &corrupted_first_json,
    );
    insert_checkpoint_row(&store, &second, second.body.batch_end_seq);
    insert_checkpoint_row(&store, &third, third.body.batch_end_seq);

    let error = ReceiptStore::append_chio_receipt_returning_seq(
        &store,
        &sample_receipt_with_id("rcpt-fail-closed"),
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("does not match signed body"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_rejects_conflicting_rewritten_checkpoint_rows() {
    let path = unique_db_path("chio-receipts-cp-rewrite-detect");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-rewrite-{i}"));
        seqs.push(
            store
                .append_chio_receipt_returning_seq(&receipt)
                .test_unwrap(),
        );
    }

    let checkpoint_kp = receipt_test_keypair();
    let first = build_checkpoint(
        1,
        seqs[0],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[0], seqs[1]),
        &checkpoint_kp,
    )
    .test_unwrap();
    insert_checkpoint_row(&store, &first, seqs[1] + 1);

    let second = build_checkpoint(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &checkpoint_kp,
    )
    .test_unwrap();
    let error = ReceiptStore::store_checkpoint(&store, &second).test_unwrap_err();
    assert!(
        error.to_string().contains("does not match signed body"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_wrong_predecessor_digest() {
    let path = unique_db_path("chio-receipts-cp-continuity");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let kp = receipt_test_keypair();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-predecessor-digest-{i}"));
        seqs.push(
            store
                .append_chio_receipt_returning_seq(&receipt)
                .test_unwrap(),
        );
    }

    let first = build_checkpoint(
        1,
        seqs[0],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[0], seqs[1]),
        &kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &first).test_unwrap();

    let mut second = build_checkpoint_with_previous(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &kp,
        Some(&first),
    )
    .test_unwrap();
    second.body.previous_checkpoint_sha256 = Some("not-the-real-digest".to_string());
    second.signature = kp.sign(&chio_core::canonical_json_bytes(&second.body).test_unwrap());
    let error = ReceiptStore::store_checkpoint(&store, &second).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match predecessor digest"));

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_conflicting_rewrite() {
    let path = unique_db_path("chio-receipts-cp-rewrite");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let kp = receipt_test_keypair();

    let first = sample_receipt_with_id("rcpt-rewrite-first");
    let second = sample_receipt_with_id("rcpt-rewrite-second");
    let first_seq = store
        .append_chio_receipt_returning_seq(&first)
        .test_unwrap();
    let second_seq = store
        .append_chio_receipt_returning_seq(&second)
        .test_unwrap();
    let checkpoint = build_checkpoint(
        1,
        first_seq,
        second_seq,
        &canonical_receipt_bytes(&store, first_seq, second_seq),
        &kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let conflicting = build_checkpoint(
        1,
        first_seq,
        second_seq,
        &[b"one".to_vec(), b"changed".to_vec()],
        &kp,
    )
    .test_unwrap();
    let error = ReceiptStore::store_checkpoint(&store, &conflicting).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("already exists with different content"));

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_missing_projection_atomically() {
    let path = unique_db_path("chio-receipts-cp-projection-missing");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-projection-missing");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();

    store
        .connection()
        .test_unwrap()
        .execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;")
        .test_unwrap();
    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();

    assert!(
        error.to_string().contains("projection") && error.to_string().contains("missing"),
        "unexpected error: {error}"
    );
    let count: i64 = store
        .connection()
        .test_unwrap()
        .query_row(
            "SELECT COUNT(*) FROM kernel_checkpoints WHERE checkpoint_seq = 1",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(count, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_idempotent_rechecks_projection_rows() {
    let path = unique_db_path("chio-receipts-cp-idempotent-projection-drift");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-idempotent-projection-drift");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_delete;
            DELETE FROM checkpoint_tree_heads WHERE checkpoint_seq = 1;
            "#,
        )
        .test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();
    assert!(
        error.to_string().contains("projection") && error.to_string().contains("missing"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_checkpoint_status_reports_projection_drift() {
    let path = unique_db_path("chio-receipts-cp-status-projection-drift");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-status-projection-drift");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_delete;
            DELETE FROM checkpoint_publication_metadata WHERE checkpoint_seq = 1;
            "#,
        )
        .test_unwrap();

    let report = store.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(!report.healthy);
    assert!(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or_default()
            .contains("projection"),
        "unexpected report: {report:?}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_existing_checkpoint_status_does_not_repair_missing_projection() {
    let path = unique_db_path("chio-receipts-cp-open-existing-projection-drift");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-open-existing-projection-drift");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_delete;
            DELETE FROM checkpoint_publication_metadata WHERE checkpoint_seq = 1;
            "#,
        )
        .test_unwrap();
    drop(connection);
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path).test_unwrap();
    let report = reopened.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(!report.healthy);
    assert!(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or_default()
            .contains("projection"),
        "unexpected report: {report:?}"
    );
    let missing_count: i64 = reopened
        .connection()
        .test_unwrap()
        .query_row(
            "SELECT COUNT(*) FROM checkpoint_publication_metadata WHERE checkpoint_seq = 1",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(
        missing_count, 0,
        "open_existing/status must not repair checkpoint projection rows"
    );

    let _ = fs::remove_file(path);
}

/// The read-only health sampler the SIEM serve-mode watchdog uses must NOT
/// propagate a checkpoint-chain-integrity Err. On the fixed interval the
/// watchdog logs-and-skips a sample error with no gauge update, so a corrupt
/// store would look silent instead of alarming. Under chain corruption the
/// read-only path must instead return a report carrying the checkpoint_error and
/// a large-backlog range (checkpointed defaults to 0, spanning the whole
/// committed log) so the watchdog still emits a gauge, matching the fail-open
/// shape of `receipt_checkpoint_status`.
#[test]
fn health_read_only_reports_checkpoint_error_under_chain_corruption() {
    let path = unique_db_path("chio-receipts-health-ro-chain-corruption");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-health-ro-chain-corruption");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    // Corrupt the checkpoint chain: drop the immutability trigger and delete a
    // projection row so verify_checkpoint_chain_integrity fails on reopen.
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_delete;
            DELETE FROM checkpoint_publication_metadata WHERE checkpoint_seq = 1;
            "#,
        )
        .test_unwrap();
    drop(connection);
    drop(store);

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path).test_unwrap();
    assert!(
        !report.healthy,
        "a corrupt chain is not healthy: {report:?}"
    );
    assert!(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or_default()
            .contains("projection"),
        "the read-only sampler must attach the chain-integrity error: {report:?}"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.latest_checkpoint_seq, None);
    // The uncheckpointed range must span the whole committed log so the watchdog
    // emits a large-backlog gauge rather than skipping the sample.
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(seq));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_checkpoint_status_reports_extra_projection_drift() {
    let path = unique_db_path("chio-receipts-cp-status-extra-projection");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-status-extra-projection");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let connection = store.connection().test_unwrap();
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            INSERT INTO checkpoint_tree_heads (
                checkpoint_seq,
                batch_start_seq,
                batch_end_seq,
                tree_size,
                merkle_root,
                issued_at,
                kernel_key,
                previous_checkpoint_sha256,
                statement_json,
                signature
            )
            SELECT
                999,
                batch_start_seq,
                batch_end_seq,
                tree_size,
                merkle_root,
                issued_at,
                kernel_key,
                previous_checkpoint_sha256,
                statement_json,
                signature
            FROM checkpoint_tree_heads
            WHERE checkpoint_seq = 1;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .test_unwrap();

    let report = store.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(!report.healthy);
    assert!(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or_default()
            .contains("projection drift"),
        "unexpected report: {report:?}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_mixed_receipt_signer_range() {
    let path = unique_db_path("chio-receipts-cp-mixed-signer-range");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let first_keypair = receipt_test_keypair();
    let second_keypair = Keypair::from_seed(&[0x43; 32]);
    let first_receipt = sample_receipt_with_keypair("rcpt-mixed-signer-1", 1, &first_keypair);
    let second_receipt = sample_receipt_with_keypair("rcpt-mixed-signer-2", 2, &second_keypair);
    let first_seq = store
        .append_chio_receipt_returning_seq(&first_receipt)
        .test_unwrap();
    let second_seq = store
        .append_chio_receipt_returning_seq(&second_receipt)
        .test_unwrap();
    let checkpoint = build_checkpoint(
        1,
        first_seq,
        second_seq,
        &canonical_receipt_bytes(&store, first_seq, second_seq),
        &receipt_test_keypair(),
    )
    .test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();
    assert!(
        error.to_string().contains("mixed receipt signer"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_checkpoint_key_that_does_not_match_receipt_signer() {
    let path = unique_db_path("chio-receipts-cp-wrong-kernel-key");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-wrong-checkpoint-key");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &Keypair::from_seed(&[0x44; 32]),
    )
    .test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match receipt signer key"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn health_detects_invalid_uncheckpointed_receipt_bytes() {
    // `receipt_store_health()` scans the uncheckpointed range via
    // `load_claim_tree_canonical_bytes_range`, which decodes and
    // signature-verifies each receipt. Corrupting the canonical bytes
    // of a receipt that has not yet been checkpointed must surface as
    // an error out of `receipt_store_health()`. We bypass the
    // checkpointer entirely by never calling
    // `create_next_receipt_checkpoint`, leaving the appended receipts
    // in the uncheckpointed range.
    let path = unique_db_path("chio-receipts-health-uncheckpointed");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let receipt = sample_receipt_with_id_and_timestamp("rcpt-health-tamper", 1);
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    store.flush_receipt_writes().test_unwrap();

    // Sanity: with the receipt appended but no checkpoint produced, the
    // health probe must classify the receipt as uncheckpointed.
    let healthy = store.receipt_store_health().test_unwrap();
    assert!(
        healthy.healthy,
        "store must be healthy before tampering: {healthy:?}"
    );
    assert_eq!(healthy.latest_committed_entry_seq, seq);
    assert_eq!(healthy.latest_checkpointed_entry_seq, 0);
    assert_eq!(healthy.uncheckpointed_start_seq, Some(seq));
    assert_eq!(healthy.uncheckpointed_end_seq, Some(seq));

    tamper_canonical_bytes_of_uncheckpointed_receipt(&store, &receipt.id, |receipt| {
        receipt.tool_name = "sh".to_string();
    });

    let error = store.receipt_store_health().test_unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("invalid signature") || message.contains("verification failed"),
        "unexpected health error: {message}"
    );

    let _ = fs::remove_file(path);
}
