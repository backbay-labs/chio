use super::super::*;
use super::support::*;

#[test]
fn receipts_canonical_bytes_range_returns_correct_count() {
    let path = unique_db_path("chio-receipts-canon-range");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    for i in 0..10usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
        store
            .append_chio_receipt_returning_seq(&receipt)
            .test_unwrap();
    }

    // Fetch seqs 3..=7 (5 receipts).
    let range = store.receipts_canonical_bytes_range(3, 7).test_unwrap();
    assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
    assert_eq!(range[0].0, 3);
    assert_eq!(range[4].0, 7);

    // Verify all bytes are non-empty canonical JSON.
    for (_, bytes) in &range {
        assert!(!bytes.is_empty());
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_slice(bytes).test_unwrap();
    }

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_log_includes_child_receipts_in_unified_surface() {
    let path = unique_db_path("chio-receipts-claim-log");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let tool_before = sample_receipt_with_id_and_timestamp("claim-tool-1", 10);
    let tool_after = sample_receipt_with_id_and_timestamp("claim-tool-2", 12);
    store.append_chio_receipt(&tool_before).test_unwrap();
    store
        .append_child_receipt(&sample_child_receipt_with_id_and_timestamp(
            "claim-child-1",
            11,
        ))
        .test_unwrap();
    store.append_chio_receipt(&tool_after).test_unwrap();

    let rows = load_claim_log_rows(&store);
    assert_eq!(
        rows,
        vec![
            (1, tool_before.id.clone(), "tool_receipt".to_string(), 1, 10),
            (
                2,
                "claim-child-1".to_string(),
                "child_receipt".to_string(),
                1,
                11
            ),
            (3, tool_after.id.clone(), "tool_receipt".to_string(), 2, 12),
        ]
    );

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(load_claim_log_rows(&reopened), rows);

    let _ = fs::remove_file(path);
}

#[test]
fn append_receipt_sequences_follow_unified_claim_log() {
    let path = unique_db_path("chio-receipts-claim-log-seq");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let first_tool = sample_receipt_with_id_and_timestamp("claim-seq-tool-1", 10);
    let second_tool = sample_receipt_with_id_and_timestamp("claim-seq-tool-2", 12);
    let first_tool_seq = store
        .append_chio_receipt_returning_seq(&first_tool)
        .test_unwrap();
    let child_seq = ReceiptStore::append_child_receipt_returning_seq(
        &store,
        &sample_child_receipt_with_id_and_timestamp("claim-seq-child-1", 11),
    )
    .test_unwrap()
    .test_expect("sqlite store should return child claim-log seq");
    let second_tool_seq = store
        .append_chio_receipt_returning_seq(&second_tool)
        .test_unwrap();

    assert_eq!(first_tool_seq, 1);
    assert_eq!(child_seq, 2);
    assert_eq!(second_tool_seq, 3);

    let rows = load_claim_log_rows(&store);
    assert_eq!(
        rows.into_iter()
            .map(|(entry_seq, receipt_id, _, _, _)| (entry_seq, receipt_id))
            .collect::<Vec<_>>(),
        vec![
            (1, first_tool.id),
            (2, "claim-seq-child-1".to_string()),
            (3, second_tool.id),
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_log_includes_child_receipts_in_tree() {
    let path = unique_db_path("chio-receipts-claim-tree");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let checkpoint_kp = receipt_test_keypair();
    let tool_before = sample_receipt_with_keypair("claim-tree-tool-1", 10, &checkpoint_kp);
    let child =
        sample_child_receipt_with_keypair_and_timestamp("claim-tree-child-1", 11, &checkpoint_kp);
    let tool_after = sample_receipt_with_keypair("claim-tree-tool-2", 12, &checkpoint_kp);

    store.append_chio_receipt(&tool_before).test_unwrap();
    store.append_child_receipt(&child).test_unwrap();
    store.append_chio_receipt(&tool_after).test_unwrap();

    let claim_rows = load_claim_log_rows(&store);
    assert_eq!(
        claim_rows,
        vec![
            (1, tool_before.id.clone(), "tool_receipt".to_string(), 1, 10),
            (
                2,
                "claim-tree-child-1".to_string(),
                "child_receipt".to_string(),
                1,
                11
            ),
            (3, tool_after.id.clone(), "tool_receipt".to_string(), 2, 12),
        ]
    );

    let start_seq = claim_rows.first().test_expect("claim log row").0;
    let end_seq = claim_rows.last().test_expect("claim log row").0;
    let canonical_range = store
        .receipts_canonical_bytes_range(start_seq, end_seq)
        .test_unwrap();
    assert_eq!(
        canonical_range
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(canonical_range.len(), 3);
    let child_canonical = canonical_json_bytes(&child).test_unwrap();
    assert_eq!(canonical_range[1].1, child_canonical);
    let canonical = canonical_range
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();

    let checkpoint =
        build_checkpoint(1, start_seq, end_seq, &canonical, &checkpoint_kp).test_unwrap();
    assert_eq!(checkpoint.body.tree_size as u64, 3);
    store.store_checkpoint(&checkpoint).test_unwrap();
    let stored_checkpoint = store
        .load_checkpoint_by_seq(1)
        .test_unwrap()
        .test_expect("stored checkpoint");
    assert_eq!(stored_checkpoint.body.batch_start_seq, 1);
    assert_eq!(stored_checkpoint.body.batch_end_seq, 3);
    assert_eq!(stored_checkpoint.body.tree_size, 3);

    let tree = MerkleTree::from_leaves(&canonical).test_unwrap();
    let proof = build_inclusion_proof(&tree, 1, start_seq, 2).test_unwrap();
    assert_eq!(proof.receipt_seq, 2);
    assert!(proof.verify(&child_canonical, &stored_checkpoint.body.merkle_root));

    let tree_heads = load_checkpoint_tree_head_rows(&store);
    assert_eq!(tree_heads, vec![(1, start_seq, 3, None)]);

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(
        reopened
            .receipts_canonical_bytes_range(start_seq, end_seq)
            .test_unwrap()
            .len(),
        3
    );
    assert_eq!(load_checkpoint_tree_head_rows(&reopened), tree_heads);

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_lineage_verification_backfills_from_governed_call_chain_metadata() {
    let path = unique_db_path("chio-receipts-lineage-links");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let parent_receipt_kp = Keypair::generate();
    let child_receipt_kp = Keypair::generate();
    let statement_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-lineage-links".to_string(),
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
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .test_unwrap();
    store
        .record_capability_snapshot(&capability, None)
        .test_unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-parent-lineage".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo parent" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-parent-lineage".to_string(),
            policy_hash: "policy-lineage".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: parent_receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &parent_receipt_kp,
    )
    .test_unwrap();
    store.append_chio_receipt(&parent_receipt).test_unwrap();

    let child_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-child-lineage".to_string(),
            timestamp: 2_100,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo child" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-child-lineage".to_string(),
            policy_hash: "policy-lineage".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-lineage".to_string(),
                    intent_hash: "intent-hash-lineage".to_string(),
                    purpose: "continue delegated workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: None,
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-lineage".to_string(),
                        approver_key: issuer_hex.clone(),
                        approval_artifact_digest: None,
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: Some(GovernedCallChainProvenance::verified(
                        GovernedCallChainContext {
                            chain_id: "chain-lineage".to_string(),
                            parent_request_id: "req-parent-lineage".to_string(),
                            parent_receipt_id: Some(parent_receipt.id.clone()),
                            origin_subject: "subject-root".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        },
                    )),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: child_receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &child_receipt_kp,
    )
    .test_unwrap();
    store.append_chio_receipt(&child_receipt).test_unwrap();

    store
        .record_session_anchor_record(
            "sess-lineage",
            "anchor-child-lineage",
            "authctx-lineage",
            2_090,
            None,
            &serde_json::json!({
                "schema": "chio.session_anchor.v1",
                "id": "anchor-child-lineage"
            }),
        )
        .test_unwrap();
    store
        .record_request_lineage_record(
            "sess-lineage",
            "req-parent-lineage",
            None,
            Some("anchor-child-lineage"),
            2_091,
            Some("req-parent-lineage-fingerprint"),
            &request_lineage_json("req-parent-lineage", "anchor-child-lineage", None),
        )
        .test_unwrap();
    store
        .record_request_lineage_record(
            "sess-lineage",
            "req-child-lineage",
            Some("req-parent-lineage"),
            Some("anchor-child-lineage"),
            2_092,
            Some("req-child-lineage-fingerprint"),
            &request_lineage_json(
                "req-child-lineage",
                "anchor-child-lineage",
                Some("req-parent-lineage"),
            ),
        )
        .test_unwrap();

    let statement = ReceiptLineageStatement::sign(
        ReceiptLineageStatementBody::new(
            "stmt-lineage-001",
            ReceiptLineageEndpoints::new(
                parent_receipt.id.clone(),
                child_receipt.id.clone(),
                RequestId::new("req-parent-lineage"),
                RequestId::new("req-child-lineage"),
                SessionAnchorReference::new("anchor-parent-lineage", "anchor-parent-lineage-hash"),
                SessionAnchorReference::new("anchor-child-lineage", "anchor-child-lineage-hash"),
            ),
            ReceiptLineageRelationKind::Continued,
            2_101,
            statement_kp.public_key(),
        ),
        &statement_kp,
    )
    .test_unwrap();
    let statement_json = serde_json::to_value(&statement).test_unwrap();
    store
        .record_receipt_lineage_statement_record(
            &child_receipt.id,
            None,
            Some("sess-lineage"),
            None,
            None,
            None,
            Some("chain-lineage"),
            2_101,
            &statement_json,
        )
        .test_unwrap();

    let parent_links = store
        .list_receipt_lineage_statement_links(&parent_receipt.id)
        .test_unwrap();
    assert_eq!(parent_links.len(), 1);
    assert_eq!(
        parent_links[0].statement_id.as_deref(),
        Some("stmt-lineage-001")
    );
    assert_eq!(parent_links[0].child_receipt_id, child_receipt.id);
    assert_eq!(
        parent_links[0].parent_receipt_id.as_deref(),
        Some(parent_receipt.id.as_str())
    );
    assert_eq!(
        parent_links[0].child_request_id.as_deref(),
        Some("req-child-lineage")
    );
    assert_eq!(
        parent_links[0].parent_request_id.as_deref(),
        Some("req-parent-lineage")
    );
    assert_eq!(
        parent_links[0].session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(parent_links[0].chain_id.as_deref(), Some("chain-lineage"));

    let child_links = store
        .list_receipt_lineage_statement_links(&child_receipt.id)
        .test_unwrap();
    assert_eq!(child_links, parent_links);
    let loaded_statement = store
        .receipt_lineage_statement(&child_receipt.id)
        .test_unwrap()
        .test_expect("signed receipt lineage statement");
    assert_eq!(loaded_statement, statement);
    assert!(loaded_statement.verify_signature().test_unwrap());

    let verification = store
        .receipt_lineage_verification(&child_receipt.id)
        .test_unwrap()
        .test_expect("child receipt lineage verification");
    assert!(verification.session_anchor_verified);
    assert!(verification.parent_request_verified);
    assert!(verification.parent_receipt_verified);
    assert!(verification.replay_protected);

    let report = store
        .query_authorization_context_report(&OperatorReportQuery {
            capability_id: Some(capability.id),
            authorization_limit: Some(10),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..OperatorReportQuery::default()
        })
        .test_unwrap();
    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.session_anchor_receipts, 1);
    assert_eq!(report.summary.receipt_lineage_statement_receipts, 1);
    assert_eq!(report.receipts.len(), 1);
    let call_chain = report.receipts[0]
        .transaction_context
        .call_chain
        .as_ref()
        .test_expect("call-chain projection");
    assert_eq!(
        call_chain.session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(
        call_chain.receipt_lineage_statement_id.as_deref(),
        Some("stmt-lineage-001")
    );
    let diagnostics = report.receipts[0]
        .governed_transaction_diagnostics
        .as_ref()
        .test_expect("governed transaction diagnostics");
    assert_eq!(
        diagnostics.lineage_references.session_anchor_id.as_deref(),
        Some("anchor-child-lineage")
    );
    assert_eq!(
        diagnostics
            .lineage_references
            .receipt_lineage_statement_id
            .as_deref(),
        Some("stmt-lineage-001")
    );

    let review_pack = store
        .query_authorization_review_pack(&OperatorReportQuery {
            capability_id: Some("cap-lineage-links".to_string()),
            authorization_limit: Some(10),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..OperatorReportQuery::default()
        })
        .test_unwrap();
    assert_eq!(review_pack.summary.receipt_lineage_statement_receipts, 1);
    assert_eq!(
        review_pack.records[0]
            .governed_transaction
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.receipt_lineage_statement_id.as_deref()),
        Some("stmt-lineage-001")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_lineage_statement_links_parent_and_child_receipts() {
    let path = unique_db_path("chio-receipts-lineage-link");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt_kp = Keypair::generate();

    let parent = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-lineage-parent".to_string(),
            timestamp: 1_000,
            capability_id: "cap-lineage".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo parent" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-lineage-parent".to_string(),
            policy_hash: "policy-lineage-parent".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &receipt_kp,
    )
    .test_unwrap();
    store.append_chio_receipt(&parent).test_unwrap();

    let child = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-lineage-child".to_string(),
            timestamp: 1_001,
            capability_id: "cap-lineage".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo child" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-lineage-child".to_string(),
            policy_hash: "policy-lineage-child".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-lineage-child".to_string(),
                    intent_hash: "intent-hash-lineage-child".to_string(),
                    purpose: "continue delegated workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    approval: None,
                    runtime_assurance: None,
                    call_chain: Some(
                        GovernedCallChainProvenance::verified(GovernedCallChainContext {
                            chain_id: "chain-lineage".to_string(),
                            parent_request_id: "req-lineage-parent".to_string(),
                            parent_receipt_id: Some(parent.id.clone()),
                            origin_subject: "subject-origin".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        })
                    ),
                    autonomy: None,
                    economic_authorization: None,
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
    store.append_chio_receipt(&child).test_unwrap();

    let verification = store
        .receipt_lineage_verification(&child.id)
        .test_unwrap()
        .test_expect("lineage verification should exist");
    assert_eq!(verification.receipt_id, child.id);
    assert!(verification.parent_receipt_verified);
    assert!(verification.delegated_call_chain_bound());

    let _ = fs::remove_file(path);
}
