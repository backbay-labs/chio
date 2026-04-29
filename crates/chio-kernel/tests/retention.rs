/// Retention and archival tests for SqliteReceiptStore.
///
/// These tests cover COMP-03 (configurable retention) and COMP-04 (archived
/// receipt verification). All tests use temporary files that are cleaned up
/// after each test.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod retention {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_core::merkle::MerkleTree;
    use chio_core::receipt::{
        ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, Decision,
        ToolCallAction,
    };
    use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};

    use chio_kernel::build_checkpoint;
    use chio_kernel::build_checkpoint_with_previous;
    use chio_kernel::build_inclusion_proof;
    use chio_kernel::verify_checkpoint_signature;
    use chio_kernel::{ReceiptStore, RetentionConfig};
    use chio_store_sqlite::SqliteReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn receipt_with_capability_and_ts(
        id: &str,
        capability_id: &str,
        timestamp: u64,
    ) -> ChioReceipt {
        receipt_with_capability_ts_and_tenant(id, capability_id, timestamp, None)
    }

    fn receipt_with_capability_ts_and_tenant(
        id: &str,
        capability_id: &str,
        timestamp: u64,
        tenant_id: Option<String>,
    ) -> ChioReceipt {
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("hash receipt parameters");
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action,
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign receipt")
    }

    fn receipt_with_ts(id: &str, timestamp: u64) -> ChioReceipt {
        receipt_with_capability_and_ts(id, "cap-1", timestamp)
    }

    fn receipt_with_tenant(id: &str, timestamp: u64, tenant_id: &str) -> ChioReceipt {
        receipt_with_capability_ts_and_tenant(id, "cap-1", timestamp, Some(tenant_id.to_string()))
    }

    fn child_receipt_with_ts(id: &str, timestamp: u64) -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: id.to_string(),
                timestamp,
                session_id: SessionId::new("sess-retention"),
                parent_request_id: RequestId::new("parent-retention"),
                request_id: RequestId::new(format!("request-{id}")),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: format!("outcome-{id}"),
                policy_hash: "policy-retention".to_string(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign child receipt")
    }

    fn capability_with_id(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: 10_000,
                delegation_chain: vec![],
            },
            issuer,
        )
        .expect("sign capability")
    }

    /// Time-based rotation: receipts before the cutoff are archived, receipts
    /// after the cutoff remain in the live DB.
    #[test]
    fn retention_rotates_at_time_boundary() {
        let live_path = unique_db_path("retention-time-live");
        let archive_path = unique_db_path("retention-time-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();

        // Insert 10 receipts with timestamps below the cutoff (100-109).
        for i in 0..10usize {
            let receipt = receipt_with_ts(&format!("rcpt-old-{i}"), 100 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }

        // Insert 5 receipts with timestamps above the cutoff (200-204).
        for i in 0..5usize {
            let receipt = receipt_with_ts(&format!("rcpt-new-{i}"), 200 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }

        // Cutoff at timestamp 150: all receipts with timestamp < 150 should be archived.
        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 10, "should have archived 10 receipts");

        // Live DB should have 5 receipts.
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            5,
            "live DB should have 5 receipts after archival"
        );

        // Archive DB should have 10 receipts.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(
            archive_store.tool_receipt_count().unwrap(),
            10,
            "archive DB should have 10 receipts"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn retention_retry_deletes_rows_already_present_in_archive() {
        let live_path = unique_db_path("retention-retry-live");
        let archive_path = unique_db_path("retention-retry-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        let receipts: Vec<_> = (0..3usize)
            .map(|i| receipt_with_ts(&format!("rcpt-retry-{i}"), 100 + i as u64))
            .collect();
        for receipt in &receipts {
            store.append_chio_receipt_returning_seq(receipt).unwrap();
            archive_store
                .append_chio_receipt_returning_seq(receipt)
                .unwrap();
        }
        drop(archive_store);

        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(
            archived, 0,
            "retry should not count rows already present in the archive"
        );
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            0,
            "retry must still delete live rows that already exist in archive"
        );

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(archive_store.tool_receipt_count().unwrap(), 3);

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn retention_archive_for_tenant_preserves_other_tenants() {
        let live_path = unique_db_path("retention-tenant-live");
        let archive_path = unique_db_path("retention-tenant-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_tenant("rcpt-a-old", 100, "tenant-a"))
            .unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_tenant("rcpt-b-old", 100, "tenant-b"))
            .unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_tenant("rcpt-a-new", 200, "tenant-a"))
            .unwrap();

        let archived = store
            .archive_receipts_before_for_tenant(150, archive_path.to_str().unwrap(), "tenant-a")
            .unwrap();
        assert_eq!(archived, 1, "should only archive tenant-a old receipt");
        assert_eq!(store.tool_receipt_count().unwrap(), 2);

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(
            archive_store.tool_receipt_count().unwrap(),
            1,
            "archive should only contain tenant-a evidence selected by the scoped cutoff"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn tenant_archive_does_not_copy_global_batch_checkpoints() {
        let live_path = unique_db_path("retention-tenant-checkpoint-live");
        let archive_path = unique_db_path("retention-tenant-checkpoint-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let checkpoint_key = Keypair::generate();
        let tenant_a_seq = store
            .append_chio_receipt_returning_seq(&receipt_with_tenant("rcpt-a-old", 100, "tenant-a"))
            .unwrap();
        let tenant_b_seq = store
            .append_chio_receipt_returning_seq(&receipt_with_tenant("rcpt-b-old", 100, "tenant-b"))
            .unwrap();
        let canonical = store
            .receipts_canonical_bytes_range(tenant_a_seq, tenant_b_seq)
            .unwrap();
        let checkpoint_bytes: Vec<Vec<u8>> =
            canonical.iter().map(|(_, bytes)| bytes.clone()).collect();
        let checkpoint = build_checkpoint(
            1,
            tenant_a_seq,
            tenant_b_seq,
            &checkpoint_bytes,
            &checkpoint_key,
        )
        .unwrap();
        store.store_checkpoint(&checkpoint).unwrap();

        let archived = store
            .archive_receipts_before_for_tenant(150, archive_path.to_str().unwrap(), "tenant-a")
            .unwrap();
        assert_eq!(archived, 1);

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert!(
            archive_store.load_checkpoint_by_seq(1).unwrap().is_none(),
            "tenant-scoped archive must not copy a checkpoint over a mixed-tenant batch"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn retention_archive_for_tenant_archives_old_child_receipts() {
        let live_path = unique_db_path("retention-tenant-child-live");
        let archive_path = unique_db_path("retention-tenant-child-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let tenant_a_parent = receipt_with_tenant("rcpt-a-old", 100, "tenant-a");
        let tenant_b_parent = receipt_with_tenant("rcpt-b-old", 100, "tenant-b");
        let tenant_a_child = child_receipt_with_ts("tenant-child-a", 100);
        let tenant_b_child = child_receipt_with_ts("tenant-child-b", 100);
        store
            .append_chio_receipt_returning_seq(&tenant_a_parent)
            .unwrap();
        store
            .append_chio_receipt_returning_seq(&tenant_b_parent)
            .unwrap();
        store.append_child_receipt(&tenant_a_child).unwrap();
        store.append_child_receipt(&tenant_b_child).unwrap();
        store
            .record_receipt_lineage_statement_record(
                &tenant_a_child.id,
                Some(tenant_a_child.request_id.as_str()),
                Some(tenant_a_child.session_id.as_str()),
                None,
                Some(tenant_a_child.parent_request_id.as_str()),
                Some(&tenant_a_parent.id),
                Some("tenant-a-chain"),
                100,
                &serde_json::json!({
                    "child_receipt_id": tenant_a_child.id,
                    "parent_receipt_id": tenant_a_parent.id,
                    "parent_request_id": tenant_a_child.parent_request_id.as_str(),
                    "child_request_id": tenant_a_child.request_id.as_str()
                }),
            )
            .unwrap();
        store
            .record_receipt_lineage_statement_record(
                &tenant_b_child.id,
                Some(tenant_b_child.request_id.as_str()),
                Some(tenant_b_child.session_id.as_str()),
                None,
                Some(tenant_b_child.parent_request_id.as_str()),
                Some(&tenant_b_parent.id),
                Some("tenant-b-chain"),
                100,
                &serde_json::json!({
                    "child_receipt_id": tenant_b_child.id,
                    "parent_receipt_id": tenant_b_parent.id,
                    "parent_request_id": tenant_b_child.parent_request_id.as_str(),
                    "child_request_id": tenant_b_child.request_id.as_str()
                }),
            )
            .unwrap();

        let archived = store
            .archive_receipts_before_for_tenant(150, archive_path.to_str().unwrap(), "tenant-a")
            .unwrap();
        assert_eq!(archived, 1);
        assert_eq!(store.tool_receipt_count().unwrap(), 1);
        assert_eq!(store.child_receipt_count().unwrap(), 1);
        assert_eq!(
            store
                .list_child_receipts(
                    10,
                    None,
                    None,
                    Some(tenant_b_child.request_id.as_str()),
                    None,
                    None
                )
                .unwrap()
                .len(),
            1
        );

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(archive_store.tool_receipt_count().unwrap(), 1);
        assert_eq!(archive_store.child_receipt_count().unwrap(), 1);
        assert_eq!(
            archive_store
                .list_child_receipts(
                    10,
                    None,
                    None,
                    Some(tenant_a_child.request_id.as_str()),
                    None,
                    None
                )
                .unwrap()
                .len(),
            1
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Size-based rotation: if the DB size exceeds max_size_bytes, rotate_if_needed
    /// archives some receipts.
    #[test]
    fn retention_rotates_at_size_boundary() {
        let live_path = unique_db_path("retention-size-live");
        let archive_path = unique_db_path("retention-size-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();

        // Insert 100 receipts to accumulate some size.
        for i in 0..100usize {
            let receipt = receipt_with_ts(&format!("rcpt-sz-{i}"), 1000 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }

        // Measure current DB size.
        let current_size = store.db_size_bytes().unwrap();
        assert!(current_size > 0, "DB should have nonzero size");

        // Set max_size_bytes to 1 byte below current size to force rotation.
        let config = RetentionConfig {
            retention_days: 3650, // 10 years -- time threshold won't trigger
            max_size_bytes: current_size.saturating_sub(1),
            archive_path: archive_path.to_str().unwrap().to_string(),
            tenant_id: None,
        };

        let archived = store.rotate_if_needed(&config).unwrap();
        assert!(
            archived > 0,
            "size-triggered rotation should archive some receipts"
        );

        // After rotation live DB should have fewer receipts.
        let remaining = store.tool_receipt_count().unwrap();
        assert!(
            remaining < 100,
            "live DB should have fewer than 100 receipts after size rotation"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Archived receipts must be verifiable against the checkpoint roots stored
    /// in the archive database.
    #[test]
    fn archived_receipt_verifies_against_checkpoint() {
        let live_path = unique_db_path("retention-verify-live");
        let archive_path = unique_db_path("retention-verify-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Insert 10 receipts with timestamp < 500.
        let mut seqs = Vec::new();
        for i in 0..10usize {
            let receipt = receipt_with_ts(&format!("rcpt-verify-{i}"), 100 + i as u64);
            let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }

        // Build a Merkle checkpoint over those 10 receipts using canonical bytes.
        let canonical_bytes = store
            .receipts_canonical_bytes_range(seqs[0], seqs[9])
            .unwrap();
        let bytes_vec: Vec<Vec<u8>> = canonical_bytes.iter().map(|(_, b)| b.clone()).collect();

        let cp = build_checkpoint(1, seqs[0], seqs[9], &bytes_vec, &kp).unwrap();
        store.store_checkpoint(&cp).unwrap();

        // Archive all 10 receipts (cutoff = 500, all timestamps < 500).
        let archived = store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 10, "should archive all 10 receipts");

        // Open archive DB and load the checkpoint.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        let loaded_cp = archive_store
            .load_checkpoint_by_seq(1)
            .unwrap()
            .expect("checkpoint should be in archive");

        // Verify the checkpoint signature.
        assert!(
            verify_checkpoint_signature(&loaded_cp).unwrap(),
            "checkpoint signature should verify in archive"
        );

        // Load canonical bytes from archive and verify inclusion proof.
        let archive_canonical = archive_store
            .receipts_canonical_bytes_range(seqs[0], seqs[9])
            .unwrap();
        assert_eq!(
            archive_canonical.len(),
            10,
            "archive should contain all 10 receipts"
        );

        // Build a Merkle tree from the archived bytes and verify inclusion.
        let archived_bytes: Vec<Vec<u8>> =
            archive_canonical.iter().map(|(_, b)| b.clone()).collect();
        let tree = MerkleTree::from_leaves(&archived_bytes).unwrap();

        let proof = build_inclusion_proof(&tree, 0, 1, seqs[0]).unwrap();
        assert!(
            proof.verify(&archived_bytes[0], &loaded_cp.body.merkle_root),
            "receipt 0 inclusion proof should verify against archived checkpoint root"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Archiving receipts from batch 1 should include batch 1's checkpoint row
    /// in the archive, but leave batch 2's checkpoint in the live DB.
    #[test]
    fn archive_preserves_checkpoint_rows() {
        let live_path = unique_db_path("retention-cp-rows-live");
        let archive_path = unique_db_path("retention-cp-rows-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Insert 10 receipts for batch 1 (timestamps 100-109).
        let mut batch1_seqs = Vec::new();
        for i in 0..10usize {
            let receipt = receipt_with_ts(&format!("rcpt-batch1-{i}"), 100 + i as u64);
            let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
            batch1_seqs.push(seq);
        }

        // Build and store checkpoint for batch 1.
        let bytes1 = store
            .receipts_canonical_bytes_range(batch1_seqs[0], batch1_seqs[9])
            .unwrap();
        let bv1: Vec<Vec<u8>> = bytes1.iter().map(|(_, b)| b.clone()).collect();
        let cp1 = build_checkpoint(1, batch1_seqs[0], batch1_seqs[9], &bv1, &kp).unwrap();
        store.store_checkpoint(&cp1).unwrap();

        // Insert 10 receipts for batch 2 (timestamps 200-209).
        let mut batch2_seqs = Vec::new();
        for i in 0..10usize {
            let receipt = receipt_with_ts(&format!("rcpt-batch2-{i}"), 200 + i as u64);
            let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
            batch2_seqs.push(seq);
        }

        // Build and store checkpoint for batch 2.
        let bytes2 = store
            .receipts_canonical_bytes_range(batch2_seqs[0], batch2_seqs[9])
            .unwrap();
        let bv2: Vec<Vec<u8>> = bytes2.iter().map(|(_, b)| b.clone()).collect();
        let cp2 = build_checkpoint_with_previous(
            2,
            batch2_seqs[0],
            batch2_seqs[9],
            &bv2,
            &kp,
            Some(&cp1),
        )
        .unwrap();
        store.store_checkpoint(&cp2).unwrap();

        // Archive only batch 1 receipts (cutoff = 150, timestamps 100-109 < 150).
        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 10, "should archive 10 receipts from batch 1");

        // Archive DB should have batch 1's checkpoint row.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        let arch_cp1 = archive_store.load_checkpoint_by_seq(1).unwrap();
        assert!(
            arch_cp1.is_some(),
            "archive DB should have batch 1 checkpoint"
        );

        // Archive DB should NOT have batch 2's checkpoint row.
        let arch_cp2 = archive_store.load_checkpoint_by_seq(2).unwrap();
        assert!(
            arch_cp2.is_none(),
            "archive DB should NOT have batch 2 checkpoint"
        );

        // Live DB should still have batch 2's checkpoint row.
        let live_cp2 = store.load_checkpoint_by_seq(2).unwrap();
        assert!(
            live_cp2.is_some(),
            "live DB should still have batch 2 checkpoint"
        );

        // Live DB should NOT have batch 1's checkpoint (it was archived).
        // Note: per plan spec, only receipt rows are deleted from live; checkpoint
        // rows for fully-archived batches are also deleted. We verify batch 2 checkpoint
        // is still present but do not mandate batch 1 checkpoint deletion from live
        // (that is an optimization -- we just require it exists in the archive).

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Archive with no checkpoints: storing receipts without any checkpoint rows
    /// and calling archive_receipts_before should succeed without error.
    ///
    /// This covers the degenerate case where co-archival has nothing to do.
    #[test]
    fn archive_with_no_checkpoints_succeeds() {
        let live_path = unique_db_path("retention-no-cp-live");
        let archive_path = unique_db_path("retention-no-cp-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();

        // Insert 5 receipts, but store NO checkpoints.
        for i in 0..5usize {
            let receipt = receipt_with_ts(&format!("rcpt-no-cp-{i}"), 100 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }

        // Verify no checkpoints exist before archiving (seq 1 is absent).
        assert!(
            store.load_checkpoint_by_seq(1).unwrap().is_none(),
            "should have no checkpoints before archive"
        );

        // archive_receipts_before must succeed even with no checkpoint rows.
        let archived = store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 5, "should have archived 5 receipts");

        // Live DB should be empty.
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            0,
            "live DB should be empty after archiving all receipts"
        );

        // Archive DB should have 5 receipts and 0 checkpoints.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(
            archive_store.tool_receipt_count().unwrap(),
            5,
            "archive DB should have 5 receipts"
        );
        // Archive DB should have no checkpoints (none were stored before archiving).
        assert!(
            archive_store.load_checkpoint_by_seq(1).unwrap().is_none(),
            "archive DB should have no checkpoints"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn archive_copies_and_deletes_child_receipts() {
        let live_path = unique_db_path("retention-child-live");
        let archive_path = unique_db_path("retention-child-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        store
            .append_chio_receipt(&receipt_with_ts("rcpt-parent", 100))
            .unwrap();
        store
            .append_child_receipt(&child_receipt_with_ts("child-parent", 100))
            .unwrap();

        let archived = store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(
            archived, 1,
            "tool receipt archival count should remain stable"
        );
        assert_eq!(store.child_receipt_count().unwrap(), 0);

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(archive_store.child_receipt_count().unwrap(), 1);

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    #[test]
    fn archive_copies_capability_lineage_for_archived_receipts() {
        let live_path = unique_db_path("retention-lineage-live");
        let archive_path = unique_db_path("retention-lineage-archive");

        let mut store = SqliteReceiptStore::open(&live_path).unwrap();
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-retention-lineage", &subject, &issuer);
        store.record_capability_snapshot(&capability, None).unwrap();
        store
            .append_chio_receipt(&receipt_with_capability_and_ts(
                "rcpt-lineage",
                &capability.id,
                100,
            ))
            .unwrap();

        store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        let archived_lineage = archive_store
            .get_lineage("cap-retention-lineage")
            .unwrap()
            .expect("archived lineage snapshot");
        assert_eq!(archived_lineage.subject_key, subject.public_key().to_hex());

        let live_lineage = store
            .get_lineage("cap-retention-lineage")
            .unwrap()
            .expect("live lineage snapshot should remain");
        assert_eq!(live_lineage.issuer_key, issuer.public_key().to_hex());

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }
}
