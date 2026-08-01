/// Retention and archival tests for SqliteReceiptStore.
///
/// These tests cover COMP-03 (configurable retention) and COMP-04 (archived
/// receipt verification). Archival removes only the whole checkpointed prefix
/// that has aged past the cutoff, co-archiving the claim-log projection and
/// deleting it together with the source rows. Tenant-scoped rotation is
/// rejected fail-closed. Per-table co-archival mechanics are unit-tested in the
/// store crate at
/// `crates/platform/chio-store-sqlite/src/receipt_store/tests/retention.rs`.
/// All tests use temporary files that are cleaned up after each test.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod retention {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_core::merkle::MerkleTree;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
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
        let keypair = Keypair::generate();
        receipt_with_capability_ts_and_keypair(id, capability_id, timestamp, &keypair)
    }

    /// Sign a receipt with a caller-supplied keypair so a batch of receipts
    /// shares one signer. The checkpoint protocol requires every receipt in a
    /// checkpoint range to have the same `kernel_key` as the checkpoint itself,
    /// so tests that build a checkpoint over a receipt batch route through this
    /// helper.
    fn receipt_with_capability_ts_and_keypair(
        id: &str,
        capability_id: &str,
        timestamp: u64,
        keypair: &Keypair,
    ) -> ChioReceipt {
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
            keypair,
        )
        .expect("sign receipt")
    }

    fn receipt_with_ts(id: &str, timestamp: u64) -> ChioReceipt {
        receipt_with_capability_and_ts(id, "cap-1", timestamp)
    }

    fn receipt_with_ts_and_keypair(id: &str, timestamp: u64, keypair: &Keypair) -> ChioReceipt {
        receipt_with_capability_ts_and_keypair(id, "cap-1", timestamp, keypair)
    }

    fn child_receipt_with_ts_and_keypair(
        id: &str,
        timestamp: u64,
        keypair: &Keypair,
    ) -> ChildRequestReceipt {
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
            keypair,
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
                aggregate_invocation_budget: None,
            },
            issuer,
        )
        .expect("sign capability")
    }

    /// Checkpoint a receipt batch over the given entry_seq range on `store`,
    /// signed with `keypair` (all receipts in the range must share it).
    fn checkpoint_range(
        store: &SqliteReceiptStore,
        checkpoint_seq: u64,
        start_seq: u64,
        end_seq: u64,
        keypair: &Keypair,
        previous: Option<&chio_kernel::checkpoint::KernelCheckpoint>,
    ) -> chio_kernel::checkpoint::KernelCheckpoint {
        let canonical = store
            .receipts_canonical_bytes_range(start_seq, end_seq)
            .unwrap();
        let bytes: Vec<Vec<u8>> = canonical.iter().map(|(_, b)| b.clone()).collect();
        let checkpoint = match previous {
            None => build_checkpoint(checkpoint_seq, start_seq, end_seq, &bytes, keypair).unwrap(),
            Some(previous) => build_checkpoint_with_previous(
                checkpoint_seq,
                start_seq,
                end_seq,
                &bytes,
                keypair,
                Some(previous),
                &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&previous.body).unwrap()],
            )
            .unwrap(),
        };
        store.store_checkpoint(&checkpoint).unwrap();
        checkpoint
    }

    /// Time-based rotation: the aged, checkpointed prefix is archived; the fresh
    /// uncheckpointed receipts remain in the live DB.
    #[test]
    fn retention_rotates_at_time_boundary() {
        let live_path = unique_db_path("retention-time-live");
        let archive_path = unique_db_path("retention-time-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // 10 aged receipts (timestamps 100-109), all signed by `kp` so a
        // checkpoint over the batch passes the signer-binding check.
        let mut seqs = Vec::new();
        for i in 0..10usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-old-{i}"), 100 + i as u64, &kp);
            seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        // Checkpoint the aged prefix [1, 10] so it can age out.
        checkpoint_range(&store, 1, seqs[0], seqs[9], &kp, None);

        // 5 fresh receipts (timestamps 200-204) stay uncheckpointed.
        for i in 0..5usize {
            let receipt = receipt_with_ts(&format!("rcpt-new-{i}"), 200 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }

        // Cutoff at timestamp 150: the entire checkpointed prefix has aged.
        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(
            archived, 10,
            "should archive the 10 checkpointed aged receipts"
        );

        // Live DB should have the 5 fresh receipts.
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

    /// Once a receipt id has been co-archived and deleted, re-appending it must
    /// be rejected: the live UNIQUE(receipt_id) sentinel is gone, but the
    /// archive already holds it, so accepting it as a new live receipt would
    /// overlap the archived and live histories and make a lookup by that id
    /// ambiguous.
    #[test]
    fn archived_receipt_id_cannot_be_reappended() {
        let live_path = unique_db_path("retention-reuse-live");
        let archive_path = unique_db_path("retention-reuse-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();
        let mut seqs = Vec::new();
        for i in 0..3usize {
            let receipt = receipt_with_ts_and_keypair(&format!("reuse-{i}"), 100 + i as u64, &kp);
            seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        checkpoint_range(&store, 1, seqs[0], seqs[2], &kp, None);

        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 3, "the checkpointed prefix archives");
        assert_eq!(store.tool_receipt_count().unwrap(), 0);

        // Replaying an archived id (a retry or a forged append) must fail rather
        // than silently insert a second live copy.
        let replay = receipt_with_ts_and_keypair("reuse-0", 100, &kp);
        assert!(
            store.append_chio_receipt_returning_seq(&replay).is_err(),
            "an archived receipt id must not be re-appended as a new live receipt"
        );
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            0,
            "the rejected replay must not add an overlapping live row"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// A repeated rotation at the same cutoff is a clean no-op: the watermark
    /// already covers the archived prefix, so nothing new is archived and the
    /// live store is untouched (monotonic watermark, idempotent re-run).
    #[test]
    fn retention_retry_is_idempotent() {
        let live_path = unique_db_path("retention-retry-live");
        let archive_path = unique_db_path("retention-retry-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();
        let mut seqs = Vec::new();
        for i in 0..3usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-retry-{i}"), 100 + i as u64, &kp);
            seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        checkpoint_range(&store, 1, seqs[0], seqs[2], &kp, None);

        let first = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(first, 3, "first rotation archives the checkpointed prefix");
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            0,
            "live rows are deleted after the first rotation"
        );

        let second = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(
            second, 0,
            "retry over an already-archived prefix is a no-op"
        );
        assert_eq!(store.tool_receipt_count().unwrap(), 0);

        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(archive_store.tool_receipt_count().unwrap(), 3);

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Tenant-scoped retention is not expressible as a prefix watermark (the
    /// checkpoint-aligned watermark spans every tenant in a batch), so a
    /// rotation with `tenant_id: Some(..)` is rejected fail-closed with
    /// `RetentionTenantScopeUnsupported` and modifies nothing: no receipts
    /// are archived, no archive file is created, and the live store is left
    /// exactly as it was.
    #[test]
    fn tenant_scoped_rotation_is_rejected_and_leaves_counts_unchanged() {
        let live_path = unique_db_path("retention-tenant-rejected-live");
        let archive_path = unique_db_path("retention-tenant-rejected-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Aged, checkpointed receipts that WOULD be eligible for a global
        // rotation, to prove the tenant-scoped rejection leaves them alone.
        let mut seqs = Vec::new();
        for i in 0..3usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-tenant-{i}"), 100 + i as u64, &kp);
            seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        checkpoint_range(&store, 1, seqs[0], seqs[2], &kp, None);

        let config = RetentionConfig {
            tenant_id: Some("tenant-a".to_string()),
            archive_path: archive_path.to_str().unwrap().to_string(),
            explicit_cutoff_unix_secs: Some(150),
            ..RetentionConfig::default()
        };

        let error = store.rotate_if_needed(&config);
        let message = error
            .expect_err("expected RetentionTenantScopeUnsupported")
            .to_string();
        assert!(
            message.contains("tenant-scoped retention"),
            "unexpected error: {message}"
        );

        // Fail-closed: nothing archived, live counts unchanged, no archive
        // file materializes.
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            3,
            "tenant-scoped rejection must not modify the live store"
        );
        assert!(
            !archive_path.exists(),
            "tenant-scoped rejection must not create an archive file"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Size-based rotation: with the time threshold disabled, exceeding
    /// `max_size_bytes` rotates at the median timestamp, archiving the whole
    /// checkpointed prefix that has aged past that median.
    #[test]
    fn retention_rotates_at_size_boundary() {
        let live_path = unique_db_path("retention-size-live");
        let archive_path = unique_db_path("retention-size-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Insert 100 receipts (timestamps 1000-1099), all signed by `kp`.
        let mut seqs = Vec::new();
        for i in 0..100usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-sz-{i}"), 1000 + i as u64, &kp);
            seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        // Two checkpoints of 50 each: [1, 50] and [51, 100]. The median cutoff
        // (timestamp 1050) fully ages the first batch only.
        let cp1 = checkpoint_range(&store, 1, seqs[0], seqs[49], &kp, None);
        checkpoint_range(&store, 2, seqs[50], seqs[99], &kp, Some(&cp1));

        let current_size = store.db_size_bytes().unwrap();
        assert!(current_size > 0, "DB should have nonzero size");

        // retention_days = u64::MAX disables the time threshold (time_cutoff
        // saturates to 0), so only the size threshold can trigger.
        let config = RetentionConfig {
            retention_days: u64::MAX,
            max_size_bytes: current_size.saturating_sub(1),
            archive_path: archive_path.to_str().unwrap().to_string(),
            tenant_id: None,
            explicit_cutoff_unix_secs: None,
            ..RetentionConfig::default()
        };

        let archived = store.rotate_if_needed(&config).unwrap();
        assert_eq!(
            archived, 50,
            "size-triggered rotation archives the first checkpointed batch"
        );

        let remaining = store.tool_receipt_count().unwrap();
        assert_eq!(
            remaining, 50,
            "live DB retains the un-aged second checkpointed batch"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// Archived receipts must be verifiable against the checkpoint roots stored
    /// in the archive database (COMP-04).
    #[test]
    fn archived_receipt_verifies_against_checkpoint() {
        let live_path = unique_db_path("retention-verify-live");
        let archive_path = unique_db_path("retention-verify-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Insert 10 receipts with timestamp < 500. Every receipt is signed with
        // `kp` so the checkpoint's signer-binding check passes.
        let mut seqs = Vec::new();
        for i in 0..10usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-verify-{i}"), 100 + i as u64, &kp);
            let seq = store.append_chio_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }

        // Build a Merkle checkpoint over those 10 receipts using canonical bytes.
        let cp = checkpoint_range(&store, 1, seqs[0], seqs[9], &kp, None);

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
        assert_eq!(loaded_cp.body.merkle_root, cp.body.merkle_root);

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

    /// Archiving batch 1 copies batch 1's checkpoint row into the archive but
    /// leaves batch 2's checkpoint in the live DB (batch 2 has not aged).
    #[test]
    fn archive_preserves_checkpoint_rows() {
        let live_path = unique_db_path("retention-cp-rows-live");
        let archive_path = unique_db_path("retention-cp-rows-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();

        // Insert 10 receipts for batch 1 (timestamps 100-109).
        let mut batch1_seqs = Vec::new();
        for i in 0..10usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-batch1-{i}"), 100 + i as u64, &kp);
            batch1_seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        let cp1 = checkpoint_range(&store, 1, batch1_seqs[0], batch1_seqs[9], &kp, None);

        // Insert 10 receipts for batch 2 (timestamps 200-209).
        let mut batch2_seqs = Vec::new();
        for i in 0..10usize {
            let receipt =
                receipt_with_ts_and_keypair(&format!("rcpt-batch2-{i}"), 200 + i as u64, &kp);
            batch2_seqs.push(store.append_chio_receipt_returning_seq(&receipt).unwrap());
        }
        checkpoint_range(&store, 2, batch2_seqs[0], batch2_seqs[9], &kp, Some(&cp1));

        // Archive only batch 1 receipts (cutoff = 150, timestamps 100-109 < 150).
        let archived = store
            .archive_receipts_before(150, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 10, "should archive 10 receipts from batch 1");

        // Archive DB should have batch 1's checkpoint row.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert!(
            archive_store.load_checkpoint_by_seq(1).unwrap().is_some(),
            "archive DB should have batch 1 checkpoint"
        );

        // Archive DB should NOT have batch 2's checkpoint row.
        assert!(
            archive_store.load_checkpoint_by_seq(2).unwrap().is_none(),
            "archive DB should NOT have batch 2 checkpoint"
        );

        // Live DB should still have batch 2's checkpoint row (rotation never
        // deletes checkpoint rows from the live store).
        assert!(
            store.load_checkpoint_by_seq(2).unwrap().is_some(),
            "live DB should still have batch 2 checkpoint"
        );

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// With no checkpoints there is no aged checkpointed prefix, so archival is
    /// a fail-safe no-op: nothing is archived and the live store is untouched.
    #[test]
    fn archive_with_no_checkpoints_is_a_noop() {
        let live_path = unique_db_path("retention-no-cp-live");
        let archive_path = unique_db_path("retention-no-cp-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();

        // Insert 5 receipts, but store NO checkpoints.
        for i in 0..5usize {
            let receipt = receipt_with_ts(&format!("rcpt-no-cp-{i}"), 100 + i as u64);
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }
        assert!(
            store.load_checkpoint_by_seq(1).unwrap().is_none(),
            "should have no checkpoints before archive"
        );

        // archive_receipts_before is a no-op with no checkpointed prefix.
        let archived = store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 0, "no checkpointed prefix has aged");

        // Live DB is untouched.
        assert_eq!(
            store.tool_receipt_count().unwrap(),
            5,
            "live DB retains every receipt (nothing archived)"
        );

        // The archive file was never created; opening it yields an empty store.
        let archive_store = SqliteReceiptStore::open(&archive_path).unwrap();
        assert_eq!(archive_store.tool_receipt_count().unwrap(), 0);

        let _ = fs::remove_file(&live_path);
        let _ = fs::remove_file(&archive_path);
    }

    /// A checkpointed tool+child prefix co-archives both receipt kinds and
    /// deletes them together from the live store.
    #[test]
    fn archive_copies_and_deletes_child_receipts() {
        let live_path = unique_db_path("retention-child-live");
        let archive_path = unique_db_path("retention-child-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let kp = Keypair::generate();
        // Parent tool receipt (entry_seq 1) and child receipt (entry_seq 2),
        // both signed by `kp` so the checkpoint over [1, 2] binds one signer.
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_keypair(
                "rcpt-parent",
                100,
                &kp,
            ))
            .unwrap();
        store
            .append_child_receipt(&child_receipt_with_ts_and_keypair("child-parent", 100, &kp))
            .unwrap();
        checkpoint_range(&store, 1, 1, 2, &kp, None);

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

    /// Archiving a checkpointed receipt co-archives its capability lineage while
    /// the live lineage snapshot remains (rotation never deletes lineage rows).
    #[test]
    fn archive_copies_capability_lineage_for_archived_receipts() {
        let live_path = unique_db_path("retention-lineage-live");
        let archive_path = unique_db_path("retention-lineage-archive");

        let store = SqliteReceiptStore::open(&live_path).unwrap();
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let kp = Keypair::generate();
        let capability = capability_with_id("cap-retention-lineage", &subject, &issuer);
        store.record_capability_snapshot(&capability, None).unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_capability_ts_and_keypair(
                "rcpt-lineage",
                &capability.id,
                100,
                &kp,
            ))
            .unwrap();
        checkpoint_range(&store, 1, 1, 1, &kp, None);

        let archived = store
            .archive_receipts_before(500, archive_path.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 1);

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

    #[test]
    fn kernel_maintenance_task_rotates_when_configured() {
        use std::sync::Arc;
        let live = unique_db_path("kernel-maint-live");
        let archive = unique_db_path("kernel-maint-archive");
        let keypair = Keypair::generate();
        let store = SqliteReceiptStore::open(&live).unwrap();
        // `SqliteReceiptStore` also has an inherent `enable_background_checkpoints`
        // that takes a `BackgroundCheckpointSigner` (not exported from this
        // integration-test crate); UFCS pins the call to the public
        // `ReceiptStore` trait method (`keypair`, `max_batch`) instead.
        <SqliteReceiptStore as ReceiptStore>::enable_background_checkpoints(
            &store,
            keypair.clone(),
            2,
        )
        .unwrap();
        // Every receipt in a checkpointed range must share the checkpoint's
        // kernel key, so all four receipts are signed with the same keypair
        // installed as the background checkpoint signer above.
        for i in 0..4u64 {
            let r =
                receipt_with_capability_ts_and_keypair(&format!("km-{i}"), "cap", 100, &keypair);
            store.append_chio_receipt_returning_seq(&r).unwrap();
        }
        store.flush_receipt_writes().unwrap();

        // Directly exercise the trait entry point the maintenance task calls
        // (the task itself is a timed loop; here we assert the wiring closes).
        let handle: Arc<dyn ReceiptStore> = Arc::new(store);
        let config = RetentionConfig {
            retention_days: 0,
            check_interval_secs: 1,
            archive_path: archive.to_str().unwrap().to_string(),
            explicit_cutoff_unix_secs: Some(1_000),
            ..RetentionConfig::default()
        };
        let archived = handle.rotate_receipts(&config).unwrap();
        assert_eq!(
            archived, 4,
            "the maintenance entry point archived the aged prefix"
        );
        assert!(handle.receipt_store_health().unwrap().healthy);

        let _ = fs::remove_file(&live);
        let _ = fs::remove_file(&archive);
    }
}
