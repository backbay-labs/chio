use super::super::*;
use super::support::*;

#[test]
fn store_and_load_checkpoint_by_seq() {
    let path = unique_db_path("chio-receipts-cp-store");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    // Append 5 receipts.
    let mut seqs = Vec::new();
    for i in 0..5usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
        let seq = store
            .append_chio_receipt_returning_seq(&receipt)
            .test_unwrap();
        seqs.push(seq);
    }

    // Build checkpoint.
    let kp = receipt_test_keypair();
    let bytes = canonical_receipt_bytes(&store, seqs[0], seqs[4]);
    let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).test_unwrap();

    // Store and retrieve.
    ReceiptStore::store_checkpoint(&store, &cp).test_unwrap();
    let loaded = store.load_checkpoint_by_seq(1).test_unwrap();
    assert!(loaded.is_some(), "checkpoint should be loadable");
    let loaded = loaded.test_unwrap();
    assert_eq!(loaded.body.checkpoint_seq, 1);
    assert_eq!(loaded.body.tree_size, 5);
    assert_eq!(loaded.body.batch_start_seq, seqs[0]);
    assert_eq!(loaded.body.batch_end_seq, seqs[4]);
    assert_eq!(
        loaded.signature.to_hex(),
        cp.signature.to_hex(),
        "signature should round-trip"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_first_checkpoint_that_skips_committed_prefix() {
    let path = unique_db_path("chio-receipts-cp-skipped-prefix");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let first_receipt = sample_receipt_with_id("rcpt-prefix-1");
    let second_receipt = sample_receipt_with_id("rcpt-prefix-2");
    store
        .append_chio_receipt_returning_seq(&first_receipt)
        .test_unwrap();
    let second_seq = store
        .append_chio_receipt_returning_seq(&second_receipt)
        .test_unwrap();

    let kp = receipt_test_keypair();
    let checkpoint = build_checkpoint(
        1,
        second_seq,
        second_seq,
        &canonical_receipt_bytes(&store, second_seq, second_seq),
        &kp,
    )
    .test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("first checkpoint must start at entry_seq 1"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn load_checkpoint_by_seq_returns_none_for_missing() {
    let path = unique_db_path("chio-receipts-cp-missing");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let result = store.load_checkpoint_by_seq(999).test_unwrap();
    assert!(result.is_none());
    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_rejects_contiguous_successor_without_predecessor_digest() {
    let path = unique_db_path("chio-receipts-cp-missing-predecessor-digest");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let mut seqs = Vec::new();
    for i in 0..2usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-missing-digest-{i}"));
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
        seqs[0],
        &canonical_receipt_bytes(&store, seqs[0], seqs[0]),
        &checkpoint_kp,
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &first).test_unwrap();

    let second = build_checkpoint(
        2,
        seqs[1],
        seqs[1],
        &canonical_receipt_bytes(&store, seqs[1], seqs[1]),
        &checkpoint_kp,
    )
    .test_unwrap();

    let error = ReceiptStore::store_checkpoint(&store, &second).test_unwrap_err();
    assert!(
        error.to_string().contains("missing predecessor digest")
            || error
                .to_string()
                .contains("checkpoint predecessor digest is required"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_enforces_predecessor_continuity() {
    let path = unique_db_path("chio-receipts-cp-continuity");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-predecessor-{i}"));
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
    ReceiptStore::store_checkpoint(&store, &first).test_unwrap();

    let second = build_checkpoint(
        2,
        seqs[3],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[3], seqs[3]),
        &checkpoint_kp,
    )
    .test_unwrap();
    let error = ReceiptStore::store_checkpoint(&store, &second).test_unwrap_err();
    assert!(
        error.to_string().contains("predecessor continuity"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn trait_store_checkpoint_installs_immutable_checkpoint_triggers() {
    let path = unique_db_path("chio-receipts-cp-immutable");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let receipt = sample_receipt_with_id("rcpt-immutable-1");
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

    let error = store
        .connection()
        .test_unwrap()
        .execute(
            "UPDATE kernel_checkpoints SET issued_at = issued_at + 1 WHERE checkpoint_seq = 1",
            [],
        )
        .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("kernel checkpoints are immutable"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn frontier_rebuild_rejects_legacy_v1_mirror_divergence_before_v2_migration() {
    let path = unique_db_path("chio-receipts-legacy-frontier-mirror");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt_seq = store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id(
            "legacy-frontier-mirror-receipt",
        ))
        .test_unwrap();
    let checkpoint_keypair = receipt_test_keypair();
    let mut legacy = build_checkpoint(
        1,
        receipt_seq,
        receipt_seq,
        &canonical_receipt_bytes(&store, receipt_seq, receipt_seq),
        &checkpoint_keypair,
    )
    .test_unwrap();
    legacy.body.schema = chio_kernel::checkpoint::CHECKPOINT_SCHEMA_V1.to_string();
    legacy.body.chain_root = None;
    legacy.signature = checkpoint_keypair
        .sign(&canonical_json_bytes(&legacy.body).test_expect("canonical legacy checkpoint body"));
    ReceiptStore::store_checkpoint(&store, &legacy).test_unwrap();

    let signed_leaf =
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&legacy.body).test_unwrap();
    assert_eq!(
        load_checkpoint_chain_leaf_hashes(&store.connection().test_unwrap()).test_unwrap(),
        vec![signed_leaf],
        "an intact legacy row must rebuild from its signed body"
    );

    let divergent_root = chio_core::hashing::Hash::zero();
    assert_ne!(divergent_root, legacy.body.merkle_root);
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")
        .test_unwrap();
    let changed = connection
        .execute(
            "UPDATE kernel_checkpoints SET merkle_root = ?1 WHERE checkpoint_seq = 1",
            rusqlite::params![divergent_root.to_hex()],
        )
        .test_unwrap();
    assert_eq!(changed, 1);

    let error = load_checkpoint_chain_leaf_hashes(&connection).test_unwrap_err();
    assert!(
        error.to_string().contains("merkle_root column")
            && error.to_string().contains("does not match signed body"),
        "frontier rebuild must reject a divergent legacy mirror before signing a v2 root: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn create_next_receipt_checkpoint_respects_max_batch() {
    let path = unique_db_path("chio-receipts-cp-create-next-max-batch");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for index in 0..5 {
        store
            .append_chio_receipt_returning_seq(&sample_receipt_with_id(&format!(
                "rcpt-create-next-max-batch-{index}"
            )))
            .test_unwrap();
    }

    let report = <SqliteReceiptStore as ReceiptStore>::create_next_receipt_checkpoint(
        &store,
        2,
        &receipt_test_keypair(),
    )
    .test_unwrap();

    assert!(report.created);
    assert_eq!(report.checkpoint_seq, Some(1));
    assert_eq!(report.batch_start_seq, Some(1));
    assert_eq!(report.batch_end_seq, Some(2));
    assert_eq!(report.latest_committed_entry_seq, 5);
    assert_eq!(report.latest_checkpointed_entry_seq, 2);
    assert_eq!(
        store
            .receipt_checkpoint_status(Some(2))
            .test_unwrap()
            .next_range,
        Some(chio_kernel::ReceiptCheckpointRange {
            start_seq: 3,
            end_seq: 4
        })
    );

    let _ = fs::remove_file(path);
}

#[test]
fn concurrent_create_next_receipt_checkpoint_produces_one_checkpoint() {
    let path = unique_db_path("chio-receipts-cp-create-next-concurrent");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for index in 0..3 {
        store
            .append_chio_receipt_returning_seq(&sample_receipt_with_id(&format!(
                "rcpt-create-next-concurrent-{index}"
            )))
            .test_unwrap();
    }
    drop(store);

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = SqliteReceiptStore::open(&path).test_unwrap();
            barrier.wait();
            store
                .create_next_receipt_checkpoint(10, &receipt_test_keypair())
                .test_unwrap()
        }));
    }

    let reports = handles
        .into_iter()
        .map(|handle| handle.join().unwrap_or_else(|_| panic!("thread panicked")))
        .collect::<Vec<_>>();

    assert_eq!(reports.iter().filter(|report| report.created).count(), 1);
    assert!(reports
        .iter()
        .all(|report| report.latest_checkpointed_entry_seq == 3));

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    let status = reopened.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(status.healthy);
    assert_eq!(status.latest_checkpoint_seq, Some(1));
    assert_eq!(status.latest_checkpointed_entry_seq, 3);
    assert!(status.next_range.is_none());

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_accepts_contiguous_predecessor() {
    let path = unique_db_path("chio-receipts-cp-predecessor");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let kp = receipt_test_keypair();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-contiguous-predecessor-{i}"));
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

    let second = build_checkpoint_with_previous(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    ReceiptStore::store_checkpoint(&store, &second).test_unwrap();

    let loaded = store
        .load_checkpoint_by_seq(2)
        .test_unwrap()
        .test_expect("second checkpoint");
    assert_eq!(
        loaded.body.previous_checkpoint_sha256,
        second.body.previous_checkpoint_sha256
    );

    let _ = fs::remove_file(path);
}

#[test]
fn store_checkpoint_projects_tree_heads_and_predecessor_witnesses() {
    let path = unique_db_path("chio-receipts-tree-heads");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let mut seqs = Vec::new();
    for i in 0..4usize {
        let receipt =
            sample_receipt_with_id_and_timestamp(&format!("tree-head-{i}"), 100 + i as u64);
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
    store.store_checkpoint(&first).test_unwrap();

    let second = build_checkpoint_with_previous(
        2,
        seqs[2],
        seqs[3],
        &canonical_receipt_bytes(&store, seqs[2], seqs[3]),
        &checkpoint_kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    store.store_checkpoint(&second).test_unwrap();

    let tree_heads = load_checkpoint_tree_head_rows(&store);
    assert_eq!(
        tree_heads,
        vec![
            (1, seqs[0], first.body.tree_size as u64, None),
            (
                2,
                seqs[2],
                second.body.tree_size as u64,
                second.body.previous_checkpoint_sha256.clone(),
            ),
        ]
    );

    let witnesses = load_checkpoint_predecessor_witness_rows(&store);
    assert_eq!(
        witnesses,
        vec![(
            1,
            2,
            second.body.previous_checkpoint_sha256.clone().test_unwrap(),
        )]
    );
    let first_publication = build_checkpoint_publication(&first).test_unwrap();
    let second_publication = build_checkpoint_publication(&second).test_unwrap();
    let publications = load_checkpoint_publication_metadata_rows(&store);
    assert_eq!(
        publications,
        vec![
            (
                first_publication.checkpoint_seq,
                first_publication.schema,
                first_publication.merkle_root.to_hex(),
                first_publication.published_at,
                first_publication.kernel_key.to_hex(),
                first_publication.log_tree_size,
                first_publication.entry_start_seq,
                first_publication.entry_end_seq,
                first_publication.previous_checkpoint_sha256,
            ),
            (
                second_publication.checkpoint_seq,
                second_publication.schema,
                second_publication.merkle_root.to_hex(),
                second_publication.published_at,
                second_publication.kernel_key.to_hex(),
                second_publication.log_tree_size,
                second_publication.entry_start_seq,
                second_publication.entry_end_seq,
                second_publication.previous_checkpoint_sha256,
            ),
        ]
    );

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(load_checkpoint_tree_head_rows(&reopened), tree_heads);
    assert_eq!(
        load_checkpoint_predecessor_witness_rows(&reopened),
        witnesses
    );
    assert_eq!(
        load_checkpoint_publication_metadata_rows(&reopened),
        publications
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_backfills_claim_log_and_checkpoint_transparency_projections() {
    let path = unique_db_path("chio-receipts-legacy-projections");
    let tool_receipt = sample_receipt_with_id_and_timestamp("legacy-tool-1", 20);
    let child_receipt = sample_child_receipt_with_id_and_timestamp("legacy-child-1", 21);

    // Seed a legacy pre-projection store with only the raw receipt tables,
    // no checkpoints yet. The claim log backfill fail-closes whenever a
    // checkpoint already exists over an empty projection, so the legacy
    // checkpoint rows below are introduced only once the claim log projection
    // is already populated by this first open.
    seed_pre_projection_store(
        &path,
        std::slice::from_ref(&tool_receipt),
        std::slice::from_ref(&child_receipt),
        &[],
    );

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(
        load_claim_log_rows(&store),
        vec![
            (
                1,
                tool_receipt.id.clone(),
                "tool_receipt".to_string(),
                1,
                20
            ),
            (
                2,
                child_receipt.id.clone(),
                "child_receipt".to_string(),
                1,
                21
            ),
        ]
    );

    // Now land legacy checkpoints on top of the already-backfilled claim
    // log, inserted directly (bypassing `store_checkpoint`'s validation
    // path) to simulate a store that predates checkpoint_tree_heads /
    // checkpoint_predecessor_witnesses / checkpoint_publication_metadata.
    let checkpoint_kp = receipt_test_keypair();
    let first = build_checkpoint(1, 1, 1, &[b"legacy-one".to_vec()], &checkpoint_kp).test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        2,
        2,
        &[b"legacy-two".to_vec()],
        &checkpoint_kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    insert_checkpoint_row(&store, &first, first.body.batch_end_seq);
    insert_checkpoint_row(&store, &second, second.body.batch_end_seq);

    // Reopening backfills the checkpoint transparency projections from the
    // now-persisted legacy checkpoint rows. The claim log is already
    // populated, so the (unaffected) validate branch runs, not the guarded
    // empty-projection repair branch.
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(
        load_checkpoint_tree_head_rows(&store),
        vec![
            (1, 1, first.body.tree_size as u64, None),
            (
                2,
                2,
                second.body.tree_size as u64,
                second.body.previous_checkpoint_sha256.clone(),
            ),
        ]
    );
    assert_eq!(
        load_checkpoint_predecessor_witness_rows(&store),
        vec![(
            1,
            2,
            second.body.previous_checkpoint_sha256.clone().test_unwrap(),
        )]
    );
    let first_publication = build_checkpoint_publication(&first).test_unwrap();
    let second_publication = build_checkpoint_publication(&second).test_unwrap();
    assert_eq!(
        load_checkpoint_publication_metadata_rows(&store),
        vec![
            (
                first_publication.checkpoint_seq,
                first_publication.schema,
                first_publication.merkle_root.to_hex(),
                first_publication.published_at,
                first_publication.kernel_key.to_hex(),
                first_publication.log_tree_size,
                first_publication.entry_start_seq,
                first_publication.entry_end_seq,
                first_publication.previous_checkpoint_sha256,
            ),
            (
                second_publication.checkpoint_seq,
                second_publication.schema,
                second_publication.merkle_root.to_hex(),
                second_publication.published_at,
                second_publication.kernel_key.to_hex(),
                second_publication.log_tree_size,
                second_publication.entry_start_seq,
                second_publication.entry_end_seq,
                second_publication.previous_checkpoint_sha256,
            ),
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn record_checkpoint_publication_trust_anchor_binding_is_idempotent_and_visible_in_export_summary()
{
    let path = unique_db_path("chio-receipts-publication-binding");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let first_receipt = sample_receipt_with_id("publication-binding-first");
    let second_receipt = sample_receipt_with_id("publication-binding-second");
    let first_seq = store
        .append_chio_receipt_returning_seq(&first_receipt)
        .test_unwrap();
    let second_seq = store
        .append_chio_receipt_returning_seq(&second_receipt)
        .test_unwrap();
    let checkpoint_kp = receipt_test_keypair();
    let first = build_checkpoint(
        1,
        first_seq,
        first_seq,
        &canonical_receipt_bytes(&store, first_seq, first_seq),
        &checkpoint_kp,
    )
    .test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        second_seq,
        second_seq,
        &canonical_receipt_bytes(&store, second_seq, second_seq),
        &checkpoint_kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();

    store.store_checkpoint(&first).test_unwrap();
    store.store_checkpoint(&second).test_unwrap();

    let second_publication = build_checkpoint_publication(&second).test_unwrap();
    let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
            chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
            second_publication.log_id.clone(),
        ),
        trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
            chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };

    store
        .record_checkpoint_publication_trust_anchor_binding(second.body.checkpoint_seq, &binding)
        .test_unwrap();
    store
        .record_checkpoint_publication_trust_anchor_binding(second.body.checkpoint_seq, &binding)
        .test_unwrap();

    assert_eq!(
        load_checkpoint_publication_trust_anchor_binding_rows(&store),
        vec![(second.body.checkpoint_seq, binding.clone())]
    );

    let summary = store
        .build_evidence_export_transparency_summary(&[first.clone(), second.clone()])
        .test_unwrap();
    assert!(summary.publications[0].trust_anchor_binding.is_none());
    assert_eq!(
        summary.publications[1].trust_anchor_binding.as_ref(),
        Some(&binding)
    );

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(
        load_checkpoint_publication_trust_anchor_binding_rows(&reopened),
        vec![(second.body.checkpoint_seq, binding.clone())]
    );
    let reopened_summary = reopened
        .build_evidence_export_transparency_summary(&[first.clone(), second.clone()])
        .test_unwrap();
    assert_eq!(
        reopened_summary.publications[1]
            .trust_anchor_binding
            .as_ref(),
        Some(&binding)
    );

    let _ = fs::remove_file(path);
}
