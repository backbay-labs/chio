use super::*;

fn replace_base_checkpoint(
    connection: &Connection,
    replacement: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    let statement_json = serde_json::to_string(&replacement.body)?;
    let signature = replacement.signature.to_hex();
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;
        "#,
    )?;
    connection.execute(
        "UPDATE kernel_checkpoints
         SET batch_start_seq = ?1, batch_end_seq = ?2, tree_size = ?3,
             merkle_root = ?4, issued_at = ?5, statement_json = ?6,
             signature = ?7, kernel_key = ?8
         WHERE checkpoint_seq = 1",
        rusqlite::params![
            replacement.body.batch_start_seq as i64,
            replacement.body.batch_end_seq as i64,
            replacement.body.tree_size as i64,
            replacement.body.merkle_root.to_hex(),
            replacement.body.issued_at as i64,
            statement_json,
            signature,
            replacement.body.kernel_key.to_hex(),
        ],
    )?;
    connection.execute(
        "UPDATE checkpoint_tree_heads
         SET batch_start_seq = ?1, batch_end_seq = ?2, tree_size = ?3,
             merkle_root = ?4, issued_at = ?5, kernel_key = ?6,
             previous_checkpoint_sha256 = NULL, statement_json = ?7,
             signature = ?8
         WHERE checkpoint_seq = 1",
        rusqlite::params![
            replacement.body.batch_start_seq as i64,
            replacement.body.batch_end_seq as i64,
            replacement.body.tree_size as i64,
            replacement.body.merkle_root.to_hex(),
            replacement.body.issued_at as i64,
            replacement.body.kernel_key.to_hex(),
            statement_json,
            signature,
        ],
    )?;
    connection.execute(
        "UPDATE checkpoint_publication_metadata
         SET merkle_root = ?1, published_at = ?2, kernel_key = ?3,
             log_tree_size = ?4, entry_start_seq = ?5, entry_end_seq = ?6,
             previous_checkpoint_sha256 = NULL
         WHERE checkpoint_seq = 1",
        rusqlite::params![
            replacement.body.merkle_root.to_hex(),
            replacement.body.issued_at as i64,
            replacement.body.kernel_key.to_hex(),
            replacement.body.batch_end_seq as i64,
            replacement.body.batch_start_seq as i64,
            replacement.body.batch_end_seq as i64,
        ],
    )?;
    ensure_checkpoint_transparency_guards(connection)?;
    ensure_transparency_projection_guards(connection)
}

#[test]
fn rejected_checkpoint_commits_restored_guards_but_not_candidate(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-guard-savepoint")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..4u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("guard-savepoint-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let checkpoint_two = build_checkpoint_with_previous(
        2,
        3,
        4,
        &canonical_receipt_bytes(&store, 3, 4),
        &keypair,
        Some(&checkpoint_one),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
            &checkpoint_one.body,
        )?],
    )?;

    let connection = store.connection()?;
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;
        "#,
    )?;
    drop(connection);

    let error = store
        .store_checkpoint(&checkpoint_two)
        .err()
        .ok_or("missing projection must reject checkpoint 2")?;
    assert!(
        error.to_string().contains("projection") && error.to_string().contains("missing"),
        "unexpected checkpoint rejection: {error}"
    );

    // Read sqlite_master directly. Calling a store API here could restore a
    // missing checkpoint guard and mask a rollback bug.
    let connection = store.connection()?;
    for trigger in [
        "kernel_checkpoints_reject_update",
        "checkpoint_tree_heads_reject_update",
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            rusqlite::params![trigger],
            |row| row.get(0),
        )?;
        assert!(present, "{trigger} must survive candidate rejection");
    }
    let checkpoint_two_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM kernel_checkpoints WHERE checkpoint_seq = 2",
        [],
        |row| row.get(0),
    )?;
    let projection_two_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM checkpoint_tree_heads WHERE checkpoint_seq = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        (checkpoint_two_count, projection_two_count),
        (0, 0),
        "the inner savepoint must roll back the rejected candidate"
    );
    let checkpoint_update = connection
        .execute(
            "UPDATE kernel_checkpoints SET issued_at = issued_at WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("checkpoint immutability guard must block UPDATE")?;
    assert!(checkpoint_update
        .to_string()
        .contains("kernel checkpoints are immutable"));
    let projection_update = connection
        .execute(
            "UPDATE checkpoint_tree_heads SET issued_at = issued_at WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("projection immutability guard must block UPDATE")?;
    assert!(projection_update
        .to_string()
        .contains("checkpoint tree heads are immutable"));

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn panicked_checkpoint_commits_restored_guards_but_not_candidate(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-guard-panic")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = test_hooks::PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH;
    for i in 0..(max_batch * 2) {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("guard-panic-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;

    let mut connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    head.chain_frontier = None;
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;
        "#,
    )?;

    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(true, std::sync::atomic::Ordering::SeqCst);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_checkpoint_after_frontier_cache_miss(
            &mut connection,
            &mut head,
            &signer(&keypair, max_batch),
        )
    }));
    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(false, std::sync::atomic::Ordering::SeqCst);
    let panic_payload = panic
        .err()
        .ok_or("the injected checkpoint panic must resume")?;
    let panic_message = panic_payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
        .ok_or("checkpoint panic payload must be a string")?;
    assert_eq!(
        panic_message, "injected test panic during background checkpoint build",
        "the wrapper must resume the original panic payload"
    );
    assert_eq!(
        head.latest_checkpoint.as_ref(),
        Some(&checkpoint_one),
        "a panicked candidate must not publish a new verified head"
    );
    assert!(
        head.chain_frontier.is_none(),
        "a panicked cache-miss build must preserve the live frontier"
    );

    // Inspect the database directly so a store API cannot recreate a missing
    // guard and hide a rollback bug.
    for trigger in [
        "kernel_checkpoints_reject_update",
        "checkpoint_tree_heads_reject_update",
        "checkpoint_publication_metadata_reject_update",
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            rusqlite::params![trigger],
            |row| row.get(0),
        )?;
        assert!(present, "{trigger} must survive the resumed panic");
    }
    let candidate_rows: (i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM kernel_checkpoints WHERE checkpoint_seq = 2),
             (SELECT COUNT(*) FROM checkpoint_tree_heads WHERE checkpoint_seq = 2)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        candidate_rows,
        (0, 0),
        "the panicked candidate savepoint must roll back"
    );
    let checkpoint_update = connection
        .execute(
            "UPDATE kernel_checkpoints SET issued_at = issued_at WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("checkpoint UPDATE must remain guarded after panic")?;
    assert!(checkpoint_update
        .to_string()
        .contains("kernel checkpoints are immutable"));
    let tree_update = connection
        .execute(
            "UPDATE checkpoint_tree_heads SET issued_at = issued_at WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("tree-head UPDATE must remain guarded after panic")?;
    assert!(tree_update
        .to_string()
        .contains("checkpoint tree heads are immutable"));
    let publication_update = connection
        .execute(
            "UPDATE checkpoint_publication_metadata
             SET published_at = published_at
             WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("publication UPDATE must remain guarded after panic")?;
    assert!(publication_update
        .to_string()
        .contains("checkpoint publication metadata is immutable"));

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn panicked_savepoint_write_rolls_back_candidate_and_resumes_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    const PANIC_MARKER: &str = "checkpoint candidate write panic marker";

    let (temp_dir, path) = temp_db("chio-checkpoint-savepoint-write-panic")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..4u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("savepoint-write-panic-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let checkpoint_two = build_checkpoint_with_previous(
        2,
        3,
        4,
        &canonical_receipt_bytes(&store, 3, 4),
        &keypair,
        Some(&checkpoint_one),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
            &checkpoint_one.body,
        )?],
    )?;

    let mut connection = store.connection()?;
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;
        "#,
    )?;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        checkpoint_guarded_immediate::<()>(&mut connection, |tx| {
            let inserted =
                insert_checkpoint_incremental_tx(tx, Some(&checkpoint_one), &checkpoint_two)?;
            if inserted != checkpoint_two {
                return Err(ReceiptStoreError::Conflict(
                    "candidate insert did not persist the expected checkpoint".to_string(),
                ));
            }
            std::panic::panic_any(PANIC_MARKER);
        })
    }));
    let panic_payload = panic
        .err()
        .ok_or("the post-insert savepoint panic must resume")?;
    assert_eq!(
        panic_payload.downcast_ref::<&str>().copied(),
        Some(PANIC_MARKER),
        "the wrapper must resume the original post-write panic payload"
    );

    let candidate_rows: (i64, i64, i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM kernel_checkpoints WHERE checkpoint_seq = 2),
             (SELECT COUNT(*) FROM checkpoint_tree_heads WHERE checkpoint_seq = 2),
             (SELECT COUNT(*) FROM checkpoint_predecessor_witnesses
              WHERE witness_checkpoint_seq = 2),
             (SELECT COUNT(*) FROM checkpoint_publication_metadata
              WHERE checkpoint_seq = 2)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        candidate_rows,
        (0, 0, 0, 0),
        "every candidate write must roll back with the panicked savepoint"
    );
    for trigger in [
        "kernel_checkpoints_reject_update",
        "checkpoint_tree_heads_reject_update",
        "checkpoint_publication_metadata_reject_update",
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            rusqlite::params![trigger],
            |row| row.get(0),
        )?;
        assert!(present, "{trigger} must survive the post-write panic");
    }
    let checkpoint_update = connection
        .execute(
            "UPDATE kernel_checkpoints SET issued_at = issued_at WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("checkpoint UPDATE must remain guarded after post-write panic")?;
    assert!(checkpoint_update
        .to_string()
        .contains("kernel checkpoints are immutable"));

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn cache_miss_holds_insert_lock_across_interior_projection_audit(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-cache-miss-interior")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..6u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("cache-miss-interior-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    let mut connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    head.chain_frontier = None;

    // Remove the interior projection guard before the cache-miss operation.
    // The outer transaction restores it, but that DDL is not visible to this
    // peer until commit. If the write lock did not span audit through insert,
    // the peer's exact mid-operation UPDATE would commit in the old gap.
    let peer = store.connection()?;
    peer.busy_timeout(Duration::ZERO)?;
    peer.execute_batch("DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;")?;
    let mut peer_blocked = false;
    let (frontier, advanced) = build_checkpoint_after_frontier_cache_miss_with_hook(
        &mut connection,
        &mut head,
        &signer(&keypair, 2),
        |_| {
            let error = peer
                .execute(
                    "UPDATE checkpoint_publication_metadata
                     SET published_at = published_at + 1
                     WHERE checkpoint_seq = 1",
                    [],
                )
                .err()
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "peer mutated an audited projection before checkpoint insert".to_string(),
                    )
                })?;
            match error {
                rusqlite::Error::SqliteFailure(sqlite_error, _)
                    if matches!(
                        sqlite_error.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    peer_blocked = true;
                    Ok(())
                }
                other => Err(ReceiptStoreError::Conflict(format!(
                    "unexpected peer write result during cache-miss audit: {other}"
                ))),
            }
        },
    )?;
    assert!(peer_blocked, "the peer write attempt must reach SQLite");
    assert!(advanced, "the owed checkpoint must commit");
    assert_eq!(frontier.leaf_count(), 3);
    assert_eq!(head.checkpoint_seq(), 3);
    assert!(
        load_persisted_checkpoint_row(&connection, 3)?.is_some(),
        "checkpoint 3 must persist after the locked audit"
    );
    verify_checkpoint_chain_integrity(&connection)?;

    let post_commit_error = peer
        .execute(
            "UPDATE checkpoint_publication_metadata
             SET published_at = published_at + 1
             WHERE checkpoint_seq = 1",
            [],
        )
        .err()
        .ok_or("restored projection guard must reject UPDATE after commit")?;
    assert!(
        post_commit_error
            .to_string()
            .contains("checkpoint publication metadata is immutable"),
        "unexpected post-commit projection update result: {post_commit_error}"
    );

    drop(peer);
    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn cache_miss_uses_locked_legacy_replacement_frontier_when_no_build_is_due(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-cache-miss-legacy")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..2u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("cache-miss-legacy-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;

    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    drop(connection);
    let mut checkpoint_a =
        build_checkpoint(1, 1, 1, &canonical_receipt_bytes(&store, 1, 1), &keypair)?;
    checkpoint_a.body.schema = chio_kernel::checkpoint::CHECKPOINT_SCHEMA_V1.to_string();
    checkpoint_a.body.chain_root = None;
    checkpoint_a.signature = keypair.sign(&canonical_json_bytes(&checkpoint_a.body)?);
    insert_checkpoint_row(&store, &checkpoint_a, checkpoint_a.body.batch_end_seq);

    let mut connection = store.connection()?;
    let stale_frontier = rebuild_checkpoint_frontier(&mut connection, None)?;
    let mut checkpoint_b =
        build_checkpoint(1, 1, 2, &canonical_receipt_bytes(&store, 1, 2), &keypair)?;
    checkpoint_b.body.schema = chio_kernel::checkpoint::CHECKPOINT_SCHEMA_V1.to_string();
    checkpoint_b.body.chain_root = None;
    checkpoint_b.signature = keypair.sign(&canonical_json_bytes(&checkpoint_b.body)?);
    assert_ne!(
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_a.body)?,
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_b.body)?,
        "the replacement must change a chain-leaf-bound field"
    );
    replace_base_checkpoint(&connection, &checkpoint_b)?;
    assert_eq!(
        verify_checkpoint_chain_integrity(&connection)?.as_ref(),
        Some(&checkpoint_b)
    );

    head.chain_frontier = None;
    let advanced = maybe_build_checkpoint(&mut connection, &mut head, &signer(&keypair, 1))?;
    assert!(advanced, "the locked audit must adopt checkpoint B");
    assert_eq!(head.latest_checkpoint.as_ref(), Some(&checkpoint_b));
    let adopted_frontier = head
        .chain_frontier
        .as_ref()
        .ok_or("adopted legacy frontier missing")?;
    assert_ne!(
        adopted_frontier.root(),
        stale_frontier.root(),
        "the stale A frontier must not overwrite the caught-up B frontier"
    );
    let expected_frontier = CheckpointChainFrontier::from_leaves(&[
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_b.body)?,
    ]);
    assert_eq!(adopted_frontier.root(), expected_frontier.root());
    assert!(
        load_persisted_checkpoint_row(&connection, 2)?.is_none(),
        "checkpoint B covers every receipt, so no successor is due"
    );

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn cache_hit_adopts_valid_different_batch_winner_frontier() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-checkpoint-different-batch-hit")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..5u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("different-batch-hit-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let chain_leaves = [chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
        &checkpoint_one.body,
    )?];
    let prior_frontier = CheckpointChainFrontier::from_leaves(&chain_leaves);
    let loser = build_checkpoint_with_previous(
        2,
        3,
        4,
        &canonical_receipt_bytes(&store, 3, 4),
        &keypair,
        Some(&checkpoint_one),
        &chain_leaves,
    )?;
    let winner = build_checkpoint_with_previous(
        2,
        3,
        5,
        &canonical_receipt_bytes(&store, 3, 5),
        &keypair,
        Some(&checkpoint_one),
        &chain_leaves,
    )?;
    assert_ne!(
        loser.body.chain_root, winner.body.chain_root,
        "different valid batch lengths must produce different chain roots"
    );
    store.store_checkpoint(&winner)?;

    let mut connection = store.connection()?;
    let (adopted, adopted_frontier) = insert_background_checkpoint_guarded(
        &mut connection,
        Some(&checkpoint_one),
        &prior_frontier,
        &loser,
    )?;
    assert_eq!(adopted, winner);
    assert_eq!(adopted_frontier.root(), winner.body.chain_root);
    assert_ne!(adopted_frontier.root(), loser.body.chain_root);
    assert_eq!(
        parse_persisted_checkpoint_row(
            load_persisted_checkpoint_row(&connection, 2)?
                .ok_or("persisted checkpoint 2 missing")?,
        )?,
        winner
    );
    assert!(load_persisted_checkpoint_row(&connection, 3)?.is_none());
    verify_checkpoint_chain_integrity(&connection)?;

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn cache_miss_adopts_valid_different_batch_winner_frontier(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-different-batch-miss")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..5u64 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("different-batch-miss-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let chain_leaves = [chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
        &checkpoint_one.body,
    )?];
    let loser = build_checkpoint_with_previous(
        2,
        3,
        4,
        &canonical_receipt_bytes(&store, 3, 4),
        &keypair,
        Some(&checkpoint_one),
        &chain_leaves,
    )?;
    let winner = build_checkpoint_with_previous(
        2,
        3,
        5,
        &canonical_receipt_bytes(&store, 3, 5),
        &keypair,
        Some(&checkpoint_one),
        &chain_leaves,
    )?;
    assert_ne!(loser.body.chain_root, winner.body.chain_root);

    let mut connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    head.chain_frontier = None;
    let (frontier, advanced) = build_checkpoint_after_frontier_cache_miss_with_hook(
        &mut connection,
        &mut head,
        &signer(&keypair, 2),
        |tx| {
            let inserted = insert_checkpoint_incremental_tx(tx, Some(&checkpoint_one), &winner)?;
            if inserted != winner {
                return Err(ReceiptStoreError::Conflict(
                    "different-batch winner injection diverged".to_string(),
                ));
            }
            Ok(())
        },
    )?;
    assert!(advanced);
    assert_eq!(frontier.leaf_count(), 2);
    assert_eq!(frontier.root(), winner.body.chain_root);
    assert_ne!(frontier.root(), loser.body.chain_root);
    assert_eq!(head.latest_checkpoint.as_ref(), Some(&winner));
    assert_eq!(head.chain_frontier.as_ref(), Some(&frontier));
    assert_eq!(head.checkpointed_entry_seq(), 5);
    assert_eq!(
        parse_persisted_checkpoint_row(
            load_persisted_checkpoint_row(&connection, 2)?
                .ok_or("persisted checkpoint 2 missing")?,
        )?,
        winner
    );
    assert!(load_persisted_checkpoint_row(&connection, 3)?.is_none());
    verify_checkpoint_chain_integrity(&connection)?;

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn archived_peer_checkpoint_winner_is_authenticated_before_adoption(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-checkpoint-archived-winner")?;
    let archive = unique_db_path("chio-checkpoint-archived-winner-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..5u64 {
        let timestamp = if i < 4 { 100 } else { 500 };
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair_and_timestamp(
            &format!("archived-winner-{i}"),
            i + 1,
            timestamp,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let chain_leaves = [chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
        &checkpoint_one.body,
    )?];
    let loser = build_checkpoint_with_previous(
        2,
        3,
        4,
        &canonical_receipt_bytes(&store, 3, 4),
        &keypair,
        Some(&checkpoint_one),
        &chain_leaves,
    )?;
    let mut winner = loser.clone();
    winner.body.issued_at = loser.body.issued_at.saturating_add(1_000);
    winner.signature = keypair.sign(&canonical_json_bytes(&winner.body)?);
    assert_ne!(loser, winner);
    assert_eq!(loser.body.chain_root, winner.body.chain_root);

    let peer = SqliteReceiptStore::open_existing(&path)?;
    peer.store_checkpoint(&winner)?;
    let archived = peer.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the winner's complete prefix must rotate");
    let peer_connection = peer.connection()?;
    assert_eq!(trusted_retention_watermark(&peer_connection)?, 4);
    let live_range: (i64, i64) = peer_connection.query_row(
        "SELECT COUNT(*), COALESCE(MIN(entry_seq), 0)
         FROM claim_receipt_log_entries",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(live_range, (1, 5), "only receipt 5 must remain live");
    drop(peer_connection);

    let prior_frontier = CheckpointChainFrontier::from_leaves(&chain_leaves);
    let mut connection = store.connection()?;
    let (adopted, adopted_frontier) = insert_background_checkpoint_guarded(
        &mut connection,
        Some(&checkpoint_one),
        &prior_frontier,
        &loser,
    )?;
    assert_eq!(
        adopted, winner,
        "the loser must adopt the archived peer winner"
    );
    assert_eq!(adopted_frontier.root(), winner.body.chain_root);

    // Diverge only the live surrogate row id. Checkpoint parsing, receipt
    // signatures, signer binding, and Merkle validation cannot observe this
    // field, so withdrawing trust here specifically proves exact archive-row
    // identity is required.
    let live_winner_row =
        load_persisted_checkpoint_row(&connection, 2)?.ok_or("live winner row missing")?;
    let divergent_id = live_winner_row
        .id
        .checked_add(1_000)
        .ok_or("checkpoint row id overflow")?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    assert_eq!(
        connection.execute(
            "UPDATE kernel_checkpoints SET id = ?1 WHERE checkpoint_seq = 2",
            rusqlite::params![sqlite_i64(divergent_id, "divergent checkpoint id")?],
        )?,
        1
    );
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "an id-only live/archive row mismatch must withdraw trust"
    );
    assert_eq!(
        connection.execute(
            "UPDATE kernel_checkpoints SET id = ?1 WHERE checkpoint_seq = 2",
            rusqlite::params![sqlite_i64(live_winner_row.id, "restored checkpoint id")?],
        )?,
        1
    );
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        4,
        "restoring exact row identity must restore archive trust"
    );

    // Replace the persisted winner and all of its live projections with a
    // checkpoint signed by an attacker. Its range, receipt Merkle root,
    // predecessor link, and chain root remain authentic, so only archived
    // checkpoint identity and receipt-signer binding distinguish it.
    let attacker = Keypair::from_seed(&[0x5d; 32]);
    let mut forged = winner.clone();
    forged.body.kernel_key = attacker.public_key();
    forged.signature = attacker.sign(&canonical_json_bytes(&forged.body)?);
    chio_kernel::checkpoint::validate_checkpoint(&forged)?;
    chio_kernel::checkpoint::validate_checkpoint_predecessor(&checkpoint_one, &forged)?;
    assert_eq!(forged.body.batch_start_seq, winner.body.batch_start_seq);
    assert_eq!(forged.body.batch_end_seq, winner.body.batch_end_seq);
    assert_eq!(forged.body.merkle_root, winner.body.merkle_root);
    assert_eq!(forged.body.chain_root, winner.body.chain_root);
    assert_ne!(forged.body.kernel_key, winner.body.kernel_key);

    let forged_json = serde_json::to_string(&forged.body)?;
    let forged_signature = forged.signature.to_hex();
    let forged_key = forged.body.kernel_key.to_hex();
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_predecessor_witnesses_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;
        "#,
    )?;
    assert_eq!(
        connection.execute(
            "UPDATE kernel_checkpoints
             SET statement_json = ?1, signature = ?2, kernel_key = ?3
             WHERE checkpoint_seq = 2",
            rusqlite::params![&forged_json, &forged_signature, &forged_key],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_tree_heads
             SET kernel_key = ?1, statement_json = ?2, signature = ?3
             WHERE checkpoint_seq = 2",
            rusqlite::params![&forged_key, &forged_json, &forged_signature],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_predecessor_witnesses
             SET witness_statement_json = ?1
             WHERE witness_checkpoint_seq = 2",
            rusqlite::params![&forged_json],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_publication_metadata
             SET kernel_key = ?1
             WHERE checkpoint_seq = 2",
            rusqlite::params![&forged_key],
        )?,
        1
    );
    let live_forged_row =
        load_persisted_checkpoint_row(&connection, 2)?.ok_or("forged checkpoint 2 missing")?;
    assert_eq!(
        parse_persisted_checkpoint_row(live_forged_row.clone())?,
        forged
    );
    validate_checkpoint_projection_rows(&connection, &live_forged_row, &forged)?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "live/archive checkpoint identity mismatch must withdraw trust"
    );

    // Replace the archived checkpoint row too. Exact row identity and the
    // authentic Merkle root now pass, but the untouched archived receipts are
    // still signed by the original key. Full archived claim-log validation
    // must therefore keep the watermark untrusted.
    let archive_connection = rusqlite::Connection::open(&archive)?;
    assert_eq!(
        archive_connection.execute(
            "UPDATE kernel_checkpoints
             SET statement_json = ?1, signature = ?2, kernel_key = ?3
             WHERE checkpoint_seq = 2",
            rusqlite::params![&forged_json, &forged_signature, &forged_key],
        )?,
        1
    );
    let archived_forged_row = load_persisted_checkpoint_row(&archive_connection, 2)?
        .ok_or("archived forged checkpoint 2 missing")?;
    assert_eq!(archived_forged_row, live_forged_row);
    drop(archive_connection);
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "attacker-signed checkpoint must not authenticate original-key archived receipts"
    );

    let error = insert_background_checkpoint_guarded(
        &mut connection,
        Some(&checkpoint_one),
        &prior_frontier,
        &loser,
    )
    .err()
    .ok_or("attacker-signed archived winner must be rejected")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_))
            && error
                .to_string()
                .contains("gap in checkpoint signer binding"),
        "unexpected archived-winner rejection: {error:?}"
    );
    assert_eq!(
        parse_persisted_checkpoint_row(
            load_persisted_checkpoint_row(&connection, 2)?
                .ok_or("persisted forged checkpoint 2 missing after rejection")?,
        )?,
        forged
    );
    for trigger in [
        "kernel_checkpoints_reject_update",
        "checkpoint_tree_heads_reject_update",
        "checkpoint_predecessor_witnesses_reject_update",
        "checkpoint_publication_metadata_reject_update",
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            rusqlite::params![trigger],
            |row| row.get(0),
        )?;
        assert!(present, "{trigger} must be restored after rejection");
    }

    drop(connection);
    drop(peer);
    drop(store);
    temp_dir.close()?;
    let _ = fs::remove_file(archive);
    Ok(())
}
