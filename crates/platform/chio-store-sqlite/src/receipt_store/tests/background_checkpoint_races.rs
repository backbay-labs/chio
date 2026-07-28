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
        || {
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
fn archived_peer_checkpoint_winner_is_adopted_after_live_rows_rotate(
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

    let mut connection = store.connection()?;
    let adopted =
        insert_background_checkpoint_guarded(&mut connection, Some(&checkpoint_one), &loser)?;
    assert_eq!(
        adopted, winner,
        "the loser must adopt the archived peer winner"
    );

    drop(connection);
    drop(peer);
    drop(store);
    temp_dir.close()?;
    let _ = fs::remove_file(archive);
    Ok(())
}
