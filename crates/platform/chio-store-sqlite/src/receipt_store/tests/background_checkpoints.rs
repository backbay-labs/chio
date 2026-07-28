use super::super::*;
use super::support::*;

fn signer(keypair: &Keypair, max_batch: u64) -> BackgroundCheckpointSigner {
    BackgroundCheckpointSigner {
        keypair: Arc::new(keypair.clone()),
        max_batch,
    }
}

#[test]
fn checkpoint_signer_survives_supervisor_restart() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-bg-signer-restart")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    store
        .receipt_commit_actor
        .sender
        .try_send(ReceiptCommitCommand::RestartSupervisor)?;

    for i in 0..2 {
        store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
            &format!("rcpt-bg-signer-restart-{i}"),
            i + 1,
            &keypair,
        ))?;
    }
    store.flush_receipt_writes()?;

    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the restarted writer must retain the installed checkpoint signer"
    );
    assert_eq!(
        store
            .receipt_commit_actor
            .worker
            .health()
            .ok_or("missing supervisor health")?
            .snapshot()
            .restart_total,
        1
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// A panic mid checkpoint-build (Merkle build, Ed25519 sign, serde) must not
/// kill the writer thread and must not leave `head.latest_checkpoint` pointing
/// at a half-built checkpoint. Uses the
/// `test_hooks::PANIC_DURING_CHECKPOINT_BUILD` fault hook, which fires after the
/// checkpoint body is computed but before its write transaction opens
/// (`maybe_build_checkpoint`), mirroring the fault-hook pattern used elsewhere
/// in this suite.
///
/// This crate's tests run in parallel and the fault-hook flag is
/// process-global, so this test uses
/// `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH` as its `max_batch`: the
/// hook only fires for a signer using that exact (otherwise unused) batch
/// size, so a concurrently running, unrelated background-checkpoint test
/// cannot be hit by this test's injected panic.
#[test]
fn background_build_panic_is_isolated() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-bg-panic-isolated")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = test_hooks::PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH;
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;

    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(true, std::sync::atomic::Ordering::SeqCst);
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-bg-panic-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    // Flush is the synchronization barrier: the actor attempts the
    // checkpoint build inside the same command iteration as the batch that
    // crosses the threshold, and a Flush enqueued afterwards is only served
    // once that iteration (panic included) finishes.
    store.flush_receipt_writes()?;
    test_hooks::PANIC_DURING_CHECKPOINT_BUILD.store(false, std::sync::atomic::Ordering::SeqCst);

    // last_error records the caught panic; no checkpoint was persisted
    // (head.latest_checkpoint stayed unassigned: the panic fires before the
    // write transaction opens).
    let health = store.receipt_store_health()?;
    let last_error = health.writer.last_error.as_deref().unwrap_or_default();
    assert!(
        last_error.contains("receipt writer job panicked"),
        "expected last_error to record the injected panic, got {last_error:?}"
    );
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "a panic mid-build must not leave a partially built checkpoint"
    );
    // `receipt_store_health` folds `writer.last_error.is_some()` into
    // `healthy` (same as a non-panic checkpoint-build `Err` would), so the
    // caught panic is visible here too: it is NOT swallowed. This is distinct
    // from head poisoning, which is proven below by the recovery append
    // succeeding (a poisoned head fails every subsequent write).
    assert!(
        !health.healthy,
        "a recorded writer error must still surface through receipt_store_health"
    );

    // Teeth: the writer thread survived AND the head was not poisoned. The
    // next append (now with the injected panic off) still succeeds and
    // builds the checkpoint the earlier, panic-interrupted attempt owed;
    // the batch commit that carries it also clears `last_error`.
    let receipt = sample_receipt_with_keypair("rcpt-bg-panic-recovery", max_batch + 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "writer thread must still be alive and able to build checkpoints after the panic"
    );
    let recovered_health = store.receipt_store_health()?;
    assert!(
        recovered_health.healthy,
        "a successful batch after the panic must clear last_error: {recovered_health:?}"
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn maybe_build_checkpoint_builds_one_checkpoint_per_crossed_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-threshold");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 3))?;

    // 7 appends with max_batch 3: exactly two checkpoints (1..=3, 4..=6);
    // entry 7 stays uncheckpointed (partial final batch, ADR-0008).
    for i in 0..7 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    // Flush is the synchronization barrier: the actor builds checkpoints
    // inside the same command iteration as the batch commit, and a Flush
    // enqueued afterwards is only served once that iteration finishes.
    store.flush_receipt_writes()?;

    let first = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;
    let second = store
        .load_checkpoint_by_seq(2)?
        .ok_or("checkpoint 2 missing")?;
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "no third checkpoint yet"
    );
    assert_eq!(
        (first.body.batch_start_seq, first.body.batch_end_seq),
        (1, 3)
    );
    assert_eq!(
        (second.body.batch_start_seq, second.body.batch_end_seq),
        (4, 6)
    );
    // previous_checkpoint_sha256 links to the head's cached predecessor.
    let expected_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&first.body)?;
    assert_eq!(
        second.body.previous_checkpoint_sha256.as_deref(),
        Some(expected_digest.as_str())
    );
    assert!(first.body.previous_checkpoint_sha256.is_none());

    // The full audit surface agrees (chain + projections all valid).
    let status = store.receipt_checkpoint_status(Some(3))?;
    assert!(
        status.healthy,
        "audit after background checkpoints: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(2));
    assert_eq!(status.latest_checkpointed_entry_seq, 6);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn zero_max_batch_disables_background_checkpointing() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-disabled");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 0))?;
    for i in 0..5 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-off-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "batch_size 0 disables checkpoints"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn one_big_batch_crossing_two_thresholds_builds_both_checkpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-multicross");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    // 4 appends may commit as ONE group-commit batch; the while-loop in
    // maybe_build_checkpoint must still emit checkpoints 1..=2 and 3..=4.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-bg-multi-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());
    assert!(store.load_checkpoint_by_seq(2)?.is_some());
    assert!(store.load_checkpoint_by_seq(3)?.is_none());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn background_and_writer_routed_child_appends_share_the_threshold(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-child");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(signer(&keypair, 2))?;
    let receipt = sample_receipt_with_keypair("rcpt-bg-child-0", 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-bg-1", 2, &keypair);
    store.append_child_receipt_record(&child)?; // writer-routed, claim-log row 2
    store.flush_receipt_writes()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("child append must count toward the threshold")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 2)
    );
    let _ = fs::remove_file(path);
    Ok(())
}

/// Idempotent background-checkpoint convergence: two kernels/store instances
/// sharing one receipt DB can each build the same due checkpoint before either
/// head catches up. The loser reaches `insert_checkpoint_incremental_tx` after
/// the winner already committed a byte-identical row. It must be treated as
/// success (like `store_kernel_checkpoint_tx`), not a conflict that records
/// `writer.last_error` and reports the store UNHEALTHY even though the persisted
/// chain is valid.
#[test]
fn identical_background_checkpoint_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-idempotent");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Seed three receipts and build checkpoint 1 (batch 1..=3): the "winner".
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-idem-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let persisted = store
        .load_checkpoint_by_seq(1)?
        .ok_or("winner checkpoint 1 missing")?;

    // The "loser" rebuilds and re-inserts the byte-identical checkpoint 1. A
    // byte-identical re-insert is adopted as success rather than hitting the
    // primary-key conflict.
    {
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_checkpoint_incremental_tx(&tx, None, &persisted)?;
        tx.commit()?;
    }

    // The persisted chain is unchanged and the full audit stays healthy: no
    // duplicate row, checkpoint head caught up at seq 1.
    let status = store.receipt_checkpoint_status(Some(3))?;
    assert!(
        status.healthy,
        "idempotent re-insert must keep the store healthy: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(1));
    assert_eq!(status.latest_checkpointed_entry_seq, 3);
    assert!(
        store.load_checkpoint_by_seq(2)?.is_none(),
        "the idempotent re-insert must not add a second checkpoint row"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Flush-report freshness: when a second handle extends the checkpoint chain
/// out of band and this handle has had no intervening append, a Flush must
/// reflect the CURRENT persisted checkpoint (read from the DB), not the stale
/// writer-head atomics that would overstate the uncheckpointed range.
#[test]
fn flush_report_reflects_externally_extended_checkpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-flush-external-ckpt");
    let keypair = receipt_test_keypair();
    let store_a = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-flush-{i}"), (i + 1) as u64, &keypair);
        store_a.append_chio_receipt_returning_seq(&receipt)?;
    }
    store_a.flush_receipt_writes()?;

    // A stale baseline flush: no checkpoint exists yet.
    let baseline = store_a.flush_receipt_writes()?;
    assert_eq!(baseline.latest_checkpoint_seq, None);
    assert_eq!(baseline.uncheckpointed_end_seq, Some(3));

    // A second handle on the SAME DB extends the checkpoint chain.
    let store_b = SqliteReceiptStore::open_existing(&path)?;
    store_b.create_next_receipt_checkpoint(3, &keypair)?;

    // store_a had no intervening write, so its head atomics are stale. The
    // flush report must still reflect the externally persisted checkpoint.
    let report = store_a.flush_receipt_writes()?;
    assert_eq!(
        report.latest_checkpoint_seq,
        Some(1),
        "flush must reflect the externally extended checkpoint"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 3);
    assert_eq!(report.uncheckpointed_start_seq, None);
    assert_eq!(report.uncheckpointed_end_seq, None);

    let _ = fs::remove_file(path);
    Ok(())
}

/// On a shared receipt DB another writer can commit a due checkpoint AFTER this
/// actor's append pre-check but BEFORE its batch tx. The batch adopts that
/// writer's claim-log rows via the baseline delta yet leaves
/// `head.latest_checkpoint` stale, so building from the stale position would try
/// to rebuild the already-committed checkpoint with THIS actor's own issued_at
/// (clock skew) -> "already exists with different content", recording
/// writer.last_error and reporting the store UNHEALTHY even though the persisted
/// chain is valid (the idempotent-identical guard does not cover this skew
/// case). The background builder must refresh the head against the latest
/// persisted checkpoint before building, ADOPTING the external checkpoint
/// instead of rebuilding it.
#[test]
fn shared_db_background_build_adopts_external_checkpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-bg-adopt-external");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-adopt-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // "Instance B" (another writer on the same file) commits the due checkpoint
    // 1 (batch 1..=3). The store enforces checkpoint-key == receipt-signer-key,
    // so it is signed by the same kernel key but carries a DISTINCT issued_at
    // (the clock-skew case): byte-different from the checkpoint "instance A"
    // would build for the same range.
    let receipt_bytes = canonical_receipt_bytes(&store, 1, max_batch);
    let mut external = build_checkpoint(1, 1, max_batch, &receipt_bytes, &keypair)?;
    external.body.issued_at = external.body.issued_at.saturating_add(1_000);
    let body_bytes = canonical_json_bytes(&external.body).test_unwrap();
    external.signature = keypair.sign(&body_bytes);
    store.store_checkpoint(&external)?;

    // "Instance A" holds a STALE head: its pre-check ran before B committed, so
    // it still believes the chain is empty (latest_checkpoint = None) while its
    // claim-log counters already cover entries 1..=3 (adopted via the baseline
    // delta). Building due checkpoints from this stale head drives the exact
    // production path. (The reader pool is used only as a connection source for
    // this off-thread reproduction; the adoption logic lives in
    // build_due_checkpoints.)
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: max_batch,
        claim_log_max_seq: max_batch,
    };
    let signer_a = signer(&keypair, max_batch);
    let result = build_due_checkpoints(&store.pool, &mut stale_head, &signer_a);
    assert!(
        result.is_ok(),
        "stale-head background build must adopt the external checkpoint, got {result:?}"
    );
    assert_eq!(
        stale_head.checkpoint_seq(),
        1,
        "the head must have adopted the externally committed checkpoint"
    );
    assert!(
        store.load_checkpoint_by_seq(2)?.is_none(),
        "the already-covered range must not be rebuilt into a second checkpoint"
    );
    // The persisted chain is unchanged and audits clean.
    let status = store.receipt_checkpoint_status(Some(max_batch))?;
    assert!(status.healthy, "chain must stay healthy: {status:?}");
    assert_eq!(status.latest_checkpoint_seq, Some(1));

    let _ = fs::remove_file(path);
    Ok(())
}

/// A prior background checkpoint build that failed sets writer.last_error. A
/// later successful build reached via a writer-routed op (a `Write` job crossing
/// the threshold) refreshes the head snapshot but, on the append batch's
/// clearing path being skipped, must also clear last_error so
/// receipt_store_health reflects the recovered state instead of staying
/// unhealthy until the next normal append.
#[test]
fn successful_checkpoint_build_clears_stale_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-bg-clear-stale-error");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-clear-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // A due checkpoint (1..=3) is pending; none built yet.
    assert!(store.load_checkpoint_by_seq(1)?.is_none());

    // Simulate a writer that recorded a PRIOR background-checkpoint failure
    // (e.g. a transient build panic) that set last_error and was never cleared
    // by a subsequent append batch.
    let health = ReceiptCommitWriterHealth::default();
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some("prior background checkpoint build failed".to_string());
    }

    // The recovery build succeeds and must clear the stale error.
    let mut head = VerifiedHead {
        latest_checkpoint: None,
        chain_frontier: None,
        claim_log_count: max_batch,
        claim_log_max_seq: max_batch,
    };
    build_due_checkpoints_and_record(
        &store.pool,
        &mut head,
        &Some(signer(&keypair, max_batch)),
        &health,
    );
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the recovery build must persist checkpoint 1"
    );
    let cleared = health
        .last_error
        .lock()
        .map(|guard| guard.is_none())
        .unwrap_or(false);
    assert!(
        cleared,
        "a successful background build must clear the stale writer error"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// flush_report reads the persisted latest checkpoint's batch_end_seq to reflect
/// an externally extended chain. It must only trust that row if its signed body
/// VERIFIES; a tampered/out-of-band row with an inflated batch_end_seq must not
/// make the report advertise a false checkpointed_entry_seq and hide the
/// uncheckpointed range. A VALID external checkpoint is still reflected.
#[test]
fn flush_report_ignores_unverified_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-flush-ignore-forged-ckpt");
    let keypair = receipt_test_keypair();
    let store_a = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-forge-{i}"), (i + 1) as u64, &keypair);
        store_a.append_chio_receipt_returning_seq(&receipt)?;
    }
    store_a.flush_receipt_writes()?;

    // A VALID external checkpoint (built by a second handle) is still reflected.
    let store_b = SqliteReceiptStore::open_existing(&path)?;
    store_b.create_next_receipt_checkpoint(3, &keypair)?;
    let good = store_a.flush_receipt_writes()?;
    assert_eq!(good.latest_checkpoint_seq, Some(1));
    assert_eq!(good.latest_checkpointed_entry_seq, 3);

    // Forge the latest checkpoint row: inflate the batch_end_seq COLUMN while
    // leaving the signed body untouched, so the column no longer matches the
    // signed body (same tamper mechanics as the verified_head fixtures).
    let connection = store_a.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET batch_end_seq = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![9_999_i64],
    )?;
    drop(connection);

    // flush_report must NOT trust the forged, unverified row: it falls back to
    // the actor's verified head (which never saw a checkpoint), so the bogus
    // inflated batch_end_seq is not reported and the uncheckpointed range is
    // restored.
    let report = store_a.flush_receipt_writes()?;
    assert_ne!(
        report.latest_checkpointed_entry_seq, 9_999,
        "a forged checkpoint row must not be reported as checkpointed progress"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_end_seq, Some(3));

    let _ = fs::remove_file(path);
    Ok(())
}

/// `flush_report` trusts the persisted latest checkpoint's `batch_end_seq` after
/// `parse_persisted_checkpoint_row`, which validates only ONE row's
/// columns/body/signature. A latest checkpoint that is individually well-formed
/// but DISCONNECTED from the chain (skipped `checkpoint_seq` or wrong
/// predecessor) must NOT be reported as checkpointed progress; the report must
/// fall back to the last chain-connected checkpoint. A properly chain-connected
/// latest IS reported. The predecessor check stays bounded O(1) on the health
/// surface, never walking full history.
#[test]
fn flush_report_rejects_disconnected_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = receipt_test_keypair();

    // CONNECTED (accepted): a properly chain-connected latest checkpoint (cp2
    // linked to cp1) has its batch_end_seq reported.
    let good_path = unique_db_path("chio-flush-connected-ckpt");
    let good_store = SqliteReceiptStore::open(&good_path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-conn-{i}"), (i + 1) as u64, &keypair);
        good_store.append_chio_receipt_returning_seq(&receipt)?;
    }
    good_store.flush_receipt_writes()?;
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp1 (1..=3)
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp2 (4..=6), chain-connected
    let good = good_store.flush_receipt_writes()?;
    assert_eq!(good.latest_checkpoint_seq, Some(2));
    assert_eq!(good.latest_checkpointed_entry_seq, 6);
    assert_eq!(good.uncheckpointed_end_seq, None);
    let _ = fs::remove_file(good_path);

    // DISCONNECTED (rejected): cp1 (1..=3) is chain-connected and adopted by the
    // actor head; then a latest cp2 (4..=6) is persisted OUT OF BAND whose signed
    // `previous_checkpoint_sha256` does NOT match cp1 (re-signed after mutation),
    // so it parses individually yet is disconnected. Its inflated batch_end_seq
    // must not be reported; the report falls back to the last chain-connected
    // checkpoint (cp1, batch_end 3).
    let bad_path = unique_db_path("chio-flush-disconnected-ckpt");
    let bad_store = SqliteReceiptStore::open(&bad_path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-disc-{i}"), (i + 1) as u64, &keypair);
        bad_store.append_chio_receipt_returning_seq(&receipt)?;
    }
    bad_store.flush_receipt_writes()?;
    bad_store.create_next_receipt_checkpoint(3, &keypair)?; // cp1 (1..=3), adopted by the head
    let checkpoint_one = bad_store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;

    let range_bytes = canonical_receipt_bytes(&bad_store, 4, 6);
    let mut disconnected_two = build_checkpoint_with_previous(
        2,
        4,
        6,
        &range_bytes,
        &keypair,
        Some(&checkpoint_one),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(
            &checkpoint_one.body,
        )?],
    )?;
    // Break the predecessor linkage while keeping the row individually valid:
    // point at a digest that is NOT cp1's, then re-sign so the body/signature
    // still verify (same mechanics as the clock-skew re-sign fixtures).
    disconnected_two.body.previous_checkpoint_sha256 = Some("00".repeat(32));
    let body_bytes = canonical_json_bytes(&disconnected_two.body).test_unwrap();
    disconnected_two.signature = keypair.sign(&body_bytes);
    insert_checkpoint_row(
        &bad_store,
        &disconnected_two,
        disconnected_two.body.batch_end_seq,
    );

    let report = bad_store.flush_receipt_writes()?;
    assert_ne!(
        report.latest_checkpointed_entry_seq, 6,
        "a chain-disconnected latest checkpoint must not be reported as checkpointed progress"
    );
    assert_eq!(
        report.latest_checkpointed_entry_seq, 3,
        "the report must fall back to the last chain-connected checkpoint (cp1)"
    );
    assert_eq!(report.latest_checkpoint_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(6));

    let _ = fs::remove_file(bad_path);
    Ok(())
}

/// On a shared DB a separate process can advance `kernel_checkpoints` with a
/// latest row that PARSES (its columns match its signed body) AND is
/// chain-connected as a valid base, yet whose signed batch was built over
/// receipts THIS database never held (an imported/foreign checkpoint).
/// `parse_persisted_checkpoint_row` + `latest_checkpoint_is_chain_connected`
/// alone trust its inflated `batch_end_seq`, making `flush_receipt_writes`
/// advertise a false `checkpointed_entry_seq` and hide the uncheckpointed range.
/// `flush_report` must rebuild the checkpoint's Merkle range from the LOCAL claim
/// log (`validate_checkpoint_against_claim_log`) and drop the row on mismatch,
/// falling back to the actor's verified head. Bounded O(b) over the single
/// latest checkpoint's own batch on the operator/health surface, never
/// re-verifying whole history.
#[test]
fn flush_report_rejects_checkpoint_foreign_to_local_claim_log(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-flush-foreign-claim-log-ckpt");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-foreign-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // Build a base checkpoint (seq 1, batch_start 1) over SIX forged leaves this
    // store's `claim_receipt_log_entries` (only 3 rows) never contained, so it
    // parses and validates as a base but its `merkle_root`/`tree_size` do not
    // match the local claim-log range [1..=6]. Persist it out of band, modelling
    // a shared-DB separate process advancing the chain with foreign contents.
    let foreign_leaves: Vec<Vec<u8>> = (0..6)
        .map(|i| format!("foreign-leaf-{i}").into_bytes())
        .collect();
    let foreign = build_checkpoint(1, 1, 6, &foreign_leaves, &keypair)?;
    assert_eq!(foreign.body.batch_end_seq, 6);
    assert_eq!(foreign.body.tree_size, 6);
    insert_checkpoint_row(&store, &foreign, foreign.body.batch_end_seq);

    let report = store.flush_receipt_writes()?;
    assert_ne!(
        report.latest_checkpointed_entry_seq, 6,
        "a checkpoint foreign to the local claim log must not be reported as checkpointed progress"
    );
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.latest_checkpoint_seq, None);
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(3));

    let _ = fs::remove_file(path);
    Ok(())
}

/// `latest_checkpoint_is_chain_connected` (the `flush_report` filter guarding a
/// trusted `batch_end_seq`) must verify more than that the LATEST checkpoint
/// links to its IMMEDIATE predecessor. An EARLIER checkpoint row missing from the
/// persisted chain (a partial import, an out-of-band delete) leaves the
/// seq-1..seq link intact, so a predecessor-only check would still accept the
/// latest checkpoint even though the prefix is not actually complete, hiding an
/// unattested range from the flush report. The check requires the persisted
/// chain to hold every seq 1..=latest with no gap (one bounded COUNT aggregate
/// over the checkpoint table, no per-checkpoint parse/signature/Merkle work, so
/// it stays bounded and never re-verifies whole history). A DEEPER gap (not the
/// immediate predecessor, which the existing predecessor check already catches)
/// must fail closed.
#[test]
fn chain_connected_rejects_missing_earlier_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-chain-connected-gap");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Four receipts -> four single-entry checkpoints (seq 1..=4).
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-gap-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    for _ in 0..4 {
        store.create_next_receipt_checkpoint(1, &keypair)?;
    }
    let latest = store
        .load_checkpoint_by_seq(4)?
        .ok_or("checkpoint 4 missing")?;

    let connection = store.connection()?;
    // Baseline: an intact 1..=4 chain is chain-connected.
    latest_checkpoint_is_chain_connected(&connection, &latest)?;

    // Delete an EARLIER checkpoint row (seq 2) out of band - NOT the immediate
    // predecessor (seq 3), which stays present so the predecessor-link check
    // alone would still accept seq 4. Disable foreign keys so removing the
    // kernel_checkpoints row does not cascade into (immutable) projection tables;
    // the gap guard only counts kernel_checkpoints rows.
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF; DROP TRIGGER IF EXISTS kernel_checkpoints_reject_delete;",
    )?;
    let deleted = connection.execute(
        "DELETE FROM kernel_checkpoints WHERE checkpoint_seq = 2",
        [],
    )?;
    assert_eq!(deleted, 1, "expected to remove exactly one checkpoint row");

    // The immediate predecessor (seq 3) is still present, so a predecessor-only
    // check would return Ok; the prefix-completeness guard instead fails closed
    // on the missing seq 2.
    let error = latest_checkpoint_is_chain_connected(&connection, &latest)
        .err()
        .ok_or("a chain with a missing earlier checkpoint must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("prefix is incomplete") && message.contains("chio receipt audit"),
                "Conflict must name the incomplete prefix and the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// The OPERATOR/IMPORT checkpoint append (store_checkpoint ->
/// store_kernel_checkpoint_atomic) only parses the LATEST checkpoint as
/// predecessor, so a mid-chain tamper whose latest row still parses would let an
/// operator extend an already-corrupt chain. The operator path must re-verify the
/// full chain and fail closed. (This does NOT touch the background builder, which
/// stays on the incremental head and never walks full history.)
#[test]
fn operator_checkpoint_append_reverifies_chain() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-operator-reverify-chain");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-op-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Two checkpoints: 1 (1..=2), 2 (3..=4).
    store.create_next_receipt_checkpoint(2, &keypair)?;
    store.create_next_receipt_checkpoint(2, &keypair)?;
    // Two more uncheckpointed entries so a VALID checkpoint 3 (5..=6) exists.
    for i in 4..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-op-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let checkpoint_two = store
        .load_checkpoint_by_seq(2)?
        .ok_or("checkpoint 2 must exist")?;
    let range_bytes = canonical_receipt_bytes(&store, 5, 6);
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 must exist")?;
    let checkpoint_three = build_checkpoint_with_previous(
        3,
        5,
        6,
        &range_bytes,
        &keypair,
        Some(&checkpoint_two),
        &[
            chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_one.body)?,
            chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_two.body)?,
        ],
    )?;

    // Tamper an EARLIER checkpoint (seq 1) while the LATEST (seq 2) still parses:
    // mutate checkpoint 1's signed batch_end_seq so it no longer matches its
    // stored column. The incremental predecessor check (which only looks at the
    // latest) would miss this.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":2', '\"batch_end_seq\":1') WHERE checkpoint_seq = 1",
        [],
    )?;
    drop(connection);

    // The operator append must fail closed: the full chain re-verification
    // catches the mid-chain tamper before extending the chain.
    let error = store
        .store_checkpoint(&checkpoint_three)
        .err()
        .ok_or("operator checkpoint append must fail closed on a mid-chain tamper")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "the corrupt chain must not be extended with checkpoint 3"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Two shared-DB builders stamp different wall-clock `issued_at`, so the loser
/// can reach `insert_checkpoint_incremental_tx` AFTER the winner already
/// committed a byte-DIFFERENT (but valid) checkpoint at the same seq (the race
/// window past the head refresh). A byte-identical row is adopted idempotently; a
/// clock-skew winner is likewise ADOPTED (validated BOUNDED: its signature,
/// predecessor linkage, its own claim-log range, and its projections - one
/// checkpoint, not the whole chain) instead of failing the primary-key conflict
/// and reporting the store UNHEALTHY though the persisted chain is valid. A
/// genuinely INVALID same-seq checkpoint still fails closed.
#[test]
fn concurrent_valid_checkpoint_is_adopted_not_conflicted() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-bg-adopt-valid-winner");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-adopt-valid-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // The WINNER: checkpoint 1 (batch 1..=3) persisted through the store.
    store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    let winner = store
        .load_checkpoint_by_seq(1)?
        .ok_or("winner checkpoint 1 missing")?;

    // The LOSER built the SAME range but with a later wall-clock issued_at, so
    // its bytes (and thus signature) differ from the persisted winner.
    let receipt_bytes = canonical_receipt_bytes(&store, 1, max_batch);
    let mut loser = build_checkpoint(1, 1, max_batch, &receipt_bytes, &keypair)?;
    loser.body.issued_at = winner.body.issued_at.saturating_add(1_000);
    let body_bytes = canonical_json_bytes(&loser.body).test_unwrap();
    loser.signature = keypair.sign(&body_bytes);
    assert_ne!(loser.body.issued_at, winner.body.issued_at);
    assert_ne!(loser, winner);

    // The loser inserts: the byte-different but VALID winner is validated and
    // adopted, and the returned checkpoint is the WINNER (so the caller catches
    // its head up to the persisted row, not to its discarded build).
    let adopted = {
        let mut connection = store.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let adopted = insert_checkpoint_incremental_tx(&tx, None, &loser)?;
        tx.commit()?;
        adopted
    };
    assert_eq!(
        adopted, winner,
        "the loser must adopt the persisted winner, not its own clock-skewed build"
    );

    // Health stays healthy; no duplicate row; head sits at seq 1.
    let status = store.receipt_checkpoint_status(Some(max_batch))?;
    assert!(
        status.healthy,
        "adopting a valid clock-skew winner must stay healthy: {status:?}"
    );
    assert_eq!(status.latest_checkpoint_seq, Some(1));
    assert!(
        store.load_checkpoint_by_seq(2)?.is_none(),
        "adoption must not add a second checkpoint row"
    );

    let _ = fs::remove_file(path);

    // Teeth: a GENUINELY INVALID persisted checkpoint at the same seq stays
    // fail-closed even though the incoming checkpoint is valid. Use a fresh DB
    // whose seq-1 slot holds a forged checkpoint (its merkle_root is over
    // unrelated bytes, so it cannot validate against the real claim-log range).
    let bad_path = unique_db_path("chio-bg-adopt-invalid-winner");
    let bad_store = SqliteReceiptStore::open(&bad_path)?;
    for i in 0..max_batch {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-adopt-invalid-{i}"), i + 1, &keypair);
        bad_store.append_chio_receipt_returning_seq(&receipt)?;
    }
    bad_store.flush_receipt_writes()?;
    let bogus_bytes = vec![
        b"bogus-receipt-a".to_vec(),
        b"bogus-receipt-b".to_vec(),
        b"bogus-receipt-c".to_vec(),
    ];
    let forged = build_checkpoint(1, 1, max_batch, &bogus_bytes, &keypair)?;
    assert_ne!(forged.body.merkle_root, winner.body.merkle_root);
    // Insert the forged row directly, bypassing the store's full validation.
    insert_checkpoint_row(&bad_store, &forged, forged.body.batch_end_seq);
    // A VALID loser for the same range arrives and must be rejected because the
    // persisted checkpoint it would adopt does not validate.
    let good_bytes = canonical_receipt_bytes(&bad_store, 1, max_batch);
    let good = build_checkpoint(1, 1, max_batch, &good_bytes, &keypair)?;
    let mut connection = bad_store.connection()?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let error = insert_checkpoint_incremental_tx(&tx, None, &good)
        .err()
        .ok_or("an invalid persisted checkpoint at the same seq must fail closed")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict on an invalid same-seq winner, got {error:?}"
    );
    drop(tx);
    drop(connection);
    let _ = fs::remove_file(bad_path);
    Ok(())
}

/// The frontier cache-miss scan races independently from the latest-row head
/// refresh. Model the precise interleaving where the refresh saw an empty
/// checkpoint chain, a peer then committed checkpoint 1, and the frontier scan
/// sees that winner. The builder must boundedly verify and adopt the winner,
/// reuse the one-leaf frontier, and continue with checkpoint 2 rather than
/// reporting a false head/frontier conflict.
#[test]
fn frontier_rebuild_adopts_concurrent_checkpoint_winner() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-bg-frontier-race")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 2;
    for i in 0..(max_batch * 2) {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-frontier-race-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // This is the loser's cached state immediately after its latest-row
    // refresh: four claim-log entries are known, but no checkpoint or chain
    // frontier was visible yet.
    let connection = store.connection()?;
    let mut stale_head = seed_verified_head(&connection)?;
    assert_eq!(stale_head.checkpoint_seq(), 0);
    assert_eq!(
        stale_head
            .chain_frontier
            .as_ref()
            .map(CheckpointChainFrontier::leaf_count),
        Some(0),
        "startup must retain the verified empty frontier"
    );
    // Model a dropped cache between the refresh and frontier rebuild.
    stale_head.chain_frontier = None;
    assert!(stale_head.chain_frontier.is_none());
    drop(connection);

    // The peer wins checkpoint 1 after that refresh and before the loser's
    // cache-miss frontier scan.
    store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    let winner = store
        .load_checkpoint_by_seq(1)?
        .ok_or("concurrent checkpoint winner missing")?;

    // Enter at the frontier-rebuild stage. It now observes one persisted leaf
    // while the cached head is still at zero. Adoption must succeed, then the
    // second owed batch must extend the adopted winner.
    let mut connection = store.connection()?;
    let advanced = maybe_build_checkpoint(
        &mut connection,
        &mut stale_head,
        &signer(&keypair, max_batch),
    )?;
    assert!(
        advanced,
        "winner adoption and catch-up must report progress"
    );
    assert_eq!(
        stale_head.latest_checkpoint.as_ref(),
        store.load_checkpoint_by_seq(2)?.as_ref(),
        "the cached head must continue through the second owed checkpoint"
    );
    assert_eq!(
        stale_head
            .chain_frontier
            .as_ref()
            .map(CheckpointChainFrontier::leaf_count),
        Some(2),
        "the reused frontier must cover the adopted winner and its successor"
    );
    assert_eq!(
        store.load_checkpoint_by_seq(1)?.as_ref(),
        Some(&winner),
        "catch-up must preserve the concurrently committed winner"
    );
    verify_checkpoint_chain_integrity(&connection)?;

    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// A failed build consumes the cached chain frontier before returning its
/// error. A retry therefore enters the cache-miss path. That path must fully
/// verify predecessor continuity, not merely hash individually valid rows,
/// before a v2 successor commits a legacy v1 prefix.
#[test]
fn frontier_cache_miss_rejects_disconnected_legacy_prefix_after_failed_build(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-bg-frontier-cache-loss")?;
    let keypair = receipt_test_keypair();
    let wrong_keypair = Keypair::from_seed(&[0x43; 32]);
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 2;
    for i in 0..(max_batch * 3) {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-frontier-cache-loss-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let mut checkpoint_one = build_checkpoint(
        1,
        1,
        max_batch,
        &canonical_receipt_bytes(&store, 1, max_batch),
        &keypair,
    )?;
    checkpoint_one.body.schema = chio_kernel::checkpoint::CHECKPOINT_SCHEMA_V1.to_string();
    checkpoint_one.body.chain_root = None;
    checkpoint_one.signature = keypair.sign(&canonical_json_bytes(&checkpoint_one.body)?);
    insert_checkpoint_row(&store, &checkpoint_one, checkpoint_one.body.batch_end_seq);

    let checkpoint_one_leaf =
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint_one.body)?;
    let mut checkpoint_two = build_checkpoint_with_previous(
        2,
        max_batch + 1,
        max_batch * 2,
        &canonical_receipt_bytes(&store, max_batch + 1, max_batch * 2),
        &keypair,
        Some(&checkpoint_one),
        &[checkpoint_one_leaf],
    )?;
    checkpoint_two.body.schema = chio_kernel::checkpoint::CHECKPOINT_SCHEMA_V1.to_string();
    checkpoint_two.body.chain_root = None;
    checkpoint_two.signature = keypair.sign(&canonical_json_bytes(&checkpoint_two.body)?);
    insert_checkpoint_row(&store, &checkpoint_two, checkpoint_two.body.batch_end_seq);

    let mut connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    assert_eq!(head.latest_checkpoint.as_ref(), Some(&checkpoint_two));
    assert_eq!(
        head.chain_frontier
            .as_ref()
            .map(CheckpointChainFrontier::leaf_count),
        Some(2),
        "seeding must retain the fully verified legacy frontier"
    );

    let error = maybe_build_checkpoint(
        &mut connection,
        &mut head,
        &signer(&wrong_keypair, max_batch),
    )
    .err()
    .ok_or("the mismatched signer must fail after consuming the cached frontier")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_))
            && error
                .to_string()
                .contains("does not match receipt signer key"),
        "expected the mismatched signer to fail closed, got {error:?}"
    );
    assert!(
        head.chain_frontier.is_none(),
        "the failed build must exercise the retry's cache-miss path"
    );
    assert!(
        store.load_checkpoint_by_seq(3)?.is_none(),
        "the failed build must not persist its candidate"
    );

    // Replace checkpoint 1 out of band with a separately valid v1 statement.
    // Its earlier timestamp changes its signed body digest without changing
    // the covered receipts. Checkpoint 2 remains byte-for-byte unchanged and
    // therefore still points at the original checkpoint 1.
    let mut replacement = checkpoint_one.clone();
    replacement.body.issued_at = checkpoint_one
        .body
        .issued_at
        .checked_sub(1)
        .ok_or("checkpoint timestamp must permit a distinct predecessor")?;
    replacement.signature = keypair.sign(&canonical_json_bytes(&replacement.body)?);
    chio_kernel::checkpoint::validate_checkpoint(&replacement)?;
    assert!(
        chio_kernel::checkpoint::validate_checkpoint_predecessor(&replacement, &checkpoint_two)
            .is_err(),
        "the retained checkpoint 2 must be disconnected from the replacement"
    );
    let replacement_json = serde_json::to_string(&replacement.body)?;
    let replacement_signature = replacement.signature.to_hex();
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
             SET issued_at = ?1, statement_json = ?2, signature = ?3
             WHERE checkpoint_seq = 1",
            rusqlite::params![
                replacement.body.issued_at as i64,
                replacement_json,
                replacement_signature,
            ],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_tree_heads
             SET issued_at = ?1, statement_json = ?2, signature = ?3
             WHERE checkpoint_seq = 1",
            rusqlite::params![
                replacement.body.issued_at as i64,
                replacement_json,
                replacement_signature,
            ],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_publication_metadata
             SET published_at = ?1
             WHERE checkpoint_seq = 1",
            rusqlite::params![replacement.body.issued_at as i64],
        )?,
        1
    );

    let error = maybe_build_checkpoint(&mut connection, &mut head, &signer(&keypair, max_batch))
        .err()
        .ok_or("a cache-miss retry must reject the disconnected legacy prefix")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_))
            && error
                .to_string()
                .contains("does not match predecessor digest"),
        "expected full predecessor verification to reject the retry, got {error:?}"
    );
    assert!(
        load_persisted_checkpoint_row(&connection, 3)?.is_none(),
        "a disconnected legacy prefix must not gain a v2 successor"
    );

    // Now make the replacement prefix internally coherent by re-linking and
    // re-signing checkpoint 2. The full audit succeeds over this replacement,
    // but its latest checkpoint is not the writer's previously verified head.
    // The cache-miss path must reject that same-length fork rather than combine
    // the replacement frontier with the stale checkpoint 2 predecessor.
    let mut replacement_two = checkpoint_two.clone();
    replacement_two.body.previous_checkpoint_sha256 = Some(
        chio_kernel::checkpoint::checkpoint_body_sha256(&replacement.body)?,
    );
    replacement_two.signature = keypair.sign(&canonical_json_bytes(&replacement_two.body)?);
    chio_kernel::checkpoint::validate_checkpoint_predecessor(&replacement, &replacement_two)?;
    let replacement_two_json = serde_json::to_string(&replacement_two.body)?;
    let replacement_two_signature = replacement_two.signature.to_hex();
    let replacement_predecessor = replacement_two
        .body
        .previous_checkpoint_sha256
        .as_deref()
        .ok_or("replacement checkpoint 2 must retain its predecessor digest")?;
    assert_eq!(
        connection.execute(
            "UPDATE kernel_checkpoints
             SET statement_json = ?1, signature = ?2
             WHERE checkpoint_seq = 2",
            rusqlite::params![replacement_two_json, replacement_two_signature],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_tree_heads
             SET previous_checkpoint_sha256 = ?1, statement_json = ?2, signature = ?3
             WHERE checkpoint_seq = 2",
            rusqlite::params![
                replacement_predecessor,
                replacement_two_json,
                replacement_two_signature,
            ],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_predecessor_witnesses
             SET previous_checkpoint_sha256 = ?1, witness_statement_json = ?2
             WHERE witness_checkpoint_seq = 2",
            rusqlite::params![replacement_predecessor, replacement_two_json],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE checkpoint_publication_metadata
             SET previous_checkpoint_sha256 = ?1
             WHERE checkpoint_seq = 2",
            rusqlite::params![replacement_predecessor],
        )?,
        1
    );

    let error = maybe_build_checkpoint(&mut connection, &mut head, &signer(&keypair, max_batch))
        .err()
        .ok_or("a cache-miss retry must reject a coherent same-length fork")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_))
            && error
                .to_string()
                .contains("diverged from the verified head"),
        "expected same-length head reconciliation to reject the retry, got {error:?}"
    );
    assert!(
        load_persisted_checkpoint_row(&connection, 3)?.is_none(),
        "a coherent replacement prefix must not be joined to the stale head"
    );

    ensure_checkpoint_transparency_guards(&connection)?;
    ensure_transparency_projection_guards(&connection)?;
    drop(connection);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// If the `InstallSigner` handler only STORED the signer, an already-owed
/// checkpoint (the store opened on a DB that already has at least max_batch
/// uncheckpointed claim-log entries, e.g. a crash between the durable append
/// response and the background build, or enabling checkpointing on an existing
/// store) would not be built until some future Append/Write, leaving a quiet
/// restarted store uncheckpointed indefinitely. The handler must run the bounded
/// catch-up builder at install time.
#[test]
fn install_signer_builds_owed_checkpoints() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-install-owed-ckpt");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    // Append >= max_batch receipts with NO signer installed: durable, but no
    // checkpoint is built, so the store carries an owed (uncheckpointed) range.
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-install-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "no checkpoint before the signer is installed"
    );

    // Install the signer. The InstallSigner handler must build the owed
    // checkpoint IMMEDIATELY, not wait for a future append.
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;
    // Flush is only a synchronization barrier here: it makes the InstallSigner
    // command observably processed. It does NOT itself append or build.
    store.flush_receipt_writes()?;

    // No further append happened; the owed checkpoint exists.
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("InstallSigner must build the owed checkpoint at install time")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 3)
    );
    let status = store.receipt_checkpoint_status(Some(max_batch))?;
    assert!(status.healthy, "audit after install-time build: {status:?}");
    assert_eq!(status.latest_checkpoint_seq, Some(1));
    assert_eq!(status.latest_checkpointed_entry_seq, 3);

    let _ = fs::remove_file(path);
    Ok(())
}

/// Install-time catch-up builds owed checkpoints when the signer is installed.
/// But with `incremental_verification = false` the actor seeds via
/// `seed_head_snapshot`, which INTENTIONALLY skips the full claim-log +
/// checkpoint-chain audit (deferred to the next append/verify), so the seeded
/// head is `Verified`-but-UNVALIDATED. Building catch-up checkpoints at install
/// over that range would checkpoint unaudited data (fail-closed violation), so
/// the install-time build must DEFER in this mode: the next append runs the full
/// per-append validation and THEN the owed checkpoints build. The normal verified
/// mode (`install_signer_builds_owed_checkpoints`) still builds at install.
#[test]
fn install_catch_up_respects_deferred_validation() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-install-deferred");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open_with_options(
        &path,
        crate::SqliteStoreOptions {
            incremental_verification: false,
            ..crate::SqliteStoreOptions::default()
        },
    )?;
    let max_batch = 3;
    // Append >= max_batch receipts with NO signer: durable and uncheckpointed,
    // and (deferred-seed mode) not yet covered by the full audit.
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-deferred-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // Install the signer. In deferred-seed mode the head is
    // Verified-but-UNVALIDATED, so the install-time catch-up MUST NOT build over
    // it.
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;
    // Flush is only a synchronization barrier: it makes the InstallSigner
    // command observably processed. It does NOT itself append or build.
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "deferred-seed mode must not checkpoint the unvalidated range at install"
    );

    // It DEFERS, not skips: the next append runs the full per-append validation
    // (non-incremental path) and then builds the now-owed checkpoint.
    let receipt = sample_receipt_with_keypair("rcpt-deferred-tail", max_batch + 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("the deferred catch-up must build once the full validation has run")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 3)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Deterministically co-drain a Flush with a group-commit batch of `n` fresh
/// appends. The writer actor is first occupied by a blocking Write job so every
/// following command queues behind it; then `n` Append commands and one Flush
/// are enqueued IN ORDER directly on the actor channel; then the Write job is
/// released. The actor drains the whole queue in ONE batch iteration, so the
/// Flush lands inside the group-commit coalescing window (co-drained) instead
/// of arriving as a standalone barrier afterward. Returns the flush waiter's
/// result once the actor releases it (AFTER the checkpoint build).
fn co_drain_flush_with_appends(
    store: &SqliteReceiptStore,
    keypair: &Keypair,
    n: u64,
    id_prefix: &str,
) -> Result<Result<(), ReceiptStoreError>, Box<dyn std::error::Error>> {
    let sender = store.receipt_commit_actor.sender.clone();
    let handle = store.writer_handle();
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let job = std::thread::spawn(move || {
        handle.run_write(move |_connection| -> Result<(), ReceiptStoreError> {
            // Signal that the actor is now blocked INSIDE this Write job, then
            // wait to be released so the commands below queue behind us.
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
    });
    started_rx.recv()?;

    let mut append_receivers = Vec::new();
    for i in 0..n {
        let receipt = sample_receipt_with_keypair(&format!("{id_prefix}-{i}"), i + 1, keypair);
        let raw_json = serde_json::to_string(&receipt)?;
        let (response, receiver) = std::sync::mpsc::sync_channel(1);
        sender
            .try_send(ReceiptCommitCommand::Append(Box::new(
                ReceiptCommitRequest {
                    receipt,
                    raw_json,
                    ensure_lineage: false,
                    response,
                },
            )))
            .map_err(|_| "failed to enqueue append")?;
        append_receivers.push(receiver);
    }
    let (flush_response, flush_receiver) = std::sync::mpsc::sync_channel(1);
    sender
        .try_send(ReceiptCommitCommand::Flush(flush_response))
        .map_err(|_| "failed to enqueue flush")?;

    // Release the Write job: the actor now drains [Append x n, Flush] as one
    // batch, building owed checkpoints BEFORE releasing the flush waiter.
    release_tx.send(())?;
    job.join().map_err(|_| "write job thread panicked")??;

    let flush_result = flush_receiver.recv()?;
    // Keep the append receivers alive until the flush returns.
    drop(append_receivers);
    Ok(flush_result)
}

/// A Flush co-drained with a group-commit batch must not be answered by
/// `commit_receipt_batch` BEFORE the checkpoint build step runs, or a
/// flush-as-barrier caller could observe a missing checkpoint / stale
/// uncheckpointed range. The co-drained Flush waiters are released only AFTER
/// `build_due_checkpoints` has run for that batch, and a build failure surfaces
/// to the flush caller as an error. Append durability responses still fan out
/// before the build (ADR-0013).
#[test]
fn flush_is_a_checkpoint_barrier() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = receipt_test_keypair();

    // Barrier: an append batch crosses the checkpoint threshold and a Flush is
    // co-drained with it. When flush_receipt_writes()'s waiter returns, the due
    // checkpoint MUST already exist.
    let path = unique_db_path("chio-flush-barrier");
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;
    store.flush_receipt_writes()?; // sync InstallSigner (no receipts yet, no build)

    let flush_result = co_drain_flush_with_appends(&store, &keypair, max_batch, "rcpt-barrier")?;
    assert!(
        flush_result.is_ok(),
        "the co-drained flush must succeed: {flush_result:?}"
    );
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "flush must not return until the co-drained batch's checkpoint is built"
    );
    let _ = fs::remove_file(path);

    // Teeth: a checkpoint-build FAILURE for the co-drained batch surfaces to the
    // flush caller as an Err (not a silent Ok). Uses the distinct
    // FAIL_CHECKPOINT_BUILD hook (marker max_batch) so the process-global flag
    // cannot interfere with the panic-isolation test.
    let fail_path = unique_db_path("chio-flush-barrier-fail");
    let fail_store = SqliteReceiptStore::open(&fail_path)?;
    let fail_batch = test_hooks::FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH;
    fail_store.enable_background_checkpoints(signer(&keypair, fail_batch))?;
    fail_store.flush_receipt_writes()?;

    test_hooks::FAIL_CHECKPOINT_BUILD.store(true, std::sync::atomic::Ordering::SeqCst);
    let flush_result =
        co_drain_flush_with_appends(&fail_store, &keypair, fail_batch, "rcpt-barrier-fail")?;
    test_hooks::FAIL_CHECKPOINT_BUILD.store(false, std::sync::atomic::Ordering::SeqCst);

    let error = flush_result
        .err()
        .ok_or("a checkpoint-build failure must surface to the flush caller")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "flush must receive the build error, got {error:?}"
    );
    assert!(
        fail_store.load_checkpoint_by_seq(1)?.is_none(),
        "the failed build must not persist a checkpoint"
    );
    let _ = fs::remove_file(fail_path);

    Ok(())
}

/// When the background signer is installed while the writer head is POISONED, the
/// InstallSigner install-time catch-up is skipped (it only builds for a Verified
/// head). After the operator repairs the database and the reseed succeeds, the
/// owed checkpoints must be built: the reseed just full-verified the head, so the
/// SAME bounded catch-up used by InstallSigner runs here (O(b) per owed
/// checkpoint, a recovery path rather than the steady-state bounded per-append
/// cost). Otherwise a quiet reseeded store with owed uncheckpointed entries stays
/// uncheckpointed until some future write.
#[test]
fn reseed_builds_owed_checkpoints_after_repair() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reseed-owed-ckpt");
    let keypair = receipt_test_keypair();
    let max_batch = 3;
    let store = SqliteReceiptStore::open(&path)?;

    // Seed >= max_batch uncheckpointed entries with NO signer: owed but unbuilt.
    let mut first_id = String::new();
    for i in 0..max_batch {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-reseed-owed-{i}"), i + 1, &keypair);
        if i == 0 {
            first_id = receipt.id.clone();
        }
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "no checkpoint before a signer is installed"
    );

    // Corrupt a claim-log projection row and capture the original bytes so the
    // repair below can restore an exactly-valid log.
    let original_raw_json = {
        let connection = store.connection()?;
        connection
            .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;")?;
        let original: String = connection.query_row(
            "SELECT raw_json FROM claim_receipt_log_entries WHERE receipt_id = ?1 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![first_id],
            |row| row.get(0),
        )?;
        let mut tampered: ChioReceipt = serde_json::from_str(&original)?;
        tampered.tool_name = "tampered".to_string();
        let tampered_json = serde_json::to_string(&tampered)?;
        connection.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![tampered_json, first_id],
        )?;
        original
    };

    // A reseed over the corrupt log fails closed and POISONS the head.
    assert!(
        store.reseed_verified_head().is_err(),
        "a reseed over a corrupt log must fail closed"
    );

    // Install the signer while the head is POISONED: the install-time catch-up is
    // skipped (it only builds for a Verified head), so no checkpoint is built.
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;
    // Barrier: the Flush queues behind (and is processed after) the InstallSigner,
    // so once it returns the signer is observably installed. It may itself return
    // the stale poisoned error, which is irrelevant here.
    let _ = store.flush_receipt_writes();
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "no checkpoint may be built while the head is poisoned"
    );

    // Repair the database out of band, restoring the original bytes.
    {
        let connection = store.connection()?;
        connection
            .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;")?;
        connection.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![original_raw_json, first_id],
        )?;
    }

    // Reseed now succeeds (full verify) and builds the owed checkpoint WITHOUT
    // any further append.
    store.reseed_verified_head()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("reseed must build the owed checkpoint without a further append")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 3)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// A background checkpoint build that previously failed set `writer.last_error`.
/// A later manual recovery via `create_next_receipt_checkpoint` creates/adopts
/// the missing checkpoint so there is no due work left; the follow-up
/// `build_due_checkpoints_and_record` then returns `Ok(false)` and would leave
/// the stale error in place, so `receipt_store_health` keeps reporting the store
/// UNHEALTHY after the repair. The recovery must clear the stale error when the
/// checkpoint chain actually advanced. A real later failure re-sets it.
#[test]
fn manual_recovery_clears_stale_checkpoint_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-manual-recovery-clear-error");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let max_batch = 3;
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-recover-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "a due checkpoint (1..=3) is pending but unbuilt (no signer installed)"
    );

    // Simulate a PRIOR background-checkpoint build failure that set the actor's
    // last_error and was never cleared (same precondition as the
    // successful_checkpoint_build_clears_stale_error fixture, exercised through
    // the real writer-routed recovery path here).
    if let Ok(mut last_error) = store.receipt_commit_actor.health.last_error.lock() {
        *last_error = Some("prior background checkpoint build failed".to_string());
    }
    let unhealthy = store.receipt_store_health()?;
    assert!(
        !unhealthy.healthy && unhealthy.writer.last_error.is_some(),
        "a recorded background-build error must report the store unhealthy: {unhealthy:?}"
    );

    // Manual recovery: create the missing checkpoint. The Write resync adopts it
    // (advancing the head's checkpoint seq), so the follow-up due-check finds
    // nothing to build and returns Ok(false); the stale error must still clear.
    store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the manual recovery must persist the missing checkpoint"
    );
    let recovered = store.receipt_store_health()?;
    assert!(
        recovered.writer.last_error.is_none(),
        "a successful manual recovery must clear the stale checkpoint error: {recovered:?}"
    );
    assert!(
        recovered.healthy,
        "the store must report healthy after recovery: {recovered:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// On a non-incremental (suspect) store the head is seeded UNVALIDATED
/// (`seed_head_snapshot`), and the InstallSigner defer already skips the
/// install-time catch-up. If the Write resync path then called
/// `build_due_checkpoints_and_record` UNCONDITIONALLY after every successful
/// Write, including a metadata-only `run_write` that never ran the full claim-log
/// validation, then on a store with already-due uncheckpointed entries that
/// metadata write would checkpoint unaudited claim-log rows before the deferred
/// full validation ever runs. The build must be gated on a full-verified head
/// (incremental mode OR a receipt-appending job that just ran the full
/// validation), fail-closed. A receipt-appending write still builds.
#[test]
fn metadata_write_does_not_checkpoint_unvalidated_data() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-metadata-defer-build");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open_with_options(
        &path,
        crate::SqliteStoreOptions {
            incremental_verification: false,
            ..crate::SqliteStoreOptions::default()
        },
    )?;
    let max_batch = 3;
    // Append >= max_batch receipts with NO signer: durable, uncheckpointed, and
    // (deferred-seed mode) not yet covered by the full audit.
    for i in 0..max_batch {
        let receipt = sample_receipt_with_keypair(&format!("rcpt-meta-defer-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // Install the signer: deferred-seed mode skips the install-time catch-up, so
    // no checkpoint yet.
    store.enable_background_checkpoints(signer(&keypair, max_batch))?;
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "deferred-seed mode must not checkpoint at install"
    );

    // A metadata-only writer-routed write (`run_write`, appends_receipts = false)
    // must NOT trigger the catch-up build over the still-unvalidated range.
    store
        .writer_handle()
        .run_write(move |_connection| -> Result<(), ReceiptStoreError> { Ok(()) })?;
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_none(),
        "a metadata-only write must not checkpoint the unvalidated range (fail-closed)"
    );

    // It DEFERS, not skips: a receipt-appending write reruns the full claim-log
    // validation, so the now-validated owed checkpoint builds.
    let receipt = sample_receipt_with_keypair("rcpt-meta-defer-tail", max_batch + 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let checkpoint = store
        .load_checkpoint_by_seq(1)?
        .ok_or("a receipt-appending write after full validation must build the owed checkpoint")?;
    assert_eq!(
        (
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ),
        (1, 3)
    );

    let _ = fs::remove_file(path);
    Ok(())
}
