use super::super::*;
use super::support::*;

fn open_seeded_store(
    prefix: &str,
    receipts: usize,
) -> Result<(std::path::PathBuf, SqliteReceiptStore, Keypair), Box<dyn std::error::Error>> {
    let path = unique_db_path(prefix);
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..receipts {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-head-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    Ok((path, store, keypair))
}

#[test]
fn seed_verified_head_matches_persisted_state() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-seed", 5)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    let connection = store.connection()?;
    let head = seed_verified_head(&connection)?;
    assert_eq!(head.claim_log_count, 5);
    assert_eq!(head.claim_log_max_seq, 5);
    assert_eq!(head.checkpoint_seq(), 1);
    assert_eq!(head.checkpointed_entry_seq(), 3);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn verify_head_accepts_matching_head_and_catches_up_forward(
) -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-accept", 4)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Matching head: one row read + digest compare, Ok.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;

    // A checkpoint created out of band (manual operator path) validly
    // extends the chain: the head catches up instead of false-Conflicting.
    store.create_next_receipt_checkpoint(4, &keypair)?;
    verify_head_against_latest_checkpoint(&connection, &mut head)?;
    assert_eq!(head.checkpoint_seq(), 1);
    assert_eq!(head.checkpointed_entry_seq(), 4);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn verify_head_rejects_tampered_latest_checkpoint_with_conflict(
) -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-tamper", 3)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Tamper the persisted latest checkpoint body out of band (drop the
    // immutability trigger first, exactly like tests/support tamper helpers).
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("tampered checkpoint must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn claim_log_delta_aggregate_is_scoped_to_the_floor() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, _keypair) = open_seeded_store("chio-head-delta", 6)?;
    let connection = store.connection()?;
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 0)?, (6, 6));
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 4)?, (2, 6));
    // Empty range: count 0, max falls back to the floor.
    assert_eq!(claim_log_delta_count_and_max_seq(&connection, 6)?, (0, 6));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn incremental_append_updates_the_head_and_stays_correct() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-head-incremental");
    let store = SqliteReceiptStore::open(&path)?; // default: incremental on
    assert!(store.incremental_verification_enabled());
    let keypair = receipt_test_keypair();
    for i in 0..7 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-inc-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let snapshot = store.writer_head_snapshot();
    assert_eq!(snapshot.claim_log_count, 7);
    assert_eq!(snapshot.claim_log_max_seq, 7);
    // The head equals what a full re-verification computes.
    let connection = store.connection()?;
    let reference = seed_verified_head(&connection)?;
    assert_eq!(snapshot.claim_log_count, reference.claim_log_count);
    assert_eq!(snapshot.claim_log_max_seq, reference.claim_log_max_seq);
    assert_eq!(snapshot.checkpoint_seq, reference.checkpoint_seq());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn append_denies_when_head_diverges() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-deny");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-deny-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    // Prime the head past the checkpoint (any append or flush suffices).
    store.flush_receipt_writes()?;

    // Out-of-band mutation of the persisted latest checkpoint row.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    // Mutate a REAL body field (an ignored extra field would not change the
    // RFC 8785 digest of the parsed body): batch_end_seq 3 -> 2.
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    // The NEXT append fails closed with Conflict pointing at the audit CLI.
    let receipt = sample_receipt_with_keypair("rcpt-deny-after-tamper", 99, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("append after tamper must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(message.contains("chio receipt audit"), "got: {message}");
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The audit surface localizes the divergence (full chain verify fails
    // with a checkpoint-identifying error).
    let status = store.receipt_checkpoint_status(Some(1))?;
    assert!(!status.healthy);
    let checkpoint_error = status
        .checkpoint_error
        .ok_or("audit must report the fault")?;
    assert!(
        checkpoint_error.contains("checkpoint") || checkpoint_error.contains("1"),
        "audit must localize the divergent checkpoint: {checkpoint_error}"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn writer_routed_inserts_do_not_false_conflict_the_next_append(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-resync");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_keypair("rcpt-resync-0", 1, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;

    // Writer-routed child receipt inserts a claim-log row via the projection
    // trigger (bootstrap/open.rs:711); manual checkpoint creation inserts a
    // checkpoint row. Both must be absorbed by the post-Write resync.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-resync-1", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    // The next appends must succeed (no projection-drift Conflict, no
    // predecessor Conflict).
    for i in 1..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-resync-{i}"), (i + 2) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let snapshot = store.writer_head_snapshot();
    assert_eq!(snapshot.claim_log_max_seq, 5); // 1 tool + 1 child + 3 tool
    assert_eq!(snapshot.checkpoint_seq, 1);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn full_verification_fallback_still_catches_projection_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-fallback");
    let keypair = receipt_test_keypair();
    // `ChioReceipt::sign` overwrites `body.id` with the authoritative
    // `chio_receipt_id` (an RFC 8785 canonical-body sha256), discarding the
    // caller-supplied seed string, so the persisted `receipt_id` must be read
    // back from the signed receipt, not the seed passed to
    // `sample_receipt_with_keypair`.
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        let receipt = sample_receipt_with_keypair("rcpt-fallback-0", 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        store.flush_receipt_writes()?;
        receipt.id.clone()
    };
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Same tamper the legacy full path catches today.
    tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });
    let receipt = sample_receipt_with_keypair("rcpt-fallback-1", 2, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("full-path append after tamper must be denied")?;
    assert!(matches!(error, ReceiptStoreError::Conflict(_)));
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn reseed_clears_a_poisoned_head_after_repairing_the_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-reseed");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-reseed-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Poison: tamper the latest checkpoint, trigger the denial, then repair
    // the row back to its original bytes and reseed.
    let connection = store.connection()?;
    let original: String = connection.query_row(
        "SELECT statement_json FROM kernel_checkpoints WHERE checkpoint_seq = 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    let receipt = sample_receipt_with_keypair("rcpt-reseed-denied", 50, &keypair);
    assert!(store.append_chio_receipt_returning_seq(&receipt).is_err());

    // Repair the database out of band, then reseed the head. The denied
    // append above ran `ensure_checkpoint_transparency_guards` before its
    // predecessor check failed, silently recreating the immutability
    // trigger; an out-of-band repair must drop it again before writing,
    // exactly as the initial tamper did.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    // Appends flow again.
    let receipt = sample_receipt_with_keypair("rcpt-reseed-ok", 51, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert!(
        health.writer.last_error.is_none(),
        "reseed must clear last_error"
    );
    let _ = fs::remove_file(path);
    Ok(())
}

/// `chio receipt audit --repair` on a store whose data is STILL corrupt (the
/// operator ran `--repair` without actually fixing the underlying rows) must
/// fail closed: `reseed_verified_head` returns `Err`, the writer stays
/// `Poisoned`, and the next append is denied via the poisoned-head Conflict
/// (not silently readopted as healthy). This is the counterpart to
/// `reseed_clears_a_poisoned_head_after_repairing_the_database`, which proves
/// the success path; this test proves the fail-closed path.
#[test]
fn reseed_on_still_corrupt_store_stays_poisoned() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-reseed-fail");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-reseed-fail-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Same tamper mechanics as `reseed_clears_a_poisoned_head_after_repairing_the_database`:
    // drop the immutability trigger, then mutate a real body field so the
    // RFC 8785 digest changes. Keep the original bytes so the last section of
    // this test can still prove the same store object recovers once the data
    // really is repaired.
    let connection = store.connection()?;
    let original: String = connection.query_row(
        "SELECT statement_json FROM kernel_checkpoints WHERE checkpoint_seq = 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    // Poison the writer's cached head exactly as the existing reseed test
    // does: a denied append surfaces the divergence without repairing it.
    let denied_before_reseed =
        sample_receipt_with_keypair("rcpt-reseed-fail-denied-before", 50, &keypair);
    assert!(store
        .append_chio_receipt_returning_seq(&denied_before_reseed)
        .is_err());

    // The corruption is NOT repaired here (unlike the success-path test):
    // reseed_verified_head reruns full verification on the still-corrupt
    // store and must fail closed.
    let reseed_error = store
        .reseed_verified_head()
        .err()
        .ok_or("reseed on a still-corrupt store must return Err")?;
    match &reseed_error {
        ReceiptStoreError::Conflict(_) => {}
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The writer-health surface reflects the reseed failure: `last_error` is
    // read here, before the next append below overwrites it with its own
    // (differently worded) poisoned-Conflict text, so this specifically
    // checks the ReseedHead command's own failure, not a downstream echo.
    let health = store.receipt_store_health()?;
    let last_error = health
        .writer
        .last_error
        .clone()
        .ok_or("writer last_error must be set after a failed reseed")?;
    assert_eq!(
        last_error,
        reseed_error.to_string(),
        "writer last_error must mirror the reseed failure"
    );

    // The store stays fail-closed: the next append is still rejected, now
    // via the Poisoned head_state (not the stale predecessor check that
    // denied the pre-reseed append above), which points the operator back at
    // `chio receipt audit --repair`.
    let denied_after_reseed =
        sample_receipt_with_keypair("rcpt-reseed-fail-denied-after", 51, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&denied_after_reseed)
        .err()
        .ok_or("append on a still-poisoned store must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "poisoned Conflict must point the operator at the audit CLI, got: {message}"
            );
            assert!(
                message.contains("verified head is unavailable"),
                "poisoned Conflict must come from the Poisoned head_state (not a stale \
                 predecessor-check Conflict), got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // The same store object recovers once the data is actually repaired.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    let receipt = sample_receipt_with_keypair("rcpt-reseed-fail-recovered", 52, &keypair);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert!(
        health.writer.last_error.is_none(),
        "reseed after a real repair must clear last_error"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// `reseed_verified_head()` success clears `last_error` and replaces the head,
/// and must ALSO clear the actor loop's separate `pending_flush_error` (set by
/// an earlier poisoned append). Otherwise a subsequent STANDALONE
/// `flush_receipt_writes()` (no queued writes) keeps returning the stale append
/// error even though the reseed revalidated the DB.
#[test]
fn reseed_clears_stale_flush_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reseed-clears-flush-error");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt = sample_receipt_with_keypair(
            &format!("rcpt-reseed-flush-{i}"),
            (i + 1) as u64,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;

    // Poison: tamper the latest checkpoint so the next append is denied. The
    // denied append records the actor loop's `pending_flush_error`.
    let connection = store.connection()?;
    let original: String = connection.query_row(
        "SELECT statement_json FROM kernel_checkpoints WHERE checkpoint_seq = 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":3', '\"batch_end_seq\":2')",
        [],
    )?;
    drop(connection);

    let denied = sample_receipt_with_keypair("rcpt-reseed-flush-denied", 50, &keypair);
    assert!(store.append_chio_receipt_returning_seq(&denied).is_err());
    // A standalone flush now surfaces the stale append error (the flush error
    // outlives the failed append).
    assert!(
        store.flush_receipt_writes().is_err(),
        "a poisoned append must leave the standalone flush returning the stale error"
    );

    // Repair the DB out of band, then reseed. The denied append re-created the
    // immutability trigger, so drop it again before the repair write.
    let connection = store.connection()?;
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    connection.execute(
        "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params![original],
    )?;
    drop(connection);
    store.reseed_verified_head()?;

    // A subsequent STANDALONE flush (no intervening append that would itself
    // reset the error) returns Ok, not the stale append error.
    let report = store.flush_receipt_writes();
    assert!(
        report.is_ok(),
        "reseed success must clear the stale flush error: {report:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// When another writer extends the checkpoint chain out of band, the catch-up
/// adoption path verifies signature + predecessor + claim-log range but must
/// ALSO validate the adopted checkpoint's transparency projection rows (which
/// full `verify_checkpoint_chain_integrity` checks) before advancing
/// `head.latest_checkpoint`. A checkpoint with missing / divergent projection
/// rows must NOT be adopted; a valid extension still is (bounded per-checkpoint,
/// not a full-history walk).
#[test]
fn catch_up_validates_checkpoint_projections() -> Result<(), Box<dyn std::error::Error>> {
    // REJECT: an externally persisted checkpoint whose kernel_checkpoints row is
    // present (valid signature, valid predecessor linkage, valid claim-log range)
    // but whose transparency projection rows are MISSING must fail the catch-up
    // closed. The projections are normally auto-populated by the
    // `kernel_checkpoints_project_tree_head` AFTER INSERT trigger, so this drops
    // that trigger out of band before the external insert to leave the projection
    // rows missing (the exact state full verify_checkpoint_chain_integrity
    // rejects).
    let path = unique_db_path("chio-catchup-bad-projections");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-catchup-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Checkpoint 1 (1..=3) with full, valid projections.
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let checkpoint_one = store
        .load_checkpoint_by_seq(1)?
        .ok_or("checkpoint 1 missing")?;

    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    assert_eq!(head.checkpoint_seq(), 1);

    // Another writer extends with a chain-linked checkpoint 2 (4..=6). Drop the
    // projection auto-populate trigger first so the row lands with MISSING
    // transparency projections.
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;")?;
    let range_bytes = canonical_receipt_bytes(&store, 4, 6);
    let checkpoint_two =
        build_checkpoint_with_previous(2, 4, 6, &range_bytes, &keypair, Some(&checkpoint_one))?;
    insert_checkpoint_row(&store, &checkpoint_two, checkpoint_two.body.batch_end_seq);

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("catch-up must reject a checkpoint with missing projection rows")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );
    assert_eq!(
        head.checkpoint_seq(),
        1,
        "the head must NOT adopt a checkpoint whose projection rows are invalid"
    );
    drop(connection);
    let _ = fs::remove_file(path);

    // ADOPT: a valid extension (projection rows written by the store's own
    // checkpoint builder) is still caught up.
    let good_path = unique_db_path("chio-catchup-good-projections");
    let good_store = SqliteReceiptStore::open(&good_path)?;
    for i in 0..6 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-catchup-ok-{i}"), (i + 1) as u64, &keypair);
        good_store.append_chio_receipt_returning_seq(&receipt)?;
    }
    good_store.flush_receipt_writes()?;
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp1 (1..=3)
    let good_connection = good_store.connection()?;
    let mut good_head = seed_verified_head(&good_connection)?;
    assert_eq!(good_head.checkpoint_seq(), 1);
    good_store.create_next_receipt_checkpoint(3, &keypair)?; // cp2 (4..=6), valid projections
    verify_head_against_latest_checkpoint(&good_connection, &mut good_head)?;
    assert_eq!(
        good_head.checkpoint_seq(),
        2,
        "a valid extension with intact projection rows must be adopted"
    );
    drop(good_connection);
    let _ = fs::remove_file(good_path);
    Ok(())
}

/// Fail-closed parity: a writer-routed (Write path) receipt append (child
/// receipt / consuming-auth append) on an `incremental_verification = false`
/// store must run the SAME full claim-log validation the append batch path
/// runs, so uncheckpointed projection drift is denied at append time. A
/// fallback pre-check that ran only `verify_latest_checkpoint_integrity`
/// (which returns Ok when no checkpoint exists) would let a writer-routed
/// append silently commit over tampered rows. Sibling of
/// `full_verification_fallback_still_catches_projection_drift` (which covers
/// the append batch path).
#[test]
fn writer_routed_fallback_append_catches_uncheckpointed_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-fallback-drift");
    let keypair = receipt_test_keypair();
    // Seed one tool receipt on the default (incremental) store; capture the
    // authoritative persisted receipt id.
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        let receipt = sample_receipt_with_keypair("rcpt-wfd-0", 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
        store.flush_receipt_writes()?;
        receipt.id.clone()
    };
    // Reopen with incremental verification OFF (full-verification fallback).
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Tamper an UNCHECKPOINTED claim-log row (no checkpoint has been built).
    tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });

    // A writer-routed child receipt append must be DENIED fail-closed by the
    // pre-write full claim-log validation, not silently committed.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-wfd-1", 2, &keypair);
    let error = store
        .append_child_receipt_record(&child)
        .err()
        .ok_or("writer-routed append after uncheckpointed tamper must be denied")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected fail-closed Conflict, got {error:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// `append_receipt_batch` adopts every claim_receipt_log_entries row past a
/// STALE actor head as trusted baseline (the pre_delta), cross-checking only
/// the rows THIS batch inserts. A shared-DB out-of-band orphan/mismatched row
/// in that adopted range must not be blindly trusted: the batch validates JUST
/// that bounded delta range against the source tables. The single-writer
/// no-stale-head case (empty delta) adds no validation, so per-append cost
/// stays bounded by the batch, not total history.
#[test]
fn stale_head_validates_adopted_delta_before_trusting() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-stale-head-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-stale-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4. Inserts are not blocked by the reject_update trigger; the
    // CHECK constraint just requires the tool-receipt columns to be populated.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-oob-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a STALE head (claim_log_max_seq = 3) puts the orphan at
    // entry_seq 4 inside the adopted pre_delta. The append must be denied.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-append", 10, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let results = append_receipt_batch(&store.pool, &mut stale_head, true, &requests);
    let error = results
        .into_iter()
        .next()
        .ok_or("expected one append result")?
        .err()
        .ok_or("stale-head append over an out-of-band orphan row must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "fail-closed Conflict must point at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // NO-OP: a FRESH head whose claim_log_max_seq already covers the orphan
    // (= 4) has an EMPTY delta, so the range validator does NOT re-scan the
    // below-floor orphan; appending a brand-new receipt succeeds.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    let receipt = sample_receipt_with_keypair("rcpt-stale-fresh", 11, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, _rx) = std::sync::mpsc::sync_channel(1);
    let requests = vec![ReceiptCommitRequest {
        receipt,
        raw_json,
        ensure_lineage: false,
        response,
    }];
    let results = append_receipt_batch(&store.pool, &mut fresh_head, true, &requests);
    assert!(
        results.iter().all(|result| result.is_ok()),
        "empty-delta append must add no validation and succeed: {results:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// `resync_head_after_write` advances the head after a Write closure by
/// COUNT/MAX over `claim_receipt_log_entries`. When another process (or a
/// receipt-appending Write job) commits rows PAST this actor's head, blindly
/// adopting them would trust an out-of-band orphan/divergent row that later
/// appends then skip as already-verified (a background checkpoint could then
/// cover an unaudited entry). Resync must validate JUST the adopted delta (the
/// same bounded `validate_adopted_claim_log_delta` the append path uses) before
/// advancing. The single-writer common case (empty delta) adds no validation,
/// so per-append cost stays bounded by the batch, not total history.
#[test]
fn resync_validates_adopted_delta() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-resync-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Three real receipts -> claim-log entries 1..=3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-resync-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer commits an ORPHAN claim-log row (no source receipt)
    // at entry_seq 4, past this actor's head. Same injection as the append-path
    // sibling above; inserts are not blocked by the reject_update trigger.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-resync-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // FAIL-CLOSED: a head at claim_log_max_seq = 3 puts the orphan at entry_seq 4
    // inside the adopted resync delta. The resync must REJECT it, not silently
    // absorb it, and must not advance the head.
    let mut stale_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 3,
        claim_log_max_seq: 3,
    };
    let connection = store.connection()?;
    let error = resync_head_after_write(&connection, &mut stale_head)
        .err()
        .ok_or("resync over an out-of-band orphan row must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "fail-closed Conflict must point at the audit CLI, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }
    assert_eq!(
        stale_head.claim_log_max_seq, 3,
        "a rejected resync must not adopt the divergent delta"
    );

    // NO-OP: a head already covering the orphan (max_seq = 4) has an EMPTY
    // resync delta, so the range validator does NOT re-scan the below-floor
    // orphan and the resync is a no-op.
    let mut fresh_head = VerifiedHead {
        latest_checkpoint: None,
        claim_log_count: 4,
        claim_log_max_seq: 4,
    };
    resync_head_after_write(&connection, &mut fresh_head)?;
    assert_eq!(
        fresh_head.claim_log_max_seq, 4,
        "empty-delta resync must be a no-op"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// For a writer-routed Write job the actor must send the caller's result only
/// AFTER running `resync_head_after_write`. Because that resync can FAIL (it
/// poisons the head on a divergent adopted delta), a write whose closure
/// COMMITTED but whose resync then failed would otherwise return `Ok` while the
/// head was left poisoned. Deferring the response until after resync means a
/// committed write whose resync fails returns the resync error, not a stale
/// `Ok`.
#[test]
fn write_job_response_reflects_resync_failure() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-write-resync-fail");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Real receipts -> claim-log entries 1..=3, writer head at claim_log_max_seq 3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-wrf-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // A Write job whose closure COMMITS (returns Ok) but inserts an out-of-band
    // ORPHAN claim-log row at entry_seq 4 (no source receipt). The post-write
    // resync adopts (3, 4] as a delta, validates it, and REJECTS the orphan,
    // poisoning the head. The caller must receive that resync error, NOT Ok.
    let result: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO claim_receipt_log_entries (
                    entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                    capability_id, tool_server, tool_name, raw_json
                ) VALUES (4, 'orphan-wrf-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
                "#,
                [],
            )?;
            Ok(())
        });

    let error = result
        .err()
        .ok_or("a committed Write whose resync fails must return the resync error, not Ok")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "resync failure must surface the fail-closed Conflict, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // Teeth: the resync failure poisoned the head, so the next write is denied.
    let next: Result<(), ReceiptStoreError> = store.writer_handle().run_write(|_connection| Ok(()));
    assert!(next.is_err(), "resync failure must poison the head");

    let _ = fs::remove_file(path);
    Ok(())
}

/// With incremental verification a RECEIPT-APPENDING writer-routed job (child
/// receipt / auth-consuming append) that pre-checked only the checkpoint head,
/// NOT the claim-log rows an out-of-band writer left AHEAD of this actor's
/// head, would let a bad/orphan `claim_receipt_log_entries` row present BEFORE
/// the job ran DURABLY insert its receipt and only THEN, in
/// `resync_head_after_write`, detect the orphan and poison the head (a
/// fail-OPEN durable write). Validating the adopted claim-log delta (the same
/// bounded `validate_adopted_claim_log_delta` the append path uses) BEFORE the
/// job runs denies the job with NO durable insert. The validation is
/// delta-bounded (an empty delta is the single-writer no-op), so per-append
/// cost stays bounded by the batch, not total history.
#[test]
fn writer_job_validates_adopted_delta_before_commit() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-preval-delta");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Real receipts -> claim-log entries 1..=3, writer head at claim_log_max_seq 3.
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-preval-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // An out-of-band writer leaves a bad/orphan claim-log row (no source receipt)
    // at entry_seq 4, AHEAD of this actor's head, BEFORE any writer job runs.
    {
        let connection = store.connection()?;
        connection.execute(
            r#"
            INSERT INTO claim_receipt_log_entries (
                entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                capability_id, tool_server, tool_name, raw_json
            ) VALUES (4, 'orphan-preval-4', 'tool_receipt', 999, 1, 'cap-oob', 'shell', 'bash', '{}')
            "#,
            [],
        )?;
    }

    // A RECEIPT-APPENDING writer job (`run_write_receipt`, appends_receipts =
    // true) whose closure would DURABLY insert a new claim-log row at entry_seq
    // 5. The pre-check must DENY the job because the adopted delta (3, 4] holds
    // the orphan, and the closure's row must never be durably inserted.
    let result: Result<(), ReceiptStoreError> =
        store.writer_handle().run_write_receipt(move |connection| {
            connection.execute(
                r#"
                INSERT INTO claim_receipt_log_entries (
                    entry_seq, receipt_id, receipt_kind, source_seq, timestamp,
                    capability_id, tool_server, tool_name, raw_json
                ) VALUES (5, 'writer-job-row-5', 'tool_receipt', 5, 1, 'cap-job', 'shell', 'bash', '{}')
                "#,
                [],
            )?;
            Ok(())
        });

    let error = result
        .err()
        .ok_or("a receipt-appending writer job over a pre-existing orphan must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => assert!(
            message.contains("chio receipt audit"),
            "fail-closed Conflict must point at the audit CLI, got: {message}"
        ),
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    // TEETH: the job's row must be rejected BEFORE the durable insert. A
    // post-commit resync check would let the closure run and persist entry_seq
    // 5 before rejecting; the pre-check denies the job so entry_seq 5 never
    // exists.
    let connection = store.connection()?;
    let job_row: i64 = connection.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq = 5",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        job_row, 0,
        "the writer job's receipt must NOT be durably inserted when a pre-existing orphan blocks the adopted baseline"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// On the same-seq fast path `verify_head_against_latest_checkpoint` compares
/// the RFC 8785 body digest (statement_json) plus the signature/kernel_key
/// columns. The kernel_checkpoints row ALSO stores batch_start_seq/
/// batch_end_seq/tree_size/merkle_root/issued_at as their own columns; a
/// signed-body-bound column tampered out of band while statement_json is
/// untouched would pass a digest-only check. Reconciling EVERY such column
/// against the signed body (`ensure_checkpoint_columns_match_body`, O(1) over
/// one row, no Ed25519) makes the column tamper fail closed.
#[test]
fn head_trust_checks_all_checkpoint_columns() -> Result<(), Box<dyn std::error::Error>> {
    let (path, store, keypair) = open_seeded_store("chio-head-allcols", 3)?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;

    // Baseline: an untouched same-seq checkpoint verifies clean on the fast path.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;

    // Tamper a SIGNED-BODY integrity COLUMN (batch_end_seq) out of band while
    // leaving statement_json (and thus the body digest) intact, bypassing the
    // immutability trigger. The digest branch alone would accept this.
    connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
    let tampered = connection.execute(
        "UPDATE kernel_checkpoints SET batch_end_seq = batch_end_seq + 1 WHERE checkpoint_seq = 1",
        [],
    )?;
    assert_eq!(tampered, 1, "expected to tamper exactly one checkpoint row");

    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("a tampered signed-body column must be rejected on the fast path")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("batch_end_seq"),
                "Conflict should name the tampered column, got: {message}"
            );
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// `validate_adopted_claim_log_delta` that iterated only the claim-log rows
/// that CURRENTLY EXIST in the adopted range would let an interior GAP (a
/// missing entry_seq) pass unnoticed. The adopted range must therefore be
/// CONTIGUOUS (floor+1..=max with no hole), an O(delta) ordered scan over the
/// already-loaded delta, rejecting fail-closed on a gap while a contiguous
/// delta still passes.
#[test]
fn adopted_delta_rejects_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-adopted-delta-gap");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    // Four real, correctly-projecting receipts -> contiguous claim-log entries
    // 1,2,3,4. Every row projects from its source receipt, so the projection
    // cross-check alone cannot fail; only the contiguity rule can.
    for i in 0..4 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-gap-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let connection = store.connection()?;

    // Contiguous delta (0, 4] = {1,2,3,4}: every row present and projecting, so
    // the validator accepts it.
    validate_adopted_claim_log_delta(&connection, 0, 4)?;

    // Punch an INTERIOR hole: delete entry_seq 3 (drop the append-only trigger
    // first), leaving {1,2,4}. The three surviving rows still project cleanly.
    connection.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    let deleted = connection.execute(
        "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 3",
        [],
    )?;
    assert_eq!(deleted, 1, "expected to remove exactly one claim-log row");

    // Now (0, 4] = {1,2,4} is non-contiguous. Without the contiguity check the
    // projection loop would accept the surviving rows and return Ok; the
    // contiguity scan detects the gap at entry_seq 3 and fails closed.
    let error = validate_adopted_claim_log_delta(&connection, 0, 4)
        .err()
        .ok_or("a non-contiguous adopted delta must be rejected")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("not contiguous") && message.contains('3'),
                "Conflict should identify the interior gap, got: {message}"
            );
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// `verify_head_against_latest_checkpoint` compares the RFC 8785 body digest for
/// a same-seq checkpoint (keeping the Ed25519 verify off the per-append hot
/// path). A persisted `signature` COLUMN corrupted out of band while
/// statement_json is untouched would pass a digest-only check. Comparing the
/// signature/kernel_key COLUMNS against the signature-verified cached head (O(1)
/// string compare, no crypto) catches the column tamper fail-closed.
#[test]
fn tampered_checkpoint_signature_column_denies_append() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-sig-column-tamper");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-sigcol-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?;
    // Prime the actor head so its cached latest_checkpoint is checkpoint 1 with
    // the ORIGINAL signature (this append forces the head to catch up to seq 1,
    // so the tamper below lands on the same-seq body-digest branch).
    store.append_chio_receipt_returning_seq(&sample_receipt_with_keypair(
        "rcpt-sigcol-prime",
        4,
        &keypair,
    ))?;
    store.flush_receipt_writes()?;

    // Corrupt ONLY the persisted signature column (statement_json/body intact),
    // bypassing the immutability trigger. A DIFFERENT but valid-hex Ed25519
    // signature (over unrelated bytes) keeps the row parseable.
    let tampered_signature_hex = keypair
        .sign(b"unrelated-bytes-for-a-different-valid-signature")
        .to_hex();
    {
        let connection = store.connection()?;
        let original: String = connection.query_row(
            "SELECT signature FROM kernel_checkpoints WHERE checkpoint_seq = 1",
            [],
            |row| row.get(0),
        )?;
        assert_ne!(original, tampered_signature_hex);
        connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
        connection.execute(
            "UPDATE kernel_checkpoints SET signature = ?1 WHERE checkpoint_seq = 1",
            rusqlite::params![tampered_signature_hex],
        )?;
    }

    // The next append hits the same-seq branch (body digest matches, body was
    // untouched) and must now fail closed on the signature-column mismatch.
    let receipt = sample_receipt_with_keypair("rcpt-sigcol-after", 5, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("append after signature-column tamper must be denied")?;
    match &error {
        ReceiptStoreError::Conflict(message) => {
            assert!(
                message.contains("chio receipt audit"),
                "Conflict must point the operator at the audit CLI, got: {message}"
            );
        }
        other => return Err(format!("expected Conflict, got {other}").into()),
    }

    let _ = fs::remove_file(path);
    Ok(())
}

/// With incremental verification the per-append count/MAX cross-check only
/// proves the projection advanced by the right NUMBER of rows;
/// `append_chio_receipt_tx` verifies only the projected `receipt_id`/`raw_json`.
/// A projection trigger that emits one row per insert whose OTHER columns (here
/// `tool_name`) diverge from the source receipt would slip past the count/MAX
/// gate and advance the head, after which later appends treat the bad row as
/// already verified. Validating the NEWLY-projected (baseline_max, post_max]
/// delta with the full-field validator BEFORE the head advances (O(delta),
/// single-batch bounded) rejects the divergent row fail-closed and the head
/// does not move.
#[test]
fn divergent_newly_projected_row_is_rejected_before_head_advance(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-head-newproj-drift");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-newproj-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let head_before = store.writer_head_snapshot().claim_log_max_seq;
    assert_eq!(head_before, 3);

    // Simulate a modified projection trigger that still emits exactly one row per
    // insert (count/MAX gate passes) and keeps `receipt_id`/`raw_json` correct
    // (append_chio_receipt_tx passes) but writes a DIVERGENT `tool_name` column
    // that does not match the source receipt.
    let connection = store.connection()?;
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS chio_tool_receipts_project_claim_log_entry;
        CREATE TRIGGER chio_tool_receipts_project_claim_log_entry
        AFTER INSERT ON chio_tool_receipts
        BEGIN
            INSERT INTO claim_receipt_log_entries (
                receipt_id,
                receipt_kind,
                source_seq,
                timestamp,
                capability_id,
                session_id,
                parent_request_id,
                request_id,
                subject_key,
                issuer_key,
                tool_server,
                tool_name,
                raw_json
            ) VALUES (
                NEW.receipt_id,
                'tool_receipt',
                NEW.seq,
                NEW.timestamp,
                NEW.capability_id,
                NULL,
                NULL,
                NULL,
                NEW.subject_key,
                NEW.issuer_key,
                NEW.tool_server,
                'divergent-projected-tool-name',
                NEW.raw_json
            );
        END;
        "#,
    )?;
    drop(connection);

    // The append inserts a source receipt whose projected row now diverges in
    // `tool_name`; the newly-projected-delta validation must reject it BEFORE the
    // head advances (fail-closed Conflict).
    let receipt = sample_receipt_with_keypair("rcpt-newproj-divergent", 4, &keypair);
    let error = store
        .append_chio_receipt_returning_seq(&receipt)
        .err()
        .ok_or("a divergent newly-projected row must be rejected before the head advances")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );

    // The head did NOT advance: the rejected append rolled its transaction back,
    // so the actor's cached head still stops at the last clean entry. (No flush
    // here: the failed batch leaves a pending flush error by design.)
    let head_after = store.writer_head_snapshot().claim_log_max_seq;
    assert_eq!(
        head_after, head_before,
        "the head must not advance past a divergent newly-projected row"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// `reseed_verified_head()` is the `chio receipt audit --repair` recovery path.
/// Even when the store was opened with `incremental_verification = false`
/// (where the hot path defers the full claim-log audit to the next append), a
/// RESEED must run the FULL verification so it cannot clear `last_error` and
/// mark a still-corrupt log as `Verified` (repair theater). This is the
/// deliberate opposite of the InstallSigner catch-up, which legitimately DEFERS
/// in the same mode because its seed is unvalidated.
#[test]
fn reseed_runs_full_verification_in_non_incremental_mode() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-reseed-nonincremental-fullverify");
    let keypair = receipt_test_keypair();
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        let mut first_id = String::new();
        for i in 0..3 {
            let receipt = sample_receipt_with_keypair(
                &format!("rcpt-reseed-fv-{i}"),
                (i + 1) as u64,
                &keypair,
            );
            if i == 0 {
                first_id = receipt.id.clone();
            }
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        first_id
    };

    // Reopen with incremental_verification = false: the hot path would only run
    // the cheap `seed_head_snapshot`.
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Corrupt a claim-log projection row. The cheap snapshot never inspects
    // projection rows, so only a FULL verification catches this.
    tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });

    // The reseed must fail closed (full verification catches the tamper) rather
    // than clearing the head to `Verified` over a corrupt log.
    let error = store.reseed_verified_head().err().ok_or(
        "reseed in non-incremental mode must run the full verify and reject a corrupt log",
    )?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the full reseed verification, got {error:?}"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// A successfully-enqueued writer-routed (`run_write`/`run_write_receipt`)
/// write must increment the writer `accepted_total` health counter, mirroring
/// the Append path. Child receipts and authorization-consuming receipts flow
/// through `run_write_receipt`, so without this a store dominated by
/// writer-routed receipts would advance the log while `accepted_total` stayed
/// at zero.
#[test]
fn writer_routed_write_increments_accepted_total() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-routed-accepted");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    // A parent tool receipt first (Append path, also increments accepted_total);
    // capture the baseline AFTER it so the child's writer-routed write is the only
    // additional accepted enqueue measured below.
    let parent = sample_receipt_with_keypair("rcpt-writer-routed-parent", 1, &keypair);
    store.append_chio_receipt_returning_seq(&parent)?;
    let baseline = store.flush_receipt_writes()?.writer.accepted_total;

    // A child receipt append is a writer-routed (`run_write_receipt`) write.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-writer-routed", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    let accepted = store.flush_receipt_writes()?.writer.accepted_total;

    assert_eq!(
        accepted,
        baseline + 1,
        "a successfully-enqueued writer-routed write must increment accepted_total"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// Writer-routed writes (`run_write_receipt` child receipts / consuming auth,
/// and the general `run_write` path) are `accepted_total`-counted at enqueue,
/// but their success/failure OUTCOME must ALSO be folded into `committed_total`
/// / `failed_total`; otherwise accepted / committed / failed do not reconcile
/// and a store dominated by writer-routed receipts undercounts commits. The
/// actor records each writer-routed job's resync-adjusted outcome (O(1) per
/// write): a success increments committed_total, a failure increments
/// failed_total.
#[test]
fn writer_routed_write_outcome_updates_committed_and_failed(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-routed-outcome");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    // Parent tool receipt (Append path) so the child below has a lineage anchor;
    // capture the baseline AFTER it so only the writer-routed writes are measured.
    let parent = sample_receipt_with_keypair("rcpt-outcome-parent", 1, &keypair);
    store.append_chio_receipt_returning_seq(&parent)?;
    let baseline = store.flush_receipt_writes()?.writer;

    // A child receipt append (run_write_receipt) SUCCEEDS: committed_total + 1.
    let child = sample_child_receipt_with_keypair_and_timestamp("child-outcome", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    let after_commit = store.flush_receipt_writes()?.writer;
    assert_eq!(
        after_commit.committed_total,
        baseline.committed_total + 1,
        "a writer-routed success must increment committed_total"
    );
    assert_eq!(
        after_commit.failed_total, baseline.failed_total,
        "a writer-routed success must not increment failed_total"
    );

    // A general `run_write` whose job returns Err FAILS: failed_total + 1.
    let failed =
        store
            .writer_handle()
            .run_write(move |_connection| -> Result<(), ReceiptStoreError> {
                Err(ReceiptStoreError::Conflict(
                    "intentional writer job failure".to_string(),
                ))
            });
    assert!(failed.is_err(), "the failing job must surface its error");
    let after_fail = store.flush_receipt_writes()?.writer;
    assert_eq!(
        after_fail.failed_total,
        after_commit.failed_total + 1,
        "a writer-routed failure must increment failed_total"
    );
    assert_eq!(
        after_fail.committed_total, after_commit.committed_total,
        "a writer-routed failure must not increment committed_total"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

/// When the latest checkpoint seq is UNCHANGED, the append pre-check hot path
/// (`verify_head_against_latest_checkpoint`'s seq-equal branch) re-verifies the
/// `kernel_checkpoints` row's body digest, columns, and signature on every
/// append but must ALSO recheck the checkpoint's transparency projection rows.
/// A projection row tampered out of band (guards momentarily absent, then
/// restored) while the seq is unchanged would otherwise be trusted as verified
/// until the next open/health/audit. The recheck closes that gap symmetrically
/// with the per-append column recheck (O(1), three indexed single-row
/// projection lookups, no batch/leaf scan). A valid projection still passes.
#[test]
fn seq_unchanged_recheck_catches_projection_tamper() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-seq-unchanged-projection-tamper");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    for i in 0..3 {
        let receipt =
            sample_receipt_with_keypair(&format!("rcpt-seq-tamper-{i}"), (i + 1) as u64, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.create_next_receipt_checkpoint(3, &keypair)?; // cp1 (1..=3), adopted

    let connection = store.connection()?;
    let mut head = seed_verified_head(&connection)?;
    assert_eq!(head.checkpoint_seq(), 1);

    // A clean recheck (seq unchanged, projections intact) still passes.
    verify_head_against_latest_checkpoint(&connection, &mut head)?;
    assert_eq!(head.checkpoint_seq(), 1);

    // Tamper the latest checkpoint's tree-head projection row WITHOUT changing
    // the checkpoint seq: drop the immutability guard, then mutate merkle_root so
    // the projection row diverges from the untouched kernel_checkpoints row.
    connection.execute_batch("DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;")?;
    connection.execute(
        "UPDATE checkpoint_tree_heads SET merkle_root = ?1 WHERE checkpoint_seq = 1",
        rusqlite::params!["00".repeat(32)],
    )?;

    // The seq-unchanged hot path must now reject the tampered projection.
    let error = verify_head_against_latest_checkpoint(&connection, &mut head)
        .err()
        .ok_or("the seq-unchanged recheck must reject a tampered projection row")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict, got {error:?}"
    );

    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}
