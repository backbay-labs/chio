use super::super::*;
use super::support::*;

fn attempt_count(store: &SqliteReceiptStore, receipt_id: &str) -> Result<u64, ReceiptStoreError> {
    let connection = store.connection()?;
    let count = connection.query_row(
        "SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1",
        [receipt_id],
        |row| row.get::<_, i64>(0),
    )?;
    sqlite_u64(count, "settlement attempt count")
}

#[test]
fn settlement_projection_binding_is_scoped_to_one_writer() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-binding");
    let store = SqliteReceiptStore::open(&path)?;

    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&store),
        chio_kernel::AtomicReceiptProjection::SettlementObservationV1
    );
    assert!(ReceiptStore::supports_atomic_receipt_projection_with_timeout(&store));
    let binding = ReceiptStore::settlement_store_binding(&store)
        .ok_or("migrated receipt store did not expose settlement binding")?;
    assert_eq!(
        store
            .writer_handle()
            .settlement_store_binding()
            .ok_or("writer handle did not copy settlement binding")?,
        binding
    );
    assert_eq!(
        store
            .writer_handle()
            .settlement_store_binding()
            .ok_or("second writer handle did not copy settlement binding")?,
        binding
    );

    let separate = SqliteReceiptStore::open(&path)?;
    assert_ne!(
        ReceiptStore::settlement_store_binding(&separate),
        Some(binding)
    );
    drop(separate);
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::SettlementObservationV1
    );
    assert!(ReceiptStore::supports_atomic_receipt_projection_with_timeout(&reopened));
    assert!(ReceiptStore::settlement_store_binding(&reopened).is_some());

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_does_not_install_missing_settlement_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TABLE settle_attempts")?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert!(!ReceiptStore::supports_atomic_receipt_projection_with_timeout(&reopened));
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);
    let unsupported_receipt = sample_receipt_with_id("rcpt-settlement-unsupported");
    let unsupported = ReceiptStore::append_chio_receipt_with_pending_observation(
        &reopened,
        &unsupported_receipt,
        &chio_kernel::PendingSettlementObservation {
            next_visible_at_ms: 1,
        },
    );
    assert!(matches!(
        unsupported,
        Err(ReceiptStoreError::Unsupported(_))
    ));
    assert!(reopened
        .load_chio_receipt(&unsupported_receipt.id)?
        .is_none());
    let connection = reopened.connection()?;
    let attempts_table: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'settle_attempts'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    assert_eq!(attempts_table, None);

    drop(connection);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_does_not_reinstall_missing_settlement_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing-guard");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TRIGGER trg_settle_attempts_reject_terminal_insert")?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);
    let connection = reopened.connection()?;
    let guard: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_settle_attempts_reject_terminal_insert'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    assert_eq!(guard, None);

    drop(connection);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_same_named_noop_settlement_guard() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-open-existing-noop-guard");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER trg_settle_attempts_reject_terminal_insert; \
             CREATE TRIGGER trg_settle_attempts_reject_terminal_insert \
             BEFORE INSERT ON settle_attempts BEGIN SELECT 1; END;",
        )?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_unconstrained_settlement_table() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-settlement-open-existing-drifted-table");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TABLE settle_attempts; \
             CREATE TABLE settle_attempts (\
                 receipt_id TEXT, finalized_at INTEGER, work_kind TEXT, attempts INTEGER, \
                 next_visible_at_ms INTEGER, row_version INTEGER, lease_owner TEXT, \
                 lease_token TEXT, lease_until_ms INTEGER, reason_code TEXT, \
                 reason_detail_sha256 BLOB, updated_at_ms INTEGER\
             );",
        )?;
        connection.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_MIGRATION)?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn open_existing_rejects_extra_settlement_trigger() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-open-existing-extra-trigger");
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "CREATE TRIGGER delete_seeded_settlement_attempt \
             AFTER INSERT ON settle_attempts BEGIN \
                 DELETE FROM settle_attempts WHERE receipt_id = NEW.receipt_id; \
             END;",
        )?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(ReceiptStore::settlement_store_binding(&reopened), None);

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn atomic_receipt_append_seeds_attempt_zero_once() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-atomic-append");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id("rcpt-settlement-atomic");
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 9_001,
    };

    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    let connection = store.connection()?;
    let row = connection.query_row(
        "SELECT finalized_at, work_kind, attempts, next_visible_at_ms, row_version, lease_owner, lease_token, lease_until_ms, reason_code, reason_detail_sha256 FROM settle_attempts WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        },
    )?;
    assert_eq!(row.0, i64::try_from(receipt.timestamp)?);
    assert_eq!(row.1, "pending_observation");
    assert_eq!(row.2, 0);
    assert_eq!(row.3, 9_001);
    assert_eq!(row.4, 0);
    assert_eq!(
        (row.5, row.6, row.7, row.8, row.9),
        (None, None, None, None, None)
    );
    drop(connection);

    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    assert_eq!(attempt_count(&store, &receipt.id)?, 1);

    let conflicting = sample_receipt_with_id("rcpt-settlement-attempt-conflict");
    store.writer_handle().run_write({
        let receipt_id = conflicting.id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settle_attempts (receipt_id, finalized_at, work_kind, attempts, next_visible_at_ms, row_version, updated_at_ms) VALUES (?1, 1, 'pending_observation', 0, 1, 0, 1)",
                [receipt_id],
            )?;
            Ok(())
        }
    })?;
    let conflict =
        ReceiptStore::append_chio_receipt_with_pending_observation(&store, &conflicting, &pending);
    assert!(conflict.is_err());
    assert!(store.load_chio_receipt(&conflicting.id)?.is_none());
    assert_eq!(attempt_count(&store, &conflicting.id)?, 1);

    let overflow = sample_receipt_with_id("rcpt-settlement-visible-overflow");
    let overflow_result = ReceiptStore::append_chio_receipt_with_pending_observation(
        &store,
        &overflow,
        &chio_kernel::PendingSettlementObservation {
            next_visible_at_ms: u64::MAX,
        },
    );
    assert!(overflow_result.is_err());
    assert!(store.load_chio_receipt(&overflow.id)?.is_none());

    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn duplicate_receipt_without_settlement_obligation_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-missing-obligation");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id("rcpt-settlement-missing-obligation");
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 9_001,
    };

    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    store.writer_handle().run_write({
        let receipt_id = receipt.id.clone();
        move |connection| {
            connection.execute(
                "DELETE FROM settle_attempts WHERE receipt_id = ?1",
                [receipt_id],
            )?;
            Ok(())
        }
    })?;

    let result =
        ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending);
    assert!(matches!(result, Err(ReceiptStoreError::Conflict(_))));
    assert_eq!(attempt_count(&store, &receipt.id)?, 0);

    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn atomic_receipt_append_with_timeout_returns_seq_and_seeds_attempt_zero(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-atomic-append-timeout");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id("rcpt-settlement-atomic-timeout");
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 9_002,
    };

    let seq = ReceiptStore::append_chio_receipt_with_pending_observation_and_timeout(
        &store,
        &receipt,
        &pending,
        Duration::from_secs(2),
    )?
    .ok_or("sqlite atomic settlement append did not return its claim-log seq")?;

    assert!(store.load_chio_receipt(&receipt.id)?.is_some());
    assert_eq!(attempt_count(&store, &receipt.id)?, 1);
    let connection = store.connection()?;
    let persisted_seq = connection.query_row(
        "SELECT entry_seq FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(seq, sqlite_u64(persisted_seq, "claim-log entry seq")?);

    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn timed_out_atomic_receipt_append_commits_once_after_writer_drains(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-settlement-atomic-timeout-late-success")?;
    let store = SqliteReceiptStore::open(&path)?;
    let baseline = store.receipt_commit_actor.writer_counters();
    let blocker = store.writer_handle();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let blocker_thread = std::thread::spawn(move || {
        blocker.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
    });
    started_rx.recv()?;

    let receipt = sample_receipt_with_id("rcpt-settlement-atomic-timeout-late-success");
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 9_003,
    };
    let error = ReceiptStore::append_chio_receipt_with_pending_observation_and_timeout(
        &store,
        &receipt,
        &pending,
        Duration::from_millis(25),
    )
    .err()
    .ok_or("atomic settlement append must time out behind the blocked writer")?;
    assert!(matches!(error, ReceiptStoreError::Timeout { .. }));
    assert!(store.load_chio_receipt(&receipt.id)?.is_none());
    assert_eq!(attempt_count(&store, &receipt.id)?, 0);
    let timed_out = store.receipt_commit_actor.writer_counters();
    assert_eq!(timed_out.accepted_total, baseline.accepted_total + 2);
    assert_eq!(timed_out.committed_total, baseline.committed_total);
    assert_eq!(timed_out.failed_total, baseline.failed_total);
    assert_eq!(timed_out.timed_out_total, baseline.timed_out_total + 1);
    assert_eq!(timed_out.timed_out_inflight, 1);
    assert_eq!(
        store.writer_liveness(Duration::from_secs(60)),
        chio_kernel::ReceiptWriterLiveness::Wedged
    );

    release_tx.send(())?;
    blocker_thread
        .join()
        .map_err(|_| "blocking writer thread panicked")??;
    let mut drained = false;
    for _ in 0..1_000 {
        let counters = store.receipt_commit_actor.writer_counters();
        if counters.timed_out_inflight == 0
            && counters.committed_total == baseline.committed_total + 2
            && store.load_chio_receipt(&receipt.id)?.is_some()
            && attempt_count(&store, &receipt.id)? == 1
        {
            drained = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(drained, "timed-out atomic write did not drain and commit");

    let completed = store.receipt_commit_actor.writer_counters();
    assert_eq!(completed.timed_out_total, baseline.timed_out_total + 1);
    assert_eq!(completed.timed_out_inflight, 0);
    assert_eq!(completed.failed_total, baseline.failed_total);
    assert_eq!(
        completed.accepted_total,
        completed.committed_total + completed.failed_total
    );
    assert!(!store
        .receipt_commit_actor
        .health
        .critical_write_poisoned
        .load(Ordering::SeqCst));
    assert!(!store.writer_serving_closed());
    assert_eq!(
        store.writer_liveness(Duration::from_secs(60)),
        chio_kernel::ReceiptWriterLiveness::Healthy
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn atomic_settlement_write_failure_closes_serving_before_returning(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-settlement-write-failure")?;
    let store = SqliteReceiptStore::open(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TABLE settle_attempts")?;
        Ok(())
    })?;

    let receipt = sample_receipt_with_id("rcpt-settlement-write-failure");
    let error = ReceiptStore::append_chio_receipt_with_pending_observation(
        &store,
        &receipt,
        &chio_kernel::PendingSettlementObservation {
            next_visible_at_ms: 1,
        },
    )
    .err()
    .ok_or("a missing settlement projection must reject the atomic write")?;
    assert!(error.to_string().contains("settle_attempts"));
    assert!(
        store.writer_serving_closed(),
        "the critical writer route must close serving before returning its error"
    );
    let health = store.receipt_store_health()?;
    assert!(
        health
            .writer
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("settle_attempts")),
        "the projection failure must be retained in writer health: {health:?}"
    );
    let reseed = store
        .reseed_verified_head()
        .err()
        .ok_or("receipt-log reseed must not clear a critical projection failure")?;
    assert!(reseed.to_string().contains("reopen the receipt store"));
    assert!(store.writer_serving_closed());

    let later = store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id(
            "rcpt-after-settlement-write-failure",
        ))
        .err()
        .ok_or("a critical projection failure must poison later receipt writes")?;
    assert!(later.to_string().contains("verified head is unavailable"));

    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn receipt_retention_preserves_active_settlement_attempts() -> Result<(), Box<dyn std::error::Error>>
{
    use chio_settle::{
        RetryPolicy, SettlementOutcomeStore, SettlementRoute, SettlementRoutingInput,
    };

    let path = unique_db_path("chio-settlement-retention");
    let archive_path = unique_db_path("chio-settlement-retention-archive");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id_and_timestamp("rcpt-settlement-retention", 1);
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 1,
    };
    ReceiptStore::append_chio_receipt_with_pending_observation(&store, &receipt, &pending)?;
    store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;

    assert_eq!(
        store.archive_receipts_before(2, archive_path.to_str().ok_or("invalid archive path")?)?,
        0
    );
    assert!(store.load_chio_receipt(&receipt.id)?.is_some());
    assert_eq!(attempt_count(&store, &receipt.id)?, 1);

    let outcomes = crate::SqliteSettlementOutcomeStore::open_alongside(&store)?;
    let claim = outcomes
        .claim_receipt(&receipt.id, "retention-test", 1, 100)?
        .ok_or("settlement attempt was not claimable")?;
    assert_eq!(
        outcomes.record_claimed_outcome(
            &claim,
            &SettlementRoutingInput::Accepted,
            RetryPolicy::default(),
            1,
        )?,
        SettlementRoute::NoAction
    );

    assert_eq!(
        store.archive_receipts_before(2, archive_path.to_str().ok_or("invalid archive path")?)?,
        1
    );
    assert!(store.load_chio_receipt(&receipt.id)?.is_none());
    assert_eq!(attempt_count(&store, &receipt.id)?, 0);

    drop(outcomes);
    drop(store);
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(archive_path);
    Ok(())
}

#[test]
fn receipt_retention_supports_store_without_settlement_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-settlement-retention-legacy");
    let archive_path = unique_db_path("chio-settlement-retention-legacy-archive");
    let store = SqliteReceiptStore::open(&path)?;
    let receipt = sample_receipt_with_id_and_timestamp("rcpt-settlement-retention-legacy", 1);
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch("DROP TABLE settle_attempts")?;
        Ok(())
    })?;
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path)?;
    assert_eq!(
        ReceiptStore::atomic_receipt_projection(&reopened),
        chio_kernel::AtomicReceiptProjection::Unsupported
    );
    assert_eq!(
        reopened
            .archive_receipts_before(2, archive_path.to_str().ok_or("invalid archive path")?,)?,
        1
    );
    assert!(reopened.load_chio_receipt(&receipt.id)?.is_none());

    drop(reopened);
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(archive_path);
    Ok(())
}
