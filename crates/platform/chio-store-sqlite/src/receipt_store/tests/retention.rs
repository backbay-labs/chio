//! Retention behavior tests (co-archive-and-delete, watermark, chain
//! exemption, size convergence, recovery).

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{ReceiptStoreError, RetentionConfig};

use crate::SqliteReceiptStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "chio-{prefix}-{}-{nonce}.sqlite3",
        std::process::id()
    ))
}

#[test]
fn watermark_ledger_reports_max_and_rejects_regression() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{insert_receipt_retention_watermark, retention_watermark};
    let path = unique_db_path("watermark-ledger");
    let store = SqliteReceiptStore::open(&path)?;
    // A pristine store has never archived.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&connection)?, None);

    insert_receipt_retention_watermark(&connection, 10, 100, "archive.sqlite3", None, 1)?;
    insert_receipt_retention_watermark(&connection, 25, 200, "archive.sqlite3", None, 2)?;
    assert_eq!(retention_watermark(&connection)?, Some(25));

    // A rotation that would lower the watermark is rejected fail-closed.
    let regression =
        insert_receipt_retention_watermark(&connection, 20, 300, "archive.sqlite3", None, 3);
    let message = regression
        .err()
        .ok_or("expected RetentionWatermarkRegression")?
        .to_string();
    assert!(
        message.contains("retention watermark regression"),
        "unexpected error: {message}"
    );
    // The rejected write left the ledger unchanged.
    assert_eq!(retention_watermark(&connection)?, Some(25));

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn backfill_refuses_regeneration_over_checkpointed_range() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::support::validate_or_backfill_claim_receipt_log_entries;

    let path = unique_db_path("backfill-refuse");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let keypair = super::support::receipt_test_keypair();
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..2u64 {
            let receipt =
                super::support::sample_receipt_with_keypair(&format!("bf-{i}"), i + 1, &keypair);
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        // A checkpoint now covers [1, 2].
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
    }

    // Simulate a botched manual repair: empty the projection on a checkpointed
    // store by dropping the reject-delete guard and deleting the rows.
    let store = SqliteReceiptStore::open_existing(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM claim_receipt_log_entries;",
        )?;
        Ok(())
    })?;

    let connection = store.reader_connection_for_test()?;
    let error = validate_or_backfill_claim_receipt_log_entries(&connection, true);
    let message = error
        .err()
        .ok_or("expected ArchivedRangeProjection, backfill regenerated instead")?
        .to_string();
    assert!(
        message.contains("checkpointed or archived range"),
        "unexpected error: {message}"
    );
    // `chio receipt retention repair` only removes claim-log rows whose source
    // rows are already gone; with an empty projection it removes nothing and
    // leaves the store bricked, so the guidance must not point there. It must
    // name an applicable recovery instead.
    assert!(
        !message.contains("retention repair"),
        "must not point at the no-op retention repair for a missing projection: {message}"
    );
    assert!(
        message.contains("restore") && message.contains("backup"),
        "must direct operators to an applicable recovery path: {message}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Append two aged receipts (timestamp 100) checkpointed as [1,2] and four
/// fresh receipts (timestamp 500) checkpointed as [3,4] with 5..6 left
/// uncheckpointed, then genuinely archive the aged range so a real archive holds
/// the co-archived `[1, 2]` prefix and the live rows are deleted with the
/// watermark set to 2.
fn store_with_archived_first_checkpoint(
    path: &std::path::Path,
    archive_path: &str,
    keypair: &chio_core::crypto::Keypair,
) -> Result<SqliteReceiptStore, Box<dyn std::error::Error>> {
    let store = SqliteReceiptStore::open(path)?;
    store.enable_background_checkpoints(super::support::signer(keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-aged-{i}"),
            i + 1,
            100,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    for i in 2..6u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-fresh-{i}"),
            i + 1,
            500,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Archive only the aged first checkpoint's range [1,2]: the rows move to a
    // real archive, the live prefix is deleted, and the ledger records W=2.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2, "only the aged [1,2] batch archives");
    Ok(store)
}

#[test]
fn checkpoint_chain_watermark_exemption() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::verify_checkpoint_chain_integrity;

    let path = unique_db_path("chain-exemption");
    let archive = unique_db_path("chain-exemption-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // With the exemption the chain still verifies: checkpoint 1 (batch_end_seq
    // <= W = 2) skips the live Merkle rebuild and trusts the co-archived range;
    // checkpoint 2 (batch_end_seq 4 > W) is rebuilt as before.
    let connection = store.reader_connection_for_test()?;
    verify_checkpoint_chain_integrity(&connection)?;

    // Tamper with a claim-log row ABOVE the watermark: the chain must still
    // fail (the exemption never weakens verification above W).
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 3;",
        )?;
        Ok(())
    })?;
    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "tamper above the watermark must still fail the chain"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The watermark exemption must be backed by the archived evidence, not merely
/// by a matching checkpoint boundary and an absent live prefix. After a genuine
/// rotation the watermark is trusted, but once the archive that vouches for the
/// deleted prefix is gone the exemption is withdrawn fail-closed even though the
/// ledger and boundary are unchanged (the state an out-of-band prefix delete
/// plus a planted watermark would leave behind).
#[test]
fn watermark_trust_requires_backing_archive() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::trusted_retention_watermark;

    let path = unique_db_path("watermark-backing");
    let archive = unique_db_path("watermark-backing-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // Archive present and covering [1,2]: the watermark is trusted.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(trusted_retention_watermark(&connection)?, 2);
    drop(connection);

    // Remove the archive that backs the deleted prefix. The ledger row, the
    // matching checkpoint boundary, and the absent live prefix are all still in
    // place, but there is no longer any archived evidence to trust.
    std::fs::remove_file(&archive)?;
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "a watermark with no backing archive must not be trusted"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Co-archive-and-delete removes the source tables and the claim-log projection
/// together, so append, health, checkpoint status, and a fresh open() all
/// succeed after archival. (Deleting source rows while leaving the projection
/// behind would leave set drift that bricks the store on the next rotation.)
#[test]
fn retention_then_append_and_reopen_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-reopen");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("retention-reopen-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        // 4 aged receipts (old timestamps) get two checkpoints [1,2],[3,4];
        // 2 fresh receipts stay uncheckpointed and unaged.
        for i in 0..4u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("aged-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());

        // Archive everything older than timestamp 150 (all four aged rows).
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the two checkpointed aged batches archive");

        // The store is NOT bricked: append, health, and checkpoint status all
        // succeed AFTER archival.
        let fresh =
            super::support::sample_receipt_with_keypair_and_timestamp("fresh-0", 5, 500, &keypair);
        store.append_chio_receipt_returning_seq(&fresh)?;
        store.flush_receipt_writes()?;
        assert!(
            store.receipt_store_health()?.healthy,
            "store healthy post-archival"
        );
        assert!(store.receipt_checkpoint_status(Some(1))?.healthy);
    }

    // And a fresh open() succeeds (open-time seed runs the full verifier and
    // the watermark-aware chain walk against the co-archived range).
    let reopened = SqliteReceiptStore::open(&path)?;
    let more =
        super::support::sample_receipt_with_keypair_and_timestamp("fresh-1", 6, 600, &keypair);
    reopened.append_chio_receipt_returning_seq(&more)?;
    reopened.flush_receipt_writes()?;
    assert!(reopened.receipt_store_health()?.healthy);

    // The archived and live receipt-id sets partition the history with no
    // overlap: the four aged ids are gone from live, present in the archive.
    // The archive is a minimal evidence bundle (no live-only tables), so it is
    // consumed with open() (which rebuilds the checkpoint projections from the
    // co-archived kernel_checkpoints), not open_existing().
    let archive_store = SqliteReceiptStore::open(&archive)?;
    assert_eq!(archive_store.tool_receipt_count()?, 4);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A rotation must dispatch to the writer actor, never begin a write
/// transaction on a reader-pool connection (mirrors single_writer.rs
/// `reader_pool_never_begins_a_write_transaction`).
#[test]
fn reader_pool_never_rotates() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("reader-never-rotates");
    let store = SqliteReceiptStore::open(&path)?;
    // A rotation over an empty store is a no-op but still routes through the
    // &self -> Rotate-command path to the single writer.
    let archived = store.rotate_if_needed(&RetentionConfig::default())?;
    assert_eq!(archived, 0);
    // Pin a reader-pool connection read-only: it can never open the IMMEDIATE
    // (write) transaction the co-archive-and-delete needs, so retention could
    // only have executed on the writer actor.
    let reader = store.reader_connection_for_test()?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    let write_attempt = reader.execute("CREATE TABLE reader_probe (x INTEGER)", []);
    assert!(
        write_attempt.is_err(),
        "reader-pool connections must be read-only (retention runs on the writer)"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The retention watermark ledger is security-load-bearing (chain verification
/// trusts W to skip claim-log validation), so its append-only, strictly
/// monotonic guarantee is enforced by DB triggers, not only by the insert
/// helper. A raw UPDATE, a raw DELETE, and a non-monotonic INSERT are all
/// rejected by the database.
#[test]
fn watermark_ledger_db_triggers_reject_tamper() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::insert_receipt_retention_watermark;
    let path = unique_db_path("watermark-triggers");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;

    // Seed a legitimate mark through the helper (the trigger allows the first
    // strictly-increasing insert).
    insert_receipt_retention_watermark(&connection, 10, 100, "archive.sqlite3", None, 1)?;

    // A raw UPDATE is rejected by receipt_retention_watermark_reject_update.
    let updated = connection.execute(
        "UPDATE receipt_retention_watermark SET archived_through_entry_seq = 999",
        [],
    );
    assert!(
        updated.is_err(),
        "raw UPDATE of the watermark must be rejected"
    );

    // A raw DELETE is rejected by receipt_retention_watermark_reject_delete.
    let deleted = connection.execute("DELETE FROM receipt_retention_watermark", []);
    assert!(
        deleted.is_err(),
        "raw DELETE of the watermark must be rejected"
    );

    // A non-monotonic raw INSERT (equal to the current MAX) is rejected by
    // receipt_retention_watermark_reject_regression, even though it bypasses the
    // insert helper's own regression check.
    let equal = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at) \
         VALUES (10, 200, 'archive.sqlite3', NULL, 2)",
        [],
    );
    assert!(
        equal.is_err(),
        "a non-increasing raw INSERT must be rejected"
    );

    // A lower raw INSERT is likewise rejected.
    let lower = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at) \
         VALUES (5, 300, 'archive.sqlite3', NULL, 3)",
        [],
    );
    assert!(lower.is_err(), "a regressing raw INSERT must be rejected");

    // The ledger is unchanged: still exactly the one legitimate mark of 10.
    let (count, max_seq): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(archived_through_entry_seq), 0) FROM receipt_retention_watermark",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(max_seq, 10);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn tenant_scoped_rotation_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("tenant-rejected");
    let store = SqliteReceiptStore::open(&path)?;
    let config = RetentionConfig {
        tenant_id: Some("tenant-a".to_string()),
        ..RetentionConfig::default()
    };
    let error = store.rotate_if_needed(&config);
    let message = error
        .err()
        .ok_or("expected RetentionTenantScopeUnsupported")?
        .to_string();
    assert!(
        message.contains("tenant-scoped retention"),
        "unexpected: {message}"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn settlement_and_metered_rows_are_archived_not_cascaded() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("recon-archived");
    let archive = unique_db_path("recon-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("recon-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Attach a settlement + metered reconciliation row, and an authorization
    // consumption row, to the first receipt. All three sit in the archived
    // range (entry_seq <= W) because the receipt itself does.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'settled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-1', 1, 1, 'usd', NULL, 1, 'reconciled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            // chio_authorization_receipt_consumptions.authorization_receipt_id
            // is FK REFERENCES chio_tool_receipts(receipt_id), so it must name
            // an existing receipt; consumer_receipt_id/request_id/session_id/
            // tool_call_id/parameter_hash carry no FK, so arbitrary values
            // satisfy their NOT NULL constraints.
            connection.execute(
                "INSERT INTO chio_authorization_receipt_consumptions \
                 (authorization_receipt_id, consumer_receipt_id, request_id, session_id, tool_call_id, tenant_id, parameter_hash, consumed_at_unix_ms) \
                 VALUES (?1, 'consumer-recon-0', 'req-recon-0', 'sess-recon-0', 'tool-call-recon-0', NULL, 'hash-recon-0', 1000)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2);

    // Gone from live, present in the archive (co-archived, not cascaded away).
    let live = store.reader_connection_for_test()?;
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_settlement, 0, "settlement row absent from live");
    let live_metered: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_metered, 0, "metered row absent from live");
    let live_consumptions: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_consumptions, 0, "consumption row absent from live");
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let arch_settlement: i64 = arch.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_metered: i64 = arch.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_consumptions: i64 = arch.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(arch_settlement, 1, "settlement row co-archived");
    assert_eq!(arch_metered, 1, "metered row co-archived");
    assert_eq!(arch_consumptions, 1, "consumption row co-archived");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Settlement and metered reconciliation rows are mutated in place by ongoing
/// reconciliation upserts, so a rotation can copy a reconciliation row, have a
/// later update change it, and then abort under the write-locked co-archival
/// re-verify because the archive holds the pre-update bytes. The archive copy of
/// these mutable tables must REFRESH a conflicting stale row from the current
/// live row; an `INSERT OR IGNORE` retry would keep the stale bytes and leave
/// the prefix permanently unrotatable.
#[test]
fn rotation_refreshes_stale_reconciliation_archive_rows() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("recon-refresh");
    let archive = unique_db_path("recon-refresh-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("recon-refresh-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // The current (already reconciled) live rows for the first archived receipt.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'settled-final', 'live-note', 200)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-final', 42, 42, 'usd', NULL, 200, 'reconciled', 'live-note', 200)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    // Simulate the archive an earlier rotation left behind: a copy of the
    // reconciliation rows captured BEFORE the update above, so the archived
    // bytes are now stale. The bulk evidence tables are created and copied
    // faithfully by the rotation itself.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY, reconciliation_state TEXT NOT NULL,
                note TEXT, updated_at INTEGER NOT NULL
            );
            CREATE TABLE metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY, adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL, observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL, billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT, recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL, note TEXT, updated_at INTEGER NOT NULL
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
             VALUES (?1, 'settled-pending', 'stale-note', 100)",
            rusqlite::params![receipt_id],
        )?;
        seed.execute(
            "INSERT INTO metered_billing_reconciliations \
             (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
             VALUES (?1, 'test', 'ev-stale', 1, 1, 'usd', NULL, 100, 'pending', 'stale-note', 100)",
            rusqlite::params![receipt_id],
        )?;
    }

    // Rotation must refresh the stale archive rows and complete, not stall on
    // the pre-update bytes.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "rotation must refresh the stale archived reconciliation rows and complete"
    );

    // The archive now holds the current live reconciliation state.
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let settled_state: String = arch.query_row(
        "SELECT reconciliation_state FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settled_state, "settled-final",
        "the archived settlement row must refresh to the current live state"
    );
    let metered_units: i64 = arch.query_row(
        "SELECT observed_units FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_units, 42,
        "the archived metered row must refresh to the current live units"
    );

    // The live rows are gone (co-archived, not cascaded).
    let live = store.reader_connection_for_test()?;
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_settlement, 0, "settlement row absent from live");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn size_rotation_converges_below_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("size-converges");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("size-archive");
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
    for i in 0..64u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sz-{i}"),
            i + 1,
            100 + i,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    // Force the size branch: threshold just under the current live size.
    let before = store.live_db_size_bytes()?;
    let config = RetentionConfig {
        retention_days: u64::MAX, // disable the time branch
        max_size_bytes: before.saturating_sub(1),
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert!(archived > 0, "size trigger archived a checkpointed prefix");

    // After incremental_vacuum the live measured size drops below the
    // threshold, so a second rotation with the SAME config is a no-op (the
    // trigger converged, it did not re-fire).
    let after = store.live_db_size_bytes()?;
    assert!(
        after < before,
        "live size shrank after rotation ({after} < {before})"
    );
    let again = store.rotate_if_needed(&config)?;
    // Either the size is already below the (updated) threshold, or the only
    // remaining rows are uncheckpointed so W stays put: no runaway loop.
    assert!(again == 0 || store.live_db_size_bytes()? <= after);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Size-driven rotation must still make progress when many receipts share the
/// median timestamp (second-resolution or bursty traffic). A cutoff exactly at
/// the shared median blocks every checkpoint batch that contains a row at the
/// median, so the median cutoff must clear the shared timestamp; otherwise the
/// size trigger archives nothing and the DB never shrinks below the threshold.
#[test]
fn size_rotation_archives_when_median_timestamp_is_shared() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("size-shared-median");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("size-shared-median-archive");
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
    // Every receipt carries the SAME timestamp, so the median equals it too.
    for i in 0..64u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;

    let before = store.live_db_size_bytes()?;
    let config = RetentionConfig {
        retention_days: u64::MAX, // disable the time branch
        max_size_bytes: before.saturating_sub(1),
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert!(
        archived > 0,
        "size rotation must archive a checkpointed prefix even when the median timestamp is shared"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention triggers must age out CHILD-receipt evidence too. The threshold
/// resolver reads the claim receipt log, which projects both tool and child
/// receipts, not chio_tool_receipts alone; otherwise a store whose evidence is
/// child-only sees an empty tool table and never crosses the time trigger, so
/// aged child receipts would be retained forever even though the rotation path
/// co-archives child rows once a cutoff is chosen.
#[test]
fn child_only_evidence_ages_out_under_time_trigger() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-child-only");
    let archive = unique_db_path("retention-child-only-archive");
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged child receipts and NO tool receipts. Their claim-log entries form
    // a checkpointed batch far past any retention window.
    for i in 0..2u64 {
        let child = super::support::sample_child_receipt_with_keypair_and_timestamp(
            &format!("aged-child-{i}"),
            100,
            &keypair,
        );
        store.append_child_receipt_record(&child)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(1)?.is_some(),
        "the child-only prefix must be checkpointed before it can be archived"
    );

    let before = store.reader_connection_for_test()?;
    let tool_rows: i64 =
        before.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(tool_rows, 0, "the store holds child receipts only");
    let child_rows: i64 =
        before.query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(child_rows, 2, "two child receipts are live before rotation");

    // Time-driven rotation: the timestamp-100 receipts are far past a one-day
    // window; the size branch is disabled.
    let config = RetentionConfig {
        retention_days: 1,
        max_size_bytes: u64::MAX,
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    store.rotate_if_needed(&config)?;

    // The aged child prefix aged out. rotate_if_needed reports tool rows archived
    // (zero here), so assert directly on the live child rows.
    let after = store.reader_connection_for_test()?;
    let live_child: i64 =
        after.query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(
        live_child, 0,
        "aged child-only evidence must age out under the time trigger"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The time and size triggers are independent: a store over its size limit must
/// still rotate even when the age cutoff would archive nothing. A checkpoint ages
/// out only when its ENTIRE prefix is older than the cutoff, so a still-fresh
/// receipt at the head of the prefix blocks the age cutoff for every batch.
/// Resolving that no-op age cutoff and returning before the size check would
/// leave an oversized store oversized forever; the size cutoff must apply on the
/// same pass.
#[test]
fn size_trigger_applies_when_time_cutoff_is_a_noop() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-size-fallthrough");
    let archive = unique_db_path("retention-size-fallthrough-archive");
    let keypair = super::support::receipt_test_keypair();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // entry_seq -> timestamp. Entry 1 is still inside the 10-day window, so it
    // blocks the age cutoff for the whole prefix; entry 2 is well aged, so the
    // time trigger still fires. Entry 4 is brand new, so the median+1 size cutoff
    // frees only the first checkpoint batch [1,2], not [3,4].
    let timestamps = [
        now.saturating_sub(500_000),
        now.saturating_sub(2_000_000),
        now.saturating_sub(100_000),
        now,
    ];
    for (i, ts) in timestamps.iter().enumerate() {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("fallthrough-{i}"),
            (i + 1) as u64,
            *ts,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(
        store.load_checkpoint_by_seq(2)?.is_some(),
        "both checkpoint batches must be persisted before rotation"
    );

    // Time trigger fires (entry 2 is well past the 10-day window) but its cutoff
    // archives nothing (entry 1 is still fresh at the head of the prefix). The
    // store is over the size limit, so the size cutoff must free the first aged
    // checkpoint batch on the same pass.
    let config = RetentionConfig {
        retention_days: 10,
        max_size_bytes: 1,
        archive_path: archive.to_str().ok_or("archive path invalid")?.to_string(),
        ..RetentionConfig::default()
    };
    let archived = store.rotate_if_needed(&config)?;
    assert_eq!(
        archived, 2,
        "the size cutoff must free the first checkpoint batch even though the age cutoff is a no-op"
    );

    let after = store.reader_connection_for_test()?;
    let live_tool: i64 = after.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "the aged first batch was archived and deleted; the fresh batch stayed live"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation deletes evidence, so it must run on a verified chain. A store opened
/// with `incremental_verification = false` seeds its writer head via the cheap
/// `seed_head_snapshot`, which defers the full claim-log and checkpoint-chain
/// audit to the next append, so a Verified head is NOT proof of integrity in that
/// mode. A corrupt projection must make the rotation fail closed and delete
/// nothing, rather than archive-and-delete against an unaudited log.
#[test]
fn non_incremental_rotation_validates_chain_before_deleting(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-nonincremental-validate");
    let archive = unique_db_path("retention-nonincremental-validate-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a checkpointed prefix at timestamp 100 (older than the cutoff below).
    let receipt_id = {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        let mut first_id = String::new();
        for i in 0..2u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("nonincr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            if i == 0 {
                first_id = receipt.id.clone();
            }
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(
            store.load_checkpoint_by_seq(1)?.is_some(),
            "the prefix must be checkpointed so a rotation would otherwise archive it"
        );
        first_id
    };

    // Reopen with incremental_verification = false: the writer head is seeded via
    // the cheap snapshot without auditing the claim log.
    let store = SqliteReceiptStore::open_existing_with_options(
        &path,
        crate::SqliteStoreOptions {
            pool: crate::SqlitePoolConfig::default(),
            incremental_verification: false,
        },
    )?;
    assert!(!store.incremental_verification_enabled());

    // Corrupt a claim-log projection row. The snapshot seed never inspects it, so
    // only the full pre-rotation verification catches this.
    super::support::tamper_claim_log_tool_receipt(&store, &receipt_id, |receipt| {
        receipt.tool_name = "tampered".to_string();
    });

    // Rotation must fail closed on the corrupt chain rather than archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or(
            "rotation on a corrupt non-incremental chain must fail closed, not archive-and-delete",
        )?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the pre-rotation verification, got {error:?}"
    );

    // Fail-closed: nothing was deleted; the live evidence is intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "no evidence may be deleted when the chain is unverified"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no claim-log rows may be deleted when the chain is unverified"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation deletes evidence, so it must never run against a claim-log
/// projection that has already drifted from its source rows - even on an
/// incremental store, whose per-append verified head never re-checks a
/// retroactive source-row deletion. A store in the drift shape (source receipts
/// deleted, orphaned claim-log rows left behind) must make the rotation fail
/// closed and delete nothing, rather than co-archive the orphans without their
/// receipts and then delete the live claim log, destroying the evidence
/// `retention_repair` needs to recover.
#[test]
fn incremental_rotation_rejects_projection_drift() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("incremental-drift-rotation");
    let archive = unique_db_path("incremental-drift-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // A default open() store runs incremental verification, so the pre-rotation
    // checkpoint audit is skipped; only the projection audit can catch the drift.
    let store = SqliteReceiptStore::open(&path)?;
    assert!(store.incremental_verification_enabled());
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("id-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;

    // Fabricate the drift shape on the same live instance: co-archive the
    // claim-log for [1,2] and delete ONLY their source rows, leaving orphaned
    // claim-log rows. The incremental head stays Verified because it never
    // re-audits the retroactive source deletion.
    store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                   (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                    source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                    parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                    tool_name TEXT, raw_json TEXT NOT NULL); \
                 INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                   SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                 DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                 DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                 CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                   BEFORE DELETE ON chio_tool_receipts \
                   BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(())
        }
    })?;

    // The rotation must detect the projection drift and fail closed BEFORE any
    // archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation over a drifted projection must fail closed, not archive-and-delete")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the projection audit, got {error:?}"
    );

    // Fail-closed: the orphaned claim-log rows survive, so repair can still run.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// An incremental store's per-append verified head attests only NEW appends, so
/// it never notices a retroactive deletion of BOTH a checkpoint-covered source
/// row and its claim-log projection row. That drift leaves the source and
/// projection sets matching (the projection audit passes) while the covering
/// checkpoint's claim-log range falls short of its signed tree_size. Rotation
/// must audit the live checkpoint chain before deleting even in incremental
/// mode and fail closed, rather than co-archive only the survivors, delete the
/// rest, and stamp a watermark the archive can never back (a bricked store with
/// its remaining live evidence gone).
#[test]
fn incremental_rotation_audits_chain_before_deleting() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("incremental-chain-audit-rotation");
    let archive = unique_db_path("incremental-chain-audit-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // A default open() store runs incremental verification, so the per-append
    // head is trusted and the O(N) chain rebuild would otherwise be skipped.
    let store = SqliteReceiptStore::open(&path)?;
    assert!(store.incremental_verification_enabled());
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("id-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    // Checkpoint [1,2] covers entry_seq 1 and 2 with a signed tree_size of 2.
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Retroactively delete BOTH the source row and its claim-log row for a
    // checkpoint-[1,2]-covered receipt. The source and projection sets both lose
    // the same receipt, so they stay in agreement and the projection audit
    // passes; only the checkpoint chain audit notices the now-short covered range.
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
             DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM main.chio_tool_receipts WHERE seq = 2; \
             DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 2; \
             CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
               BEFORE DELETE ON chio_tool_receipts \
               BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
             CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
               BEFORE DELETE ON claim_receipt_log_entries \
               BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
        )?;
        Ok(())
    })?;

    // The rotation must detect the short checkpoint range and fail closed BEFORE
    // any archive-and-delete.
    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or(
            "rotation over an unaudited checkpoint chain must fail closed, not archive-and-delete",
        )?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict from the chain audit, got {error:?}"
    );

    // Fail-closed: the surviving live evidence for [1,2] was not deleted.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 1,
        "the surviving covered claim-log row must not be deleted when the chain is unaudited"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store reopened through `open_existing` holds READ_WRITE-without-CREATE
/// connection flags so that a missing main database fails closed. Because
/// `ATTACH DATABASE` inherits those flags, the first retention rotation against
/// such a store must still create its not-yet-existing sibling archive rather
/// than fail on the ATTACH. The rotation materializes the archive with CREATE
/// permission before attaching it, so the first rotation succeeds and the
/// archive appears.
#[test]
fn first_rotation_creates_archive_on_open_existing_store() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("open-existing-first-rotation");
    let archive = unique_db_path("open-existing-first-rotation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a store with a fully checkpointed prefix that will age past the
    // cutoff, then close it so the reopen exercises the open_existing flags.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("first-rotation-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(
            store.load_checkpoint_by_seq(1)?.is_some(),
            "the prefix must be checkpointed so the rotation has something to archive"
        );
    }

    // The first rotation is responsible for creating the archive; it must not
    // exist yet.
    assert!(
        !archive.exists(),
        "the archive must be absent before the first rotation"
    );

    // Reopen through open_existing (READ_WRITE without CREATE). Without the
    // pre-ATTACH archive creation the rotation fails here: the inherited
    // no-CREATE flags cannot create the sibling archive at ATTACH time.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "the aged checkpointed prefix archives on the first rotation"
    );
    assert!(
        archive.exists(),
        "the first rotation created the sibling archive database"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Rotation co-archives evidence and then deletes the live prefix, so it must
/// refuse a non-durable or self-aliasing archive target. An in-memory database
/// is destroyed on DETACH, and a path that aliases the live database makes
/// SQLite attach the live file itself; either way the delete would remove the
/// only copy of the archived evidence while still recording a watermark. The
/// rotation must fail closed and delete nothing.
#[test]
fn rotation_rejects_non_durable_or_aliasing_archive_path() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("nondurable-archive");
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("nd-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;

    // An in-memory archive target is destroyed on DETACH: the rotation must
    // reject it before archiving-and-deleting the live prefix.
    let memory_error = store
        .archive_receipts_before(150, ":memory:")
        .err()
        .ok_or("rotation into an in-memory archive must fail closed")?;
    assert!(
        matches!(memory_error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict over a non-durable archive, got {memory_error:?}"
    );

    // An archive path that aliases the live database is rejected the same way:
    // attaching the live file as `archive` would let the delete destroy the only
    // copy.
    let live_path = path.to_str().ok_or("db path invalid")?;
    let alias_error = store
        .archive_receipts_before(150, live_path)
        .err()
        .ok_or("rotation into a self-aliasing archive must fail closed")?;
    assert!(
        matches!(alias_error, ReceiptStoreError::Conflict(_)),
        "expected a fail-closed Conflict over a self-aliasing archive, got {alias_error:?}"
    );

    // Fail-closed: no evidence was deleted; the live prefix is intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 4,
        "no receipts may be deleted on a rejected archive target"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 4,
        "no claim-log rows may be deleted on a rejected archive target"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A rotation is an in-flight writer, so `dispatch_rotate` increments
/// `writer.inflight` before sending the Rotate
/// command and the actor's Rotate arm must decrement it on dequeue. Without the
/// decrement the counter leaks and `receipt_store_health().writer.inflight`
/// would report a permanently in-flight writer after any rotation.
#[test]
fn rotate_does_not_leak_inflight() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotate-inflight");
    let archive = unique_db_path("rotate-inflight-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("inflight-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Baseline: with every append drained, no writer is in flight.
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "baseline inflight must be zero after flush"
    );

    // A successful archival (two checkpointed batches age past the cutoff).
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the aged checkpointed prefix archives");

    // The rotation released its in-flight slot: the counter is back to baseline,
    // not permanently incremented.
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "a successful rotation must not leak an in-flight writer"
    );

    // A no-op rotation (nothing new to archive) also balances the counter.
    let again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(again, 0, "re-archiving the same aged prefix is a no-op");
    assert_eq!(
        store.receipt_store_health()?.writer.inflight,
        0,
        "a no-op rotation must not leak an in-flight writer either"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Watermark-aware chain verification skips the live Merkle rebuild for
/// checkpoints with `batch_end_seq <= W`, trusting
/// W from the retention ledger. The ledger's DB triggers enforce monotonicity
/// ONLY, not that W is a genuine archived-checkpoint boundary, so a forged,
/// strictly-larger W (past the latest real checkpoint) must NOT disable
/// verification for never-archived live ranges. W is trusted as a skip
/// exemption only when it matches a persisted checkpoint boundary; otherwise
/// verification falls back to a full rebuild (fail-closed).
#[test]
fn bogus_watermark_does_not_skip_verification() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{
        insert_receipt_retention_watermark, verify_checkpoint_chain_integrity,
    };

    let path = unique_db_path("bogus-watermark");
    let store = SqliteReceiptStore::open(&path)?;
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two checkpoints cover [1,2] and [3,4]; NOTHING is archived (every
    // claim-log row is still live), so honest verification fully rebuilds.
    for i in 0..4u64 {
        let receipt =
            super::support::sample_receipt_with_keypair(&format!("bw-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Forge a strictly-larger-but-bogus watermark: W = 100 is far beyond the
    // latest real checkpoint boundary (4) and matches no kernel_checkpoints
    // batch_end_seq. The monotonic-only ledger trigger accepts the first insert.
    store.writer_handle().run_write(|connection| {
        insert_receipt_retention_watermark(connection, 100, 100, "bogus-archive.sqlite3", None, 1)?;
        Ok(())
    })?;

    // Tamper a live claim-log row inside checkpoint 1's range [1,2]. The Merkle
    // rebuild for checkpoint 1 would now fail if (and only if) it actually runs.
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 1;",
        )?;
        Ok(())
    })?;

    // Fail-closed: because the bogus W does not correspond to a real archived
    // checkpoint boundary, verification must NOT skip the [1,2] range; it
    // rebuilds and catches the tamper. Trusting the bogus W would skip both
    // checkpoints and wrongly pass.
    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "a bogus watermark must not disable Merkle verification for un-archived ranges"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The co-archival completeness check must verify each archived table by
/// IDENTITY, not row-count. If the archive
/// file already holds a stale/conflicting row for a receipt in the archived
/// prefix (different bytes), the idempotent `INSERT OR IGNORE` copy keeps the
/// stale row and drops the live one, so a count-only check would pass while the
/// archived bytes diverge. Verification must FAIL fail-closed before any delete,
/// leaving the live rows intact.
#[test]
fn co_archival_rejects_conflicting_stale_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-conflict");
    let archive = unique_db_path("co-archival-conflict-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("conflict-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Pre-seed the archive file with a STALE, conflicting claim-log row for the
    // archived prefix: the same entry_seq (PK) as a live row that will be
    // archived, but with different bytes and a different receipt_id. The
    // rotation's `INSERT OR IGNORE` copy keeps this stale row (PK collision) and
    // drops the faithful live row, so a count-only co-archival check would pass
    // while the archived bytes diverge.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL,
                capability_id TEXT, session_id TEXT, parent_request_id TEXT,
                request_id TEXT, subject_key TEXT, issuer_key TEXT,
                tool_server TEXT, tool_name TEXT, raw_json TEXT NOT NULL
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO claim_receipt_log_entries \
             (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, raw_json) \
             VALUES (1, 'stale-conflict-id', 'tool_receipt', 1, 100, '{\"stale\":true}')",
            [],
        )?;
    }

    // Rotate: the co-archival identity check must reject the divergent archive
    // and abort fail-closed BEFORE any delete.
    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or(
            "expected RetentionArchiveIncomplete; rotation succeeded over a conflicting archive",
        )?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );

    // The live rows are intact: the abort happened before the delete.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no live claim-log rows deleted when co-archival verify fails"
    );
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival must verify capability lineage by identity too. The delete
/// removes the archived receipts but leaves the live lineage rows, so the
/// archive becomes the only standalone copy of those receipts' subject/issuer/
/// grants. A reused archive holding the same capability_id under divergent
/// lineage bytes is kept by the idempotent `INSERT OR IGNORE` copy, so a
/// count-only check would pass while the archived attribution diverges.
/// Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_conflicting_capability_lineage() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-cap-lineage");
    let archive = unique_db_path("co-archival-cap-lineage-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("cl-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // The sample receipts all carry capability_id "cap-1"; give it a live
    // lineage row so the co-archival copy has an attribution row to archive.
    store.writer_handle().run_write(|connection| {
        connection.execute(
            "INSERT INTO capability_lineage \
             (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id) \
             VALUES ('cap-1', 'subject-live', 'issuer-live', 1, 100, '[]', 0, NULL)",
            [],
        )?;
        Ok(())
    })?;

    // Pre-seed the archive with a CONFLICTING lineage row for the same
    // capability_id but divergent identity bytes. The rotation's INSERT OR
    // IGNORE copy keeps this stale row, so without an identity check the delete
    // would proceed and the standalone archive would misattribute the receipts.
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            r#"
            CREATE TABLE capability_lineage (
                capability_id TEXT PRIMARY KEY, subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT
            );
            "#,
        )?;
        seed.execute(
            "INSERT INTO capability_lineage \
             (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id) \
             VALUES ('cap-1', 'subject-stale', 'issuer-stale', 1, 100, '[]', 0, NULL)",
            [],
        )?;
    }

    // Rotate: the capability-lineage identity check must reject the divergent
    // archive and abort fail-closed BEFORE any delete.
    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete over a conflicting capability lineage")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete for capability_lineage"),
        "unexpected error: {message}"
    );

    // The live receipts are intact: the abort happened before any delete.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when capability-lineage verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The operator recovery path (`chio receipt retention repair --archive`): a
/// store bricked by source rows deleted with the claim-log projection rows left
/// behind can be repaired back to a writable, reopenable, healthy store.
#[test]
fn bricked_store_repair_restores_append() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("bricked-repair");
    let archive = unique_db_path("bricked-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a bricked store: archive + delete the source rows for a
    // checkpointed range but LEAVE the claim-log rows (the set-drift shape),
    // and copy the claim-log rows into the archive so repair can validate them.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("br-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate the bricked state: co-archive the claim-log for [1,2] into
        // the archive, then delete ONLY the source rows in live (leaving the
        // claim-log rows -> set drift).
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // The store is bricked: open() fails with set drift.
    assert!(
        SqliteReceiptStore::open(&path).is_err(),
        "store should be bricked pre-repair"
    );

    // Repair via open_existing (skips backfill), then append + open succeed.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert!(removed > 0, "repair removed the extra claim-log rows");
    drop(store);

    let repaired = SqliteReceiptStore::open(&path)?;
    let r =
        super::support::sample_receipt_with_keypair_and_timestamp("after-repair", 9, 900, &keypair);
    repaired.append_chio_receipt_returning_seq(&r)?;
    repaired.flush_receipt_writes()?;
    assert!(repaired.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store created before the retention migration and bricked by old deletes
/// has no watermark ledger, and repair opens it via `open_existing` (which does
/// not run the writable open() migration). Repair must create the ledger before
/// recording the repair watermark; otherwise the watermark insert fails on a
/// missing table, rolls the whole repair transaction back, and leaves the
/// legacy store unrepaired.
#[test]
fn repair_creates_missing_watermark_ledger_on_legacy_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("legacy-repair-watermark");
    let archive = unique_db_path("legacy-repair-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lg-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate a legacy bricked state: co-archive the claim-log for [1,2],
        // delete only the source rows (set drift), AND drop the watermark ledger
        // so the store looks like it predates the retention migration.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     DROP TABLE IF EXISTS receipt_retention_watermark;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // Repair via open_existing (skips backfill). Without the ledger creation the
    // watermark insert fails with "no such table: receipt_retention_watermark".
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert!(removed > 0, "repair removed the extra claim-log rows");
    drop(store);

    // The repair recorded a watermark and the store reopens healthy.
    let repaired = SqliteReceiptStore::open(&path)?;
    assert!(repaired.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival identity must pin the receipt-table primary key `seq`, not just
/// `receipt_id` + `raw_json`. The projection's `source_seq` (copied verbatim)
/// points at that `seq`, so an archive that already holds the same receipt under
/// a DIFFERENT `seq` (the idempotent copy keeps it on the `receipt_id` UNIQUE
/// conflict) would leave the archived projection pointing at the wrong source
/// row. Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_reused_seq_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-reused-seq");
    let archive = unique_db_path("co-archival-reused-seq-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("reused-seq-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Read the true bytes of the first receipt (seq 1), then pre-seed the archive
    // with that receipt under a DIVERGENT primary-key `seq`. The rotation's
    // INSERT OR IGNORE copy keeps this row on the receipt_id UNIQUE conflict, so
    // a receipt_id+raw_json-only check would pass while source_seq points nowhere.
    let (receipt_id, raw_json): (String, String) = {
        let live = store.reader_connection_for_test()?;
        live.query_row(
            "SELECT receipt_id, raw_json FROM chio_tool_receipts WHERE seq = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?
    };
    {
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(
            "CREATE TABLE chio_tool_receipts (\
                seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL, \
                capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT, grant_index INTEGER, \
                tool_server TEXT NOT NULL, tool_name TEXT NOT NULL, decision_kind TEXT NOT NULL, \
                policy_hash TEXT NOT NULL, content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT);",
        )?;
        seed.execute(
            "INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES (9001, ?1, 100, 'cap', 'srv', 'tool', 'allow', 'ph', 'ch', ?2)",
            rusqlite::params![receipt_id, raw_json],
        )?;
    }

    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; rotation accepted a reused-seq archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("chio_tool_receipts"),
        "the seq mismatch must fail the tool-receipt identity check: {message}"
    );

    // Fail-closed: the abort happened before any delete, so live rows are intact.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "claim-log intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Co-archival identity must cover the FULL receipt row, not just
/// `seq`/`receipt_id`/`raw_json`. Archive reads filter on the indexed/attribution
/// columns (`subject_key`, `issuer_key`, `grant_index`, `tenant_id`), so a reused
/// archive whose row matches those three columns but diverges on an attribution
/// column would misattribute the retained receipt once the live row is deleted.
/// Verification must FAIL fail-closed before any delete.
#[test]
fn co_archival_rejects_divergent_attribution_columns() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("co-archival-attribution");
    let archive = unique_db_path("co-archival-attribution-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("attr-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());

    // Pre-seed the archive with a copy of the true seq-1 receipt that is byte
    // identical on every column EXCEPT `subject_key`. Copying from the live DB
    // (naming columns, not `SELECT *`) keeps seq/receipt_id/raw_json exactly
    // equal to live; only the attribution column is then tampered. The rotation's
    // INSERT OR IGNORE copy keeps this row on the seq primary-key conflict, so a
    // seq/receipt_id/raw_json-only check would pass while the archived attribution
    // silently diverges from the receipt being deleted.
    {
        let live_path = path.to_str().ok_or("db path invalid")?.replace('\'', "''");
        let seed = rusqlite::Connection::open(&archive)?;
        seed.execute_batch(&format!("ATTACH DATABASE '{live_path}' AS live;"))?;
        seed.execute_batch(
            "CREATE TABLE chio_tool_receipts (\
                seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL, \
                capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT, grant_index INTEGER, \
                tool_server TEXT NOT NULL, tool_name TEXT NOT NULL, decision_kind TEXT NOT NULL, \
                policy_hash TEXT NOT NULL, content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT);",
        )?;
        seed.execute_batch(
            "INSERT INTO chio_tool_receipts \
             (seq, receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, \
              tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json, tenant_id) \
             SELECT seq, receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, \
              tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json, tenant_id \
             FROM live.chio_tool_receipts WHERE seq = 1;",
        )?;
        // Tamper ONLY the attribution: a value guaranteed to differ from the live
        // subject_key whether that was NULL or a real key.
        seed.execute(
            "UPDATE chio_tool_receipts SET subject_key = 'tampered-attribution-' || COALESCE(subject_key, '') WHERE seq = 1",
            [],
        )?;
        seed.execute_batch("DETACH DATABASE live;")?;
    }

    let result = store.archive_receipts_before(150, archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; rotation accepted a divergent-attribution archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("chio_tool_receipts"),
        "the attribution mismatch must fail the tool-receipt identity check: {message}"
    );

    // Fail-closed: the abort happened before any delete, so live rows are intact
    // with their true attribution.
    let live = store.reader_connection_for_test()?;
    let live_tool: i64 = live.query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        live_tool, 2,
        "tool receipts intact when co-archival verify fails"
    );
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "claim-log intact when co-archival verify fails"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair must validate the archived copy by IDENTITY before deleting
/// the orphaned live claim-log row, not merely by `receipt_id` presence. A reused
/// or wrong archive that carries the receipt under a divergent `source_seq` (or
/// any other column) would otherwise pass, and deleting the live row would leave
/// no faithful archived evidence behind.
#[test]
fn repair_rejects_divergent_archive_identity() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-divergent-archive");
    let archive = unique_db_path("repair-divergent-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("dv-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Fabricate the bricked state, but co-archive a DIVERGENT projection: same
        // receipt_id and entry_seq, wrong source_seq. Then delete the source rows
        // for [1,2], leaving orphaned claim-log rows.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, session_id, \
                        parent_request_id, request_id, subject_key, issuer_key, tool_server, tool_name, raw_json) \
                       SELECT entry_seq, receipt_id, receipt_kind, source_seq + 500, timestamp, capability_id, session_id, \
                        parent_request_id, request_id, subject_key, issuer_key, tool_server, tool_name, raw_json \
                       FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected RetentionArchiveIncomplete; repair trusted a divergent archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );

    // Fail-closed: the orphaned rows survive, so no faithful evidence was lost.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive a rejected repair"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair rounds the watermark up to a checkpoint boundary. When the
/// orphaned rows cover only PART of that batch, the rows above them may still
/// have live source receipts; stamping the watermark there would mark them
/// archived and skip their Merkle rebuild forever. Repair must refuse a partial
/// batch fail-closed.
#[test]
fn repair_refuses_partial_checkpoint_batch() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-partial-batch");
    let archive = unique_db_path("repair-partial-batch-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        // One checkpoint covers the whole batch [1,4] (max_batch 4).
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("pb-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        assert!(
            store.load_checkpoint_by_seq(2)?.is_none(),
            "one batch [1,4]"
        );
        // Orphan ONLY rows 1..=2 (co-archive faithfully, delete their source
        // rows), leaving rows 3..=4 with live source receipts inside the same
        // checkpoint batch.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a partial-batch refusal; repair watermarked live rows")?
        .to_string();
    assert!(
        message.contains("partially archived batch"),
        "unexpected error: {message}"
    );

    // Fail-closed: no watermark was recorded and the orphans survive.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned claim-log rows must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair stamps a checkpoint-aligned watermark that trusts the whole
/// [1, rounded] prefix as archived and skips its Merkle rebuild. Verifying only
/// the surviving orphaned rows is not enough: a botched rotation may also have
/// deleted some projection rows in that prefix outright, and if the archive
/// never held them the repair would seal an incomplete archive behind a trusted
/// watermark. Repair must verify a faithful archive row for every entry in the
/// prefix and refuse otherwise.
#[test]
fn repair_refuses_incomplete_prefix_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-incomplete-prefix");
    let archive = unique_db_path("repair-incomplete-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        // One checkpoint covers the whole batch [1,4] (max_batch 4), so the
        // repair rounds up to boundary 4.
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("ip-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Fabricate a damaged store: archive ONLY the claim-log rows [3,4]
        // faithfully and orphan them (delete their source rows), while rows [1,2]
        // are deleted OUTRIGHT from both source AND projection and never archived.
        // The surviving orphans [3,4] pass the per-extra identity check, but the
        // prefix [1,4] the boundary would seal is missing [1,2] in the archive.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq IN (3, 4); \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim_receipt_log_entries is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected an incomplete-archive refusal; repair sealed a partial archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("claim_receipt_log_entries"),
        "the missing prefix rows must fail the claim-log completeness check: {message}"
    );

    // Fail-closed: no watermark was recorded and the surviving orphans remain.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "surviving orphan rows must remain after the refusal"
    );
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(
        watermark, None,
        "no watermark may be stamped over an incomplete archive"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A botched rotation can record a watermark and then fail before removing the
/// orphaned claim-log rows it left behind. Re-running repair rounds to the same
/// boundary the watermark already covers; an unconditional re-insert would hit
/// the ledger's monotonic-insert trigger and roll the whole repair back, so the
/// store could never be cleaned up. Repair must skip the redundant watermark
/// insert and still remove the orphans.
#[test]
fn repair_is_idempotent_when_watermark_already_covers_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-idempotent-watermark");
    let archive = unique_db_path("repair-idempotent-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("iw-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Simulate the partial-failure state in one write: co-archive the
        // claim-log for [1,2], delete ONLY their source rows (leaving the
        // orphaned claim-log rows), and record the watermark the botched rotation
        // stamped at boundary 2 before it crashed.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                // The ledger must name the real archive the botched rotation
                // co-archived [1,2] into, so the reopen's watermark check finds
                // the backing evidence.
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    &archive_path,
                    None,
                    1,
                )?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 2, "repair removes the orphaned claim-log rows");

    // The orphans are gone and the watermark still sits at the covered boundary.
    let live = store.reader_connection_for_test()?;
    let orphans: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(orphans, 0, "orphaned claim-log rows must be removed");
    let watermark: Option<i64> = live.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(watermark, Some(2), "the covering watermark is preserved");
    drop(live);
    drop(store);

    // The repaired store reopens healthy.
    let reopened = SqliteReceiptStore::open(&path)?;
    assert!(reopened.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store whose entire checkpointed history was archived has legitimately empty
/// source tables AND an empty projection. The next writable `open()` must NOT
/// brick it on the empty-projection backfill guard just because a checkpoint or
/// watermark exists; there is nothing to regenerate.
#[test]
fn fully_archived_store_reopens_writable() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("fully-archived-reopen");
    let archive = unique_db_path("fully-archived-reopen-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole history archives");
    }

    // Reopen writable: the empty expected + empty existing case must be accepted.
    let reopened = SqliteReceiptStore::open(&path)?;
    assert!(reopened.receipt_store_health()?.healthy);
    // And the store is still appendable after the full-prefix rotation.
    let fresh =
        super::support::sample_receipt_with_keypair_and_timestamp("fr-fresh", 9, 900, &keypair);
    reopened.append_chio_receipt_returning_seq(&fresh)?;
    reopened.flush_receipt_writes()?;
    assert!(reopened.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// After a full-prefix rotation the live claim-log table is empty, so the
/// writable checkpoint-status path must floor committed progress at the
/// retention watermark just like the read-only health path. Otherwise it
/// reports committed progress regressing to 0 while the checkpoint chain still
/// sits at the archived boundary W, corrupting health and metrics.
#[test]
fn checkpoint_status_floors_committed_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("status-floor-watermark");
    let archive = unique_db_path("status-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sf-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    let status = store.receipt_checkpoint_status(None)?;
    assert_eq!(
        status.retention_watermark_entry_seq,
        Some(4),
        "the watermark records the fully archived boundary"
    );
    assert_eq!(
        status.latest_checkpointed_entry_seq, 4,
        "the checkpoint chain still sits at the archived boundary"
    );
    assert_eq!(
        status.latest_committed_entry_seq, 4,
        "committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Direct trait callers read committed progress from `latest_committed_entry_seq`.
/// After a full-prefix rotation empties the live claim-log table, its raw
/// MAX(entry_seq) is 0 while the checkpoint chain and retention watermark still
/// sit at the archived boundary W. This accessor must fold in the archived
/// prefix like the status/health/flush paths, otherwise a `ReceiptStore` caller
/// sees committed regress to 0 until the next append.
#[test]
fn latest_committed_entry_seq_floors_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("committed-floor-watermark");
    let archive = unique_db_path("committed-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lc-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    assert_eq!(
        store.latest_committed_entry_seq()?,
        4,
        "committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// After a full-prefix rotation, removing the backing archive withdraws the
/// watermark's trust, so the checkpoint chain fails to verify: status reports a
/// checkpoint_error while the committed floor still sits at the archived
/// boundary W. `receipt_store_health` must surface that prepared unhealthy
/// report, not re-probe the [1, W] range whose rows retention already deleted -
/// a probe that would turn the report into a hard error and hide the
/// checkpoint_error operators need.
#[test]
fn health_reports_checkpoint_error_without_probing_archived_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("health-missing-archive");
    let archive = unique_db_path("health-missing-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("hm-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    // Remove the archive backing the deleted [1,4] prefix. The watermark is no
    // longer trusted, so chain verification fails and the committed floor (W = 4)
    // now looks like a backlog over rows retention deleted.
    std::fs::remove_file(&archive)?;

    let report = store.receipt_store_health()?;
    assert!(!report.healthy, "a missing backing archive is unhealthy");
    assert!(
        report.checkpoint_error.is_some(),
        "the checkpoint_error must be surfaced, not swallowed by a hard error from probing deleted rows"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// An authorization receipt in an aged checkpointed prefix whose consumer
/// receipt is still live must not be archived-and-deleted: doing so would strand
/// the live consumer's `chio_authorization_receipt_consumptions` binding. The
/// watermark must stop below the authorization so the whole pair archives
/// together on a later rotation, and the live binding survives in the meantime.
#[test]
fn rotation_preserves_binding_for_live_consumer_of_aged_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("live-consumer-binding");
    let archive = unique_db_path("live-consumer-binding-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The
    // authorization sits at entry 3 (aged) and its consumer at entry 5 (fresh),
    // so a naive cutoff would archive the authorization while the consumer stays
    // live and split their binding.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lb-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lb-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let authorization_id = receipt_id_at(3)?;
    let consumer_id = receipt_id_at(5)?;
    store.writer_handle().run_write({
        let authorization_id = authorization_id.clone();
        let consumer_id = consumer_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO chio_authorization_receipt_consumptions \
                 (authorization_receipt_id, consumer_receipt_id, request_id, session_id, tool_call_id, tenant_id, parameter_hash, consumed_at_unix_ms) \
                 VALUES (?1, ?2, 'req-lb', 'sess-lb', 'call-lb', NULL, 'hash-lb', 1000)",
                rusqlite::params![authorization_id, consumer_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged authorization at entry 3), not
    // advance to 4 and strand the live consumer's binding.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below the authorization whose consumer is still live"
    );

    let live = store.reader_connection_for_test()?;
    let surviving: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        surviving, 1,
        "the live consumer's authorization-consumption binding must survive the rotation"
    );
    let binding: (String, String) = live.query_row(
        "SELECT authorization_receipt_id, consumer_receipt_id \
         FROM chio_authorization_receipt_consumptions",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    assert_eq!(
        binding,
        (authorization_id.clone(), consumer_id),
        "the surviving binding must still bind the live consumer to its authorization"
    );
    let authorization_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![authorization_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        authorization_live, 1,
        "the authorization backing the live binding must remain live"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A surviving child receipt records its parent in
/// `receipt_lineage_statements.parent_receipt_id`, and lineage verification
/// resolves that parent only in the live receipt tables. Rotation must not
/// advance the watermark past a lineage parent whose child is still live, or the
/// child would lose its verified parent and governed call-chain validation would
/// fail for a session whose parent just aged out.
#[test]
fn rotation_preserves_live_child_lineage_parent() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("lineage-parent-preserve");
    let archive = unique_db_path("lineage-parent-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The lineage
    // parent sits at entry 3 (aged) and its child at entry 5 (fresh), so a naive
    // cutoff would archive the parent while the child stays live and strand the
    // child's verified lineage.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lp-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lp-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let parent_id = receipt_id_at(3)?;
    let child_id = receipt_id_at(5)?;
    // The live child (entry 5) records the aged receipt (entry 3) as its lineage
    // parent.
    store.writer_handle().run_write({
        let parent_id = parent_id.clone();
        let child_id = child_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO receipt_lineage_statements \
                 (receipt_id, statement_id, request_id, session_id, session_anchor_id, chain_id, \
                  parent_request_id, parent_receipt_id, evidence_class, evidence_sources_json, \
                  verified_session_anchor, verified_parent_request, verified_parent_receipt, \
                  replay_protected, recorded_at, source_kind, json_sha256, raw_json) \
                 VALUES (?1, 'stmt-lp', NULL, NULL, NULL, 'chain-lp', NULL, ?2, 'delegated', NULL, \
                         0, 0, 1, 0, 500, 'test', 'sha-lp', '{\"schema\":\"lineage\"}')",
                rusqlite::params![child_id, parent_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged parent at entry 3), not
    // advance to 4 and delete the parent the live child still points at.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below the lineage parent whose child is still live"
    );

    let live = store.reader_connection_for_test()?;
    let parent_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        parent_live, 1,
        "the lineage parent backing the live child must remain live"
    );
    let parent_receipt_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        parent_receipt_live, 1,
        "the parent's source receipt must survive so lineage verification can resolve it"
    );
    let lineage_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1 AND parent_receipt_id = ?2",
        rusqlite::params![child_id, parent_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        lineage_live, 1,
        "the live child's lineage row must still bind it to the surviving parent"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A receipt whose settlement reconciliation is still `open` hosts the only live
/// row the reconciliation upsert and operator reports can act on, and the upsert
/// requires that receipt to still exist in `chio_tool_receipts`. Rotation must
/// not advance the watermark past an aged receipt with a nonterminal
/// reconciliation, or the actionable item vanishes and the next reconciliation
/// attempt fails NotFound. Once the reconciliation reaches a terminal state a
/// later rotation archives the receipt and its reconciliation together.
#[test]
fn rotation_preserves_receipt_with_open_settlement_reconciliation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("open-settlement-preserve");
    let archive = unique_db_path("open-settlement-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Checkpoints [1,2] and [3,4] are fully aged; [5,6] is fresh. The receipt at
    // entry 3 (aged) carries an open settlement reconciliation, so a naive cutoff
    // would archive it and strand its only live, actionable reconciliation row.
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("os-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("os-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let receipt_id = receipt_id_at(3)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'open', NULL, 500)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    // The watermark must stop at 2 (below the aged receipt at entry 3), not
    // advance to 4 and delete the only live row the reconciliation can update.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below a receipt whose settlement reconciliation is still open"
    );

    let live = store.reader_connection_for_test()?;
    let settlement_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settlement_live, 1,
        "the open reconciliation row must survive so a later reconciliation can update it"
    );
    let receipt_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        receipt_live, 1,
        "the receipt backing the open reconciliation must remain live for the upsert path"
    );
    drop(live);

    // The reconciliation reaches a terminal state; a later rotation now archives
    // the receipt and its reconciliation together.
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "UPDATE settlement_reconciliations SET reconciliation_state = 'reconciled', updated_at = 600 \
                 WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    let archived_again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived_again, 2,
        "once the reconciliation is terminal the later rotation archives the [3,4] pair"
    );
    let live = store.reader_connection_for_test()?;
    let settlement_after: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        settlement_after, 0,
        "the terminal reconciliation archives with its receipt on the later rotation"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The same pin applies to metered-billing reconciliations and to the
/// `retry_scheduled` state: an aged receipt whose metered-billing reconciliation
/// is still awaiting a scheduled retry must not be archived out from under the
/// row a later reconciliation attempt needs to resolve. Once the reconciliation
/// is terminal a later rotation archives the pair.
#[test]
fn rotation_preserves_receipt_with_scheduled_metered_reconciliation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("scheduled-metered-preserve");
    let archive = unique_db_path("scheduled-metered-preserve-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-aged-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 4..6u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("sm-fresh-{i}"),
            i + 1,
            500,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(3)?.is_some());

    let receipt_id_at = |entry_seq: i64| -> Result<String, Box<dyn std::error::Error>> {
        let connection = store.reader_connection_for_test()?;
        Ok(connection.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            rusqlite::params![entry_seq],
            |row| row.get::<_, String>(0),
        )?)
    };
    let receipt_id = receipt_id_at(3)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-sm', 1, 1, 'usd', NULL, 500, 'retry_scheduled', NULL, 500)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 2,
        "the watermark must stop below a receipt whose metered-billing reconciliation is scheduled"
    );
    let live = store.reader_connection_for_test()?;
    let metered_live: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_live, 1,
        "the scheduled reconciliation row must survive for the pending retry"
    );
    drop(live);

    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "UPDATE metered_billing_reconciliations SET reconciliation_state = 'ignored', updated_at = 600 \
                 WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    let archived_again = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived_again, 2,
        "once the reconciliation is terminal the later rotation archives the [3,4] pair"
    );
    let live = store.reader_connection_for_test()?;
    let metered_after: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        metered_after, 0,
        "the terminal reconciliation archives with its receipt on the later rotation"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// `chio receipt flush` reads committed progress from `flush_report`. After a
/// full-prefix rotation deletes every live claim-log row, the live MAX(entry_seq)
/// is 0 while the checkpoint chain and retention watermark still sit at the
/// archived boundary W. Flush committed progress must fold in the archived
/// prefix; a report that regressed to 0 would contradict health/status and
/// corrupt operator flush metrics.
#[test]
fn flush_report_floors_committed_at_watermark_after_full_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("flush-floor-watermark");
    let archive = unique_db_path("flush-floor-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ff-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 4, "the whole history archives");

    let report = store.flush_receipt_writes()?;
    assert_eq!(
        report.latest_checkpointed_entry_seq, 4,
        "the checkpoint chain still sits at the archived boundary"
    );
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "flush committed progress must fold in the archived prefix, not regress to 0"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A handle whose cached head is behind a checkpoint that a DIFFERENT handle
/// created and then archived must still report the archived boundary as
/// checkpointed. `flush` folds in the persisted latest checkpoint, but its live
/// claim-log rows were co-archived and deleted, so the persisted-checkpoint
/// validation must honor the archival watermark exemption (as the full chain
/// walk does). Without it flush discards the checkpoint and reports a stale
/// `checkpointed_entry_seq` with a spurious uncheckpointed range.
#[test]
fn flush_reports_watermark_covered_checkpoint_from_stale_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("flush-stale-head-watermark");
    let archive = unique_db_path("flush-stale-head-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Instance A checkpoints [1,2] and keeps its cached head at boundary 2.
    let store_a = SqliteReceiptStore::open(&path)?;
    store_a.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("fs-a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store_a.append_chio_receipt_returning_seq(&r)?;
    }
    store_a.flush_receipt_writes()?;
    assert!(store_a.load_checkpoint_by_seq(1)?.is_some());

    // A second instance appends [3,4], builds checkpoint 2 (boundary 4), then
    // archives the ENTIRE checkpointed history: every live claim-log row is
    // deleted and the watermark is set to 4. Instance A stays idle, so its cached
    // head never advances past boundary 2.
    {
        let store_b = SqliteReceiptStore::open_existing(&path)?;
        store_b.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 2..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fs-b-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store_b.append_chio_receipt_returning_seq(&r)?;
        }
        store_b.flush_receipt_writes()?;
        assert!(store_b.load_checkpoint_by_seq(2)?.is_some());
        let archived = store_b.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole checkpointed history archives");
    }

    // Flush through the stale instance A. Its head sits at boundary 2, so the
    // report must fold in the persisted checkpoint 2 (boundary 4) even though the
    // live rows for its range are gone behind the watermark.
    let report = store_a.flush_receipt_writes()?;
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "committed progress folds in the archived prefix"
    );
    assert_eq!(
        report.latest_checkpointed_entry_seq, 4,
        "a watermark-covered persisted checkpoint must still be reported as checkpointed"
    );
    assert_eq!(
        report.uncheckpointed_start_seq, None,
        "a fully-checkpointed, fully-archived store has no uncheckpointed range"
    );
    assert_eq!(report.uncheckpointed_end_seq, None);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The read-only health path must survive a store created before the retention
/// migration: a missing watermark ledger is "never archived" (None), not a hard
/// error that denies the observer every health report.
#[test]
fn read_only_health_ok_on_pre_retention_schema() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("read-only-pre-retention");
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..2u64 {
            let r =
                super::support::sample_receipt_with_keypair(&format!("pr-{i}"), i + 1, &keypair);
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Simulate a pre-retention schema by dropping the watermark ledger the
        // migration would have created. A read-only observer opens without the
        // writable migration, so it must tolerate the missing table.
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("DROP TABLE IF EXISTS receipt_retention_watermark;")?;
            Ok(())
        })?;
        store.flush_receipt_writes()?;
    }

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path)?;
    assert!(
        report.healthy,
        "a pre-retention store must still report health to a read-only observer"
    );
    assert_eq!(report.retention_watermark_entry_seq, None);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A watermark that merely MATCHES a checkpoint boundary is not proof of
/// archival. If the covered rows are still live (a raw INSERT at a real
/// boundary), verification must NOT skip their Merkle rebuild; corruption below
/// the forged boundary must still be caught fail-closed.
#[test]
fn boundary_matching_watermark_over_live_prefix_does_not_skip_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{
        insert_receipt_retention_watermark, verify_checkpoint_chain_integrity,
    };

    let path = unique_db_path("boundary-live-watermark");
    let store = SqliteReceiptStore::open(&path)?;
    let keypair = super::support::receipt_test_keypair();
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two checkpoints cover [1,2] and [3,4]; NOTHING is archived.
    for i in 0..4u64 {
        let receipt =
            super::support::sample_receipt_with_keypair(&format!("bm-{i}"), i + 1, &keypair);
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Forge W = 2: a REAL checkpoint boundary (checkpoint 1's batch_end), but the
    // covered rows [1,2] are never deleted. Then tamper a still-live row in that
    // range. A boundary-only exemption would skip the [1,2] rebuild and pass.
    store.writer_handle().run_write(|connection| {
        insert_receipt_retention_watermark(connection, 2, 100, "phantom-archive.sqlite3", None, 1)?;
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 1;",
        )?;
        Ok(())
    })?;

    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "a boundary-matching watermark over a live prefix must not skip verification"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A writer whose verified head is behind a checkpoint another handle archived
/// must still catch up across the boundary. The incremental catch-up path must
/// honor the same archival-watermark exemption as the full chain walk; otherwise
/// it rebuilds the deleted prefix from the live claim log and fails.
#[test]
fn catch_up_honors_archival_watermark_exemption() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("catch-up-watermark");
    let archive = unique_db_path("catch-up-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    // Checkpoints cover [1,2] and [3,4]; the aged [1,2] range is genuinely
    // archived (real archive, watermark W=2, live prefix deleted).
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // A fresh (behind) verified head catching up from seq 0 to seq 2 must process
    // checkpoint 1, whose range [1,2] was archived. Without the exemption the
    // rebuild from the emptied prefix fails; with it (backed by the real archive)
    // the head advances cleanly.
    let connection = store.reader_connection_for_test()?;
    let mut head = crate::receipt_store::VerifiedHead::default();
    crate::receipt_store::catch_up_verified_head_to(&connection, &mut head, 2)?;
    assert_eq!(
        head.checkpoint_seq(),
        2,
        "the head must catch up across the archived boundary"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A full-prefix rotation deletes every live claim-log row, so the read-only
/// watchdog sees a live MAX(entry_seq) of 0 while the latest checkpoint still
/// sits at the archived watermark. Committed progress must fold in the archived
/// prefix so a healthy, fully-archived store is not reported as behind.
#[test]
fn read_only_health_floors_committed_at_watermark() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("read-only-fully-archived");
    let archive = unique_db_path("read-only-fully-archived-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("fa-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        // Archive the entire checkpointed history: every live claim-log row goes.
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the whole history archives");
        store.flush_receipt_writes()?;
    }

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path)?;
    assert!(
        report.healthy,
        "a fully-archived store must read healthy from the read-only watchdog"
    );
    assert_eq!(report.retention_watermark_entry_seq, Some(4));
    assert_eq!(
        report.latest_committed_entry_seq, 4,
        "committed progress must be floored at the archival watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The watermark-trust reader opens the archive by the path recorded in the
/// ledger, so that path must be absolute: a relative or otherwise non-canonical
/// path resolves against whatever working directory the reader runs in, so a
/// restart or a CLI health check launched elsewhere would find no archive and
/// withdraw the exemption. Give a rotation a non-canonical path (routed through
/// a symlinked directory) and assert the ledger records the resolved location.
#[cfg(unix)]
#[test]
fn rotation_records_absolute_archive_path() -> Result<(), Box<dyn std::error::Error>> {
    let dir = unique_db_path("abs-archive-dir");
    std::fs::create_dir_all(&dir)?;
    let real_archive = dir.join("archive.sqlite3");
    let link = dir.join("dirlink");
    std::os::unix::fs::symlink(&dir, &link)?;
    // Absolute but non-canonical: dir/dirlink/archive.sqlite3 resolves through
    // the symlink to dir/archive.sqlite3.
    let noncanonical = link.join("archive.sqlite3");
    let noncanonical_str = noncanonical.to_str().ok_or("archive path not utf-8")?;

    let path = unique_db_path("abs-archive-store");
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, noncanonical_str, &keypair)?;

    let connection = store.reader_connection_for_test()?;
    let stored: String = connection.query_row(
        "SELECT archive_path FROM receipt_retention_watermark \
         ORDER BY archived_through_entry_seq DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    drop(connection);

    let canonical = std::fs::canonicalize(&real_archive)?;
    let canonical_str = canonical.to_str().ok_or("canonical path not utf-8")?;
    assert_eq!(
        stored, canonical_str,
        "the ledger must record the canonical absolute archive path"
    );
    assert_ne!(
        stored, noncanonical_str,
        "the ledger must not record the non-canonical input path verbatim"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Once the first rotation deletes the archived prefix it can never re-copy
/// those rows, so a later rotation pointed at a DIFFERENT archive would write
/// only the newer suffix there and strand the earlier prefix in the original
/// file, splitting one logical archive across two files that neither alone can
/// satisfy. A rotation whose archive path differs from the one an earlier
/// rotation committed to must be rejected fail-closed before any copy or delete.
#[test]
fn rotation_rejects_archive_path_change_after_first() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("archive-path-change");
    let archive_a = unique_db_path("archive-path-change-a");
    let archive_b = unique_db_path("archive-path-change-b");
    let archive_a_path = archive_a.to_str().ok_or("archive path invalid")?;
    let archive_b_path = archive_b.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged batches: [1,2] at timestamp 100, [3,4] at timestamp 200.
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 2..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("b-{i}"),
            i + 1,
            200,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // First rotation archives [1,2] to archive A (W=2).
    let first = store.archive_receipts_before(150, archive_a_path)?;
    assert_eq!(first, 2, "the aged [1,2] batch archives to A");

    // A second rotation would advance to W=4 but names a DIFFERENT archive B: it
    // must be rejected before any copy or delete.
    let result = store.archive_receipts_before(250, archive_b_path);
    let message = result
        .err()
        .ok_or("expected a Conflict; rotation accepted a changed archive path")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // The [3,4] rows are intact in live: the abort happened before any delete.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no [3,4] rows deleted when the path change is rejected"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive_a);
    let _ = std::fs::remove_file(&archive_b);
    Ok(())
}

/// The watermark exemption skips the live Merkle rebuild for the archived prefix
/// and trusts the archive to serve that deep verification. A count of archived
/// rows is not enough: an archive holding the right number of rows but with
/// tampered contents no longer hashes to the signed checkpoint roots. Trust must
/// be withdrawn when the archived receipts no longer re-derive the signed roots,
/// even though the archived row count is unchanged.
#[test]
fn watermark_trust_rejects_tampered_archive_contents() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::trusted_retention_watermark;

    let path = unique_db_path("watermark-tampered");
    let archive = unique_db_path("watermark-tampered-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // A faithful archive backs the watermark.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(trusted_retention_watermark(&connection)?, 2);
    drop(connection);

    // Tamper the archived claim-log contents WITHOUT changing the row count: the
    // archive still holds two entries for [1,2], but one no longer matches the
    // receipt that was checkpointed.
    {
        let tampered = rusqlite::Connection::open(&archive)?;
        let changed = tampered.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' \
             WHERE entry_seq = 1",
            [],
        )?;
        assert_eq!(changed, 1, "exactly one archived row tampered");
    }

    // The row count is still 2, but the archived prefix no longer re-derives the
    // signed checkpoint root, so the exemption is withdrawn fail-closed.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "a watermark whose archive no longer matches the signed roots must not be trusted"
    );

    drop(connection);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Retention repair deletes the surviving orphaned claim-log rows for receipts
/// whose source rows are already gone. Those orphan rows hold the last live
/// UNIQUE(receipt_id) sentinel, so repair must tombstone each archived id before
/// deleting it, exactly as the rotation delete does. Otherwise the same archived
/// receipt_id could be appended again as a brand-new live receipt, recreating
/// the archived/live identity ambiguity the tombstone exists to prevent.
#[test]
fn repair_tombstones_archived_ids_to_block_reuse() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-tombstone");
    let archive = unique_db_path("repair-tombstone-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a bricked store: co-archive the claim-log for [1,2], then delete
    // ONLY the source receipt rows (leaving the claim-log rows -> set drift).
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("dup-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // Repair the bricked store.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 2, "repair removed the two orphaned claim-log rows");
    drop(store);

    // The repaired (archived) ids are tombstoned, so re-appending one as a fresh
    // live receipt is rejected: the archived id cannot be resurrected.
    let reopened = SqliteReceiptStore::open(&path)?;
    let reused =
        super::support::sample_receipt_with_keypair_and_timestamp("dup-0", 1, 100, &keypair);
    let result = reopened.append_chio_receipt_returning_seq(&reused);
    assert!(
        result.is_err(),
        "re-appending an archived receipt id must be rejected by the retention tombstone"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair must tombstone EVERY archived id in the repaired prefix, not only the
/// claim-log rows that survived as extras. When a botched rotation already
/// deleted some archived rows from the live projection, those ids have no live
/// UNIQUE(receipt_id) sentinel AND no extra to iterate, so tombstoning only the
/// extras would leave them re-appendable and recreate the archived/live identity
/// ambiguity. Re-appending an already-deleted archived id must still be rejected.
#[test]
fn repair_tombstones_already_deleted_prefix_ids() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-tombstone-prefix");
    let archive = unique_db_path("repair-tombstone-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Build a store, co-archive [1,2], then fabricate a mixed drift: delete the
    // source rows for [1,2] AND the LIVE claim-log row for entry_seq 1, leaving
    // only entry_seq 2 as a surviving orphan. Entry 1's archived id is gone from
    // the live projection entirely, so it is not an extra repair would iterate.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("pre-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 1; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    // Repair removes only the surviving orphan (entry 2) but must tombstone the
    // whole archived prefix [1,2].
    let store = SqliteReceiptStore::open_existing(&path)?;
    let removed = store.retention_repair(archive_path)?;
    assert_eq!(removed, 1, "repair removed the one surviving orphaned row");
    drop(store);

    // The already-deleted archived id (entry 1, "pre-0") must be tombstoned too:
    // re-appending it as a fresh live receipt is rejected.
    let reopened = SqliteReceiptStore::open(&path)?;
    let reused =
        super::support::sample_receipt_with_keypair_and_timestamp("pre-0", 1, 100, &keypair);
    let result = reopened.append_chio_receipt_returning_seq(&reused);
    assert!(
        result.is_err(),
        "re-appending an already-deleted archived receipt id must be rejected by the tombstone"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair stamps tombstones from the SUPPLIED archive, but the archive that
/// actually backs an already-committed watermark is the LEDGER's archive. When a
/// caller supplies a different archive that happens to be faithful for the
/// surviving orphans yet divergent for prefix entries already deleted from the
/// live projection, the root re-derivation still passed against the ledger
/// archive while the tombstones were stamped for the wrong receipt ids, leaving
/// the truly archived ids re-appendable. Repair must require the supplied archive
/// to be the ledger archive so both run against the one archive that backs the
/// watermark; a mismatch fails closed.
#[test]
fn repair_rejects_archive_that_does_not_back_the_watermark(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-wrong-backing");
    let ledger_archive = unique_db_path("repair-wrong-backing-ledger");
    let ledger_path = ledger_archive
        .to_str()
        .ok_or("ledger archive path invalid")?;
    let supplied_archive = unique_db_path("repair-wrong-backing-supplied");
    let supplied_path = supplied_archive
        .to_str()
        .ok_or("supplied archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Mixed drift: co-archive [1,2] into the LEDGER archive, delete the source
    // rows for [1,2] and the LIVE claim-log row for entry 1 (fully deleted,
    // tombstoned only from the archive), leaving entry 2 as the surviving orphan.
    // Record a watermark at boundary 2 naming the ledger archive.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("wb-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        store.writer_handle().run_write({
            let ledger_path = ledger_path.to_string();
            let supplied_path = supplied_path.to_string();
            move |connection| {
                let ledger_escaped = ledger_path.replace('\'', "''");
                // The ledger archive faithfully backs [1,2] so its checkpoint root
                // re-derives.
                connection
                    .execute_batch(&format!("ATTACH DATABASE '{ledger_escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;

                // The SUPPLIED archive is faithful for the surviving orphan (entry
                // 2) but carries a divergent row for the already-deleted entry 1.
                let supplied_escaped = supplied_path.replace('\'', "''");
                connection
                    .execute_batch(&format!("ATTACH DATABASE '{supplied_escaped}' AS supplied"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS supplied.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO supplied.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq = 2; \
                     INSERT INTO supplied.claim_receipt_log_entries \
                       (entry_seq, receipt_id, receipt_kind, source_seq, timestamp, raw_json) \
                       VALUES (1, 'wrong-archived-id', 'tool_receipt', 1, 100, '{\"wrong\":true}');",
                )?;
                connection.execute_batch("DETACH DATABASE supplied")?;

                // Fabricate the drift.
                connection.execute_batch(
                    "DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq = 1; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim receipt log entries are immutable'); END;",
                )?;
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection,
                    2,
                    100,
                    &ledger_path,
                    None,
                    1,
                )?;
                Ok(())
            }
        })?;
    }

    // Repair with the divergent archive must fail closed instead of tombstoning
    // from an archive that does not back the committed watermark.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(supplied_path);
    let message = result
        .err()
        .ok_or("expected repair to reject an archive that does not back the watermark")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // Fail-closed: the surviving orphan is untouched, so a correct re-run against
    // the ledger archive can still complete.
    let live = store.reader_connection_for_test()?;
    let orphan_present: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        orphan_present, 1,
        "a rejected repair must leave the orphan for a correct re-run"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&ledger_archive);
    let _ = std::fs::remove_file(&supplied_archive);
    Ok(())
}

/// In incremental mode the rotation skips the O(N) chain rebuild on the append
/// hot path and trusts the per-append verified head, which can lag
/// `kernel_checkpoints` when a second store instance appends checkpoint rows
/// this handle has not adopted. The rotation path itself still audits the FULL
/// persisted checkpoint chain before pruning, so it must cap the archival
/// watermark at the freshest VERIFIED boundary (the latest persisted checkpoint)
/// rather than the possibly-stale in-memory head. Otherwise a quiet store that
/// another instance advanced would archive nothing every interval despite
/// holding aged, checkpointed receipts.
#[test]
fn rotation_archives_to_freshest_verified_checkpoint_despite_stale_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotation-verified-ceiling");
    let archive = unique_db_path("rotation-verified-ceiling-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    // Instance A checkpoints [1,2] and keeps its verified head at boundary 2.
    let store_a = SqliteReceiptStore::open(&path)?;
    store_a.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ceil-a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store_a.append_chio_receipt_returning_seq(&r)?;
    }
    store_a.flush_receipt_writes()?;
    assert!(store_a.load_checkpoint_by_seq(1)?.is_some());

    // A second instance appends [3,4] and builds checkpoint 2 covering boundary
    // 4. Instance A stays idle, so its cached verified head never advances past
    // boundary 2 even though the DB now holds an aged, checkpointed [1,4].
    {
        let store_b = SqliteReceiptStore::open_existing(&path)?;
        store_b.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 2..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("ceil-b-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store_b.append_chio_receipt_returning_seq(&r)?;
        }
        store_b.flush_receipt_writes()?;
        assert!(store_b.load_checkpoint_by_seq(2)?.is_some());
    }

    // Rotate through the stale instance A. Its cached head sits at boundary 2,
    // but the rotation audits the full persisted chain and archives the whole
    // aged, verified [1,4] instead of stalling at the stale head.
    let archived = store_a.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "rotation must archive to the freshest verified checkpoint boundary"
    );

    let conn = store_a.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "the watermark advances to the freshest verified boundary"
    );
    let survivors: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        survivors, 0,
        "the aged, verified checkpoint's rows are pruned once the chain is audited"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A store opened through `open_existing` skips the writable `open()` migration
/// that creates the watermark ledger, so a legacy database can reach rotation
/// without it. The rotation records the archival high-water mark, so it must
/// create the ledger first; otherwise the insert fails on a missing table after
/// the archive copy has run, rolling the delete back and looping forever without
/// pruning.
#[test]
fn rotation_creates_missing_watermark_ledger_on_legacy_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("legacy-rotation-watermark");
    let archive = unique_db_path("legacy-rotation-watermark-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lgr-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());
        // Drop the watermark ledger so the store looks like it predates the
        // retention migration.
        store.writer_handle().run_write(|connection| {
            connection.execute_batch("DROP TABLE IF EXISTS receipt_retention_watermark;")?;
            Ok(())
        })?;
    }

    // Reopen through open_existing (skips the ledger-creating migration) and
    // rotate. Without creating the ledger the watermark insert fails on the
    // missing table and the rotation errors after copying the archive.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(
        archived, 4,
        "the aged checkpointed prefix archives once the ledger is created"
    );

    let conn = store.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        watermark,
        Some(4),
        "the rotation created the ledger and recorded the boundary"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Once a rotation deletes the live receipt (and its `UNIQUE(receipt_id)`
/// sentinel), the tombstone row is the only DB-level record that the id was
/// archived, so it must be as immutable as the append-only projection tables. A
/// writer that bypasses the Rust path must not be able to delete or rewrite a
/// tombstone and then re-insert the archived id.
#[test]
fn retention_tombstones_are_immutable() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("tombstone-immutable");
    let store = SqliteReceiptStore::open(&path)?;
    let conn = store.reader_connection_for_test()?;

    // open() creates the tombstone table; seed one row (INSERT stays allowed).
    conn.execute(
        "INSERT INTO receipt_retention_tombstones \
         (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
         VALUES ('archived-1', 'tool_receipt', 5, 100)",
        [],
    )?;

    // A raw UPDATE is rejected by the reject-update trigger.
    let updated = conn.execute(
        "UPDATE receipt_retention_tombstones SET archived_through_entry_seq = 999",
        [],
    );
    assert!(
        updated.is_err(),
        "raw UPDATE of a tombstone must be rejected"
    );

    // A raw DELETE is rejected by the reject-delete trigger.
    let deleted = conn.execute("DELETE FROM receipt_retention_tombstones", []);
    assert!(
        deleted.is_err(),
        "raw DELETE of a tombstone must be rejected"
    );

    // The tombstone is unchanged: still exactly the one seeded row.
    let (count, seq): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(MAX(archived_through_entry_seq), 0) FROM receipt_retention_tombstones",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(seq, 5);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// A subsequent rotation only appends the newer suffix to the archive the ledger
/// already committed to; the earlier prefix was deleted from the live store and
/// survives nowhere else. If that archive is missing, recreating an empty file
/// and co-archiving only the new suffix would advance the watermark while the
/// earlier prefix is backed by no archive. Rotation must fail closed and leave
/// the prefix intact. With the missing archive the committed watermark can no
/// longer be trusted, so the pre-rotation chain audit sees the deleted `[1,2]`
/// prefix as a live claim-log gap and refuses there; either that gap refusal or
/// the archive-backing refusal is an acceptable fail-closed outcome, and neither
/// may advance the watermark or delete the surviving suffix.
#[test]
fn rotation_refuses_when_prior_archive_missing() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("rotation-missing-prior-archive");
    let archive = unique_db_path("rotation-missing-prior-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // Delete the archive that backs the committed [1,2] prefix.
    std::fs::remove_file(&archive)?;

    // A second rotation would advance the watermark to cover the aged [3,4]
    // batch; with the prior archive gone it must refuse rather than strand [1,2].
    let result = store.archive_receipts_before(600, archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; rotation stranded the prior prefix")?
        .to_string();
    assert!(
        message.contains("no longer backs the committed watermark")
            || message.contains("gap in checkpoint signer binding"),
        "unexpected error: {message}"
    );

    // Fail-closed: the watermark stays at 2 and the [3,4] rows survive.
    let conn = store.reader_connection_for_test()?;
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(watermark, Some(2), "the watermark must not advance");
    let survivors: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(survivors, 2, "the suffix rows must survive the refusal");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Repair stamps a checkpoint-aligned watermark that trusts the whole prefix as
/// archived and skips its Merkle rebuild. For prefix rows already deleted from
/// the live projection there is no live row to compare, so a full-count archive
/// carrying corrupted bytes would pass the presence check yet fail the next
/// archive-backed chain verification and brick the store. Repair must re-derive
/// the covered checkpoint roots from the archive and refuse a divergent one.
#[test]
fn repair_rejects_corrupted_archive_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-corrupt-prefix");
    let archive = unique_db_path("repair-corrupt-prefix-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        // One checkpoint covers [1,4] (max_batch 4), so repair rounds to 4.
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 4))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("cp-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Archive the FULL prefix [1,4] but corrupt entry 1's raw_json, then
        // delete all source rows and delete claim-log rows [1,2] outright (so they
        // have no live row to compare). Orphans [3,4] survive and pass the
        // per-extra identity check; the count check passes (archive holds 4 rows);
        // only re-deriving the checkpoint root from the archive catches the
        // corrupted entry 1.
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 4; \
                     UPDATE archive.claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 1; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 4; \
                     DELETE FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END; \
                     CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete \
                       BEFORE DELETE ON claim_receipt_log_entries \
                       BEGIN SELECT RAISE(ABORT, 'claim_receipt_log_entries is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                Ok(())
            }
        })?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; repair sealed a corrupted archive")?
        .to_string();
    assert!(
        message.contains("co-archival incomplete"),
        "unexpected error: {message}"
    );

    // Fail-closed: surviving orphans remain and no watermark is stamped.
    let conn = store.reader_connection_for_test()?;
    let orphans: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq IN (3, 4)",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "surviving orphans must remain after the refusal"
    );
    let watermark: Option<i64> = conn.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )?;
    assert_eq!(watermark, None, "no watermark may seal a corrupted archive");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A prior botched rotation can leave a watermark covering the boundary but
/// pointing at a missing or wrong archive, with the orphaned claim-log rows still
/// live. Re-running repair with a different archive must not silently skip the
/// insert (the monotonic ledger cannot be corrected in place) and delete the
/// orphans behind a watermark whose recorded archive can never satisfy
/// verification. Tombstones must be stamped from the archive that backs the
/// watermark, so a supplied archive that is not the ledger archive (here the
/// ledger names a missing file) fails closed without deleting.
#[test]
fn repair_refuses_when_ledger_names_missing_archive() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("repair-ledger-missing-archive");
    let archive = unique_db_path("repair-ledger-missing-archive-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..4u64 {
            let r = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("lm-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&r)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        // Co-archive [1,2] faithfully into the correct archive, orphan them
        // (delete only their source rows), and record a watermark at boundary 2
        // that names a non-existent archive path (the botched rotation's stale
        // ledger entry).
        store.writer_handle().run_write({
            let archive_path = archive_path.to_string();
            move |connection| {
                let escaped = archive_path.replace('\'', "''");
                connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
                connection.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries \
                       (entry_seq INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL, \
                        source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL, capability_id TEXT, session_id TEXT, \
                        parent_request_id TEXT, request_id TEXT, subject_key TEXT, issuer_key TEXT, tool_server TEXT, \
                        tool_name TEXT, raw_json TEXT NOT NULL); \
                     INSERT OR IGNORE INTO archive.claim_receipt_log_entries \
                       SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= 2; \
                     DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete; \
                     DELETE FROM main.chio_tool_receipts WHERE seq <= 2; \
                     CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete \
                       BEFORE DELETE ON chio_tool_receipts \
                       BEGIN SELECT RAISE(ABORT, 'chio_tool_receipts is append-only'); END;",
                )?;
                connection.execute_batch("DETACH DATABASE archive")?;
                // Record a covering watermark that names a path with no archive.
                let missing = format!("{archive_path}.missing");
                crate::receipt_store::support::insert_receipt_retention_watermark(
                    connection, 2, 100, &missing, None, 1,
                )?;
                Ok(())
            }
        })?;
    }

    // Repair with an archive that is not the one the ledger names. The ledger
    // already covers boundary 2 and points at the missing file, so repair cannot
    // stamp tombstones from the archive that backs the watermark and must refuse
    // without deleting the orphans.
    let store = SqliteReceiptStore::open_existing(&path)?;
    let result = store.retention_repair(archive_path);
    let message = result
        .err()
        .ok_or("expected a fail-closed refusal; repair deleted orphans behind a broken ledger")?
        .to_string();
    assert!(
        message.contains("differs from the archive"),
        "unexpected error: {message}"
    );

    // Fail-closed: the orphaned rows survive.
    let conn = store.reader_connection_for_test()?;
    let orphans: i64 = conn.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 2",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphans, 2,
        "orphaned rows must survive a refusal over a broken ledger"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Primary correctness proof: a state-machine proptest that drives random
/// interleaved sequences of tool/child appends (non-monotonic
/// timestamps within an aged band, to exercise the MAX(timestamp)-over-prefix
/// watermark rule) and rotations against the store, and asserts at every
/// reachable state that the store stays appendable, reopenable, healthy
/// (folding set-equality and chain integrity), and that the archived and live
/// receipt-id sets partition the full appended history with no loss and no
/// double-counting.
// Named `state_machine`, not `prop`: `proptest::prelude::*` re-exports the
// whole proptest crate under the name `prop` (for `prop::collection::vec`
// etc.), so a submodule literally named `prop` combined with `use super::*`
// would glob-import itself and collide with that re-export (E0659 ambiguous
// name).
#[cfg(test)]
mod state_machine {
    use std::collections::BTreeSet;

    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op {
        AppendTool(u8),
        AppendChild(u8),
        Rotate,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..8).prop_map(Op::AppendTool),
            (0u8..8).prop_map(Op::AppendChild),
            Just(Op::Rotate),
        ]
    }

    /// Every receipt_id currently in `chio_tool_receipts` union
    /// `chio_child_receipts` on `store` (live or archive database alike).
    fn receipt_id_set(store: &SqliteReceiptStore) -> Result<BTreeSet<String>, ReceiptStoreError> {
        let connection = store.reader_connection_for_test()?;
        let mut ids = BTreeSet::new();
        let mut tool_statement = connection.prepare("SELECT receipt_id FROM chio_tool_receipts")?;
        let tool_rows = tool_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in tool_rows {
            ids.insert(id?);
        }
        let mut child_statement =
            connection.prepare("SELECT receipt_id FROM chio_child_receipts")?;
        let child_rows = child_statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in child_rows {
            ids.insert(id?);
        }
        Ok(ids)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn prop_retention_preserves_append_invariant(ops in prop::collection::vec(op_strategy(), 1..40)) {
            let path = unique_db_path("prop-retention");
            let archive = unique_db_path("prop-archive");
            let keypair = super::super::support::receipt_test_keypair();
            let archive_path = archive.to_str().ok_or_else(|| TestCaseError::fail("archive path"))?;

            let mut seq = 0u64;
            // The full history of every receipt id ever appended, independent
            // of where it ends up (live or archived): the ground truth that
            // invariant (4) below partitions against.
            let mut appended_ids: BTreeSet<String> = BTreeSet::new();
            {
                let store = SqliteReceiptStore::open(&path).map_err(map_err)?;
                store
                    .enable_background_checkpoints(super::super::support::signer(&keypair, 2))
                    .map_err(map_err)?;
                for (i, op) in ops.iter().enumerate() {
                    // Non-monotonic timestamps within an aged band to exercise
                    // the MAX(timestamp)-over-prefix watermark rule.
                    let ts = 100 + ((i as u64 * 7) % 13);
                    match op {
                        Op::AppendTool(n) => {
                            seq += 1;
                            let r = super::super::support::sample_receipt_with_keypair_and_timestamp(
                                &format!("pt-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_chio_receipt_returning_seq(&r).map_err(map_err)?;
                        }
                        Op::AppendChild(n) => {
                            seq += 1;
                            let r = super::super::support::sample_child_receipt_with_keypair_seq_and_timestamp(
                                &format!("pc-{seq}-{n}"), seq, ts, &keypair);
                            appended_ids.insert(r.id.clone());
                            store.append_child_receipt_record(&r).map_err(map_err)?;
                        }
                        Op::Rotate => {
                            store.flush_receipt_writes().map_err(map_err)?;
                            // Cutoff above BOTH the aged op band (100..=112) and
                            // the probe band (2_000), so every timestamp is
                            // below the cutoff and any fully checkpointed prefix
                            // is eligible for archival. The archival watermark
                            // W = MAX(batch_end_seq) is a PREFIX rule: a
                            // checkpoint qualifies only if no entry in [1, W]
                            // has timestamp >= cutoff. A cutoff below the probe
                            // band would let the low-seq probes poison every
                            // prefix and make the co-archive-and-delete path a
                            // permanent no-op (W = 0), so the archived/live
                            // partition below would never actually be exercised.
                            store.archive_receipts_before(3_000, archive_path).map_err(map_err)?;
                        }
                    }
                    // Invariant (1): the next append still succeeds.
                    seq += 1;
                    let probe = super::super::support::sample_receipt_with_keypair_and_timestamp(
                        &format!("probe-{seq}"), seq, 2_000, &keypair);
                    appended_ids.insert(probe.id.clone());
                    store.append_chio_receipt_returning_seq(&probe).map_err(map_err)?;
                    // Invariant (3): health stays healthy (folds set-equality
                    // and chain integrity).
                    store.flush_receipt_writes().map_err(map_err)?;
                    prop_assert!(store.receipt_store_health().map_err(map_err)?.healthy);
                }
            }
            // Invariant (2): reopen succeeds (open-time seed re-verifies).
            // The verified-head seed runs on the commit-writer thread, so flush
            // to drain it before sampling health; until the seed completes the
            // head reads poisoned and the writer serves closed.
            let reopened = SqliteReceiptStore::open(&path).map_err(map_err)?;
            reopened.flush_receipt_writes().map_err(map_err)?;
            prop_assert!(reopened.receipt_store_health().map_err(map_err)?.healthy);

            // Invariant (4): the archived and live receipt-id sets partition
            // the full appended history. No id is lost (union covers
            // everything ever appended) and none is double-counted (the two
            // sets are disjoint). A run with no eligible rotation leaves the
            // archive set empty and everything live, which still satisfies
            // the partition.
            let live_ids = receipt_id_set(&reopened).map_err(map_err)?;
            let archive_store = SqliteReceiptStore::open(&archive).map_err(map_err)?;
            let archived_ids = receipt_id_set(&archive_store).map_err(map_err)?;
            let overlap: Vec<&String> = live_ids.intersection(&archived_ids).collect();
            prop_assert!(
                overlap.is_empty(),
                "receipt ids double-counted in both live and archive: {overlap:?}"
            );
            let union: BTreeSet<String> = live_ids.union(&archived_ids).cloned().collect();
            prop_assert_eq!(
                union,
                appended_ids,
                "archived and live receipt-id sets must partition the full appended history"
            );

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&archive);
        }
    }

    fn map_err(error: ReceiptStoreError) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }
}

/// A dependent row that a second store handle commits into the archived prefix
/// AFTER the co-archival copy but BEFORE the delete transaction takes its write
/// lock must never be deleted un-archived. The delete re-checks co-archival
/// completeness under the BEGIN IMMEDIATE lock and fails closed, so the prefix
/// and the newly inserted row survive for a later rotation to re-copy.
#[test]
fn delete_fails_closed_when_a_dependent_row_escapes_the_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-delete");
    let archive = unique_db_path("toctou-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("toctou-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    let receipt_id = super::support::first_tool_receipt_id(&store)?;

    // Co-archive the aged [1,2] prefix, then simulate a concurrent handle
    // committing a settlement reconciliation for a receipt in that prefix after
    // the copy has run, and only then attempt the delete.
    let fail_closed = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let receipt_id = receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            copy_archived_prefix(connection, 2)?;
            // The archive now faithfully holds [1,2]. A second writer commits a
            // dependent row into the archived prefix, unseen by the copy above.
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'settled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            let result = delete_archived_prefix_in_tx(connection, 2, 150, &archive_path);
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(result.is_err())
        }
    })?;
    assert!(
        fail_closed,
        "the delete must fail closed when a dependent row is not in the archive"
    );

    // Fail-closed: the prefix and the un-archived reconciliation both survive.
    let live = store.reader_connection_for_test()?;
    let live_receipts: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE seq <= 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_receipts, 2,
        "the archived prefix must survive the refusal"
    );
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_settlement, 1,
        "the un-archived reconciliation must survive the refusal"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The archive-path pin is checked before the delete transaction takes the write
/// lock, so two store handles rotating concurrently to DIFFERENT archives can
/// split the prefix: one commits `[1, W1]` to archive A after the outer check,
/// then the other copies only the surviving suffix to archive B and records a
/// higher watermark naming B, leaving the ledger pointing at a file that lacks
/// the earlier prefix. The delete must re-read and re-enforce the ledger archive
/// path AFTER acquiring the write lock and fail closed, so the split is caught
/// and the surviving suffix is preserved for a later rotation.
#[test]
fn delete_rechecks_archive_path_under_the_write_lock() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-path-split");
    let archive_a = unique_db_path("toctou-path-split-a");
    let archive_b = unique_db_path("toctou-path-split-b");
    let archive_a_path = archive_a.to_str().ok_or("archive path invalid")?;
    let archive_b_path = archive_b.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged batches: [1,2] at timestamp 100, [3,4] at timestamp 200.
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 2..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("b-{i}"),
            i + 1,
            200,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // A concurrent rotation commits [1,2] to archive A: the ledger now pins the
    // archive path to A and the live prefix [1,2] is gone.
    let first = store.archive_receipts_before(150, archive_a_path)?;
    assert_eq!(first, 2, "the aged [1,2] batch archives to A");

    // This rotation, in flight against a DIFFERENT archive B, has already copied
    // the surviving suffix [3,4] into B and now reaches its locked delete for
    // W=4. Under the write lock the ledger names A, so the delete must refuse the
    // path split rather than strand [1,2] in A behind a ledger pointing at B.
    let refusal = store.writer_handle().run_write({
        let archive_b_path = archive_b_path.to_string();
        move |connection| {
            let escaped = archive_b_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            copy_archived_prefix(connection, 4)?;
            let result = delete_archived_prefix_in_tx(connection, 4, 250, &archive_b_path);
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok(result.err().map(|error| error.to_string()))
        }
    })?;
    let message = refusal
        .ok_or("the delete must fail closed when a concurrent rotation split the archive path")?;
    assert!(
        message.contains("differs from the archive"),
        "expected the archive-path pin to fire under the write lock, got: {message}"
    );

    // Fail-closed: the surviving [3,4] suffix is intact for a later rotation.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no [3,4] rows may be deleted when the locked path re-check rejects the split"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive_a);
    let _ = std::fs::remove_file(&archive_b);
    Ok(())
}

/// A governed receipt's lineage statement must travel into the archive with the
/// receipt. The delete leaves the live lineage row in place (like capability
/// lineage), so the archive becomes the standalone copy: opening it must still
/// surface the archived receipt's call-chain provenance.
#[test]
fn governed_receipt_lineage_is_co_archived() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("lineage-archived");
    let archive = unique_db_path("lineage-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lineage-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Persist a lineage statement for the first receipt, the shape a governed
    // call-chain receipt records on append. It sits in the archived range
    // because its receipt does.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO receipt_lineage_statements \
                 (receipt_id, statement_id, request_id, session_id, session_anchor_id, chain_id, \
                  parent_request_id, parent_receipt_id, evidence_class, evidence_sources_json, \
                  verified_session_anchor, verified_parent_request, verified_parent_receipt, \
                  replay_protected, recorded_at, source_kind, json_sha256, raw_json) \
                 VALUES (?1, 'stmt-lineage-0', NULL, NULL, NULL, 'chain-lineage-0', NULL, \
                         'parent-receipt-lineage-0', 'delegated', NULL, 0, 0, 1, 0, 100, 'test', \
                         'sha-lineage-0', '{\"schema\":\"lineage\"}')",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2);

    // The live lineage row survives (not cascaded away).
    let live = store.reader_connection_for_test()?;
    let live_lineage: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_lineage, 1,
        "the live lineage row must survive rotation"
    );

    // The archive holds a faithful copy, so the archived receipt keeps its
    // provenance when the archive is opened standalone.
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let (arch_lineage, arch_chain, arch_parent): (i64, Option<String>, Option<String>) = arch
        .query_row(
            "SELECT COUNT(*), MAX(chain_id), MAX(parent_receipt_id) \
             FROM receipt_lineage_statements WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!(
        arch_lineage, 1,
        "the governed receipt's lineage statement must be co-archived"
    );
    assert_eq!(arch_chain.as_deref(), Some("chain-lineage-0"));
    assert_eq!(arch_parent.as_deref(), Some("parent-receipt-lineage-0"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
