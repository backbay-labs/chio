use super::*;

/// Append-only ledger of archival high-water marks. The effective watermark is
/// `MAX(archived_through_entry_seq)`; a rotation that would lower it is rejected
/// (`RetentionWatermarkRegression`). Created on every open (new and existing).
///
/// The ledger is SECURITY-LOAD-BEARING: watermark-aware chain verification
/// trusts `W = MAX(archived_through_entry_seq)` to SKIP the live
/// Merkle rebuild for every checkpoint with `batch_end_seq <= W`. A forged or
/// inflated `W` written by a raw `INSERT`/`UPDATE` would therefore skip
/// claim-log validation chain-wide. The three triggers below make the ledger's
/// append-only, strictly-monotonic guarantee DB-enforced, mirroring the
/// `reject_update`/`reject_delete` immutability guards used for the other
/// append-only projection tables (`TRANSPARENCY_PROJECTION_GUARDS_SQL`), so `W`
/// cannot be regressed or forged even by a writer that bypasses
/// `insert_receipt_retention_watermark`.
pub(crate) fn ensure_receipt_retention_watermark_table(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS receipt_retention_watermark (
            archived_through_entry_seq INTEGER NOT NULL,
            archived_through_timestamp INTEGER NOT NULL,
            archive_path               TEXT NOT NULL,
            archive_sha256             TEXT,
            rotated_at                 INTEGER NOT NULL,
            CHECK (archived_through_entry_seq >= 0)
        );

        CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_update
        BEFORE UPDATE ON receipt_retention_watermark
        BEGIN
            SELECT RAISE(ABORT, 'retention watermark ledger is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_delete
        BEFORE DELETE ON receipt_retention_watermark
        BEGIN
            SELECT RAISE(ABORT, 'retention watermark ledger is append-only');
        END;

        -- Monotonic increase enforced at the DB level: a new mark must be
        -- strictly greater than the current MAX. The subquery is NULL on an
        -- empty ledger, so the WHEN clause is NULL (not true) and the first
        -- mark is always accepted.
        CREATE TRIGGER IF NOT EXISTS receipt_retention_watermark_reject_regression
        BEFORE INSERT ON receipt_retention_watermark
        WHEN NEW.archived_through_entry_seq
            <= (SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark)
        BEGIN
            SELECT RAISE(ABORT, 'retention watermark must increase monotonically');
        END;
        "#,
    )?;
    Ok(())
}

/// Tombstones for receipt ids removed from the live store by a retention
/// rotation, plus the DB triggers that keep an archived id from being reused.
///
/// A rotation deletes the live receipt rows (and their `UNIQUE(receipt_id)`
/// sentinel) once they are co-archived. Without a record of what left, the
/// append path's `ON CONFLICT(receipt_id) DO NOTHING` sees an archived id as
/// brand new and inserts a second live receipt/claim-log entry for it, so a
/// retry or a forged append overlaps the archived and live histories and makes a
/// point lookup by receipt id ambiguous. The tombstone table preserves the
/// uniqueness sentinel across archival (one small row per archived id, not the
/// full receipt), and the two `BEFORE INSERT` triggers RAISE(ABORT) any source
/// insert whose id is tombstoned, DB-enforced like the immutability guards so a
/// writer that bypasses the Rust append path still cannot resurrect an archived
/// id. Created on every writable open (new and existing).
///
/// The tombstone rows are themselves append-only. Once a rotation deletes the
/// live receipt (and its `UNIQUE(receipt_id)` sentinel), the tombstone is the
/// only DB-level record that the id was archived, so it carries the same
/// immutability guarantee as the append-only projection tables: two
/// `BEFORE UPDATE`/`BEFORE DELETE` triggers RAISE(ABORT) so a writer that
/// bypasses the Rust path cannot delete or rewrite a tombstone and then
/// re-insert the archived id, recreating the archived/live ambiguity these
/// triggers exist to prevent.
pub(crate) fn ensure_receipt_retention_tombstones(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS receipt_retention_tombstones (
            receipt_id                 TEXT PRIMARY KEY,
            receipt_kind               TEXT NOT NULL,
            archived_through_entry_seq INTEGER NOT NULL,
            tombstoned_at              INTEGER NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS receipt_retention_tombstones_reject_update
        BEFORE UPDATE ON receipt_retention_tombstones
        BEGIN
            SELECT RAISE(ABORT, 'receipt retention tombstones are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS receipt_retention_tombstones_reject_delete
        BEFORE DELETE ON receipt_retention_tombstones
        BEGIN
            SELECT RAISE(ABORT, 'receipt retention tombstones are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_archived_reuse
        BEFORE INSERT ON chio_tool_receipts
        WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id)
        BEGIN
            SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended');
        END;

        CREATE TRIGGER IF NOT EXISTS chio_child_receipts_reject_archived_reuse
        BEFORE INSERT ON chio_child_receipts
        WHEN EXISTS (SELECT 1 FROM receipt_retention_tombstones WHERE receipt_id = NEW.receipt_id)
        BEGIN
            SELECT RAISE(ABORT, 'receipt_id was archived by retention and cannot be re-appended');
        END;
        "#,
    )?;
    Ok(())
}

/// The current effective archival watermark, or `None` if the store has never
/// archived (no ledger rows).
///
/// Called by `insert_receipt_retention_watermark`, the claim-log backfill
/// guard (`claim_log/validation.rs`), the Rotate command, and the
/// watermark-aware chain verification.
pub(crate) fn retention_watermark(
    connection: &rusqlite::Connection,
) -> Result<Option<u64>, ReceiptStoreError> {
    // A store created before the retention migration has no watermark ledger,
    // and read-only observers (the SIEM watchdog, CLI inspectors) open such a
    // store without the writable `open()` migration that creates the table. A
    // missing table means "never archived" (None), not a hard error that would
    // deny every reader a health report. Fail-closed safe: a None watermark
    // disables the chain-verification skip exemption, so even a store whose
    // ledger was dropped out of band falls back to full verification.
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let value: Option<i64> = connection.query_row(
        "SELECT MAX(archived_through_entry_seq) FROM receipt_retention_watermark",
        [],
        |row| row.get(0),
    )?;
    match value {
        None => Ok(None),
        Some(raw) => Ok(Some(sqlite_u64(raw, "retention watermark")?)),
    }
}

/// The archive path recorded by the most recent watermark row, or `None` when
/// the store has never archived.
///
/// Retention archives a contiguous `[1, W]` prefix, and every faithful archive
/// of that prefix holds ALL of `[1, W]`. Once the first rotation deletes the
/// live rows it can never re-copy them, so a later rotation pointed at a
/// DIFFERENT target would write only the new suffix there and leave the earlier
/// prefix stranded in the original archive, splitting one logical archive across
/// two files that neither alone can satisfy. Callers use this to pin the archive
/// path across rotations. Ordered by the watermark high-water mark (with
/// `rotated_at` as a tiebreak) so the most recently advanced mark wins.
pub(crate) fn latest_watermark_archive_path(
    connection: &rusqlite::Connection,
) -> Result<Option<String>, ReceiptStoreError> {
    if !receipt_retention_watermark_table_exists(connection)? {
        return Ok(None);
    }
    let path: Option<String> = connection
        .query_row(
            "SELECT archive_path FROM receipt_retention_watermark \
             ORDER BY archived_through_entry_seq DESC, rotated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(path)
}

fn receipt_retention_watermark_table_exists(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = 'receipt_retention_watermark'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

/// True if any checkpoint has ever been persisted. Called by the claim-log
/// backfill guard (`claim_log/validation.rs`) and the watermark-aware chain
/// verification.
pub(crate) fn kernel_checkpoints_exist(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })?;
    Ok(count > 0)
}

/// Record a new archival high-water mark. Fail-closed: a value below the
/// current MAX is a regression and is rejected without inserting. The DB-level
/// `receipt_retention_watermark_reject_regression` trigger additionally rejects
/// a non-strictly-increasing raw INSERT, so the monotonic guarantee holds even
/// for a writer that bypasses this helper.
///
/// Called on the writer connection by the Rotate command
/// (`delete_archived_prefix_in_tx`).
pub(crate) fn insert_receipt_retention_watermark(
    connection: &rusqlite::Connection,
    archived_through_entry_seq: u64,
    archived_through_timestamp: u64,
    archive_path: &str,
    archive_sha256: Option<&str>,
    rotated_at: u64,
) -> Result<(), ReceiptStoreError> {
    if let Some(current) = retention_watermark(connection)? {
        if archived_through_entry_seq < current {
            return Err(ReceiptStoreError::RetentionWatermarkRegression {
                attempted: archived_through_entry_seq,
                current,
            });
        }
    }
    connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            sqlite_i64(archived_through_entry_seq, "watermark entry_seq")?,
            sqlite_i64(archived_through_timestamp, "watermark timestamp")?,
            archive_path,
            archive_sha256,
            sqlite_i64(rotated_at, "watermark rotated_at")?,
        ],
    )?;
    Ok(())
}

/// One-time migration: enable `PRAGMA auto_vacuum = INCREMENTAL` on a store
/// that predates the pragma.
///
/// SQLite only applies a changed `auto_vacuum` mode to a brand-new (empty)
/// database; on an existing populated database the pragma write is silently
/// a no-op until a full `VACUUM` runs, which is the only way to convert an
/// existing file's auto-vacuum mode (see the SQLite `auto_vacuum` pragma
/// docs). `PRAGMA auto_vacuum` reads back `0` (NONE) until that conversion
/// happens, so this helper checks the current mode and, only when it is
/// still `NONE`, sets the pragma and runs one full `VACUUM` to convert the
/// file. Idempotent: once converted, `PRAGMA auto_vacuum` reads back `2`
/// (INCREMENTAL) and this becomes a cheap no-op read on every subsequent
/// call. Called on the drained writer connection at the first rotation pass
/// (`rotate_on_writer_connection`) so a legacy store converts exactly once,
/// off the append hot path.
pub(crate) fn migrate_auto_vacuum_incremental_if_needed(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let mode: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if mode == 0 {
        connection.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    }
    Ok(())
}
