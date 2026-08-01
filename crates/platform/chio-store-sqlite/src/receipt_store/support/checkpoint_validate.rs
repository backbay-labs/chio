use super::*;

const CHECKPOINT_TRANSPARENCY_GUARDS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS kernel_checkpoints_reject_update
BEFORE UPDATE ON kernel_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'kernel checkpoints are immutable');
END;

CREATE TRIGGER IF NOT EXISTS kernel_checkpoints_reject_delete
BEFORE DELETE ON kernel_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'kernel checkpoints are immutable');
END;

CREATE TRIGGER IF NOT EXISTS kernel_checkpoints_enforce_append_only
BEFORE INSERT ON kernel_checkpoints
BEGIN
    SELECT CASE
        WHEN NEW.checkpoint_seq < 1
            THEN RAISE(ABORT, 'checkpoint_seq must be greater than zero')
        WHEN NEW.batch_start_seq < 1
            THEN RAISE(ABORT, 'batch_start_seq must be greater than zero')
        WHEN NEW.batch_end_seq < NEW.batch_start_seq
            THEN RAISE(ABORT, 'checkpoint batch_end_seq must be >= batch_start_seq')
        WHEN NEW.tree_size < 1
            THEN RAISE(ABORT, 'checkpoint tree_size must be greater than zero')
        WHEN NEW.checkpoint_seq = 1
            AND NEW.batch_start_seq != 1
            THEN RAISE(ABORT, 'first checkpoint must start at entry_seq 1')
        WHEN NEW.checkpoint_seq = 1
            AND json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NOT NULL
            THEN RAISE(ABORT, 'first checkpoint must not include a predecessor digest')
        WHEN NEW.checkpoint_seq > 1
            AND json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NULL
            THEN RAISE(ABORT, 'checkpoint predecessor digest is required')
        WHEN EXISTS (
            SELECT 1
            FROM kernel_checkpoints existing
            WHERE existing.checkpoint_seq >= NEW.checkpoint_seq
        )
            THEN RAISE(
                ABORT,
                'kernel checkpoints must be appended in strictly increasing checkpoint_seq order'
            )
        WHEN NEW.checkpoint_seq > 1
            AND NOT EXISTS (
                SELECT 1
                FROM kernel_checkpoints predecessor
                WHERE predecessor.checkpoint_seq = NEW.checkpoint_seq - 1
                  AND predecessor.batch_end_seq + 1 = NEW.batch_start_seq
            )
            THEN RAISE(ABORT, 'kernel checkpoint predecessor continuity violation')
    END;
END;
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedCheckpointRow {
    pub(crate) id: u64,
    pub(crate) checkpoint_seq: u64,
    pub(crate) batch_start_seq: u64,
    pub(crate) batch_end_seq: u64,
    pub(crate) tree_size: u64,
    pub(crate) merkle_root_hex: String,
    pub(crate) issued_at: u64,
    pub(crate) statement_json: String,
    pub(crate) signature_hex: String,
    pub(crate) kernel_key_hex: String,
}

pub(crate) fn checkpoint_error_to_receipt_store(
    error: chio_kernel::checkpoint::CheckpointError,
) -> ReceiptStoreError {
    ReceiptStoreError::Conflict(format!("checkpoint integrity failure: {error}"))
}

pub(crate) fn ensure_checkpoint_transparency_guards(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(CHECKPOINT_TRANSPARENCY_GUARDS_SQL)?;
    Ok(())
}

/// Run one checkpoint write while preserving restored immutability guards even
/// when candidate validation fails.
///
/// Guard DDL belongs to the outer Immediate transaction. Candidate reads and
/// writes belong to the inner savepoint. On a domain error or panic the
/// savepoint rolls back, then the outer transaction commits only the restored
/// checkpoint and transparency-projection guards. A panic is resumed after
/// that cleanup so callers retain their existing unwind behavior.
pub(crate) fn checkpoint_guarded_immediate<T>(
    connection: &mut Connection,
    operation: impl FnOnce(&rusqlite::Savepoint<'_>) -> Result<T, ReceiptStoreError>,
) -> Result<T, ReceiptStoreError> {
    let mut tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure_checkpoint_transparency_guards(&tx)?;
    ensure_transparency_projection_guards(&tx)?;
    let savepoint = tx.savepoint()?;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&savepoint))) {
        Ok(Ok(value)) => {
            savepoint.commit()?;
            tx.commit()?;
            Ok(value)
        }
        Ok(Err(error)) => {
            savepoint.finish()?;
            tx.commit()?;
            Err(error)
        }
        Err(payload) => {
            if savepoint.finish().is_ok() {
                let _guard_commit_result = tx.commit();
            }
            std::panic::resume_unwind(payload);
        }
    }
}

pub(crate) fn load_persisted_checkpoint_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT id, checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                   merkle_root, issued_at, statement_json, signature, kernel_key
            FROM kernel_checkpoints
            WHERE checkpoint_seq = ?1
            "#,
            params![sqlite_i64(checkpoint_seq, "checkpoint_seq")?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                id,
                checkpoint_seq,
                batch_start_seq,
                batch_end_seq,
                tree_size,
                merkle_root_hex,
                issued_at,
                statement_json,
                signature_hex,
                kernel_key_hex,
            )| {
                Ok(PersistedCheckpointRow {
                    id: sqlite_u64(id, "checkpoint id")?,
                    checkpoint_seq: sqlite_u64(checkpoint_seq, "checkpoint_seq")?,
                    batch_start_seq: sqlite_u64(batch_start_seq, "batch_start_seq")?,
                    batch_end_seq: sqlite_u64(batch_end_seq, "batch_end_seq")?,
                    tree_size: sqlite_u64(tree_size, "tree_size")?,
                    merkle_root_hex,
                    issued_at: sqlite_u64(issued_at, "issued_at")?,
                    statement_json,
                    signature_hex,
                    kernel_key_hex,
                })
            },
        )
        .transpose()
}

pub(crate) fn load_latest_persisted_checkpoint_row(
    connection: &Connection,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    let latest_seq = connection
        .query_row(
            "SELECT checkpoint_seq FROM kernel_checkpoints ORDER BY checkpoint_seq DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    latest_seq
        .map(|value| {
            load_persisted_checkpoint_row(connection, sqlite_u64(value, "checkpoint_seq")?)
        })
        .transpose()
        .map(|row| row.flatten())
}

pub(crate) fn load_all_persisted_checkpoint_rows(
    connection: &Connection,
) -> Result<Vec<PersistedCheckpointRow>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT id, checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
               merkle_root, issued_at, statement_json, signature, kernel_key
        FROM kernel_checkpoints
        ORDER BY checkpoint_seq ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
        ))
    })?;

    rows.map(|row| {
        let (
            id,
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            tree_size,
            merkle_root_hex,
            issued_at,
            statement_json,
            signature_hex,
            kernel_key_hex,
        ) = row.map_err(ReceiptStoreError::from)?;
        Ok(PersistedCheckpointRow {
            id: sqlite_u64(id, "checkpoint id")?,
            checkpoint_seq: sqlite_u64(checkpoint_seq, "checkpoint_seq")?,
            batch_start_seq: sqlite_u64(batch_start_seq, "batch_start_seq")?,
            batch_end_seq: sqlite_u64(batch_end_seq, "batch_end_seq")?,
            tree_size: sqlite_u64(tree_size, "tree_size")?,
            merkle_root_hex,
            issued_at: sqlite_u64(issued_at, "issued_at")?,
            statement_json,
            signature_hex,
            kernel_key_hex,
        })
    })
    .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn parse_persisted_checkpoint_row(
    row: PersistedCheckpointRow,
) -> Result<KernelCheckpoint, ReceiptStoreError> {
    let body: KernelCheckpointBody = serde_json::from_str(&row.statement_json)?;
    let signature = Signature::from_hex(&row.signature_hex)
        .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))?;
    let checkpoint = KernelCheckpoint { body, signature };

    if checkpoint.body.checkpoint_seq != row.checkpoint_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint row seq {} does not match signed checkpoint_seq {}",
            row.checkpoint_seq, checkpoint.body.checkpoint_seq
        )));
    }
    if checkpoint.body.batch_start_seq != row.batch_start_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} batch_start_seq column {} does not match signed body {}",
            row.checkpoint_seq, row.batch_start_seq, checkpoint.body.batch_start_seq
        )));
    }
    if checkpoint.body.batch_end_seq != row.batch_end_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} batch_end_seq column {} does not match signed body {}",
            row.checkpoint_seq, row.batch_end_seq, checkpoint.body.batch_end_seq
        )));
    }
    if checkpoint.body.tree_size as u64 != row.tree_size {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} tree_size column {} does not match signed body {}",
            row.checkpoint_seq, row.tree_size, checkpoint.body.tree_size
        )));
    }
    if checkpoint.body.merkle_root.to_hex() != row.merkle_root_hex {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} merkle_root column {} does not match signed body {}",
            row.checkpoint_seq,
            row.merkle_root_hex,
            checkpoint.body.merkle_root.to_hex()
        )));
    }
    if checkpoint.body.issued_at != row.issued_at {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} issued_at column {} does not match signed body {}",
            row.checkpoint_seq, row.issued_at, checkpoint.body.issued_at
        )));
    }
    if checkpoint.signature.to_hex() != row.signature_hex {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} signature column does not match parsed signature",
            row.checkpoint_seq
        )));
    }
    if checkpoint.body.kernel_key.to_hex() != row.kernel_key_hex {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} kernel_key column {} does not match signed body {}",
            row.checkpoint_seq,
            row.kernel_key_hex,
            checkpoint.body.kernel_key.to_hex()
        )));
    }

    chio_kernel::checkpoint::validate_checkpoint(&checkpoint)
        .map_err(checkpoint_error_to_receipt_store)?;

    Ok(checkpoint)
}

/// Confirm every persisted checkpoint COLUMN that mirrors a signed body field
/// still matches that body. The `kernel_checkpoints` row stores
/// checkpoint_seq/batch_start_seq/batch_end_seq/tree_size/merkle_root/issued_at
/// and kernel_key as their OWN columns in addition to the signed
/// `statement_json`, so a column corrupted out of band (immutability trigger
/// bypassed) while statement_json is untouched must still be caught. Pure O(1)
/// int/string equality over a single row (no Ed25519 verify), so it is safe on
/// the incremental hot path. The `signature` column is the
/// signature OVER the body, not a body field, so each caller checks it
/// separately. Fail closed on any divergence.
pub(crate) fn ensure_checkpoint_columns_match_body(
    row: &PersistedCheckpointRow,
    body: &KernelCheckpointBody,
) -> Result<(), ReceiptStoreError> {
    if body.checkpoint_seq != row.checkpoint_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint row seq {} does not match signed checkpoint_seq {}; run `chio receipt audit`",
            row.checkpoint_seq, body.checkpoint_seq
        )));
    }
    if body.batch_start_seq != row.batch_start_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} batch_start_seq column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq, row.batch_start_seq, body.batch_start_seq
        )));
    }
    if body.batch_end_seq != row.batch_end_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} batch_end_seq column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq, row.batch_end_seq, body.batch_end_seq
        )));
    }
    if body.tree_size as u64 != row.tree_size {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} tree_size column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq, row.tree_size, body.tree_size
        )));
    }
    if body.merkle_root.to_hex() != row.merkle_root_hex {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} merkle_root column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq,
            row.merkle_root_hex,
            body.merkle_root.to_hex()
        )));
    }
    if body.issued_at != row.issued_at {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} issued_at column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq, row.issued_at, body.issued_at
        )));
    }
    if body.kernel_key.to_hex() != row.kernel_key_hex {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} kernel_key column {} does not match signed body {}; run `chio receipt audit`",
            row.checkpoint_seq,
            row.kernel_key_hex,
            body.kernel_key.to_hex()
        )));
    }
    Ok(())
}

pub(crate) fn verify_latest_checkpoint_integrity(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    if load_latest_persisted_checkpoint_row(connection)?.is_none() {
        return Ok(());
    }
    verify_checkpoint_chain_integrity(connection).map(|_| ())
}

/// The archival watermark that may be TRUSTED to skip the live Merkle rebuild
/// for every checkpoint whose `batch_end_seq <= W`, or 0 when no exemption is
/// safe. The watermark ledger's DB triggers enforce monotonicity ONLY, not that
/// the covered rows were ever archived, so three independent facts must hold
/// before the exemption applies:
///
/// 1. `W` matches a persisted checkpoint's `batch_end_seq`. The archival path
///    only ever advances `W` to a checkpoint boundary (`compute_archival_watermark`)
///    and `kernel_checkpoints` is immutable and signature-verified, so a genuine
///    `W` always lands on a boundary. A forged `W` past the latest real
///    checkpoint would otherwise skip the rebuild for never-archived live ranges.
///
/// 2. No live claim-log row survives at or below `W`. A matching boundary is not
///    proof of archival: a raw INSERT of `W` at a real boundary while the covered
///    rows stay live would satisfy (1) yet skip the Merkle rebuild for corrupted
///    still-present rows. The archival delete removes the entire covered claim-log
///    prefix atomically with the watermark insert, so a truly archived `W` leaves
///    no live row `entry_seq <= W`; any survivor means the prefix was never
///    archived.
///
/// 3. The archive named in the ledger actually holds the `[1, W]` claim-log
///    prefix. Conditions (1) and (2) are equally satisfied by a genuine rotation
///    and by an out-of-band delete of the live prefix followed by a planted
///    watermark: both land on a boundary and leave no live prefix row. Only the
///    genuine rotation co-archives the deleted rows first. Skipping the rebuild
///    trusts that those rows survive in the archive, so opening the archive and
///    confirming it covers the prefix ties the exemption to the evidence rather
///    than to the mere absence of live rows. A missing, unreadable, short, or
///    signer-divergent archive is not proof of archival and withdraws the
///    exemption.
///
/// Fail-closed: any condition failing yields 0 (full verification, which then
/// rejects a truly unarchived prefix because its live rows are gone). Archive
/// trust performs the deep receipt and checkpoint validation that replaces the
/// unavailable live-prefix validation.
pub(crate) fn trusted_retention_watermark(
    connection: &Connection,
) -> Result<u64, ReceiptStoreError> {
    let raw = retention_watermark(connection)?.unwrap_or(0);
    if raw == 0 {
        return Ok(0);
    }
    let raw_i64 = sqlite_i64(raw, "retention watermark")?;
    let boundary_matches: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM kernel_checkpoints WHERE batch_end_seq = ?1)",
        params![raw_i64],
        |row| row.get(0),
    )?;
    if !boundary_matches {
        return Ok(0);
    }
    let live_prefix_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM claim_receipt_log_entries WHERE entry_seq <= ?1)",
        params![raw_i64],
        |row| row.get(0),
    )?;
    if live_prefix_present {
        return Ok(0);
    }
    if !archived_prefix_is_backed(connection, raw_i64)? {
        return Ok(0);
    }
    Ok(raw)
}

/// True only when the archive named by the current watermark ledger row holds
/// byte-identical checkpoint rows and co-archived claim-log rows that fully
/// validate every checkpoint covered by `watermark`.
///
/// A count or Merkle-root match is not proof: an attacker can sign an authentic
/// receipt root with a different checkpoint key. For each covered checkpoint,
/// this requires exact live/archive checkpoint-row identity and then performs
/// full checkpoint validation against the archived receipts, including receipt
/// signatures, signer-key binding, range continuity, and Merkle reconstruction.
/// This is the deep re-verification the watermark exemption promises to serve
/// from the archive; it is bounded to the archived rows and runs on the
/// open/health path, never per append.
///
/// Opens the archive read-only on its own connection (never ATTACHing onto the
/// caller's). Any missing, unreadable, short, non-contiguous,
/// identity-divergent, signer-divergent, or root-divergent archive returns false
/// so the caller falls back to full verification, which then rejects the store
/// because the live prefix was deleted (fail-closed).
fn archived_prefix_is_backed(
    connection: &Connection,
    watermark: i64,
) -> Result<bool, ReceiptStoreError> {
    let Some(archive_path) = latest_watermark_archive_path(connection)? else {
        return Ok(false);
    };
    archive_path_backs_prefix(
        connection,
        &archive_path,
        sqlite_u64(watermark, "watermark")?,
    )
}

/// True only when the archive at `archive_path` holds byte-identical checkpoint
/// rows and co-archived claim-log rows that fully validate every checkpoint
/// covered by `watermark`.
///
/// The watermark-trust reader (`archived_prefix_is_backed`) resolves the path
/// from the ledger, but the rotation and repair paths must vet a SPECIFIC
/// archive before advancing or sealing a watermark over it: a subsequent
/// rotation must confirm the ledger archive still backs the committed prefix
/// before extending it, and a repair must confirm the supplied (or ledger)
/// archive re-derives the covered roots before deleting the orphaned live rows.
/// A row count or Merkle-root match is not proof: an attacker can sign the
/// authentic root with a different key. Each live checkpoint row must match its
/// archived row exactly, and full claim-log validation against the archive must
/// verify receipt signatures, signer-key binding, range continuity, and the
/// Merkle root. Opens the archive read-only on its own connection. Any missing,
/// unreadable, short, non-contiguous, identity-divergent, signer-divergent, or
/// root-divergent archive returns false so every caller falls back to full
/// verification fail-closed.
pub(crate) fn archive_path_backs_prefix(
    connection: &Connection,
    archive_path: &str,
    watermark: u64,
) -> Result<bool, ReceiptStoreError> {
    if watermark == 0 {
        return Ok(false);
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(mut archive) = rusqlite::Connection::open_with_flags(archive_path, flags) else {
        return Ok(false);
    };
    let covered: Vec<PersistedCheckpointRow> = load_all_persisted_checkpoint_rows(connection)?
        .into_iter()
        .filter(|row| row.batch_end_seq <= watermark)
        .collect();
    // A trusted watermark must fall on a real checkpoint boundary, so at least
    // one covered checkpoint must exist; none means the boundary is not backed.
    if covered.is_empty() {
        return Ok(false);
    }
    let Ok(archive_tx) = archive.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
    else {
        return Ok(false);
    };
    for live_row in covered {
        let archived_row = match load_persisted_checkpoint_row(&archive_tx, live_row.checkpoint_seq)
        {
            Ok(Some(row)) => row,
            Ok(None) | Err(_) => return Ok(false),
        };
        if archived_row != live_row {
            return Ok(false);
        }
        // Parsing authenticates the live row's signed body and denormalized
        // columns. Full validation against the archived claim log additionally
        // authenticates every receipt and binds its signer to the checkpoint
        // key before accepting the archived Merkle root.
        let checkpoint = parse_persisted_checkpoint_row(live_row)?;
        if validate_checkpoint_against_claim_log(&archive_tx, &checkpoint).is_err() {
            return Ok(false);
        }
    }
    archive_tx.commit()?;
    Ok(true)
}

/// Chain leaf hashes for every persisted checkpoint, in sequence order.
///
/// Fails closed when the persisted chain is not a gap-free run starting at
/// sequence 1: a chain commitment over an incomplete leaf set would be
/// unsound. Every leaf is derived from a signature-validated checkpoint body,
/// never from the denormalized mirror columns.
pub(crate) fn load_checkpoint_chain_leaf_hashes(
    connection: &Connection,
) -> Result<Vec<chio_core::hashing::Hash>, ReceiptStoreError> {
    let rows = load_all_persisted_checkpoint_rows(connection)?;
    let mut chain_leaf_hashes = Vec::with_capacity(rows.len());
    for row in rows {
        let checkpoint = parse_persisted_checkpoint_row(row)?;
        let checkpoint_seq = checkpoint.body.checkpoint_seq;
        let expected_seq = chain_leaf_hashes.len() as u64 + 1;
        if checkpoint_seq != expected_seq {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint chain has a gap: expected seq {expected_seq}, found {checkpoint_seq}"
            )));
        }
        chain_leaf_hashes.push(
            chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                .map_err(checkpoint_error_to_receipt_store)?,
        );
    }
    Ok(chain_leaf_hashes)
}

pub(crate) fn verify_checkpoint_chain_integrity(
    connection: &Connection,
) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
    verify_checkpoint_chain_integrity_with_frontier(connection).map(|(latest, _)| latest)
}

pub(crate) fn verify_checkpoint_chain_integrity_with_frontier(
    connection: &Connection,
) -> Result<(Option<KernelCheckpoint>, CheckpointChainFrontier), ReceiptStoreError> {
    let rows = load_all_persisted_checkpoint_rows(connection)?;
    let mut latest = None;
    let mut expected_head_ids = BTreeSet::new();
    let mut expected_witness_ids = BTreeSet::new();
    let mut expected_publication_ids = BTreeSet::new();
    let mut chain_frontier = chio_kernel::checkpoint::CheckpointChainFrontier::empty();

    let watermark = trusted_retention_watermark(connection)?;
    for row in rows {
        let checkpoint = parse_persisted_checkpoint_row(row.clone())?; // signature + column consistency
                                                                       // Checkpoints fully covered by a persisted archival watermark have
                                                                       // had their claim-log rows co-archived and deleted; their deep Merkle
                                                                       // re-verification is served from the archive. Skip only the live
                                                                       // Merkle rebuild for them; everything else (signature above, projection
                                                                       // rows, predecessor linkage below) still runs. Because W is always
                                                                       // some checkpoint's batch_end_seq and batches tile the prefix
                                                                       // contiguously (ADR-0008), no checkpoint range straddles the
                                                                       // watermark, so the exemption is all-or-nothing per checkpoint.
        if checkpoint.body.batch_end_seq > watermark {
            validate_checkpoint_against_claim_log(connection, &checkpoint)?;
        }
        validate_checkpoint_projection_rows(connection, &row, &checkpoint)?;
        let (_, expected_witness, _) = expected_checkpoint_projection_rows(&row, &checkpoint)?;
        expected_head_ids.insert(row.checkpoint_seq);
        if let Some(witness) = expected_witness {
            expected_witness_ids.insert(witness.witness_checkpoint_seq);
        }
        expected_publication_ids.insert(row.checkpoint_seq);
        if let Some(predecessor) = latest.as_ref() {
            chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                .map_err(checkpoint_error_to_receipt_store)?;
        } else {
            validate_checkpoint_base(&checkpoint)?;
        }
        // A signed chain commitment must equal the root over the chain leaves
        // accumulated so far, so a mid-chain rewrite of any earlier batch root
        // fails here even when every per-row signature still verifies.
        chain_frontier.append(
            chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                .map_err(checkpoint_error_to_receipt_store)?,
        );
        if let Some(chain_root) = checkpoint.body.chain_root {
            let expected_chain_root = chain_frontier.root().ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "checkpoint chain frontier is unexpectedly empty".to_string(),
                )
            })?;
            if chain_root != expected_chain_root {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} chain_root does not match the persisted chain",
                    checkpoint.body.checkpoint_seq
                )));
            }
        }
        latest = Some(checkpoint);
    }

    validate_checkpoint_projection_id_sets(
        connection,
        &expected_head_ids,
        &expected_witness_ids,
        &expected_publication_ids,
    )?;

    Ok((latest, chain_frontier))
}

/// Fully verify a cache-miss frontier and reconcile a same-length persisted
/// chain with the caller's already-verified head. A coherent out-of-band
/// replacement can pass the full audit on its own, but it must not be combined
/// with the stale predecessor retained by a long-lived writer.
#[cfg(test)]
pub(crate) fn rebuild_checkpoint_frontier(
    connection: &mut Connection,
    head_latest: Option<&KernelCheckpoint>,
) -> Result<CheckpointChainFrontier, ReceiptStoreError> {
    // Keep checkpoint rows, claim-log evidence, and projection ID sets on one
    // read snapshot. A peer may commit immediately before or after this audit,
    // but cannot appear in only the later projection queries.
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let (persisted_latest, frontier) = verify_checkpoint_chain_integrity_with_frontier(&tx)?;
    let head_seq = head_latest.map_or(0, |checkpoint| checkpoint.body.checkpoint_seq);
    if frontier.leaf_count() == head_seq && persisted_latest.as_ref() != head_latest {
        return Err(ReceiptStoreError::Conflict(format!(
            "persisted checkpoint at verified sequence {head_seq} diverged from the verified head while rebuilding the chain frontier"
        )));
    }
    tx.commit()?;
    Ok(frontier)
}

/// Rebuild a missing frontier and, when one is due, persist its first successor
/// under the same write lock that protects the full audit.
///
/// This is the cache-miss path only. The outer Immediate transaction prevents a
/// peer from replacing any audited checkpoint row or projection before the
/// candidate is built and inserted. The common cache-hit path remains
/// incremental.
pub(crate) fn build_checkpoint_after_frontier_cache_miss(
    connection: &mut Connection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<(CheckpointChainFrontier, bool), ReceiptStoreError> {
    build_checkpoint_after_frontier_cache_miss_with_hook(connection, head, signer, |_| Ok(()))
}

pub(crate) fn build_checkpoint_after_frontier_cache_miss_with_hook(
    connection: &mut Connection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
    after_audit: impl FnOnce(&rusqlite::Savepoint<'_>) -> Result<(), ReceiptStoreError>,
) -> Result<(CheckpointChainFrontier, bool), ReceiptStoreError> {
    let mut staged_head = head.clone();
    let outcome = checkpoint_guarded_immediate(connection, |tx| {
        let (_persisted_latest, mut frontier) =
            verify_checkpoint_chain_integrity_with_frontier(tx)?;
        let head_seq = staged_head.checkpoint_seq();
        if frontier.leaf_count() < head_seq {
            return Err(ReceiptStoreError::Conflict(format!(
                "persisted chain covers {} checkpoints but the verified head is at {head_seq}",
                frontier.leaf_count()
            )));
        }
        if head_seq > 0 {
            let persisted_head_row =
                load_persisted_checkpoint_row(tx, head_seq)?.ok_or_else(|| {
                    ReceiptStoreError::Conflict(format!(
                        "persisted checkpoint at verified sequence {head_seq} disappeared while rebuilding the chain frontier"
                    ))
                })?;
            let persisted_head = parse_persisted_checkpoint_row(persisted_head_row.clone())?;
            validate_checkpoint_projection_rows(tx, &persisted_head_row, &persisted_head)?;
            if Some(&persisted_head) != staged_head.latest_checkpoint.as_ref() {
                return Err(ReceiptStoreError::Conflict(format!(
                    "persisted checkpoint at verified sequence {head_seq} diverged from the verified head while rebuilding the chain frontier"
                )));
            }
        }

        let mut advanced = false;
        if frontier.leaf_count() > head_seq {
            catch_up_verified_head_to(tx, &mut staged_head, frontier.leaf_count())?;
            advanced = true;
        }
        if frontier.leaf_count() != staged_head.checkpoint_seq() {
            return Err(ReceiptStoreError::Conflict(format!(
                "persisted chain covers {} checkpoints but the head is at {}",
                frontier.leaf_count(),
                staged_head.checkpoint_seq()
            )));
        }
        after_audit(tx)?;
        if staged_head
            .claim_log_max_seq
            .saturating_sub(staged_head.checkpointed_entry_seq())
            < signer.max_batch
        {
            staged_head.chain_frontier = Some(frontier.clone());
            return Ok((frontier, advanced));
        }

        let start_seq = staged_head.checkpointed_entry_seq().saturating_add(1);
        let end_seq = start_seq.saturating_add(signer.max_batch - 1);
        ensure_claim_log_range_contiguous(tx, start_seq, end_seq, "checkpoint range")?;
        let receipt_bytes = load_claim_tree_canonical_bytes_range(tx, start_seq, end_seq)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = staged_head
            .checkpoint_seq()
            .checked_add(1)
            .ok_or_else(|| ReceiptStoreError::Conflict("checkpoint_seq overflow".to_string()))?;
        let checkpoint = chio_kernel::checkpoint::build_checkpoint_with_chain_frontier(
            checkpoint_seq,
            start_seq,
            end_seq,
            &receipt_bytes,
            &signer.keypair,
            staged_head.latest_checkpoint.as_ref(),
            &frontier,
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        #[cfg(test)]
        if test_hooks::panic_during_checkpoint_build(signer.max_batch) {
            panic!("injected test panic during background checkpoint build");
        }
        #[cfg(test)]
        if test_hooks::fail_checkpoint_build(signer.max_batch) {
            return Err(ReceiptStoreError::Conflict(
                "injected test checkpoint build failure".to_string(),
            ));
        }

        let adopted = insert_checkpoint_incremental_tx(
            tx,
            staged_head.latest_checkpoint.as_ref(),
            &checkpoint,
        )?;
        frontier = extend_frontier_with_adopted_checkpoint(&frontier, &adopted)?;
        staged_head.latest_checkpoint = Some(adopted);
        staged_head.chain_frontier = Some(frontier.clone());
        Ok((frontier, true))
    })?;
    *head = staged_head;
    Ok(outcome)
}

/// Insert or adopt one background checkpoint on the cache-hit path.
pub(crate) fn insert_background_checkpoint_guarded(
    connection: &mut Connection,
    predecessor: Option<&KernelCheckpoint>,
    prior_frontier: &CheckpointChainFrontier,
    checkpoint: &KernelCheckpoint,
) -> Result<(KernelCheckpoint, CheckpointChainFrontier), ReceiptStoreError> {
    checkpoint_guarded_immediate(connection, |tx| {
        let adopted = insert_checkpoint_incremental_tx(tx, predecessor, checkpoint)?;
        let frontier = extend_frontier_with_adopted_checkpoint(prior_frontier, &adopted)?;
        Ok((adopted, frontier))
    })
}

fn extend_frontier_with_adopted_checkpoint(
    prior_frontier: &CheckpointChainFrontier,
    adopted: &KernelCheckpoint,
) -> Result<CheckpointChainFrontier, ReceiptStoreError> {
    let mut frontier = prior_frontier.clone();
    frontier.append(
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&adopted.body)
            .map_err(checkpoint_error_to_receipt_store)?,
    );
    if adopted.body.chain_root != frontier.root() {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} adopted with a divergent chain commitment",
            adopted.body.checkpoint_seq
        )));
    }
    Ok(frontier)
}

/// Extend the verified checkpoint-chain frontier by one peer checkpoint.
///
/// A cache miss rebuilds only the prefix represented by `predecessor`; startup
/// normally retains the frontier returned by full verification. Signed v2
/// roots must match before the caller advances its verified head. Legacy v1
/// checkpoints carry no root, but their leaves still extend the frontier so a
/// later v2 checkpoint commits the complete history.
pub(crate) fn advance_verified_checkpoint_chain_frontier(
    connection: &Connection,
    cached: Option<&CheckpointChainFrontier>,
    predecessor: Option<&KernelCheckpoint>,
    checkpoint: &KernelCheckpoint,
) -> Result<CheckpointChainFrontier, ReceiptStoreError> {
    let predecessor_seq = predecessor.map_or(0, |item| item.body.checkpoint_seq);
    let mut frontier = match cached.filter(|item| item.leaf_count() == predecessor_seq) {
        Some(frontier) => frontier.clone(),
        None => {
            // A missing cache has no trusted prefix commitment of its own.
            // Prove the persisted chain before deriving the predecessor slice.
            verify_checkpoint_chain_integrity_with_frontier(connection)?;
            let chain_leaf_hashes = load_checkpoint_chain_leaf_hashes(connection)?;
            let prefix_len = usize::try_from(predecessor_seq).map_err(|_| {
                ReceiptStoreError::Conflict(format!(
                    "verified checkpoint sequence {predecessor_seq} exceeds platform limits"
                ))
            })?;
            if chain_leaf_hashes.len() < prefix_len {
                return Err(ReceiptStoreError::Conflict(format!(
                    "persisted checkpoint chain ends before verified head {predecessor_seq}"
                )));
            }
            CheckpointChainFrontier::from_leaves(&chain_leaf_hashes[..prefix_len])
        }
    };
    if let Some(chain_root) = predecessor.and_then(|item| item.body.chain_root) {
        if frontier.root() != Some(chain_root) {
            return Err(ReceiptStoreError::Conflict(format!(
                "verified checkpoint {predecessor_seq} chain_root does not match the persisted chain"
            )));
        }
    }
    frontier.append(
        chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
            .map_err(checkpoint_error_to_receipt_store)?,
    );
    if let Some(chain_root) = checkpoint.body.chain_root {
        if frontier.root() != Some(chain_root) {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} chain_root does not match the persisted chain",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    Ok(frontier)
}

pub(crate) fn validate_checkpoint_base(
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    if checkpoint.body.checkpoint_seq != 1 {
        return Err(ReceiptStoreError::Conflict(format!(
            "first checkpoint in store must have checkpoint_seq 1, got {}",
            checkpoint.body.checkpoint_seq
        )));
    }
    if checkpoint.body.batch_start_seq != 1 {
        return Err(ReceiptStoreError::Conflict(format!(
            "first checkpoint must start at entry_seq 1, got {}",
            checkpoint.body.batch_start_seq
        )));
    }
    if checkpoint.body.previous_checkpoint_sha256.is_some() {
        return Err(ReceiptStoreError::Conflict(
            "first checkpoint must not include a predecessor digest".to_string(),
        ));
    }
    Ok(())
}

/// Confirm the LATEST persisted checkpoint is CHAIN-CONNECTED before an
/// operator/health surface (`flush_report`) trusts its `batch_end_seq`. A single
/// row parsed by `parse_persisted_checkpoint_row` validates only its OWN
/// columns/body/signature; a latest row with a skipped `checkpoint_seq` or a
/// wrong predecessor digest still parses individually yet is DISCONNECTED from
/// the chain, which a full `verify_checkpoint_chain_integrity` would reject.
/// This is the bounded predecessor check:
/// for the base checkpoint (seq 1) confirm it is a valid base; otherwise read
/// the IMMEDIATELY PRIOR checkpoint row (seq - 1) and confirm predecessor
/// linkage (contiguous seq/batch + matching `previous_checkpoint_sha256`). One
/// indexed row read + linkage compare, NOT a full O(N) chain walk, so it never
/// lands on the per-append hot path. Fail closed on any gap or mismatch.
pub(crate) fn latest_checkpoint_is_chain_connected(
    connection: &Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    let checkpoint_seq = checkpoint.body.checkpoint_seq;
    // Prefix-completeness guard: the immediate-predecessor
    // link below proves only that the LATEST checkpoint connects to seq - 1. An
    // EARLIER checkpoint row missing from the persisted chain (a partial import,
    // an out-of-band delete) leaves seq-1..seq intact yet the range that earlier
    // checkpoint attested is no longer covered, and `flush_report` would still
    // report this checkpoint's `batch_end_seq` as checkpointed - hiding an
    // uncheckpointed range and letting retention prune unattested entries. The
    // persisted chain must therefore hold EVERY seq 1..=checkpoint_seq with no
    // gap. Because `checkpoint_seq` values are unique and positive and this is
    // the LATEST checkpoint (its seq is the max), `COUNT(*) == checkpoint_seq`
    // together with `MAX(checkpoint_seq) == checkpoint_seq` proves the prefix is
    // gap-free. This is one aggregate over the checkpoint table (its row count is
    // ~ entries / batch, and there is NO per-checkpoint parse, signature verify,
    // or Merkle rebuild), so it stays bounded and never re-verifies whole
    // history; a full `verify_checkpoint_chain_integrity` parses and
    // re-validates every checkpoint. A genuine earlier-row TAMPER (an interior
    // predecessor/projection corrupted while all rows remain present) is not a
    // gap and stays the domain of the O(N) `chio receipt audit`.
    let (present, max_seq) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(checkpoint_seq), 0) FROM kernel_checkpoints",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let present = sqlite_u64(present, "persisted checkpoint count")?;
    let max_seq = sqlite_u64(max_seq, "persisted checkpoint max seq")?;
    if max_seq != checkpoint_seq || present != checkpoint_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint chain prefix is incomplete: latest checkpoint is {checkpoint_seq} but the persisted chain holds {present} checkpoints up to {max_seq}; run `chio receipt audit`"
        )));
    }
    if checkpoint_seq <= 1 {
        return validate_checkpoint_base(checkpoint);
    }
    let predecessor_seq = checkpoint_seq - 1;
    let Some(predecessor_row) = load_persisted_checkpoint_row(connection, predecessor_seq)? else {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {checkpoint_seq} predecessor {predecessor_seq} is missing; run `chio receipt audit`"
        )));
    };
    let predecessor = parse_persisted_checkpoint_row(predecessor_row)?;
    chio_kernel::checkpoint::validate_checkpoint_predecessor(&predecessor, checkpoint)
        .map_err(checkpoint_error_to_receipt_store)
}

pub(crate) fn validate_checkpoint_against_claim_log(
    connection: &Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    validate_checkpoint_claim_log_signer_range(connection, checkpoint)?;
    let rows = load_claim_tree_canonical_bytes_range(
        connection,
        checkpoint.body.batch_start_seq,
        checkpoint.body.batch_end_seq,
    )?;
    let receipt_bytes = rows.into_iter().map(|(_, bytes)| bytes).collect::<Vec<_>>();
    if receipt_bytes.len() != checkpoint.body.tree_size {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} tree_size {} does not match claim receipt log range {}..={} length {}",
            checkpoint.body.checkpoint_seq,
            checkpoint.body.tree_size,
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq,
            receipt_bytes.len()
        )));
    }
    let tree = chio_core::merkle::MerkleTree::from_leaves(&receipt_bytes).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "checkpoint receipt-log merkle rebuild failed: {error}"
        ))
    })?;
    if tree.root() != checkpoint.body.merkle_root {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} merkle_root does not match claim receipt log range {}..={}",
            checkpoint.body.checkpoint_seq,
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        )));
    }
    Ok(())
}

/// Validate a persisted checkpoint against the live claim log, falling back to
/// its trusted archive proof only when live validation fails and the complete
/// range is covered by the retention watermark.
///
/// The normal live path does not open or scan an archive. A straddling or
/// unwatermarked range returns the original live-validation error. This helper
/// is only sound for a checkpoint already persisted in `kernel_checkpoints`,
/// because the trusted-watermark proof re-derives those persisted roots.
pub(crate) fn validate_persisted_checkpoint_against_live_or_archived_claim_log(
    connection: &Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    match validate_checkpoint_against_claim_log(connection, checkpoint) {
        Ok(()) => Ok(()),
        Err(live_error) => {
            let watermark = trusted_retention_watermark(connection)?;
            if checkpoint.body.batch_end_seq <= watermark {
                Ok(())
            } else {
                Err(live_error)
            }
        }
    }
}

pub(crate) fn store_kernel_checkpoint_atomic(
    connection: &mut Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    checkpoint_guarded_immediate(connection, |tx| {
        // Operator / import append re-verification: a
        // manually stored or externally imported checkpoint is a rare, off-hot-path
        // surface. `store_kernel_checkpoint_tx` only parses the LATEST checkpoint as
        // the predecessor, so a mid-chain tamper (an earlier checkpoint or a
        // projection row whose latest row still parses) would go undetected and this
        // append would extend an already-corrupt chain. Re-verify the FULL persisted
        // chain here so the operator path fails closed. This is the operator/import
        // surface ONLY; the background builder (maybe_build_checkpoint /
        // insert_checkpoint_incremental_tx) deliberately stays on the O(b)
        // incremental head and does not run through here. Full-chain cost is
        // accepted here precisely because this is the rare operator path.
        verify_checkpoint_chain_integrity(tx)?;
        // An extending checkpoint that carries a chain commitment must commit
        // exactly the persisted chain plus its own leaf; anything else is caught
        // here rather than on the next append. Idempotent re-imports of an
        // already-persisted sequence are byte-compared by
        // `store_kernel_checkpoint_tx` instead.
        if let Some(chain_root) = checkpoint.body.chain_root {
            let chain_leaf_hashes = load_checkpoint_chain_leaf_hashes(tx)?;
            if checkpoint.body.checkpoint_seq == chain_leaf_hashes.len() as u64 + 1 {
                let mut chain_frontier =
                    chio_kernel::checkpoint::CheckpointChainFrontier::from_leaves(
                        &chain_leaf_hashes,
                    );
                chain_frontier.append(
                    chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                        .map_err(checkpoint_error_to_receipt_store)?,
                );
                let expected_chain_root = chain_frontier.root().ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "extended checkpoint chain frontier is unexpectedly empty".to_string(),
                    )
                })?;
                if chain_root != expected_chain_root {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "checkpoint {} chain_root does not extend the persisted chain",
                        checkpoint.body.checkpoint_seq
                    )));
                }
            }
        }
        store_kernel_checkpoint_tx(tx, checkpoint)
    })
}

pub(crate) fn create_next_receipt_checkpoint_atomic(
    connection: &mut Connection,
    max_batch: u64,
    keypair: &Keypair,
) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
    checkpoint_guarded_immediate(connection, |tx| {
        let previous_checkpoint = verify_checkpoint_chain_integrity(tx)?;
        let latest_committed_entry_seq = super::latest_claim_log_entry_seq(tx)?;
        let Some(range) = super::next_checkpoint_range_for_connection(tx, max_batch)? else {
            let latest_checkpointed_entry_seq = previous_checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
            return Ok(ReceiptCheckpointCreateReport {
                created: false,
                checkpoint_seq: None,
                batch_start_seq: None,
                batch_end_seq: None,
                latest_committed_entry_seq,
                latest_checkpointed_entry_seq,
            });
        };

        let receipt_bytes =
            load_claim_tree_canonical_bytes_range(tx, range.start_seq, range.end_seq)?
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>();
        let checkpoint_seq = previous_checkpoint.as_ref().map_or(Ok(1), |checkpoint| {
            checkpoint
                .body
                .checkpoint_seq
                .checked_add(1)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while creating receipt checkpoint".to_string(),
                    )
                })
        })?;
        let chain_leaf_hashes = load_checkpoint_chain_leaf_hashes(tx)?;
        let checkpoint = chio_kernel::build_checkpoint_with_previous(
            checkpoint_seq,
            range.start_seq,
            range.end_seq,
            &receipt_bytes,
            keypair,
            previous_checkpoint.as_ref(),
            &chain_leaf_hashes,
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        store_kernel_checkpoint_tx(tx, &checkpoint)?;
        Ok(ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(checkpoint.body.checkpoint_seq),
            batch_start_seq: Some(checkpoint.body.batch_start_seq),
            batch_end_seq: Some(checkpoint.body.batch_end_seq),
            latest_committed_entry_seq,
            latest_checkpointed_entry_seq: checkpoint.body.batch_end_seq,
        })
    })
}

/// Insert one checkpoint with single-shot validation against a KNOWN
/// predecessor: validate_checkpoint (one signature), predecessor linkage,
/// claim-log range check for the new range only, INSERT (projection triggers
/// populate tree-head/witness/publication rows), read-back equality, and
/// projection-row validation for the new row. No chain rebuild. Returns the
/// checkpoint now persisted at this seq (the one just inserted, or the
/// concurrently committed winner that was adopted) so the caller can catch
/// its cached head up to it.
pub(crate) fn insert_checkpoint_incremental_tx(
    tx: &rusqlite::Savepoint<'_>,
    predecessor: Option<&KernelCheckpoint>,
    checkpoint: &KernelCheckpoint,
) -> Result<KernelCheckpoint, ReceiptStoreError> {
    chio_kernel::checkpoint::validate_checkpoint(checkpoint)
        .map_err(checkpoint_error_to_receipt_store)?;
    match predecessor {
        Some(predecessor) => {
            chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, checkpoint)
                .map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "checkpoint predecessor continuity violation: {error}"
                    ))
                })?;
        }
        None => validate_checkpoint_base(checkpoint)?,
    }
    // The frontier audit and candidate construction happen before the caller
    // opens this Immediate transaction. A peer can coherently replace the
    // persisted prefix in that gap, leaving `predecessor` and the candidate
    // internally consistent with each other but disconnected from the prefix
    // now on disk. Re-read seq - 1 after the write lock is held and require it
    // to be byte-identical to the predecessor used to build the candidate.
    // This still permits a peer winner at the candidate's own sequence: that
    // row is handled and adopted below after its shared predecessor is pinned.
    if let Some(predecessor) = predecessor {
        let predecessor_seq = predecessor.body.checkpoint_seq;
        let persisted_predecessor_row =
            load_persisted_checkpoint_row(tx, predecessor_seq)?.ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "checkpoint {} cached predecessor {predecessor_seq} disappeared before persistence",
                    checkpoint.body.checkpoint_seq
                ))
            })?;
        let persisted_predecessor =
            parse_persisted_checkpoint_row(persisted_predecessor_row.clone())?;
        validate_checkpoint_projection_rows(
            tx,
            &persisted_predecessor_row,
            &persisted_predecessor,
        )?;
        if persisted_predecessor != *predecessor {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} cached predecessor {predecessor_seq} changed before persistence",
                checkpoint.body.checkpoint_seq
            )));
        }
    }
    // Idempotent and concurrent-winner background-checkpoint convergence
    // (the byte-identical case and the clock-skew case).
    // Two kernels or store instances sharing one receipt DB can each build the
    // same due checkpoint before either head catches up. The loser reaches
    // here after the winner already committed a row at this seq. A
    // byte-identical winner is adopted as-is. A winner that differs only by its
    // wall-clock `issued_at` (and thus its signature) is still a VALID
    // checkpoint for the same range, so instead of failing the raw INSERT on
    // the primary-key conflict (which would record writer.last_error and report
    // the store UNHEALTHY though the persisted chain is valid) we VALIDATE the
    // winner BOUNDED and ADOPT it: its signature (via parse_persisted_
    // checkpoint_row), its predecessor linkage against our cached predecessor,
    // its own claim-log range (live, or fully covered by a trusted archival
    // watermark), and its projection rows. That is one checkpoint plus its
    // bounded batch range, NOT a full chain rebuild.
    // Only a genuinely invalid or divergent-predecessor winner stays
    // fail-closed.
    if let Some(existing) = load_persisted_checkpoint_row(tx, checkpoint.body.checkpoint_seq)? {
        let existing_checkpoint = parse_persisted_checkpoint_row(existing.clone())?;
        if existing_checkpoint != *checkpoint {
            match predecessor {
                Some(predecessor) => {
                    chio_kernel::checkpoint::validate_checkpoint_predecessor(
                        predecessor,
                        &existing_checkpoint,
                    )
                    .map_err(|error| {
                        ReceiptStoreError::Conflict(format!(
                            "checkpoint {} already exists with a divergent predecessor linkage: {error}",
                            checkpoint.body.checkpoint_seq
                        ))
                    })?;
                }
                None => validate_checkpoint_base(&existing_checkpoint)?,
            }
        }
        validate_persisted_checkpoint_against_live_or_archived_claim_log(tx, &existing_checkpoint)?;
        validate_checkpoint_projection_rows(tx, &existing, &existing_checkpoint)?;
        return Ok(existing_checkpoint);
    }
    validate_checkpoint_against_claim_log(tx, checkpoint)?;
    let statement_json = serde_json::to_string(&checkpoint.body)?;
    tx.execute(
        r#"
        INSERT INTO kernel_checkpoints (
            checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
            merkle_root, issued_at, statement_json, signature, kernel_key
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            sqlite_i64(checkpoint.body.checkpoint_seq, "checkpoint_seq")?,
            sqlite_i64(checkpoint.body.batch_start_seq, "batch_start_seq")?,
            sqlite_i64(checkpoint.body.batch_end_seq, "batch_end_seq")?,
            sqlite_i64(checkpoint.body.tree_size as u64, "tree_size")?,
            checkpoint.body.merkle_root.to_hex(),
            sqlite_i64(checkpoint.body.issued_at, "issued_at")?,
            statement_json,
            checkpoint.signature.to_hex(),
            checkpoint.body.kernel_key.to_hex(),
        ],
    )
    .map_err(|error| ReceiptStoreError::Conflict(format!("checkpoint append conflict: {error}")))?;
    let stored =
        load_persisted_checkpoint_row(tx, checkpoint.body.checkpoint_seq)?.ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "checkpoint {} was not visible after persistence",
                checkpoint.body.checkpoint_seq
            ))
        })?;
    let parsed = parse_persisted_checkpoint_row(stored.clone())?;
    if parsed != *checkpoint {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} persisted with conflicting contents",
            checkpoint.body.checkpoint_seq
        )));
    }
    validate_checkpoint_projection_rows(tx, &stored, &parsed)?;
    Ok(parsed)
}

fn store_kernel_checkpoint_tx(
    tx: &rusqlite::Savepoint<'_>,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    chio_kernel::checkpoint::validate_checkpoint(checkpoint)
        .map_err(checkpoint_error_to_receipt_store)?;

    if let Some(existing) = load_persisted_checkpoint_row(tx, checkpoint.body.checkpoint_seq)? {
        let existing_checkpoint = parse_persisted_checkpoint_row(existing.clone())?;
        if existing_checkpoint == *checkpoint {
            validate_checkpoint_projection_rows(tx, &existing, checkpoint)?;
            return Ok(());
        }
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} already exists with different content",
            checkpoint.body.checkpoint_seq
        )));
    }

    let predecessor = load_latest_persisted_checkpoint_row(tx)?
        .map(parse_persisted_checkpoint_row)
        .transpose()?;
    if let Some(predecessor) = predecessor.as_ref() {
        if checkpoint.body.checkpoint_seq <= predecessor.body.checkpoint_seq {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} must be appended after existing checkpoint {}",
                checkpoint.body.checkpoint_seq, predecessor.body.checkpoint_seq
            )));
        }
    } else if checkpoint.body.checkpoint_seq != 1 {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} cannot initialize an empty checkpoint log",
            checkpoint.body.checkpoint_seq
        )));
    }
    insert_checkpoint_incremental_tx(tx, predecessor.as_ref(), checkpoint).map(|_| ())
}

fn validate_checkpoint_claim_log_signer_range(
    connection: &Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    super::ensure_claim_log_range_contiguous(
        connection,
        checkpoint.body.batch_start_seq,
        checkpoint.body.batch_end_seq,
        "checkpoint signer binding",
    )?;
    let mut range_signer_key: Option<String> = None;
    let mut statement = connection.prepare(
        r#"
        SELECT entry_seq, receipt_kind, raw_json
        FROM claim_receipt_log_entries
        WHERE entry_seq >= ?1 AND entry_seq <= ?2
        ORDER BY entry_seq ASC
        "#,
    )?;
    let rows = statement.query_map(
        params![
            sqlite_i64(
                checkpoint.body.batch_start_seq,
                "checkpoint signer start_seq"
            )?,
            sqlite_i64(checkpoint.body.batch_end_seq, "checkpoint signer end_seq")?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    for row in rows {
        let (entry_seq, receipt_kind, raw_json) = row?;
        let entry_seq = sqlite_positive_u64(entry_seq, "checkpoint signer entry_seq")?;
        let receipt_key = match receipt_kind.as_str() {
            "tool_receipt" => decode_verified_chio_receipt(
                &raw_json,
                "checkpoint signer tool receipt",
                Some(entry_seq),
            )?
            .kernel_key
            .to_hex(),
            "child_receipt" => decode_verified_child_receipt(
                &raw_json,
                "checkpoint signer child receipt",
                Some(entry_seq),
            )?
            .kernel_key
            .to_hex(),
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "unsupported claim receipt kind `{other}` in checkpoint signer binding"
                )));
            }
        };
        match range_signer_key.as_deref() {
            Some(expected_key) if expected_key != receipt_key => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} covers mixed receipt signer range: {receipt_kind} entry {entry_seq} uses kernel key {receipt_key}, expected {expected_key}",
                    checkpoint.body.checkpoint_seq
                )));
            }
            Some(_) => {}
            None => range_signer_key = Some(receipt_key),
        }
    }
    let checkpoint_key = checkpoint.body.kernel_key.to_hex();
    match range_signer_key.as_deref() {
        Some(receipt_key) if receipt_key == checkpoint_key => Ok(()),
        Some(receipt_key) => Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} kernel key {} does not match receipt signer key {} for claim receipt log range {}..={}",
            checkpoint.body.checkpoint_seq,
            checkpoint_key,
            receipt_key,
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ))),
        None => Err(ReceiptStoreError::Conflict(format!(
            "checkpoint {} covers no receipt signer keys in claim receipt log range {}..={}",
            checkpoint.body.checkpoint_seq,
            checkpoint.body.batch_start_seq,
            checkpoint.body.batch_end_seq
        ))),
    }
}

fn expected_checkpoint_projection_rows(
    row: &PersistedCheckpointRow,
    checkpoint: &KernelCheckpoint,
) -> Result<
    (
        CheckpointTreeHeadProjectionRow,
        Option<CheckpointPredecessorWitnessProjectionRow>,
        CheckpointPublicationMetadataProjectionRow,
    ),
    ReceiptStoreError,
> {
    let publication = chio_kernel::checkpoint::build_checkpoint_publication(checkpoint)
        .map_err(checkpoint_error_to_receipt_store)?;
    let head = CheckpointTreeHeadProjectionRow {
        checkpoint_seq: row.checkpoint_seq,
        batch_start_seq: row.batch_start_seq,
        batch_end_seq: row.batch_end_seq,
        tree_size: row.tree_size,
        merkle_root: row.merkle_root_hex.clone(),
        issued_at: row.issued_at,
        kernel_key: row.kernel_key_hex.clone(),
        previous_checkpoint_sha256: checkpoint.body.previous_checkpoint_sha256.clone(),
        statement_json: row.statement_json.clone(),
        signature: row.signature_hex.clone(),
    };
    let witness = if let Some(previous_checkpoint_sha256) =
        checkpoint.body.previous_checkpoint_sha256.clone()
    {
        if checkpoint.body.checkpoint_seq <= 1 {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} cannot witness a predecessor digest",
                checkpoint.body.checkpoint_seq
            )));
        }
        Some(CheckpointPredecessorWitnessProjectionRow {
            predecessor_checkpoint_seq: checkpoint.body.checkpoint_seq - 1,
            witness_checkpoint_seq: checkpoint.body.checkpoint_seq,
            previous_checkpoint_sha256,
            witnessed_at: checkpoint.body.issued_at,
            witness_statement_json: row.statement_json.clone(),
        })
    } else {
        None
    };
    let publication = CheckpointPublicationMetadataProjectionRow {
        checkpoint_seq: publication.checkpoint_seq,
        publication_schema: publication.schema,
        merkle_root: publication.merkle_root.to_hex(),
        published_at: publication.published_at,
        kernel_key: publication.kernel_key.to_hex(),
        log_tree_size: publication.log_tree_size,
        entry_start_seq: publication.entry_start_seq,
        entry_end_seq: publication.entry_end_seq,
        previous_checkpoint_sha256: publication.previous_checkpoint_sha256,
    };
    Ok((head, witness, publication))
}

pub(crate) fn validate_checkpoint_projection_rows(
    connection: &Connection,
    row: &PersistedCheckpointRow,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    let (expected_head, expected_witness, expected_publication) =
        expected_checkpoint_projection_rows(row, checkpoint)?;

    match load_checkpoint_tree_head_projection_row(connection, row.checkpoint_seq)? {
        Some(existing) if existing == expected_head => {}
        Some(_) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint tree head projection for checkpoint {} diverges from persisted checkpoint row",
                row.checkpoint_seq
            )));
        }
        None => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint tree head projection for checkpoint {} is missing",
                row.checkpoint_seq
            )));
        }
    }

    match (
        load_checkpoint_predecessor_witness_projection_row(connection, row.checkpoint_seq)?,
        expected_witness,
    ) {
        (Some(existing), Some(expected)) if existing == expected => {}
        (Some(_), Some(_)) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint predecessor witness projection for checkpoint {} diverges from persisted checkpoint chain",
                row.checkpoint_seq
            )));
        }
        (None, Some(_)) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint predecessor witness projection for checkpoint {} is missing",
                row.checkpoint_seq
            )));
        }
        (Some(_), None) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint predecessor witness projection for checkpoint {} is unexpected",
                row.checkpoint_seq
            )));
        }
        (None, None) => {}
    }

    match load_checkpoint_publication_metadata_projection_row(connection, row.checkpoint_seq)? {
        Some(existing) if existing == expected_publication => {}
        Some(_) => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint publication metadata projection for checkpoint {} diverges from persisted checkpoint row",
                row.checkpoint_seq
            )));
        }
        None => {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint publication metadata projection for checkpoint {} is missing",
                row.checkpoint_seq
            )));
        }
    }

    Ok(())
}

fn validate_checkpoint_projection_id_sets(
    connection: &Connection,
    expected_head_ids: &BTreeSet<u64>,
    expected_witness_ids: &BTreeSet<u64>,
    expected_publication_ids: &BTreeSet<u64>,
) -> Result<(), ReceiptStoreError> {
    let existing_head_ids = load_checkpoint_tree_head_projection_ids(connection)?;
    if &existing_head_ids != expected_head_ids {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint tree head projection drift detected ({})",
            projection_set_drift(expected_head_ids, &existing_head_ids)
        )));
    }

    let existing_witness_ids = load_checkpoint_predecessor_witness_projection_ids(connection)?;
    if &existing_witness_ids != expected_witness_ids {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint predecessor witness projection drift detected ({})",
            projection_set_drift(expected_witness_ids, &existing_witness_ids)
        )));
    }

    let existing_publication_ids = load_checkpoint_publication_metadata_projection_ids(connection)?;
    if &existing_publication_ids != expected_publication_ids {
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint publication metadata projection drift detected ({})",
            projection_set_drift(expected_publication_ids, &existing_publication_ids)
        )));
    }

    Ok(())
}

fn projection_set_drift(expected: &BTreeSet<u64>, existing: &BTreeSet<u64>) -> String {
    let missing = expected.difference(existing).next().copied();
    let extra = existing.difference(expected).next().copied();
    format!(
        "missing: {}, extra: {}",
        missing
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        extra
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    )
}
