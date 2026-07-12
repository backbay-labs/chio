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

#[derive(Debug, Clone)]
pub(crate) struct PersistedCheckpointRow {
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

pub(crate) fn load_persisted_checkpoint_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
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
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
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
        SELECT checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
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
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;

    rows.map(|row| {
        let (
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
///    than to the mere absence of live rows. A missing, unreadable, or short
///    archive is not proof of archival and withdraws the exemption.
///
/// Fail-closed: any condition failing yields 0 (full verification, which then
/// rejects a truly unarchived prefix because its live rows are gone). Bounded to
/// two indexed existence probes plus one archive open and indexed count, never an
/// O(log length) scan.
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
/// the co-archived claim-log rows that re-derive the SIGNED checkpoint roots for
/// every checkpoint covered by `watermark`.
///
/// A count of `entry_seq <= watermark` rows is not proof: an archive that merely
/// holds `watermark` rows keyed on the right `entry_seq` values but carrying
/// replaced or corrupted `raw_json` would satisfy a count check while no longer
/// matching the signed checkpoint roots, so skipping the live Merkle rebuild for
/// that prefix would accept a store whose only retained evidence has been
/// tampered. Instead, for each covered checkpoint this re-derives the Merkle
/// root from the archived receipts in the checkpoint's batch range and compares
/// it to the checkpoint's signed root (obtained by parsing the live
/// `kernel_checkpoints` row, which validates the signature and that the stored
/// root matches the signed body). The kernel signing key is required to produce
/// a batch of receipts that hash to a signed root, so a forged archive cannot
/// pass. This is the deep re-verification the watermark exemption promises to
/// serve from the archive; it is bounded to the archived rows and runs on the
/// open/health path, never per append.
///
/// Opens the archive read-only on its own connection (never ATTACHing onto the
/// caller's). Any missing, unreadable, short, non-contiguous, or root-divergent
/// archive returns false so the caller falls back to full verification, which
/// then rejects the store because the live prefix was deleted (fail-closed).
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

/// True only when the archive at `archive_path` holds co-archived claim-log rows
/// that re-derive the SIGNED checkpoint roots for every checkpoint covered by
/// `watermark`.
///
/// The watermark-trust reader (`archived_prefix_is_backed`) resolves the path
/// from the ledger, but the rotation and repair paths must vet a SPECIFIC
/// archive before advancing or sealing a watermark over it: a subsequent
/// rotation must confirm the ledger archive still backs the committed prefix
/// before extending it, and a repair must confirm the supplied (or ledger)
/// archive re-derives the covered roots before deleting the orphaned live rows.
/// A row count is not proof: an archive holding the right `entry_seq` values but
/// replaced or corrupted `raw_json` would satisfy a count while no longer
/// matching the signed roots. Opens the archive read-only on its own connection.
/// Any missing, unreadable, short, non-contiguous, or root-divergent archive
/// returns false (never an error) so every caller falls back to full
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
    let Ok(archive) = rusqlite::Connection::open_with_flags(archive_path, flags) else {
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
    for row in covered {
        // Parse validates the signature and that the stored root matches the
        // signed body, so `body.merkle_root` is the authenticated root.
        let checkpoint = parse_persisted_checkpoint_row(row)?;
        if !archive_batch_matches_signed_root(&archive, &checkpoint)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Re-derive the Merkle root of `checkpoint`'s batch range from the archived
/// receipts and compare it to the checkpoint's signed root. False (not an error)
/// when the archive is missing rows, has the wrong leaf count, or produces a
/// different root, so the caller withdraws the watermark exemption fail-closed.
fn archive_batch_matches_signed_root(
    archive: &Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<bool, ReceiptStoreError> {
    let rows = match load_claim_tree_canonical_bytes_range(
        archive,
        checkpoint.body.batch_start_seq,
        checkpoint.body.batch_end_seq,
    ) {
        Ok(rows) => rows,
        // A short or non-contiguous archived range is not proof of archival.
        Err(_) => return Ok(false),
    };
    let receipt_bytes: Vec<Vec<u8>> = rows.into_iter().map(|(_, bytes)| bytes).collect();
    if receipt_bytes.len() != checkpoint.body.tree_size {
        return Ok(false);
    }
    let tree = match chio_core::merkle::MerkleTree::from_leaves(&receipt_bytes) {
        Ok(tree) => tree,
        Err(_) => return Ok(false),
    };
    Ok(tree.root() == checkpoint.body.merkle_root)
}

pub(crate) fn verify_checkpoint_chain_integrity(
    connection: &Connection,
) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
    let rows = load_all_persisted_checkpoint_rows(connection)?;
    let mut latest = None;
    let mut expected_head_ids = BTreeSet::new();
    let mut expected_witness_ids = BTreeSet::new();
    let mut expected_publication_ids = BTreeSet::new();

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
        latest = Some(checkpoint);
    }

    validate_checkpoint_projection_id_sets(
        connection,
        &expected_head_ids,
        &expected_witness_ids,
        &expected_publication_ids,
    )?;

    Ok(latest)
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

pub(crate) fn store_kernel_checkpoint_atomic(
    connection: &mut Connection,
    checkpoint: &KernelCheckpoint,
) -> Result<(), ReceiptStoreError> {
    ensure_checkpoint_transparency_guards(connection)?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Operator / import append re-verification: a
    // manually stored or externally imported checkpoint is a rare, off-hot-path
    // surface. `store_kernel_checkpoint_tx` only parses the LATEST checkpoint as
    // the predecessor, so a mid-chain tamper (an earlier checkpoint or a
    // projection row whose latest row still parses) would go undetected and this
    // append would extend an already-corrupt chain. Re-verify the FULL persisted
    // chain here so the operator path fails closed. This is the operator/import
    // surface ONLY; the background builder (maybe_build_checkpoint /
    // insert_checkpoint_incremental_tx) deliberately stays on the O(b)
    // incremental head and does not run through here.
    verify_checkpoint_chain_integrity(&tx)?;
    store_kernel_checkpoint_tx(&tx, checkpoint)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn create_next_receipt_checkpoint_atomic(
    connection: &mut Connection,
    max_batch: u64,
    keypair: &Keypair,
) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
    ensure_checkpoint_transparency_guards(connection)?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let previous_checkpoint = verify_checkpoint_chain_integrity(&tx)?;
    let latest_committed_entry_seq = super::latest_claim_log_entry_seq(&tx)?;
    let Some(range) = super::next_checkpoint_range_for_connection(&tx, max_batch)? else {
        let latest_checkpointed_entry_seq = previous_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        tx.commit()?;
        return Ok(ReceiptCheckpointCreateReport {
            created: false,
            checkpoint_seq: None,
            batch_start_seq: None,
            batch_end_seq: None,
            latest_committed_entry_seq,
            latest_checkpointed_entry_seq,
        });
    };

    let receipt_bytes = load_claim_tree_canonical_bytes_range(&tx, range.start_seq, range.end_seq)?
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
    let checkpoint = chio_kernel::build_checkpoint_with_previous(
        checkpoint_seq,
        range.start_seq,
        range.end_seq,
        &receipt_bytes,
        keypair,
        previous_checkpoint.as_ref(),
    )
    .map_err(checkpoint_error_to_receipt_store)?;
    store_kernel_checkpoint_tx(&tx, &checkpoint)?;
    let report = ReceiptCheckpointCreateReport {
        created: true,
        checkpoint_seq: Some(checkpoint.body.checkpoint_seq),
        batch_start_seq: Some(checkpoint.body.batch_start_seq),
        batch_end_seq: Some(checkpoint.body.batch_end_seq),
        latest_committed_entry_seq,
        latest_checkpointed_entry_seq: checkpoint.body.batch_end_seq,
    };
    tx.commit()?;
    Ok(report)
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
    tx: &rusqlite::Transaction<'_>,
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
    validate_checkpoint_against_claim_log(tx, checkpoint)?;
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
    // its own claim-log range (validate_checkpoint_against_claim_log for THAT
    // one checkpoint's batch range only), and its projection rows. That is one
    // checkpoint plus its bounded batch range, NOT a full chain rebuild.
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
            validate_checkpoint_against_claim_log(tx, &existing_checkpoint)?;
        }
        validate_checkpoint_projection_rows(tx, &existing, &existing_checkpoint)?;
        return Ok(existing_checkpoint);
    }
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
    tx: &rusqlite::Transaction<'_>,
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
