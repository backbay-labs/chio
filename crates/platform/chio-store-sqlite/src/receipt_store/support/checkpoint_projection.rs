use super::*;

const TRANSPARENCY_PROJECTION_GUARDS_SQL: &str = r#"
CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_update
BEFORE UPDATE ON chio_tool_receipts
BEGIN
    SELECT RAISE(ABORT, 'tool receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete
BEFORE DELETE ON chio_tool_receipts
BEGIN
    SELECT RAISE(ABORT, 'tool receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_child_receipts_reject_update
BEFORE UPDATE ON chio_child_receipts
BEGIN
    SELECT RAISE(ABORT, 'child receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_child_receipts_reject_delete
BEFORE DELETE ON chio_child_receipts
BEGIN
    SELECT RAISE(ABORT, 'child receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_update
BEFORE UPDATE ON claim_receipt_log_entries
BEGIN
    SELECT RAISE(ABORT, 'claim receipt log entries are immutable');
END;

CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete
BEFORE DELETE ON claim_receipt_log_entries
BEGIN
    SELECT RAISE(ABORT, 'claim receipt log entries are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_tree_heads_reject_update
BEFORE UPDATE ON checkpoint_tree_heads
BEGIN
    SELECT RAISE(ABORT, 'checkpoint tree heads are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_tree_heads_reject_delete
BEFORE DELETE ON checkpoint_tree_heads
BEGIN
    SELECT RAISE(ABORT, 'checkpoint tree heads are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_predecessor_witnesses_reject_update
BEFORE UPDATE ON checkpoint_predecessor_witnesses
BEGIN
    SELECT RAISE(ABORT, 'checkpoint predecessor witnesses are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_predecessor_witnesses_reject_delete
BEFORE DELETE ON checkpoint_predecessor_witnesses
BEGIN
    SELECT RAISE(ABORT, 'checkpoint predecessor witnesses are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_publication_metadata_reject_update
BEFORE UPDATE ON checkpoint_publication_metadata
BEGIN
    SELECT RAISE(ABORT, 'checkpoint publication metadata is immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_publication_metadata_reject_delete
BEFORE DELETE ON checkpoint_publication_metadata
BEGIN
    SELECT RAISE(ABORT, 'checkpoint publication metadata is immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_publication_trust_anchor_bindings_reject_update
BEFORE UPDATE ON checkpoint_publication_trust_anchor_bindings
BEGIN
    SELECT RAISE(ABORT, 'checkpoint publication trust-anchor bindings are immutable');
END;

CREATE TRIGGER IF NOT EXISTS checkpoint_publication_trust_anchor_bindings_reject_delete
BEFORE DELETE ON checkpoint_publication_trust_anchor_bindings
BEGIN
    SELECT RAISE(ABORT, 'checkpoint publication trust-anchor bindings are immutable');
END;
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimReceiptLogProjectionRow {
    pub(crate) receipt_id: String,
    pub(crate) receipt_kind: String,
    pub(crate) source_seq: u64,
    pub(crate) timestamp: u64,
    pub(crate) capability_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) parent_request_id: Option<String>,
    pub(crate) request_id: Option<String>,
    pub(crate) subject_key: Option<String>,
    pub(crate) issuer_key: Option<String>,
    pub(crate) tool_server: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) raw_json: String,
}

impl ClaimReceiptLogProjectionRow {
    pub(crate) fn kind_rank(&self) -> u8 {
        match self.receipt_kind.as_str() {
            "tool_receipt" => 0,
            "child_receipt" => 1,
            _ => 2,
        }
    }

    pub(crate) fn matches_projection_or_enrichment(&self, expected: &Self) -> bool {
        self.receipt_id == expected.receipt_id
            && self.receipt_kind == expected.receipt_kind
            && self.source_seq == expected.source_seq
            && self.timestamp == expected.timestamp
            && self.capability_id == expected.capability_id
            && self.session_id == expected.session_id
            && self.parent_request_id == expected.parent_request_id
            && self.request_id == expected.request_id
            && self.tool_server == expected.tool_server
            && self.tool_name == expected.tool_name
            && self.raw_json == expected.raw_json
            && optional_enrichment_matches(&self.subject_key, &expected.subject_key)
            && optional_enrichment_matches(&self.issuer_key, &expected.issuer_key)
    }
}

fn optional_enrichment_matches(existing: &Option<String>, expected: &Option<String>) -> bool {
    existing == expected || (existing.is_none() && expected.is_some())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointTreeHeadProjectionRow {
    pub(crate) checkpoint_seq: u64,
    pub(crate) batch_start_seq: u64,
    pub(crate) batch_end_seq: u64,
    pub(crate) tree_size: u64,
    pub(crate) merkle_root: String,
    pub(crate) issued_at: u64,
    pub(crate) kernel_key: String,
    pub(crate) previous_checkpoint_sha256: Option<String>,
    pub(crate) statement_json: String,
    pub(crate) signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointPredecessorWitnessProjectionRow {
    pub(crate) predecessor_checkpoint_seq: u64,
    pub(crate) witness_checkpoint_seq: u64,
    pub(crate) previous_checkpoint_sha256: String,
    pub(crate) witnessed_at: u64,
    pub(crate) witness_statement_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointPublicationMetadataProjectionRow {
    pub(crate) checkpoint_seq: u64,
    pub(crate) publication_schema: String,
    pub(crate) merkle_root: String,
    pub(crate) published_at: u64,
    pub(crate) kernel_key: String,
    pub(crate) log_tree_size: u64,
    pub(crate) entry_start_seq: u64,
    pub(crate) entry_end_seq: u64,
    pub(crate) previous_checkpoint_sha256: Option<String>,
}

pub(crate) fn load_tool_claim_receipt_projection_rows(
    connection: &Connection,
) -> Result<Vec<ClaimReceiptLogProjectionRow>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT receipt_id, seq, timestamp, capability_id, subject_key, issuer_key,
               tool_server, tool_name, raw_json
        FROM chio_tool_receipts
        ORDER BY timestamp ASC, seq ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;
    rows.map(|row| {
        let (
            receipt_id,
            source_seq,
            timestamp,
            capability_id,
            subject_key,
            issuer_key,
            tool_server,
            tool_name,
            raw_json,
        ) = row.map_err(ReceiptStoreError::from)?;
        Ok(ClaimReceiptLogProjectionRow {
            receipt_id,
            receipt_kind: "tool_receipt".to_string(),
            source_seq: sqlite_positive_u64(source_seq, "claim tool source_seq")?,
            timestamp: sqlite_u64(timestamp, "claim tool timestamp")?,
            capability_id,
            session_id: None,
            parent_request_id: None,
            request_id: None,
            subject_key,
            issuer_key,
            tool_server,
            tool_name,
            raw_json,
        })
    })
    .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn load_child_claim_receipt_projection_rows(
    connection: &Connection,
) -> Result<Vec<ClaimReceiptLogProjectionRow>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT receipt_id, seq, timestamp, session_id, parent_request_id,
               request_id, raw_json
        FROM chio_child_receipts
        ORDER BY timestamp ASC, seq ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    rows.map(|row| {
        let (
            receipt_id,
            source_seq,
            timestamp,
            session_id,
            parent_request_id,
            request_id,
            raw_json,
        ) = row?;
        Ok(ClaimReceiptLogProjectionRow {
            receipt_id,
            receipt_kind: "child_receipt".to_string(),
            source_seq: sqlite_positive_u64(source_seq, "claim child source_seq")?,
            timestamp: sqlite_u64(timestamp, "claim child timestamp")?,
            capability_id: None,
            session_id,
            parent_request_id,
            request_id,
            subject_key: None,
            issuer_key: None,
            tool_server: None,
            tool_name: None,
            raw_json,
        })
    })
    .collect()
}

pub(crate) fn load_claim_receipt_log_projection_row(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<ClaimReceiptLogProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT receipt_id, receipt_kind, source_seq, timestamp, capability_id,
                   session_id, parent_request_id, request_id, subject_key, issuer_key,
                   tool_server, tool_name, raw_json
            FROM claim_receipt_log_entries
            WHERE receipt_id = ?1
            "#,
            params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
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
                raw_json,
            )| {
                Ok(ClaimReceiptLogProjectionRow {
                    receipt_id,
                    receipt_kind,
                    source_seq: sqlite_positive_u64(source_seq, "claim log source_seq")?,
                    timestamp: sqlite_u64(timestamp, "claim log timestamp")?,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json,
                })
            },
        )
        .transpose()
}

pub(crate) fn insert_claim_receipt_log_projection_row(
    connection: &Connection,
    row: &ClaimReceiptLogProjectionRow,
) -> Result<(), ReceiptStoreError> {
    connection.execute(
        r#"
        INSERT INTO claim_receipt_log_entries (
            receipt_id, receipt_kind, source_seq, timestamp, capability_id,
            session_id, parent_request_id, request_id, subject_key, issuer_key,
            tool_server, tool_name, raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        "#,
        params![
            row.receipt_id.as_str(),
            row.receipt_kind.as_str(),
            sqlite_i64(row.source_seq, "claim log source_seq")?,
            sqlite_i64(row.timestamp, "claim log timestamp")?,
            row.capability_id.as_deref(),
            row.session_id.as_deref(),
            row.parent_request_id.as_deref(),
            row.request_id.as_deref(),
            row.subject_key.as_deref(),
            row.issuer_key.as_deref(),
            row.tool_server.as_deref(),
            row.tool_name.as_deref(),
            row.raw_json.as_str(),
        ],
    )?;
    Ok(())
}

pub(crate) fn load_claim_receipt_log_receipt_ids(
    connection: &Connection,
) -> Result<BTreeSet<String>, ReceiptStoreError> {
    let mut statement = connection
        .prepare("SELECT receipt_id FROM claim_receipt_log_entries ORDER BY entry_seq ASC")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<BTreeSet<_>, _>>()
        .map_err(ReceiptStoreError::from)
}

/// Rebuild the expected claim-log projection for ONE tool receipt straight from
/// its source row (`chio_tool_receipts`), scoped by receipt_id (indexed unique
/// key). Mirror of `load_tool_claim_receipt_projection_rows` for a single id;
/// returns None when no source tool row exists.
pub(crate) fn load_tool_claim_receipt_projection_row_by_id(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<ClaimReceiptLogProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT receipt_id, seq, timestamp, capability_id, subject_key, issuer_key,
                   tool_server, tool_name, raw_json
            FROM chio_tool_receipts
            WHERE receipt_id = ?1
            "#,
            params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
                receipt_id,
                source_seq,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                tool_server,
                tool_name,
                raw_json,
            )| {
                Ok(ClaimReceiptLogProjectionRow {
                    receipt_id,
                    receipt_kind: "tool_receipt".to_string(),
                    source_seq: sqlite_positive_u64(source_seq, "claim tool source_seq")?,
                    timestamp: sqlite_u64(timestamp, "claim tool timestamp")?,
                    capability_id,
                    session_id: None,
                    parent_request_id: None,
                    request_id: None,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json,
                })
            },
        )
        .transpose()
}

/// Rebuild the expected claim-log projection for ONE child receipt straight
/// from its source row (`chio_child_receipts`), scoped by receipt_id. Mirror of
/// `load_child_claim_receipt_projection_rows` for a single id; returns None
/// when no source child row exists.
pub(crate) fn load_child_claim_receipt_projection_row_by_id(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<ClaimReceiptLogProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT receipt_id, seq, timestamp, session_id, parent_request_id,
                   request_id, raw_json
            FROM chio_child_receipts
            WHERE receipt_id = ?1
            "#,
            params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
                receipt_id,
                source_seq,
                timestamp,
                session_id,
                parent_request_id,
                request_id,
                raw_json,
            )| {
                Ok(ClaimReceiptLogProjectionRow {
                    receipt_id,
                    receipt_kind: "child_receipt".to_string(),
                    source_seq: sqlite_positive_u64(source_seq, "claim child source_seq")?,
                    timestamp: sqlite_u64(timestamp, "claim child timestamp")?,
                    capability_id: None,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key: None,
                    issuer_key: None,
                    tool_server: None,
                    tool_name: None,
                    raw_json,
                })
            },
        )
        .transpose()
}

/// Bounded projection cross-check over the (`floor_entry_seq`,
/// `max_entry_seq`] delta range ONLY. Every
/// claim_receipt_log_entries row an append adopts as pre-existing baseline
/// (rows a shared-DB writer committed past this actor's head) must project
/// EXACTLY from its source receipt row. Scoped to the delta (O(delta) indexed
/// lookups); the full-log validator (`validate_claim_receipt_log_entries`) is
/// NEVER invoked, so the single-writer no-stale-head path (empty delta) is a
/// no-op and the flat per-append cost holds. Runs inside the caller's
/// already-open transaction (no nested transaction).
///
/// Entries at or below the retention watermark were archived and deleted, so
/// their absence is expected rather than a gap. The contiguity floor is raised
/// to the watermark; the surviving range above it must still be contiguous, so
/// a real hole in the live log is still rejected.
///
/// Only a TRUSTED watermark raises the floor. The watermark ledger's DB triggers
/// enforce monotonicity alone, not that the covered prefix was ever archived, so
/// a raw INSERT could plant a high but bogus watermark while the covered rows are
/// still live. Trusting the raw value would let a stale writer skip the
/// contiguity and source-row projection checks for a delta at or below that
/// watermark, silently adopting corrupted or orphaned claim-log rows. Deferring
/// to `trusted_retention_watermark` (which additionally requires the value to
/// land on a checkpoint boundary and no live prefix row to survive) makes an
/// unarchived watermark fall back to 0, so the full delta is still validated and
/// the append fails closed.
pub(crate) fn validate_adopted_claim_log_delta(
    connection: &Connection,
    floor_entry_seq: u64,
    max_entry_seq: u64,
) -> Result<(), ReceiptStoreError> {
    // `trusted_retention_watermark` opens the archive and re-hashes every
    // covered checkpoint, so calling it on every append would make steady-state
    // appends O(archived history) once the store has ever rotated. The trusted
    // watermark is always bounded above by the raw ledger watermark (a cheap
    // indexed read), so it can only raise the floor when the raw watermark
    // exceeds `floor_entry_seq`. Gate the archive scan on that fast check: when
    // the floor already sits at or above the raw watermark the trusted value
    // cannot move it, and the hot path skips the archive entirely.
    let raw_watermark = retention_watermark(connection)?.unwrap_or(0);
    let effective_floor = if raw_watermark > floor_entry_seq {
        floor_entry_seq.max(trusted_retention_watermark(connection)?)
    } else {
        floor_entry_seq
    };
    if max_entry_seq <= effective_floor {
        return Ok(());
    }
    let entries = {
        let mut statement = connection.prepare(
            r#"
            SELECT entry_seq, receipt_id, receipt_kind
            FROM claim_receipt_log_entries
            WHERE entry_seq > ?1 AND entry_seq <= ?2
            ORDER BY entry_seq ASC
            "#,
        )?;
        let rows = statement.query_map(
            params![
                sqlite_i64(effective_floor, "adopted delta floor entry_seq")?,
                sqlite_i64(max_entry_seq, "adopted delta max entry_seq")?,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (entry_seq, receipt_id, receipt_kind) = row.map_err(ReceiptStoreError::from)?;
            Ok::<_, ReceiptStoreError>((
                sqlite_positive_u64(entry_seq, "adopted delta entry_seq")?,
                receipt_id,
                receipt_kind,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?
    };
    // Contiguity: the adopted range must be exactly
    // floor+1, floor+2, ..., max_entry_seq with no missing entry_seq. The
    // projection loop below only inspects rows that CURRENTLY EXIST, so a hole
    // (an append or resync adopting a non-contiguous shared-DB delta) would
    // slip through and a later append would skip the hole as already-verified.
    // One ordered scan over the already-loaded delta (O(delta), NOT O(N))
    // catches the first break; a trailing check confirms the range is closed at
    // max_entry_seq (a row missing at the top of the range). Fail closed on a
    // gap so the whole adopted delta is rejected, mirroring the contiguity rule
    // enforced for the checkpoint build range. `entries` is ordered ASC by the
    // query above.
    let mut expected_seq = effective_floor.saturating_add(1);
    for (entry_seq, _, _) in &entries {
        if *entry_seq != expected_seq {
            return Err(ReceiptStoreError::Conflict(format!(
                "adopted claim receipt log delta ({effective_floor}, {max_entry_seq}] is not contiguous: expected entry_seq {expected_seq}, found {entry_seq}; run `chio receipt audit`"
            )));
        }
        expected_seq = expected_seq.saturating_add(1);
    }
    if expected_seq != max_entry_seq.saturating_add(1) {
        return Err(ReceiptStoreError::Conflict(format!(
            "adopted claim receipt log delta ({effective_floor}, {max_entry_seq}] is missing trailing entries after entry_seq {}; run `chio receipt audit`",
            expected_seq.saturating_sub(1)
        )));
    }
    for (entry_seq, receipt_id, receipt_kind) in entries {
        let existing = load_claim_receipt_log_projection_row(connection, &receipt_id)?
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "adopted claim receipt log entry `{receipt_id}` (entry_seq {entry_seq}) vanished during validation; run `chio receipt audit`"
                ))
            })?;
        let expected = match receipt_kind.as_str() {
            "tool_receipt" => {
                load_tool_claim_receipt_projection_row_by_id(connection, &receipt_id)?
            }
            "child_receipt" => {
                load_child_claim_receipt_projection_row_by_id(connection, &receipt_id)?
            }
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "adopted claim receipt log entry `{receipt_id}` (entry_seq {entry_seq}) has unsupported kind `{other}`; run `chio receipt audit`"
                )));
            }
        };
        let Some(expected) = expected else {
            return Err(ReceiptStoreError::Conflict(format!(
                "adopted claim receipt log entry `{receipt_id}` (entry_seq {entry_seq}) has no source {receipt_kind} row; run `chio receipt audit`"
            )));
        };
        if !existing.matches_projection_or_enrichment(&expected) {
            return Err(ReceiptStoreError::Conflict(format!(
                "adopted claim receipt log entry `{receipt_id}` (entry_seq {entry_seq}) diverges from its source {receipt_kind} row; run `chio receipt audit`"
            )));
        }
    }
    Ok(())
}

fn canonical_bytes_from_claim_log_row(
    receipt_kind: &str,
    raw_json: &str,
    entry_seq: u64,
) -> Result<Vec<u8>, ReceiptStoreError> {
    match receipt_kind {
        "tool_receipt" => {
            let receipt =
                decode_verified_chio_receipt(raw_json, "claim-log tool receipt", Some(entry_seq))?;
            chio_core::canonical::canonical_json_bytes(&receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))
        }
        "child_receipt" => {
            let receipt = decode_verified_child_receipt(
                raw_json,
                "claim-log child receipt",
                Some(entry_seq),
            )?;
            chio_core::canonical::canonical_json_bytes(&receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))
        }
        other => Err(ReceiptStoreError::Conflict(format!(
            "unsupported claim receipt kind `{other}` in claim tree"
        ))),
    }
}

pub(crate) fn load_claim_tree_canonical_bytes_range(
    connection: &Connection,
    start_entry_seq: u64,
    end_entry_seq: u64,
) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
    super::ensure_claim_log_range_contiguous(connection, start_entry_seq, end_entry_seq, "range")?;
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
            sqlite_i64(start_entry_seq, "claim tree start_entry_seq")?,
            sqlite_i64(end_entry_seq, "claim tree end_entry_seq")?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    let mut result = Vec::new();
    for row in rows {
        let (entry_seq, receipt_kind, raw_json) = row?;
        let entry_seq = sqlite_positive_u64(entry_seq, "claim tree entry_seq")?;
        result.push((
            entry_seq,
            canonical_bytes_from_claim_log_row(&receipt_kind, &raw_json, entry_seq)?,
        ));
    }
    Ok(result)
}

pub(crate) fn load_checkpoint_tree_head_projection_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<CheckpointTreeHeadProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT checkpoint_seq, batch_start_seq, batch_end_seq, tree_size, merkle_root,
                   issued_at, kernel_key, previous_checkpoint_sha256, statement_json, signature
            FROM checkpoint_tree_heads
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
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
                checkpoint_seq,
                batch_start_seq,
                batch_end_seq,
                tree_size,
                merkle_root,
                issued_at,
                kernel_key,
                previous_checkpoint_sha256,
                statement_json,
                signature,
            )| {
                Ok(CheckpointTreeHeadProjectionRow {
                    checkpoint_seq: sqlite_u64(checkpoint_seq, "tree head checkpoint_seq")?,
                    batch_start_seq: sqlite_u64(batch_start_seq, "tree head batch_start_seq")?,
                    batch_end_seq: sqlite_u64(batch_end_seq, "tree head batch_end_seq")?,
                    tree_size: sqlite_u64(tree_size, "tree head tree_size")?,
                    merkle_root,
                    issued_at: sqlite_u64(issued_at, "tree head issued_at")?,
                    kernel_key,
                    previous_checkpoint_sha256,
                    statement_json,
                    signature,
                })
            },
        )
        .transpose()
}

fn insert_checkpoint_tree_head_projection_row(
    connection: &Connection,
    row: &CheckpointTreeHeadProjectionRow,
) -> Result<(), ReceiptStoreError> {
    connection.execute(
        r#"
        INSERT INTO checkpoint_tree_heads (
            checkpoint_seq, batch_start_seq, batch_end_seq, tree_size, merkle_root,
            issued_at, kernel_key, previous_checkpoint_sha256, statement_json, signature
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            sqlite_i64(row.checkpoint_seq, "checkpoint_seq")?,
            sqlite_i64(row.batch_start_seq, "batch_start_seq")?,
            sqlite_i64(row.batch_end_seq, "batch_end_seq")?,
            sqlite_i64(row.tree_size, "tree_size")?,
            row.merkle_root.as_str(),
            sqlite_i64(row.issued_at, "issued_at")?,
            row.kernel_key.as_str(),
            row.previous_checkpoint_sha256.as_deref(),
            row.statement_json.as_str(),
            row.signature.as_str(),
        ],
    )?;
    Ok(())
}

pub(crate) fn load_checkpoint_tree_head_projection_ids(
    connection: &Connection,
) -> Result<BTreeSet<u64>, ReceiptStoreError> {
    let mut statement = connection
        .prepare("SELECT checkpoint_seq FROM checkpoint_tree_heads ORDER BY checkpoint_seq ASC")?;
    let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
    rows.map(|row| {
        let checkpoint_seq = row.map_err(ReceiptStoreError::from)?;
        sqlite_u64(checkpoint_seq, "checkpoint_seq")
    })
    .collect::<Result<BTreeSet<_>, _>>()
}

pub(crate) fn load_checkpoint_predecessor_witness_projection_row(
    connection: &Connection,
    witness_checkpoint_seq: u64,
) -> Result<Option<CheckpointPredecessorWitnessProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT predecessor_checkpoint_seq, witness_checkpoint_seq,
                   previous_checkpoint_sha256, witnessed_at, witness_statement_json
            FROM checkpoint_predecessor_witnesses
            WHERE witness_checkpoint_seq = ?1
            "#,
            params![sqlite_i64(
                witness_checkpoint_seq,
                "witness_checkpoint_seq"
            )?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
                predecessor_checkpoint_seq,
                witness_checkpoint_seq,
                previous_checkpoint_sha256,
                witnessed_at,
                witness_statement_json,
            )| {
                Ok(CheckpointPredecessorWitnessProjectionRow {
                    predecessor_checkpoint_seq: sqlite_u64(
                        predecessor_checkpoint_seq,
                        "predecessor_checkpoint_seq",
                    )?,
                    witness_checkpoint_seq: sqlite_u64(
                        witness_checkpoint_seq,
                        "witness_checkpoint_seq",
                    )?,
                    previous_checkpoint_sha256,
                    witnessed_at: sqlite_u64(witnessed_at, "witnessed_at")?,
                    witness_statement_json,
                })
            },
        )
        .transpose()
}

fn insert_checkpoint_predecessor_witness_projection_row(
    connection: &Connection,
    row: &CheckpointPredecessorWitnessProjectionRow,
) -> Result<(), ReceiptStoreError> {
    connection.execute(
        r#"
        INSERT INTO checkpoint_predecessor_witnesses (
            predecessor_checkpoint_seq, witness_checkpoint_seq,
            previous_checkpoint_sha256, witnessed_at, witness_statement_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            sqlite_i64(row.predecessor_checkpoint_seq, "predecessor_checkpoint_seq")?,
            sqlite_i64(row.witness_checkpoint_seq, "witness_checkpoint_seq")?,
            row.previous_checkpoint_sha256.as_str(),
            sqlite_i64(row.witnessed_at, "witnessed_at")?,
            row.witness_statement_json.as_str(),
        ],
    )?;
    Ok(())
}

pub(crate) fn load_checkpoint_predecessor_witness_projection_ids(
    connection: &Connection,
) -> Result<BTreeSet<u64>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT witness_checkpoint_seq FROM checkpoint_predecessor_witnesses ORDER BY witness_checkpoint_seq ASC",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
    rows.map(|row| {
        let witness_checkpoint_seq = row.map_err(ReceiptStoreError::from)?;
        sqlite_u64(witness_checkpoint_seq, "witness_checkpoint_seq")
    })
    .collect::<Result<BTreeSet<_>, _>>()
}

pub(crate) fn load_checkpoint_publication_metadata_projection_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<CheckpointPublicationMetadataProjectionRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT checkpoint_seq, publication_schema, merkle_root, published_at,
                   kernel_key, log_tree_size, entry_start_seq, entry_end_seq,
                   previous_checkpoint_sha256
            FROM checkpoint_publication_metadata
            WHERE checkpoint_seq = ?1
            "#,
            params![sqlite_i64(checkpoint_seq, "checkpoint_seq")?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?
        .map(
            |(
                checkpoint_seq,
                publication_schema,
                merkle_root,
                published_at,
                kernel_key,
                log_tree_size,
                entry_start_seq,
                entry_end_seq,
                previous_checkpoint_sha256,
            )| {
                Ok(CheckpointPublicationMetadataProjectionRow {
                    checkpoint_seq: sqlite_u64(
                        checkpoint_seq,
                        "checkpoint publication metadata checkpoint_seq",
                    )?,
                    publication_schema,
                    merkle_root,
                    published_at: sqlite_u64(
                        published_at,
                        "checkpoint publication metadata published_at",
                    )?,
                    kernel_key,
                    log_tree_size: sqlite_u64(
                        log_tree_size,
                        "checkpoint publication metadata log_tree_size",
                    )?,
                    entry_start_seq: sqlite_u64(
                        entry_start_seq,
                        "checkpoint publication metadata entry_start_seq",
                    )?,
                    entry_end_seq: sqlite_u64(
                        entry_end_seq,
                        "checkpoint publication metadata entry_end_seq",
                    )?,
                    previous_checkpoint_sha256,
                })
            },
        )
        .transpose()
}

fn insert_checkpoint_publication_metadata_projection_row(
    connection: &Connection,
    row: &CheckpointPublicationMetadataProjectionRow,
) -> Result<(), ReceiptStoreError> {
    connection.execute(
        r#"
        INSERT INTO checkpoint_publication_metadata (
            checkpoint_seq, publication_schema, merkle_root, published_at, kernel_key,
            log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            sqlite_i64(row.checkpoint_seq, "checkpoint_seq")?,
            row.publication_schema.as_str(),
            row.merkle_root.as_str(),
            sqlite_i64(row.published_at, "published_at")?,
            row.kernel_key.as_str(),
            sqlite_i64(row.log_tree_size, "log_tree_size")?,
            sqlite_i64(row.entry_start_seq, "entry_start_seq")?,
            sqlite_i64(row.entry_end_seq, "entry_end_seq")?,
            row.previous_checkpoint_sha256.as_deref(),
        ],
    )?;
    Ok(())
}

pub(crate) fn load_checkpoint_publication_metadata_projection_ids(
    connection: &Connection,
) -> Result<BTreeSet<u64>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT checkpoint_seq FROM checkpoint_publication_metadata ORDER BY checkpoint_seq ASC",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
    rows.map(|row| {
        let checkpoint_seq = row.map_err(ReceiptStoreError::from)?;
        sqlite_u64(
            checkpoint_seq,
            "checkpoint publication metadata checkpoint_seq",
        )
    })
    .collect::<Result<BTreeSet<_>, _>>()
}

pub(crate) fn ensure_transparency_projection_guards(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(TRANSPARENCY_PROJECTION_GUARDS_SQL)?;
    Ok(())
}

pub(crate) fn drop_transparency_projection_guards(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;
        DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_update;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
        DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;
        DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_tree_heads_reject_delete;
        DROP TRIGGER IF EXISTS checkpoint_predecessor_witnesses_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_predecessor_witnesses_reject_delete;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_metadata_reject_delete;
        DROP TRIGGER IF EXISTS checkpoint_publication_trust_anchor_bindings_reject_update;
        DROP TRIGGER IF EXISTS checkpoint_publication_trust_anchor_bindings_reject_delete;
        "#,
    )?;
    Ok(())
}

pub(crate) fn backfill_checkpoint_transparency_projections(
    connection: &mut Connection,
) -> Result<(), ReceiptStoreError> {
    let rows = load_all_persisted_checkpoint_rows(connection)?;
    let mut parsed_checkpoints = Vec::with_capacity(rows.len());
    let mut expected_heads = Vec::with_capacity(rows.len());
    let mut expected_witnesses = Vec::new();
    let mut expected_publications = Vec::with_capacity(rows.len());

    for row in rows {
        let checkpoint = parse_persisted_checkpoint_row(row.clone())?;
        if let Some(predecessor) = parsed_checkpoints.last() {
            chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                .map_err(checkpoint_error_to_receipt_store)?;
        }
        let publication = chio_kernel::checkpoint::build_checkpoint_publication(&checkpoint)
            .map_err(checkpoint_error_to_receipt_store)?;

        expected_heads.push(CheckpointTreeHeadProjectionRow {
            checkpoint_seq: row.checkpoint_seq,
            batch_start_seq: row.batch_start_seq,
            batch_end_seq: row.batch_end_seq,
            tree_size: row.tree_size,
            merkle_root: row.merkle_root_hex,
            issued_at: row.issued_at,
            kernel_key: row.kernel_key_hex,
            previous_checkpoint_sha256: checkpoint.body.previous_checkpoint_sha256.clone(),
            statement_json: row.statement_json.clone(),
            signature: row.signature_hex,
        });
        expected_publications.push(CheckpointPublicationMetadataProjectionRow {
            checkpoint_seq: publication.checkpoint_seq,
            publication_schema: publication.schema,
            merkle_root: publication.merkle_root.to_hex(),
            published_at: publication.published_at,
            kernel_key: publication.kernel_key.to_hex(),
            log_tree_size: publication.log_tree_size,
            entry_start_seq: publication.entry_start_seq,
            entry_end_seq: publication.entry_end_seq,
            previous_checkpoint_sha256: publication.previous_checkpoint_sha256,
        });

        if let Some(previous_checkpoint_sha256) = checkpoint.body.previous_checkpoint_sha256.clone()
        {
            if checkpoint.body.checkpoint_seq <= 1 {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} cannot witness a predecessor digest",
                    checkpoint.body.checkpoint_seq
                )));
            }
            expected_witnesses.push(CheckpointPredecessorWitnessProjectionRow {
                predecessor_checkpoint_seq: checkpoint.body.checkpoint_seq - 1,
                witness_checkpoint_seq: checkpoint.body.checkpoint_seq,
                previous_checkpoint_sha256,
                witnessed_at: checkpoint.body.issued_at,
                witness_statement_json: row.statement_json,
            });
        }

        parsed_checkpoints.push(checkpoint);
    }

    let tx = connection.transaction()?;
    for row in &expected_heads {
        match load_checkpoint_tree_head_projection_row(&tx, row.checkpoint_seq)? {
            Some(existing) if existing == *row => {}
            Some(_) => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint tree head projection for checkpoint {} diverges from persisted checkpoint row",
                    row.checkpoint_seq
                )))
            }
            None => insert_checkpoint_tree_head_projection_row(&tx, row)?,
        }
    }

    let expected_head_ids = expected_heads
        .iter()
        .map(|row| row.checkpoint_seq)
        .collect::<BTreeSet<_>>();
    let existing_head_ids = load_checkpoint_tree_head_projection_ids(&tx)?;
    if existing_head_ids != expected_head_ids {
        let missing = expected_head_ids
            .difference(&existing_head_ids)
            .next()
            .copied();
        let extra = existing_head_ids
            .difference(&expected_head_ids)
            .next()
            .copied();
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint tree head projection drift detected (missing: {}, extra: {})",
            missing
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            extra
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        )));
    }

    for row in &expected_witnesses {
        match load_checkpoint_predecessor_witness_projection_row(&tx, row.witness_checkpoint_seq)? {
            Some(existing) if existing == *row => {}
            Some(_) => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint predecessor witness projection for checkpoint {} diverges from persisted checkpoint chain",
                    row.witness_checkpoint_seq
                )))
            }
            None => insert_checkpoint_predecessor_witness_projection_row(&tx, row)?,
        }
    }

    let expected_witness_ids = expected_witnesses
        .iter()
        .map(|row| row.witness_checkpoint_seq)
        .collect::<BTreeSet<_>>();
    let existing_witness_ids = load_checkpoint_predecessor_witness_projection_ids(&tx)?;
    if existing_witness_ids != expected_witness_ids {
        let missing = expected_witness_ids
            .difference(&existing_witness_ids)
            .next()
            .copied();
        let extra = existing_witness_ids
            .difference(&expected_witness_ids)
            .next()
            .copied();
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint predecessor witness projection drift detected (missing: {}, extra: {})",
            missing
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            extra
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        )));
    }

    for row in &expected_publications {
        match load_checkpoint_publication_metadata_projection_row(&tx, row.checkpoint_seq)? {
            Some(existing) if existing == *row => {}
            Some(_) => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint publication metadata projection for checkpoint {} diverges from persisted checkpoint row",
                    row.checkpoint_seq
                )))
            }
            None => insert_checkpoint_publication_metadata_projection_row(&tx, row)?,
        }
    }

    let expected_publication_ids = expected_publications
        .iter()
        .map(|row| row.checkpoint_seq)
        .collect::<BTreeSet<_>>();
    let existing_publication_ids = load_checkpoint_publication_metadata_projection_ids(&tx)?;
    if existing_publication_ids != expected_publication_ids {
        let missing = expected_publication_ids
            .difference(&existing_publication_ids)
            .next()
            .copied();
        let extra = existing_publication_ids
            .difference(&expected_publication_ids)
            .next()
            .copied();
        return Err(ReceiptStoreError::Conflict(format!(
            "checkpoint publication metadata projection drift detected (missing: {}, extra: {})",
            missing
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            extra
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        )));
    }

    tx.commit()?;
    Ok(())
}
