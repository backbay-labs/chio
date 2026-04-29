use super::*;

pub(crate) fn unix_timestamp_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn sqlite_i64(value: u64, field: &str) -> Result<i64, ReceiptStoreError> {
    i64::try_from(value).map_err(|_| {
        ReceiptStoreError::Conflict(format!(
            "{field} value {value} exceeds SQLite INTEGER range"
        ))
    })
}

pub(crate) fn sqlite_u64(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    u64::try_from(value).map_err(|_| {
        ReceiptStoreError::Conflict(format!(
            "{field} value {value} is outside the supported u64 range"
        ))
    })
}

pub(crate) fn sqlite_bool(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

pub(crate) fn ensure_chio_receipt_verified(receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
    ensure_chio_receipt_verified_with_context(receipt, "tool receipt", None)
}

pub(crate) fn ensure_child_receipt_verified(
    receipt: &ChildRequestReceipt,
) -> Result<(), ReceiptStoreError> {
    ensure_child_receipt_verified_with_context(receipt, "child receipt", None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionParameterHashPolicy {
    Strict,
    AllowLegacySignedMismatch,
}

fn format_receipt_context(
    receipt_kind: &str,
    receipt_id: Option<&str>,
    seq: Option<u64>,
) -> String {
    let mut context = receipt_kind.to_string();
    if let Some(seq) = seq {
        context.push_str(&format!(" seq {seq}"));
    }
    if let Some(receipt_id) = receipt_id {
        context.push_str(&format!(" receipt {receipt_id}"));
    }
    context
}

pub(crate) fn ensure_chio_receipt_verified_with_context(
    receipt: &ChioReceipt,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<(), ReceiptStoreError> {
    ensure_chio_receipt_verified_with_context_and_action_hash_policy(
        receipt,
        receipt_kind,
        seq,
        ActionParameterHashPolicy::Strict,
    )
}

fn ensure_chio_receipt_verified_with_context_and_action_hash_policy(
    receipt: &ChioReceipt,
    receipt_kind: &str,
    seq: Option<u64>,
    action_hash_policy: ActionParameterHashPolicy,
) -> Result<(), ReceiptStoreError> {
    let context = format_receipt_context(receipt_kind, Some(receipt.id.as_str()), seq);
    let signature_valid = receipt.verify_signature().map_err(|error| {
        ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
    })?;
    if !signature_valid {
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has invalid signature",
        )));
    }

    let parameter_hash_valid = receipt.action.verify_hash().map_err(|error| {
        ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
    })?;
    if !parameter_hash_valid {
        if action_hash_policy == ActionParameterHashPolicy::AllowLegacySignedMismatch {
            // Older signed receipts may carry pre-canonical parameter hashes.
            // Keep them readable, but only after the receipt signature verifies.
            return Ok(());
        }
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has mismatched action parameter hash",
        )));
    }

    Ok(())
}

pub(crate) fn ensure_child_receipt_verified_with_context(
    receipt: &ChildRequestReceipt,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<(), ReceiptStoreError> {
    let context = format_receipt_context(receipt_kind, Some(receipt.id.as_str()), seq);
    let signature_valid = receipt.verify_signature().map_err(|error| {
        ReceiptStoreError::Conflict(format!("{context} verification failed: {error}"))
    })?;
    if !signature_valid {
        return Err(ReceiptStoreError::Conflict(format!(
            "{context} has invalid signature",
        )));
    }

    Ok(())
}

pub(crate) fn decode_verified_chio_receipt(
    raw_json: &str,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<ChioReceipt, ReceiptStoreError> {
    let value: serde_json::Value = serde_json::from_str(raw_json).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, None, seq)
        ))
    })?;
    let receipt_id = value
        .get("id")
        .and_then(|field| field.as_str())
        .map(str::to_string);
    let receipt: ChioReceipt = serde_json::from_value(value).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, receipt_id.as_deref(), seq)
        ))
    })?;
    ensure_chio_receipt_verified_with_context_and_action_hash_policy(
        &receipt,
        receipt_kind,
        seq,
        ActionParameterHashPolicy::AllowLegacySignedMismatch,
    )?;
    Ok(receipt)
}

pub(crate) fn decode_verified_child_receipt(
    raw_json: &str,
    receipt_kind: &str,
    seq: Option<u64>,
) -> Result<ChildRequestReceipt, ReceiptStoreError> {
    let value: serde_json::Value = serde_json::from_str(raw_json).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, None, seq)
        ))
    })?;
    let receipt_id = value
        .get("id")
        .and_then(|field| field.as_str())
        .map(str::to_string);
    let receipt: ChildRequestReceipt = serde_json::from_value(value).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "{} failed to decode: {error}",
            format_receipt_context(receipt_kind, receipt_id.as_deref(), seq)
        ))
    })?;
    ensure_child_receipt_verified_with_context(&receipt, receipt_kind, seq)?;
    Ok(receipt)
}

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
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root_hex: String,
    issued_at: u64,
    statement_json: String,
    signature_hex: String,
    kernel_key_hex: String,
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

pub(crate) fn verify_latest_checkpoint_integrity(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    if load_latest_persisted_checkpoint_row(connection)?.is_none() {
        return Ok(());
    }
    verify_checkpoint_chain_integrity(connection).map(|_| ())
}

pub(crate) fn verify_checkpoint_chain_integrity(
    connection: &Connection,
) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
    let rows = load_all_persisted_checkpoint_rows(connection)?;
    let mut latest = None;

    for row in rows {
        let checkpoint = parse_persisted_checkpoint_row(row)?;
        if let Some(predecessor) = latest.as_ref() {
            chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                .map_err(checkpoint_error_to_receipt_store)?;
        }
        latest = Some(checkpoint);
    }

    Ok(latest)
}

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
struct ClaimReceiptLogProjectionRow {
    receipt_id: String,
    receipt_kind: String,
    source_seq: u64,
    timestamp: u64,
    capability_id: Option<String>,
    session_id: Option<String>,
    parent_request_id: Option<String>,
    request_id: Option<String>,
    subject_key: Option<String>,
    issuer_key: Option<String>,
    tool_server: Option<String>,
    tool_name: Option<String>,
    raw_json: String,
}

impl ClaimReceiptLogProjectionRow {
    fn kind_rank(&self) -> u8 {
        match self.receipt_kind.as_str() {
            "tool_receipt" => 0,
            "child_receipt" => 1,
            _ => 2,
        }
    }

    fn matches_projection_or_legacy_enrichment(&self, expected: &Self) -> bool {
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
            && legacy_optional_enrichment_matches(&self.subject_key, &expected.subject_key)
            && legacy_optional_enrichment_matches(&self.issuer_key, &expected.issuer_key)
    }
}

fn legacy_optional_enrichment_matches(
    existing: &Option<String>,
    expected: &Option<String>,
) -> bool {
    existing == expected || (existing.is_none() && expected.is_some())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckpointTreeHeadProjectionRow {
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: String,
    issued_at: u64,
    kernel_key: String,
    previous_checkpoint_sha256: Option<String>,
    statement_json: String,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckpointPredecessorWitnessProjectionRow {
    predecessor_checkpoint_seq: u64,
    witness_checkpoint_seq: u64,
    previous_checkpoint_sha256: String,
    witnessed_at: u64,
    witness_statement_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckpointPublicationMetadataProjectionRow {
    checkpoint_seq: u64,
    publication_schema: String,
    merkle_root: String,
    published_at: u64,
    kernel_key: String,
    log_tree_size: u64,
    entry_start_seq: u64,
    entry_end_seq: u64,
    previous_checkpoint_sha256: Option<String>,
}

fn load_tool_claim_receipt_projection_rows(
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
            source_seq: sqlite_u64(source_seq, "claim tool source_seq")?,
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

fn load_child_claim_receipt_projection_rows(
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
            source_seq: sqlite_u64(source_seq, "claim child source_seq")?,
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

fn load_claim_receipt_log_projection_row(
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
                    source_seq: sqlite_u64(source_seq, "claim log source_seq")?,
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

fn insert_claim_receipt_log_projection_row(
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

fn load_claim_receipt_log_receipt_ids(
    connection: &Connection,
) -> Result<BTreeSet<String>, ReceiptStoreError> {
    let mut statement = connection
        .prepare("SELECT receipt_id FROM claim_receipt_log_entries ORDER BY entry_seq ASC")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<BTreeSet<_>, _>>()
        .map_err(ReceiptStoreError::from)
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
        let entry_seq = sqlite_u64(entry_seq, "claim tree entry_seq")?;
        result.push((
            entry_seq,
            canonical_bytes_from_claim_log_row(&receipt_kind, &raw_json, entry_seq)?,
        ));
    }
    Ok(result)
}

fn load_checkpoint_tree_head_projection_row(
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

fn load_checkpoint_tree_head_projection_ids(
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

fn load_checkpoint_predecessor_witness_projection_row(
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

fn load_checkpoint_predecessor_witness_projection_ids(
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

fn load_checkpoint_publication_metadata_projection_row(
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

fn load_checkpoint_publication_metadata_projection_ids(
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

pub(crate) fn backfill_claim_receipt_log_entries(
    connection: &mut Connection,
) -> Result<(), ReceiptStoreError> {
    let mut expected = load_tool_claim_receipt_projection_rows(connection)?;
    expected.extend(load_child_claim_receipt_projection_rows(connection)?);
    expected.sort_by(|left, right| {
        (
            left.timestamp,
            left.kind_rank(),
            left.source_seq,
            left.receipt_id.as_str(),
        )
            .cmp(&(
                right.timestamp,
                right.kind_rank(),
                right.source_seq,
                right.receipt_id.as_str(),
            ))
    });

    let existing_count = connection.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let existing_count = sqlite_u64(existing_count, "claim_receipt_log_entries count")?;
    let expected_receipt_ids = expected
        .iter()
        .map(|row| row.receipt_id.clone())
        .collect::<BTreeSet<_>>();

    let tx = connection.transaction()?;
    if existing_count == 0 {
        for row in &expected {
            insert_claim_receipt_log_projection_row(&tx, row)?;
        }
        tx.commit()?;
        return Ok(());
    }

    for row in &expected {
        let Some(existing) = load_claim_receipt_log_projection_row(&tx, &row.receipt_id)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` is missing for persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        };
        if !existing.matches_projection_or_legacy_enrichment(row) {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` diverges from persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        }
    }

    let existing_receipt_ids = load_claim_receipt_log_receipt_ids(&tx)?;
    if existing_receipt_ids != expected_receipt_ids {
        let missing = expected_receipt_ids
            .difference(&existing_receipt_ids)
            .next()
            .cloned();
        let extra = existing_receipt_ids
            .difference(&expected_receipt_ids)
            .next()
            .cloned();
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log entry set drift detected (missing: {}, extra: {})",
            missing.as_deref().unwrap_or("<none>"),
            extra.as_deref().unwrap_or("<none>")
        )));
    }

    tx.commit()?;
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

pub(crate) fn settlement_reconciliation_state_text(
    state: SettlementReconciliationState,
) -> &'static str {
    match state {
        SettlementReconciliationState::Open => "open",
        SettlementReconciliationState::Reconciled => "reconciled",
        SettlementReconciliationState::Ignored => "ignored",
        SettlementReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_settlement_reconciliation_state(
    value: &str,
) -> Result<SettlementReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn metered_billing_reconciliation_state_text(
    state: MeteredBillingReconciliationState,
) -> &'static str {
    match state {
        MeteredBillingReconciliationState::Open => "open",
        MeteredBillingReconciliationState::Reconciled => "reconciled",
        MeteredBillingReconciliationState::Ignored => "ignored",
        MeteredBillingReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_metered_billing_reconciliation_state(
    value: &str,
) -> Result<MeteredBillingReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn underwriting_decision_outcome_label(
    outcome: UnderwritingDecisionOutcome,
) -> &'static str {
    match outcome {
        UnderwritingDecisionOutcome::Approve => "approve",
        UnderwritingDecisionOutcome::ReduceCeiling => "reduce_ceiling",
        UnderwritingDecisionOutcome::StepUp => "step_up",
        UnderwritingDecisionOutcome::Deny => "deny",
    }
}

pub(crate) fn underwriting_lifecycle_state_label(
    state: UnderwritingDecisionLifecycleState,
) -> &'static str {
    match state {
        UnderwritingDecisionLifecycleState::Active => "active",
        UnderwritingDecisionLifecycleState::Superseded => "superseded",
    }
}

pub(crate) fn underwriting_review_state_label(
    state: chio_kernel::UnderwritingReviewState,
) -> &'static str {
    match state {
        chio_kernel::UnderwritingReviewState::Approved => "approved",
        chio_kernel::UnderwritingReviewState::ManualReviewRequired => "manual_review_required",
        chio_kernel::UnderwritingReviewState::Denied => "denied",
    }
}

pub(crate) fn underwriting_risk_class_label(
    class: chio_kernel::UnderwritingRiskClass,
) -> &'static str {
    match class {
        chio_kernel::UnderwritingRiskClass::Baseline => "baseline",
        chio_kernel::UnderwritingRiskClass::Guarded => "guarded",
        chio_kernel::UnderwritingRiskClass::Elevated => "elevated",
        chio_kernel::UnderwritingRiskClass::Critical => "critical",
    }
}

pub(crate) fn underwriting_appeal_status_label(status: UnderwritingAppealStatus) -> &'static str {
    match status {
        UnderwritingAppealStatus::Open => "open",
        UnderwritingAppealStatus::Accepted => "accepted",
        UnderwritingAppealStatus::Rejected => "rejected",
    }
}

pub(crate) fn credit_facility_disposition_label(
    disposition: CreditFacilityDisposition,
) -> &'static str {
    match disposition {
        CreditFacilityDisposition::Grant => "grant",
        CreditFacilityDisposition::ManualReview => "manual_review",
        CreditFacilityDisposition::Deny => "deny",
    }
}

pub(crate) fn credit_facility_lifecycle_state_label(
    state: CreditFacilityLifecycleState,
) -> &'static str {
    match state {
        CreditFacilityLifecycleState::Active => "active",
        CreditFacilityLifecycleState::Superseded => "superseded",
        CreditFacilityLifecycleState::Denied => "denied",
        CreditFacilityLifecycleState::Expired => "expired",
    }
}

pub(crate) fn credit_bond_disposition_label(disposition: CreditBondDisposition) -> &'static str {
    match disposition {
        CreditBondDisposition::Lock => "lock",
        CreditBondDisposition::Hold => "hold",
        CreditBondDisposition::Release => "release",
        CreditBondDisposition::Impair => "impair",
    }
}

pub(crate) fn credit_bond_lifecycle_state_label(state: CreditBondLifecycleState) -> &'static str {
    match state {
        CreditBondLifecycleState::Active => "active",
        CreditBondLifecycleState::Superseded => "superseded",
        CreditBondLifecycleState::Released => "released",
        CreditBondLifecycleState::Impaired => "impaired",
        CreditBondLifecycleState::Expired => "expired",
    }
}

pub(crate) fn liability_provider_lifecycle_state_label(
    state: LiabilityProviderLifecycleState,
) -> &'static str {
    match state {
        LiabilityProviderLifecycleState::Active => "active",
        LiabilityProviderLifecycleState::Suspended => "suspended",
        LiabilityProviderLifecycleState::Superseded => "superseded",
        LiabilityProviderLifecycleState::Retired => "retired",
    }
}

pub(crate) fn credit_loss_lifecycle_event_kind_label(
    kind: CreditLossLifecycleEventKind,
) -> &'static str {
    match kind {
        CreditLossLifecycleEventKind::Delinquency => "delinquency",
        CreditLossLifecycleEventKind::Recovery => "recovery",
        CreditLossLifecycleEventKind::ReserveRelease => "reserve_release",
        CreditLossLifecycleEventKind::ReserveSlash => "reserve_slash",
        CreditLossLifecycleEventKind::WriteOff => "write_off",
    }
}

pub(crate) fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<UnderwritingDecisionLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<CreditFacilityLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<CreditBondLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<LiabilityProviderLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn liability_quote_disposition_label(
    disposition: &LiabilityQuoteDisposition,
) -> &'static str {
    match disposition {
        LiabilityQuoteDisposition::Quoted => "quoted",
        LiabilityQuoteDisposition::Declined => "declined",
    }
}

pub(crate) fn liability_auto_bind_disposition_label(
    disposition: &LiabilityAutoBindDisposition,
) -> &'static str {
    match disposition {
        LiabilityAutoBindDisposition::AutoBound => "auto_bound",
        LiabilityAutoBindDisposition::ManualReview => "manual_review",
        LiabilityAutoBindDisposition::Denied => "denied",
    }
}

pub(crate) fn query_underwriting_appeal(
    tx: &rusqlite::Transaction<'_>,
    appeal_id: &str,
) -> Result<Option<UnderwritingAppealRecord>, ReceiptStoreError> {
    let row = tx
        .query_row(
            "SELECT decision_id, requested_by, reason, status, note, created_at, updated_at,
                resolved_by, replacement_decision_id
         FROM underwriting_appeals
         WHERE appeal_id = ?1",
            params![appeal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?;

    row.map(
        |(
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        )| {
            Ok(UnderwritingAppealRecord {
                schema: chio_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
                appeal_id: appeal_id.to_string(),
                decision_id,
                requested_by,
                reason,
                status: parse_underwriting_appeal_status(&status)?,
                note,
                created_at: created_at.max(0) as u64,
                updated_at: updated_at.max(0) as u64,
                resolved_by,
                replacement_decision_id,
            })
        },
    )
    .transpose()
}

pub(crate) fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<UnderwritingAppealStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn load_underwriting_appeal_rows(
    connection: &Connection,
) -> Result<Vec<UnderwritingAppealRecord>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT appeal_id, decision_id, requested_by, reason, status, note, created_at,
                updated_at, resolved_by, replacement_decision_id
         FROM underwriting_appeals
         ORDER BY updated_at DESC, appeal_id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        ) = row.map_err(ReceiptStoreError::from)?;
        Ok(UnderwritingAppealRecord {
            schema: chio_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status: parse_underwriting_appeal_status(&status)?,
            note,
            created_at: created_at.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            resolved_by,
            replacement_decision_id,
        })
    })
    .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn underwriting_decision_matches_query(
    decision: &SignedUnderwritingDecision,
    lifecycle_state: UnderwritingDecisionLifecycleState,
    latest_appeal_status: Option<UnderwritingAppealStatus>,
    query: &UnderwritingDecisionQuery,
) -> bool {
    let filters = &decision.body.evaluation.input.filters;
    let decision_id_matches = query
        .decision_id
        .as_deref()
        .is_none_or(|decision_id| decision.body.decision_id == decision_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let outcome_matches = query
        .outcome
        .is_none_or(|outcome| decision.body.evaluation.outcome == outcome);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let appeal_matches = query
        .appeal_status
        .is_none_or(|status| latest_appeal_status == Some(status));

    decision_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && outcome_matches
        && lifecycle_matches
        && appeal_matches
}

pub(crate) fn effective_credit_facility_lifecycle_state(
    facility: &SignedCreditFacility,
    persisted: CreditFacilityLifecycleState,
    now: u64,
) -> CreditFacilityLifecycleState {
    if persisted == CreditFacilityLifecycleState::Active && facility.body.expires_at <= now {
        CreditFacilityLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn effective_credit_bond_lifecycle_state(
    bond: &SignedCreditBond,
    persisted: CreditBondLifecycleState,
    now: u64,
) -> CreditBondLifecycleState {
    if persisted == CreditBondLifecycleState::Active && bond.body.expires_at <= now {
        CreditBondLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn credit_facility_matches_query(
    facility: &SignedCreditFacility,
    lifecycle_state: CreditFacilityLifecycleState,
    query: &CreditFacilityListQuery,
) -> bool {
    let filters = &facility.body.report.filters;
    let facility_id_matches = query
        .facility_id
        .as_deref()
        .is_none_or(|facility_id| facility.body.facility_id == facility_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| facility.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn credit_bond_matches_query(
    bond: &SignedCreditBond,
    lifecycle_state: CreditBondLifecycleState,
    query: &CreditBondListQuery,
) -> bool {
    let filters = &bond.body.report.filters;
    let bond_id_matches = query
        .bond_id
        .as_deref()
        .is_none_or(|bond_id| bond.body.bond_id == bond_id);
    let facility_id_matches = query.facility_id.as_deref().is_none_or(|facility_id| {
        bond.body.report.latest_facility_id.as_deref() == Some(facility_id)
    });
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| bond.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    bond_id_matches
        && facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn liability_provider_matches_query(
    provider: &SignedLiabilityProvider,
    lifecycle_state: LiabilityProviderLifecycleState,
    query: &LiabilityProviderListQuery,
) -> bool {
    let report = &provider.body.report;
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| report.provider_id == provider_id);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        report
            .policies
            .iter()
            .any(|policy| policy.jurisdiction.eq_ignore_ascii_case(jurisdiction))
    });
    let coverage_matches = query.coverage_class.is_none_or(|coverage_class| {
        report
            .policies
            .iter()
            .any(|policy| policy.coverage_classes.contains(&coverage_class))
    });
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        report.policies.iter().any(|policy| {
            policy
                .supported_currencies
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(currency))
        })
    });

    provider_id_matches
        && lifecycle_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_provider_policy_matches_resolution(
    policy: &chio_kernel::LiabilityJurisdictionPolicy,
    query: &LiabilityProviderResolutionQuery,
) -> bool {
    policy
        .jurisdiction
        .eq_ignore_ascii_case(&query.jurisdiction)
        && policy.coverage_classes.contains(&query.coverage_class)
        && policy
            .supported_currencies
            .iter()
            .any(|currency| currency.eq_ignore_ascii_case(&query.currency))
}

pub(crate) fn liability_market_workflow_matches_query(
    quote_request: &SignedLiabilityQuoteRequest,
    query: &LiabilityMarketWorkflowQuery,
) -> bool {
    let request = &quote_request.body;
    let quote_request_id_matches = query
        .quote_request_id
        .as_deref()
        .is_none_or(|quote_request_id| request.quote_request_id == quote_request_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| request.provider_policy.provider_id == provider_id);
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| request.risk_package.body.subject_key == subject);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        request
            .provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let coverage_matches = query
        .coverage_class
        .is_none_or(|coverage_class| request.provider_policy.coverage_class == coverage_class);
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        request
            .requested_coverage_amount
            .currency
            .eq_ignore_ascii_case(currency)
    });

    quote_request_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_claim_workflow_matches_query(
    claim: &SignedLiabilityClaimPackage,
    query: &LiabilityClaimWorkflowQuery,
) -> bool {
    let claim_body = &claim.body;
    let provider_policy = &claim_body
        .bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .provider_policy;
    let claim_id_matches = query
        .claim_id
        .as_deref()
        .is_none_or(|claim_id| claim_body.claim_id == claim_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| provider_policy.provider_id == provider_id);
    let subject_matches = query.agent_subject.as_deref().is_none_or(|subject| {
        claim_body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key
            == subject
    });
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let policy_number_matches = query
        .policy_number
        .as_deref()
        .is_none_or(|policy_number| claim_body.bound_coverage.body.policy_number == policy_number);

    claim_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && policy_number_matches
}

pub(crate) fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

pub(crate) fn parse_settlement_status(value: &str) -> Result<SettlementStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn settlement_reconciliation_action_required(
    settlement_status: SettlementStatus,
    reconciliation_state: SettlementReconciliationState,
) -> bool {
    matches!(
        settlement_status,
        SettlementStatus::Pending | SettlementStatus::Failed
    ) && !matches!(
        reconciliation_state,
        SettlementReconciliationState::Reconciled | SettlementReconciliationState::Ignored
    )
}

pub(crate) fn metered_billing_evidence_record_from_columns(
    adapter_kind: Option<String>,
    evidence_id: Option<String>,
    observed_units: Option<i64>,
    billed_cost_units: Option<i64>,
    billed_cost_currency: Option<String>,
    evidence_sha256: Option<String>,
    recorded_at: Option<i64>,
) -> Option<MeteredBillingEvidenceRecord> {
    let (
        Some(adapter_kind),
        Some(evidence_id),
        Some(observed_units),
        Some(billed_cost_units),
        Some(billed_cost_currency),
        Some(recorded_at),
    ) = (
        adapter_kind,
        evidence_id,
        observed_units,
        billed_cost_units,
        billed_cost_currency,
        recorded_at,
    )
    else {
        return None;
    };

    Some(MeteredBillingEvidenceRecord {
        usage_evidence: chio_core::receipt::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: adapter_kind,
            evidence_id,
            observed_units: observed_units.max(0) as u64,
            evidence_sha256,
        },
        billed_cost: chio_core::capability::MonetaryAmount {
            units: billed_cost_units.max(0) as u64,
            currency: billed_cost_currency,
        },
        recorded_at: recorded_at.max(0) as u64,
    })
}

pub(crate) struct MeteredBillingReconciliationAnalysis {
    pub(crate) evidence_missing: bool,
    pub(crate) exceeds_quoted_units: bool,
    pub(crate) exceeds_max_billed_units: bool,
    pub(crate) exceeds_quoted_cost: bool,
    pub(crate) financial_mismatch: bool,
    pub(crate) action_required: bool,
}

pub(crate) fn analyze_metered_billing_reconciliation(
    metered: &chio_core::receipt::MeteredBillingReceiptMetadata,
    financial: Option<&FinancialReceiptMetadata>,
    evidence: Option<&MeteredBillingEvidenceRecord>,
    reconciliation_state: MeteredBillingReconciliationState,
) -> MeteredBillingReconciliationAnalysis {
    let evidence_missing = evidence.is_none();
    let exceeds_quoted_units = evidence
        .is_some_and(|record| record.usage_evidence.observed_units > metered.quote.quoted_units);
    let exceeds_max_billed_units = evidence.is_some_and(|record| {
        metered
            .max_billed_units
            .is_some_and(|max_units| record.usage_evidence.observed_units > max_units)
    });
    let exceeds_quoted_cost = evidence.is_some_and(|record| {
        record.billed_cost.currency != metered.quote.quoted_cost.currency
            || record.billed_cost.units > metered.quote.quoted_cost.units
    });
    let financial_mismatch = evidence.is_some_and(|record| {
        financial.is_some_and(|financial| {
            record.billed_cost.currency != financial.currency
                || record.billed_cost.units != financial.cost_charged
        })
    });
    let action_required = (evidence_missing
        || exceeds_quoted_units
        || exceeds_max_billed_units
        || exceeds_quoted_cost
        || financial_mismatch)
        && !matches!(
            reconciliation_state,
            MeteredBillingReconciliationState::Reconciled
                | MeteredBillingReconciliationState::Ignored
        );

    MeteredBillingReconciliationAnalysis {
        evidence_missing,
        exceeds_quoted_units,
        exceeds_max_billed_units,
        exceeds_quoted_cost,
        financial_mismatch,
        action_required,
    }
}

#[derive(Default)]
pub(crate) struct RootAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
    pub(crate) leaf_subjects: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct LeafAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
}

#[derive(Default)]
pub(crate) struct ReceiptAttributionColumns {
    pub(crate) subject_key: Option<String>,
    pub(crate) issuer_key: Option<String>,
    pub(crate) grant_index: Option<u32>,
}

pub(crate) fn extract_receipt_attribution(receipt: &ChioReceipt) -> ReceiptAttributionColumns {
    let Some(metadata) = receipt.metadata.as_ref() else {
        return ReceiptAttributionColumns::default();
    };

    let attribution = metadata
        .get("attribution")
        .cloned()
        .and_then(|value| serde_json::from_value::<ReceiptAttributionMetadata>(value).ok());
    let grant_index = attribution
        .as_ref()
        .and_then(|value| value.grant_index)
        .or_else(|| {
            metadata
                .get("financial")
                .and_then(|value| value.get("grant_index"))
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as u32)
        });

    ReceiptAttributionColumns {
        subject_key: attribution.as_ref().map(|value| value.subject_key.clone()),
        issuer_key: attribution.as_ref().map(|value| value.issuer_key.clone()),
        grant_index,
    }
}

pub(crate) fn extract_financial_metadata(
    receipt: &ChioReceipt,
) -> Option<FinancialReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .and_then(|value| serde_json::from_value::<FinancialReceiptMetadata>(value).ok())
}

pub(crate) fn extract_governed_transaction_metadata(
    receipt: &ChioReceipt,
) -> Option<GovernedTransactionReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionReceiptMetadata>(value).ok())
}

pub(crate) fn extract_economic_authorization_metadata(
    receipt: &ChioReceipt,
) -> Option<chio_core::receipt::EconomicAuthorizationReceiptMetadata> {
    extract_governed_transaction_metadata(receipt)
        .and_then(|governed| governed.economic_authorization)
}

pub(crate) fn authorization_details_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> Vec<GovernedAuthorizationDetail> {
    let mut details = vec![GovernedAuthorizationDetail {
        detail_type: CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
        locations: vec![governed.server_id.clone()],
        actions: vec![governed.tool_name.clone()],
        purpose: Some(governed.purpose.clone()),
        max_amount: governed.max_amount.clone(),
        commerce: None,
        metered_billing: None,
    }];

    if let Some(commerce) = governed.commerce.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: governed.max_amount.clone(),
            commerce: Some(GovernedAuthorizationCommerceDetail {
                seller: commerce.seller.clone(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
            }),
            metered_billing: None,
        });
    }

    if let Some(metered) = governed.metered_billing.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: None,
            commerce: None,
            metered_billing: Some(GovernedAuthorizationMeteredBillingDetail {
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
            }),
        });
    }

    details
}

pub(crate) fn authorization_transaction_context_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedAuthorizationTransactionContext {
    GovernedAuthorizationTransactionContext {
        intent_id: governed.intent_id.clone(),
        intent_hash: governed.intent_hash.clone(),
        approval_token_id: governed
            .approval
            .as_ref()
            .map(|value| value.token_id.clone()),
        approval_approved: governed.approval.as_ref().map(|value| value.approved),
        approver_key: governed
            .approval
            .as_ref()
            .map(|value| value.approver_key.clone()),
        runtime_assurance_tier: governed.runtime_assurance.as_ref().map(|value| value.tier),
        runtime_assurance_schema: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.schema.clone()),
        runtime_assurance_verifier_family: governed
            .runtime_assurance
            .as_ref()
            .and_then(|value| value.verifier_family),
        runtime_assurance_verifier: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.verifier.clone()),
        runtime_assurance_evidence_sha256: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.evidence_sha256.clone()),
        call_chain: governed.call_chain.clone(),
        identity_assertion: None,
    }
}

fn delegated_call_chain_is_sender_bound(
    call_chain: Option<&chio_core::capability::GovernedCallChainProvenance>,
) -> bool {
    let Some(call_chain) = call_chain else {
        return false;
    };
    if call_chain.evidence_class == chio_core::capability::GovernedProvenanceEvidenceClass::Asserted
    {
        return false;
    }

    let has_local_lineage_link = call_chain.evidence_sources.iter().any(|source| {
        matches!(
            source,
            chio_core::capability::GovernedCallChainEvidenceSource::SessionParentRequestLineage
                | chio_core::capability::GovernedCallChainEvidenceSource::LocalParentReceiptLinkage
                | chio_core::capability::GovernedCallChainEvidenceSource::UpstreamDelegatorProof
        )
    });
    let has_capability_subject_binding = call_chain.evidence_sources.iter().any(|source| {
        matches!(
            source,
            chio_core::capability::GovernedCallChainEvidenceSource::CapabilityDelegatorSubject
                | chio_core::capability::GovernedCallChainEvidenceSource::CapabilityOriginSubject
        )
    });

    has_local_lineage_link
        || (call_chain.evidence_class
            == chio_core::capability::GovernedProvenanceEvidenceClass::Verified
            && has_capability_subject_binding)
}

pub(crate) fn resolve_sender_constraint_subject_key(
    receipt_id: &str,
    receipt_subject_key: Option<&str>,
    lineage_subject_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_subject_key, lineage_subject_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.subjectKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.subjectKey `{receipt_key}` does not match capability snapshot subject `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound subjectKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_issuer_key(
    receipt_id: &str,
    receipt_issuer_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_issuer_key, lineage_issuer_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.issuerKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.issuerKey `{receipt_key}` does not match capability snapshot issuer `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound issuerKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_grant(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
) -> Result<(u32, bool), ReceiptStoreError> {
    let grants_json = grants_json.ok_or_else(|| {
        invalid_chio_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires capability snapshot grants_json",
        )
    })?;
    let scope: ChioScope = serde_json::from_str(grants_json).map_err(|error| {
        invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("invalid capability snapshot grants_json: {error}"),
        )
    })?;

    if let Some(index) = grant_index {
        let grant = scope.grants.get(index as usize).ok_or_else(|| {
            invalid_chio_oauth_authorization_profile(
                receipt_id,
                format!("matched grant_index `{index}` is outside the capability scope"),
            )
        })?;
        if grant.server_id != tool_server || grant.tool_name != tool_name {
            return Err(invalid_chio_oauth_authorization_profile(
                receipt_id,
                format!(
                    "grant_index `{index}` resolves to {}/{} instead of {tool_server}/{tool_name}",
                    grant.server_id, grant.tool_name
                ),
            ));
        }
        return Ok((index, grant.dpop_required == Some(true)));
    }

    let mut matches = scope
        .grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| grant.server_id == tool_server && grant.tool_name == tool_name);
    let Some((index, grant)) = matches.next() else {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("capability snapshot does not contain a grant for {tool_server}/{tool_name}"),
        ));
    };
    if matches.next().is_some() {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!(
                "capability snapshot contains multiple grants for {tool_server}/{tool_name}; grant_index is required"
            ),
        ));
    }
    Ok((index as u32, grant.dpop_required == Some(true)))
}

pub(crate) struct AuthorizationSenderConstraintArgs<'a> {
    pub(crate) tool_server: &'a str,
    pub(crate) tool_name: &'a str,
    pub(crate) receipt_subject_key: Option<&'a str>,
    pub(crate) receipt_issuer_key: Option<&'a str>,
    pub(crate) lineage_subject_key: Option<&'a str>,
    pub(crate) lineage_issuer_key: Option<&'a str>,
    pub(crate) grant_index: Option<u32>,
    pub(crate) grants_json: Option<&'a str>,
}

pub(crate) fn derive_authorization_sender_constraint(
    receipt_id: &str,
    args: AuthorizationSenderConstraintArgs<'_>,
    transaction_context: &GovernedAuthorizationTransactionContext,
) -> Result<AuthorizationContextSenderConstraint, ReceiptStoreError> {
    let AuthorizationSenderConstraintArgs {
        tool_server,
        tool_name,
        receipt_subject_key,
        receipt_issuer_key,
        lineage_subject_key,
        lineage_issuer_key,
        grant_index,
        grants_json,
    } = args;
    let (subject_key, subject_key_source) = resolve_sender_constraint_subject_key(
        receipt_id,
        receipt_subject_key,
        lineage_subject_key,
    )?;
    let (issuer_key, issuer_key_source) =
        resolve_sender_constraint_issuer_key(receipt_id, receipt_issuer_key, lineage_issuer_key)?;
    let (matched_grant_index, proof_required) = resolve_sender_constraint_grant(
        receipt_id,
        tool_server,
        tool_name,
        grant_index,
        grants_json,
    )?;

    Ok(AuthorizationContextSenderConstraint {
        subject_key,
        subject_key_source,
        issuer_key,
        issuer_key_source,
        matched_grant_index,
        proof_required,
        proof_type: proof_required.then(|| CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP.to_string()),
        proof_schema: proof_required.then(|| DPOP_SCHEMA.to_string()),
        runtime_assurance_bound: transaction_context.runtime_assurance_tier.is_some(),
        delegated_call_chain_bound: delegated_call_chain_is_sender_bound(
            transaction_context.call_chain.as_ref(),
        ),
    })
}

pub(crate) fn invalid_chio_oauth_authorization_profile(
    receipt_id: &str,
    detail: impl AsRef<str>,
) -> ReceiptStoreError {
    ReceiptStoreError::Canonical(format!(
        "receipt {receipt_id} violates Chio OAuth authorization profile: {}",
        detail.as_ref()
    ))
}

pub(crate) fn ensure_non_empty_profile_value(
    receipt_id: &str,
    field: &str,
    value: &str,
) -> Result<(), ReceiptStoreError> {
    if value.trim().is_empty() {
        return Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_chio_oauth_authorization_detail(
    receipt_id: &str,
    detail: &GovernedAuthorizationDetail,
) -> Result<bool, ReceiptStoreError> {
    match detail.detail_type.as_str() {
        CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE => {
            if detail.locations.is_empty() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must include at least one location",
                ));
            }
            if detail.actions.is_empty() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must include at least one action",
                ));
            }
            for location in &detail.locations {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.locations[]",
                    location,
                )?;
            }
            for action in &detail.actions {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.actions[]",
                    action,
                )?;
            }
            if detail.commerce.is_some() || detail.metered_billing.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_tool must not carry commerce or meteredBilling sidecars",
                ));
            }
            Ok(true)
        }
        CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE => {
            let Some(commerce) = detail.commerce.as_ref() else {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_commerce must include commerce detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.seller",
                &commerce.seller,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.sharedPaymentTokenId",
                &commerce.shared_payment_token_id,
            )?;
            if detail.metered_billing.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_commerce must not carry meteredBilling detail",
                ));
            }
            Ok(false)
        }
        CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE => {
            let Some(metered) = detail.metered_billing.as_ref() else {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_metered_billing must include meteredBilling detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.provider",
                &metered.provider,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.quoteId",
                &metered.quote_id,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.billingUnit",
                &metered.billing_unit,
            )?;
            if detail.commerce.is_some() {
                return Err(invalid_chio_oauth_authorization_profile(
                    receipt_id,
                    "chio_governed_metered_billing must not carry commerce detail",
                ));
            }
            Ok(false)
        }
        unsupported => Err(invalid_chio_oauth_authorization_profile(
            receipt_id,
            format!("unsupported authorizationDetails.type `{unsupported}`"),
        )),
    }
}

pub(crate) fn validate_chio_oauth_authorization_row(
    row: &AuthorizationContextRow,
) -> Result<(), ReceiptStoreError> {
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentId",
        &row.transaction_context.intent_id,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentHash",
        &row.transaction_context.intent_hash,
    )?;

    let mut saw_tool_detail = false;
    for detail in &row.authorization_details {
        if validate_chio_oauth_authorization_detail(&row.receipt_id, detail)? {
            saw_tool_detail = true;
        }
    }
    if !saw_tool_detail {
        return Err(invalid_chio_oauth_authorization_profile(
            &row.receipt_id,
            "report must include one chio_governed_tool authorization detail",
        ));
    }

    if let Some(token_id) = row.transaction_context.approval_token_id.as_deref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approvalTokenId",
            token_id,
        )?;
        let approver_key = row
            .transaction_context
            .approver_key
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "approvalTokenId requires approverKey",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approverKey",
            approver_key,
        )?;
        if row.transaction_context.approval_approved.is_none() {
            return Err(invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "approvalTokenId requires approvalApproved",
            ));
        }
    }

    if let Some(call_chain) = row.transaction_context.call_chain.as_ref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.chainId",
            &call_chain.chain_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.parentRequestId",
            &call_chain.parent_request_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.originSubject",
            &call_chain.origin_subject,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.delegatorSubject",
            &call_chain.delegator_subject,
        )?;
        if let Some(parent_receipt_id) = call_chain.parent_receipt_id.as_deref() {
            ensure_non_empty_profile_value(
                &row.receipt_id,
                "transactionContext.callChain.parentReceiptId",
                parent_receipt_id,
            )?;
        }
        if row.sender_constraint.delegated_call_chain_bound
            && !delegated_call_chain_is_sender_bound(Some(call_chain))
        {
            return Err(invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "senderConstraint.delegatedCallChainBound requires corroborated call-chain provenance",
            ));
        }
    }

    if row.transaction_context.runtime_assurance_tier.is_some() {
        let runtime_assurance_schema = row
            .transaction_context
            .runtime_assurance_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceSchema",
            runtime_assurance_schema,
        )?;
        row.transaction_context
            .runtime_assurance_verifier_family
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifierFamily",
                )
            })?;
        let runtime_assurance_verifier = row
            .transaction_context
            .runtime_assurance_verifier
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifier",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceVerifier",
            runtime_assurance_verifier,
        )?;
        let runtime_assurance_evidence_sha256 = row
            .transaction_context
            .runtime_assurance_evidence_sha256
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceEvidenceSha256",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceEvidenceSha256",
            runtime_assurance_evidence_sha256,
        )?;
    }

    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKey",
        &row.sender_constraint.subject_key,
    )?;
    if row.subject_key.as_deref() != Some(row.sender_constraint.subject_key.as_str()) {
        return Err(invalid_chio_oauth_authorization_profile(
            &row.receipt_id,
            "row subjectKey must match senderConstraint.subjectKey",
        ));
    }
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKeySource",
        &row.sender_constraint.subject_key_source,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKey",
        &row.sender_constraint.issuer_key,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKeySource",
        &row.sender_constraint.issuer_key_source,
    )?;
    if row.sender_constraint.proof_required {
        let proof_type = row.sender_constraint.proof_type.as_deref().ok_or_else(|| {
            invalid_chio_oauth_authorization_profile(
                &row.receipt_id,
                "proofRequired requires senderConstraint.proofType",
            )
        })?;
        ensure_non_empty_profile_value(&row.receipt_id, "senderConstraint.proofType", proof_type)?;
        let proof_schema = row
            .sender_constraint
            .proof_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_chio_oauth_authorization_profile(
                    &row.receipt_id,
                    "proofRequired requires senderConstraint.proofSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "senderConstraint.proofSchema",
            proof_schema,
        )?;
    }

    Ok(())
}

pub(crate) fn chain_is_complete(
    capability_id: &str,
    chain: &[chio_kernel::CapabilitySnapshot],
) -> bool {
    if chain.is_empty() {
        return false;
    }
    let Some(leaf) = chain.last() else {
        return false;
    };
    if leaf.capability_id != capability_id {
        return false;
    }
    if chain
        .first()
        .and_then(|snapshot| snapshot.parent_capability_id.as_ref())
        .is_some()
    {
        return false;
    }
    if chain.windows(2).any(|window| {
        window[1].parent_capability_id.as_deref() != Some(window[0].capability_id.as_str())
    }) {
        return false;
    }
    if leaf.parent_capability_id.is_some() && chain.len() == 1 {
        return false;
    }
    if leaf.delegation_depth as usize != chain.len().saturating_sub(1) {
        return false;
    }
    true
}

pub(crate) fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

pub(crate) fn compliance_export_scope_note(
    query: &OperatorReportQuery,
    export_query: &EvidenceExportQuery,
) -> Option<String> {
    let mut notes = Vec::new();

    if !query.direct_evidence_export_supported() {
        notes.push(
            "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window".to_string(),
        );
    }

    match export_query.child_receipt_scope() {
        EvidenceChildReceiptScope::TimeWindowContextOnly => notes.push(
            "child receipts are included only as time-window context for this export scope".to_string(),
        ),
        EvidenceChildReceiptScope::OmittedNoJoinPath => notes.push(
            "child receipts are omitted for this export scope because no capability/agent join exists yet".to_string(),
        ),
        EvidenceChildReceiptScope::FullQueryWindow => {}
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}

pub(crate) fn ensure_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(chio_tool_receipts)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "subject_key") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN subject_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "issuer_key") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN issuer_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "grant_index") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN grant_index INTEGER",
            [],
        )?;
    }

    // Phase 1.5 multi-tenant receipt isolation: tenant_id column.
    //
    // Pre-multitenant receipts migrate to NULL, which the
    // tenant-scoped WHERE clause treats as a "public" fallback set (a
    // tenant A query returns its own rows AND the NULL-tagged legacy
    // set), so historical data remains visible under query modes that
    // opt into backward compatibility. Operators that need strict
    // isolation across the legacy set can enable
    // [`SqliteReceiptStore::with_strict_tenant_isolation`].
    //
    // Migration fails closed: if the column cannot be added we bail
    // out and the caller treats the store as unreadable, per the
    // kernel's fail-closed convention.
    if !columns.iter().any(|column| column == "tenant_id") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN tenant_id TEXT",
            [],
        )?;
    }

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject ON chio_tool_receipts(subject_key)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant ON chio_tool_receipts(capability_id, grant_index)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tenant ON chio_tool_receipts(tenant_id)",
        [],
    )?;
    Ok(())
}

pub(crate) fn ensure_receipt_lineage_statement_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(receipt_lineage_statements)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "statement_id") {
        connection.execute(
            "ALTER TABLE receipt_lineage_statements ADD COLUMN statement_id TEXT",
            [],
        )?;
    }

    connection.execute(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_statement_id
            ON receipt_lineage_statements(statement_id)
            WHERE statement_id IS NOT NULL
        "#,
        [],
    )?;
    connection.execute(
        r#"
        UPDATE receipt_lineage_statements
        SET statement_id = json_extract(raw_json, '$.id')
        WHERE statement_id IS NULL
          AND json_extract(raw_json, '$.schema') = ?1
        "#,
        params![chio_core::receipt::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA],
    )?;
    Ok(())
}

pub(crate) fn backfill_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        UPDATE chio_tool_receipts
        SET grant_index = CAST(COALESCE(
            json_extract(raw_json, '$.metadata.attribution.grant_index'),
            json_extract(raw_json, '$.metadata.financial.grant_index')
        ) AS INTEGER)
        WHERE grant_index IS NULL
          AND COALESCE(
                json_extract(raw_json, '$.metadata.attribution.grant_index'),
                json_extract(raw_json, '$.metadata.financial.grant_index')
              ) IS NOT NULL;

        UPDATE chio_tool_receipts
        SET subject_key = COALESCE(
            subject_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
            (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
        )
        WHERE subject_key IS NULL
          AND COALESCE(
                CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
                (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
              ) IS NOT NULL;

        UPDATE chio_tool_receipts
        SET issuer_key = COALESCE(
            issuer_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
            (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
        )
        WHERE issuer_key IS NULL
          AND COALESCE(
                CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
                (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
              ) IS NOT NULL;

        -- Phase 1.5 multi-tenant receipt isolation: hydrate tenant_id
        -- from the canonical receipt body. Legacy receipts (pre-1.5)
        -- that were stored before the field existed stay NULL, which
        -- means "public / visible to any tenant under the default
        -- compat query mode". Operators who want to purge those
        -- legacy rows can enable strict tenant isolation on queries.
        --
        -- The receipt body uses snake_case field names (no rename_all),
        -- so the JSON key is `tenant_id`, not `tenantId`.
        UPDATE chio_tool_receipts
        SET tenant_id = CAST(json_extract(raw_json, '$.tenant_id') AS TEXT)
        WHERE tenant_id IS NULL
          AND json_extract(raw_json, '$.tenant_id') IS NOT NULL;
        "#,
    )?;
    Ok(())
}

const SESSION_ANCHOR_SOURCE_KIND: &str = "session_anchor";
const REQUEST_LINEAGE_SOURCE_KIND: &str = "request_lineage_record";
const RECEIPT_LINEAGE_SOURCE_KIND: &str = "receipt_lineage_statement";
const CHILD_RECEIPT_BACKFILL_SOURCE_KIND: &str = "child_receipt_backfill";
const GOVERNED_RECEIPT_BACKFILL_SOURCE_KIND: &str = "governed_receipt_backfill";

fn provenance_json_sha256(value: &serde_json::Value) -> Result<String, ReceiptStoreError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

fn sanitize_required_identifier(
    record_kind: &str,
    record_id: &str,
    field: &str,
    value: &str,
) -> Result<String, ReceiptStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ReceiptStoreError::Conflict(format!(
            "{record_kind} `{record_id}` requires non-empty {field}"
        )));
    }
    Ok(trimmed.to_string())
}

fn sanitize_optional_identifier(
    record_kind: &str,
    record_id: &str,
    field: &str,
    value: Option<&str>,
) -> Result<Option<String>, ReceiptStoreError> {
    value
        .map(|value| sanitize_required_identifier(record_kind, record_id, field, value))
        .transpose()
}

fn merge_optional_identifier(
    record_kind: &str,
    record_id: &str,
    field: &str,
    existing: Option<String>,
    incoming: Option<&str>,
) -> Result<Option<String>, ReceiptStoreError> {
    let incoming = sanitize_optional_identifier(record_kind, record_id, field, incoming)?;
    match (existing, incoming) {
        (Some(existing), Some(incoming)) if existing != incoming => {
            Err(ReceiptStoreError::Conflict(format!(
                "{record_kind} `{record_id}` reuses {field} with conflicting value `{incoming}` (existing `{existing}`)"
            )))
        }
        (Some(existing), _) => Ok(Some(existing)),
        (None, incoming) => Ok(incoming),
    }
}

fn request_lineage_exists_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    request_id: &str,
) -> Result<bool, ReceiptStoreError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1
            FROM request_lineage
            WHERE session_id = ?1 AND request_id = ?2
            LIMIT 1
            "#,
            params![session_id, request_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn anchored_request_lineage_exists_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    request_id: &str,
    session_anchor_id: &str,
) -> Result<bool, ReceiptStoreError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1
            FROM request_lineage
            WHERE session_id = ?1
              AND request_id = ?2
              AND session_anchor_id = ?3
            LIMIT 1
            "#,
            params![session_id, request_id, session_anchor_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn session_anchor_exists_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    session_anchor_id: &str,
) -> Result<bool, ReceiptStoreError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1
            FROM session_anchors
            WHERE anchor_id = ?1
              AND session_id = ?2
            LIMIT 1
            "#,
            params![session_anchor_id, session_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn receipt_id_exists_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
) -> Result<bool, ReceiptStoreError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1
            FROM (
                SELECT receipt_id FROM chio_tool_receipts
                UNION ALL
                SELECT receipt_id FROM chio_child_receipts
            )
            WHERE receipt_id = ?1
            LIMIT 1
            "#,
            params![receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn extract_lineage_evidence_class(statement_json: &serde_json::Value) -> Option<String> {
    let nested = statement_json
        .get("callChain")
        .or_else(|| statement_json.get("call_chain"));
    [Some(statement_json), nested]
        .into_iter()
        .flatten()
        .find_map(|value| {
            value
                .get("evidenceClass")
                .or_else(|| value.get("evidence_class"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
}

fn extract_lineage_evidence_sources_json(
    statement_json: &serde_json::Value,
) -> Result<Option<String>, ReceiptStoreError> {
    let nested = statement_json
        .get("callChain")
        .or_else(|| statement_json.get("call_chain"));
    for value in [Some(statement_json), nested].into_iter().flatten() {
        if let Some(sources) = value
            .get("evidenceSources")
            .or_else(|| value.get("evidence_sources"))
        {
            return Ok(Some(serde_json::to_string(sources)?));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Default)]
struct ReceiptLineageStatementIdentifiers {
    statement_id: Option<String>,
    child_receipt_id: Option<String>,
    child_request_id: Option<String>,
    child_session_anchor_id: Option<String>,
    parent_request_id: Option<String>,
    parent_receipt_id: Option<String>,
}

fn extract_receipt_lineage_statement_identifiers(
    statement_json: &serde_json::Value,
) -> ReceiptLineageStatementIdentifiers {
    let schema = statement_json
        .get("schema")
        .and_then(serde_json::Value::as_str);
    if schema != Some(chio_core::receipt::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA) {
        return ReceiptLineageStatementIdentifiers::default();
    }

    if let Ok(statement) = serde_json::from_value::<chio_core::receipt::ReceiptLineageStatement>(
        statement_json.clone(),
    ) {
        return ReceiptLineageStatementIdentifiers {
            statement_id: Some(statement.id),
            child_receipt_id: Some(statement.child_receipt_id),
            child_request_id: Some(statement.child_request_id.to_string()),
            child_session_anchor_id: Some(statement.child_session_anchor.session_anchor_id),
            parent_request_id: Some(statement.parent_request_id.to_string()),
            parent_receipt_id: Some(statement.parent_receipt_id),
        };
    }

    if let Ok(statement) = serde_json::from_value::<chio_core::receipt::ReceiptLineageStatementBody>(
        statement_json.clone(),
    ) {
        return ReceiptLineageStatementIdentifiers {
            statement_id: Some(statement.id),
            child_receipt_id: Some(statement.child_receipt_id),
            child_request_id: Some(statement.child_request_id.to_string()),
            child_session_anchor_id: Some(statement.child_session_anchor.session_anchor_id),
            parent_request_id: Some(statement.parent_request_id.to_string()),
            parent_receipt_id: Some(statement.parent_receipt_id),
        };
    }

    ReceiptLineageStatementIdentifiers::default()
}

fn build_receipt_lineage_verification_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
    request_id: Option<&str>,
    session_id: Option<&str>,
    session_anchor_id: Option<&str>,
    parent_request_id: Option<&str>,
    parent_receipt_id: Option<&str>,
) -> Result<ReceiptLineageVerification, ReceiptStoreError> {
    let session_anchor_verified = match (session_id, session_anchor_id) {
        (Some(session_id), Some(session_anchor_id)) => {
            session_anchor_exists_tx(tx, session_id, session_anchor_id)?
        }
        _ => false,
    };
    let parent_request_verified = match (session_id, parent_request_id) {
        (Some(session_id), Some(parent_request_id)) => {
            request_lineage_exists_tx(tx, session_id, parent_request_id)?
        }
        _ => false,
    };
    let parent_receipt_verified = match parent_receipt_id {
        Some(parent_receipt_id) => receipt_id_exists_tx(tx, parent_receipt_id)?,
        None => false,
    };
    let replay_protected = match (session_id, request_id, session_anchor_id) {
        (Some(session_id), Some(request_id), Some(session_anchor_id))
            if session_anchor_verified =>
        {
            anchored_request_lineage_exists_tx(tx, session_id, request_id, session_anchor_id)?
        }
        _ => false,
    };

    Ok(ReceiptLineageVerification {
        receipt_id: receipt_id.to_string(),
        request_id: request_id.map(str::to_string),
        session_id: session_id.map(str::to_string),
        session_anchor_id: session_anchor_id.map(str::to_string),
        session_anchor_verified,
        parent_request_verified,
        parent_receipt_verified,
        replay_protected,
    })
}

fn refresh_receipt_lineage_verification_state_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
) -> Result<(), ReceiptStoreError> {
    let row = tx
        .query_row(
            r#"
            SELECT request_id, session_id, session_anchor_id, parent_request_id, parent_receipt_id
            FROM receipt_lineage_statements
            WHERE receipt_id = ?1
            "#,
            params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((request_id, session_id, session_anchor_id, parent_request_id, parent_receipt_id)) =
        row
    else {
        return Ok(());
    };

    let verification = build_receipt_lineage_verification_tx(
        tx,
        receipt_id,
        request_id.as_deref(),
        session_id.as_deref(),
        session_anchor_id.as_deref(),
        parent_request_id.as_deref(),
        parent_receipt_id.as_deref(),
    )?;
    tx.execute(
        r#"
        UPDATE receipt_lineage_statements
        SET verified_session_anchor = ?2,
            verified_parent_request = ?3,
            verified_parent_receipt = ?4,
            replay_protected = ?5
        WHERE receipt_id = ?1
        "#,
        params![
            receipt_id,
            sqlite_bool(verification.session_anchor_verified),
            sqlite_bool(verification.parent_request_verified),
            sqlite_bool(verification.parent_receipt_verified),
            sqlite_bool(verification.replay_protected),
        ],
    )?;
    Ok(())
}

fn refresh_receipt_lineage_rows_for_request_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    request_id: &str,
) -> Result<(), ReceiptStoreError> {
    let mut statement = tx.prepare(
        r#"
        SELECT receipt_id
        FROM receipt_lineage_statements
        WHERE session_id = ?1
          AND (request_id = ?2 OR parent_request_id = ?2)
        "#,
    )?;
    let receipt_ids = statement
        .query_map(params![session_id, request_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for receipt_id in receipt_ids {
        refresh_receipt_lineage_verification_state_tx(tx, &receipt_id)?;
    }
    Ok(())
}

fn refresh_receipt_lineage_rows_for_anchor_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    session_anchor_id: &str,
) -> Result<(), ReceiptStoreError> {
    let mut statement = tx.prepare(
        r#"
        SELECT receipt_id
        FROM receipt_lineage_statements
        WHERE session_id = ?1
          AND session_anchor_id = ?2
        "#,
    )?;
    let receipt_ids = statement
        .query_map(params![session_id, session_anchor_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for receipt_id in receipt_ids {
        refresh_receipt_lineage_verification_state_tx(tx, &receipt_id)?;
    }
    Ok(())
}

fn refresh_receipt_lineage_rows_for_parent_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    parent_receipt_id: &str,
) -> Result<(), ReceiptStoreError> {
    let mut statement = tx.prepare(
        r#"
        SELECT receipt_id
        FROM receipt_lineage_statements
        WHERE parent_receipt_id = ?1
        "#,
    )?;
    let receipt_ids = statement
        .query_map(params![parent_receipt_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for receipt_id in receipt_ids {
        refresh_receipt_lineage_verification_state_tx(tx, &receipt_id)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_session_anchor_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    anchor_id: &str,
    auth_context_fingerprint: &str,
    issued_at: u64,
    supersedes_anchor_id: Option<&str>,
    source_kind: &str,
    anchor_json: &serde_json::Value,
) -> Result<(), ReceiptStoreError> {
    let session_id =
        sanitize_required_identifier("session anchor", anchor_id, "session_id", session_id)?;
    let anchor_id =
        sanitize_required_identifier("session anchor", anchor_id, "anchor_id", anchor_id)?;
    let auth_context_fingerprint = sanitize_required_identifier(
        "session anchor",
        &anchor_id,
        "auth_context_fingerprint",
        auth_context_fingerprint,
    )?;
    let supersedes_anchor_id = sanitize_optional_identifier(
        "session anchor",
        &anchor_id,
        "supersedes_anchor_id",
        supersedes_anchor_id,
    )?;
    if supersedes_anchor_id.as_deref() == Some(anchor_id.as_str()) {
        return Err(ReceiptStoreError::Conflict(format!(
            "session anchor `{anchor_id}` cannot supersede itself"
        )));
    }

    let replaces_current_anchor = match supersedes_anchor_id.as_deref() {
        Some(supersedes_anchor_id) => tx
            .query_row(
                r#"
                SELECT is_current
                FROM session_anchors
                WHERE session_id = ?1
                  AND anchor_id = ?2
                "#,
                params![&session_id, supersedes_anchor_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|is_current| is_current != 0)
            .unwrap_or(false),
        None => false,
    };

    if !replaces_current_anchor
        && tx
            .query_row(
                r#"
                SELECT anchor_id
                FROM session_anchors
                WHERE session_id = ?1
                  AND auth_context_fingerprint = ?2
                  AND anchor_id <> ?3
                LIMIT 1
                "#,
                params![&session_id, &auth_context_fingerprint, &anchor_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some()
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "session anchor replay detected for session `{session_id}` auth_context_fingerprint `{auth_context_fingerprint}`"
        )));
    }

    if let Some(existing_session_id) = tx
        .query_row(
            "SELECT session_id FROM session_anchors WHERE anchor_id = ?1",
            params![&anchor_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        if existing_session_id != session_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "session anchor `{anchor_id}` is already bound to session `{existing_session_id}`"
            )));
        }
    }

    let raw_json = serde_json::to_string(anchor_json)?;
    let json_sha256 = provenance_json_sha256(anchor_json)?;

    tx.execute(
        "UPDATE session_anchors SET is_current = 0 WHERE session_id = ?1 AND anchor_id <> ?2",
        params![&session_id, &anchor_id],
    )?;
    tx.execute(
        r#"
        INSERT INTO session_anchors (
            anchor_id,
            session_id,
            auth_context_fingerprint,
            issued_at,
            supersedes_anchor_id,
            is_current,
            source_kind,
            json_sha256,
            raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)
        ON CONFLICT(anchor_id) DO UPDATE SET
            auth_context_fingerprint = excluded.auth_context_fingerprint,
            issued_at = excluded.issued_at,
            supersedes_anchor_id = COALESCE(excluded.supersedes_anchor_id, session_anchors.supersedes_anchor_id),
            is_current = 1,
            source_kind = excluded.source_kind,
            json_sha256 = excluded.json_sha256,
            raw_json = excluded.raw_json
        "#,
        params![
            &anchor_id,
            &session_id,
            &auth_context_fingerprint,
            sqlite_i64(issued_at, "session anchor issued_at")?,
            supersedes_anchor_id.as_deref(),
            source_kind,
            &json_sha256,
            &raw_json,
        ],
    )?;
    refresh_receipt_lineage_rows_for_anchor_tx(tx, &session_id, &anchor_id)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_request_lineage_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    request_id: &str,
    parent_request_id: Option<&str>,
    session_anchor_id: Option<&str>,
    recorded_at: u64,
    request_fingerprint: Option<&str>,
    source_kind: &str,
    lineage_json: &serde_json::Value,
) -> Result<(), ReceiptStoreError> {
    let session_id =
        sanitize_required_identifier("request lineage", request_id, "session_id", session_id)?;
    let request_id =
        sanitize_required_identifier("request lineage", request_id, "request_id", request_id)?;
    let parent_request_id = sanitize_optional_identifier(
        "request lineage",
        &request_id,
        "parent_request_id",
        parent_request_id,
    )?;
    if parent_request_id.as_deref() == Some(request_id.as_str()) {
        return Err(ReceiptStoreError::Conflict(format!(
            "request lineage `{request_id}` cannot point at itself as parent_request_id"
        )));
    }

    let existing = tx
        .query_row(
            r#"
            SELECT parent_request_id, session_anchor_id, request_fingerprint
            FROM request_lineage
            WHERE session_id = ?1 AND request_id = ?2
            "#,
            params![&session_id, &request_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    let (existing_parent_request_id, existing_session_anchor_id, existing_request_fingerprint) =
        existing.unwrap_or((None, None, None));

    let session_anchor_id = merge_optional_identifier(
        "request lineage",
        &request_id,
        "session_anchor_id",
        existing_session_anchor_id,
        session_anchor_id,
    )?;
    let parent_request_id = merge_optional_identifier(
        "request lineage",
        &request_id,
        "parent_request_id",
        existing_parent_request_id,
        parent_request_id.as_deref(),
    )?;
    let request_fingerprint = merge_optional_identifier(
        "request lineage",
        &request_id,
        "request_fingerprint",
        existing_request_fingerprint,
        request_fingerprint,
    )?;

    let raw_json = serde_json::to_string(lineage_json)?;
    let json_sha256 = provenance_json_sha256(lineage_json)?;
    tx.execute(
        r#"
        INSERT INTO request_lineage (
            session_id,
            request_id,
            parent_request_id,
            session_anchor_id,
            recorded_at,
            request_fingerprint,
            source_kind,
            json_sha256,
            raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(session_id, request_id) DO UPDATE SET
            parent_request_id = excluded.parent_request_id,
            session_anchor_id = excluded.session_anchor_id,
            recorded_at = excluded.recorded_at,
            request_fingerprint = excluded.request_fingerprint,
            source_kind = excluded.source_kind,
            json_sha256 = excluded.json_sha256,
            raw_json = excluded.raw_json
        "#,
        params![
            &session_id,
            &request_id,
            parent_request_id.as_deref(),
            session_anchor_id.as_deref(),
            sqlite_i64(recorded_at, "request lineage recorded_at")?,
            request_fingerprint.as_deref(),
            source_kind,
            &json_sha256,
            &raw_json,
        ],
    )?;
    refresh_receipt_lineage_rows_for_request_tx(tx, &session_id, &request_id)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_receipt_lineage_statement_tx(
    tx: &rusqlite::Transaction<'_>,
    child_receipt_id: &str,
    request_id: Option<&str>,
    session_id: Option<&str>,
    session_anchor_id: Option<&str>,
    parent_request_id: Option<&str>,
    parent_receipt_id: Option<&str>,
    chain_id: Option<&str>,
    recorded_at: u64,
    source_kind: &str,
    statement_json: &serde_json::Value,
) -> Result<(), ReceiptStoreError> {
    let child_receipt_id = sanitize_required_identifier(
        "receipt lineage statement",
        child_receipt_id,
        "child_receipt_id",
        child_receipt_id,
    )?;
    let extracted = extract_receipt_lineage_statement_identifiers(statement_json);
    if let Some(extracted_child_receipt_id) = extracted.child_receipt_id.as_deref() {
        let extracted_child_receipt_id = sanitize_required_identifier(
            "receipt lineage statement",
            &child_receipt_id,
            "statement.child_receipt_id",
            extracted_child_receipt_id,
        )?;
        if extracted_child_receipt_id != child_receipt_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt lineage statement `{child_receipt_id}` conflicts with signed child_receipt_id `{extracted_child_receipt_id}`"
            )));
        }
    }

    let existing = tx
        .query_row(
            r#"
            SELECT statement_id, request_id, session_id, session_anchor_id, parent_request_id, parent_receipt_id, chain_id
            FROM receipt_lineage_statements
            WHERE receipt_id = ?1
            "#,
            params![&child_receipt_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;
    let (
        existing_statement_id,
        existing_request_id,
        existing_session_id,
        existing_session_anchor_id,
        existing_parent_request_id,
        existing_parent_receipt_id,
        existing_chain_id,
    ) = existing.unwrap_or((None, None, None, None, None, None, None));

    let statement_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "statement_id",
        existing_statement_id,
        extracted.statement_id.as_deref(),
    )?;

    let request_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "request_id",
        existing_request_id,
        extracted.child_request_id.as_deref().or(request_id),
    )?;
    let session_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "session_id",
        existing_session_id,
        session_id,
    )?;
    let session_anchor_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "session_anchor_id",
        existing_session_anchor_id,
        extracted
            .child_session_anchor_id
            .as_deref()
            .or(session_anchor_id),
    )?;
    let parent_request_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "parent_request_id",
        existing_parent_request_id,
        extracted.parent_request_id.as_deref().or(parent_request_id),
    )?;
    let parent_receipt_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "parent_receipt_id",
        existing_parent_receipt_id,
        extracted.parent_receipt_id.as_deref().or(parent_receipt_id),
    )?;
    let chain_id = merge_optional_identifier(
        "receipt lineage statement",
        &child_receipt_id,
        "chain_id",
        existing_chain_id,
        chain_id,
    )?;

    if session_anchor_id.is_some() && session_id.is_none() {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt lineage statement `{child_receipt_id}` requires session_id when session_anchor_id is present"
        )));
    }
    if request_id.is_some() && session_id.is_none() {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt lineage statement `{child_receipt_id}` requires session_id when request_id is present"
        )));
    }
    if request_id.is_some() && parent_request_id.is_some() && request_id == parent_request_id {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt lineage statement `{child_receipt_id}` cannot reuse request_id as parent_request_id"
        )));
    }
    if parent_receipt_id.as_deref() == Some(child_receipt_id.as_str()) {
        return Err(ReceiptStoreError::Conflict(format!(
            "receipt lineage statement `{child_receipt_id}` cannot point at itself as parent_receipt_id"
        )));
    }

    let verification = build_receipt_lineage_verification_tx(
        tx,
        &child_receipt_id,
        request_id.as_deref(),
        session_id.as_deref(),
        session_anchor_id.as_deref(),
        parent_request_id.as_deref(),
        parent_receipt_id.as_deref(),
    )?;
    let evidence_class = extract_lineage_evidence_class(statement_json);
    let evidence_sources_json = extract_lineage_evidence_sources_json(statement_json)?;
    let raw_json = serde_json::to_string(statement_json)?;
    let json_sha256 = provenance_json_sha256(statement_json)?;

    tx.execute(
        r#"
        INSERT INTO receipt_lineage_statements (
            receipt_id,
            statement_id,
            request_id,
            session_id,
            session_anchor_id,
            chain_id,
            parent_request_id,
            parent_receipt_id,
            evidence_class,
            evidence_sources_json,
            verified_session_anchor,
            verified_parent_request,
            verified_parent_receipt,
            replay_protected,
            recorded_at,
            source_kind,
            json_sha256,
            raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        ON CONFLICT(receipt_id) DO UPDATE SET
            statement_id = excluded.statement_id,
            request_id = excluded.request_id,
            session_id = excluded.session_id,
            session_anchor_id = excluded.session_anchor_id,
            chain_id = excluded.chain_id,
            parent_request_id = excluded.parent_request_id,
            parent_receipt_id = excluded.parent_receipt_id,
            evidence_class = excluded.evidence_class,
            evidence_sources_json = excluded.evidence_sources_json,
            verified_session_anchor = excluded.verified_session_anchor,
            verified_parent_request = excluded.verified_parent_request,
            verified_parent_receipt = excluded.verified_parent_receipt,
            replay_protected = excluded.replay_protected,
            recorded_at = excluded.recorded_at,
            source_kind = excluded.source_kind,
            json_sha256 = excluded.json_sha256,
            raw_json = excluded.raw_json
        "#,
        params![
            &child_receipt_id,
            statement_id.as_deref(),
            request_id.as_deref(),
            session_id.as_deref(),
            session_anchor_id.as_deref(),
            chain_id.as_deref(),
            parent_request_id.as_deref(),
            parent_receipt_id.as_deref(),
            evidence_class.as_deref(),
            evidence_sources_json.as_deref(),
            sqlite_bool(verification.session_anchor_verified),
            sqlite_bool(verification.parent_request_verified),
            sqlite_bool(verification.parent_receipt_verified),
            sqlite_bool(verification.replay_protected),
            sqlite_i64(recorded_at, "receipt lineage statement recorded_at")?,
            source_kind,
            &json_sha256,
            &raw_json,
        ],
    )?;
    refresh_receipt_lineage_rows_for_parent_receipt_tx(tx, &child_receipt_id)?;
    Ok(())
}

fn ensure_receipt_lineage_statement_for_receipt_id_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
) -> Result<(), ReceiptStoreError> {
    if tx
        .query_row(
            "SELECT 1 FROM receipt_lineage_statements WHERE receipt_id = ?1 LIMIT 1",
            params![receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        refresh_receipt_lineage_verification_state_tx(tx, receipt_id)?;
        refresh_receipt_lineage_rows_for_parent_receipt_tx(tx, receipt_id)?;
        return Ok(());
    }

    let row = tx
        .query_row(
            "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((seq, raw_json)) = row else {
        return Ok(());
    };
    let receipt =
        decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq.max(0) as u64))?;
    let Some(governed) = extract_governed_transaction_metadata(&receipt) else {
        refresh_receipt_lineage_rows_for_parent_receipt_tx(tx, receipt_id)?;
        return Ok(());
    };
    let Some(call_chain) = governed.call_chain.as_ref() else {
        refresh_receipt_lineage_rows_for_parent_receipt_tx(tx, receipt_id)?;
        return Ok(());
    };

    persist_receipt_lineage_statement_tx(
        tx,
        &receipt.id,
        None,
        None,
        None,
        Some(call_chain.parent_request_id.as_str()),
        call_chain.parent_receipt_id.as_deref(),
        Some(call_chain.chain_id.as_str()),
        receipt.timestamp,
        GOVERNED_RECEIPT_BACKFILL_SOURCE_KIND,
        &serde_json::to_value(call_chain)?,
    )?;
    Ok(())
}

fn load_receipt_lineage_verification(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT receipt_id, request_id, session_id, session_anchor_id,
                   verified_session_anchor, verified_parent_request,
                   verified_parent_receipt, replay_protected
            FROM receipt_lineage_statements
            WHERE receipt_id = ?1
            "#,
            params![receipt_id],
            |row| {
                Ok(ReceiptLineageVerification {
                    receipt_id: row.get::<_, String>(0)?,
                    request_id: row.get::<_, Option<String>>(1)?,
                    session_id: row.get::<_, Option<String>>(2)?,
                    session_anchor_id: row.get::<_, Option<String>>(3)?,
                    session_anchor_verified: row.get::<_, i64>(4)? != 0,
                    parent_request_verified: row.get::<_, i64>(5)? != 0,
                    parent_receipt_verified: row.get::<_, i64>(6)? != 0,
                    replay_protected: row.get::<_, i64>(7)? != 0,
                })
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)
}

fn load_receipt_lineage_statement_links(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT statement_id,
               receipt_id,
               request_id,
               parent_receipt_id,
               parent_request_id,
               session_id,
               session_anchor_id,
               chain_id,
               recorded_at
        FROM receipt_lineage_statements
        WHERE receipt_id = ?1
           OR parent_receipt_id = ?1
        ORDER BY recorded_at ASC, receipt_id ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![receipt_id], |row| {
            let recorded_at = row.get::<_, i64>(8)?;
            let recorded_at = u64::try_from(recorded_at)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(8, recorded_at))?;
            Ok(ReceiptLineageStatementLink {
                statement_id: row.get::<_, Option<String>>(0)?,
                child_receipt_id: row.get::<_, String>(1)?,
                child_request_id: row.get::<_, Option<String>>(2)?,
                parent_receipt_id: row.get::<_, Option<String>>(3)?,
                parent_request_id: row.get::<_, Option<String>>(4)?,
                session_id: row.get::<_, Option<String>>(5)?,
                session_anchor_id: row.get::<_, Option<String>>(6)?,
                chain_id: row.get::<_, Option<String>>(7)?,
                recorded_at,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub(crate) fn backfill_provenance_lineage_tables(
    connection: &mut Connection,
) -> Result<(), ReceiptStoreError> {
    let tx = connection.transaction()?;

    let child_rows = {
        let mut statement = tx.prepare(
            "SELECT seq, raw_json FROM chio_child_receipts ORDER BY timestamp ASC, seq ASC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (seq, raw_json) in child_rows {
        let receipt = decode_verified_child_receipt(
            &raw_json,
            "persisted child receipt",
            Some(seq.max(0) as u64),
        )?;
        persist_request_lineage_tx(
            &tx,
            receipt.session_id.as_str(),
            receipt.request_id.as_str(),
            Some(receipt.parent_request_id.as_str()),
            None,
            receipt.timestamp,
            None,
            CHILD_RECEIPT_BACKFILL_SOURCE_KIND,
            &serde_json::from_str::<serde_json::Value>(&raw_json)?,
        )?;
    }

    let tool_receipt_ids = {
        let mut statement = tx
            .prepare("SELECT receipt_id FROM chio_tool_receipts ORDER BY timestamp ASC, seq ASC")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for receipt_id in tool_receipt_ids {
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt_id)?;
    }

    tx.commit()?;
    Ok(())
}

impl SqliteReceiptStore {
    #[allow(dead_code)]
    pub(crate) fn claim_tree_canonical_bytes_range(
        &self,
        start_entry_seq: u64,
        end_entry_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let connection = self.connection()?;
        load_claim_tree_canonical_bytes_range(&connection, start_entry_seq, end_entry_seq)
    }

    pub fn record_session_anchor_record(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        persist_session_anchor_tx(
            &tx,
            session_id,
            anchor_id,
            auth_context_fingerprint,
            issued_at,
            supersedes_anchor_id,
            SESSION_ANCHOR_SOURCE_KIND,
            anchor_json,
        )?;
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_request_lineage_record(
        &self,
        session_id: &str,
        request_id: &str,
        parent_request_id: Option<&str>,
        session_anchor_id: Option<&str>,
        recorded_at: u64,
        request_fingerprint: Option<&str>,
        lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        persist_request_lineage_tx(
            &tx,
            session_id,
            request_id,
            parent_request_id,
            session_anchor_id,
            recorded_at,
            request_fingerprint,
            REQUEST_LINEAGE_SOURCE_KIND,
            lineage_json,
        )?;
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_receipt_lineage_statement_record(
        &self,
        child_receipt_id: &str,
        request_id: Option<&str>,
        session_id: Option<&str>,
        session_anchor_id: Option<&str>,
        parent_request_id: Option<&str>,
        parent_receipt_id: Option<&str>,
        chain_id: Option<&str>,
        recorded_at: u64,
        statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        persist_receipt_lineage_statement_tx(
            &tx,
            child_receipt_id,
            request_id,
            session_id,
            session_anchor_id,
            parent_request_id,
            parent_receipt_id,
            chain_id,
            recorded_at,
            RECEIPT_LINEAGE_SOURCE_KIND,
            statement_json,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_receipt_lineage_statement_links(
        &self,
        receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, receipt_id)?;
        refresh_receipt_lineage_rows_for_parent_receipt_tx(&tx, receipt_id)?;
        let links = load_receipt_lineage_statement_links(&tx, receipt_id)?;
        tx.commit()?;
        Ok(links)
    }

    pub fn receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, receipt_id)?;
        let verification = load_receipt_lineage_verification(&tx, receipt_id)?;
        tx.commit()?;
        Ok(verification)
    }

    pub fn append_child_receipt_record(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_child_receipt_verified(receipt)?;
        let raw_json = serde_json::to_string(receipt)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            r#"
            INSERT INTO chio_child_receipts (
                receipt_id,
                timestamp,
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                policy_hash,
                outcome_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                sqlite_i64(receipt.timestamp, "child receipt timestamp")?,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                &raw_json,
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(0);
        }
        let source_seq = tx.query_row(
            "SELECT seq FROM chio_child_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        let source_seq = sqlite_u64(source_seq, "child receipt source_seq")?;
        let entry_seq = tx.query_row(
            r#"
            SELECT entry_seq
            FROM claim_receipt_log_entries
            WHERE receipt_kind = 'child_receipt' AND source_seq = ?1
            "#,
            params![sqlite_i64(source_seq, "child receipt source_seq")?],
            |row| row.get::<_, i64>(0),
        )?;
        persist_request_lineage_tx(
            &tx,
            receipt.session_id.as_str(),
            receipt.request_id.as_str(),
            Some(receipt.parent_request_id.as_str()),
            None,
            receipt.timestamp,
            None,
            CHILD_RECEIPT_BACKFILL_SOURCE_KIND,
            &serde_json::from_str::<serde_json::Value>(&raw_json)?,
        )?;
        tx.commit()?;
        sqlite_u64(entry_seq, "child receipt claim log entry_seq")
    }
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt).map(|_| ())
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        let seq = SqliteReceiptStore::append_chio_receipt_returning_seq(self, receipt)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
        tx.commit()?;
        Ok(Some(seq))
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        SqliteReceiptStore::receipts_canonical_bytes_range(self, start_seq, end_seq)
    }

    fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;

        chio_kernel::checkpoint::validate_checkpoint(checkpoint)
            .map_err(checkpoint_error_to_receipt_store)?;
        if let Some(existing) =
            load_persisted_checkpoint_row(&connection, checkpoint.body.checkpoint_seq)?
        {
            let existing = parse_persisted_checkpoint_row(existing)?;
            if existing == *checkpoint {
                return Ok(());
            }
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} already exists with different content",
                checkpoint.body.checkpoint_seq
            )));
        }

        match verify_checkpoint_chain_integrity(&connection)? {
            Some(predecessor) => {
                if checkpoint.body.checkpoint_seq <= predecessor.body.checkpoint_seq {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "checkpoint {} must be appended after existing checkpoint {}",
                        checkpoint.body.checkpoint_seq, predecessor.body.checkpoint_seq
                    )));
                }
                chio_kernel::checkpoint::validate_checkpoint_predecessor(&predecessor, checkpoint)
                    .map_err(|error| {
                        ReceiptStoreError::Conflict(format!(
                            "checkpoint predecessor continuity violation: {error}"
                        ))
                    })?;
            }
            None if checkpoint.body.checkpoint_seq != 1 => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} cannot initialize an empty checkpoint log",
                    checkpoint.body.checkpoint_seq
                )));
            }
            None => {}
        }

        let statement_json = serde_json::to_string(&checkpoint.body)?;
        connection
            .execute(
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
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!("checkpoint append conflict: {error}"))
            })?;

        let stored = load_persisted_checkpoint_row(&connection, checkpoint.body.checkpoint_seq)?
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "checkpoint {} was not visible after persistence",
                    checkpoint.body.checkpoint_seq
                ))
            })?;
        let stored = parse_persisted_checkpoint_row(stored)?;
        if stored != *checkpoint {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} persisted with conflicting contents",
                checkpoint.body.checkpoint_seq
            )));
        }

        Ok(())
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        SqliteReceiptStore::load_checkpoint_by_seq(self, checkpoint_seq)
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_checkpoint_chain_integrity(&connection)?;
        load_latest_persisted_checkpoint_row(&connection)?
            .map(parse_persisted_checkpoint_row)
            .transpose()
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot(self, token, parent_capability_id).map_err(
            |error| match error {
                chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                chio_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            },
        )
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        SqliteReceiptStore::get_lineage(self, capability_id).map_err(|error| match error {
            chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
            chio_kernel::CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
            chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
        })
    }

    fn get_capability_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        SqliteReceiptStore::get_delegation_chain(self, capability_id).map_err(|error| match error {
            chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
            chio_kernel::CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
            chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
        })
    }

    fn record_session_anchor(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_session_anchor_record(
            session_id,
            anchor_id,
            auth_context_fingerprint,
            issued_at,
            supersedes_anchor_id,
            anchor_json,
        )
    }

    fn record_request_lineage(
        &self,
        session_id: &str,
        request_id: &str,
        parent_request_id: Option<&str>,
        session_anchor_id: Option<&str>,
        recorded_at: u64,
        request_fingerprint: Option<&str>,
        lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_request_lineage_record(
            session_id,
            request_id,
            parent_request_id,
            session_anchor_id,
            recorded_at,
            request_fingerprint,
            lineage_json,
        )
    }

    fn record_receipt_lineage_statement(
        &self,
        child_receipt_id: &str,
        request_id: Option<&str>,
        session_id: Option<&str>,
        session_anchor_id: Option<&str>,
        parent_request_id: Option<&str>,
        parent_receipt_id: Option<&str>,
        chain_id: Option<&str>,
        recorded_at: u64,
        statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_receipt_lineage_statement_record(
            child_receipt_id,
            request_id,
            session_id,
            session_anchor_id,
            parent_request_id,
            parent_receipt_id,
            chain_id,
            recorded_at,
            statement_json,
        )
    }

    fn get_receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        self.receipt_lineage_verification(receipt_id)
    }

    fn list_receipt_lineage_statement_links(
        &self,
        receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        SqliteReceiptStore::list_receipt_lineage_statement_links(self, receipt_id)
    }

    fn as_any_mut(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.query_credit_bonds(&CreditBondListQuery {
            bond_id: Some(bond_id.to_string()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(1),
        })
        .map(|report| report.bonds.into_iter().next())
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        SqliteReceiptStore::append_child_receipt_record(self, receipt).map(|_| ())
    }

    fn append_child_receipt_returning_seq(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        SqliteReceiptStore::append_child_receipt_record(self, receipt).map(Some)
    }
}

impl SqliteReceiptStore {
    pub fn record_checkpoint_publication_trust_anchor_binding(
        &mut self,
        checkpoint_seq: u64,
        binding: &chio_core::receipt::CheckpointPublicationTrustAnchorBinding,
    ) -> Result<(), ReceiptStoreError> {
        binding
            .validate()
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let checkpoint = self
            .load_checkpoint_by_seq(checkpoint_seq)?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "checkpoint {} does not exist for publication binding",
                    checkpoint_seq
                ))
            })?;
        let publication = chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(
            &checkpoint,
            binding.clone(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        let normalized_binding = publication.trust_anchor_binding.ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "checkpoint {} trust-anchor binding was not preserved during validation",
                checkpoint_seq
            ))
        })?;

        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        ensure_transparency_projection_guards(&connection)?;

        let existing = connection
            .query_row(
                r#"
                SELECT binding_json
                FROM checkpoint_publication_trust_anchor_bindings
                WHERE checkpoint_seq = ?1
                "#,
                params![sqlite_i64(checkpoint_seq, "checkpoint_seq")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match existing {
            Some(binding_json) => {
                let existing_binding: chio_core::receipt::CheckpointPublicationTrustAnchorBinding =
                    serde_json::from_str(&binding_json)?;
                if existing_binding == normalized_binding {
                    return Ok(());
                }
                Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} already has a different trust-anchor publication binding",
                    checkpoint_seq
                )))
            }
            None => {
                connection.execute(
                    r#"
                    INSERT INTO checkpoint_publication_trust_anchor_bindings (
                        checkpoint_seq,
                        binding_json
                    ) VALUES (?1, ?2)
                    "#,
                    params![
                        sqlite_i64(checkpoint_seq, "checkpoint_seq")?,
                        serde_json::to_string(&normalized_binding)?,
                    ],
                )?;
                Ok(())
            }
        }
    }
}

pub(crate) fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

pub(crate) fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}
