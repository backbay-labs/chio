use super::*;

pub(crate) const SESSION_ANCHOR_SOURCE_KIND: &str = "session_anchor";
pub(crate) const REQUEST_LINEAGE_SOURCE_KIND: &str = "request_lineage_record";
pub(crate) const RECEIPT_LINEAGE_SOURCE_KIND: &str = "receipt_lineage_statement";
pub(crate) const CHILD_RECEIPT_BACKFILL_SOURCE_KIND: &str = "child_receipt_backfill";
const GOVERNED_RECEIPT_BACKFILL_SOURCE_KIND: &str = "governed_receipt_backfill";

fn provenance_json_sha256(value: &serde_json::Value) -> Result<String, ReceiptStoreError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

fn validate_request_lineage_schema(
    lineage_json: &serde_json::Value,
) -> Result<(), ReceiptStoreError> {
    let record: chio_core::session::RequestLineageRecord =
        serde_json::from_value(lineage_json.clone())?;
    record
        .validate_schema()
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))
}

pub(crate) fn child_receipt_request_lineage_json(
    receipt: &ChildRequestReceipt,
) -> Result<serde_json::Value, ReceiptStoreError> {
    let body_hash = canonical_json_bytes(&receipt.body())
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let anchor = SessionAnchorReference::new(
        format!("child-receipt-backfill:{}", receipt.session_id.as_str()),
        body_hash,
    );
    let lineage = RequestLineageRecord::new(
        receipt.request_id.clone(),
        anchor,
        receipt.operation_kind,
        RequestLineageMode::LocalChild,
        receipt.timestamp,
    )
    .with_parent_request_id(receipt.parent_request_id.clone());

    Ok(serde_json::to_value(lineage)?)
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
    if schema != Some(chio_core::receipt::lineage::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA) {
        return ReceiptLineageStatementIdentifiers::default();
    }

    if let Ok(statement) = serde_json::from_value::<
        chio_core::receipt::lineage::ReceiptLineageStatement,
    >(statement_json.clone())
    {
        return ReceiptLineageStatementIdentifiers {
            statement_id: Some(statement.id),
            child_receipt_id: Some(statement.child_receipt_id),
            child_request_id: Some(statement.child_request_id.to_string()),
            child_session_anchor_id: Some(statement.child_session_anchor.session_anchor_id),
            parent_request_id: Some(statement.parent_request_id.to_string()),
            parent_receipt_id: Some(statement.parent_receipt_id),
        };
    }

    if let Ok(statement) = serde_json::from_value::<
        chio_core::receipt::lineage::ReceiptLineageStatementBody,
    >(statement_json.clone())
    {
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

pub(crate) fn refresh_receipt_lineage_rows_for_parent_receipt_tx(
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
pub(crate) fn persist_session_anchor_tx(
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
pub(crate) fn persist_request_lineage_tx(
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

    validate_request_lineage_schema(lineage_json)?;
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
pub(crate) fn persist_receipt_lineage_statement_tx(
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

pub(crate) fn ensure_receipt_lineage_statement_for_receipt_id_tx(
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

pub(crate) fn load_receipt_lineage_verification(
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

pub(crate) fn load_receipt_lineage_statement_links(
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
    tx: &rusqlite::Transaction<'_>,
) -> Result<(), ReceiptStoreError> {
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
            tx,
            receipt.session_id.as_str(),
            receipt.request_id.as_str(),
            Some(receipt.parent_request_id.as_str()),
            None,
            receipt.timestamp,
            None,
            CHILD_RECEIPT_BACKFILL_SOURCE_KIND,
            &child_receipt_request_lineage_json(&receipt)?,
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
        ensure_receipt_lineage_statement_for_receipt_id_tx(tx, &receipt_id)?;
    }

    Ok(())
}
