use super::*;

pub(crate) fn backfill_claim_receipt_log_entries(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), ReceiptStoreError> {
    validate_or_backfill_claim_receipt_log_entries_in_transaction(transaction, true)
}

pub(crate) fn validate_claim_receipt_log_entries(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    validate_or_backfill_claim_receipt_log_entries(connection, false)
}

pub(crate) fn validate_or_backfill_claim_receipt_log_entries(
    connection: &Connection,
    repair_empty_projection: bool,
) -> Result<(), ReceiptStoreError> {
    // Every read below must observe the same database snapshot. Without a
    // shared transaction, each SELECT takes its own WAL snapshot, so a
    // writer that commits between the source-table scans and the
    // projection reads can make the projection appear to drift when it has
    // not (a spurious "set drift detected" conflict). A deferred
    // transaction pins the snapshot on its first read and keeps the
    // validator a reader (no write lock) unless the backfill branch below
    // actually inserts rows.
    let tx = connection.unchecked_transaction()?;
    validate_or_backfill_claim_receipt_log_entries_in_transaction(&tx, repair_empty_projection)?;
    tx.commit()?;
    Ok(())
}

fn validate_or_backfill_claim_receipt_log_entries_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    repair_empty_projection: bool,
) -> Result<(), ReceiptStoreError> {
    let mut expected = load_tool_claim_receipt_projection_rows(tx)?;
    expected.extend(load_child_claim_receipt_projection_rows(tx)?);
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

    let existing_count = tx.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let existing_count = sqlite_u64(existing_count, "claim_receipt_log_entries count")?;
    let expected_receipt_ids = expected
        .iter()
        .map(|row| row.receipt_id.clone())
        .collect::<BTreeSet<_>>();

    if existing_count == 0 {
        if !repair_empty_projection {
            if expected.is_empty() {
                return Ok(());
            }
            return Err(ReceiptStoreError::Conflict(
                "claim receipt log projection is missing for persisted receipt rows".to_string(),
            ));
        }
        // A fully archived store legitimately has BOTH empty source tables and
        // an empty projection: retention co-archived and deleted the entire
        // checkpointed prefix. There is nothing to regenerate, so the empty
        // expected + empty existing state is consistent and reopenable even
        // though a checkpoint or watermark exists. Returning here keeps a valid
        // full-prefix rotation followed by a restart from bricking the store on
        // the next writable open; the checkpointed-range refusal below is only
        // for the case where SOURCE rows survived and their entry_seq ordering
        // would have to be guessed against committed checkpoint boundaries.
        if expected.is_empty() {
            return Ok(());
        }
        // Fail-closed: only regenerate a never-checkpointed, never-archived
        // projection. Once a checkpoint has committed a batch_end_seq boundary
        // or an archival watermark exists, re-deriving entry_seq from surviving
        // source rows in (timestamp, kind_rank, source_seq, receipt_id) order
        // can assign fresh sequence numbers that no longer line up with the
        // checkpoint boundaries. Refuse instead of guessing.
        let watermark = retention_watermark(tx)?;
        if kernel_checkpoints_exist(tx)? || watermark.is_some() {
            return Err(ReceiptStoreError::ArchivedRangeProjection {
                watermark: watermark.unwrap_or(0),
            });
        }
        for row in &expected {
            insert_claim_receipt_log_projection_row(tx, row)?;
        }
        return Ok(());
    }

    for row in &expected {
        let Some(existing) = load_claim_receipt_log_projection_row(tx, &row.receipt_id)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` is missing for persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        };
        if !existing.matches_projection_or_enrichment(row) {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` diverges from persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        }
    }

    let existing_receipt_ids = load_claim_receipt_log_receipt_ids(tx)?;
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

    Ok(())
}
