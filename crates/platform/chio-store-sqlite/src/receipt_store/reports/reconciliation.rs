// Settlement and metered-billing reconciliation upserts and the metered-billing reconciliation report.

use super::*;

impl SqliteReceiptStore {
    pub fn upsert_settlement_reconciliation(
        &self,
        receipt_id: &str,
        reconciliation_state: SettlementReconciliationState,
        note: Option<&str>,
    ) -> Result<i64, ReceiptStoreError> {
        let exists = self
            .connection()?
            .query_row(
                "SELECT 1 FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "receipt {receipt_id} does not exist"
            )));
        }

        let updated_at = unix_timestamp_now_i64();
        let receipt_id_owned = receipt_id.to_string();
        let note_owned = note.map(ToString::to_string);
        self.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO settlement_reconciliations (
                    receipt_id,
                    reconciliation_state,
                    note,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(receipt_id) DO UPDATE SET
                    reconciliation_state = excluded.reconciliation_state,
                    note = excluded.note,
                    updated_at = excluded.updated_at
                "#,
                params![
                    receipt_id_owned,
                    settlement_reconciliation_state_text(reconciliation_state),
                    note_owned,
                    updated_at
                ],
            )?;
            Ok(())
        })?;

        Ok(updated_at)
    }

    pub fn upsert_metered_billing_reconciliation(
        &self,
        receipt_id: &str,
        evidence: &MeteredBillingEvidenceRecord,
        reconciliation_state: MeteredBillingReconciliationState,
        note: Option<&str>,
    ) -> Result<i64, ReceiptStoreError> {
        let (seq, raw_json) = self
            .connection()?
            .query_row(
                "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!("receipt {receipt_id} does not exist"))
            })?;
        let receipt = decode_verified_chio_receipt(
            &raw_json,
            "persisted tool receipt",
            Some(seq.max(0) as u64),
        )?;
        let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "receipt {receipt_id} does not carry governed transaction metadata"
            ))
        })?;
        if governed.metered_billing.is_none() {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt {receipt_id} does not carry metered billing context"
            )));
        }

        let existing_receipt = self
            .connection()?
            .query_row(
                r#"
                SELECT receipt_id
                FROM metered_billing_reconciliations
                WHERE adapter_kind = ?1 AND evidence_id = ?2
                "#,
                params![
                    &evidence.usage_evidence.evidence_kind,
                    &evidence.usage_evidence.evidence_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_receipt) = existing_receipt {
            if existing_receipt != receipt_id {
                return Err(ReceiptStoreError::Conflict(format!(
                    "metered billing evidence {}/{} is already attached to receipt {}",
                    evidence.usage_evidence.evidence_kind,
                    evidence.usage_evidence.evidence_id,
                    existing_receipt
                )));
            }
        }

        let updated_at = unix_timestamp_now_i64();
        let receipt_id_owned = receipt_id.to_string();
        let evidence_owned = evidence.clone();
        let note_owned = note.map(ToString::to_string);
        self.writer_handle().run_write(move |connection| {
            let evidence = &evidence_owned;
            connection.execute(
                r#"
                INSERT INTO metered_billing_reconciliations (
                    receipt_id,
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at,
                    reconciliation_state,
                    note,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(receipt_id) DO UPDATE SET
                    adapter_kind = excluded.adapter_kind,
                    evidence_id = excluded.evidence_id,
                    observed_units = excluded.observed_units,
                    billed_cost_units = excluded.billed_cost_units,
                    billed_cost_currency = excluded.billed_cost_currency,
                    evidence_sha256 = excluded.evidence_sha256,
                    recorded_at = excluded.recorded_at,
                    reconciliation_state = excluded.reconciliation_state,
                    note = excluded.note,
                    updated_at = excluded.updated_at
                "#,
                params![
                    receipt_id_owned,
                    &evidence.usage_evidence.evidence_kind,
                    &evidence.usage_evidence.evidence_id,
                    evidence.usage_evidence.observed_units as i64,
                    evidence.billed_cost.units as i64,
                    &evidence.billed_cost.currency,
                    evidence.usage_evidence.evidence_sha256.as_deref(),
                    evidence.recorded_at as i64,
                    metered_billing_reconciliation_state_text(reconciliation_state),
                    note_owned,
                    updated_at
                ],
            )?;
            Ok(())
        })?;

        Ok(updated_at)
    }

    pub fn query_metered_billing_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "metered billing reconciliation report",
        )?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.metered_limit_or_default();

        let summary = self.query_metered_billing_summary(query)?;

        let rows_sql = r#"
            SELECT
                r.seq,
                r.raw_json,
                COALESCE(r.subject_key, cl.subject_key),
                mbr.adapter_kind,
                mbr.evidence_id,
                mbr.observed_units,
                mbr.billed_cost_units,
                mbr.billed_cost_currency,
                mbr.evidence_sha256,
                mbr.recorded_at,
                COALESCE(mbr.reconciliation_state, 'open'),
                mbr.note,
                mbr.updated_at
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN metered_billing_reconciliations mbr ON r.receipt_id = mbr.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
            LIMIT ?7
        "#;

        let connection = self.connection()?;
        let mut stmt = connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject,
                row_limit as i64
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (
                seq,
                raw_json,
                subject_key,
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
                reconciliation_state_text,
                note,
                updated_at,
            ) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing governed transaction metadata",
                    receipt.id
                ))
            })?;
            let metered = governed.metered_billing.ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing metered billing metadata",
                    receipt.id
                ))
            })?;
            let financial = extract_financial_metadata(&receipt);
            let evidence = metered_billing_evidence_record_from_columns(
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
            );
            let reconciliation_state =
                parse_metered_billing_reconciliation_state(&reconciliation_state_text)?;
            let analysis = analyze_metered_billing_reconciliation(
                &metered,
                financial.as_ref(),
                evidence.as_ref(),
                reconciliation_state,
            );
            let budget_authority = receipt.financial_budget_authority_metadata();

            receipts.push(MeteredBillingReconciliationRow {
                receipt_id: receipt.id,
                timestamp: receipt.timestamp,
                capability_id: receipt.capability_id,
                subject_key,
                tool_server: receipt.tool_server,
                tool_name: receipt.tool_name,
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
                financial_cost_charged: financial.as_ref().map(|value| value.cost_charged),
                financial_currency: financial.as_ref().map(|value| value.currency.clone()),
                budget_authority,
                evidence,
                reconciliation_state,
                action_required: analysis.action_required,
                evidence_missing: analysis.evidence_missing,
                exceeds_quoted_units: analysis.exceeds_quoted_units,
                exceeds_max_billed_units: analysis.exceeds_max_billed_units,
                exceeds_quoted_cost: analysis.exceeds_quoted_cost,
                financial_mismatch: analysis.financial_mismatch,
                note,
                updated_at: updated_at.map(|value| value.max(0) as u64),
            });
        }

        Ok(MeteredBillingReconciliationReport {
            summary: MeteredBillingReconciliationSummary {
                matching_receipts: summary.metered_receipts,
                returned_receipts: receipts.len() as u64,
                evidence_attached_receipts: summary.evidence_attached_receipts,
                missing_evidence_receipts: summary.missing_evidence_receipts,
                over_quoted_units_receipts: summary.over_quoted_units_receipts,
                over_max_billed_units_receipts: summary.over_max_billed_units_receipts,
                over_quoted_cost_receipts: summary.over_quoted_cost_receipts,
                financial_mismatch_receipts: summary.financial_mismatch_receipts,
                actionable_receipts: summary.actionable_receipts,
                reconciled_receipts: summary.reconciled_receipts,
                truncated: summary.metered_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }
}
