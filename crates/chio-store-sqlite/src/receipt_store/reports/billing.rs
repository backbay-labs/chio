// Metered billing summary and evidence-record loading.

use super::*;

impl SqliteReceiptStore {
    pub(crate) fn query_metered_billing_summary(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<BehavioralFeedMeteredBillingSummary, ReceiptStoreError> {
        require_admin_receipt_read_context(query.read_context.as_ref(), "metered billing summary")?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(CASE WHEN mbr.receipt_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN mbr.receipt_id IS NULL THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedUnits') AS INTEGER)
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') IS NOT NULL
                         AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') AS INTEGER)
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND (
                            mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.currency')
                            OR mbr.billed_cost_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.units') AS INTEGER)
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND json_type(r.raw_json, '$.metadata.financial') = 'object'
                         AND (
                            mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.financial.currency')
                            OR mbr.billed_cost_units != CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER)
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(mbr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(mbr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                         AND (
                            mbr.receipt_id IS NULL
                            OR mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedUnits') AS INTEGER)
                            OR (
                                json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') IS NOT NULL
                                AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') AS INTEGER)
                            )
                            OR mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.currency')
                            OR mbr.billed_cost_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.units') AS INTEGER)
                            OR (
                                json_type(r.raw_json, '$.metadata.financial') = 'object'
                                AND (
                                    mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.financial.currency')
                                    OR mbr.billed_cost_units != CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER)
                                )
                            )
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0)
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
        "#;

        let (
            metered_receipts,
            evidence_attached_receipts,
            missing_evidence_receipts,
            over_quoted_units_receipts,
            over_max_billed_units_receipts,
            over_quoted_cost_receipts,
            financial_mismatch_receipts,
            reconciled_receipts,
            actionable_receipts,
        ) = self.connection()?.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                    row.get::<_, i64>(7)?.max(0) as u64,
                    row.get::<_, i64>(8)?.max(0) as u64,
                ))
            },
        )?;

        Ok(BehavioralFeedMeteredBillingSummary {
            metered_receipts,
            evidence_attached_receipts,
            missing_evidence_receipts,
            over_quoted_units_receipts,
            over_max_billed_units_receipts,
            over_quoted_cost_receipts,
            financial_mismatch_receipts,
            actionable_receipts,
            reconciled_receipts,
        })
    }

    pub(crate) fn load_metered_billing_evidence_record(
        &self,
        receipt_id: &str,
    ) -> Result<Option<MeteredBillingEvidenceRecord>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                r#"
                SELECT
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at
                FROM metered_billing_reconciliations
                WHERE receipt_id = ?1
                "#,
                params![receipt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at,
                )| {
                    Ok(MeteredBillingEvidenceRecord {
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
                },
            )
            .transpose()
    }
}
