// Compliance report query.

use super::*;

impl SqliteReceiptStore {
    pub fn query_compliance_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ComplianceReport, ReceiptStoreError> {
        require_admin_receipt_read_context(query.read_context.as_ref(), "compliance report")?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN EXISTS(
                            SELECT 1
                            FROM kernel_checkpoints kc
                            WHERE r.seq BETWEEN kc.batch_start_seq AND kc.batch_end_seq
                        ) THEN 1
                        ELSE 0
                    END
                ), 0) AS evidence_ready_receipts,
                COALESCE(SUM(CASE WHEN cl.capability_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS lineage_covered_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_settlement_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_settlement_receipts
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            evidence_ready_receipts,
            lineage_covered_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
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
                ))
            },
        )?;

        let uncheckpointed_receipts = matching_receipts.saturating_sub(evidence_ready_receipts);
        let lineage_gap_receipts = matching_receipts.saturating_sub(lineage_covered_receipts);
        let export_query = query
            .to_evidence_export_query()
            .map_err(ReceiptStoreError::ReadBoundary)?;

        Ok(ComplianceReport {
            matching_receipts,
            evidence_ready_receipts,
            uncheckpointed_receipts,
            checkpoint_coverage_rate: ratio_option(evidence_ready_receipts, matching_receipts),
            lineage_covered_receipts,
            lineage_gap_receipts,
            lineage_coverage_rate: ratio_option(lineage_covered_receipts, matching_receipts),
            pending_settlement_receipts,
            failed_settlement_receipts,
            direct_evidence_export_supported: query.direct_evidence_export_supported(),
            child_receipt_scope: export_query.child_receipt_scope(),
            proofs_complete: uncheckpointed_receipts == 0,
            export_query: export_query.clone(),
            export_scope_note: compliance_export_scope_note(query, &export_query),
        })
    }
}
