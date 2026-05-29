// Behavioral feed receipt queries and the credit-loss receipt selection.

use super::*;

impl SqliteReceiptStore {
    pub fn query_behavioral_feed_receipts(
        &self,
        query: &BehavioralFeedQuery,
    ) -> Result<
        (
            BehavioralFeedSettlementSummary,
            BehavioralFeedGovernedActionSummary,
            BehavioralFeedMeteredBillingSummary,
            BehavioralFeedReceiptSelection,
        ),
        ReceiptStoreError,
    > {
        require_admin_receipt_read_context(query.read_context.as_ref(), "behavioral feed report")?;
        let operator_query = query.to_operator_report_query();
        let capability_id = operator_query.capability_id.as_deref();
        let tool_server = operator_query.tool_server.as_deref();
        let tool_name = operator_query.tool_name.as_deref();
        let since = operator_query.since.map(|value| value as i64);
        let until = operator_query.until.map(|value| value as i64);
        let agent_subject = operator_query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'settled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'not_applicable' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                         AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.approval') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.governed_transaction.approval.approved') = 1 THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.commerce') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.max_amount') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (settlements, governed_actions) = self.connection()?.query_row(
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
                    BehavioralFeedSettlementSummary {
                        pending_receipts: row.get::<_, i64>(0)?.max(0) as u64,
                        settled_receipts: row.get::<_, i64>(1)?.max(0) as u64,
                        failed_receipts: row.get::<_, i64>(2)?.max(0) as u64,
                        not_applicable_receipts: row.get::<_, i64>(3)?.max(0) as u64,
                        actionable_receipts: row.get::<_, i64>(4)?.max(0) as u64,
                        reconciled_receipts: row.get::<_, i64>(5)?.max(0) as u64,
                    },
                    BehavioralFeedGovernedActionSummary {
                        governed_receipts: row.get::<_, i64>(6)?.max(0) as u64,
                        approval_receipts: row.get::<_, i64>(7)?.max(0) as u64,
                        approved_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                        commerce_receipts: row.get::<_, i64>(9)?.max(0) as u64,
                        max_amount_receipts: row.get::<_, i64>(10)?.max(0) as u64,
                    },
                ))
            },
        )?;
        let metered_billing = self.query_metered_billing_summary(&operator_query)?;

        let row_limit = query.receipt_limit_or_default();
        let count_sql = r#"
            SELECT COUNT(*)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;
        let matching_receipts = self
            .connection()?
            .query_row(
                count_sql,
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;

        let rows_sql = r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
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
                row_limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut receipts = Vec::with_capacity(row_limit);
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            receipts.push(self.behavioral_feed_receipt_row_from_receipt(receipt)?);
        }

        Ok((
            settlements,
            governed_actions,
            metered_billing,
            BehavioralFeedReceiptSelection {
                matching_receipts,
                receipts,
            },
        ))
    }

    pub fn query_recent_credit_loss_receipts(
        &self,
        query: &BehavioralFeedQuery,
        limit: usize,
    ) -> Result<(u64, Vec<BehavioralFeedReceiptRow>), ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "recent credit loss receipts",
        )?;
        let operator_query = query.to_operator_report_query();
        let capability_id = operator_query.capability_id.as_deref();
        let tool_server = operator_query.tool_server.as_deref();
        let tool_name = operator_query.tool_name.as_deref();
        let since = operator_query.since.map(|value| value as i64);
        let until = operator_query.until.map(|value| value as i64);
        let agent_subject = operator_query.agent_subject.as_deref();
        let row_limit = limit.max(1);

        let count_sql = r#"
            SELECT COUNT(*)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND (
                    COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed'
                    OR (
                        COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                        AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                    )
              )
        "#;

        let matching_loss_events = self
            .connection()?
            .query_row(
                count_sql,
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;

        let rows_sql = r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND (
                    COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed'
                    OR (
                        COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                        AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                    )
              )
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
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            receipts.push(self.behavioral_feed_receipt_row_from_receipt(receipt)?);
        }

        Ok((matching_loss_events, receipts))
    }

    pub(crate) fn behavioral_feed_receipt_row_from_receipt(
        &self,
        receipt: ChioReceipt,
    ) -> Result<BehavioralFeedReceiptRow, ReceiptStoreError> {
        let attribution = extract_receipt_attribution(&receipt);
        let lineage = if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
            self.get_combined_lineage(&receipt.capability_id)?
        } else {
            None
        };
        let financial = extract_financial_metadata(&receipt);
        let governed = extract_governed_transaction_metadata(&receipt);
        let governed_projection = governed
            .as_ref()
            .map(|metadata| sanitize_governed_transaction_projection(&receipt, metadata));
        let metered_reconciliation = governed
            .as_ref()
            .and_then(|metadata| metadata.metered_billing.as_ref())
            .map(|metered| {
                let evidence = self.load_metered_billing_evidence_record(&receipt.id)?;
                let reconciliation_state = self
                    .connection()?
                    .query_row(
                        r#"
                        SELECT COALESCE(reconciliation_state, 'open')
                        FROM metered_billing_reconciliations
                        WHERE receipt_id = ?1
                        "#,
                        params![&receipt.id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .map(|value| parse_metered_billing_reconciliation_state(&value))
                    .transpose()?
                    .unwrap_or(MeteredBillingReconciliationState::Open);
                let analysis = analyze_metered_billing_reconciliation(
                    metered,
                    financial.as_ref(),
                    evidence.as_ref(),
                    reconciliation_state,
                );
                Ok::<BehavioralFeedMeteredBillingRow, ReceiptStoreError>(
                    BehavioralFeedMeteredBillingRow {
                        reconciliation_state,
                        action_required: analysis.action_required,
                        evidence_missing: analysis.evidence_missing,
                        exceeds_quoted_units: analysis.exceeds_quoted_units,
                        exceeds_max_billed_units: analysis.exceeds_max_billed_units,
                        exceeds_quoted_cost: analysis.exceeds_quoted_cost,
                        financial_mismatch: analysis.financial_mismatch,
                        evidence,
                    },
                )
            })
            .transpose()?;
        let settlement_status = financial
            .as_ref()
            .map(|metadata| metadata.settlement_status.clone())
            .unwrap_or(SettlementStatus::NotApplicable);
        let reconciliation_state = self
            .connection()?
            .query_row(
                r#"
                SELECT COALESCE(reconciliation_state, 'open')
                FROM settlement_reconciliations
                WHERE receipt_id = ?1
                "#,
                params![receipt.id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| parse_settlement_reconciliation_state(&value))
            .transpose()?
            .unwrap_or(SettlementReconciliationState::Open);
        let action_required = settlement_reconciliation_action_required(
            settlement_status.clone(),
            reconciliation_state,
        );
        let budget_authority = receipt.financial_budget_authority_metadata();
        let authorized = receipt.is_allowed()
            && receipt.verify_signature().unwrap_or(false)
            && receipt.action.verify_hash().unwrap_or(false);

        Ok(BehavioralFeedReceiptRow {
            receipt_id: receipt.id,
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            subject_key: attribution.subject_key.or_else(|| {
                lineage
                    .as_ref()
                    .map(|snapshot| snapshot.subject_key.clone())
            }),
            issuer_key: attribution
                .issuer_key
                .or_else(|| lineage.as_ref().map(|snapshot| snapshot.issuer_key.clone())),
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            decision: receipt.decision,
            authorized,
            settlement_status,
            reconciliation_state,
            action_required,
            cost_charged: financial.as_ref().map(|metadata| metadata.cost_charged),
            attempted_cost: financial
                .as_ref()
                .and_then(|metadata| metadata.attempted_cost),
            currency: financial.as_ref().map(|metadata| metadata.currency.clone()),
            budget_authority,
            governed: governed_projection
                .as_ref()
                .map(|projection| projection.strong.clone()),
            governed_transaction_diagnostics: governed_projection
                .and_then(|projection| projection.diagnostics),
            metered_reconciliation,
        })
    }
}
