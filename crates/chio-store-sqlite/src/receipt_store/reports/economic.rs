// Economic receipt projection and completion-flow report queries.

use super::*;

impl SqliteReceiptStore {
    pub fn query_economic_receipt_projection_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<EconomicReceiptProjectionReport, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "economic receipt projection report",
        )?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.economic_limit_or_default();

        let matching_receipts = self.connection()?.query_row(
            r#"
            SELECT COUNT(*)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction.economic_authorization') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            "#,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| row.get::<_, i64>(0),
        )?
        .max(0) as u64;

        let rows_sql = r#"
            SELECT
                r.seq,
                r.receipt_id,
                r.timestamp,
                r.capability_id,
                COALESCE(r.subject_key, cl.subject_key),
                r.tool_server,
                r.tool_name,
                COALESCE(sr.reconciliation_state, 'open'),
                sr.note,
                sr.updated_at,
                COALESCE(mbr.reconciliation_state, 'open'),
                mbr.note,
                mbr.updated_at,
                mbr.adapter_kind,
                mbr.evidence_id,
                mbr.observed_units,
                mbr.billed_cost_units,
                mbr.billed_cost_currency,
                mbr.evidence_sha256,
                mbr.recorded_at,
                r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            LEFT JOIN metered_billing_reconciliations mbr ON r.receipt_id = mbr.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction.economic_authorization') = 'object'
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
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                    row.get::<_, Option<i64>>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, Option<i64>>(19)?,
                    row.get::<_, String>(20)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        let mut metered_receipts = 0_u64;
        let mut pending_settlement_receipts = 0_u64;
        let mut failed_settlement_receipts = 0_u64;
        let mut settlement_actionable_receipts = 0_u64;
        let mut metering_actionable_receipts = 0_u64;
        let mut metering_evidence_missing_receipts = 0_u64;
        let mut metering_financial_mismatch_receipts = 0_u64;

        for row in rows {
            let (
                seq,
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                settlement_reconciliation_state_text,
                settlement_note,
                settlement_updated_at,
                metering_reconciliation_state_text,
                metering_note,
                metering_updated_at,
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
                raw_json,
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
            let economic_authorization = governed
                .economic_authorization
                .clone()
                .or_else(|| extract_economic_authorization_metadata(&receipt))
                .ok_or_else(|| {
                    ReceiptStoreError::Canonical(format!(
                        "receipt {} is missing economic authorization metadata",
                        receipt.id
                    ))
                })?;
            let financial = extract_financial_metadata(&receipt);
            let settlement_reconciliation_state =
                parse_settlement_reconciliation_state(&settlement_reconciliation_state_text)?;
            let settlement = EconomicReceiptSettlementProjection {
                settlement_status: economic_authorization.settlement.settlement_status.clone(),
                reconciliation_state: settlement_reconciliation_state,
                action_required: settlement_reconciliation_action_required(
                    economic_authorization.settlement.settlement_status.clone(),
                    settlement_reconciliation_state,
                ),
                note: settlement_note,
                updated_at: settlement_updated_at.map(|value| value.max(0) as u64),
            };
            if settlement.settlement_status == SettlementStatus::Pending {
                pending_settlement_receipts = pending_settlement_receipts.saturating_add(1);
            }
            if settlement.settlement_status == SettlementStatus::Failed {
                failed_settlement_receipts = failed_settlement_receipts.saturating_add(1);
            }
            if settlement.action_required {
                settlement_actionable_receipts = settlement_actionable_receipts.saturating_add(1);
            }

            let metering = if economic_authorization.metering.is_some() {
                metered_receipts = metered_receipts.saturating_add(1);
                let governed_metering = governed.metered_billing.as_ref().ok_or_else(|| {
                    ReceiptStoreError::Canonical(format!(
                        "receipt {} has economic metering metadata without governed metered billing context",
                        receipt.id
                    ))
                })?;
                let evidence = metered_billing_evidence_record_from_columns(
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at,
                );
                let reconciliation_state = parse_metered_billing_reconciliation_state(
                    &metering_reconciliation_state_text,
                )?;
                let analysis = analyze_metered_billing_reconciliation(
                    governed_metering,
                    financial.as_ref(),
                    evidence.as_ref(),
                    reconciliation_state,
                );
                if analysis.action_required {
                    metering_actionable_receipts = metering_actionable_receipts.saturating_add(1);
                }
                if analysis.evidence_missing {
                    metering_evidence_missing_receipts =
                        metering_evidence_missing_receipts.saturating_add(1);
                }
                if analysis.financial_mismatch {
                    metering_financial_mismatch_receipts =
                        metering_financial_mismatch_receipts.saturating_add(1);
                }
                Some(EconomicReceiptMeteringProjection {
                    reconciliation_state,
                    action_required: analysis.action_required,
                    evidence_missing: analysis.evidence_missing,
                    exceeds_quoted_units: analysis.exceeds_quoted_units,
                    exceeds_max_billed_units: analysis.exceeds_max_billed_units,
                    exceeds_quoted_cost: analysis.exceeds_quoted_cost,
                    financial_mismatch: analysis.financial_mismatch,
                    evidence,
                    note: metering_note,
                    updated_at: metering_updated_at.map(|value| value.max(0) as u64),
                })
            } else {
                None
            };

            receipts.push(EconomicReceiptProjectionRow {
                receipt_id,
                timestamp: timestamp.max(0) as u64,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                economic_authorization,
                budget_authority: receipt.financial_budget_authority_metadata(),
                settlement,
                metering,
            });
        }

        Ok(EconomicReceiptProjectionReport {
            summary: EconomicReceiptProjectionSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                metered_receipts,
                pending_settlement_receipts,
                failed_settlement_receipts,
                settlement_actionable_receipts,
                metering_actionable_receipts,
                metering_evidence_missing_receipts,
                metering_financial_mismatch_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn query_economic_completion_flow_report(
        &self,
        query: &ExposureLedgerQuery,
        read_context: ReceiptReadContext,
    ) -> Result<EconomicCompletionFlowReport, ReceiptStoreError> {
        let normalized = query.normalized();
        if let Err(message) = normalized.validate() {
            return Err(ReceiptStoreError::Conflict(message));
        }

        let economic_receipts =
            self.query_economic_receipt_projection_report(&OperatorReportQuery {
                capability_id: normalized.capability_id.clone(),
                agent_subject: normalized.agent_subject.clone(),
                tool_server: normalized.tool_server.clone(),
                tool_name: normalized.tool_name.clone(),
                since: normalized.since,
                until: normalized.until,
                economic_limit: normalized.receipt_limit,
                read_context: Some(read_context),
                ..OperatorReportQuery::default()
            })?;
        let underwriting_decisions =
            self.query_underwriting_decisions(&UnderwritingDecisionQuery {
                decision_id: None,
                capability_id: normalized.capability_id.clone(),
                agent_subject: normalized.agent_subject.clone(),
                tool_server: normalized.tool_server.clone(),
                tool_name: normalized.tool_name.clone(),
                outcome: None,
                lifecycle_state: None,
                appeal_status: None,
                limit: normalized.decision_limit,
            })?;
        let credit_facilities = self.query_credit_facilities(&CreditFacilityListQuery {
            facility_id: None,
            capability_id: normalized.capability_id.clone(),
            agent_subject: normalized.agent_subject.clone(),
            tool_server: normalized.tool_server.clone(),
            tool_name: normalized.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: normalized.decision_limit,
        })?;
        let credit_bonds = self.query_credit_bonds(&CreditBondListQuery {
            bond_id: None,
            facility_id: None,
            capability_id: normalized.capability_id.clone(),
            agent_subject: normalized.agent_subject.clone(),
            tool_server: normalized.tool_server.clone(),
            tool_name: normalized.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: normalized.decision_limit,
        })?;

        let latest_underwriting = underwriting_decisions
            .decisions
            .iter()
            .find(|row| row.lifecycle_state == UnderwritingDecisionLifecycleState::Active)
            .or_else(|| underwriting_decisions.decisions.first());
        let latest_credit_facility = credit_facilities
            .facilities
            .iter()
            .find(|row| row.lifecycle_state == CreditFacilityLifecycleState::Active)
            .or_else(|| credit_facilities.facilities.first());
        let latest_credit_bond = credit_bonds
            .bonds
            .iter()
            .find(|row| row.lifecycle_state == CreditBondLifecycleState::Active)
            .or_else(|| credit_bonds.bonds.first());

        Ok(EconomicCompletionFlowReport {
            schema: ECONOMIC_COMPLETION_FLOW_SCHEMA.to_string(),
            generated_at: unix_now(),
            filters: normalized,
            summary: EconomicCompletionFlowSummary {
                matching_receipts: economic_receipts.summary.matching_receipts,
                returned_receipts: economic_receipts.summary.returned_receipts,
                matching_underwriting_decisions: underwriting_decisions.summary.matching_decisions,
                returned_underwriting_decisions: underwriting_decisions.summary.returned_decisions,
                matching_credit_facilities: credit_facilities.summary.matching_facilities,
                returned_credit_facilities: credit_facilities.summary.returned_facilities,
                matching_credit_bonds: credit_bonds.summary.matching_bonds,
                returned_credit_bonds: credit_bonds.summary.returned_bonds,
                pending_settlement_receipts: economic_receipts.summary.pending_settlement_receipts,
                failed_settlement_receipts: economic_receipts.summary.failed_settlement_receipts,
                metering_actionable_receipts: economic_receipts
                    .summary
                    .metering_actionable_receipts,
                latest_underwriting_decision_id: latest_underwriting
                    .map(|row| row.decision.body.decision_id.clone()),
                latest_underwriting_outcome: latest_underwriting
                    .map(|row| row.decision.body.evaluation.outcome),
                latest_credit_facility_id: latest_credit_facility
                    .map(|row| row.facility.body.facility_id.clone()),
                latest_credit_facility_disposition: latest_credit_facility
                    .map(|row| row.facility.body.report.disposition),
                latest_credit_bond_id: latest_credit_bond.map(|row| row.bond.body.bond_id.clone()),
                latest_credit_bond_disposition: latest_credit_bond
                    .map(|row| row.bond.body.report.disposition),
            },
            economic_receipts,
            underwriting_decisions,
            credit_facilities,
            credit_bonds,
        })
    }
}
