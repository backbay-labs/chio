use super::*;

use chio_core::capability::GovernedProvenanceEvidenceClass;
use chio_kernel::evidence_export::EvidenceLineageReferences;
use chio_kernel::operator_report::GovernedTransactionDiagnostics;

#[derive(Debug, Clone)]
struct GovernedTransactionProjection {
    strong: GovernedTransactionReceiptMetadata,
    diagnostics: Option<GovernedTransactionDiagnostics>,
}

#[derive(Debug, Clone, Default)]
struct PersistedLineageReferences {
    statement_id: Option<String>,
    session_anchor_id: Option<String>,
}

fn extract_governed_transaction_diagnostics(
    receipt: &ChioReceipt,
) -> Option<GovernedTransactionDiagnostics> {
    let diagnostics = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction_diagnostics"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionDiagnostics>(value).ok())
        .unwrap_or_default();

    (!diagnostics.is_empty()).then_some(diagnostics)
}

fn sanitize_governed_transaction_projection(
    receipt: &ChioReceipt,
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedTransactionProjection {
    let mut strong = governed.clone();
    let mut diagnostics = extract_governed_transaction_diagnostics(receipt).unwrap_or_default();

    if let Some(call_chain) = strong
        .call_chain
        .clone()
        .filter(|call_chain| call_chain.evidence_class == GovernedProvenanceEvidenceClass::Asserted)
    {
        strong.call_chain = None;
        if diagnostics.asserted_call_chain.is_none() {
            diagnostics.asserted_call_chain = Some(call_chain);
        }
    }

    if diagnostics.lineage_references.session_anchor_id.is_none() {
        diagnostics.lineage_references.session_anchor_id = strong
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.session_anchor_id.clone())
            .or_else(|| {
                diagnostics
                    .asserted_call_chain
                    .as_ref()
                    .and_then(|call_chain| call_chain.session_anchor_id.clone())
            });
    }
    if diagnostics
        .lineage_references
        .receipt_lineage_statement_id
        .is_none()
    {
        diagnostics.lineage_references.receipt_lineage_statement_id = strong
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone())
            .or_else(|| {
                diagnostics
                    .asserted_call_chain
                    .as_ref()
                    .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone())
            });
    }

    GovernedTransactionProjection {
        strong,
        diagnostics: (!diagnostics.is_empty()).then_some(diagnostics),
    }
}

fn apply_persisted_lineage_references(
    projection: &mut GovernedTransactionProjection,
    persisted: &PersistedLineageReferences,
) {
    if persisted.statement_id.is_none() && persisted.session_anchor_id.is_none() {
        return;
    }

    if let Some(call_chain) = projection.strong.call_chain.as_mut() {
        if call_chain.session_anchor_id.is_none() {
            call_chain.session_anchor_id = persisted.session_anchor_id.clone();
        }
        if call_chain.receipt_lineage_statement_id.is_none() {
            call_chain.receipt_lineage_statement_id = persisted.statement_id.clone();
        }
    }

    let diagnostics = projection
        .diagnostics
        .get_or_insert_with(GovernedTransactionDiagnostics::default);
    if let Some(call_chain) = diagnostics.asserted_call_chain.as_mut() {
        if call_chain.session_anchor_id.is_none() {
            call_chain.session_anchor_id = persisted.session_anchor_id.clone();
        }
        if call_chain.receipt_lineage_statement_id.is_none() {
            call_chain.receipt_lineage_statement_id = persisted.statement_id.clone();
        }
    }
    if diagnostics.lineage_references.session_anchor_id.is_none() {
        diagnostics.lineage_references.session_anchor_id = persisted.session_anchor_id.clone();
    }
    if diagnostics
        .lineage_references
        .receipt_lineage_statement_id
        .is_none()
    {
        diagnostics.lineage_references.receipt_lineage_statement_id =
            persisted.statement_id.clone();
    }
    if diagnostics.is_empty() {
        projection.diagnostics = None;
    }
}

fn call_chain_evidence_class(
    projection: &GovernedTransactionProjection,
) -> Option<GovernedProvenanceEvidenceClass> {
    projection
        .strong
        .call_chain
        .as_ref()
        .map(|call_chain| call_chain.evidence_class)
        .or_else(|| {
            projection
                .diagnostics
                .as_ref()
                .and_then(|diagnostics| diagnostics.asserted_call_chain.as_ref())
                .map(|call_chain| call_chain.evidence_class)
        })
}

fn lineage_references_from_projection(
    projection: &GovernedTransactionProjection,
) -> Option<&EvidenceLineageReferences> {
    projection
        .diagnostics
        .as_ref()
        .map(|diagnostics| &diagnostics.lineage_references)
        .filter(|references| !references.is_empty())
}

fn authorization_transaction_context_from_projection(
    projection: &GovernedTransactionProjection,
) -> chio_kernel::operator_report::GovernedAuthorizationTransactionContext {
    let mut transaction_context =
        authorization_transaction_context_from_governed_metadata(&projection.strong);
    if transaction_context.call_chain.is_none() {
        transaction_context.call_chain = projection
            .diagnostics
            .as_ref()
            .and_then(|diagnostics| diagnostics.asserted_call_chain.clone());
    }
    transaction_context
}

impl SqliteReceiptStore {
    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        let group_limit = query
            .group_limit
            .unwrap_or(50)
            .clamp(1, MAX_ANALYTICS_GROUP_LIMIT);
        let time_bucket = query.time_bucket.unwrap_or(AnalyticsTimeBucket::Day);
        let bucket_width = time_bucket.width_secs() as i64;

        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;
        let summary = self.connection()?.query_row(
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
                Ok(ReceiptAnalyticsMetrics::from_raw(
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                ))
            },
        )?;

        let by_agent_sql = r#"
            SELECT
                COALESCE(r.subject_key, cl.subject_key) AS subject_key,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND COALESCE(r.subject_key, cl.subject_key) IS NOT NULL
            GROUP BY COALESCE(r.subject_key, cl.subject_key)
            ORDER BY total_receipts DESC, subject_key ASC
            LIMIT ?7
        "#;
        let by_agent = self
            .connection()?
            .prepare(by_agent_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(AgentAnalyticsRow {
                        subject_key: row.get(0)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_tool_sql = r#"
            SELECT
                r.tool_server,
                r.tool_name,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY r.tool_server, r.tool_name
            ORDER BY total_receipts DESC, r.tool_server ASC, r.tool_name ASC
            LIMIT ?7
        "#;
        let by_tool = self
            .connection()?
            .prepare(by_tool_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(ToolAnalyticsRow {
                        tool_server: row.get(0)?,
                        tool_name: row.get(1)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                            row.get::<_, i64>(8)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_time_sql = r#"
            SELECT
                CAST((r.timestamp / ?7) * ?7 AS INTEGER) AS bucket_start,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            LIMIT ?8
        "#;
        let by_time = self
            .connection()?
            .prepare(by_time_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    bucket_width,
                    group_limit as i64
                ],
                |row| {
                    let bucket_start = row.get::<_, i64>(0)?.max(0) as u64;
                    Ok(TimeAnalyticsRow {
                        bucket_start,
                        bucket_end: bucket_start
                            .saturating_add(bucket_width.max(1) as u64)
                            .saturating_sub(1),
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ReceiptAnalyticsResponse {
            summary,
            by_agent,
            by_tool,
            by_time,
        })
    }

    pub fn query_cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        let limit = query
            .limit
            .unwrap_or(100)
            .clamp(1, MAX_COST_ATTRIBUTION_LIMIT);
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

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
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
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

        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
            ORDER BY r.seq ASC
        "#;

        let rows = self
            .connection()?
            .prepare(data_sql)?
            .query_map(
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
                        row.get::<_, String>(1)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut receipts = Vec::with_capacity(rows.len().min(limit));
        let mut by_root = BTreeMap::<String, RootAggregate>::new();
        let mut by_leaf = BTreeMap::<(String, String), LeafAggregate>::new();
        let mut distinct_roots = BTreeSet::new();
        let mut distinct_leaves = BTreeSet::new();
        let mut total_cost_charged = 0_u64;
        let mut total_attempted_cost = 0_u64;
        let mut max_delegation_depth = 0_u64;
        let mut lineage_gap_count = 0_u64;

        for (seq, raw_json) in rows {
            let receipt =
                decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq))?;
            let Some(financial) = extract_financial_metadata(&receipt) else {
                continue;
            };
            let attribution = extract_receipt_attribution(&receipt);
            let chain_snapshots = self
                .get_combined_delegation_chain(&receipt.capability_id)
                .unwrap_or_default();
            let lineage_complete = chain_is_complete(&receipt.capability_id, &chain_snapshots);
            if !lineage_complete {
                lineage_gap_count = lineage_gap_count.saturating_add(1);
            }

            let chain = chain_snapshots
                .iter()
                .map(|snapshot| CostAttributionChainHop {
                    capability_id: snapshot.capability_id.clone(),
                    subject_key: snapshot.subject_key.clone(),
                    issuer_key: snapshot.issuer_key.clone(),
                    delegation_depth: snapshot.delegation_depth,
                    parent_capability_id: snapshot.parent_capability_id.clone(),
                })
                .collect::<Vec<_>>();

            let root_subject_key = chain_snapshots
                .first()
                .map(|snapshot| snapshot.subject_key.clone())
                .or_else(|| Some(financial.root_budget_holder.clone()));
            let leaf_subject_key = attribution.subject_key.clone().or_else(|| {
                chain_snapshots
                    .last()
                    .map(|snapshot| snapshot.subject_key.clone())
            });
            let attempted_cost = financial.attempted_cost.unwrap_or(0);
            let decision = receipt_decision_kind(&receipt).to_string();

            total_cost_charged = total_cost_charged.saturating_add(financial.cost_charged);
            total_attempted_cost = total_attempted_cost.saturating_add(attempted_cost);
            max_delegation_depth = max_delegation_depth.max(financial.delegation_depth as u64);

            if let Some(root_key) = root_subject_key.clone() {
                distinct_roots.insert(root_key.clone());
                let root_entry = by_root.entry(root_key.clone()).or_default();
                root_entry.receipt_count = root_entry.receipt_count.saturating_add(1);
                root_entry.total_cost_charged = root_entry
                    .total_cost_charged
                    .saturating_add(financial.cost_charged);
                root_entry.total_attempted_cost = root_entry
                    .total_attempted_cost
                    .saturating_add(attempted_cost);
                root_entry.max_delegation_depth = root_entry
                    .max_delegation_depth
                    .max(financial.delegation_depth as u64);

                if let Some(leaf_key) = leaf_subject_key.clone() {
                    root_entry.leaf_subjects.insert(leaf_key.clone());
                    let leaf_entry = by_leaf.entry((root_key, leaf_key)).or_default();
                    leaf_entry.receipt_count = leaf_entry.receipt_count.saturating_add(1);
                    leaf_entry.total_cost_charged = leaf_entry
                        .total_cost_charged
                        .saturating_add(financial.cost_charged);
                    leaf_entry.total_attempted_cost = leaf_entry
                        .total_attempted_cost
                        .saturating_add(attempted_cost);
                    leaf_entry.max_delegation_depth = leaf_entry
                        .max_delegation_depth
                        .max(financial.delegation_depth as u64);
                }
            }

            if let Some(leaf_key) = leaf_subject_key.clone() {
                distinct_leaves.insert(leaf_key);
            }

            if receipts.len() < limit {
                receipts.push(CostAttributionReceiptRow {
                    seq,
                    receipt_id: receipt.id.clone(),
                    timestamp: receipt.timestamp,
                    capability_id: receipt.capability_id.clone(),
                    tool_server: receipt.tool_server.clone(),
                    tool_name: receipt.tool_name.clone(),
                    decision_kind: decision,
                    root_subject_key,
                    leaf_subject_key,
                    grant_index: Some(financial.grant_index),
                    delegation_depth: financial.delegation_depth as u64,
                    cost_charged: financial.cost_charged,
                    attempted_cost: financial.attempted_cost,
                    currency: financial.currency.clone(),
                    budget_total: Some(financial.budget_total),
                    budget_remaining: Some(financial.budget_remaining),
                    settlement_status: Some(financial.settlement_status),
                    payment_reference: financial.payment_reference.clone(),
                    budget_authority: receipt.financial_budget_authority_metadata(),
                    lineage_complete,
                    chain,
                });
            }
        }

        let mut by_root = by_root
            .into_iter()
            .map(|(root_subject_key, aggregate)| RootCostAttributionRow {
                root_subject_key,
                receipt_count: aggregate.receipt_count,
                total_cost_charged: aggregate.total_cost_charged,
                total_attempted_cost: aggregate.total_attempted_cost,
                distinct_leaf_subjects: aggregate.leaf_subjects.len() as u64,
                max_delegation_depth: aggregate.max_delegation_depth,
            })
            .collect::<Vec<_>>();
        by_root.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
        });

        let mut by_leaf = by_leaf
            .into_iter()
            .map(
                |((root_subject_key, leaf_subject_key), aggregate)| LeafCostAttributionRow {
                    root_subject_key,
                    leaf_subject_key,
                    receipt_count: aggregate.receipt_count,
                    total_cost_charged: aggregate.total_cost_charged,
                    total_attempted_cost: aggregate.total_attempted_cost,
                    max_delegation_depth: aggregate.max_delegation_depth,
                },
            )
            .collect::<Vec<_>>();
        by_leaf.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
                .then_with(|| left.leaf_subject_key.cmp(&right.leaf_subject_key))
        });

        Ok(CostAttributionReport {
            summary: CostAttributionSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                total_cost_charged,
                total_attempted_cost,
                max_delegation_depth,
                distinct_root_subjects: distinct_roots.len() as u64,
                distinct_leaf_subjects: distinct_leaves.len() as u64,
                lineage_gap_count,
                truncated: matching_receipts > receipts.len() as u64,
            },
            by_root,
            by_leaf,
            receipts,
        })
    }

    pub fn query_shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, ReceiptStoreError> {
        let limit = query.limit_or_default();
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let issuer = query.issuer.as_deref();
        let partner = query.partner.as_deref();

        let rows = self
            .connection()?
            .prepare(
                r#"
                SELECT r.receipt_id, r.timestamp, r.capability_id, r.decision_kind
                FROM chio_tool_receipts r
                LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
                WHERE (?1 IS NULL OR r.capability_id = ?1)
                  AND (?2 IS NULL OR r.tool_server = ?2)
                  AND (?3 IS NULL OR r.tool_name = ?3)
                  AND (?4 IS NULL OR r.timestamp >= ?4)
                  AND (?5 IS NULL OR r.timestamp <= ?5)
                  AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
                ORDER BY r.seq ASC
                "#,
            )?
            .query_map(
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
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut share_cache = BTreeMap::<String, Option<FederatedEvidenceShareSummary>>::new();
        let mut references = BTreeMap::<(String, String), SharedEvidenceReferenceRow>::new();
        let mut matched_local_receipts = BTreeSet::<String>::new();

        for (receipt_id, timestamp, local_capability_id, decision) in rows {
            let chain = self.get_combined_delegation_chain(&local_capability_id)?;
            if chain.is_empty() {
                continue;
            }

            let mut matched_this_receipt = false;
            for (index, snapshot) in chain.iter().enumerate() {
                let share = match share_cache.get(&snapshot.capability_id) {
                    Some(cached) => cached.clone(),
                    None => {
                        let loaded = self
                            .get_federated_share_for_capability(&snapshot.capability_id)?
                            .map(|(share, _)| share);
                        share_cache.insert(snapshot.capability_id.clone(), loaded.clone());
                        loaded
                    }
                };
                let Some(share) = share else {
                    continue;
                };
                if issuer.is_some_and(|expected| share.issuer != expected) {
                    continue;
                }
                if partner.is_some_and(|expected| share.partner != expected) {
                    continue;
                }

                let local_anchor_capability_id =
                    chain.iter().skip(index + 1).find_map(|candidate| {
                        match share_cache.get(&candidate.capability_id) {
                            Some(Some(_)) => None,
                            Some(None) => Some(candidate.capability_id.clone()),
                            None => {
                                let loaded = self
                                    .get_federated_share_for_capability(&candidate.capability_id)
                                    .ok()
                                    .and_then(|value| value.map(|(share, _)| share));
                                share_cache.insert(candidate.capability_id.clone(), loaded.clone());
                                if loaded.is_some() {
                                    None
                                } else {
                                    Some(candidate.capability_id.clone())
                                }
                            }
                        }
                    });

                let key = (share.share_id.clone(), snapshot.capability_id.clone());
                let entry = references
                    .entry(key)
                    .or_insert_with(|| SharedEvidenceReferenceRow {
                        share: share.clone(),
                        capability_id: snapshot.capability_id.clone(),
                        subject_key: snapshot.subject_key.clone(),
                        issuer_key: snapshot.issuer_key.clone(),
                        delegation_depth: snapshot.delegation_depth,
                        parent_capability_id: snapshot.parent_capability_id.clone(),
                        local_anchor_capability_id: local_anchor_capability_id.clone(),
                        matched_local_receipts: 0,
                        allow_count: 0,
                        deny_count: 0,
                        cancelled_count: 0,
                        incomplete_count: 0,
                        first_seen: Some(timestamp),
                        last_seen: Some(timestamp),
                    });

                entry.local_anchor_capability_id = entry
                    .local_anchor_capability_id
                    .clone()
                    .or(local_anchor_capability_id);
                entry.matched_local_receipts = entry.matched_local_receipts.saturating_add(1);
                entry.first_seen = Some(
                    entry
                        .first_seen
                        .map_or(timestamp, |value| value.min(timestamp)),
                );
                entry.last_seen = Some(
                    entry
                        .last_seen
                        .map_or(timestamp, |value| value.max(timestamp)),
                );
                match decision.as_str() {
                    "allow" => entry.allow_count = entry.allow_count.saturating_add(1),
                    "deny" => entry.deny_count = entry.deny_count.saturating_add(1),
                    "cancelled" => entry.cancelled_count = entry.cancelled_count.saturating_add(1),
                    _ => entry.incomplete_count = entry.incomplete_count.saturating_add(1),
                }
                matched_this_receipt = true;
            }

            if matched_this_receipt {
                matched_local_receipts.insert(receipt_id);
            }
        }

        let mut returned_references = references.into_values().collect::<Vec<_>>();
        returned_references.sort_by(|left, right| {
            right
                .matched_local_receipts
                .cmp(&left.matched_local_receipts)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| right.share.imported_at.cmp(&left.share.imported_at))
                .then_with(|| left.share.share_id.cmp(&right.share.share_id))
                .then_with(|| left.capability_id.cmp(&right.capability_id))
        });

        let mut distinct_shares = BTreeMap::<String, FederatedEvidenceShareSummary>::new();
        let mut distinct_remote_subjects = BTreeSet::<String>::new();
        for reference in &returned_references {
            distinct_shares
                .entry(reference.share.share_id.clone())
                .or_insert_with(|| reference.share.clone());
            distinct_remote_subjects.insert(reference.subject_key.clone());
        }

        let matching_references = returned_references.len() as u64;
        let truncated = returned_references.len() > limit;
        if truncated {
            returned_references.truncate(limit);
        }

        Ok(SharedEvidenceReferenceReport {
            summary: SharedEvidenceReferenceSummary {
                matching_shares: distinct_shares.len() as u64,
                matching_references,
                matching_local_receipts: matched_local_receipts.len() as u64,
                remote_tool_receipts: distinct_shares
                    .values()
                    .map(|share| share.tool_receipts)
                    .sum(),
                remote_lineage_records: distinct_shares
                    .values()
                    .map(|share| share.capability_lineage)
                    .sum(),
                distinct_remote_subjects: distinct_remote_subjects.len() as u64,
                proof_required_shares: distinct_shares
                    .values()
                    .filter(|share| share.require_proofs)
                    .count() as u64,
                truncated,
            },
            references: returned_references,
        })
    }

    pub fn query_compliance_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ComplianceReport, ReceiptStoreError> {
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
        let export_query = query.to_evidence_export_query();

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
        self.connection()?.execute(
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
                receipt_id,
                settlement_reconciliation_state_text(reconciliation_state),
                note,
                updated_at
            ],
        )?;

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
        self.connection()?.execute(
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
                receipt_id,
                &evidence.usage_evidence.evidence_kind,
                &evidence.usage_evidence.evidence_id,
                evidence.usage_evidence.observed_units as i64,
                evidence.billed_cost.units as i64,
                &evidence.billed_cost.currency,
                evidence.usage_evidence.evidence_sha256.as_deref(),
                evidence.recorded_at as i64,
                metered_billing_reconciliation_state_text(reconciliation_state),
                note,
                updated_at
            ],
        )?;

        Ok(updated_at)
    }

    pub fn query_metered_billing_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, ReceiptStoreError> {
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

    pub fn query_economic_receipt_projection_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<EconomicReceiptProjectionReport, ReceiptStoreError> {
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

    pub fn query_settlement_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<SettlementReconciliationReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.settlement_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored') THEN 1
                        ELSE 0
                    END
                ), 0) AS actionable_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0) AS reconciled_receipts
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            pending_receipts,
            failed_receipts,
            actionable_receipts,
            reconciled_receipts,
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

        let rows_sql = r#"
            SELECT
                r.seq,
                r.receipt_id,
                r.timestamp,
                r.capability_id,
                COALESCE(r.subject_key, cl.subject_key),
                r.tool_server,
                r.tool_name,
                json_extract(r.raw_json, '$.metadata.financial.payment_reference'),
                json_extract(r.raw_json, '$.metadata.financial.settlement_status'),
                CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER),
                json_extract(r.raw_json, '$.metadata.financial.currency'),
                COALESCE(sr.reconciliation_state, 'open'),
                sr.note,
                sr.updated_at,
                r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
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
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (
                seq,
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status_text,
                cost_charged,
                currency,
                reconciliation_state_text,
                note,
                updated_at,
                raw_json,
            ) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            let settlement_status = parse_settlement_status(&settlement_status_text)?;
            let reconciliation_state =
                parse_settlement_reconciliation_state(&reconciliation_state_text)?;
            let action_required = settlement_reconciliation_action_required(
                settlement_status.clone(),
                reconciliation_state,
            );
            receipts.push(SettlementReconciliationRow {
                receipt_id,
                timestamp: timestamp.max(0) as u64,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status,
                cost_charged: cost_charged.map(|value| value.max(0) as u64),
                currency,
                budget_authority: receipt.financial_budget_authority_metadata(),
                reconciliation_state,
                action_required,
                note,
                updated_at: updated_at.map(|value| value.max(0) as u64),
            });
        }

        Ok(SettlementReconciliationReport {
            summary: SettlementReconciliationSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                pending_receipts,
                failed_receipts,
                actionable_receipts,
                reconciled_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn query_authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.authorization_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.approval') = 'object' THEN 1
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
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.commerce') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.runtime_assurance') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.call_chain') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.max_amount') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            approval_receipts,
            approved_receipts,
            commerce_receipts,
            metered_billing_receipts,
            runtime_assurance_receipts,
            _call_chain_receipts,
            max_amount_receipts,
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
                ))
            },
        )?;

        let rows_sql = r#"
            SELECT
                r.seq,
                r.raw_json,
                r.subject_key,
                r.issuer_key,
                cl.subject_key,
                cl.issuer_key,
                r.grant_index,
                cl.grants_json,
                rls.statement_id,
                rls.session_anchor_id
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN receipt_lineage_statements rls ON r.receipt_id = rls.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
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
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )?;

        let mut sender_bound_receipts = 0_u64;
        let mut dpop_bound_receipts = 0_u64;
        let mut runtime_assurance_bound_receipts = 0_u64;
        let mut delegated_sender_bound_receipts = 0_u64;
        let mut call_chain_receipts = 0_u64;
        let mut asserted_call_chain_receipts = 0_u64;
        let mut observed_call_chain_receipts = 0_u64;
        let mut verified_call_chain_receipts = 0_u64;
        let mut session_anchor_receipts = 0_u64;
        let mut request_lineage_receipts = 0_u64;
        let mut receipt_lineage_statement_receipts = 0_u64;
        let mut receipts = Vec::new();
        for row in rows {
            let (
                seq,
                raw_json,
                receipt_subject_key,
                receipt_issuer_key,
                lineage_subject_key,
                lineage_issuer_key,
                persisted_grant_index,
                grants_json,
                persisted_statement_id,
                persisted_session_anchor_id,
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
            let mut projection = sanitize_governed_transaction_projection(&receipt, &governed);
            apply_persisted_lineage_references(
                &mut projection,
                &PersistedLineageReferences {
                    statement_id: persisted_statement_id,
                    session_anchor_id: persisted_session_anchor_id,
                },
            );
            let attribution = extract_receipt_attribution(&receipt);
            let transaction_context =
                authorization_transaction_context_from_projection(&projection);
            let sender_constraint = derive_authorization_sender_constraint(
                &receipt.id,
                AuthorizationSenderConstraintArgs {
                    tool_server: &receipt.tool_server,
                    tool_name: &receipt.tool_name,
                    receipt_subject_key: receipt_subject_key.as_deref(),
                    receipt_issuer_key: receipt_issuer_key.as_deref(),
                    lineage_subject_key: lineage_subject_key.as_deref(),
                    lineage_issuer_key: lineage_issuer_key.as_deref(),
                    grant_index: attribution
                        .grant_index
                        .or_else(|| persisted_grant_index.map(|value| value.max(0) as u32)),
                    grants_json: grants_json.as_deref(),
                },
                &transaction_context,
            )?;

            let authorization_row = AuthorizationContextRow {
                receipt_id: receipt.id,
                timestamp: receipt.timestamp,
                capability_id: receipt.capability_id,
                subject_key: Some(sender_constraint.subject_key.clone()),
                tool_server: receipt.tool_server,
                tool_name: receipt.tool_name,
                decision: receipt.decision,
                authorization_details: authorization_details_from_governed_metadata(
                    &projection.strong,
                ),
                transaction_context,
                governed_transaction_diagnostics: projection.diagnostics.clone(),
                sender_constraint,
            };
            validate_chio_oauth_authorization_row(&authorization_row)?;
            if let Some(evidence_class) = call_chain_evidence_class(&projection) {
                call_chain_receipts += 1;
                match evidence_class {
                    GovernedProvenanceEvidenceClass::Asserted => {
                        asserted_call_chain_receipts += 1;
                    }
                    GovernedProvenanceEvidenceClass::Observed => {
                        observed_call_chain_receipts += 1;
                    }
                    GovernedProvenanceEvidenceClass::Verified => {
                        verified_call_chain_receipts += 1;
                    }
                }
            }
            if let Some(lineage_references) = lineage_references_from_projection(&projection) {
                if lineage_references.session_anchor_id.is_some() {
                    session_anchor_receipts += 1;
                }
                if lineage_references.request_lineage_id.is_some() {
                    request_lineage_receipts += 1;
                }
                if lineage_references.receipt_lineage_statement_id.is_some() {
                    receipt_lineage_statement_receipts += 1;
                }
            }
            sender_bound_receipts += 1;
            if authorization_row.sender_constraint.proof_required {
                dpop_bound_receipts += 1;
            }
            if authorization_row.sender_constraint.runtime_assurance_bound {
                runtime_assurance_bound_receipts += 1;
            }
            if authorization_row
                .sender_constraint
                .delegated_call_chain_bound
            {
                delegated_sender_bound_receipts += 1;
            }
            if receipts.len() < row_limit {
                receipts.push(authorization_row);
            }
        }

        Ok(AuthorizationContextReport {
            schema: CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            profile: ChioOAuthAuthorizationProfile::default(),
            summary: AuthorizationContextSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                approval_receipts,
                approved_receipts,
                commerce_receipts,
                metered_billing_receipts,
                runtime_assurance_receipts,
                call_chain_receipts,
                asserted_call_chain_receipts,
                observed_call_chain_receipts,
                verified_call_chain_receipts,
                max_amount_receipts,
                sender_bound_receipts,
                dpop_bound_receipts,
                runtime_assurance_bound_receipts,
                delegated_sender_bound_receipts,
                session_anchor_receipts,
                request_lineage_receipts,
                receipt_lineage_statement_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn authorization_profile_metadata_report(&self) -> ChioOAuthAuthorizationMetadataReport {
        ChioOAuthAuthorizationMetadataReport {
            schema: CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA.to_string(),
            generated_at: unix_now(),
            profile: ChioOAuthAuthorizationProfile::default(),
            report_schema: CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            discovery: ChioOAuthAuthorizationDiscoveryMetadata {
                protected_resource_metadata_paths: vec![
                    "/.well-known/oauth-protected-resource".to_string(),
                    "/.well-known/oauth-protected-resource/mcp".to_string(),
                ],
                authorization_server_metadata_path_template:
                    "/.well-known/oauth-authorization-server/{issuer-path}".to_string(),
                discovery_informational_only: true,
            },
            support_boundary: ChioOAuthAuthorizationSupportBoundary {
                governed_receipts_authoritative: true,
                hosted_request_time_authorization_supported: true,
                resource_indicator_binding_supported: true,
                sender_constrained_projection: true,
                runtime_assurance_projection: true,
                delegated_call_chain_projection: true,
                generic_token_issuance_supported: false,
                oidc_identity_assertions_supported: false,
                mtls_transport_binding_in_profile: false,
                approval_tokens_runtime_authorization_supported: false,
                capabilities_runtime_authorization_supported: false,
                reviewer_evidence_runtime_authorization_supported: false,
            },
            example_mapping: ChioOAuthAuthorizationExampleMapping {
                authorization_detail_types: vec![
                    "type".to_string(),
                    "locations".to_string(),
                    "actions".to_string(),
                    "purpose".to_string(),
                    "maxAmount".to_string(),
                    "commerce".to_string(),
                    "meteredBilling".to_string(),
                ],
                transaction_context_fields: ChioOAuthAuthorizationProfile::default()
                    .transaction_context_fields,
                sender_constraint_fields: vec![
                    "subjectKey".to_string(),
                    "subjectKeySource".to_string(),
                    "issuerKey".to_string(),
                    "issuerKeySource".to_string(),
                    "matchedGrantIndex".to_string(),
                    "proofRequired".to_string(),
                    "proofType".to_string(),
                    "proofSchema".to_string(),
                    "runtimeAssuranceBound".to_string(),
                    "delegatedCallChainBound".to_string(),
                ],
            },
        }
    }

    pub fn query_authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ChioOAuthAuthorizationReviewPack, ReceiptStoreError> {
        let authorization_context = self.query_authorization_context_report(query)?;
        let metadata = self.authorization_profile_metadata_report();
        let mut records = Vec::with_capacity(authorization_context.receipts.len());

        for row in authorization_context.receipts {
            let (seq, raw_json) = self.connection()?.query_row(
                "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![row.receipt_id.as_str()],
                |db_row| Ok((db_row.get::<_, i64>(0)?, db_row.get::<_, String>(1)?)),
            )?;
            let signed_receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )?;
            let governed_transaction = extract_governed_transaction_metadata(&signed_receipt)
                .ok_or_else(|| {
                    ReceiptStoreError::Canonical(format!(
                        "receipt {} is missing governed transaction metadata",
                        signed_receipt.id
                    ))
                })?;
            let mut projection =
                sanitize_governed_transaction_projection(&signed_receipt, &governed_transaction);
            if let Some(diagnostics) = row.governed_transaction_diagnostics.as_ref() {
                apply_persisted_lineage_references(
                    &mut projection,
                    &PersistedLineageReferences {
                        statement_id: diagnostics
                            .lineage_references
                            .receipt_lineage_statement_id
                            .clone(),
                        session_anchor_id: diagnostics.lineage_references.session_anchor_id.clone(),
                    },
                );
            }
            records.push(ChioOAuthAuthorizationReviewPackRecord {
                receipt_id: row.receipt_id.clone(),
                capability_id: row.capability_id.clone(),
                authorization_context: row,
                governed_transaction: projection.strong,
                governed_transaction_diagnostics: projection.diagnostics,
                signed_receipt,
            });
        }

        Ok(ChioOAuthAuthorizationReviewPack {
            schema: CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA.to_string(),
            generated_at: unix_now(),
            filters: query.clone(),
            metadata,
            summary: ChioOAuthAuthorizationReviewPackSummary {
                matching_receipts: authorization_context.summary.matching_receipts,
                returned_receipts: records.len() as u64,
                dpop_required_receipts: authorization_context.summary.dpop_bound_receipts,
                runtime_assurance_receipts: authorization_context
                    .summary
                    .runtime_assurance_bound_receipts,
                delegated_call_chain_receipts: authorization_context.summary.call_chain_receipts,
                asserted_call_chain_receipts: authorization_context
                    .summary
                    .asserted_call_chain_receipts,
                observed_call_chain_receipts: authorization_context
                    .summary
                    .observed_call_chain_receipts,
                verified_call_chain_receipts: authorization_context
                    .summary
                    .verified_call_chain_receipts,
                session_anchor_receipts: authorization_context.summary.session_anchor_receipts,
                request_lineage_receipts: authorization_context.summary.request_lineage_receipts,
                receipt_lineage_statement_receipts: authorization_context
                    .summary
                    .receipt_lineage_statement_receipts,
                truncated: authorization_context.summary.truncated,
            },
            records,
        })
    }

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
        let authorized = receipt.is_allowed();

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

    pub(crate) fn query_metered_billing_summary(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<BehavioralFeedMeteredBillingSummary, ReceiptStoreError> {
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
