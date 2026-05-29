// Cost attribution report query.

use super::*;

impl SqliteReceiptStore {
    pub fn query_cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        require_admin_receipt_read_context(query.read_context.as_ref(), "cost attribution report")?;
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
}
