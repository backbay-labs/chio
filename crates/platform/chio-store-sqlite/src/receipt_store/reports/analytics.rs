// Receipt analytics report query.

use super::*;

impl SqliteReceiptStore {
    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "receipt analytics report",
        )?;
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
}
