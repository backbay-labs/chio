use crate::{
    i64_from_u64, u64_from_i64, PeerDirectory, PeerDirectoryStateDocument, PheromoneRelayError,
    RelayProfile, PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA,
};
use rusqlite::params;
use rusqlite::Connection;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMetricsFormat {
    Json,
    Prometheus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayQueueSummary {
    pub pending: u64,
    pub retry: u64,
    pub leased: u64,
    pub delivered: u64,
    pub dead_letter: u64,
    pub oldest_pending_age_ms: Option<u64>,
    pub stale_lease_count: u64,
    pub inbox_count: u64,
    pub cursor_count: u64,
    pub catchup_event_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDirectorySummary {
    pub active_version: Option<u64>,
    pub active_bundle_sha256: Option<String>,
    pub directory_sha256: Option<String>,
    pub issuer: Option<String>,
    pub expires_at_unix_ms: Option<u64>,
    pub removed_peer_count: u64,
    pub removed_peer_ids: Vec<String>,
    pub rejected_candidate_count: u64,
    pub last_rejection_code: Option<String>,
    pub profile: RelayProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayFailureSummary {
    pub code: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOperatorRecommendation {
    pub code: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayObservabilityReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub directory: RelayDirectorySummary,
    pub queue: RelayQueueSummary,
    pub recent_failures: Vec<RelayFailureSummary>,
    pub recommendations: Vec<RelayOperatorRecommendation>,
}

pub struct RelayObservabilityInput<'a> {
    pub local_kernel_id: &'a str,
    pub generated_at_unix_ms: u64,
    pub peer_directory: Option<&'a PeerDirectory>,
    pub peer_directory_state: Option<&'a PeerDirectoryStateDocument>,
    pub profile: RelayProfile,
    pub recent_failure_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayMetricSample {
    pub name: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayMetricsSnapshot {
    pub schema: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub samples: Vec<RelayMetricSample>,
}

impl RelayMetricsSnapshot {
    #[must_use]
    pub fn render(&self, format: RelayMetricsFormat) -> String {
        match format {
            RelayMetricsFormat::Json => match serde_json::to_string_pretty(self) {
                Ok(json) => format!("{json}\n"),
                Err(error) => format!("{{\"schema\":\"{PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA}\",\"error\":\"{error}\"}}\n"),
            },
            RelayMetricsFormat::Prometheus => self.render_prometheus(),
        }
    }

    fn render_prometheus(&self) -> String {
        let mut output = String::new();
        let mut described = BTreeSet::new();
        for sample in &self.samples {
            if described.insert(sample.name.clone()) {
                let help = prometheus_help(&sample.name);
                let kind = prometheus_kind(&sample.name);
                output.push_str(&format!("# HELP {} {help}\n", sample.name));
                output.push_str(&format!("# TYPE {} {kind}\n", sample.name));
            }
            output.push_str(&sample.name);
            if !sample.labels.is_empty() {
                output.push('{');
                for (index, (name, value)) in sample.labels.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(name);
                    output.push_str("=\"");
                    output.push_str(&prometheus_label_value(value));
                    output.push('"');
                }
                output.push('}');
            }
            output.push(' ');
            output.push_str(&format_float(sample.value));
            output.push('\n');
        }
        output
    }
}

pub(crate) fn relay_directory_summary(
    directory: Option<&PeerDirectory>,
    state: Option<&PeerDirectoryStateDocument>,
    profile: RelayProfile,
) -> RelayDirectorySummary {
    let active = state.and_then(|document| document.active.as_ref());
    let mut removed_peer_ids = active
        .map(|entry| entry.removed_peer_ids.clone())
        .unwrap_or_default();
    removed_peer_ids.sort();
    let last_rejection_code = state
        .and_then(|document| document.rejected.last())
        .map(|entry| entry.code.clone());
    RelayDirectorySummary {
        active_version: active
            .map(|entry| entry.version)
            .or_else(|| directory.and_then(PeerDirectory::version)),
        active_bundle_sha256: active.map(|entry| entry.bundle_sha256.clone()),
        directory_sha256: active.map(|entry| entry.directory_sha256.clone()),
        issuer: active.map(|entry| entry.bundle.body.issuer.clone()),
        expires_at_unix_ms: active
            .map(|entry| entry.bundle.body.expires_at_unix_ms)
            .or_else(|| {
                directory.map(|peer_directory| peer_directory.document().expires_at_unix_ms)
            }),
        removed_peer_count: u64::try_from(removed_peer_ids.len()).unwrap_or(u64::MAX),
        removed_peer_ids,
        rejected_candidate_count: state
            .map(|document| u64::try_from(document.rejected.len()).unwrap_or(u64::MAX))
            .unwrap_or(0),
        last_rejection_code,
        profile,
    }
}

pub(crate) fn relay_queue_summary(
    conn: &Connection,
    generated_at_unix_ms: u64,
) -> Result<RelayQueueSummary, PheromoneRelayError> {
    let pending = count_outbox_statuses(conn, &["pending"])?;
    let retry = count_outbox_statuses(conn, &["retry"])?;
    let leased = count_outbox_statuses(conn, &["leased"])?;
    let delivered = count_outbox_statuses(conn, &["delivered"])?;
    let dead_letter = count_outbox_statuses(conn, &["dead_letter"])?;
    let oldest_pending = oldest_pending_queued_at(conn)?;
    Ok(RelayQueueSummary {
        pending,
        retry,
        leased,
        delivered,
        dead_letter,
        oldest_pending_age_ms: oldest_pending
            .map(|queued| generated_at_unix_ms.saturating_sub(queued)),
        stale_lease_count: count_stale_leases(conn, generated_at_unix_ms)?,
        inbox_count: count_rows(conn, "chio_pheromone_relay_inbox")?,
        cursor_count: count_rows(conn, "chio_pheromone_relay_cursors")?,
        catchup_event_count: count_catchup_events(conn)?,
    })
}

pub(crate) fn recent_failure_summaries(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<RelayFailureSummary>, PheromoneRelayError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut counts = BTreeMap::<String, u64>::new();
    let mut stmt = conn.prepare(
        r#"
        SELECT code, COUNT(*)
        FROM chio_pheromone_relay_attempts
        GROUP BY code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "attempt count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }
    drop(stmt);

    let mut stmt = conn.prepare(
        r#"
        SELECT last_error_code, COUNT(*)
        FROM chio_pheromone_relay_outbox
        WHERE status = 'dead_letter' AND last_error_code IS NOT NULL
        GROUP BY last_error_code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "dead-letter count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }
    drop(stmt);

    let mut stmt = conn.prepare(
        r#"
        SELECT code, COUNT(*)
        FROM chio_pheromone_relay_events
        WHERE accepted = 0
        GROUP BY code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "event count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }

    let mut summaries = counts
        .into_iter()
        .map(|(code, count)| RelayFailureSummary { code, count })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.code.cmp(&right.code))
    });
    summaries.truncate(limit);
    Ok(summaries)
}

pub(crate) fn push_queue_depth_sample(
    samples: &mut Vec<RelayMetricSample>,
    status: &str,
    value: u64,
) {
    let mut labels = BTreeMap::new();
    labels.insert("status".to_string(), status.to_string());
    samples.push(RelayMetricSample {
        name: "chio_pheromone_relay_queue_depth".to_string(),
        value: value as f64,
        labels,
    });
}

pub(crate) fn count_catchup_events(conn: &Connection) -> Result<u64, PheromoneRelayError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_pheromone_relay_events WHERE event_kind = 'catchup'",
        [],
        |row| row.get(0),
    )?;
    u64_from_i64(count, "catch-up event count")
}

pub(crate) fn prometheus_help(name: &str) -> &'static str {
    match name {
        "chio_pheromone_relay_queue_depth" => "Relay outbox depth by bounded status.",
        "chio_pheromone_relay_oldest_pending_age_seconds" => {
            "Oldest pending relay outbox age in seconds."
        }
        "chio_pheromone_relay_stale_leases" => "Relay scheduler leases past their expiry.",
        "chio_pheromone_relay_dead_letters_total" => {
            "Total relay outbox batches moved to dead letter."
        }
        "chio_pheromone_relay_rejections_total" => {
            "Total live pheromone relay rejections by bounded reason."
        }
        _ => "Chio relay metric.",
    }
}

pub(crate) fn prometheus_kind(name: &str) -> &'static str {
    match name {
        "chio_pheromone_relay_dead_letters_total" | "chio_pheromone_relay_rejections_total" => {
            "counter"
        }
        _ => "gauge",
    }
}

pub(crate) fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub(crate) fn format_float(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.6}")
    }
}

pub(crate) fn count_outbox_statuses(
    conn: &Connection,
    statuses: &[&str],
) -> Result<u64, PheromoneRelayError> {
    let placeholders = statuses.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let count: i64 = stmt.query_row(rusqlite::params_from_iter(statuses.iter()), |row| {
        row.get(0)
    })?;
    u64_from_i64(count, "count")
}

pub(crate) fn count_rows(conn: &Connection, table: &str) -> Result<u64, PheromoneRelayError> {
    let allowed = ["chio_pheromone_relay_inbox", "chio_pheromone_relay_cursors"];
    if !allowed.contains(&table) {
        return Err(PheromoneRelayError::Sqlite(format!(
            "unsupported count table {table}"
        )));
    }
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    u64_from_i64(count, "count")
}

pub(crate) fn count_stale_leases(
    conn: &Connection,
    now_unix_ms: u64,
) -> Result<u64, PheromoneRelayError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status = 'leased' AND lease_expires_unix_ms <= ?1",
        params![i64_from_u64(now_unix_ms, "now_unix_ms")?],
        |row| row.get(0),
    )?;
    u64_from_i64(count, "stale lease count")
}

pub(crate) fn oldest_pending_queued_at(
    conn: &Connection,
) -> Result<Option<u64>, PheromoneRelayError> {
    let queued: Option<i64> = conn.query_row(
        "SELECT MIN(queued_at_unix_ms) FROM chio_pheromone_relay_outbox WHERE status IN ('pending', 'retry', 'leased')",
        [],
        |row| row.get(0),
    )?;
    queued
        .map(|value| u64_from_i64(value, "queued_at_unix_ms"))
        .transpose()
}
