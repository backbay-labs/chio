use super::*;

pub(crate) const CHIO_CLI_RECEIPT_HEALTH_SCHEMA: &str = "chio.cli.receipt.health.v1";
pub(crate) const CHIO_CLI_RECEIPT_FLUSH_SCHEMA: &str = "chio.cli.receipt.flush.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_status.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_create.v1";
pub(crate) const CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA: &str =
    "chio.cli.receipt.checkpoint_verify.v1";
pub(crate) const CHIO_CLI_RECEIPT_AUDIT_SCHEMA: &str = "chio.cli.receipt.audit.v1";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptOperatorJsonEnvelope<'a, T>
where
    T: serde::Serialize + ?Sized,
{
    schema: &'static str,
    report: &'a T,
}

pub(crate) fn receipt_operator_json_value<T>(
    schema: &'static str,
    report: &T,
) -> Result<serde_json::Value, CliError>
where
    T: serde::Serialize + ?Sized,
{
    Ok(serde_json::to_value(ReceiptOperatorJsonEnvelope {
        schema,
        report,
    })?)
}

pub(crate) fn print_receipt_operator_json<T>(
    schema: &'static str,
    report: &T,
) -> Result<(), CliError>
where
    T: serde::Serialize + ?Sized,
{
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt_operator_json_value(schema, report)?)?
    );
    Ok(())
}

pub(crate) fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub(crate) fn push_writer_counters_human(
    lines: &mut Vec<String>,
    writer: &chio_kernel::ReceiptWriterCounters,
) {
    lines.push(format!("writer_accepted_total: {}", writer.accepted_total));
    lines.push(format!("writer_committed_total: {}", writer.committed_total));
    lines.push(format!("writer_failed_total: {}", writer.failed_total));
    lines.push(format!("writer_saturated_total: {}", writer.saturated_total));
    lines.push(format!("writer_inflight: {}", writer.inflight));
    lines.push(format!(
        "writer_last_commit_unix_ms: {}",
        optional_u64(writer.last_commit_unix_ms)
    ));
    lines.push(format!(
        "writer_last_error: {}",
        writer.last_error.as_deref().unwrap_or("none")
    ));
}

pub(crate) fn render_receipt_health_human(report: &chio_kernel::ReceiptStoreHealthReport) -> String {
    let mut lines = vec![
        format!(
            "status: {}",
            if report.healthy {
                "healthy"
            } else {
                "unhealthy"
            }
        ),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let (Some(start), Some(end)) = (
        report.uncheckpointed_start_seq,
        report.uncheckpointed_end_seq,
    ) {
        lines.push(format!("uncheckpointed_range: {start}..={end}"));
    }
    push_writer_counters_human(&mut lines, &report.writer);
    lines.push(format!(
        "db_size_bytes: {}",
        optional_u64(report.db_size_bytes)
    ));
    if let Some(error) = report.checkpoint_error.as_deref() {
        lines.push(format!("checkpoint_error: {error}"));
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_flush_human(report: &chio_kernel::ReceiptFlushReport) -> String {
    let mut lines = vec![
        "flushed: true".to_string(),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let (Some(start), Some(end)) = (
        report.uncheckpointed_start_seq,
        report.uncheckpointed_end_seq,
    ) {
        lines.push(format!("uncheckpointed_range: {start}..={end}"));
    }
    push_writer_counters_human(&mut lines, &report.writer);
    lines.push(format!(
        "db_size_bytes: {}",
        optional_u64(report.db_size_bytes)
    ));
    if let Some(wal) = &report.wal_checkpoint {
        lines.push(format!("wal_checkpoint_busy: {}", wal.busy));
        lines.push(format!("wal_checkpoint_log_frames: {}", wal.log_frames));
        lines.push(format!(
            "wal_checkpoint_checkpointed_frames: {}",
            wal.checkpointed_frames
        ));
    } else {
        lines.push("wal_checkpoint_busy: none".to_string());
        lines.push("wal_checkpoint_log_frames: none".to_string());
        lines.push("wal_checkpoint_checkpointed_frames: none".to_string());
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_checkpoint_status_human(
    report: &chio_kernel::ReceiptCheckpointStatusReport,
) -> String {
    let mut lines = vec![
        format!(
            "status: {}",
            if report.healthy {
                "healthy"
            } else {
                "unhealthy"
            }
        ),
        format!("committed_entry_seq: {}", report.latest_committed_entry_seq),
        format!("checkpoint_seq: {}", optional_u64(report.latest_checkpoint_seq)),
        format!(
            "checkpointed_entry_seq: {}",
            report.latest_checkpointed_entry_seq
        ),
    ];
    if let Some(range) = &report.next_range {
        lines.push(format!("next_range: {}..={}", range.start_seq, range.end_seq));
    } else {
        lines.push("next_range: none".to_string());
    }
    if let Some(error) = report.checkpoint_error.as_deref() {
        lines.push(format!("checkpoint_error: {error}"));
    }
    lines.join("\n") + "\n"
}

pub(crate) fn render_receipt_checkpoint_create_human(
    report: &chio_kernel::ReceiptCheckpointCreateReport,
) -> String {
    let mut lines = vec![
        format!("created: {}", report.created),
        format!("checkpoint_seq: {}", optional_u64(report.checkpoint_seq)),
    ];
    if let (Some(start), Some(end)) = (report.batch_start_seq, report.batch_end_seq) {
        lines.push(format!("checkpoint_range: {start}..={end}"));
    } else {
        lines.push("checkpoint_range: none".to_string());
    }
    lines.push(format!(
        "committed_entry_seq: {}",
        report.latest_committed_entry_seq
    ));
    lines.push(format!(
        "checkpointed_entry_seq: {}",
        report.latest_checkpointed_entry_seq
    ));
    lines.join("\n") + "\n"
}
