//! Prometheus text exposition for guard metrics.

use chio_metrics_spec::{
    CHIO_GUARD_DENY_TOTAL, CHIO_GUARD_EVAL_DURATION_SECONDS, CHIO_GUARD_FUEL_CONSUMED_TOTAL,
    CHIO_GUARD_HOST_CALL_DURATION_SECONDS, CHIO_GUARD_MODULE_BYTES, CHIO_GUARD_RELOAD_TOTAL,
    CHIO_GUARD_VERDICT_TOTAL, CHIO_SIGNING_QUEUE_BLOCK_TOTAL, GUARD_EVAL_DURATION_BUCKETS_SECONDS,
    GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS,
};

pub use chio_metrics_spec::MetricKind as PrometheusMetricKind;

pub const GUARD_METRICS_PATH: &str = "/metrics";
pub const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuardMetricFamily {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: PrometheusMetricKind,
    pub labels: &'static [&'static str],
    pub buckets: &'static [&'static str],
}

const LABELS_GUARD_VERDICT: &[&str] = &["guard_id", "verdict"];
const LABELS_GUARD_ONLY: &[&str] = &["guard_id"];
const LABELS_GUARD_REASON_CLASS: &[&str] = &["guard_id", "reason_class"];
const LABELS_GUARD_OUTCOME: &[&str] = &["guard_id", "outcome"];
const LABELS_GUARD_HOST_FN: &[&str] = &["guard_id", "host_fn"];
const LABELS_GUARD_EPOCH: &[&str] = &["guard_id", "epoch"];

pub const GUARD_METRIC_FAMILIES: &[GuardMetricFamily] = &[
    GuardMetricFamily {
        name: CHIO_GUARD_EVAL_DURATION_SECONDS,
        help: "WASM guard evaluation duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_VERDICT,
        buckets: GUARD_EVAL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: CHIO_GUARD_FUEL_CONSUMED_TOTAL,
        help: "Total WASM guard fuel units consumed.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_ONLY,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_VERDICT_TOTAL,
        help: "Total WASM guard verdicts by guard and verdict.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_VERDICT,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_DENY_TOTAL,
        help: "Total WASM guard denies by reason class.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_REASON_CLASS,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_RELOAD_TOTAL,
        help: "Total WASM guard reload outcomes.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_OUTCOME,
        buckets: &[],
    },
    GuardMetricFamily {
        name: CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
        help: "WASM guard host-call duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_HOST_FN,
        buckets: GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: CHIO_GUARD_MODULE_BYTES,
        help: "Loaded WASM guard module size in bytes.",
        kind: PrometheusMetricKind::Gauge,
        labels: LABELS_GUARD_EPOCH,
        buckets: &[],
    },
];

pub use chio_metrics_spec::CHIO_OTEL_INGRESS_DROP_TOTAL as METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL;
pub use chio_metrics_spec::CHIO_OTEL_SINK_DROP_TOTAL as METRIC_CHIO_OTEL_SINK_DROP_TOTAL;

// Advertised runtime (non-guard) families the /metrics endpoint renders via the
// chio-metrics-spec runtime families. Retained as endpoint documentation; the
// actual samples are produced by render_otel_drop_families and the signing
// family render, so this table is not iterated by the renderer.
#[allow(dead_code)]
const RUNTIME_METRIC_FAMILIES: &[GuardMetricFamily] = &[
    GuardMetricFamily {
        name: CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
        help: "Total receipt signing requests blocked by bounded queue capacity or byte budget.",
        kind: PrometheusMetricKind::Counter,
        labels: &["reason"],
        buckets: &[],
    },
    GuardMetricFamily {
        name: METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL,
        help: "Total OTEL ingress batches dropped by bounded queue admission.",
        kind: PrometheusMetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
    GuardMetricFamily {
        name: METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
        help: "Total OTEL receipt sink batches dropped before append.",
        kind: PrometheusMetricKind::Counter,
        labels: &[],
        buckets: &[],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsEndpointResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

#[must_use]
pub fn guard_metrics_endpoint(path: &str) -> Option<MetricsEndpointResponse> {
    if path != GUARD_METRICS_PATH {
        return None;
    }

    Some(MetricsEndpointResponse {
        status: 200,
        content_type: PROMETHEUS_TEXT_CONTENT_TYPE,
        body: render_guard_metrics_prometheus(),
    })
}

/// Render the kernel `/metrics` body from the chio-metrics-spec runtime
/// families. The kernel renders the guard families and the two OTEL-drop
/// families (whose sole producers are chio-wasm-guards and the OTLP ingress,
/// which cannot be depended on by the kernel) plus the signing-queue block
/// family, so every sample is a real, correctly-labeled counter rather than a
/// hardcoded zero placeholder.
#[must_use]
pub fn render_guard_metrics_prometheus() -> String {
    let mut output = String::new();
    chio_metrics_spec::runtime::render_guard_families(&mut output);
    chio_metrics_spec::runtime::render_otel_drop_families(&mut output);
    chio_metrics_spec::runtime::families::SIGNING_QUEUE_BLOCK.render(&mut output);
    chio_metrics_spec::runtime::render_receipt_watchdog_gauges(&mut output);
    output
}

/// Turn a receipt-store health report into the watchdog gauges: the
/// uncheckpointed entry_seq range and the seconds since the last commit. A
/// serve-mode watchdog loop calls this on an interval so uncheckpointed growth
/// and checkpoint staleness are observable without a human `chio receipt health`
/// run.
pub fn record_receipt_health_gauges(
    report: &crate::receipt_store::ReceiptStoreHealthReport,
    now_unix_ms: u64,
) {
    let range = match (
        report.uncheckpointed_start_seq,
        report.uncheckpointed_end_seq,
    ) {
        (Some(start), Some(end)) => end.saturating_sub(start),
        _ => 0,
    };
    chio_metrics_spec::runtime::families::RECEIPT_UNCHECKPOINTED_RANGE.set(&[], range);

    // Base `chio_receipt_seconds_since_last_checkpoint` on checkpoint PROGRESS,
    // not on `writer.last_commit_unix_ms`. In an active store where writes keep
    // committing while checkpointing stalls, the last-commit timestamp stays
    // fresh, so a commit-based gauge would read near zero and the
    // ChioReceiptCheckpointStale alert would never fire even as the
    // uncheckpointed range grows. Track when the checkpointed high-water mark
    // last advanced while a backlog was pending instead.
    let has_backlog = report.latest_committed_entry_seq > report.latest_checkpointed_entry_seq;
    let age_seconds = match CHECKPOINT_PROGRESS.lock() {
        Ok(mut state) => checkpoint_staleness_seconds(
            &mut state,
            report.latest_checkpointed_entry_seq,
            has_backlog,
            now_unix_ms,
        ),
        // Fail-closed observability: a poisoned lock drops the sample (0) rather
        // than unwinding the watchdog loop.
        Err(_) => 0,
    };
    chio_metrics_spec::runtime::families::RECEIPT_CHECKPOINT_AGE_SECONDS.set(&[], age_seconds);
}

/// Process-global record of when the receipt checkpoint high-water mark last
/// advanced, so `chio_receipt_seconds_since_last_checkpoint` measures
/// checkpoint staleness rather than write-commit freshness.
struct CheckpointProgress {
    /// The latest checkpointed entry seq observed on the previous sample.
    checkpointed_entry_seq: u64,
    /// Wall-clock (unix ms) at which that seq was last observed to advance, i.e.
    /// the start of the current staleness interval.
    advanced_at_unix_ms: u64,
}

static CHECKPOINT_PROGRESS: std::sync::Mutex<Option<CheckpointProgress>> =
    std::sync::Mutex::new(None);

/// Seconds since the checkpoint high-water mark last advanced while a backlog is
/// pending. Resets to 0 whenever the checkpoint advances OR there is no
/// uncheckpointed backlog (a healthy, quiet store is never "stale"). Grows only
/// while committed data sits uncheckpointed and the checkpoint seq does not move.
/// Pure over `state` so it is unit-testable without the process-global.
fn checkpoint_staleness_seconds(
    state: &mut Option<CheckpointProgress>,
    checkpointed_entry_seq: u64,
    has_backlog: bool,
    now_unix_ms: u64,
) -> u64 {
    let progressed = state
        .as_ref()
        .map(|prev| prev.checkpointed_entry_seq != checkpointed_entry_seq)
        .unwrap_or(true);

    if progressed || !has_backlog {
        // Checkpoint advanced this sample, or nothing is pending to checkpoint:
        // the store is healthy, so reset the staleness clock.
        *state = Some(CheckpointProgress {
            checkpointed_entry_seq,
            advanced_at_unix_ms: now_unix_ms,
        });
        return 0;
    }

    // A backlog is present and the checkpoint high-water mark has not moved since
    // the last sample: report how long it has been stalled.
    state
        .as_ref()
        .map(|prev| now_unix_ms.saturating_sub(prev.advanced_at_unix_ms) / 1000)
        .unwrap_or(0)
}

#[cfg(test)]
mod checkpoint_staleness_tests {
    use super::{checkpoint_staleness_seconds, CheckpointProgress};

    #[test]
    fn resets_when_checkpoint_advances_even_as_time_passes() {
        let mut state: Option<CheckpointProgress> = None;
        // First sample seeds the clock at 0.
        assert_eq!(checkpoint_staleness_seconds(&mut state, 5, true, 1_000), 0);
        // Checkpoint advanced 5 -> 9: the clock resets despite 60s elapsing.
        assert_eq!(checkpoint_staleness_seconds(&mut state, 9, true, 61_000), 0);
    }

    #[test]
    fn grows_while_backlog_stays_uncheckpointed() {
        let mut state: Option<CheckpointProgress> = None;
        assert_eq!(checkpoint_staleness_seconds(&mut state, 5, true, 1_000), 0);
        // Same checkpoint seq, backlog still pending, 90s later: staleness grows.
        // A commit-based gauge would read ~0 here because writes keep committing.
        assert_eq!(
            checkpoint_staleness_seconds(&mut state, 5, true, 91_000),
            90
        );
    }

    #[test]
    fn stays_zero_for_a_healthy_quiet_store_without_backlog() {
        let mut state: Option<CheckpointProgress> = None;
        assert_eq!(checkpoint_staleness_seconds(&mut state, 5, false, 1_000), 0);
        // No backlog: even a long-idle store must never look stale.
        assert_eq!(
            checkpoint_staleness_seconds(&mut state, 5, false, 999_000),
            0
        );
    }
}
