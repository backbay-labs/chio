//! Prometheus text exposition for guard metrics.

use chio_metrics_spec::{
    CHIO_GUARD_DENY_TOTAL, CHIO_GUARD_EVAL_DURATION_SECONDS, CHIO_GUARD_FUEL_CONSUMED_TOTAL,
    CHIO_GUARD_HOST_CALL_DURATION_SECONDS, CHIO_GUARD_MODULE_BYTES, CHIO_GUARD_RELOAD_TOTAL,
    CHIO_GUARD_VERDICT_TOTAL, CHIO_SIGNING_QUEUE_BLOCK_TOTAL, GUARD_EVAL_DURATION_BUCKETS_SECONDS,
    GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS,
};

use crate::kernel::signing_task::signing_queue_block_total;

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

const RUNTIME_METRIC_FAMILIES: &[GuardMetricFamily] = &[
    GuardMetricFamily {
        name: CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
        help: "Total receipt signing requests blocked by bounded queue capacity.",
        kind: PrometheusMetricKind::Counter,
        labels: &[],
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

#[must_use]
pub fn render_guard_metrics_prometheus() -> String {
    let mut output = String::new();
    for family in GUARD_METRIC_FAMILIES.iter().chain(RUNTIME_METRIC_FAMILIES) {
        output.push_str("# HELP ");
        output.push_str(family.name);
        output.push(' ');
        output.push_str(family.help);
        output.push('\n');
        output.push_str("# TYPE ");
        output.push_str(family.name);
        output.push(' ');
        output.push_str(family.kind.as_str());
        output.push('\n');
        match family.kind {
            PrometheusMetricKind::Counter | PrometheusMetricKind::Gauge => {
                render_scalar_family(&mut output, family);
            }
            PrometheusMetricKind::Histogram => {
                render_histogram_family(&mut output, family);
            }
        }
    }
    output
}

fn render_scalar_family(output: &mut String, family: &GuardMetricFamily) {
    output.push_str(family.name);
    output.push_str(&render_empty_labels(family.labels));
    output.push(' ');
    output.push_str(&scalar_metric_value(family).to_string());
    output.push('\n');
}

fn scalar_metric_value(family: &GuardMetricFamily) -> u64 {
    match family.name {
        CHIO_SIGNING_QUEUE_BLOCK_TOTAL => signing_queue_block_total(),
        _ => 0,
    }
}

fn render_histogram_family(output: &mut String, family: &GuardMetricFamily) {
    for bucket in family.buckets {
        output.push_str(family.name);
        output.push_str("_bucket");
        output.push_str(&render_labels_with_bucket(family.labels, bucket));
        output.push_str(" 0\n");
    }
    output.push_str(family.name);
    output.push_str("_bucket");
    output.push_str(&render_labels_with_bucket(family.labels, "+Inf"));
    output.push_str(" 0\n");
    output.push_str(family.name);
    output.push_str("_sum");
    output.push_str(&render_empty_labels(family.labels));
    output.push_str(" 0\n");
    output.push_str(family.name);
    output.push_str("_count");
    output.push_str(&render_empty_labels(family.labels));
    output.push_str(" 0\n");
}

fn render_empty_labels(labels: &[&str]) -> String {
    render_labels(labels, None)
}

fn render_labels_with_bucket(labels: &[&str], bucket: &str) -> String {
    render_labels(labels, Some(bucket))
}

fn render_labels(labels: &[&str], bucket: Option<&str>) -> String {
    if labels.is_empty() && bucket.is_none() {
        return String::new();
    }

    let mut parts = Vec::with_capacity(labels.len() + usize::from(bucket.is_some()));
    for label in labels {
        parts.push(format!("{label}=\"\""));
    }
    if let Some(bucket) = bucket {
        parts.push(format!("le=\"{bucket}\""));
    }
    format!("{{{}}}", parts.join(","))
}
