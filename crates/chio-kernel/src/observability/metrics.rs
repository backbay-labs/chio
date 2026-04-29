//! Prometheus text exposition for guard metrics.

pub const GUARD_METRICS_PATH: &str = "/metrics";
pub const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const EVAL_DURATION_BUCKETS_SECONDS: &[&str] = &[
    "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0",
];
const HOST_CALL_DURATION_BUCKETS_SECONDS: &[&str] = &[
    "0.00001", "0.00005", "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrometheusMetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl PrometheusMetricKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

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
        name: "chio_guard_eval_duration_seconds",
        help: "WASM guard evaluation duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_VERDICT,
        buckets: EVAL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: "chio_guard_fuel_consumed_total",
        help: "Total WASM guard fuel units consumed.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_ONLY,
        buckets: &[],
    },
    GuardMetricFamily {
        name: "chio_guard_verdict_total",
        help: "Total WASM guard verdicts by guard and verdict.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_VERDICT,
        buckets: &[],
    },
    GuardMetricFamily {
        name: "chio_guard_deny_total",
        help: "Total WASM guard denies by reason class.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_REASON_CLASS,
        buckets: &[],
    },
    GuardMetricFamily {
        name: "chio_guard_reload_total",
        help: "Total WASM guard reload outcomes.",
        kind: PrometheusMetricKind::Counter,
        labels: LABELS_GUARD_OUTCOME,
        buckets: &[],
    },
    GuardMetricFamily {
        name: "chio_guard_host_call_duration_seconds",
        help: "WASM guard host-call duration in seconds.",
        kind: PrometheusMetricKind::Histogram,
        labels: LABELS_GUARD_HOST_FN,
        buckets: HOST_CALL_DURATION_BUCKETS_SECONDS,
    },
    GuardMetricFamily {
        name: "chio_guard_module_bytes",
        help: "Loaded WASM guard module size in bytes.",
        kind: PrometheusMetricKind::Gauge,
        labels: LABELS_GUARD_EPOCH,
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
    for family in GUARD_METRIC_FAMILIES {
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
    output.push_str(" 0\n");
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
    let mut parts = Vec::with_capacity(labels.len() + usize::from(bucket.is_some()));
    for label in labels {
        parts.push(format!("{label}=\"\""));
    }
    if let Some(bucket) = bucket {
        parts.push(format!("le=\"{bucket}\""));
    }
    format!("{{{}}}", parts.join(","))
}
