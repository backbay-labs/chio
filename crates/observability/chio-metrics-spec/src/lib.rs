//! Workspace-wide metric registry for Chio SRE surfaces.
//!
//! New Prometheus metric names must be added here first, then consumed from
//! constants instead of inlining string literals at emission sites. The
//! snapshot test in this crate is the CI gate for taxonomy drift.

#![forbid(unsafe_code)]

pub mod runtime;

/// Prometheus metric family kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl MetricKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One registered metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDescriptor {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: MetricKind,
    pub labels: &'static [&'static str],
    pub buckets: &'static [&'static str],
}

/// Semantic validation failure for metric descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricValidationError {
    InvalidMetricName {
        name: &'static str,
    },
    InvalidLabelName {
        metric: &'static str,
        label: &'static str,
    },
    DuplicateLabelName {
        metric: &'static str,
        label: &'static str,
    },
    UnexpectedBuckets {
        metric: &'static str,
        kind: MetricKind,
    },
    MissingHistogramBuckets {
        metric: &'static str,
    },
    InvalidHistogramBucket {
        metric: &'static str,
        bucket: &'static str,
    },
    NonIncreasingHistogramBucket {
        metric: &'static str,
        previous: &'static str,
        bucket: &'static str,
    },
    DuplicateMetricName {
        metric: &'static str,
    },
    RegistryNotSorted {
        previous: &'static str,
        current: &'static str,
    },
}

/// Declare a metric descriptor from a const name.
///
/// The macro intentionally accepts a single name expression plus literal
/// metadata. Sites that need a new name add a constant first, which keeps the
/// grep gate and snapshot aligned.
#[macro_export]
macro_rules! describe {
    (
        name = $name:expr,
        help = $help:literal,
        kind = $kind:ident,
        labels = [$($label:literal),* $(,)?],
        buckets = [$($bucket:literal),* $(,)?] $(,)?
    ) => {
        $crate::MetricDescriptor {
            name: $name,
            help: $help,
            kind: $crate::MetricKind::$kind,
            labels: &[$($label),*],
            buckets: &[$($bucket),*],
        }
    };
    (
        name = $name:expr,
        help = $help:literal,
        kind = $kind:ident,
        labels = [$($label:literal),* $(,)?] $(,)?
    ) => {
        $crate::describe!(
            name = $name,
            help = $help,
            kind = $kind,
            labels = [$($label),*],
            buckets = []
        )
    };
}

pub const CHIO_ALERT_DISPATCH_TOTAL: &str = "chio_alert_dispatch_total";
pub const CHIO_ALERT_DISPATCH_LATENCY_SECONDS: &str = "chio_alert_dispatch_latency_seconds";
pub const CHIO_ANCHOR_ROUND_LATENCY_SECONDS: &str = "chio_anchor_round_latency_seconds";
pub const CHIO_CAPABILITY_REVOCATION_LAG_SECONDS: &str = "chio_capability_revocation_lag_seconds";
pub const CHIO_DISPATCH_FAILURE_TOTAL: &str = "chio_dispatch_failure_total";
pub const CHIO_DLQ_DEPTH: &str = "chio_dlq_depth";
pub const CHIO_FAIL_OPEN_SUSPECTED_TOTAL: &str = "chio_fail_open_suspected_total";
pub const CHIO_FEDERATION_HOP_LATENCY_SECONDS: &str = "chio_federation_hop_latency_seconds";
pub const CHIO_FEDERATION_HOP_TOTAL: &str = "chio_federation_hop_total";
pub const CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS: &str =
    "chio_federation_transport_accept_duration_seconds";
pub const CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN: &str = "chio_federation_transport_accept_open";
pub const CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL: &str =
    "chio_federation_transport_admission_total";
pub const CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL: &str =
    "chio_federation_transport_catchup_epoch_gap_total";
pub const CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL: &str =
    "chio_federation_transport_directory_reload_total";
pub const CHIO_FEDERATION_TRANSPORT_LANE_TOTAL: &str = "chio_federation_transport_lane_total";
pub const CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL: &str = "chio_federation_transport_outbox_total";
pub const CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE: &str = "chio_federation_transport_router_alive";
pub const CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL: &str =
    "chio_federation_transport_verify_failures_total";
pub const CHIO_GUARD_DENY_TOTAL: &str = "chio_guard_deny_total";
pub const CHIO_GUARD_EVAL_DURATION_SECONDS: &str = "chio_guard_eval_duration_seconds";
pub const CHIO_GUARD_EVALUATIONS_TOTAL: &str = "chio_guard_evaluations_total";
pub const CHIO_GUARD_FUEL_CONSUMED_TOTAL: &str = "chio_guard_fuel_consumed_total";
pub const CHIO_GUARD_HOST_CALL_DURATION_SECONDS: &str = "chio_guard_host_call_duration_seconds";
pub const CHIO_GUARD_MODULE_BYTES: &str = "chio_guard_module_bytes";
pub const CHIO_GUARD_POOL_CHECKOUT_TOTAL: &str = "chio_guard_pool_checkout_total";
pub const CHIO_GUARD_POOL_EVICT_TOTAL: &str = "chio_guard_pool_evict_total";
pub const CHIO_GUARD_POOL_WARM_SIZE: &str = "chio_guard_pool_warm_size";
pub const CHIO_GUARD_RELOAD_TOTAL: &str = "chio_guard_reload_total";
pub const CHIO_GUARD_VERDICT_TOTAL: &str = "chio_guard_verdict_total";
pub const CHIO_KERNEL_DECISION_LATENCY_SECONDS: &str = "chio_kernel_decision_latency_seconds";
pub const CHIO_OTEL_INGRESS_DROP_TOTAL: &str = "chio_otel_ingress_drop_total";
pub const CHIO_OTEL_SINK_DROP_TOTAL: &str = "chio_otel_sink_drop_total";
pub const CHIO_PHEROMONE_QUEUE_OVERFLOW_TOTAL: &str = "chio_pheromone_queue_overflow_total";
pub const CHIO_PHEROMONE_RELAY_CATCHUP_BYTES_SERVED_TOTAL: &str =
    "chio_pheromone_relay_catchup_bytes_served_total";
pub const CHIO_PHEROMONE_RELAY_CATCHUP_DENIES_TOTAL: &str =
    "chio_pheromone_relay_catchup_denies_total";
pub const CHIO_PHEROMONE_RELAY_DEAD_LETTERS_TOTAL: &str = "chio_pheromone_relay_dead_letters_total";
pub const CHIO_PHEROMONE_RELAY_DELIVERY_TOTAL: &str = "chio_pheromone_relay_delivery_total";
pub const CHIO_PHEROMONE_RELAY_ENDPOINT_DENIED_TOTAL: &str =
    "chio_pheromone_relay_endpoint_denied_total";
pub const CHIO_PHEROMONE_RELAY_LATENCY_SECONDS: &str = "chio_pheromone_relay_latency_seconds";
pub const CHIO_PHEROMONE_RELAY_NONCE_REPLAY_CONFLICTS_TOTAL: &str =
    "chio_pheromone_relay_nonce_replay_conflicts_total";
pub const CHIO_PHEROMONE_RELAY_OLDEST_PENDING_AGE_SECONDS: &str =
    "chio_pheromone_relay_oldest_pending_age_seconds";
pub const CHIO_PHEROMONE_RELAY_QUEUE_DEPTH: &str = "chio_pheromone_relay_queue_depth";
pub const CHIO_PHEROMONE_RELAY_REJECTIONS_TOTAL: &str = "chio_pheromone_relay_rejections_total";
pub const CHIO_PHEROMONE_RELAY_STALE_DIRECTORIES_TOTAL: &str =
    "chio_pheromone_relay_stale_directories_total";
pub const CHIO_PHEROMONE_RELAY_STALE_LEASES: &str = "chio_pheromone_relay_stale_leases";
pub const CHIO_PHEROMONE_RECEIVER_DEPOSITS_TOTAL: &str = "chio_pheromone_receiver_deposits_total";
pub const CHIO_PHEROMONE_RECEIVER_LATENCY_SECONDS: &str = "chio_pheromone_receiver_latency_seconds";
pub const CHIO_PHEROMONE_RECEIVER_REJECTIONS_TOTAL: &str =
    "chio_pheromone_receiver_rejections_total";
pub const CHIO_RECEIPT_SECONDS_SINCE_LAST_CHECKPOINT: &str =
    "chio_receipt_seconds_since_last_checkpoint";
pub const CHIO_RECEIPT_UNCHECKPOINTED_SEQ_RANGE: &str = "chio_receipt_uncheckpointed_seq_range";
pub const CHIO_RECEIPT_WRITE_TOTAL: &str = "chio_receipt_write_total";
pub const CHIO_RECEIPT_WRITE_LATENCY_SECONDS: &str = "chio_receipt_write_latency_seconds";
pub const CHIO_SIDECAR_REQUESTS_TOTAL: &str = "chio_sidecar_requests_total";
pub const CHIO_SIGNING_QUEUE_BLOCK_TOTAL: &str = "chio_signing_queue_block_total";
pub const CHIO_SOC_EXPORT_TOTAL: &str = "chio_soc_export_total";
pub const CHIO_SOC_EXPORT_LAG_SECONDS: &str = "chio_soc_export_lag_seconds";
pub const CHIO_TRUST_CONTROL_READY: &str = "chio_trust_control_ready";

pub const GUARD_EVAL_DURATION_BUCKETS_SECONDS: &[&str] = &[
    "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0",
];
pub const GUARD_HOST_CALL_DURATION_BUCKETS_SECONDS: &[&str] = &[
    "0.00001", "0.00005", "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1",
];
pub const DECISION_LATENCY_BUCKETS_SECONDS: &[&str] =
    &["0.025", "0.05", "0.075", "0.1", "0.25", "0.5", "1.0", "2.5"];
pub const RECEIPT_WRITE_LATENCY_BUCKETS_SECONDS: &[&str] =
    &["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"];
pub const ALERT_DISPATCH_LATENCY_BUCKETS_SECONDS: &[&str] =
    &["0.25", "0.5", "1.0", "2.5", "5.0", "10.0"];
pub const EXPORT_LAG_BUCKETS_SECONDS: &[&str] = &["30", "60", "120", "300", "600", "1800"];
pub const ANCHOR_ROUND_LATENCY_BUCKETS_SECONDS: &[&str] =
    &["0.1", "0.5", "1.0", "2.5", "5.0", "10.0"];
pub const FEDERATION_HOP_LATENCY_BUCKETS_SECONDS: &[&str] =
    &["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"];
pub const FEDERATION_TRANSPORT_ACCEPT_DURATION_BUCKETS_SECONDS: &[&str] =
    &["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"];
pub const PHEROMONE_RECEIVER_LATENCY_BUCKETS_SECONDS: &[&str] = &[
    "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0",
];

pub const REGISTRY: &[MetricDescriptor] = &[
    describe!(
        name = CHIO_ALERT_DISPATCH_LATENCY_SECONDS,
        help = "PagerDuty or OpsGenie alert dispatch latency in seconds.",
        kind = Histogram,
        labels = ["route", "outcome"],
        buckets = ["0.25", "0.5", "1.0", "2.5", "5.0", "10.0"]
    ),
    describe!(
        name = CHIO_ALERT_DISPATCH_TOTAL,
        help = "Total PagerDuty or OpsGenie alert dispatch outcomes.",
        kind = Counter,
        labels = ["route", "outcome"]
    ),
    describe!(
        name = CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
        help = "Anchor round latency in seconds.",
        kind = Histogram,
        labels = ["witness", "outcome"],
        buckets = ["0.1", "0.5", "1.0", "2.5", "5.0", "10.0"]
    ),
    describe!(
        name = CHIO_CAPABILITY_REVOCATION_LAG_SECONDS,
        help = "Capability revocation propagation lag in seconds.",
        kind = Histogram,
        labels = ["authority"],
        buckets = ["1", "5", "15", "30", "60", "120", "300"]
    ),
    describe!(
        name = CHIO_DISPATCH_FAILURE_TOTAL,
        help = "Total tool-dispatch failures that did not bypass mediation.",
        kind = Counter,
        labels = ["surface", "outcome"]
    ),
    describe!(
        name = CHIO_DLQ_DEPTH,
        help = "Dead-letter queue depth by exporter.",
        kind = Gauge,
        labels = ["exporter"]
    ),
    describe!(
        name = CHIO_FAIL_OPEN_SUSPECTED_TOTAL,
        help = "Total suspected fail-open paths detected by SRE guards.",
        kind = Counter,
        labels = ["surface"]
    ),
    describe!(
        name = CHIO_FEDERATION_HOP_LATENCY_SECONDS,
        help = "Federation hop latency in seconds.",
        kind = Histogram,
        labels = ["result"],
        buckets = ["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"]
    ),
    describe!(
        name = CHIO_FEDERATION_HOP_TOTAL,
        help = "Total federation hop outcomes.",
        kind = Counter,
        labels = ["result"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_ACCEPT_DURATION_SECONDS,
        help = "Iroh federation-transport per-lane accept handler duration in seconds.",
        kind = Histogram,
        labels = ["lane"],
        buckets = ["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_ACCEPT_OPEN,
        help = "Iroh federation-transport in-flight accept handlers by lane (slowloris gauge).",
        kind = Gauge,
        labels = ["lane"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_ADMISSION_TOTAL,
        help = "Total iroh federation-transport admission-gate outcomes at after_handshake.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_CATCHUP_EPOCH_GAP_TOTAL,
        help = "Total iroh federation-transport revocation catch-up epoch gaps detected.",
        kind = Counter,
        labels = ["source"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_DIRECTORY_RELOAD_TOTAL,
        help = "Total iroh federation-transport directory reload outcomes.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_LANE_TOTAL,
        help = "Total iroh federation-transport per-lane accept outcomes.",
        kind = Counter,
        labels = ["lane", "outcome"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_OUTBOX_TOTAL,
        help = "Total iroh federation-transport pheromone outbox drain outcomes.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_ROUTER_ALIVE,
        help = "Iroh federation-transport router liveness (1 alive, 0 the router died).",
        kind = Gauge,
        labels = []
    ),
    describe!(
        name = CHIO_FEDERATION_TRANSPORT_VERIFY_FAILURES_TOTAL,
        help = "Total iroh federation-transport verification failures by seam and bounded reason.",
        kind = Counter,
        labels = ["seam", "reason"]
    ),
    describe!(
        name = CHIO_GUARD_DENY_TOTAL,
        help = "Total WASM guard denies by reason class.",
        kind = Counter,
        labels = ["guard_id", "reason_class"]
    ),
    describe!(
        name = CHIO_GUARD_EVAL_DURATION_SECONDS,
        help = "WASM guard evaluation duration in seconds.",
        kind = Histogram,
        labels = ["guard_id", "verdict"],
        buckets = [
            "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5",
            "1.0"
        ]
    ),
    describe!(
        name = CHIO_GUARD_EVALUATIONS_TOTAL,
        help = "Total guard evaluation outcomes across native and WASM guards.",
        kind = Counter,
        labels = ["guard", "outcome"]
    ),
    describe!(
        name = CHIO_GUARD_FUEL_CONSUMED_TOTAL,
        help = "Total WASM guard fuel units consumed.",
        kind = Counter,
        labels = ["guard_id"]
    ),
    describe!(
        name = CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
        help = "WASM guard host-call duration in seconds.",
        kind = Histogram,
        labels = ["guard_id", "host_fn"],
        buckets =
            ["0.00001", "0.00005", "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1"]
    ),
    describe!(
        name = CHIO_GUARD_MODULE_BYTES,
        help = "Loaded WASM guard module size in bytes.",
        kind = Gauge,
        labels = ["guard_id", "epoch"]
    ),
    describe!(
        name = CHIO_GUARD_POOL_CHECKOUT_TOTAL,
        help = "Total WASM guard pool checkout outcomes by tenant.",
        kind = Counter,
        labels = ["guard_id", "tenant_id"]
    ),
    describe!(
        name = CHIO_GUARD_POOL_EVICT_TOTAL,
        help = "Total WASM guard pool evictions by tenant.",
        kind = Counter,
        labels = ["guard_id", "tenant_id"]
    ),
    describe!(
        name = CHIO_GUARD_POOL_WARM_SIZE,
        help = "Warm WASM guard pool size by tenant.",
        kind = Gauge,
        labels = ["guard_id", "tenant_id"]
    ),
    describe!(
        name = CHIO_GUARD_RELOAD_TOTAL,
        help = "Total WASM guard reload outcomes.",
        kind = Counter,
        labels = ["guard_id", "outcome"]
    ),
    describe!(
        name = CHIO_GUARD_VERDICT_TOTAL,
        help = "Total WASM guard verdicts by guard and verdict.",
        kind = Counter,
        labels = ["guard_id", "verdict"]
    ),
    describe!(
        name = CHIO_KERNEL_DECISION_LATENCY_SECONDS,
        help = "Kernel mediation decision latency in seconds.",
        kind = Histogram,
        labels = ["surface", "outcome"],
        buckets = ["0.025", "0.05", "0.075", "0.1", "0.25", "0.5", "1.0", "2.5"]
    ),
    describe!(
        name = CHIO_OTEL_INGRESS_DROP_TOTAL,
        help = "Total OTEL ingress batches dropped by bounded queue admission.",
        kind = Counter,
        labels = []
    ),
    describe!(
        name = CHIO_OTEL_SINK_DROP_TOTAL,
        help = "Total OTEL receipt sink batches dropped before append.",
        kind = Counter,
        labels = []
    ),
    describe!(
        name = CHIO_PHEROMONE_QUEUE_OVERFLOW_TOTAL,
        help = "Total local pheromone gossip queue overflows.",
        kind = Counter,
        labels = ["treaty", "recipient"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RECEIVER_DEPOSITS_TOTAL,
        help = "Total local pheromone receiver deposit admission outcomes.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RECEIVER_LATENCY_SECONDS,
        help = "Local pheromone receiver batch verification latency in seconds.",
        kind = Histogram,
        labels = ["outcome"],
        buckets = ["0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RECEIVER_REJECTIONS_TOTAL,
        help = "Total local pheromone receiver rejections by bounded reason.",
        kind = Counter,
        labels = ["reason"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_CATCHUP_BYTES_SERVED_TOTAL,
        help = "Total bounded catch-up bytes served by relay.",
        kind = Counter,
        labels = ["responder", "treaty"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_CATCHUP_DENIES_TOTAL,
        help = "Total bounded catch-up requests denied by reason.",
        kind = Counter,
        labels = ["reason"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_DEAD_LETTERS_TOTAL,
        help = "Total relay outbox batches moved to dead letter.",
        kind = Counter,
        labels = ["reason"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_DELIVERY_TOTAL,
        help = "Total live pheromone relay delivery outcomes.",
        kind = Counter,
        labels = ["recipient", "outcome"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_ENDPOINT_DENIED_TOTAL,
        help = "Total relay endpoints denied by profile lint or delivery policy.",
        kind = Counter,
        labels = ["profile", "reason"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_LATENCY_SECONDS,
        help = "Live pheromone relay delivery latency in seconds.",
        kind = Histogram,
        labels = ["outcome"],
        buckets = ["0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_NONCE_REPLAY_CONFLICTS_TOTAL,
        help = "Total relay nonce replay conflicts.",
        kind = Counter,
        labels = ["peer"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_OLDEST_PENDING_AGE_SECONDS,
        help = "Oldest pending relay outbox age in seconds.",
        kind = Gauge,
        labels = []
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_QUEUE_DEPTH,
        help = "Relay outbox depth by bounded status.",
        kind = Gauge,
        labels = ["status"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_REJECTIONS_TOTAL,
        help = "Total live pheromone relay rejections by bounded reason.",
        kind = Counter,
        labels = ["reason"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_STALE_DIRECTORIES_TOTAL,
        help = "Total stale peer-directory bundles or documents rejected.",
        kind = Counter,
        labels = ["profile"]
    ),
    describe!(
        name = CHIO_PHEROMONE_RELAY_STALE_LEASES,
        help = "Relay scheduler leases past their expiry.",
        kind = Gauge,
        labels = []
    ),
    describe!(
        name = CHIO_RECEIPT_SECONDS_SINCE_LAST_CHECKPOINT,
        help = "Seconds since the receipt-store checkpoint last advanced while data was pending on the local store.",
        kind = Gauge,
        labels = []
    ),
    describe!(
        name = CHIO_RECEIPT_UNCHECKPOINTED_SEQ_RANGE,
        help = "Uncheckpointed receipt entry_seq range (end - start) on the local store.",
        kind = Gauge,
        labels = []
    ),
    describe!(
        name = CHIO_RECEIPT_WRITE_LATENCY_SECONDS,
        help = "Receipt write latency at the local store boundary in seconds.",
        kind = Histogram,
        labels = ["store", "outcome"],
        buckets = ["0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0"]
    ),
    describe!(
        name = CHIO_RECEIPT_WRITE_TOTAL,
        help = "Total receipt write outcomes after policy or guard evaluation.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_SIDECAR_REQUESTS_TOTAL,
        help = "Total sidecar request outcomes at the mediation edge.",
        kind = Counter,
        labels = ["outcome"]
    ),
    describe!(
        name = CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
        help = "Total receipt signing requests blocked by bounded queue capacity or byte budget.",
        kind = Counter,
        labels = ["reason"]
    ),
    describe!(
        name = CHIO_SOC_EXPORT_LAG_SECONDS,
        help = "SOC export lag in seconds from receipt persistence to sink acknowledgement.",
        kind = Histogram,
        labels = ["exporter", "severity"],
        buckets = ["30", "60", "120", "300", "600", "1800"]
    ),
    describe!(
        name = CHIO_SOC_EXPORT_TOTAL,
        help = "Total SOC export outcomes for audit rows.",
        kind = Counter,
        labels = ["exporter", "outcome"]
    ),
    describe!(
        name = CHIO_TRUST_CONTROL_READY,
        help = "Trust-control readiness state, where 1 is ready and 0 is not ready.",
        kind = Gauge,
        labels = []
    ),
];

#[must_use]
pub fn descriptor_for(name: &str) -> Option<&'static MetricDescriptor> {
    REGISTRY.iter().find(|descriptor| descriptor.name == name)
}

#[must_use]
pub fn is_registered_metric(name: &str) -> bool {
    descriptor_for(name).is_some()
}

pub fn validate_metric_descriptor(
    descriptor: &MetricDescriptor,
) -> Result<(), MetricValidationError> {
    if !is_prometheus_metric_name(descriptor.name) {
        return Err(MetricValidationError::InvalidMetricName {
            name: descriptor.name,
        });
    }

    for (index, label) in descriptor.labels.iter().enumerate() {
        if !is_prometheus_label_name(label) {
            return Err(MetricValidationError::InvalidLabelName {
                metric: descriptor.name,
                label,
            });
        }
        if descriptor.labels[..index].contains(label) {
            return Err(MetricValidationError::DuplicateLabelName {
                metric: descriptor.name,
                label,
            });
        }
    }

    match descriptor.kind {
        MetricKind::Histogram => validate_histogram_buckets(descriptor),
        MetricKind::Counter | MetricKind::Gauge => {
            if descriptor.buckets.is_empty() {
                Ok(())
            } else {
                Err(MetricValidationError::UnexpectedBuckets {
                    metric: descriptor.name,
                    kind: descriptor.kind,
                })
            }
        }
    }
}

pub fn validate_registry() -> Result<(), MetricValidationError> {
    let mut previous = None;
    for descriptor in REGISTRY {
        validate_metric_descriptor(descriptor)?;
        if let Some(previous_name) = previous {
            if descriptor.name == previous_name {
                return Err(MetricValidationError::DuplicateMetricName {
                    metric: descriptor.name,
                });
            }
            if descriptor.name < previous_name {
                return Err(MetricValidationError::RegistryNotSorted {
                    previous: previous_name,
                    current: descriptor.name,
                });
            }
        }
        previous = Some(descriptor.name);
    }
    Ok(())
}

#[must_use]
pub fn is_prometheus_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(first, b'_' | b':'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
}

#[must_use]
pub fn is_prometheus_label_name(name: &str) -> bool {
    if name.starts_with("__") {
        return false;
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_histogram_buckets(descriptor: &MetricDescriptor) -> Result<(), MetricValidationError> {
    if descriptor.buckets.is_empty() {
        return Err(MetricValidationError::MissingHistogramBuckets {
            metric: descriptor.name,
        });
    }

    let mut previous_value = None;
    let mut previous_bucket = "";
    for bucket in descriptor.buckets {
        let Ok(value) = bucket.parse::<f64>() else {
            return Err(MetricValidationError::InvalidHistogramBucket {
                metric: descriptor.name,
                bucket,
            });
        };
        if !value.is_finite() {
            return Err(MetricValidationError::InvalidHistogramBucket {
                metric: descriptor.name,
                bucket,
            });
        }
        if let Some(previous) = previous_value {
            if value <= previous {
                return Err(MetricValidationError::NonIncreasingHistogramBucket {
                    metric: descriptor.name,
                    previous: previous_bucket,
                    bucket,
                });
            }
        }
        previous_value = Some(value);
        previous_bucket = bucket;
    }

    Ok(())
}

#[must_use]
pub fn registry_snapshot() -> String {
    let mut output = String::new();
    for descriptor in REGISTRY {
        output.push_str(descriptor.name);
        output.push('|');
        output.push_str(descriptor.kind.as_str());
        output.push('|');
        output.push_str(&descriptor.labels.join(","));
        output.push('|');
        output.push_str(&descriptor.buckets.join(","));
        output.push('|');
        output.push_str(descriptor.help);
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED_SRE_METRICS: &[&str] = &[
        CHIO_KERNEL_DECISION_LATENCY_SECONDS,
        CHIO_RECEIPT_WRITE_TOTAL,
        CHIO_GUARD_EVALUATIONS_TOTAL,
        CHIO_CAPABILITY_REVOCATION_LAG_SECONDS,
        CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
        CHIO_FEDERATION_HOP_TOTAL,
        CHIO_DLQ_DEPTH,
    ];

    #[test]
    fn golden_snapshot_matches_registry() {
        assert_eq!(registry_snapshot(), include_str!("../metrics.snapshot"));
    }

    #[test]
    fn registry_is_sorted_and_unique() {
        let mut previous = "";
        for descriptor in REGISTRY {
            assert!(
                descriptor.name > previous,
                "metric registry must stay sorted and unique: {} after {previous}",
                descriptor.name
            );
            previous = descriptor.name;
        }
    }

    #[test]
    fn registry_metric_and_label_names_are_prometheus_safe() {
        for descriptor in REGISTRY {
            assert!(
                is_prometheus_metric_name(descriptor.name),
                "invalid metric name {}",
                descriptor.name
            );
            for label in descriptor.labels {
                assert!(
                    is_prometheus_label_name(label),
                    "invalid label name {label} on {}",
                    descriptor.name
                );
            }
        }
    }

    #[test]
    fn registry_descriptors_pass_runtime_validation() {
        assert_eq!(validate_registry(), Ok(()));
        for descriptor in REGISTRY {
            assert_eq!(validate_metric_descriptor(descriptor), Ok(()));
        }
    }

    #[test]
    fn descriptor_validation_rejects_malformed_histogram_buckets() {
        let unordered = MetricDescriptor {
            name: "bad_latency_seconds",
            help: "Bad latency buckets.",
            kind: MetricKind::Histogram,
            labels: &[],
            buckets: &["0.1", "0.05"],
        };
        assert_eq!(
            validate_metric_descriptor(&unordered),
            Err(MetricValidationError::NonIncreasingHistogramBucket {
                metric: "bad_latency_seconds",
                previous: "0.1",
                bucket: "0.05",
            })
        );

        let invalid = MetricDescriptor {
            name: "bad_latency_seconds",
            help: "Bad latency buckets.",
            kind: MetricKind::Histogram,
            labels: &[],
            buckets: &["NaN"],
        };
        assert_eq!(
            validate_metric_descriptor(&invalid),
            Err(MetricValidationError::InvalidHistogramBucket {
                metric: "bad_latency_seconds",
                bucket: "NaN",
            })
        );
    }

    #[test]
    fn descriptor_validation_rejects_bucket_kind_mismatches() {
        let counter = MetricDescriptor {
            name: "bad_total",
            help: "Bad counter buckets.",
            kind: MetricKind::Counter,
            labels: &[],
            buckets: &["1"],
        };
        assert_eq!(
            validate_metric_descriptor(&counter),
            Err(MetricValidationError::UnexpectedBuckets {
                metric: "bad_total",
                kind: MetricKind::Counter,
            })
        );

        let histogram = MetricDescriptor {
            name: "bad_latency_seconds",
            help: "Missing latency buckets.",
            kind: MetricKind::Histogram,
            labels: &[],
            buckets: &[],
        };
        assert_eq!(
            validate_metric_descriptor(&histogram),
            Err(MetricValidationError::MissingHistogramBuckets {
                metric: "bad_latency_seconds",
            })
        );
    }

    #[test]
    fn prometheus_label_names_reject_reserved_internal_prefix() {
        assert!(!is_prometheus_label_name("__name__"));
        assert!(!is_prometheus_label_name("__tenant_id"));
    }

    #[test]
    fn required_sre_metrics_are_registered() {
        for name in REQUIRED_SRE_METRICS {
            assert!(is_registered_metric(name), "missing required metric {name}");
        }
    }

    #[test]
    fn labelled_metrics_have_expected_labels() {
        assert_eq!(
            descriptor_for(CHIO_RECEIPT_WRITE_TOTAL).map(|metric| metric.labels),
            Some(&["outcome"][..])
        );
        assert_eq!(
            descriptor_for(CHIO_GUARD_EVALUATIONS_TOTAL).map(|metric| metric.labels),
            Some(&["guard", "outcome"][..])
        );
        assert_eq!(
            descriptor_for(CHIO_FEDERATION_HOP_TOTAL).map(|metric| metric.labels),
            Some(&["result"][..])
        );
        assert_eq!(
            descriptor_for(CHIO_DLQ_DEPTH).map(|metric| metric.labels),
            Some(&["exporter"][..])
        );
    }
}
