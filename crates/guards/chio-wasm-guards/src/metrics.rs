//! Prometheus metric family descriptors for WASM guard observability.
//!
//! The `METRIC_CHIO_*` names are re-exported from `chio_metrics_spec` so the
//! workspace registry is the single source of truth for Prometheus metric
//! names.

use std::collections::{BTreeMap, BTreeSet};

pub use chio_metrics_spec::{
    CHIO_GUARD_DENY_TOTAL as METRIC_CHIO_GUARD_DENY_TOTAL,
    CHIO_GUARD_EVAL_DURATION_SECONDS as METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS,
    CHIO_GUARD_FUEL_CONSUMED_TOTAL as METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL,
    CHIO_GUARD_HOST_CALL_DURATION_SECONDS as METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
    CHIO_GUARD_MODULE_BYTES as METRIC_CHIO_GUARD_MODULE_BYTES,
    CHIO_GUARD_POOL_CHECKOUT_TOTAL as METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
    CHIO_GUARD_POOL_EVICT_TOTAL as METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
    CHIO_GUARD_POOL_WARM_SIZE as METRIC_CHIO_GUARD_POOL_WARM_SIZE,
    CHIO_GUARD_RELOAD_TOTAL as METRIC_CHIO_GUARD_RELOAD_TOTAL,
    CHIO_GUARD_VERDICT_TOTAL as METRIC_CHIO_GUARD_VERDICT_TOTAL,
    CHIO_OTEL_INGRESS_DROP_TOTAL as METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL,
    CHIO_OTEL_SINK_DROP_TOTAL as METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
    CHIO_SIGNING_QUEUE_BLOCK_TOTAL as METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
};

use crate::observability::{
    HOST_FETCH_BLOB, HOST_GET_CONFIG, HOST_GET_TIME_UNIX_SECS, HOST_LOG, RELOAD_APPLIED,
    RELOAD_CANARY_FAILED, RELOAD_ROLLED_BACK, VERDICT_ALLOW, VERDICT_DENY, VERDICT_ERROR,
    VERDICT_REWRITE,
};

pub const MAX_GUARD_METRIC_CARDINALITY: usize = 1024;
pub const E_GUARD_METRIC_CARDINALITY_EXCEEDED: &str = "E_GUARD_METRIC_CARDINALITY_EXCEEDED";
pub const OVERFLOW_TENANT_ID: &str = "__overflow__";
pub const UNKNOWN_TENANT_ID: &str = "unknown";

pub const LABEL_GUARD_ID: &str = "guard_id";
pub const LABEL_VERDICT: &str = "verdict";
pub const LABEL_REASON_CLASS: &str = "reason_class";
pub const LABEL_OUTCOME: &str = "outcome";
pub const LABEL_HOST_FN: &str = "host_fn";
pub const LABEL_EPOCH: &str = "epoch";
pub const LABEL_TENANT_ID: &str = "tenant_id";

pub const EVAL_DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

pub const HOST_CALL_DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1,
];

pub const VERDICT_LABEL_VALUES: &[&str] =
    &[VERDICT_ALLOW, VERDICT_DENY, VERDICT_REWRITE, VERDICT_ERROR];

pub const REASON_CLASS_LABEL_VALUES: &[&str] = &[
    "policy",
    "pii",
    "secret",
    "prompt_injection",
    "oversize",
    "fuel",
    "trap",
];

pub const HOST_FN_LABEL_VALUES: &[&str] = &[
    HOST_LOG,
    HOST_GET_CONFIG,
    HOST_GET_TIME_UNIX_SECS,
    HOST_FETCH_BLOB,
];

pub const RELOAD_OUTCOME_LABEL_VALUES: &[&str] =
    &[RELOAD_APPLIED, RELOAD_CANARY_FAILED, RELOAD_ROLLED_BACK];

const LABELS_GUARD_VERDICT: &[&str] = &[LABEL_GUARD_ID, LABEL_VERDICT];
const LABELS_GUARD_ONLY: &[&str] = &[LABEL_GUARD_ID];
const LABELS_GUARD_REASON_CLASS: &[&str] = &[LABEL_GUARD_ID, LABEL_REASON_CLASS];
const LABELS_GUARD_OUTCOME: &[&str] = &[LABEL_GUARD_ID, LABEL_OUTCOME];
const LABELS_GUARD_HOST_FN: &[&str] = &[LABEL_GUARD_ID, LABEL_HOST_FN];
const LABELS_GUARD_EPOCH: &[&str] = &[LABEL_GUARD_ID, LABEL_EPOCH];
const LABELS_GUARD_TENANT: &[&str] = &[LABEL_GUARD_ID, LABEL_TENANT_ID];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricFamilyKind {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricFamilyDescriptor {
    pub name: &'static str,
    pub kind: MetricFamilyKind,
    pub labels: &'static [&'static str],
    pub unit: Option<&'static str>,
    pub buckets: &'static [f64],
}

pub const GUARD_METRIC_FAMILIES: &[MetricFamilyDescriptor] = &[
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS,
        kind: MetricFamilyKind::Histogram,
        labels: LABELS_GUARD_VERDICT,
        unit: Some("seconds"),
        buckets: EVAL_DURATION_BUCKETS_SECONDS,
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_ONLY,
        unit: Some("fuel units"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_VERDICT_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_VERDICT,
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_DENY_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_REASON_CLASS,
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_RELOAD_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_OUTCOME,
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
        kind: MetricFamilyKind::Histogram,
        labels: LABELS_GUARD_HOST_FN,
        unit: Some("seconds"),
        buckets: HOST_CALL_DURATION_BUCKETS_SECONDS,
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_MODULE_BYTES,
        kind: MetricFamilyKind::Gauge,
        labels: LABELS_GUARD_EPOCH,
        unit: Some("bytes"),
        buckets: &[],
    },
];

pub const GUARD_POOL_METRIC_FAMILIES: &[MetricFamilyDescriptor] = &[
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_TENANT,
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_POOL_WARM_SIZE,
        kind: MetricFamilyKind::Gauge,
        labels: LABELS_GUARD_TENANT,
        unit: Some("instances"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: LABELS_GUARD_TENANT,
        unit: Some("count"),
        buckets: &[],
    },
];

pub const RUNTIME_METRIC_FAMILIES: &[MetricFamilyDescriptor] = &[
    MetricFamilyDescriptor {
        name: METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: &[],
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: &[],
        unit: Some("count"),
        buckets: &[],
    },
    MetricFamilyDescriptor {
        name: METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
        kind: MetricFamilyKind::Counter,
        labels: &[],
        unit: Some("count"),
        buckets: &[],
    },
];

#[derive(Debug, Clone)]
pub struct GuardMetricRegistry {
    families: &'static [MetricFamilyDescriptor],
    guard_ids: BTreeSet<String>,
    max_guards: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardMetricRegistrationError {
    code: &'static str,
    guard_id: String,
    attempted: usize,
    limit: usize,
}

impl GuardMetricRegistrationError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    #[must_use]
    pub fn attempted(&self) -> usize {
        self.attempted
    }

    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    fn cardinality_exceeded(guard_id: String, attempted: usize, limit: usize) -> Self {
        Self {
            code: E_GUARD_METRIC_CARDINALITY_EXCEEDED,
            guard_id,
            attempted,
            limit,
        }
    }
}

impl std::fmt::Display for GuardMetricRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: registering guard {} would create {} metric guard IDs, limit {}",
            self.code, self.guard_id, self.attempted, self.limit
        )
    }
}

impl std::error::Error for GuardMetricRegistrationError {}

impl GuardMetricRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_guards(MAX_GUARD_METRIC_CARDINALITY)
    }

    #[must_use]
    pub fn with_max_guards(max_guards: usize) -> Self {
        Self::with_families(GUARD_METRIC_FAMILIES, max_guards)
    }

    #[must_use]
    pub fn with_families(families: &'static [MetricFamilyDescriptor], max_guards: usize) -> Self {
        Self {
            families,
            guard_ids: BTreeSet::new(),
            max_guards,
        }
    }

    #[must_use]
    pub fn families(&self) -> &'static [MetricFamilyDescriptor] {
        self.families
    }

    #[must_use]
    pub fn family(&self, name: &str) -> Option<&'static MetricFamilyDescriptor> {
        self.families.iter().find(|family| family.name == name)
    }

    #[must_use]
    pub fn max_guards(&self) -> usize {
        self.max_guards
    }

    #[must_use]
    pub fn registered_guard_count(&self) -> usize {
        self.guard_ids.len()
    }

    pub fn register_guard_digest(
        &mut self,
        digest: &str,
    ) -> Result<String, GuardMetricRegistrationError> {
        let guard_id = guard_id_label_from_digest(digest);
        self.register_guard_id(guard_id.clone())?;
        Ok(guard_id)
    }

    pub fn register_guard_id(
        &mut self,
        guard_id: impl Into<String>,
    ) -> Result<(), GuardMetricRegistrationError> {
        let guard_id = guard_id.into();
        if self.guard_ids.contains(&guard_id) {
            return Ok(());
        }

        let attempted = self.guard_ids.len() + 1;
        if attempted > self.max_guards {
            return Err(GuardMetricRegistrationError::cardinality_exceeded(
                guard_id,
                attempted,
                self.max_guards,
            ));
        }

        self.guard_ids.insert(guard_id);
        Ok(())
    }
}

impl Default for GuardMetricRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn register_guard_metric_families() -> GuardMetricRegistry {
    GuardMetricRegistry::new()
}

#[must_use]
pub fn register_guard_pool_metric_families() -> GuardMetricRegistry {
    GuardMetricRegistry::with_families(GUARD_POOL_METRIC_FAMILIES, MAX_GUARD_METRIC_CARDINALITY)
}

#[must_use]
pub fn guard_id_label_from_digest(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .chars()
        .take(12)
        .collect()
}

#[must_use]
pub fn epoch_label(epoch: u64) -> String {
    epoch.to_string()
}

#[must_use]
pub fn tenant_id_label(tenant_id: &str) -> String {
    let tenant_id = tenant_id.trim();
    if tenant_id.is_empty() {
        UNKNOWN_TENANT_ID.to_string()
    } else {
        tenant_id.to_string()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuardPoolMetricsSnapshot {
    pub checkout_total: u64,
    pub warm_size: u64,
    pub evict_total: u64,
}

#[derive(Debug, Clone)]
pub struct GuardPoolMetrics {
    registry: GuardMetricRegistry,
    tenant_snapshots: BTreeMap<String, GuardPoolMetricsSnapshot>,
    overflow_snapshot: GuardPoolMetricsSnapshot,
}

impl GuardPoolMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_tenants(MAX_GUARD_METRIC_CARDINALITY)
    }

    #[must_use]
    pub fn with_max_tenants(max_tenants: usize) -> Self {
        Self {
            registry: GuardMetricRegistry::with_families(GUARD_POOL_METRIC_FAMILIES, max_tenants),
            tenant_snapshots: BTreeMap::new(),
            overflow_snapshot: GuardPoolMetricsSnapshot::default(),
        }
    }

    #[must_use]
    pub fn families(&self) -> &'static [MetricFamilyDescriptor] {
        self.registry.families()
    }

    #[must_use]
    pub fn registered_tenant_count(&self) -> usize {
        self.registry.registered_guard_count()
    }

    #[must_use]
    pub fn max_tenants(&self) -> usize {
        self.registry.max_guards()
    }

    pub fn record_checkout(&mut self, tenant_id: &str) {
        let snapshot = self.snapshot_mut(tenant_id);
        snapshot.checkout_total = snapshot.checkout_total.saturating_add(1);
    }

    pub fn set_warm_size(&mut self, tenant_id: &str, warm_size: usize) {
        let snapshot = self.snapshot_mut(tenant_id);
        snapshot.warm_size = warm_size as u64;
    }

    pub fn record_evict(&mut self, tenant_id: &str) {
        let snapshot = self.snapshot_mut(tenant_id);
        snapshot.evict_total = snapshot.evict_total.saturating_add(1);
    }

    #[must_use]
    pub fn snapshot(&self, tenant_id: &str) -> Option<GuardPoolMetricsSnapshot> {
        let tenant_id = tenant_id_label(tenant_id);
        if tenant_id == OVERFLOW_TENANT_ID {
            Some(self.overflow_snapshot)
        } else {
            self.tenant_snapshots.get(&tenant_id).copied()
        }
    }

    #[must_use]
    pub fn overflow_snapshot(&self) -> GuardPoolMetricsSnapshot {
        self.overflow_snapshot
    }

    pub fn reset_warm_sizes(&mut self) {
        for snapshot in self.tenant_snapshots.values_mut() {
            snapshot.warm_size = 0;
        }
        self.overflow_snapshot.warm_size = 0;
    }

    fn snapshot_mut(&mut self, tenant_id: &str) -> &mut GuardPoolMetricsSnapshot {
        let tenant_id = tenant_id_label(tenant_id);
        if tenant_id == OVERFLOW_TENANT_ID {
            return &mut self.overflow_snapshot;
        }
        if self.tenant_snapshots.contains_key(&tenant_id) {
            return match self.tenant_snapshots.get_mut(&tenant_id) {
                Some(snapshot) => snapshot,
                None => &mut self.overflow_snapshot,
            };
        }
        if self.registry.register_guard_id(tenant_id.clone()).is_ok() {
            self.tenant_snapshots.entry(tenant_id).or_default()
        } else {
            &mut self.overflow_snapshot
        }
    }
}

impl Default for GuardPoolMetrics {
    fn default() -> Self {
        Self::new()
    }
}
