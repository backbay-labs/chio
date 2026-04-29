//! Prometheus metric family descriptors for WASM guard observability.

use std::collections::BTreeSet;

use crate::observability::{
    HOST_FETCH_BLOB, HOST_GET_CONFIG, HOST_GET_TIME_UNIX_SECS, HOST_LOG, RELOAD_APPLIED,
    RELOAD_CANARY_FAILED, RELOAD_ROLLED_BACK, VERDICT_ALLOW, VERDICT_DENY, VERDICT_ERROR,
    VERDICT_REWRITE,
};

pub const METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS: &str = "chio_guard_eval_duration_seconds";
pub const METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL: &str = "chio_guard_fuel_consumed_total";
pub const METRIC_CHIO_GUARD_VERDICT_TOTAL: &str = "chio_guard_verdict_total";
pub const METRIC_CHIO_GUARD_DENY_TOTAL: &str = "chio_guard_deny_total";
pub const METRIC_CHIO_GUARD_RELOAD_TOTAL: &str = "chio_guard_reload_total";
pub const METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS: &str =
    "chio_guard_host_call_duration_seconds";
pub const METRIC_CHIO_GUARD_MODULE_BYTES: &str = "chio_guard_module_bytes";

pub const MAX_GUARD_METRIC_CARDINALITY: usize = 1024;
pub const E_GUARD_METRIC_CARDINALITY_EXCEEDED: &str = "E_GUARD_METRIC_CARDINALITY_EXCEEDED";

pub const LABEL_GUARD_ID: &str = "guard_id";
pub const LABEL_VERDICT: &str = "verdict";
pub const LABEL_REASON_CLASS: &str = "reason_class";
pub const LABEL_OUTCOME: &str = "outcome";
pub const LABEL_HOST_FN: &str = "host_fn";
pub const LABEL_EPOCH: &str = "epoch";

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
        Self {
            families: GUARD_METRIC_FAMILIES,
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
