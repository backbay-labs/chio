//! Metric emission seam for the SIEM path. Keeps chio-siem decoupled from the
//! metric registry: the manager and the alerting exporter call this trait; the
//! host installs a registry-backed sink.

use std::sync::Arc;

/// Per-row export outcome. Every export path (including malformed/dlq/error)
/// records one outcome, never only `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOutcome {
    Ok,
    Malformed,
    Dlq,
    Error,
}

impl ExportOutcome {
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            // A successful export is labeled "success" (not "ok") so it agrees
            // with the shipped `chio:soc_export_error_ratio_*` recording rules,
            // whose numerator is `chio_soc_export_total{outcome!="success"}`. An
            // "ok" label would be counted as an error and drive the SOC export
            // error-budget alerts to 100% even when every export succeeds.
            ExportOutcome::Ok => "success",
            ExportOutcome::Malformed => "malformed",
            ExportOutcome::Dlq => "dlq",
            ExportOutcome::Error => "error",
        }
    }
}

/// Infallible by contract: a metric write never aborts export (fail-closed at
/// the system level).
pub trait SiemMetricsSink: Send + Sync {
    fn record_export(&self, exporter: &str, outcome: ExportOutcome);
    fn observe_export_lag(&self, exporter: &str, severity: &str, lag_seconds: f64);
    fn set_dlq_depth(&self, exporter: &str, depth: u64);
    fn record_alert_dispatch(&self, route: &str, outcome: &str);
    fn observe_alert_dispatch_latency(&self, route: &str, outcome: &str, latency_seconds: f64);
}

/// Default sink: does nothing, so chio-siem runs headless.
pub struct NoopMetricsSink;

impl SiemMetricsSink for NoopMetricsSink {
    fn record_export(&self, _exporter: &str, _outcome: ExportOutcome) {}
    fn observe_export_lag(&self, _exporter: &str, _severity: &str, _lag_seconds: f64) {}
    fn set_dlq_depth(&self, _exporter: &str, _depth: u64) {}
    fn record_alert_dispatch(&self, _route: &str, _outcome: &str) {}
    fn observe_alert_dispatch_latency(&self, _route: &str, _outcome: &str, _latency_seconds: f64) {}
}

#[must_use]
pub fn noop_metrics_sink() -> Arc<dyn SiemMetricsSink> {
    Arc::new(NoopMetricsSink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct CountingSink {
        exports: AtomicU64,
    }
    impl SiemMetricsSink for CountingSink {
        fn record_export(&self, _exporter: &str, _outcome: ExportOutcome) {
            self.exports.fetch_add(1, Ordering::Relaxed);
        }
        fn observe_export_lag(&self, _: &str, _: &str, _: f64) {}
        fn set_dlq_depth(&self, _: &str, _: u64) {}
        fn record_alert_dispatch(&self, _: &str, _: &str) {}
        fn observe_alert_dispatch_latency(&self, _: &str, _: &str, _: f64) {}
    }

    #[test]
    fn outcome_labels_are_stable() {
        assert_eq!(ExportOutcome::Malformed.as_label(), "malformed");
        assert_eq!(ExportOutcome::Dlq.as_label(), "dlq");
    }

    #[test]
    fn successful_export_uses_success_outcome_for_recording_rules() {
        // The soc_export_error_ratio recording rules count outcome!="success" as
        // an error, so a successful export MUST carry the "success" outcome or
        // the SOC export error budget reads as 100% while everything succeeds.
        assert_eq!(ExportOutcome::Ok.as_label(), "success");
    }

    #[test]
    fn manager_accepts_a_custom_sink_without_changing_new() {
        // ExporterManager::new still takes only SiemConfig; the sink is attached
        // via the builder method, defaulting to no-op.
        let sink = Arc::new(CountingSink::default());
        sink.record_export("splunk", ExportOutcome::Ok);
        assert_eq!(sink.exports.load(Ordering::Relaxed), 1);
    }
}
