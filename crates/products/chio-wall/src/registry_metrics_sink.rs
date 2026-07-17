//! Registry-backed SiemMetricsSink: forwards SIEM emission into the
//! chio-metrics-spec runtime families. Kept in the host so chio-siem stays
//! decoupled from the metric registry.

use chio_siem::{ExportOutcome, SiemMetricsSink};

pub struct RegistryMetricsSink;

impl SiemMetricsSink for RegistryMetricsSink {
    fn record_export(&self, exporter: &str, outcome: ExportOutcome) {
        chio_metrics_spec::runtime::families::SOC_EXPORT_TOTAL
            .incr(&[exporter, outcome.as_label()]);
    }
    fn observe_export_lag(&self, exporter: &str, severity: &str, lag_seconds: f64) {
        chio_metrics_spec::runtime::families::SOC_EXPORT_LAG
            .observe(&[exporter, severity], lag_seconds);
    }
    fn set_dlq_depth(&self, exporter: &str, depth: u64) {
        chio_metrics_spec::runtime::families::DLQ_DEPTH.set(&[exporter], depth);
    }
    fn record_alert_dispatch(&self, route: &str, outcome: &str) {
        chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.incr(&[route, outcome]);
    }
    fn observe_alert_dispatch_latency(&self, route: &str, outcome: &str, latency_seconds: f64) {
        chio_metrics_spec::runtime::families::ALERT_DISPATCH_LATENCY
            .observe(&[route, outcome], latency_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_forwards_export_outcome_to_runtime_family() {
        let sink = RegistryMetricsSink;
        sink.record_export("splunk-13", ExportOutcome::Dlq);
        let mut body = String::new();
        chio_metrics_spec::runtime::families::SOC_EXPORT_TOTAL.render(&mut body);
        assert!(
            body.contains("chio_soc_export_total{exporter=\"splunk-13\",outcome=\"dlq\"}"),
            "{body}"
        );
    }
}
