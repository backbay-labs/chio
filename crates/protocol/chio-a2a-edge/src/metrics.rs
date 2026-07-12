//! A2A edge metrics surfaced through the workspace `chio-metrics-spec`
//! registry. The A2A edge is wired into the workspace registry: every A2A
//! task response emerging from the kernel boundary increments
//! [`CHIO_RECEIPT_WRITE_TOTAL`] with an `outcome` label.
//!
//! The shared recorder/renderer/counter logic lives in `chio-edge-metrics`.
//! This module owns the A2A edge's own counter instance and re-exports the
//! edge-facing surface so callers keep using `crate::metrics::*`.

use chio_edge_metrics::ReceiptWriteCounters;
use chio_kernel::{ReceiptWriterLiveness, Verdict};

pub use chio_edge_metrics::{
    receipt_write_outcome_for_verdict, CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW,
    RECEIPT_WRITE_OUTCOME_DENY, RECEIPT_WRITE_OUTCOME_ERROR,
    RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

/// A2A edge receipt-write counters. Independent of every other edge's
/// counters so per-edge isolation assertions hold.
static COUNTERS: ReceiptWriteCounters = ReceiptWriteCounters::new();

pub(crate) fn record_receipt_write_verdict(verdict: Verdict) {
    COUNTERS.record_verdict(verdict);
}

pub(crate) fn record_receipt_write(outcome: &str) {
    COUNTERS.record(outcome);
}

#[must_use]
pub fn receipt_write_total(outcome: &str) -> u64 {
    COUNTERS.total(outcome)
}

/// Render the A2A edge Prometheus exposition for the registry-keyed series.
///
/// Emits the receipt-write outcome counters followed by the serving store's
/// receipt-writer liveness gauges, so a wedged or dead writer is visible on the
/// same scrape as the outcome totals. `writer_liveness` is the serving kernel or
/// store's current [`ReceiptWriterLiveness`]; pass
/// [`ReceiptWriterLiveness::Unknown`] when no async writer is wired.
#[must_use]
pub fn render_a2a_edge_metrics_prometheus(writer_liveness: ReceiptWriterLiveness) -> String {
    let mut output = COUNTERS.render_prometheus();
    output.push_str(&chio_edge_metrics::render_receipt_writer_liveness(
        writer_liveness.as_label(),
        writer_liveness.healthy(),
    ));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_RECEIPT_WRITE_TOTAL, "chio_receipt_write_total");
    }

    #[test]
    fn render_includes_pending_approval_outcome_label() {
        record_receipt_write(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
        let body = render_a2a_edge_metrics_prometheus(ReceiptWriterLiveness::Healthy);
        assert!(body.contains("outcome=\"pending_approval\""));
    }

    #[test]
    fn render_exposes_writer_liveness_gauges() {
        // The exposition must carry the receipt-writer liveness gauges so a
        // wedged or dead writer is observable at the edge scrape.
        let body = render_a2a_edge_metrics_prometheus(ReceiptWriterLiveness::Wedged);
        assert!(body.contains("chio_receipt_writer_healthy 0"));
        assert!(body.contains("chio_receipt_writer_liveness{state=\"wedged\"} 1"));
    }
}
