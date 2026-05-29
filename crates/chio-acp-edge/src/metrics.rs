//! ACP edge metrics surfaced through the workspace `chio-metrics-spec`
//! registry. The ACP edge is wired into the workspace registry: every ACP
//! invocation result emerging from the kernel boundary increments
//! [`CHIO_RECEIPT_WRITE_TOTAL`] with an `outcome` label.
//!
//! The shared recorder/renderer/counter logic lives in `chio-edge-metrics`.
//! This module owns the ACP edge's own counter instance and re-exports the
//! edge-facing surface so callers keep using `crate::metrics::*`.

use chio_edge_metrics::ReceiptWriteCounters;
use chio_kernel::Verdict;

pub use chio_edge_metrics::{
    receipt_write_outcome_for_verdict, CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_ALLOW,
    RECEIPT_WRITE_OUTCOME_DENY, RECEIPT_WRITE_OUTCOME_ERROR,
    RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};

/// ACP edge receipt-write counters. Independent of every other edge's
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

#[must_use]
pub fn render_acp_edge_metrics_prometheus() -> String {
    COUNTERS.render_prometheus()
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
        let body = render_acp_edge_metrics_prometheus();
        assert!(body.contains("outcome=\"pending_approval\""));
    }
}
