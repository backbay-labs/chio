//! ACP edge metrics surfaced through the workspace `chio-metrics-spec`
//! registry. Wave 2.4 of the trj4 closeout wires the ACP edge into the
//! workspace registry: every ACP invocation result emerging from the
//! kernel boundary increments [`CHIO_RECEIPT_WRITE_TOTAL`] with an
//! `outcome` label.
//
// TODO(wave-3): the recorder/renderer/static-counter triplet here is
// duplicated near-identically across `chio-mcp-edge`, `chio-a2a-edge`, and
// this crate. A Wave 3 follow-up will extract a shared
// `ReceiptWriteCounters` helper into `chio-metrics-spec` (or a new
// `chio-metrics-emit` crate) so each edge becomes a thin wrapper. The
// per-edge static atomics and the renderer function names
// (`render_<edge>_edge_metrics_prometheus`) are load-bearing for the
// W2.4 conformance test surface, so the extraction has to preserve both.

use std::sync::atomic::{AtomicU64, Ordering};

use chio_kernel::Verdict;
pub use chio_metrics_spec::CHIO_RECEIPT_WRITE_TOTAL;

pub const RECEIPT_WRITE_OUTCOME_ALLOW: &str = "allow";
pub const RECEIPT_WRITE_OUTCOME_DENY: &str = "deny";
pub const RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL: &str = "pending_approval";
pub const RECEIPT_WRITE_OUTCOME_ERROR: &str = "error";

static RECEIPT_WRITE_ALLOW: AtomicU64 = AtomicU64::new(0);
static RECEIPT_WRITE_DENY: AtomicU64 = AtomicU64::new(0);
static RECEIPT_WRITE_PENDING_APPROVAL: AtomicU64 = AtomicU64::new(0);
static RECEIPT_WRITE_ERROR: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn receipt_write_outcome_for_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => RECEIPT_WRITE_OUTCOME_ALLOW,
        Verdict::Deny => RECEIPT_WRITE_OUTCOME_DENY,
        Verdict::PendingApproval => RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
    }
}

pub(crate) fn record_receipt_write_verdict(verdict: Verdict) {
    record_receipt_write(receipt_write_outcome_for_verdict(verdict));
}

pub(crate) fn record_receipt_write(outcome: &str) {
    match outcome {
        RECEIPT_WRITE_OUTCOME_ALLOW => {
            RECEIPT_WRITE_ALLOW.fetch_add(1, Ordering::Relaxed);
        }
        RECEIPT_WRITE_OUTCOME_DENY => {
            RECEIPT_WRITE_DENY.fetch_add(1, Ordering::Relaxed);
        }
        RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL => {
            RECEIPT_WRITE_PENDING_APPROVAL.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            RECEIPT_WRITE_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[must_use]
pub fn receipt_write_total(outcome: &str) -> u64 {
    match outcome {
        RECEIPT_WRITE_OUTCOME_ALLOW => RECEIPT_WRITE_ALLOW.load(Ordering::Relaxed),
        RECEIPT_WRITE_OUTCOME_DENY => RECEIPT_WRITE_DENY.load(Ordering::Relaxed),
        RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL => {
            RECEIPT_WRITE_PENDING_APPROVAL.load(Ordering::Relaxed)
        }
        _ => RECEIPT_WRITE_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn render_acp_edge_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
    output.push_str(" Total receipt write outcomes after policy or guard evaluation.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
    output.push_str(" counter\n");
    for outcome in [
        RECEIPT_WRITE_OUTCOME_ALLOW,
        RECEIPT_WRITE_OUTCOME_DENY,
        RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
        RECEIPT_WRITE_OUTCOME_ERROR,
    ] {
        output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
        output.push_str("{outcome=\"");
        output.push_str(outcome);
        output.push_str("\"} ");
        output.push_str(&receipt_write_total(outcome).to_string());
        output.push('\n');
    }
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
        let body = render_acp_edge_metrics_prometheus();
        assert!(body.contains("outcome=\"pending_approval\""));
    }
}
