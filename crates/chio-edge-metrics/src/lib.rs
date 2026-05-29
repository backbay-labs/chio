//! Shared receipt-write metrics sink for Chio protocol edge crates.
//!
//! Every Chio protocol edge (MCP, ACP, A2A, ...) surfaces the same
//! `chio_receipt_write_total` series through the workspace
//! `chio-metrics-spec` registry: each response emerging from the kernel
//! boundary increments [`CHIO_RECEIPT_WRITE_TOTAL`] with an `outcome` label.
//!
//! The recorder, accessor, and renderer logic is identical across edges, so
//! it lives here once. Counter *state*, however, must stay per-edge: the
//! conformance smoke test asserts that an ACP dispatch does not advance the
//! MCP counter (and vice versa). To preserve that isolation, this crate
//! exposes a [`ReceiptWriteCounters`] instance type rather than module-level
//! statics; each edge crate declares its own `static` instance and delegates
//! to it.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use chio_kernel::Verdict;
pub use chio_metrics_spec::CHIO_RECEIPT_WRITE_TOTAL;

/// Allowed outcome label values for [`CHIO_RECEIPT_WRITE_TOTAL`].
pub const RECEIPT_WRITE_OUTCOME_ALLOW: &str = "allow";
pub const RECEIPT_WRITE_OUTCOME_DENY: &str = "deny";
pub const RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL: &str = "pending_approval";
pub const RECEIPT_WRITE_OUTCOME_ERROR: &str = "error";

/// Map a kernel [`Verdict`] to its receipt-write outcome label.
#[must_use]
pub fn receipt_write_outcome_for_verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => RECEIPT_WRITE_OUTCOME_ALLOW,
        Verdict::Deny => RECEIPT_WRITE_OUTCOME_DENY,
        Verdict::PendingApproval => RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
    }
}

/// Per-edge receipt-write counter set.
///
/// Each protocol edge owns one `static` instance so that counters stay
/// isolated across edges. The recorder and renderer behavior is shared.
#[derive(Debug)]
pub struct ReceiptWriteCounters {
    allow: AtomicU64,
    deny: AtomicU64,
    pending_approval: AtomicU64,
    error: AtomicU64,
}

impl ReceiptWriteCounters {
    /// Construct a zeroed counter set. Usable in `static` initializers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allow: AtomicU64::new(0),
            deny: AtomicU64::new(0),
            pending_approval: AtomicU64::new(0),
            error: AtomicU64::new(0),
        }
    }

    /// Record the receipt-write outcome implied by a kernel [`Verdict`].
    pub fn record_verdict(&self, verdict: Verdict) {
        self.record(receipt_write_outcome_for_verdict(verdict));
    }

    /// Record a receipt-write outcome at the edge sink boundary.
    ///
    /// `outcome` must be one of [`RECEIPT_WRITE_OUTCOME_ALLOW`],
    /// [`RECEIPT_WRITE_OUTCOME_DENY`],
    /// [`RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL`], or
    /// [`RECEIPT_WRITE_OUTCOME_ERROR`].
    /// Unknown values are recorded under the error counter so the gauge does
    /// not silently drop emissions.
    pub fn record(&self, outcome: &str) {
        match outcome {
            RECEIPT_WRITE_OUTCOME_ALLOW => {
                self.allow.fetch_add(1, Ordering::Relaxed);
            }
            RECEIPT_WRITE_OUTCOME_DENY => {
                self.deny.fetch_add(1, Ordering::Relaxed);
            }
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL => {
                self.pending_approval.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Read the current count for an outcome label. Unknown labels map to
    /// the error counter, mirroring [`Self::record`].
    #[must_use]
    pub fn total(&self, outcome: &str) -> u64 {
        match outcome {
            RECEIPT_WRITE_OUTCOME_ALLOW => self.allow.load(Ordering::Relaxed),
            RECEIPT_WRITE_OUTCOME_DENY => self.deny.load(Ordering::Relaxed),
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL => self.pending_approval.load(Ordering::Relaxed),
            _ => self.error.load(Ordering::Relaxed),
        }
    }

    /// Render the edge Prometheus exposition for the registry-keyed series.
    /// The format is intentionally kept minimal: one `# HELP`/`# TYPE` block
    /// plus one labelled sample per outcome.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
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
            output.push_str(&self.total(outcome).to_string());
            output.push('\n');
        }
        output
    }
}

impl Default for ReceiptWriteCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_RECEIPT_WRITE_TOTAL, "chio_receipt_write_total");
    }

    #[test]
    fn render_includes_registry_name_and_outcome_labels() {
        let counters = ReceiptWriteCounters::new();
        counters.record(RECEIPT_WRITE_OUTCOME_ALLOW);
        let body = counters.render_prometheus();
        assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
        assert!(body.contains("outcome=\"allow\""));
        assert!(body.contains("outcome=\"pending_approval\""));
    }

    #[test]
    fn counters_are_isolated_per_instance() {
        let a = ReceiptWriteCounters::new();
        let b = ReceiptWriteCounters::new();
        a.record(RECEIPT_WRITE_OUTCOME_ALLOW);
        assert_eq!(a.total(RECEIPT_WRITE_OUTCOME_ALLOW), 1);
        assert_eq!(b.total(RECEIPT_WRITE_OUTCOME_ALLOW), 0);
    }

    #[test]
    fn unknown_outcome_records_under_error() {
        let counters = ReceiptWriteCounters::new();
        counters.record("totally-unknown");
        assert_eq!(counters.total(RECEIPT_WRITE_OUTCOME_ERROR), 1);
        assert_eq!(counters.total("totally-unknown"), 1);
    }

    #[test]
    fn verdict_maps_to_expected_outcome() {
        assert_eq!(
            receipt_write_outcome_for_verdict(Verdict::Allow),
            RECEIPT_WRITE_OUTCOME_ALLOW
        );
        assert_eq!(
            receipt_write_outcome_for_verdict(Verdict::Deny),
            RECEIPT_WRITE_OUTCOME_DENY
        );
        assert_eq!(
            receipt_write_outcome_for_verdict(Verdict::PendingApproval),
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL
        );
    }
}
