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

/// Receipt-writer liveness gauges. `healthy` is 0/1; `liveness` is a labeled
/// series carrying the current writer state.
pub const CHIO_RECEIPT_WRITER_HEALTHY: &str = "chio_receipt_writer_healthy";
pub const CHIO_RECEIPT_WRITER_LIVENESS: &str = "chio_receipt_writer_liveness";

/// Stable exporter order for receipt-write outcome samples.
pub const RECEIPT_WRITE_OUTCOMES: [ReceiptWriteOutcome; 4] = [
    ReceiptWriteOutcome::Allow,
    ReceiptWriteOutcome::Deny,
    ReceiptWriteOutcome::PendingApproval,
    ReceiptWriteOutcome::Error,
];

/// Closed outcome taxonomy for [`CHIO_RECEIPT_WRITE_TOTAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiptWriteOutcome {
    Allow,
    Deny,
    PendingApproval,
    Error,
}

impl ReceiptWriteOutcome {
    /// Stable Prometheus label value for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => RECEIPT_WRITE_OUTCOME_ALLOW,
            Self::Deny => RECEIPT_WRITE_OUTCOME_DENY,
            Self::PendingApproval => RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
            Self::Error => RECEIPT_WRITE_OUTCOME_ERROR,
        }
    }

    /// Parse a stable receipt-write outcome label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            RECEIPT_WRITE_OUTCOME_ALLOW => Some(Self::Allow),
            RECEIPT_WRITE_OUTCOME_DENY => Some(Self::Deny),
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL => Some(Self::PendingApproval),
            RECEIPT_WRITE_OUTCOME_ERROR => Some(Self::Error),
            _ => None,
        }
    }
}

/// Map a kernel [`Verdict`] to its receipt-write outcome label.
#[must_use]
pub fn receipt_write_outcome_for_verdict(verdict: Verdict) -> &'static str {
    receipt_write_outcome_value_for_verdict(verdict).as_str()
}

/// Map a kernel [`Verdict`] to its typed receipt-write outcome.
#[must_use]
pub fn receipt_write_outcome_value_for_verdict(verdict: Verdict) -> ReceiptWriteOutcome {
    match verdict {
        Verdict::Allow => ReceiptWriteOutcome::Allow,
        Verdict::Deny => ReceiptWriteOutcome::Deny,
        Verdict::PendingApproval => ReceiptWriteOutcome::PendingApproval,
    }
}

/// Point-in-time per-outcome counter values for one edge sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptWriteSnapshot {
    pub allow: u64,
    pub deny: u64,
    pub pending_approval: u64,
    pub error: u64,
}

/// One labelled receipt-write counter sample from a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptWriteSample {
    pub outcome: ReceiptWriteOutcome,
    pub total: u64,
}

impl ReceiptWriteSample {
    /// Stable Prometheus label value for this sample.
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.outcome.as_str()
    }
}

impl ReceiptWriteSnapshot {
    /// Return the count for a typed outcome.
    #[must_use]
    pub const fn total(self, outcome: ReceiptWriteOutcome) -> u64 {
        match outcome {
            ReceiptWriteOutcome::Allow => self.allow,
            ReceiptWriteOutcome::Deny => self.deny,
            ReceiptWriteOutcome::PendingApproval => self.pending_approval,
            ReceiptWriteOutcome::Error => self.error,
        }
    }

    /// Return all samples in the stable exporter order.
    #[must_use]
    pub const fn samples(self) -> [ReceiptWriteSample; 4] {
        [
            ReceiptWriteSample {
                outcome: ReceiptWriteOutcome::Allow,
                total: self.allow,
            },
            ReceiptWriteSample {
                outcome: ReceiptWriteOutcome::Deny,
                total: self.deny,
            },
            ReceiptWriteSample {
                outcome: ReceiptWriteOutcome::PendingApproval,
                total: self.pending_approval,
            },
            ReceiptWriteSample {
                outcome: ReceiptWriteOutcome::Error,
                total: self.error,
            },
        ]
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
        self.record_outcome(receipt_write_outcome_value_for_verdict(verdict));
    }

    /// Record a typed receipt-write outcome at the edge sink boundary.
    pub fn record_outcome(&self, outcome: ReceiptWriteOutcome) {
        match outcome {
            ReceiptWriteOutcome::Allow => {
                increment_saturating(&self.allow);
            }
            ReceiptWriteOutcome::Deny => {
                increment_saturating(&self.deny);
            }
            ReceiptWriteOutcome::PendingApproval => {
                increment_saturating(&self.pending_approval);
            }
            ReceiptWriteOutcome::Error => {
                increment_saturating(&self.error);
            }
        }
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
        self.record_outcome(
            ReceiptWriteOutcome::from_label(outcome).unwrap_or(ReceiptWriteOutcome::Error),
        );
    }

    /// Read the current count for a typed outcome.
    #[must_use]
    pub fn total_outcome(&self, outcome: ReceiptWriteOutcome) -> u64 {
        match outcome {
            ReceiptWriteOutcome::Allow => self.allow.load(Ordering::Relaxed),
            ReceiptWriteOutcome::Deny => self.deny.load(Ordering::Relaxed),
            ReceiptWriteOutcome::PendingApproval => self.pending_approval.load(Ordering::Relaxed),
            ReceiptWriteOutcome::Error => self.error.load(Ordering::Relaxed),
        }
    }

    /// Read the current count for an outcome label. Unknown labels map to
    /// the error counter, mirroring [`Self::record`].
    #[must_use]
    pub fn total(&self, outcome: &str) -> u64 {
        self.total_outcome(
            ReceiptWriteOutcome::from_label(outcome).unwrap_or(ReceiptWriteOutcome::Error),
        )
    }

    /// Snapshot all counters for one edge sink.
    #[must_use]
    pub fn snapshot(&self) -> ReceiptWriteSnapshot {
        ReceiptWriteSnapshot {
            allow: self.total_outcome(ReceiptWriteOutcome::Allow),
            deny: self.total_outcome(ReceiptWriteOutcome::Deny),
            pending_approval: self.total_outcome(ReceiptWriteOutcome::PendingApproval),
            error: self.total_outcome(ReceiptWriteOutcome::Error),
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
        for sample in self.snapshot().samples() {
            output.push_str(CHIO_RECEIPT_WRITE_TOTAL);
            output.push_str("{outcome=\"");
            output.push_str(sample.label());
            output.push_str("\"} ");
            output.push_str(&sample.total.to_string());
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

fn increment_saturating(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Render the receipt-writer liveness gauges. The hosting edge passes the
/// serving kernel's current liveness label and healthy flag, giving the writer
/// health surface a real Prometheus consumer beyond the local CLI.
#[must_use]
pub fn render_receipt_writer_liveness(liveness_label: &str, healthy: bool) -> String {
    let mut output = String::new();
    output.push_str("# TYPE ");
    output.push_str(CHIO_RECEIPT_WRITER_HEALTHY);
    output.push_str(" gauge\n");
    output.push_str(CHIO_RECEIPT_WRITER_HEALTHY);
    output.push(' ');
    output.push_str(if healthy { "1" } else { "0" });
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(CHIO_RECEIPT_WRITER_LIVENESS);
    output.push_str(" gauge\n");
    output.push_str(CHIO_RECEIPT_WRITER_LIVENESS);
    output.push_str("{state=\"");
    output.push_str(liveness_label);
    output.push_str("\"} 1\n");
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
    fn writer_liveness_renders_gauge_and_labeled_series() {
        let body = render_receipt_writer_liveness("wedged", false);
        assert!(body.contains("chio_receipt_writer_healthy 0"));
        assert!(body.contains("chio_receipt_writer_liveness{state=\"wedged\"} 1"));

        let healthy = render_receipt_writer_liveness("healthy", true);
        assert!(healthy.contains("chio_receipt_writer_healthy 1"));
        assert!(healthy.contains("chio_receipt_writer_liveness{state=\"healthy\"} 1"));
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
    fn receipt_write_outcomes_are_rendered_in_stable_order() {
        assert_eq!(
            RECEIPT_WRITE_OUTCOMES,
            [
                ReceiptWriteOutcome::Allow,
                ReceiptWriteOutcome::Deny,
                ReceiptWriteOutcome::PendingApproval,
                ReceiptWriteOutcome::Error,
            ]
        );
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
    fn typed_outcomes_round_trip_to_stable_labels() {
        assert_eq!(
            ReceiptWriteOutcome::Allow.as_str(),
            RECEIPT_WRITE_OUTCOME_ALLOW
        );
        assert_eq!(
            ReceiptWriteOutcome::Deny.as_str(),
            RECEIPT_WRITE_OUTCOME_DENY
        );
        assert_eq!(
            ReceiptWriteOutcome::PendingApproval.as_str(),
            RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL
        );
        assert_eq!(
            ReceiptWriteOutcome::Error.as_str(),
            RECEIPT_WRITE_OUTCOME_ERROR
        );
        assert_eq!(
            ReceiptWriteOutcome::from_label(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL),
            Some(ReceiptWriteOutcome::PendingApproval)
        );
        assert_eq!(ReceiptWriteOutcome::from_label("bad-label"), None);
    }

    #[test]
    fn snapshot_exposes_typed_totals_without_string_lookup() {
        let counters = ReceiptWriteCounters::new();
        counters.record_outcome(ReceiptWriteOutcome::Allow);
        counters.record_outcome(ReceiptWriteOutcome::PendingApproval);
        counters.record("bad-label");

        let snapshot = counters.snapshot();

        assert_eq!(snapshot.total(ReceiptWriteOutcome::Allow), 1);
        assert_eq!(snapshot.total(ReceiptWriteOutcome::Deny), 0);
        assert_eq!(snapshot.total(ReceiptWriteOutcome::PendingApproval), 1);
        assert_eq!(snapshot.total(ReceiptWriteOutcome::Error), 1);
    }

    #[test]
    fn snapshot_samples_preserve_stable_order_and_totals() {
        let counters = ReceiptWriteCounters::new();
        counters.record_outcome(ReceiptWriteOutcome::Allow);
        counters.record_outcome(ReceiptWriteOutcome::Allow);
        counters.record_outcome(ReceiptWriteOutcome::Deny);
        counters.record_outcome(ReceiptWriteOutcome::PendingApproval);
        counters.record("unknown-label");

        let samples = counters.snapshot().samples();

        assert_eq!(
            samples,
            [
                ReceiptWriteSample {
                    outcome: ReceiptWriteOutcome::Allow,
                    total: 2,
                },
                ReceiptWriteSample {
                    outcome: ReceiptWriteOutcome::Deny,
                    total: 1,
                },
                ReceiptWriteSample {
                    outcome: ReceiptWriteOutcome::PendingApproval,
                    total: 1,
                },
                ReceiptWriteSample {
                    outcome: ReceiptWriteOutcome::Error,
                    total: 1,
                },
            ]
        );
        assert_eq!(samples[0].label(), RECEIPT_WRITE_OUTCOME_ALLOW);
    }

    #[test]
    fn receipt_write_counters_saturate_instead_of_wrapping() {
        let counters = ReceiptWriteCounters::new();
        counters.allow.store(u64::MAX, Ordering::Relaxed);

        counters.record(RECEIPT_WRITE_OUTCOME_ALLOW);

        assert_eq!(counters.total(RECEIPT_WRITE_OUTCOME_ALLOW), u64::MAX);
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
