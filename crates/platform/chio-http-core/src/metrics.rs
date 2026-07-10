//! HTTP-core verdict-edge metrics surfaced through the workspace
//! `chio-metrics-spec` registry. The HTTP edge is wired into the workspace
//! registry: every authority dispatch through
//! `HttpAuthority::evaluate` increments
//! [`CHIO_GUARD_EVALUATIONS_TOTAL`] with a `(guard, outcome)` label
//! pair and observes the dispatch latency under
//! [`CHIO_KERNEL_DECISION_LATENCY_SECONDS`].

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::{
    CHIO_GUARD_EVALUATIONS_TOTAL, CHIO_KERNEL_DECISION_LATENCY_SECONDS,
    DECISION_LATENCY_BUCKETS_SECONDS,
};

pub const GUARD_LABEL_HTTP_AUTHORITY: &str = "http_authority";

pub const GUARD_OUTCOME_ALLOW: &str = "allow";
pub const GUARD_OUTCOME_DENY: &str = "deny";
pub const GUARD_OUTCOME_ERROR: &str = "error";

static GUARD_EVAL_ALLOW: AtomicU64 = AtomicU64::new(0);
static GUARD_EVAL_DENY: AtomicU64 = AtomicU64::new(0);
static GUARD_EVAL_ERROR: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_ALLOW_NS_SUM: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_DENY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_ERROR_NS_SUM: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_ALLOW_COUNT: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_DENY_COUNT: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
static DECISION_LATENCY_ALLOW_BUCKETS: [AtomicU64; DECISION_LATENCY_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static DECISION_LATENCY_DENY_BUCKETS: [AtomicU64; DECISION_LATENCY_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static DECISION_LATENCY_ERROR_BUCKETS: [AtomicU64; DECISION_LATENCY_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const DECISION_LATENCY_BUCKET_COUNT: usize = DECISION_LATENCY_BUCKET_UPPER_NANOS.len() + 1;
const DECISION_LATENCY_BUCKET_UPPER_NANOS: [u64; 8] = [
    25_000_000,
    50_000_000,
    75_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_500_000_000,
];

struct DecisionLatencySeries {
    sum: &'static AtomicU64,
    count: &'static AtomicU64,
    buckets: &'static [AtomicU64; DECISION_LATENCY_BUCKET_COUNT],
}

/// Record the outcome of an HTTP authority evaluation. The `outcome`
/// argument should be one of [`GUARD_OUTCOME_ALLOW`],
/// [`GUARD_OUTCOME_DENY`], or [`GUARD_OUTCOME_ERROR`].
pub fn record_guard_evaluation(outcome: &str) {
    match outcome {
        GUARD_OUTCOME_ALLOW => {
            GUARD_EVAL_ALLOW.fetch_add(1, Ordering::Relaxed);
        }
        GUARD_OUTCOME_DENY => {
            GUARD_EVAL_DENY.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            GUARD_EVAL_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// +1 on chio_dispatch_failure_total for a genuine mediation-edge failure: the
/// request could not be evaluated (a fail-open/dispatch condition). `outcome` is
/// "error". A normal policy/capability deny is an expected fail-closed decision,
/// NOT a dispatch failure, and must never feed this counter or it would page the
/// P0 alert on every rejected request. Denies are tracked by the guard-verdict
/// metrics instead. Never called on allow.
pub fn record_dispatch_failure(surface: &str, outcome: &str) {
    chio_metrics_spec::runtime::families::DISPATCH_FAILURE.incr(&[surface, outcome]);
}

/// Observe a kernel decision latency sample in nanoseconds.
pub fn observe_decision_latency_nanos(nanos: u64) {
    observe_decision_latency_nanos_for_outcome(GUARD_OUTCOME_ALLOW, nanos);
}

/// Observe a kernel decision latency sample in nanoseconds for a verdict
/// outcome. Unknown labels fail closed into the error series.
pub fn observe_decision_latency_nanos_for_outcome(outcome: &str, nanos: u64) {
    let series = decision_latency_series(outcome);
    series.sum.fetch_add(nanos, Ordering::Relaxed);
    series.count.fetch_add(1, Ordering::Relaxed);
    for (index, upper) in DECISION_LATENCY_BUCKET_UPPER_NANOS.iter().enumerate() {
        if nanos <= *upper {
            series.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
    }
    series.buckets[DECISION_LATENCY_BUCKET_UPPER_NANOS.len()].fetch_add(1, Ordering::Relaxed);
}

#[must_use]
pub fn guard_evaluations_total(outcome: &str) -> u64 {
    match outcome {
        GUARD_OUTCOME_ALLOW => GUARD_EVAL_ALLOW.load(Ordering::Relaxed),
        GUARD_OUTCOME_DENY => GUARD_EVAL_DENY.load(Ordering::Relaxed),
        _ => GUARD_EVAL_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn decision_latency_count() -> u64 {
    DECISION_LATENCY_ALLOW_COUNT.load(Ordering::Relaxed)
        + DECISION_LATENCY_DENY_COUNT.load(Ordering::Relaxed)
        + DECISION_LATENCY_ERROR_COUNT.load(Ordering::Relaxed)
}

#[must_use]
pub fn render_http_core_metrics_prometheus() -> String {
    let mut output = String::new();

    output.push_str("# HELP ");
    output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
    output.push_str(" Total guard evaluation outcomes across native and WASM guards.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
    output.push_str(" counter\n");
    for outcome in [GUARD_OUTCOME_ALLOW, GUARD_OUTCOME_DENY, GUARD_OUTCOME_ERROR] {
        output.push_str(CHIO_GUARD_EVALUATIONS_TOTAL);
        output.push_str("{guard=\"");
        output.push_str(GUARD_LABEL_HTTP_AUTHORITY);
        output.push_str("\",outcome=\"");
        output.push_str(outcome);
        output.push_str("\"} ");
        output.push_str(&guard_evaluations_total(outcome).to_string());
        output.push('\n');
    }

    output.push_str("# HELP ");
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str(" Kernel mediation decision latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    for outcome in [GUARD_OUTCOME_ALLOW, GUARD_OUTCOME_DENY, GUARD_OUTCOME_ERROR] {
        render_decision_latency_histogram(&mut output, outcome);
    }

    output
}

fn decision_latency_series(outcome: &str) -> DecisionLatencySeries {
    match outcome {
        GUARD_OUTCOME_ALLOW => DecisionLatencySeries {
            sum: &DECISION_LATENCY_ALLOW_NS_SUM,
            count: &DECISION_LATENCY_ALLOW_COUNT,
            buckets: &DECISION_LATENCY_ALLOW_BUCKETS,
        },
        GUARD_OUTCOME_DENY => DecisionLatencySeries {
            sum: &DECISION_LATENCY_DENY_NS_SUM,
            count: &DECISION_LATENCY_DENY_COUNT,
            buckets: &DECISION_LATENCY_DENY_BUCKETS,
        },
        _ => DecisionLatencySeries {
            sum: &DECISION_LATENCY_ERROR_NS_SUM,
            count: &DECISION_LATENCY_ERROR_COUNT,
            buckets: &DECISION_LATENCY_ERROR_BUCKETS,
        },
    }
}

fn render_decision_latency_histogram(output: &mut String, outcome: &str) {
    let series = decision_latency_series(outcome);
    for (index, le) in DECISION_LATENCY_BUCKETS_SECONDS.iter().enumerate() {
        render_decision_latency_bucket(
            output,
            outcome,
            le,
            series.buckets[index].load(Ordering::Relaxed),
        );
    }
    render_decision_latency_bucket(
        output,
        outcome,
        "+Inf",
        series.buckets[DECISION_LATENCY_BUCKET_UPPER_NANOS.len()].load(Ordering::Relaxed),
    );
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str("_sum{surface=\"");
    output.push_str(GUARD_LABEL_HTTP_AUTHORITY);
    output.push_str("\",outcome=\"");
    output.push_str(outcome);
    output.push_str("\"} ");
    output.push_str(&format_seconds(series.sum.load(Ordering::Relaxed)));
    output.push('\n');
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str("_count{surface=\"");
    output.push_str(GUARD_LABEL_HTTP_AUTHORITY);
    output.push_str("\",outcome=\"");
    output.push_str(outcome);
    output.push_str("\"} ");
    output.push_str(&series.count.load(Ordering::Relaxed).to_string());
    output.push('\n');
}

fn render_decision_latency_bucket(output: &mut String, outcome: &str, le: &str, count: u64) {
    output.push_str(CHIO_KERNEL_DECISION_LATENCY_SECONDS);
    output.push_str("_bucket{surface=\"");
    output.push_str(GUARD_LABEL_HTTP_AUTHORITY);
    output.push_str("\",outcome=\"");
    output.push_str(outcome);
    output.push_str("\",le=\"");
    output.push_str(le);
    output.push_str("\"} ");
    output.push_str(&count.to_string());
    output.push('\n');
}

fn format_seconds(nanos: u64) -> String {
    format!("{:.9}", (nanos as f64) / (NANOS_PER_SECOND as f64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constants_match_spec() {
        assert_eq!(CHIO_GUARD_EVALUATIONS_TOTAL, "chio_guard_evaluations_total");
        assert_eq!(
            CHIO_KERNEL_DECISION_LATENCY_SECONDS,
            "chio_kernel_decision_latency_seconds"
        );
    }

    #[test]
    fn dispatch_failure_records_error_never_deny_or_allow() {
        // Only a genuine evaluation error feeds the paging counter. A normal
        // deny is NOT a dispatch failure, so the "denied" outcome is not
        // produced anywhere.
        record_dispatch_failure(GUARD_LABEL_HTTP_AUTHORITY, "error");
        let mut body = String::new();
        chio_metrics_spec::runtime::families::DISPATCH_FAILURE.render(&mut body);
        assert!(
            body.contains(
                "chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"error\"}"
            ),
            "error series missing: {body}"
        );
        // Neither a deny nor an allow outcome exists for this family.
        assert!(
            !body.contains("outcome=\"denied\""),
            "a deny must not be recorded as a dispatch failure: {body}"
        );
        assert!(
            !body.contains("outcome=\"allow\""),
            "must not record allow: {body}"
        );
    }
}
