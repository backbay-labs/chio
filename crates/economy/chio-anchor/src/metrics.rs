//! Anchor publish metrics surfaced through the workspace
//! `chio-metrics-spec` registry. The anchor publish boundary is wired into
//! the workspace registry: every
//! [`build_anchor_batch`](crate::build_anchor_batch) call observes
//! [`CHIO_ANCHOR_ROUND_LATENCY_SECONDS`].
//!
//! `chio_metrics_spec` registers
//! `chio_anchor_round_latency_seconds` as a histogram with
//! `(witness, outcome)` labels. The atomic counters here keep the
//! count and a nanosecond-summed total so the Prometheus exporter can
//! render `_sum`/`_count` companion samples without pulling in a full
//! histogram crate.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::{
    ANCHOR_ROUND_LATENCY_BUCKETS_SECONDS, CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
};

pub const ANCHOR_OUTCOME_SUCCESS: &str = "success";
pub const ANCHOR_OUTCOME_ERROR: &str = "error";
const ANCHOR_OUTCOMES: [&str; 2] = [ANCHOR_OUTCOME_SUCCESS, ANCHOR_OUTCOME_ERROR];

static ANCHOR_ROUND_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_LATENCY_ERROR_NS_SUM: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_COUNT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_COUNT_ERROR: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ROUND_SUCCESS_BUCKETS: [AtomicU64; ANCHOR_ROUND_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ANCHOR_ROUND_ERROR_BUCKETS: [AtomicU64; ANCHOR_ROUND_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const ANCHOR_ROUND_BUCKET_COUNT: usize = ANCHOR_ROUND_BUCKET_UPPER_NANOS.len() + 1;
const ANCHOR_ROUND_BUCKET_UPPER_NANOS: [u64; 6] = [
    100_000_000,
    500_000_000,
    1_000_000_000,
    2_500_000_000,
    5_000_000_000,
    10_000_000_000,
];

struct AnchorLatencySeries {
    sum: &'static AtomicU64,
    count: &'static AtomicU64,
    buckets: &'static [AtomicU64; ANCHOR_ROUND_BUCKET_COUNT],
}

/// Observe an anchor round latency sample in nanoseconds.
pub fn observe_anchor_round_latency_nanos(outcome: &str, nanos: u64) {
    let series = anchor_latency_series(outcome);
    atomic_saturating_add(series.sum, nanos);
    atomic_saturating_add(series.count, 1);
    for (index, upper) in ANCHOR_ROUND_BUCKET_UPPER_NANOS.iter().enumerate() {
        if nanos <= *upper {
            atomic_saturating_add(&series.buckets[index], 1);
        }
    }
    atomic_saturating_add(&series.buckets[ANCHOR_ROUND_BUCKET_UPPER_NANOS.len()], 1);
}

#[must_use]
pub fn anchor_round_count(outcome: &str) -> u64 {
    match outcome {
        ANCHOR_OUTCOME_SUCCESS => ANCHOR_ROUND_COUNT_SUCCESS.load(Ordering::Relaxed),
        _ => ANCHOR_ROUND_COUNT_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn render_anchor_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str(" Anchor round latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    for outcome in ANCHOR_OUTCOMES {
        render_anchor_latency_histogram(&mut output, outcome);
    }
    output
}

fn anchor_latency_series(outcome: &str) -> AnchorLatencySeries {
    match outcome {
        ANCHOR_OUTCOME_SUCCESS => AnchorLatencySeries {
            sum: &ANCHOR_ROUND_LATENCY_NS_SUM,
            count: &ANCHOR_ROUND_COUNT_SUCCESS,
            buckets: &ANCHOR_ROUND_SUCCESS_BUCKETS,
        },
        _ => AnchorLatencySeries {
            sum: &ANCHOR_ROUND_LATENCY_ERROR_NS_SUM,
            count: &ANCHOR_ROUND_COUNT_ERROR,
            buckets: &ANCHOR_ROUND_ERROR_BUCKETS,
        },
    }
}

fn render_anchor_latency_histogram(output: &mut String, outcome: &str) {
    let series = anchor_latency_series(outcome);
    for (index, le) in ANCHOR_ROUND_LATENCY_BUCKETS_SECONDS.iter().enumerate() {
        render_anchor_latency_bucket(
            output,
            outcome,
            le,
            series.buckets[index].load(Ordering::Relaxed),
        );
    }
    render_anchor_latency_bucket(
        output,
        outcome,
        "+Inf",
        series.buckets[ANCHOR_ROUND_BUCKET_UPPER_NANOS.len()].load(Ordering::Relaxed),
    );
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str("_sum{witness=\"local\",outcome=\"");
    output.push_str(outcome);
    output.push_str("\"} ");
    output.push_str(&format_seconds(series.sum.load(Ordering::Relaxed)));
    output.push('\n');
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str("_count{witness=\"local\",outcome=\"");
    output.push_str(outcome);
    output.push_str("\"} ");
    output.push_str(&series.count.load(Ordering::Relaxed).to_string());
    output.push('\n');
}

fn render_anchor_latency_bucket(output: &mut String, outcome: &str, le: &str, count: u64) {
    output.push_str(CHIO_ANCHOR_ROUND_LATENCY_SECONDS);
    output.push_str("_bucket{witness=\"local\",outcome=\"");
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

fn atomic_saturating_add(value: &AtomicU64, addend: u64) {
    let mut current = value.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(addend);
        match value.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_constant_matches_spec() {
        assert_eq!(
            CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
            "chio_anchor_round_latency_seconds"
        );
    }

    #[test]
    fn atomic_saturating_add_caps_at_u64_max() {
        let value = AtomicU64::new(u64::MAX - 1);

        atomic_saturating_add(&value, 5);

        assert_eq!(value.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn anchor_outcomes_are_rendered_in_stable_order() {
        assert_eq!(
            ANCHOR_OUTCOMES,
            [ANCHOR_OUTCOME_SUCCESS, ANCHOR_OUTCOME_ERROR]
        );

        let rendered = render_anchor_metrics_prometheus();
        let Some(success) = rendered.find(r#"outcome="success""#) else {
            panic!("success outcome rendered");
        };
        let Some(error) = rendered.find(r#"outcome="error""#) else {
            panic!("error outcome rendered");
        };
        assert!(success < error);
    }
}
