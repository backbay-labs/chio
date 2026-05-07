//! Federation-hop metrics surfaced through the workspace
//! `chio-metrics-spec` registry. Wave 2.4 of the trj4 closeout wires the
//! federation-hop boundary into the workspace registry: every
//! [`co_sign_with_origin`](crate::co_sign_with_origin) call increments
//! [`CHIO_FEDERATION_HOP_TOTAL`] with a `result` label and observes
//! [`CHIO_FEDERATION_HOP_LATENCY_SECONDS`] with the same label so the
//! `chio:federation_hop_latency:histogram_quantile_p95_5m` recording rule
//! in `deploy/prometheus/chio-recording-rules.yml` has a series to scrape.

use std::sync::atomic::{AtomicU64, Ordering};

pub use chio_metrics_spec::{
    CHIO_FEDERATION_HOP_LATENCY_SECONDS, CHIO_FEDERATION_HOP_TOTAL,
    FEDERATION_HOP_LATENCY_BUCKETS_SECONDS,
};

pub const HOP_RESULT_OK: &str = "ok";
pub const HOP_RESULT_ERROR: &str = "error";

static FEDERATION_HOP_OK: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_ERROR: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_OK_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_ERROR_LATENCY_NS_SUM: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_OK_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_ERROR_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static FEDERATION_HOP_OK_BUCKETS: [AtomicU64; FEDERATION_HOP_BUCKET_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static FEDERATION_HOP_ERROR_BUCKETS: [AtomicU64; FEDERATION_HOP_BUCKET_COUNT] = [
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
const FEDERATION_HOP_BUCKET_COUNT: usize = FEDERATION_HOP_BUCKET_UPPER_NANOS.len() + 1;
const FEDERATION_HOP_BUCKET_UPPER_NANOS: [u64; 7] = [
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
];

struct FederationLatencySeries {
    sum: &'static AtomicU64,
    count: &'static AtomicU64,
    buckets: &'static [AtomicU64; FEDERATION_HOP_BUCKET_COUNT],
}

pub fn record_federation_hop(result: &str) {
    match result {
        HOP_RESULT_OK => {
            FEDERATION_HOP_OK.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            FEDERATION_HOP_ERROR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Observe a federation-hop latency sample in nanoseconds, scoped to the
/// hop result. Saturating at u64 keeps the counter monotonic under sustained
/// load without panicking on overflow. Pairs with [`record_federation_hop`]
/// so a single boundary call increments the counter and observes the
/// histogram in lockstep.
pub fn observe_federation_hop_latency_nanos(result: &str, nanos: u64) {
    let series = federation_latency_series(result);
    series.sum.fetch_add(nanos, Ordering::Relaxed);
    series.count.fetch_add(1, Ordering::Relaxed);
    for (index, upper) in FEDERATION_HOP_BUCKET_UPPER_NANOS.iter().enumerate() {
        if nanos <= *upper {
            series.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
    }
    series.buckets[FEDERATION_HOP_BUCKET_UPPER_NANOS.len()].fetch_add(1, Ordering::Relaxed);
    record_federation_hop(result);
}

#[must_use]
pub fn federation_hop_total(result: &str) -> u64 {
    match result {
        HOP_RESULT_OK => FEDERATION_HOP_OK.load(Ordering::Relaxed),
        _ => FEDERATION_HOP_ERROR.load(Ordering::Relaxed),
    }
}

#[must_use]
pub fn federation_hop_latency_count() -> u64 {
    FEDERATION_HOP_OK_LATENCY_COUNT.load(Ordering::Relaxed)
        + FEDERATION_HOP_ERROR_LATENCY_COUNT.load(Ordering::Relaxed)
}

#[must_use]
pub fn render_federation_metrics_prometheus() -> String {
    let mut output = String::new();
    output.push_str("# HELP ");
    output.push_str(CHIO_FEDERATION_HOP_TOTAL);
    output.push_str(" Total federation hop outcomes.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_FEDERATION_HOP_TOTAL);
    output.push_str(" counter\n");
    for result in [HOP_RESULT_OK, HOP_RESULT_ERROR] {
        output.push_str(CHIO_FEDERATION_HOP_TOTAL);
        output.push_str("{result=\"");
        output.push_str(result);
        output.push_str("\"} ");
        output.push_str(&federation_hop_total(result).to_string());
        output.push('\n');
    }
    output.push_str("# HELP ");
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str(" Federation hop latency in seconds.\n");
    output.push_str("# TYPE ");
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str(" histogram\n");
    for result in [HOP_RESULT_OK, HOP_RESULT_ERROR] {
        render_federation_latency_histogram(&mut output, result);
    }
    output
}

fn federation_latency_series(result: &str) -> FederationLatencySeries {
    match result {
        HOP_RESULT_OK => FederationLatencySeries {
            sum: &FEDERATION_HOP_OK_LATENCY_NS_SUM,
            count: &FEDERATION_HOP_OK_LATENCY_COUNT,
            buckets: &FEDERATION_HOP_OK_BUCKETS,
        },
        _ => FederationLatencySeries {
            sum: &FEDERATION_HOP_ERROR_LATENCY_NS_SUM,
            count: &FEDERATION_HOP_ERROR_LATENCY_COUNT,
            buckets: &FEDERATION_HOP_ERROR_BUCKETS,
        },
    }
}

fn render_federation_latency_histogram(output: &mut String, result: &str) {
    let series = federation_latency_series(result);
    for (index, le) in FEDERATION_HOP_LATENCY_BUCKETS_SECONDS.iter().enumerate() {
        render_federation_latency_bucket(
            output,
            result,
            le,
            series.buckets[index].load(Ordering::Relaxed),
        );
    }
    render_federation_latency_bucket(
        output,
        result,
        "+Inf",
        series.buckets[FEDERATION_HOP_BUCKET_UPPER_NANOS.len()].load(Ordering::Relaxed),
    );
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str("_sum{result=\"");
    output.push_str(result);
    output.push_str("\"} ");
    output.push_str(&format_seconds(series.sum.load(Ordering::Relaxed)));
    output.push('\n');
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str("_count{result=\"");
    output.push_str(result);
    output.push_str("\"} ");
    output.push_str(&series.count.load(Ordering::Relaxed).to_string());
    output.push('\n');
}

fn render_federation_latency_bucket(output: &mut String, result: &str, le: &str, count: u64) {
    output.push_str(CHIO_FEDERATION_HOP_LATENCY_SECONDS);
    output.push_str("_bucket{result=\"");
    output.push_str(result);
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
    fn registry_constant_matches_spec() {
        assert_eq!(CHIO_FEDERATION_HOP_TOTAL, "chio_federation_hop_total");
        assert_eq!(
            CHIO_FEDERATION_HOP_LATENCY_SECONDS,
            "chio_federation_hop_latency_seconds"
        );
    }
}
