//! Sustained-load runner: paces real kernel dispatches on an absolute schedule,
//! measures per-call latency percentiles plus resident-set growth, and reports
//! a fail-closed budget verdict.

use std::thread;
use std::time::{Duration, Instant};

use crate::rss;
use crate::{LoadgenConfig, LoadgenError, StackHarness};

/// Resident-set sampling cadence during a run; folds into the end-of-run
/// high-water mark so a long run's peak, not just its final sample, bounds the
/// growth budget.
const RSS_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// Measured outcome of one sustained run.
///
/// Percentiles are computed over the end-to-end latency of the dispatches that
/// returned an allow verdict. `rss_start_bytes`/`rss_end_bytes` are carried as
/// `None` on platforms without a resident-set sampler and are never fabricated;
/// `rss_end_bytes` is the high-water mark (the end sample or any in-run sample,
/// whichever is largest) so it is the value the growth budget is measured
/// against. `within_budget` is the same verdict [`enforce_budget`] recomputes
/// from these fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadReport {
    pub calls_attempted: u64,
    pub calls_ok: u64,
    pub ttfrh_ms: u128,
    pub p50_ms: u128,
    pub p99_ms: u128,
    pub rss_start_bytes: Option<u64>,
    pub rss_end_bytes: Option<u64>,
    pub exporter_queue_high_water: Option<u64>,
    pub within_budget: bool,
}

/// Drive `config.arrival_rate_hz` dispatches per second for `config.duration`
/// against the booted `harness`.
///
/// The pacer targets absolute instants (`run_start + n * interval`) rather than
/// sleeping for `interval` after each call, so per-dispatch cost does not make
/// the arrival rate drift. A dispatch that does not return an allow verdict, or
/// a durability-flush failure, denies with the typed [`LoadgenError`] it raised;
/// there is no silent-success path.
pub fn run_sustained(
    harness: &StackHarness,
    config: &LoadgenConfig,
) -> Result<LoadReport, LoadgenError> {
    let interval_ns = dispatch_interval_ns(config.arrival_rate_hz);
    let durable = harness.store().is_some();

    let rss_start = rss::current_rss_bytes();
    let mut rss_high_water = rss_start;

    let run_start = Instant::now();
    let run_end = run_start + config.duration;
    let mut next_rss_sample = run_start + RSS_SAMPLE_INTERVAL;

    let mut latencies_ns: Vec<u64> = Vec::new();
    let mut calls_attempted: u64 = 0;
    let mut calls_ok: u64 = 0;
    let mut ttfrh: Option<Duration> = None;

    let mut tick: u64 = 0;
    while Instant::now() < run_end {
        let target = run_start + Duration::from_nanos(interval_ns.saturating_mul(tick));
        let now = Instant::now();
        if target > now {
            thread::sleep(target - now);
        }

        while Instant::now() >= next_rss_sample {
            fold_high_water(&mut rss_high_water, rss::current_rss_bytes());
            next_rss_sample += RSS_SAMPLE_INTERVAL;
        }

        calls_attempted += 1;
        let latency = harness.dispatch_allow_once()?;
        calls_ok += 1;
        latencies_ns.push(u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX));

        if durable && ttfrh.is_none() {
            let committed_seq = harness.flush_durable()?;
            if committed_seq >= 1 {
                ttfrh = Some(run_start.elapsed());
            }
        }

        tick += 1;
    }

    fold_high_water(&mut rss_high_water, rss::current_rss_bytes());
    let rss_end = rss_high_water;

    latencies_ns.sort_unstable();
    let p50_ms = percentile_ms(&latencies_ns, 50);
    let p99_ms = percentile_ms(&latencies_ns, 99);

    let p99_budget_ms = config.p99_budget.as_millis();
    let growth_bytes = rss_growth_bytes(rss_start, rss_end);
    let within_budget = p99_ms <= p99_budget_ms && growth_bytes <= config.rss_growth_budget_bytes;

    Ok(LoadReport {
        calls_attempted,
        calls_ok,
        ttfrh_ms: ttfrh.map_or(0, |elapsed| elapsed.as_millis()),
        p50_ms,
        p99_ms,
        rss_start_bytes: rss_start,
        rss_end_bytes: rss_end,
        // The load generator's dispatch path does not traverse the OTLP ingress
        // queue, so there is no live exporter queue to snapshot here; this field
        // is carried as `None` rather than reporting a queue depth the run did
        // not produce.
        exporter_queue_high_water: None,
        within_budget,
    })
}

/// Fail-closed budget gate. Denies with [`LoadgenError::P99Exceeded`] when the
/// measured p99 is over budget, then with [`LoadgenError::RssGrowthExceeded`]
/// when resident-set growth is over budget; otherwise allows.
pub fn enforce_budget(report: &LoadReport, config: &LoadgenConfig) -> Result<(), LoadgenError> {
    let budget_ms = config.p99_budget.as_millis();
    if report.p99_ms > budget_ms {
        return Err(LoadgenError::P99Exceeded {
            observed_ms: report.p99_ms,
            budget_ms,
        });
    }

    let growth_bytes = rss_growth_bytes(report.rss_start_bytes, report.rss_end_bytes);
    if growth_bytes > config.rss_growth_budget_bytes {
        return Err(LoadgenError::RssGrowthExceeded {
            grew_bytes: growth_bytes,
            budget_bytes: config.rss_growth_budget_bytes,
        });
    }

    Ok(())
}

/// Inter-dispatch interval in nanoseconds. A zero arrival rate dispatches with
/// no pacing delay.
fn dispatch_interval_ns(arrival_rate_hz: u32) -> u64 {
    if arrival_rate_hz == 0 {
        return 0;
    }
    1_000_000_000 / u64::from(arrival_rate_hz)
}

/// Growth from a start sample to an end sample, saturating at zero. Unmeasured
/// samples (either side `None`) yield zero: an absent sampler cannot prove a
/// budget violation.
fn rss_growth_bytes(start: Option<u64>, end: Option<u64>) -> u64 {
    match (start, end) {
        (Some(start), Some(end)) => end.saturating_sub(start),
        _ => 0,
    }
}

/// Raise `high_water` to `sample` when `sample` is larger (or was previously
/// unmeasured). A `None` sample leaves the high-water mark untouched.
fn fold_high_water(high_water: &mut Option<u64>, sample: Option<u64>) {
    if let Some(value) = sample {
        *high_water = Some(match *high_water {
            Some(current) => current.max(value),
            None => value,
        });
    }
}

/// Nearest-rank percentile of a pre-sorted nanosecond slice, in milliseconds.
/// An empty slice reports zero.
fn percentile_ms(sorted_ns: &[u64], percentile: u64) -> u128 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let len = sorted_ns.len();
    let rank = (percentile as usize)
        .saturating_mul(len)
        .div_ceil(100)
        .max(1);
    let index = (rank - 1).min(len - 1);
    Duration::from_nanos(sorted_ns[index]).as_millis()
}
