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
/// returned an allow verdict. `p99_nanos` is the untruncated nanosecond p99 the
/// budget comparison uses; `p99_ms` is the same value truncated to milliseconds
/// for human-readable display only and must never drive a pass/fail decision (a
/// true p99 of 50.9ms truncates to 50 and would spuriously pass a 50ms budget).
/// `rss_start_bytes`/`rss_end_bytes` are carried as `None` on platforms without
/// a resident-set sampler and are never fabricated; `rss_end_bytes` is the
/// high-water mark (the end sample or any in-run sample, whichever is largest)
/// so it is the value the growth budget is measured against. `ttfrh_ms` follows
/// the same honest-null convention: it is `None` (serialized as JSON null) when
/// no durable receipt was ever hardened, so a run that hardened nothing is
/// distinguishable from a genuine 0ms time-to-first-receipt. `within_budget` is
/// the same verdict [`enforce_budget`] recomputes from these fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadReport {
    pub calls_attempted: u64,
    pub calls_ok: u64,
    pub ttfrh_ms: Option<u128>,
    pub p50_ms: u128,
    pub p99_ms: u128,
    pub p99_nanos: u128,
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
    // Fail closed on a zero arrival rate: interval 0 would pace nothing and drive
    // an unbounded max-rate loop, which is not what "idle" means. An uncapped run
    // is spelled as a large rate, never 0.
    if config.arrival_rate_hz == 0 {
        return Err(LoadgenError::ZeroArrivalRate);
    }

    let interval_ns = dispatch_interval_ns(config.arrival_rate_hz);
    let durable = harness.store().is_some();

    // Fail closed before allocating: a duration too large to place on the
    // monotonic clock denies now, rather than after committing the latency buffer
    // or aborting on an `Instant + Duration` overflow once the run is underway.
    let run_start = Instant::now();
    let run_end = schedule_run_end(run_start, config.duration)?;

    // Pre-size the latency buffer before the RSS baseline is sampled: the backing
    // allocation (and any push-driven doubling spikes during the run) is then
    // charged to the process before rss_start, not against the measured RSS
    // growth budget. Capacity tracks the pacer's dispatch count (rate x duration),
    // capped so a pathological config cannot request an unbounded allocation.
    let mut latencies_ns: Vec<u64> = Vec::with_capacity(expected_dispatch_count(config));

    let rss_start = rss::current_rss_bytes();
    let mut rss_high_water = rss_start;

    let mut next_rss_sample = run_start + RSS_SAMPLE_INTERVAL;

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

        // Recheck the deadline after pacing to the tick instant: the top-of-loop
        // check can pass just before this final sleep, and dispatching a tick that
        // lands on or past run_end would overstate the window by one call (a 1s run
        // at 1hz would otherwise dispatch at t=0 and again at t=1s = 2 calls).
        if Instant::now() >= run_end {
            break;
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
    let p50_ns = percentile_ns(&latencies_ns, 50);
    let p99_ns = percentile_ns(&latencies_ns, 99);
    let p50_ms = Duration::from_nanos(p50_ns).as_millis();
    let p99_ms = Duration::from_nanos(p99_ns).as_millis();
    let p99_nanos = u128::from(p99_ns);

    let mut report = LoadReport {
        calls_attempted,
        calls_ok,
        ttfrh_ms: ttfrh.map(|elapsed| elapsed.as_millis()),
        p50_ms,
        p99_ms,
        p99_nanos,
        rss_start_bytes: rss_start,
        rss_end_bytes: rss_end,
        // The load generator's dispatch path does not traverse the OTLP ingress
        // queue, so there is no live exporter queue to snapshot here; this field
        // is carried as `None` rather than reporting a queue depth the run did
        // not produce.
        exporter_queue_high_water: None,
        within_budget: false,
    };
    // Keep `within_budget == enforce_budget(..).is_ok()` by construction: the same
    // fail-closed gate decides both, so an unmeasured RSS sample or an empty run
    // reads as out-of-budget here exactly as it denies there.
    report.within_budget = enforce_budget(&report, config).is_ok();
    Ok(report)
}

/// Fail-closed budget gate. Denies with [`LoadgenError::EmptyRun`] when the run
/// dispatched nothing (a gate must not pass without exercising the stack), then
/// with [`LoadgenError::P99Exceeded`] when the measured p99 is over budget, then
/// with [`LoadgenError::RssUnmeasured`] when either resident-set sample is
/// absent, then with [`LoadgenError::RssGrowthExceeded`] when resident-set growth
/// is over budget; otherwise allows.
///
/// The p99 comparison is on the untruncated `p99_nanos`, not the millisecond
/// display value, so a p99 fractionally over budget cannot pass by truncation.
/// An unmeasured resident set denies rather than folding to zero growth: a broken
/// or unsupported sampler reads as a broken lane, not a silent pass. (The Linux
/// and macOS samplers return `Some`, so the real gate path is unaffected.)
pub fn enforce_budget(report: &LoadReport, config: &LoadgenConfig) -> Result<(), LoadgenError> {
    if report.calls_attempted == 0 {
        return Err(LoadgenError::EmptyRun);
    }

    let budget_nanos = config.p99_budget.as_nanos();
    if report.p99_nanos > budget_nanos {
        return Err(LoadgenError::P99Exceeded {
            observed_nanos: report.p99_nanos,
            budget_nanos,
        });
    }

    let (Some(start), Some(end)) = (report.rss_start_bytes, report.rss_end_bytes) else {
        return Err(LoadgenError::RssUnmeasured);
    };
    let growth_bytes = end.saturating_sub(start);
    if growth_bytes > config.rss_growth_budget_bytes {
        return Err(LoadgenError::RssGrowthExceeded {
            grew_bytes: growth_bytes,
            budget_bytes: config.rss_growth_budget_bytes,
        });
    }

    Ok(())
}

/// Upper bound on the pre-sized latency buffer so a pathological rate x duration
/// cannot request an unbounded allocation. Eight million u64 samples is 64 MiB,
/// which covers hours of realistic rates while capping the worst case.
const MAX_PREALLOCATED_LATENCIES: usize = 8_000_000;

/// Expected dispatch count for the run, used only to pre-size the latency buffer.
/// Derived from the pacer's target rate over the run duration (rate x duration),
/// computed on nanoseconds so fractional-second durations are not truncated away,
/// then capped at [`MAX_PREALLOCATED_LATENCIES`].
fn expected_dispatch_count(config: &LoadgenConfig) -> usize {
    let expected = config
        .duration
        .as_nanos()
        .saturating_mul(u128::from(config.arrival_rate_hz))
        / 1_000_000_000;
    usize::try_from(expected)
        .unwrap_or(usize::MAX)
        .min(MAX_PREALLOCATED_LATENCIES)
}

/// Inter-dispatch interval in nanoseconds. Callers reject a zero arrival rate
/// before reaching here; the zero guard is defense-in-depth so the division can
/// never trap.
fn dispatch_interval_ns(arrival_rate_hz: u32) -> u64 {
    if arrival_rate_hz == 0 {
        return 0;
    }
    1_000_000_000 / u64::from(arrival_rate_hz)
}

/// Absolute run deadline for the pacer, failing closed when the configured
/// duration cannot be represented on the monotonic clock. `Instant + Duration`
/// panics on overflow, so an extreme duration must deny with a typed error before
/// the run starts rather than abort the process.
fn schedule_run_end(run_start: Instant, duration: Duration) -> Result<Instant, LoadgenError> {
    run_start
        .checked_add(duration)
        .ok_or(LoadgenError::DurationTooLong)
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

/// Nearest-rank percentile of a pre-sorted nanosecond slice, in nanoseconds. The
/// raw nanosecond value is kept so the budget comparison does not truncate. An
/// empty slice reports zero.
fn percentile_ns(sorted_ns: &[u64], percentile: u64) -> u64 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let len = sorted_ns.len();
    let rank = (percentile as usize)
        .saturating_mul(len)
        .div_ceil(100)
        .max(1);
    let index = (rank - 1).min(len - 1);
    sorted_ns[index]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoreBacking;
    use std::path::PathBuf;

    /// Build a config whose only load-bearing field for [`enforce_budget`] is the
    /// p99 budget; the store path is never opened by the gate.
    fn config_with_p99_budget(budget: Duration) -> LoadgenConfig {
        LoadgenConfig {
            arrival_rate_hz: 100,
            duration: Duration::from_secs(1),
            tool_latency: Duration::from_millis(2),
            store: StoreBacking::Sqlite {
                path: PathBuf::from("unused-by-enforce-budget.sqlite"),
            },
            p99_budget: budget,
            rss_growth_budget_bytes: u64::MAX,
        }
    }

    /// Hand-built report with a chosen attempt count and untruncated p99. RSS is
    /// measured-equal (start == end) so the growth check is a no-op zero and the
    /// fail-closed unmeasured-RSS gate is satisfied, isolating the p99/empty-run
    /// paths.
    fn make_report(calls_attempted: u64, p99_nanos: u128) -> LoadReport {
        LoadReport {
            calls_attempted,
            calls_ok: calls_attempted,
            ttfrh_ms: None,
            p50_ms: 0,
            p99_ms: p99_nanos / 1_000_000,
            p99_nanos,
            rss_start_bytes: Some(1_024),
            rss_end_bytes: Some(1_024),
            exporter_queue_high_water: None,
            within_budget: false,
        }
    }

    #[test]
    fn schedule_run_end_rejects_unrepresentable_duration() {
        let start = Instant::now();
        assert!(
            matches!(
                schedule_run_end(start, Duration::from_secs(u64::MAX)),
                Err(LoadgenError::DurationTooLong)
            ),
            "a duration near u64::MAX seconds must deny with DurationTooLong, not panic"
        );
        assert!(
            schedule_run_end(start, Duration::from_secs(1)).is_ok(),
            "a representable duration must schedule a run deadline"
        );
    }

    #[test]
    fn dispatch_interval_ns_computes_the_pacer_interval() {
        // Deterministic pacer correctness: dispatches are spaced by
        // 1e9 / rate nanoseconds. The integration test cannot assert achieved
        // throughput under a loaded runner, so the interval math is pinned here.
        assert_eq!(dispatch_interval_ns(200), 5_000_000);
        assert_eq!(dispatch_interval_ns(1_000), 1_000_000);
        assert_eq!(dispatch_interval_ns(1), 1_000_000_000);
        // A zero rate has no interval; run_sustained rejects it before pacing.
        assert_eq!(dispatch_interval_ns(0), 0);
    }

    #[test]
    fn enforce_budget_rejects_empty_run() {
        let config = config_with_p99_budget(Duration::from_millis(50));
        let report = make_report(0, 0);
        assert!(
            matches!(
                enforce_budget(&report, &config),
                Err(LoadgenError::EmptyRun)
            ),
            "a run that dispatched no calls must deny with EmptyRun"
        );
    }

    #[test]
    fn enforce_budget_compares_untruncated_p99() {
        let config = config_with_p99_budget(Duration::from_millis(50));

        // 50.9ms truncates to 50ms but is over the 50ms budget on the nanos.
        let over = make_report(100, 50_900_000);
        assert_eq!(over.p99_ms, 50, "the display value truncates to the budget");
        assert!(
            matches!(
                enforce_budget(&over, &config),
                Err(LoadgenError::P99Exceeded { .. })
            ),
            "a p99 fractionally over budget must deny on the untruncated nanos"
        );

        // Exactly at budget passes.
        let at = make_report(100, 50_000_000);
        assert!(
            enforce_budget(&at, &config).is_ok(),
            "a p99 exactly at budget must pass"
        );
    }

    #[test]
    fn enforce_budget_rejects_unmeasured_rss() {
        let config = config_with_p99_budget(Duration::from_millis(50));

        // A within-budget p99 but an absent RSS sample must deny: a broken or
        // unsupported sampler cannot prove the growth budget was met, so it fails
        // closed rather than folding a None sample to zero growth.
        let mut report = make_report(100, 10_000_000);
        report.rss_start_bytes = None;
        report.rss_end_bytes = None;
        assert!(
            matches!(
                enforce_budget(&report, &config),
                Err(LoadgenError::RssUnmeasured)
            ),
            "an unmeasured resident set must deny with RssUnmeasured"
        );

        // A half-measured sample (start present, end absent) is equally unprovable.
        let mut half = make_report(100, 10_000_000);
        half.rss_end_bytes = None;
        assert!(
            matches!(
                enforce_budget(&half, &config),
                Err(LoadgenError::RssUnmeasured)
            ),
            "a half-measured resident set must deny with RssUnmeasured"
        );
    }
}
