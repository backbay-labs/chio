//! Sustained-load runner: paces real kernel dispatches on an absolute schedule,
//! measures per-call latency percentiles plus resident-set growth, and reports
//! a fail-closed budget verdict.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::rss;
use crate::{LoadgenConfig, LoadgenError, StackHarness};

/// Resident-set sampling cadence during a run. The sampler is independent of
/// the pacer and remains live until every dispatch worker and result collector
/// completes, so queue drain and short-lived peaks are part of the budget.
const RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);

/// Maximum concurrent dispatch workers. The queue is deliberately bounded; if
/// all workers and queue slots are occupied, the configured arrival rate was not
/// delivered and the run fails instead of silently degrading to closed-loop.
const MAX_DISPATCH_WORKERS: usize = 32;
const QUEUE_SLOTS_PER_WORKER: usize = 2;

/// Hard ceiling on scheduled calls and the resident latency vector. Eight
/// million u64 samples is 64 MiB. Larger schedules deny before allocation.
const MAX_SCHEDULED_DISPATCHES: u64 = 8_000_000;

struct DispatchResults {
    latencies_ns: Vec<u64>,
    ttfrh: Option<Duration>,
    first_error: Option<LoadgenError>,
}

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

    // Fail closed above the nanosecond pacer resolution: a rate over 1e9 Hz spaces
    // dispatches less than one nanosecond apart, which the rational tick offset
    // floors to a zero interval, collapsing every tick onto run_start and driving
    // the same uncapped max-rate loop a zero rate would. An uncapped run is spelled
    // as a large-but-representable rate, never one past the clock's resolution.
    if config.arrival_rate_hz > MAX_ARRIVAL_RATE_HZ {
        return Err(LoadgenError::ArrivalRateTooHigh {
            arrival_rate_hz: config.arrival_rate_hz,
        });
    }

    let durable = harness.store().is_some();
    // Preserve the typed duration-overflow contract before evaluating the
    // bounded schedule size. An unrepresentable clock deadline is a duration
    // error even though it would also imply an enormous dispatch count.
    schedule_run_end(Instant::now(), config.duration)?;
    let scheduled = scheduled_dispatch_count(config)?;

    // Pre-size the latency buffer before the RSS baseline is sampled, and touch
    // every element so the backing pages are resident now: `with_capacity` alone
    // (and a zero-fill, which calloc serves from untouched copy-on-write zero
    // pages) maps virtual pages that would only become resident as pushes write
    // them mid-run, counting the buffer against the measured RSS growth budget
    // (at the preallocation cap the buffer alone is 64 MiB, a whole default
    // budget). Writing a nonzero fill then clearing keeps the capacity while
    // charging the resident pages to the baseline. Capacity tracks the pacer's
    // dispatch count (rate x duration), capped so a pathological config cannot
    // request an unbounded allocation.
    let latency_capacity =
        usize::try_from(scheduled).map_err(|_| LoadgenError::DispatchScheduleTooLarge {
            scheduled: u128::from(scheduled),
            maximum: MAX_SCHEDULED_DISPATCHES,
        })?;
    let mut latency_buffer: Vec<u64> = Vec::with_capacity(latency_capacity);
    latency_buffer.resize(latency_buffer.capacity(), 1);
    latency_buffer.clear();

    let rss_start = rss::current_rss_bytes();

    // Start the measured window only after bounded allocations are resident.
    // This keeps setup cost out of the configured arrival interval and RSS
    // growth inside it.
    let run_start = Instant::now();

    let (calls_attempted, mut dispatch_results, rss_end) = thread::scope(|scope| {
        let sampling_complete = Arc::new(AtomicBool::new(false));
        let sampler_complete = Arc::clone(&sampling_complete);
        let sampler = scope.spawn(move || {
            sample_rss_until(
                &sampler_complete,
                RSS_SAMPLE_INTERVAL,
                rss::current_rss_bytes,
            )
        });

        let worker_count = usize::try_from(scheduled)
            .unwrap_or(MAX_DISPATCH_WORKERS)
            .clamp(1, MAX_DISPATCH_WORKERS);
        let queue_capacity = worker_count.saturating_mul(QUEUE_SLOTS_PER_WORKER);
        let (tick_sender, tick_receiver) = mpsc::sync_channel::<()>(queue_capacity);
        let tick_receiver = Arc::new(Mutex::new(tick_receiver));
        let (result_sender, result_receiver) = mpsc::channel::<Result<Duration, LoadgenError>>();

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let receiver = Arc::clone(&tick_receiver);
            let sender = result_sender.clone();
            workers.push(scope.spawn(move || loop {
                let next = match receiver.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => {
                        let _ = sender.send(Err(LoadgenError::Dispatch(
                            "loadgen dispatch queue lock was poisoned".to_string(),
                        )));
                        break;
                    }
                };
                match next {
                    Ok(()) => {
                        let _ = sender.send(harness.dispatch_allow_once());
                    }
                    Err(_) => break,
                }
            }));
        }
        drop(result_sender);

        let collector = scope.spawn(move || {
            let mut results = DispatchResults {
                latencies_ns: latency_buffer,
                ttfrh: None,
                first_error: None,
            };
            while let Ok(result) = result_receiver.recv() {
                match result {
                    Ok(latency) => {
                        results
                            .latencies_ns
                            .push(u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX));
                        if durable && results.ttfrh.is_none() && results.first_error.is_none() {
                            match harness.flush_durable() {
                                Ok(committed_seq) if committed_seq >= 1 => {
                                    results.ttfrh = Some(run_start.elapsed());
                                }
                                Ok(_) => {}
                                Err(error) => results.first_error = Some(error),
                            }
                        }
                    }
                    Err(error) if results.first_error.is_none() => {
                        results.first_error = Some(error);
                    }
                    Err(_) => {}
                }
            }
            results
        });

        let mut attempted = 0u64;
        let mut pacing_error = None;
        for tick in 0..scheduled {
            let target =
                run_start + Duration::from_nanos(pacer_offset_ns(tick, config.arrival_rate_hz));
            let now = Instant::now();
            if target > now {
                thread::sleep(target - now);
            }

            match tick_sender.try_send(()) {
                Ok(()) => attempted += 1,
                Err(mpsc::TrySendError::Full(())) => {
                    pacing_error = Some(LoadgenError::ArrivalRateMissed {
                        scheduled,
                        attempted,
                        completed: 0,
                    });
                    break;
                }
                Err(mpsc::TrySendError::Disconnected(())) => {
                    pacing_error = Some(LoadgenError::Dispatch(
                        "all loadgen dispatch workers exited".to_string(),
                    ));
                    break;
                }
            }
        }
        drop(tick_sender);

        for worker in workers {
            if worker.join().is_err() && pacing_error.is_none() {
                pacing_error = Some(LoadgenError::Dispatch(
                    "loadgen dispatch worker panicked".to_string(),
                ));
            }
        }
        let collector_result = collector.join();
        sampling_complete.store(true, Ordering::Release);
        let rss_high_water = sampler
            .join()
            .map_err(|_| LoadgenError::Dispatch("RSS sampler panicked".to_string()))?;
        let results = collector_result
            .map_err(|_| LoadgenError::Dispatch("loadgen result collector panicked".to_string()))?;
        if let Some(error) = pacing_error {
            return Err(error);
        }
        Ok((attempted, results, rss_high_water))
    })?;

    if let Some(error) = dispatch_results.first_error.take() {
        return Err(error);
    }
    let calls_ok = u64::try_from(dispatch_results.latencies_ns.len()).unwrap_or(u64::MAX);
    if calls_attempted != scheduled || calls_ok != scheduled {
        return Err(LoadgenError::ArrivalRateMissed {
            scheduled,
            attempted: calls_attempted,
            completed: calls_ok,
        });
    }

    let mut latencies_ns = dispatch_results.latencies_ns;
    latencies_ns.sort_unstable();
    let p50_ns = percentile_ns(&latencies_ns, 50);
    let p99_ns = percentile_ns(&latencies_ns, 99);
    let p50_ms = Duration::from_nanos(p50_ns).as_millis();
    let p99_ms = Duration::from_nanos(p99_ns).as_millis();
    let p99_nanos = u128::from(p99_ns);

    let mut report = LoadReport {
        calls_attempted,
        calls_ok,
        ttfrh_ms: dispatch_results.ttfrh.map(|elapsed| elapsed.as_millis()),
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
    // Deny on zero completions as well as zero attempts: [`run_sustained`] can
    // only produce reports with `calls_attempted == calls_ok` (any dispatch
    // failure aborts the run), but `LoadReport` fields are public, so a caller
    // gating on a hand-assembled report must not pass one that completed
    // nothing.
    if report.calls_attempted == 0 || report.calls_ok == 0 {
        return Err(LoadgenError::EmptyRun);
    }

    let scheduled = scheduled_dispatch_count(config)?;
    if report.calls_attempted != scheduled || report.calls_ok != scheduled {
        return Err(LoadgenError::ArrivalRateMissed {
            scheduled,
            attempted: report.calls_attempted,
            completed: report.calls_ok,
        });
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

/// Exact number of tick instants in `[run_start, run_end)`. Fractional windows
/// round up because tick zero is immediate: 500ms at 1Hz schedules one call,
/// while 1s at 3Hz schedules exactly three. Schedules beyond the bounded result
/// buffer fail closed before any work begins.
fn scheduled_dispatch_count(config: &LoadgenConfig) -> Result<u64, LoadgenError> {
    let scheduled = config
        .duration
        .as_nanos()
        .saturating_mul(u128::from(config.arrival_rate_hz))
        .div_ceil(1_000_000_000);
    let maximum = u128::from(MAX_SCHEDULED_DISPATCHES);
    if scheduled > maximum {
        return Err(LoadgenError::DispatchScheduleTooLarge {
            scheduled,
            maximum: MAX_SCHEDULED_DISPATCHES,
        });
    }
    u64::try_from(scheduled).map_err(|_| LoadgenError::DispatchScheduleTooLarge {
        scheduled,
        maximum: MAX_SCHEDULED_DISPATCHES,
    })
}

/// Highest arrival rate the nanosecond pacer can resolve: one dispatch per
/// nanosecond. A rate above this floors the per-tick interval to zero, so
/// [`run_sustained`] denies it rather than running an uncapped max-rate loop.
const MAX_ARRIVAL_RATE_HZ: u32 = 1_000_000_000;

/// Absolute nanosecond offset from run start for `tick`, in the rational
/// multiply-before-divide form so tick N lands at exactly N/rate seconds. A
/// truncated per-tick interval (1e9 / rate) accumulates rounding that runs the
/// schedule slightly fast and can fit an extra dispatch into the window (1s at
/// 3hz would target 0, 333333333, 666666666, 999999999 = four calls); the
/// rational offset instead targets 0, 333333333, 666666667, 1000000000, and the
/// run_end recheck breaks at the 1e9 target for exactly three. The intermediate
/// product is u128 so it cannot overflow; the cast back to u64 saturates because
/// a tick offset past u64 nanoseconds is beyond any real run (the run_end recheck
/// breaks first). Callers reject a zero arrival rate before reaching here; the
/// zero guard is defense-in-depth so the division can never trap.
fn pacer_offset_ns(tick: u64, arrival_rate_hz: u32) -> u64 {
    if arrival_rate_hz == 0 {
        return 0;
    }
    let offset = u128::from(tick) * 1_000_000_000u128 / u128::from(arrival_rate_hz);
    u64::try_from(offset).unwrap_or(u64::MAX)
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

/// Sample resident-set size independently until the measured work is complete.
/// The completion check follows each sample, which guarantees one final sample
/// after the caller publishes completion and before the sampler exits.
fn sample_rss_until(
    complete: &AtomicBool,
    interval: Duration,
    mut sample: impl FnMut() -> Option<u64>,
) -> Option<u64> {
    let mut high_water = None;
    loop {
        fold_high_water(&mut high_water, sample());
        if complete.load(Ordering::Acquire) {
            return high_water;
        }
        thread::sleep(interval);
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
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

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
    fn rss_sampler_keeps_transient_peak_through_completion() {
        let stop = AtomicBool::new(false);
        let mut samples = VecDeque::from([Some(1_024), Some(8_192), Some(2_048)]);
        let high_water = sample_rss_until(&stop, Duration::ZERO, || {
            let sample = samples.pop_front();
            if samples.is_empty() {
                stop.store(true, Ordering::Release);
            }
            sample.flatten()
        });

        assert_eq!(high_water, Some(8_192));
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
    fn pacer_offset_ns_is_rational_and_drift_free() {
        // Deterministic pacer correctness: the integration test cannot assert
        // achieved throughput under a loaded runner, so the tick-offset math is
        // pinned here. A rate that does not divide 1e9 evenly must not accumulate
        // rounding: the rational offset lands tick N at exactly N/rate seconds, so
        // tick 3 at 3hz is 1e9ns to the nanosecond, not 999999999 (which a
        // truncated per-tick interval would reach, fitting a spurious fourth
        // dispatch into a 1s run).
        assert_eq!(pacer_offset_ns(0, 3), 0);
        assert_eq!(pacer_offset_ns(1, 3), 333_333_333);
        assert_eq!(pacer_offset_ns(2, 3), 666_666_666);
        assert_eq!(pacer_offset_ns(3, 3), 1_000_000_000);
        // A rate that divides 1e9 evenly is exact at every tick and unaffected.
        assert_eq!(pacer_offset_ns(200, 200), 1_000_000_000);
        assert_eq!(pacer_offset_ns(1, 200), 5_000_000);
        assert_eq!(pacer_offset_ns(1_000, 1_000), 1_000_000_000);
        // Defense-in-depth: a zero rate has no offset; run_sustained rejects it.
        assert_eq!(pacer_offset_ns(5, 0), 0);
    }

    #[test]
    fn scheduled_dispatch_count_covers_fractional_windows_exactly() {
        let mut config = config_with_p99_budget(Duration::from_millis(50));
        config.arrival_rate_hz = 3;
        config.duration = Duration::from_secs(1);
        assert!(matches!(scheduled_dispatch_count(&config), Ok(3)));

        config.arrival_rate_hz = 1;
        config.duration = Duration::from_millis(500);
        assert!(matches!(scheduled_dispatch_count(&config), Ok(1)));

        config.duration = Duration::ZERO;
        assert!(matches!(scheduled_dispatch_count(&config), Ok(0)));
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

        // Attempts without a single completion must deny too: run_sustained
        // cannot produce this shape, but the report fields are public and a
        // hand-assembled report that completed nothing must not pass the gate.
        let mut no_completions = make_report(10, 0);
        no_completions.calls_ok = 0;
        assert!(
            matches!(
                enforce_budget(&no_completions, &config),
                Err(LoadgenError::EmptyRun)
            ),
            "a run that completed no calls must deny with EmptyRun"
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
    fn enforce_budget_rejects_arrival_under_delivery() {
        let config = config_with_p99_budget(Duration::from_millis(50));
        let report = make_report(99, 10_000_000);
        assert!(
            matches!(
                enforce_budget(&report, &config),
                Err(LoadgenError::ArrivalRateMissed {
                    scheduled: 100,
                    attempted: 99,
                    completed: 99,
                })
            ),
            "a 100Hz one-second gate must reject a report that delivered only 99 calls"
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
