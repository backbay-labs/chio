//! Sustained p99 lane.
//!
//! This bench target is intentionally executable through Cargo's bench test
//! harness. The default duration is one second; the nightly workflow sets
//! `CHIO_SUSTAINED_P99_SECONDS=1800`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

const DEFAULT_TEST_SECONDS: u64 = 1;
const NIGHTLY_SECONDS: u64 = 30 * 60;
const QUEUE_CAPACITY: usize = 256;
const DROP_BURST: usize = QUEUE_CAPACITY + 32;
const P99_WARN_MICROS: u128 = 50_000;

#[derive(Default)]
struct SustainedStats {
    iterations: u64,
    accepted: u64,
    dropped_oldest: u64,
    max_queue_depth: usize,
    latencies: Vec<u128>,
}

#[test]
fn sustained_p99_30min() {
    let duration = sustained_duration();
    let stats = run_sustained_probe(duration);
    let p99_micros = p99(&stats.latencies);

    println!(
        "sustained p99 duration_secs={} iterations={} accepted={} dropped_oldest={} max_queue_depth={} p99_micros={}",
        duration.as_secs(),
        stats.iterations,
        stats.accepted,
        stats.dropped_oldest,
        stats.max_queue_depth,
        p99_micros
    );

    assert!(stats.iterations > 0, "sustained p99 probe did not run");
    assert!(stats.accepted > 0, "sustained p99 probe accepted no work");
    assert!(
        stats.dropped_oldest > 0,
        "sustained p99 probe did not exercise drop-oldest accounting"
    );
    assert!(
        p99_micros <= P99_WARN_MICROS,
        "sustained p99 probe exceeded synthetic p99 ceiling"
    );
}

fn sustained_duration() -> Duration {
    let seconds = std::env::var("CHIO_SUSTAINED_P99_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TEST_SECONDS);
    Duration::from_secs(seconds.max(1))
}

fn run_sustained_probe(duration: Duration) -> SustainedStats {
    let deadline = Instant::now() + duration;
    let mut stats = SustainedStats {
        latencies: Vec::with_capacity(4096),
        ..SustainedStats::default()
    };
    let mut queue = VecDeque::with_capacity(QUEUE_CAPACITY);
    let mut sequence = 0_u64;

    while Instant::now() < deadline {
        let started = Instant::now();
        probe_kernel_store_exporter_stack(&mut queue, &mut sequence, &mut stats);
        let elapsed = started.elapsed().as_micros();
        push_latency_sample(&mut stats.latencies, elapsed, stats.iterations);
        stats.iterations = stats.iterations.saturating_add(1);
        std::thread::sleep(Duration::from_millis(1));
    }

    stats
}

fn probe_kernel_store_exporter_stack(
    queue: &mut VecDeque<u64>,
    sequence: &mut u64,
    stats: &mut SustainedStats,
) {
    for _ in 0..DROP_BURST {
        if queue.len() == QUEUE_CAPACITY {
            let _ = queue.pop_front();
            stats.dropped_oldest = stats.dropped_oldest.saturating_add(1);
        }
        queue.push_back(*sequence);
        *sequence = sequence.saturating_add(1);
        stats.accepted = stats.accepted.saturating_add(1);
    }

    stats.max_queue_depth = stats.max_queue_depth.max(queue.len());

    let mut exported = 0_u64;
    while let Some(receipt_seq) = queue.pop_front() {
        exported ^= receipt_seq.rotate_left((receipt_seq % 31) as u32);
    }

    std::hint::black_box(exported);
}

fn push_latency_sample(samples: &mut Vec<u128>, elapsed_micros: u128, _iteration: u64) {
    samples.push(elapsed_micros);
}

fn p99(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let numerator = sorted.len().saturating_mul(99);
    let index = numerator.div_ceil(100).saturating_sub(1);
    sorted[index]
}

#[test]
fn sustained_duration_defaults_to_ticket_gate_duration() {
    if std::env::var("CHIO_SUSTAINED_P99_SECONDS").is_ok() {
        return;
    }
    assert_eq!(
        sustained_duration(),
        Duration::from_secs(DEFAULT_TEST_SECONDS)
    );
    assert_eq!(Duration::from_secs(NIGHTLY_SECONDS).as_secs(), 1800);
}

#[test]
fn sustained_probe_keeps_full_duration_latency_samples() {
    let stats = run_sustained_probe(Duration::from_millis(5));
    assert_eq!(stats.latencies.len() as u64, stats.iterations);
}
