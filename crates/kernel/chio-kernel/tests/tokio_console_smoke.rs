#![cfg(feature = "tokio-console-smoke")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKERS: usize = 8;
const ITERATIONS: usize = 128;
const MAX_IDLE: Duration = Duration::from_secs(1);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_allow_smoke_has_no_idle_over_one_second() -> TestResult {
    let max_idle_ns = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(WORKERS);

    for worker in 0..WORKERS {
        let max_idle_ns = Arc::clone(&max_idle_ns);
        handles.push(tokio::spawn(async move {
            let mut last_progress = Instant::now();
            for iteration in 0..ITERATIONS {
                tracing::info_span!("dispatch_allow_smoke_iteration", worker, iteration).in_scope(
                    || {
                        std::hint::black_box(0_u64);
                    },
                );
                tokio::task::yield_now().await;
                let idle = last_progress.elapsed();
                last_progress = Instant::now();
                record_max_idle(&max_idle_ns, idle);
                if idle > MAX_IDLE {
                    return Err(std::io::Error::other(format!(
                        "worker {worker} idle exceeded {MAX_IDLE:?}: {idle:?}"
                    )));
                }
            }
            Ok::<(), std::io::Error>(())
        }));
    }

    for handle in handles {
        handle.await??;
    }

    let max_idle = Duration::from_nanos(max_idle_ns.load(Ordering::Relaxed));
    assert!(
        max_idle <= MAX_IDLE,
        "dispatch_allow smoke max idle exceeded {MAX_IDLE:?}: {max_idle:?}"
    );
    Ok(())
}

fn record_max_idle(max_idle_ns: &AtomicU64, idle: Duration) {
    let idle_ns = idle.as_nanos().min(u128::from(u64::MAX)) as u64;
    let mut observed = max_idle_ns.load(Ordering::Relaxed);
    while idle_ns > observed {
        match max_idle_ns.compare_exchange_weak(
            observed,
            idle_ns,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}
