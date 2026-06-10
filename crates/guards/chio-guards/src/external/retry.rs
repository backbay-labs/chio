//! Retry with deterministic jitter for transient external failures.
//!
//! [`retry_with_jitter`] runs an async operation up to `max_retries + 1`
//! times, sleeping between attempts with a backoff controlled by
//! [`BackoffStrategy`] and a bounded multiplicative jitter. The sleep uses
//! [`tokio::time::sleep`], which honors [`tokio::time::pause`] + `advance`
//! so tests don't depend on wall-clock time.
//!
//! Jitter is seeded deterministically from the attempt number by default,
//! which keeps tests reproducible; callers can override the RNG via
//! [`retry_with_jitter_rng`].

use std::future::Future;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

/// Backoff strategy between retry attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffStrategy {
    /// Each attempt sleeps `base_delay * 2^(attempt - 1)` before jitter.
    Exponential,
    /// Each attempt sleeps `base_delay` before jitter.
    Constant,
    /// Each attempt sleeps `base_delay * attempt` before jitter.
    Linear,
}

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries after the initial attempt. A value of `0`
    /// means the operation is attempted exactly once.
    pub max_retries: u32,
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Upper bound on the sleep between attempts (before jitter is added).
    pub max_delay: Duration,
    /// Fraction of the computed delay to use as bounded multiplicative
    /// jitter. Must be in `[0.0, 1.0]`; values outside that range are
    /// clamped.
    pub jitter_fraction: f64,
    /// Backoff curve.
    pub strategy: BackoffStrategy,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter_fraction: 0.25,
            strategy: BackoffStrategy::Exponential,
        }
    }
}

/// Outcome reported by the caller's operation.
pub type AttemptResult<T, E> = Result<T, E>;

/// Run `op` with retry + jitter using a deterministic RNG seeded from
/// `config.max_retries`. For customizable randomness see
/// [`retry_with_jitter_rng`].
pub async fn retry_with_jitter<F, Fut, T, E>(config: &RetryConfig, op: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = AttemptResult<T, E>>,
{
    let seed = u64::from(config.max_retries).wrapping_add(0x9E37_79B9_7F4A_7C15);
    let rng = StdRng::seed_from_u64(seed);
    retry_with_jitter_rng(config, rng, op).await
}

/// Run `op` with retry + jitter using a caller-supplied RNG.
///
/// `op` receives the current attempt number (1-indexed).
pub async fn retry_with_jitter_rng<F, Fut, T, E, R>(
    config: &RetryConfig,
    mut rng: R,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = AttemptResult<T, E>>,
    R: Rng,
{
    let total_attempts = config.max_retries.saturating_add(1);
    let mut last_err: Option<E> = None;
    for attempt in 1..=total_attempts {
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt >= total_attempts {
                    break;
                }
                let delay = compute_delay(config, attempt, &mut rng);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    match last_err {
        Some(err) => Err(err),
        // Unreachable in practice: total_attempts >= 1 so the loop body runs
        // at least once and either returns Ok or records an error.
        None => unreachable!("retry loop must have produced at least one result"),
    }
}

fn compute_delay<R: Rng>(config: &RetryConfig, attempt: u32, rng: &mut R) -> Duration {
    let base = config.base_delay.as_secs_f64().max(0.0);
    let raw = match config.strategy {
        BackoffStrategy::Constant => base,
        BackoffStrategy::Linear => base * f64::from(attempt.max(1)),
        BackoffStrategy::Exponential => {
            // 2^(attempt - 1). Clamp the exponent to avoid overflow.
            let exp = attempt.saturating_sub(1).min(30);
            base * (1u64 << exp) as f64
        }
    };
    let max_secs = config.max_delay.as_secs_f64().max(0.0);
    let capped = raw.min(max_secs);
    let jitter = config.jitter_fraction.clamp(0.0, 1.0);
    let factor = if jitter == 0.0 {
        1.0
    } else {
        1.0 + rng.gen_range(-jitter..=jitter)
    };
    let jittered = (capped * factor).max(0.0);
    Duration::from_secs_f64(jittered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn succeeds_on_first_attempt() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);
        let config = RetryConfig::default();
        let result: Result<u32, &'static str> = retry_with_jitter(&config, |_| {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(42)
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn succeeds_after_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);
        let config = RetryConfig {
            max_retries: 4,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(40),
            jitter_fraction: 0.0,
            strategy: BackoffStrategy::Exponential,
        };
        let result: Result<u32, &'static str> = retry_with_jitter(&config, move |_| {
            let counter = Arc::clone(&counter_clone);
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err("transient")
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(3));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn returns_last_error_after_exhausting_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);
        let config = RetryConfig {
            max_retries: 2,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
            jitter_fraction: 0.0,
            strategy: BackoffStrategy::Constant,
        };
        let result: Result<u32, &'static str> = retry_with_jitter(&config, move |_| {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err("always fails")
            }
        })
        .await;
        assert_eq!(result, Err("always fails"));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn zero_max_retries_runs_once() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);
        let config = RetryConfig {
            max_retries: 0,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter_fraction: 0.0,
            strategy: BackoffStrategy::Exponential,
        };
        let result: Result<u32, &'static str> = retry_with_jitter(&config, move |_| {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err("boom")
            }
        })
        .await;
        assert_eq!(result, Err("boom"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn compute_delay_caps_at_max_delay() {
        let config = RetryConfig {
            max_retries: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            jitter_fraction: 0.0,
            strategy: BackoffStrategy::Exponential,
        };
        let mut rng = StdRng::seed_from_u64(1);
        // 2^9 * 100ms = 51.2s, should be capped to 500ms.
        let d = compute_delay(&config, 10, &mut rng);
        assert_eq!(d, Duration::from_millis(500));
    }
}
