//! Simple token bucket rate limiter for the external guard adapter.
//!
//! Unlike [`crate::velocity::VelocityGuard`] which tracks per-grant buckets
//! with milli-token precision, this bucket is a single-instance rate limiter
//! intended to cap the QPS of one [`crate::external::AsyncGuardAdapter`].
//!
//! The bucket uses a [`Clock`] abstraction so tests drive time via Tokio's
//! pausable timer.

use std::sync::Arc;
use std::sync::Mutex;

use tokio::time::Instant;

use super::cache::{Clock, TokioClock};

/// Single-instance token bucket rate limiter.
///
/// Tokens refill continuously at `rate_per_second` up to the `burst`
/// ceiling. A call to [`TokenBucket::try_acquire`] consumes one token;
/// returns `true` on success and `false` when the bucket is empty.
pub struct TokenBucket {
    inner: Mutex<BucketInner>,
    rate_per_second: f64,
    burst: f64,
    clock: Arc<dyn Clock>,
}

#[derive(Debug)]
struct BucketInner {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket with `rate_per_second` refill rate and `burst`
    /// capacity. Starts full. `rate_per_second` is clamped to `>= 0.0`; a
    /// zero rate means the bucket never refills (only the initial burst
    /// is available).
    pub fn new(rate_per_second: f64, burst: u32) -> Self {
        Self::with_clock(rate_per_second, burst, Arc::new(TokioClock))
    }

    /// Create a bucket with a custom clock.
    pub fn with_clock(rate_per_second: f64, burst: u32, clock: Arc<dyn Clock>) -> Self {
        let rate = rate_per_second.max(0.0);
        let burst_f = f64::from(burst.max(1));
        let now = clock.now();
        Self {
            inner: Mutex::new(BucketInner {
                tokens: burst_f,
                last_refill: now,
            }),
            rate_per_second: rate,
            burst: burst_f,
            clock,
        }
    }

    /// Configured refill rate (tokens per second).
    pub fn rate_per_second(&self) -> f64 {
        self.rate_per_second
    }

    /// Configured burst ceiling.
    pub fn burst(&self) -> u32 {
        self.burst as u32
    }

    /// Attempt to consume one token. Returns `true` if a token was available
    /// (and consumed); `false` otherwise.
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_n(1.0)
    }

    /// Attempt to consume `n` tokens.
    pub fn try_acquire_n(&self, n: f64) -> bool {
        if n <= 0.0 {
            return true;
        }
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        self.refill(&mut inner, now);
        if inner.tokens + f64::EPSILON >= n {
            inner.tokens -= n;
            if inner.tokens < 0.0 {
                inner.tokens = 0.0;
            }
            true
        } else {
            false
        }
    }

    /// Current token count. Mainly useful for tests and diagnostics.
    pub fn available(&self) -> f64 {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return 0.0;
        };
        self.refill(&mut inner, now);
        inner.tokens
    }

    fn refill(&self, inner: &mut BucketInner, now: Instant) {
        if self.rate_per_second == 0.0 {
            inner.last_refill = now;
            return;
        }
        let elapsed = now
            .saturating_duration_since(inner.last_refill)
            .as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let added = elapsed * self.rate_per_second;
        inner.tokens = (inner.tokens + added).min(self.burst);
        inner.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn starts_full_with_burst_capacity() {
        let bucket = TokenBucket::new(1.0, 3);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn refills_at_configured_rate() {
        let bucket = TokenBucket::new(2.0, 2);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
        tokio::time::advance(Duration::from_millis(1100)).await;
        // After 1.1s at 2 tok/s we should have ~2 tokens (capped).
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn zero_rate_only_uses_burst() {
        let bucket = TokenBucket::new(0.0, 1);
        assert!(bucket.try_acquire());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(!bucket.try_acquire());
    }
}
