//! Per-exporter rate limiting for SIEM batch exports.
//!
//! The limiter is intentionally scoped to `chio-siem`'s batch fan-out boundary:
//! each exporter name gets its own token bucket, and each export attempt
//! consumes one logical batch token.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for per-exporter batch rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum export batches allowed per window for each exporter.
    pub max_batches_per_window: u32,
    /// Window used to derive the steady-state refill rate.
    pub window: Duration,
    /// Burst capacity multiplier applied to `max_batches_per_window`.
    pub burst_factor: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_batches_per_window: 1,
            window: Duration::from_secs(1),
            burst_factor: 1.0,
        }
    }
}

/// Error returned for invalid rate-limit configuration.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitConfigError {
    #[error("max_batches_per_window must be greater than zero")]
    ZeroMaxBatches,
    #[error("rate-limit window must be greater than zero")]
    ZeroWindow,
    #[error("burst_factor must be finite and greater than zero")]
    InvalidBurstFactor,
    #[error("burst capacity overflows supported range")]
    CapacityOverflow,
}

impl RateLimitConfig {
    fn validate(&self) -> Result<(), RateLimitConfigError> {
        if self.max_batches_per_window == 0 {
            return Err(RateLimitConfigError::ZeroMaxBatches);
        }
        if self.window.is_zero() {
            return Err(RateLimitConfigError::ZeroWindow);
        }
        if !self.burst_factor.is_finite() || self.burst_factor <= 0.0 {
            return Err(RateLimitConfigError::InvalidBurstFactor);
        }
        self.capacity_tokens()?;
        Ok(())
    }

    fn capacity_tokens(&self) -> Result<u64, RateLimitConfigError> {
        let capacity = (f64::from(self.max_batches_per_window) * self.burst_factor).ceil();
        if !capacity.is_finite() || capacity <= 0.0 || capacity > u64::MAX as f64 {
            return Err(RateLimitConfigError::CapacityOverflow);
        }
        Ok((capacity as u64).max(1))
    }
}

/// Rate limiter keyed by exporter name.
#[derive(Debug)]
pub struct ExportRateLimiter {
    config: RateLimitConfig,
    buckets: HashMap<String, TokenBucket>,
}

impl ExportRateLimiter {
    /// Create a new per-exporter rate limiter from validated configuration.
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            buckets: HashMap::new(),
        })
    }

    /// Returns the amount of time the caller should wait before the named
    /// exporter may send its next batch. `Duration::ZERO` means the caller may
    /// proceed immediately and the token has already been consumed.
    pub fn acquire_delay(&mut self, exporter_name: &str) -> Duration {
        let Ok(capacity_tokens) = self.config.capacity_tokens() else {
            unreachable!("validated rate-limit config should remain valid");
        };

        let bucket = self
            .buckets
            .entry(exporter_name.to_string())
            .or_insert_with(|| {
                TokenBucket::new(
                    capacity_tokens,
                    u64::from(self.config.max_batches_per_window),
                    self.config.window,
                )
            });

        bucket.acquire_delay()
    }
}

#[derive(Debug)]
struct TokenBucket {
    capacity_mt: u64,
    tokens_mt: u64,
    refill_rate_mpm: u64,
    last_refill: Instant,
}

const MT_PER_TOKEN: u64 = 1_000;

impl TokenBucket {
    fn new(capacity_tokens: u64, max_batches_per_window: u64, window: Duration) -> Self {
        let window_ms = (window.as_millis() as u64).max(1);
        let refill_rate_mpm = max_batches_per_window
            .saturating_mul(MT_PER_TOKEN)
            .checked_div(window_ms)
            .unwrap_or(1)
            .max(1);

        Self {
            capacity_mt: capacity_tokens.saturating_mul(MT_PER_TOKEN),
            tokens_mt: capacity_tokens.saturating_mul(MT_PER_TOKEN),
            refill_rate_mpm,
            last_refill: Instant::now(),
        }
    }

    fn acquire_delay(&mut self) -> Duration {
        self.refill();
        if self.tokens_mt >= MT_PER_TOKEN {
            self.tokens_mt -= MT_PER_TOKEN;
            return Duration::ZERO;
        }

        let deficit_mt = MT_PER_TOKEN.saturating_sub(self.tokens_mt);
        let wait_ms = deficit_mt
            .saturating_add(self.refill_rate_mpm.saturating_sub(1))
            .checked_div(self.refill_rate_mpm)
            .unwrap_or(1)
            .max(1);
        Duration::from_millis(wait_ms)
    }

    fn refill(&mut self) {
        let elapsed_ms = self.last_refill.elapsed().as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }

        let added = elapsed_ms.saturating_mul(self.refill_rate_mpm);
        self.tokens_mt = self.tokens_mt.saturating_add(added).min(self.capacity_mt);
        self.last_refill = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn rate_limiter_requires_valid_config() {
        let error = match ExportRateLimiter::new(RateLimitConfig {
            max_batches_per_window: 0,
            window: Duration::from_secs(1),
            burst_factor: 1.0,
        }) {
            Ok(_) => panic!("zero batches must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, RateLimitConfigError::ZeroMaxBatches));
    }

    #[test]
    fn rate_limiter_refills_after_window() {
        let mut limiter = match ExportRateLimiter::new(RateLimitConfig {
            max_batches_per_window: 1,
            window: Duration::from_millis(100),
            burst_factor: 1.0,
        }) {
            Ok(limiter) => limiter,
            Err(error) => panic!("valid limiter: {error}"),
        };

        assert_eq!(limiter.acquire_delay("splunk-hec"), Duration::ZERO);
        assert!(
            limiter.acquire_delay("splunk-hec") >= Duration::from_millis(50),
            "second immediate acquire should require waiting"
        );

        thread::sleep(Duration::from_millis(120));

        assert_eq!(
            limiter.acquire_delay("splunk-hec"),
            Duration::ZERO,
            "bucket should refill after the window passes"
        );
    }

    #[test]
    fn rate_limiter_is_per_exporter() {
        let mut limiter = match ExportRateLimiter::new(RateLimitConfig {
            max_batches_per_window: 1,
            window: Duration::from_millis(200),
            burst_factor: 1.0,
        }) {
            Ok(limiter) => limiter,
            Err(error) => panic!("valid limiter: {error}"),
        };

        assert_eq!(limiter.acquire_delay("splunk-hec"), Duration::ZERO);
        assert_eq!(
            limiter.acquire_delay("elasticsearch-bulk"),
            Duration::ZERO,
            "different exporters should have independent buckets"
        );
    }
}
