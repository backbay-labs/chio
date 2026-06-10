//! Three-state circuit breaker for external service calls.
//!
//! The breaker transitions between three states:
//!
//! * [`CircuitState::Closed`] -- normal operation. Failures are counted
//!   inside a sliding window; once the count reaches
//!   [`CircuitBreakerConfig::failure_threshold`], the breaker opens.
//! * [`CircuitState::Open`] -- fail-fast. Calls are short-circuited for at
//!   least [`CircuitBreakerConfig::reset_timeout`].
//! * [`CircuitState::HalfOpen`] -- probing recovery. A limited number of
//!   trial calls are admitted; after
//!   [`CircuitBreakerConfig::success_threshold`] consecutive successes the
//!   breaker closes. Any failure reopens it.
//!
//! The breaker uses a [`Clock`] abstraction for monotonic time so tests can
//! drive transitions via [`tokio::time::pause`] + `advance` without
//! wall-clock sleep.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use super::cache::{Clock, TokioClock};

/// State of the circuit breaker.
///
/// See the module docs for the transition rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation: calls flow through.
    Closed,
    /// Tripped: calls are short-circuited until the reset timeout elapses.
    Open,
    /// Probing: a bounded number of trial calls are admitted to test
    /// whether the external dependency has recovered.
    HalfOpen,
}

/// Static configuration for a [`CircuitBreaker`].
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failures observed within `failure_window` before the breaker opens.
    pub failure_threshold: u32,
    /// Rolling window for failure counting in the Closed state. Failures
    /// older than this are discarded from the sliding count.
    pub failure_window: Duration,
    /// Consecutive successes required in the HalfOpen state before the
    /// breaker transitions back to Closed.
    pub success_threshold: u32,
    /// Time the breaker remains Open before a HalfOpen probe is allowed.
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            failure_window: Duration::from_secs(60),
            success_threshold: 2,
            reset_timeout: Duration::from_secs(30),
        }
    }
}

/// Thread-safe three-state circuit breaker.
pub struct CircuitBreaker {
    inner: Mutex<CircuitInner>,
    config: CircuitBreakerConfig,
    clock: Arc<dyn Clock>,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    /// Timestamps of recent failures in the Closed state.
    failures: Vec<Instant>,
    /// Count of consecutive successes in the HalfOpen state.
    half_open_successes: u32,
    /// When the breaker was last opened, used to schedule the HalfOpen probe.
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a new breaker with the given configuration and the default
    /// ([`TokioClock`]) clock.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self::with_clock(config, Arc::new(TokioClock))
    }

    /// Create a breaker with a custom clock (primarily for tests).
    pub fn with_clock(config: CircuitBreakerConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(CircuitInner {
                state: CircuitState::Closed,
                failures: Vec::new(),
                half_open_successes: 0,
                opened_at: None,
            }),
            config,
            clock,
        }
    }

    /// Current configuration.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Current state. Transitions from Open to HalfOpen happen lazily on
    /// observation, so this call also advances state when appropriate.
    pub fn current_state(&self) -> CircuitState {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return CircuitState::Open;
        };
        self.tick(&mut inner, now);
        inner.state
    }

    /// Ask whether a call is currently allowed through. `true` means the
    /// caller should invoke the downstream service; `false` means the
    /// breaker is Open and the caller must fail fast.
    pub fn allow_call(&self) -> bool {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        self.tick(&mut inner, now);
        !matches!(inner.state, CircuitState::Open)
    }

    /// Record a successful downstream call.
    pub fn record_success(&self) {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        self.tick(&mut inner, now);
        match inner.state {
            CircuitState::Closed => {
                inner.failures.clear();
            }
            CircuitState::HalfOpen => {
                inner.half_open_successes = inner.half_open_successes.saturating_add(1);
                if inner.half_open_successes >= self.config.success_threshold {
                    inner.state = CircuitState::Closed;
                    inner.failures.clear();
                    inner.half_open_successes = 0;
                    inner.opened_at = None;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen -- Open calls are rejected before reaching
                // the downstream. Treat as a no-op.
            }
        }
    }

    /// Record a failed downstream call.
    pub fn record_failure(&self) {
        let now = self.clock.now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        self.tick(&mut inner, now);
        match inner.state {
            CircuitState::Closed => {
                inner.failures.push(now);
                self.drop_stale_failures(&mut inner, now);
                if inner.failures.len() as u32 >= self.config.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.opened_at = Some(now);
                    inner.failures.clear();
                }
            }
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.opened_at = Some(now);
                inner.half_open_successes = 0;
            }
            CircuitState::Open => {
                // Re-arm the open timer.
                inner.opened_at = Some(now);
            }
        }
    }

    /// Reset to Closed with no recorded failures. Useful for explicit
    /// operator intervention or tests.
    pub fn reset(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.state = CircuitState::Closed;
            inner.failures.clear();
            inner.half_open_successes = 0;
            inner.opened_at = None;
        }
    }

    fn tick(&self, inner: &mut CircuitInner, now: Instant) {
        match inner.state {
            CircuitState::Open => {
                if let Some(opened) = inner.opened_at {
                    if now.duration_since(opened) >= self.config.reset_timeout {
                        inner.state = CircuitState::HalfOpen;
                        inner.half_open_successes = 0;
                    }
                }
            }
            CircuitState::Closed => {
                self.drop_stale_failures(inner, now);
            }
            CircuitState::HalfOpen => {}
        }
    }

    fn drop_stale_failures(&self, inner: &mut CircuitInner, now: Instant) {
        let window = self.config.failure_window;
        inner.failures.retain(|ts| now.duration_since(*ts) < window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(failure_threshold: u32) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold,
            failure_window: Duration::from_secs(60),
            success_threshold: 2,
            reset_timeout: Duration::from_secs(10),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn starts_closed() {
        let cb = CircuitBreaker::new(config(5));
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_call());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(config(3));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_call());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn transitions_to_half_open_after_reset_timeout() {
        let cb = CircuitBreaker::new(config(2));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        assert!(cb.allow_call());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn half_open_closes_after_success_threshold() {
        let cb = CircuitBreaker::new(config(2));
        cb.record_failure();
        cb.record_failure();
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn half_open_failure_reopens() {
        let cb = CircuitBreaker::new(config(2));
        cb.record_failure();
        cb.record_failure();
        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stale_failures_are_forgotten() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            failure_window: Duration::from_secs(5),
            success_threshold: 1,
            reset_timeout: Duration::from_secs(10),
        });
        cb.record_failure();
        cb.record_failure();
        tokio::time::advance(Duration::from_secs(6)).await;
        cb.record_failure();
        cb.record_failure();
        // Only 2 failures inside the window -> still closed.
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }
}
