use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::HostedEdgeError;

const MAX_RATE_LIMIT_KEY_BYTES: usize = 512;

/// Fixed-window limiter bounds: window length, per-key request
/// ceiling, and the maximum distinct keys retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedRateLimitConfig {
    pub window_secs: u64,
    pub maximum_requests: u32,
    pub maximum_keys: usize,
}

impl HostedRateLimitConfig {
    fn validate(self) -> Result<(), HostedEdgeError> {
        if !(1..=3_600).contains(&self.window_secs)
            || !(1..=1_000_000).contains(&self.maximum_requests)
            || !(1..=1_000_000).contains(&self.maximum_keys)
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct RateWindow {
    started_at: u64,
    count: u32,
}

#[derive(Default)]
struct RateWindows {
    entries: BTreeMap<String, RateWindow>,
    /// Fixed window whose expired entries have already been swept. Bounds
    /// the eviction scan to once per window transition instead of once per
    /// new key under capacity pressure.
    swept_at_window: u64,
}

/// Bounded pre-body limiter. Distributed monetary and tenant quotas remain
/// authoritative in durable storage; this limiter protects each edge replica.
pub struct HostedRateLimiter {
    config: HostedRateLimitConfig,
    windows: Mutex<RateWindows>,
}

impl HostedRateLimiter {
    /// Fail closed on zero bounds.
    pub fn new(config: HostedRateLimitConfig) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        Ok(Self {
            config,
            windows: Mutex::new(RateWindows::default()),
        })
    }

    /// Admit one authenticated-header request before reading its body.
    /// Returns the retry delay when the caller's fixed window is exhausted.
    pub fn admit(&self, key: &str, now: u64) -> Result<(), HostedEdgeError> {
        if key.is_empty()
            || key.len() > MAX_RATE_LIMIT_KEY_BYTES
            || key.chars().any(char::is_control)
            || now == 0
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let window_start = now - (now % self.config.window_secs);
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        if windows.swept_at_window != window_start {
            windows
                .entries
                .retain(|_, window| window.started_at == window_start);
            windows.swept_at_window = window_start;
        }
        if windows.entries.len() >= self.config.maximum_keys && !windows.entries.contains_key(key) {
            return Err(HostedEdgeError::CapacityUnavailable);
        }
        match windows.entries.get_mut(key) {
            Some(window) if window.started_at == window_start => {
                if window.count >= self.config.maximum_requests {
                    return Err(HostedEdgeError::RateLimited);
                }
                window.count = window.count.saturating_add(1);
            }
            _ => {
                windows.entries.insert(
                    key.to_owned(),
                    RateWindow {
                        started_at: window_start,
                        count: 1,
                    },
                );
            }
        }
        Ok(())
    }
}

/// The downstream dependencies the edge tracks health for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostedDependency {
    Database,
    Signer,
    Payment,
    Collateral,
    AuditWitness,
    Worker,
    Tls,
}

/// Breaker thresholds: consecutive failures to open and how long the
/// circuit stays open before a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedCircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_secs: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: u64,
    trial_in_flight: bool,
}

/// A fixed-dependency breaker. Open or poisoned state always closes admission.
pub struct HostedCircuitBreaker {
    config: HostedCircuitBreakerConfig,
    states: Mutex<BTreeMap<HostedDependency, BreakerState>>,
}

impl HostedCircuitBreaker {
    /// Fail closed on zero bounds.
    pub fn new(config: HostedCircuitBreakerConfig) -> Result<Self, HostedEdgeError> {
        if !(1..=100).contains(&config.failure_threshold)
            || !(1..=3_600).contains(&config.open_secs)
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(Self {
            config,
            states: Mutex::new(BTreeMap::new()),
        })
    }

    /// Deny when the dependency circuit is open and its cooldown has not
    /// elapsed.
    pub fn admit(&self, dependency: HostedDependency, now: u64) -> Result<(), HostedEdgeError> {
        if now == 0 {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let mut states = self
            .states
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        let state = states.entry(dependency).or_default();
        if state.open_until > now {
            return Err(HostedEdgeError::DependencyUnavailable);
        }
        if state.open_until != 0 {
            if state.trial_in_flight {
                return Err(HostedEdgeError::DependencyUnavailable);
            }
            state.trial_in_flight = true;
        }
        Ok(())
    }

    /// Close the dependency circuit and clear its failure streak.
    pub fn record_success(&self, dependency: HostedDependency) -> Result<(), HostedEdgeError> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        states.insert(dependency, BreakerState::default());
        Ok(())
    }

    /// Count one failure; the circuit opens at the configured threshold.
    pub fn record_failure(
        &self,
        dependency: HostedDependency,
        now: u64,
    ) -> Result<(), HostedEdgeError> {
        if now == 0 {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let mut states = self
            .states
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        let state = states.entry(dependency).or_default();
        state.trial_in_flight = false;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.config.failure_threshold {
            state.open_until = now.saturating_add(self.config.open_secs);
        }
        Ok(())
    }

    /// Whether the dependency currently admits traffic.
    pub fn is_closed(&self, dependency: HostedDependency, now: u64) -> bool {
        self.states.lock().is_ok_and(|states| {
            states.get(&dependency).is_none_or(|state| {
                state.open_until == 0
                    && state.open_until <= now
                    && !state.trial_in_flight
                    && state.consecutive_failures < self.config.failure_threshold
            })
        })
    }
}

/// Readiness of every tracked dependency at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedReadinessSnapshot {
    pub ready: bool,
    pub unavailable: Vec<HostedDependency>,
}

/// Tracks per-dependency readiness for the health endpoints.
pub struct HostedReadiness {
    dependencies: Mutex<BTreeMap<HostedDependency, bool>>,
}

impl HostedReadiness {
    /// Fail closed on zero bounds.
    pub fn new(
        required: impl IntoIterator<Item = HostedDependency>,
    ) -> Result<Self, HostedEdgeError> {
        let dependencies: BTreeMap<_, _> = required.into_iter().map(|item| (item, false)).collect();
        if dependencies.is_empty() {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(Self {
            dependencies: Mutex::new(dependencies),
        })
    }

    /// Record one dependency readiness observation.
    pub fn record(&self, dependency: HostedDependency, ready: bool) -> Result<(), HostedEdgeError> {
        let mut dependencies = self
            .dependencies
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        let value = dependencies
            .get_mut(&dependency)
            .ok_or(HostedEdgeError::Configuration)?;
        *value = ready;
        Ok(())
    }

    /// The current readiness of every tracked dependency.
    pub fn snapshot(&self) -> HostedReadinessSnapshot {
        let Ok(dependencies) = self.dependencies.lock() else {
            return HostedReadinessSnapshot {
                ready: false,
                unavailable: Vec::new(),
            };
        };
        let unavailable = dependencies
            .iter()
            .filter_map(|(dependency, ready)| (!ready).then_some(*dependency))
            .collect::<Vec<_>>();
        HostedReadinessSnapshot {
            ready: unavailable.is_empty(),
            unavailable,
        }
    }
}

/// Counter families the edge increments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedMetricEvent {
    RequestAccepted,
    RequestDenied,
    AuthenticationDenied,
    QuotaDenied,
    SignerError,
    PaymentError,
    CollateralError,
    WorkerError,
    LeaseConflict,
    TransitionCompleted,
    TransitionFailed,
}

/// Every counter value at one instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostedMetricSnapshot {
    pub request_accepted: u64,
    pub request_denied: u64,
    pub authentication_denied: u64,
    pub quota_denied: u64,
    pub signer_error: u64,
    pub payment_error: u64,
    pub collateral_error: u64,
    pub worker_error: u64,
    pub lease_conflict: u64,
    pub transition_completed: u64,
    pub transition_failed: u64,
}

/// Monotonic in-process counters for the operational endpoints.
#[derive(Default)]
pub struct HostedEdgeMetrics {
    counters: [AtomicU64; 11],
}

impl HostedEdgeMetrics {
    /// Count one event.
    pub fn increment(&self, event: HostedMetricEvent) {
        self.counters[event as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The current readiness of every tracked dependency.
    #[must_use]
    pub fn snapshot(&self) -> HostedMetricSnapshot {
        let value = |index: usize| self.counters[index].load(Ordering::Relaxed);
        HostedMetricSnapshot {
            request_accepted: value(0),
            request_denied: value(1),
            authentication_denied: value(2),
            quota_denied: value(3),
            signer_error: value(4),
            payment_error: value(5),
            collateral_error: value(6),
            worker_error: value(7),
            lease_conflict: value(8),
            transition_completed: value(9),
            transition_failed: value(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_is_bounded_and_resets_only_at_window_boundary() {
        let limiter = HostedRateLimiter::new(HostedRateLimitConfig {
            window_secs: 10,
            maximum_requests: 2,
            maximum_keys: 1,
        });
        assert!(limiter.is_ok());
        if let Ok(limiter) = limiter {
            assert!(limiter.admit("ip:192.0.2.1", 11).is_ok());
            assert!(limiter.admit("ip:192.0.2.1", 12).is_ok());
            assert_eq!(
                limiter.admit("ip:192.0.2.1", 13),
                Err(HostedEdgeError::RateLimited)
            );
            assert!(limiter.admit("ip:192.0.2.2", 20).is_ok());
        }
    }

    #[test]
    fn breaker_allows_one_half_open_trial_and_fail_closes() {
        let breaker = HostedCircuitBreaker::new(HostedCircuitBreakerConfig {
            failure_threshold: 2,
            open_secs: 10,
        });
        assert!(breaker.is_ok());
        if let Ok(breaker) = breaker {
            assert!(breaker
                .record_failure(HostedDependency::Payment, 10)
                .is_ok());
            assert!(breaker
                .record_failure(HostedDependency::Payment, 11)
                .is_ok());
            assert!(breaker.admit(HostedDependency::Payment, 15).is_err());
            assert!(breaker.admit(HostedDependency::Payment, 21).is_ok());
            assert!(breaker.admit(HostedDependency::Payment, 21).is_err());
            assert!(breaker.record_success(HostedDependency::Payment).is_ok());
            assert!(breaker.admit(HostedDependency::Payment, 22).is_ok());
        }
    }

    #[test]
    fn readiness_and_metrics_have_only_closed_labels() {
        let readiness =
            HostedReadiness::new([HostedDependency::Database, HostedDependency::Payment]);
        assert!(readiness.is_ok());
        if let Ok(readiness) = readiness {
            assert!(!readiness.snapshot().ready);
            assert!(readiness.record(HostedDependency::Database, true).is_ok());
            assert!(readiness.record(HostedDependency::Payment, true).is_ok());
            assert!(readiness.snapshot().ready);
        }
        let metrics = HostedEdgeMetrics::default();
        metrics.increment(HostedMetricEvent::AuthenticationDenied);
        assert_eq!(metrics.snapshot().authentication_denied, 1);
    }
}
