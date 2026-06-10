//! External guard adapter infrastructure.
//!
//! The building blocks in this module let you wrap a synchronous external
//! API (cloud guardrails, threat intel feeds, ML classifiers) as an async
//! Chio guard without leaking I/O concerns into the sync [`chio_kernel::Guard`]
//! trait.
//!
//! The pieces are:
//!
//! * [`ExternalGuard`] -- the async trait a concrete external adapter
//!   implements. It describes the one operation we actually want to make
//!   resilient: `eval(ctx) -> Result<Verdict, _>`.
//! * [`AsyncGuardAdapter`] -- composes a [`circuit_breaker::CircuitBreaker`],
//!   [`token_bucket::TokenBucket`], [`cache::TtlCache`], and
//!   [`retry_with_jitter`] around an [`ExternalGuard`].
//! * [`CircuitOpenVerdict`] -- what the adapter returns when the breaker is
//!   open. Default is [`CircuitOpenVerdict::Deny`] (fail-closed).
//! * [`RateLimitedVerdict`] -- what the adapter returns when the rate
//!   limiter rejects a call. Default is [`RateLimitedVerdict::Deny`]
//!   (fail-closed by design).
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use std::time::Duration;
//! use async_trait::async_trait;
//! use chio_guards::external::{
//!     AsyncGuardAdapter, ExternalGuard, ExternalGuardError, GuardCallContext,
//! };
//! use chio_kernel::Verdict;
//!
//! struct HelloGuard;
//!
//! #[async_trait]
//! impl ExternalGuard for HelloGuard {
//!     fn name(&self) -> &str { "hello" }
//!     fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
//!         Some(ctx.tool_name.clone())
//!     }
//!     async fn eval(&self, _ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
//!         Ok(Verdict::Allow)
//!     }
//! }
//!
//! let adapter = AsyncGuardAdapter::builder(Arc::new(HelloGuard))
//!     .cache_ttl(Duration::from_secs(30))
//!     .build();
//! ```

pub mod cache;
pub mod circuit_breaker;
pub mod retry;
pub mod token_bucket;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chio_kernel::Verdict;
use thiserror::Error;

pub use cache::{Clock, TokioClock, TtlCache};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use retry::{retry_with_jitter, retry_with_jitter_rng, BackoffStrategy, RetryConfig};
pub use token_bucket::TokenBucket;

/// Subset of guard-request information passed to an [`ExternalGuard`].
///
/// This is intentionally a thin, owned structure: external guards typically
/// need to cache or hash a small description of the request rather than the
/// full kernel `GuardContext`. Concrete adapters can extend this by wrapping
/// the adapter in a kernel-level [`chio_kernel::Guard`] that synthesizes a
/// richer `GuardCallContext` from the actual `GuardContext`.
#[derive(Debug, Clone, Default)]
pub struct GuardCallContext {
    /// Tool name being invoked.
    pub tool_name: String,
    /// Calling agent identifier.
    pub agent_id: String,
    /// Target server identifier.
    pub server_id: String,
    /// Tool arguments serialized as JSON. Kept as a `String` so the cache
    /// key can hash it cheaply without committing to a fixed schema.
    pub arguments_json: String,
}

/// Errors surfaced from an [`ExternalGuard`] call.
#[derive(Debug, Error)]
pub enum ExternalGuardError {
    /// The downstream service timed out.
    #[error("external guard timeout")]
    Timeout,
    /// The downstream service returned a retryable failure (5xx, connection
    /// reset, etc.). Retryable errors are counted towards the circuit
    /// breaker and may trigger a retry.
    #[error("transient external error: {0}")]
    Transient(String),
    /// A permanent error that should not be retried (e.g. malformed request,
    /// 4xx auth failure).
    #[error("permanent external error: {0}")]
    Permanent(String),
}

impl ExternalGuardError {
    /// Returns true for errors that should count as a circuit-breaker
    /// failure and be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout | Self::Transient(_))
    }
}

/// Trait implemented by guards that call external services.
///
/// Keep implementations free of retry / caching / rate-limiting concerns
/// -- those are handled by [`AsyncGuardAdapter`]. The `eval` method should
/// describe a single attempt: one HTTP call (or equivalent), one decision.
#[async_trait]
pub trait ExternalGuard: Send + Sync {
    /// Human-readable guard name (e.g. `"bedrock-guardrail"`).
    fn name(&self) -> &str;

    /// Return a cache key for this request, or `None` to skip caching.
    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String>;

    /// Evaluate the request against the external service.
    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError>;
}

/// Verdict returned when the circuit breaker is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CircuitOpenVerdict {
    /// Fail-closed: deny the request while the breaker is open (default).
    #[default]
    Deny,
    /// Fail-open: allow the request while the breaker is open. Use only for
    /// advisory guards where unavailability should not block traffic.
    Allow,
}

impl CircuitOpenVerdict {
    fn to_verdict(self) -> Verdict {
        match self {
            Self::Deny => Verdict::Deny,
            Self::Allow => Verdict::Allow,
        }
    }
}

/// Verdict returned when the token bucket rejects a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateLimitedVerdict {
    /// Fail-closed: deny the request when we exceed the guard's QPS budget.
    /// This is the default.
    #[default]
    Deny,
    /// Fail-open: allow the request when rate limited. Useful for advisory
    /// guards where overloading the external service is acceptable.
    Allow,
}

impl RateLimitedVerdict {
    fn to_verdict(self) -> Verdict {
        match self {
            Self::Deny => Verdict::Deny,
            Self::Allow => Verdict::Allow,
        }
    }
}

/// Configuration for [`AsyncGuardAdapter`]. Built via
/// [`AsyncGuardAdapter::builder`].
#[derive(Debug, Clone)]
pub struct AsyncGuardAdapterConfig {
    /// Circuit breaker tuning.
    pub circuit: CircuitBreakerConfig,
    /// Retry configuration applied inside the breaker.
    pub retry: RetryConfig,
    /// Maximum number of cached verdicts.
    pub cache_capacity: NonZeroUsize,
    /// TTL applied to every cached verdict.
    pub cache_ttl: Duration,
    /// Rate limit (calls per second).
    pub rate_per_second: f64,
    /// Burst capacity for the rate limiter.
    pub rate_burst: u32,
    /// Verdict returned when the breaker is open.
    pub circuit_open_verdict: CircuitOpenVerdict,
    /// Verdict returned when the rate limiter rejects a call.
    pub rate_limited_verdict: RateLimitedVerdict,
}

impl Default for AsyncGuardAdapterConfig {
    fn default() -> Self {
        Self {
            circuit: CircuitBreakerConfig::default(),
            retry: RetryConfig::default(),
            cache_capacity: NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN),
            cache_ttl: Duration::from_secs(60),
            rate_per_second: 20.0,
            rate_burst: 20,
            circuit_open_verdict: CircuitOpenVerdict::Deny,
            rate_limited_verdict: RateLimitedVerdict::Deny,
        }
    }
}

/// Fluent builder for [`AsyncGuardAdapter`].
pub struct AsyncGuardAdapterBuilder<E: ExternalGuard + ?Sized> {
    inner: Arc<E>,
    config: AsyncGuardAdapterConfig,
    clock: Arc<dyn Clock>,
}

impl<E: ExternalGuard + ?Sized> AsyncGuardAdapterBuilder<E> {
    /// Start from the given guard and default configuration.
    pub fn new(inner: Arc<E>) -> Self {
        Self {
            inner,
            config: AsyncGuardAdapterConfig::default(),
            clock: Arc::new(TokioClock),
        }
    }

    /// Override the circuit breaker configuration.
    pub fn circuit(mut self, circuit: CircuitBreakerConfig) -> Self {
        self.config.circuit = circuit;
        self
    }

    /// Override retry configuration.
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.config.retry = retry;
        self
    }

    /// Set the cache capacity (non-zero).
    pub fn cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.config.cache_capacity = capacity;
        self
    }

    /// Set the cache TTL.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.cache_ttl = ttl;
        self
    }

    /// Set the rate limiter (calls per second + burst).
    pub fn rate_limit(mut self, rate_per_second: f64, burst: u32) -> Self {
        self.config.rate_per_second = rate_per_second;
        self.config.rate_burst = burst;
        self
    }

    /// Set the verdict returned while the breaker is open.
    pub fn circuit_open_verdict(mut self, verdict: CircuitOpenVerdict) -> Self {
        self.config.circuit_open_verdict = verdict;
        self
    }

    /// Set the verdict returned when the rate limiter rejects a call.
    pub fn rate_limited_verdict(mut self, verdict: RateLimitedVerdict) -> Self {
        self.config.rate_limited_verdict = verdict;
        self
    }

    /// Override the time source. Primarily for tests.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> AsyncGuardAdapter<E> {
        let cache = TtlCache::with_clock(self.config.cache_capacity, Arc::clone(&self.clock));
        let circuit =
            CircuitBreaker::with_clock(self.config.circuit.clone(), Arc::clone(&self.clock));
        let bucket = TokenBucket::with_clock(
            self.config.rate_per_second,
            self.config.rate_burst,
            Arc::clone(&self.clock),
        );
        AsyncGuardAdapter {
            inner: self.inner,
            config: self.config,
            cache,
            circuit,
            bucket,
        }
    }
}

/// Adapter that composes circuit breaker + token bucket + TTL cache + retry
/// on top of an [`ExternalGuard`].
///
/// Flow of a single `evaluate` call:
///
/// 1. Check the **circuit breaker**. If open, return
///    [`CircuitOpenVerdict`] without calling the inner guard.
/// 2. Check the **cache**. On hit, return the cached verdict without
///    calling the inner guard.
/// 3. Check the **token bucket**. If empty, return [`RateLimitedVerdict`].
///    Rate-limited calls do *not* increment the circuit breaker.
/// 4. Call the inner guard via [`retry_with_jitter`].
/// 5. Record success/failure on the breaker. On success, cache the verdict.
pub struct AsyncGuardAdapter<E: ExternalGuard + ?Sized> {
    inner: Arc<E>,
    config: AsyncGuardAdapterConfig,
    cache: TtlCache<String, Verdict>,
    circuit: CircuitBreaker,
    bucket: TokenBucket,
}

impl<E: ExternalGuard + ?Sized> AsyncGuardAdapter<E> {
    /// Start a builder with defaults.
    pub fn builder(inner: Arc<E>) -> AsyncGuardAdapterBuilder<E> {
        AsyncGuardAdapterBuilder::new(inner)
    }

    /// Name of the wrapped guard.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Effective configuration.
    pub fn config(&self) -> &AsyncGuardAdapterConfig {
        &self.config
    }

    /// Inspect the circuit breaker state (primarily for tests and metrics).
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit.current_state()
    }

    /// Evaluate the request end-to-end.
    pub async fn evaluate(&self, ctx: &GuardCallContext) -> Verdict {
        // 1. Circuit breaker check.
        if !self.circuit.allow_call() {
            return self.config.circuit_open_verdict.to_verdict();
        }

        // 2. Cache check. Done before rate limiting so that cached hits
        //    don't count against the external QPS budget.
        let cache_key = self.inner.cache_key(ctx);
        if let Some(key) = cache_key.as_ref() {
            if let Some(cached) = self.cache.get(key) {
                return cached;
            }
        }

        // 3. Rate limit.
        if !self.bucket.try_acquire() {
            return self.config.rate_limited_verdict.to_verdict();
        }

        // 4. Retry loop against the inner guard. A permanent error short-
        //    circuits by being returned as an Ok(Err(_)) so the retry
        //    loop doesn't keep calling a known-bad request.
        let inner = Arc::clone(&self.inner);
        let ctx_ref = ctx;
        let loop_outcome: Result<Result<Verdict, ExternalGuardError>, ExternalGuardError> =
            retry_with_jitter(&self.config.retry, move |_attempt| {
                let inner = Arc::clone(&inner);
                async move {
                    match inner.eval(ctx_ref).await {
                        Ok(v) => Ok(Ok(v)),
                        Err(err) if err.is_retryable() => Err(err),
                        Err(err) => Ok(Err(err)),
                    }
                }
            })
            .await;

        let call_result: Result<Verdict, ExternalGuardError> = match loop_outcome {
            Ok(inner) => inner,
            Err(err) => Err(err),
        };

        match call_result {
            Ok(verdict) => {
                self.circuit.record_success();
                if let Some(key) = cache_key {
                    self.cache.insert(key, verdict, self.config.cache_ttl);
                }
                verdict
            }
            Err(err) => {
                self.circuit.record_failure();
                tracing::warn!(
                    guard = self.inner.name(),
                    error = %err,
                    "external guard failed"
                );
                Verdict::Deny
            }
        }
    }
}
