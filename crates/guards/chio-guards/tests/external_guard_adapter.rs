//! Integration tests for `AsyncGuardAdapter`.
//!
//! These tests exercise the composed behavior of circuit breaker + TTL
//! cache + rate limiter + retry-with-jitter on top of a mock
//! `ExternalGuard`. All timers run under `tokio::time::pause()` so the
//! tests are deterministic and do not sleep on the wall clock.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chio_guards::external::{
    AsyncGuardAdapter, CircuitBreakerConfig, CircuitOpenVerdict, ExternalGuard, ExternalGuardError,
    GuardCallContext, RateLimitedVerdict, RetryConfig,
};
use chio_kernel::Verdict;

/// Configurable mock `ExternalGuard` used by every test in this file.
struct MockGuard {
    name: &'static str,
    calls: AtomicU32,
    /// Number of initial calls that fail with a retryable error before the
    /// guard starts returning `verdict`.
    fail_until: u32,
    /// Verdict returned on success.
    verdict: Verdict,
    /// When `true`, failures are permanent (not retryable) and bypass the
    /// retry loop immediately.
    permanent_failure: bool,
    /// When `Some`, overrides the cache key. `None` means cache-by-tool-name.
    cache_key_override: Option<String>,
}

impl MockGuard {
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ExternalGuard for MockGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        match &self.cache_key_override {
            Some(k) => Some(k.clone()),
            None => Some(ctx.tool_name.clone()),
        }
    }

    async fn eval(&self, _ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_until {
            if self.permanent_failure {
                return Err(ExternalGuardError::Permanent("mock permanent".into()));
            }
            return Err(ExternalGuardError::Transient(format!(
                "mock transient #{n}"
            )));
        }
        Ok(self.verdict)
    }
}

fn mock_ctx(tool: &str) -> GuardCallContext {
    GuardCallContext {
        tool_name: tool.to_string(),
        agent_id: "agent-x".to_string(),
        server_id: "srv".to_string(),
        arguments_json: "{}".to_string(),
    }
}

fn fast_retry() -> RetryConfig {
    RetryConfig {
        max_retries: 3,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(80),
        jitter_fraction: 0.0,
        strategy: chio_guards::external::BackoffStrategy::Exponential,
    }
}

fn circuit(failure_threshold: u32) -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold,
        failure_window: Duration::from_secs(60),
        success_threshold: 1,
        reset_timeout: Duration::from_secs(30),
    }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn happy_path_allows_and_calls_once() {
    let guard = Arc::new(MockGuard {
        name: "happy",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: None,
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(5))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(30))
        .cache_capacity(NonZeroUsize::new(16).expect("nz"))
        .build();

    assert_eq!(
        adapter.evaluate(&mock_ctx("read_file")).await,
        Verdict::Allow
    );
    assert_eq!(guard.calls(), 1);
}

// ---------------------------------------------------------------------------
// Circuit breaker opens after N failures
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn circuit_opens_after_n_failures_and_skips_external_call() {
    let guard = Arc::new(MockGuard {
        name: "flaky",
        calls: AtomicU32::new(0),
        fail_until: u32::MAX,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: Some("no-cache-hit".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(3))
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter_fraction: 0.0,
            strategy: chio_guards::external::BackoffStrategy::Constant,
        })
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(1))
        .cache_capacity(NonZeroUsize::new(4).expect("nz"))
        .circuit_open_verdict(CircuitOpenVerdict::Deny)
        .build();

    // Vary the cache key per call so failures don't hit the cache.
    for i in 0..3 {
        let mut ctx = mock_ctx(&format!("tool-{i}"));
        ctx.arguments_json = format!("{{\"i\":{i}}}");
        let verdict = adapter.evaluate(&ctx).await;
        assert_eq!(verdict, Verdict::Deny, "transient fail denies (iter {i})");
    }

    assert_eq!(guard.calls(), 3, "inner guard should have been hit 3 times");
    assert_eq!(
        adapter.circuit_state(),
        chio_guards::external::CircuitState::Open,
        "breaker should be open after threshold"
    );

    // Additional calls while the breaker is open must not hit the inner
    // guard and must return the configured open verdict.
    let calls_before = guard.calls();
    for i in 0..5 {
        let mut ctx = mock_ctx(&format!("skip-{i}"));
        ctx.arguments_json = format!("{{\"i\":{i}}}");
        let verdict = adapter.evaluate(&ctx).await;
        assert_eq!(verdict, Verdict::Deny);
    }
    assert_eq!(
        guard.calls(),
        calls_before,
        "inner guard must not be called while breaker is open"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn circuit_open_allow_returns_allow() {
    let guard = Arc::new(MockGuard {
        name: "flaky-allow",
        calls: AtomicU32::new(0),
        fail_until: u32::MAX,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: Some("no-cache-hit".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(2))
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            jitter_fraction: 0.0,
            strategy: chio_guards::external::BackoffStrategy::Constant,
        })
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(1))
        .circuit_open_verdict(CircuitOpenVerdict::Allow)
        .build();

    for i in 0..2 {
        let mut ctx = mock_ctx(&format!("burn-{i}"));
        ctx.arguments_json = format!("{{\"i\":{i}}}");
        let _ = adapter.evaluate(&ctx).await;
    }
    assert_eq!(
        adapter.circuit_state(),
        chio_guards::external::CircuitState::Open
    );
    let calls_before = guard.calls();
    let mut ctx = mock_ctx("after-open");
    ctx.arguments_json = "{\"k\":\"v\"}".to_string();
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Allow);
    assert_eq!(
        guard.calls(),
        calls_before,
        "fail-open must not reach the inner guard"
    );
}

// ---------------------------------------------------------------------------
// Cache hit skips the external call
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cache_hit_skips_external_call() {
    let guard = Arc::new(MockGuard {
        name: "cached",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: Some("same-key".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(5))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(30))
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("a")).await, Verdict::Allow);
    assert_eq!(adapter.evaluate(&mock_ctx("b")).await, Verdict::Allow);
    assert_eq!(adapter.evaluate(&mock_ctx("c")).await, Verdict::Allow);
    assert_eq!(guard.calls(), 1, "only first call should reach the guard");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cache_miss_on_distinct_keys() {
    let guard = Arc::new(MockGuard {
        name: "cached-per-tool",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: None,
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(5))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(30))
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("alpha")).await, Verdict::Allow);
    assert_eq!(adapter.evaluate(&mock_ctx("beta")).await, Verdict::Allow);
    assert_eq!(adapter.evaluate(&mock_ctx("alpha")).await, Verdict::Allow);
    assert_eq!(guard.calls(), 2, "two distinct keys -> two calls");
}

// ---------------------------------------------------------------------------
// Retry succeeds after N attempts
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retry_succeeds_after_n_attempts() {
    let guard = Arc::new(MockGuard {
        name: "retry",
        calls: AtomicU32::new(0),
        fail_until: 2,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: Some("retry-key".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(10))
        .retry(RetryConfig {
            max_retries: 4,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(40),
            jitter_fraction: 0.0,
            strategy: chio_guards::external::BackoffStrategy::Exponential,
        })
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(30))
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("retry")).await, Verdict::Allow);
    assert_eq!(guard.calls(), 3, "2 transient failures + 1 success");
    assert_eq!(
        adapter.circuit_state(),
        chio_guards::external::CircuitState::Closed,
        "a retried success should leave the breaker closed"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn permanent_failure_stops_retry_loop() {
    let guard = Arc::new(MockGuard {
        name: "permanent",
        calls: AtomicU32::new(0),
        fail_until: u32::MAX,
        verdict: Verdict::Allow,
        permanent_failure: true,
        cache_key_override: Some("permanent-key".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(10))
        .retry(RetryConfig {
            max_retries: 5,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(40),
            jitter_fraction: 0.0,
            strategy: chio_guards::external::BackoffStrategy::Exponential,
        })
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(30))
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("perm")).await, Verdict::Deny);
    assert_eq!(
        guard.calls(),
        1,
        "permanent failure must not trigger retries"
    );
}

// ---------------------------------------------------------------------------
// Rate limit rejection
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn rate_limit_rejects_fail_closed_by_default() {
    let guard = Arc::new(MockGuard {
        name: "rate",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: None,
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(10))
        .retry(fast_retry())
        // 0 refill, burst of 2 -> exactly 2 distinct calls pass, then deny.
        .rate_limit(0.0, 2)
        .cache_ttl(Duration::from_secs(30))
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("one")).await, Verdict::Allow);
    assert_eq!(adapter.evaluate(&mock_ctx("two")).await, Verdict::Allow);
    // Third distinct tool name bypasses the cache and exhausts the bucket.
    assert_eq!(
        adapter.evaluate(&mock_ctx("three")).await,
        Verdict::Deny,
        "rate-limited call must fail closed"
    );
    assert_eq!(guard.calls(), 2, "third call must not reach the guard");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn rate_limit_allow_honors_fail_open_verdict() {
    let guard = Arc::new(MockGuard {
        name: "rate-open",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: None,
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(10))
        .retry(fast_retry())
        .rate_limit(0.0, 1)
        .cache_ttl(Duration::from_secs(30))
        .rate_limited_verdict(RateLimitedVerdict::Allow)
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("one")).await, Verdict::Allow);
    // Second distinct tool exhausts the bucket -> must fall through to
    // the configured rate-limited verdict (Allow).
    assert_eq!(adapter.evaluate(&mock_ctx("two")).await, Verdict::Allow);
    assert_eq!(
        guard.calls(),
        1,
        "rate-limited second call must not hit the guard"
    );
}

// ---------------------------------------------------------------------------
// Cache check happens before rate limiting
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn cache_hit_bypasses_rate_limit() {
    let guard = Arc::new(MockGuard {
        name: "cache-before-rl",
        calls: AtomicU32::new(0),
        fail_until: 0,
        verdict: Verdict::Allow,
        permanent_failure: false,
        cache_key_override: Some("shared".to_string()),
    });

    let adapter = AsyncGuardAdapter::builder(Arc::clone(&guard))
        .circuit(circuit(10))
        .retry(fast_retry())
        .rate_limit(0.0, 1)
        .cache_ttl(Duration::from_secs(30))
        .rate_limited_verdict(RateLimitedVerdict::Deny)
        .build();

    assert_eq!(adapter.evaluate(&mock_ctx("k")).await, Verdict::Allow);
    // Bucket is now empty, but subsequent calls with the same cache key
    // must hit the cache and return Allow without touching the bucket.
    for _ in 0..5 {
        assert_eq!(adapter.evaluate(&mock_ctx("k")).await, Verdict::Allow);
    }
    assert_eq!(guard.calls(), 1);
}
