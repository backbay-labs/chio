//! Velocity guard -- synchronous token bucket rate limiting per grant.
//!
//! Prevents runaway tool usage by throttling agent invocations per
//! (capability_id, grant_index) pair using a token bucket algorithm.
//! The guard uses `std::sync::Mutex` (synchronous, no async) and fits
//! into the existing `Guard` pipeline.
//!
//! All arithmetic uses integer milli-tokens (u64) to eliminate accumulated
//! floating-point drift. The refill rate is expressed as milli-tokens per
//! millisecond.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

// ---------------------------------------------------------------------------
// TokenBucket (private)
// ---------------------------------------------------------------------------

/// Token bucket using integer milli-token arithmetic to avoid floating-point
/// drift. One logical token == 1_000 milli-tokens.
///
/// Fields:
///   capacity_mt     -- maximum bucket level in milli-tokens
///   tokens_mt       -- current level in milli-tokens
///   refill_rate_mpm -- refill rate in milli-tokens per millisecond
///   last_refill     -- wall-clock instant of last refill
struct TokenBucket {
    capacity_mt: u64,
    tokens_mt: u64,
    /// Milli-tokens added per millisecond of elapsed time.
    refill_rate_mpm: u64,
    last_refill: Instant,
}

/// Milli-tokens per logical token.
const MT_PER_TOKEN: u64 = 1_000;

impl TokenBucket {
    /// Create a new bucket.
    ///
    /// `capacity_tokens`   -- maximum logical tokens (burst ceiling)
    /// `window_secs`       -- window duration used to derive the refill rate
    /// `max_per_window`    -- logical tokens added per window
    fn new(capacity_tokens: u64, max_per_window: u64, window_secs: u64) -> Self {
        // refill_rate_mpm = (max_per_window * MT_PER_TOKEN) / (window_secs * 1000 ms/s)
        // We keep a minimum rate of 1 milli-token/ms to avoid divide-by-zero and
        // ensure very slow rates still make progress.
        let window_ms = window_secs.saturating_mul(1_000).max(1);
        let refill_rate_mpm = (max_per_window.saturating_mul(MT_PER_TOKEN))
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

    /// Attempt to consume `amount_tokens` logical tokens. Returns true on
    /// success (tokens were available), false if the bucket is too empty.
    fn try_consume(&mut self, amount_tokens: u64) -> bool {
        self.refill();
        let cost_mt = amount_tokens.saturating_mul(MT_PER_TOKEN);
        if self.tokens_mt >= cost_mt {
            self.tokens_mt -= cost_mt;
            true
        } else {
            false
        }
    }

    /// Refill the bucket based on elapsed time since the last refill.
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

// ---------------------------------------------------------------------------
// VelocityConfig
// ---------------------------------------------------------------------------

/// Configuration for `VelocityGuard`.
#[derive(Clone, Debug)]
pub struct VelocityConfig {
    /// Maximum invocations per window. None means unlimited.
    pub max_invocations_per_window: Option<u32>,
    /// Maximum spend (monetary units) per window. None means unlimited.
    pub max_spend_per_window: Option<u64>,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Burst factor (1.0 = no burst above steady rate).
    pub burst_factor: f64,
}

impl Default for VelocityConfig {
    fn default() -> Self {
        Self {
            max_invocations_per_window: None,
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// VelocityGuard
// ---------------------------------------------------------------------------

/// Guard that rate-limits agent invocations using synchronous token buckets.
///
/// Buckets are keyed by `(capability_id, grant_index)` so different grants
/// within the same capability can have independent rate limits.
pub struct VelocityGuard {
    invocation_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    spend_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    config: VelocityConfig,
}

impl VelocityGuard {
    /// Create a new `VelocityGuard` with the given configuration.
    pub fn new(config: VelocityConfig) -> Self {
        Self {
            invocation_buckets: Mutex::new(HashMap::new()),
            spend_buckets: Mutex::new(HashMap::new()),
            config,
        }
    }
}

impl Guard for VelocityGuard {
    fn name(&self) -> &str {
        "velocity"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let grant_index = if self.config.max_invocations_per_window.is_some()
            || self.config.max_spend_per_window.is_some()
        {
            ctx.matched_grant_index.ok_or_else(|| {
                KernelError::Internal(
                    "velocity guard rate limiting requires matched_grant_index".to_string(),
                )
            })?
        } else {
            0
        };
        let key = (ctx.request.capability.id.clone(), grant_index);

        let window_secs = self.config.window_secs.max(1);

        // Check invocation rate limit.
        if let Some(max_inv) = self.config.max_invocations_per_window {
            // Burst capacity: max_inv * burst_factor, rounded to nearest integer.
            let capacity = ((max_inv as f64 * self.config.burst_factor).round() as u64).max(1);

            let mut buckets = self.invocation_buckets.lock().map_err(|_| {
                KernelError::Internal("velocity guard invocation lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(key.clone())
                .or_insert_with(|| TokenBucket::new(capacity, max_inv as u64, window_secs));
            if !bucket.try_consume(1) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Check spend rate limit.
        if let Some(max_spend) = self.config.max_spend_per_window {
            let capacity = ((max_spend as f64 * self.config.burst_factor).round() as u64).max(1);
            let spend_units = planned_spend_units(ctx)?;

            let mut buckets = self.spend_buckets.lock().map_err(|_| {
                KernelError::Internal("velocity guard spend lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(key)
                .or_insert_with(|| TokenBucket::new(capacity, max_spend, window_secs));
            if !bucket.try_consume(spend_units) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        Ok(GuardDecision::allow())
    }
}

fn planned_spend_units(ctx: &GuardContext) -> Result<u64, KernelError> {
    let grant_index = ctx.matched_grant_index.ok_or_else(|| {
        KernelError::Internal(
            "velocity guard spend limiting requires matched_grant_index".to_string(),
        )
    })?;
    let grant = ctx.scope.grants.get(grant_index).ok_or_else(|| {
        KernelError::Internal(format!(
            "velocity guard could not resolve grant index {grant_index}"
        ))
    })?;
    grant
        .max_cost_per_invocation
        .as_ref()
        .map(|amount| amount.units)
        .ok_or_else(|| {
            KernelError::Internal(
                "velocity guard spend limiting requires max_cost_per_invocation on the matched grant"
                    .to_string(),
            )
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use chio_core::capability::{
        scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;

    use super::*;

    // Helper: build a minimal ToolCallRequest.
    fn make_request(
        cap: &CapabilityToken,
        agent_id: &str,
        server_id: &str,
    ) -> chio_kernel::ToolCallRequest {
        chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "read_file".to_string(),
            server_id: server_id.to_string(),
            agent_id: agent_id.to_string(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    fn signed_cap(kp: &Keypair, cap_id: &str) -> CapabilityToken {
        let scope = ChioScope::default();
        let body = CapabilityTokenBody {
            id: cap_id.to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope,
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, kp).expect("sign cap")
    }

    fn spend_scope(max_cost_per_invocation: u64) -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: max_cost_per_invocation,
                    currency: "USD".to_string(),
                }),
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    fn guard_ctx<'a>(
        request: &'a chio_kernel::ToolCallRequest,
        scope: &'a ChioScope,
        agent_id: &'a String,
        server_id: &'a String,
        grant_index: Option<usize>,
    ) -> chio_kernel::GuardContext<'a> {
        chio_kernel::GuardContext {
            request,
            scope,
            agent_id,
            server_id,
            session_filesystem_roots: None,
            matched_grant_index: grant_index,
        }
    }

    #[test]
    fn guard_name_is_velocity() {
        let guard = VelocityGuard::new(VelocityConfig::default());
        assert_eq!(guard.name(), "velocity");
    }

    #[test]
    fn velocity_config_defaults_unlimited() {
        let config = VelocityConfig::default();
        assert!(config.max_invocations_per_window.is_none());
        assert!(config.max_spend_per_window.is_none());
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_factor, 1.0);
    }

    #[test]
    fn unlimited_config_always_allows() {
        let guard = VelocityGuard::new(VelocityConfig::default());
        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-unlimited");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let request = make_request(&cap, &agent, &server);
        for _ in 0..100 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(result, Verdict::Allow);
        }
    }

    #[test]
    fn allows_requests_up_to_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(5),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-limited");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for i in 0..5 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let result = guard.evaluate(&ctx).expect("evaluate should not error");
            assert_eq!(
                result,
                Verdict::Allow,
                "request {i} should be allowed (limit=5)"
            );
        }
    }

    #[test]
    fn invocation_velocity_requires_matched_grant_index() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(5),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-missing-grant-index");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let error = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, None))
            .expect_err("rate limiting without a matched grant index must fail closed");
        assert!(
            error.to_string().contains("matched_grant_index"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn denies_request_exceeding_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(5),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-exceed");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust the 5 allowed tokens.
        for _ in 0..5 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            guard.evaluate(&ctx).expect("should not error");
        }

        // 6th request must be denied.
        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Deny, "6th request should be denied");
    }

    #[test]
    fn tokens_refill_after_window() {
        // 1-second window with limit=2.  After 1.1 seconds the bucket should
        // have refilled enough to allow at least one more request.
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(2),
            max_spend_per_window: None,
            window_secs: 1,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-refill");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust the bucket.
        for _ in 0..2 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            guard.evaluate(&ctx).expect("should not error");
        }

        // Verify it denies now.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(result, Verdict::Deny, "should deny before refill");
        }

        // Wait for window to pass.
        thread::sleep(Duration::from_millis(1100));

        // Must allow again after refill.
        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Allow, "should allow after refill");
    }

    #[test]
    fn separate_buckets_for_different_grant_indices() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-multi-grant");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust grant_index 0.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "grant 0 first request");
        }
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Deny, "grant 0 second request denied");
        }

        // grant_index 1 should have a fresh bucket.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(1));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "grant 1 first request should allow");
        }
    }

    #[test]
    fn separate_buckets_for_different_capability_ids() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap_a = signed_cap(&kp, "cap-a");
        let cap_b = signed_cap(&kp, "cap-b");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let request_a = chio_kernel::ToolCallRequest {
            request_id: "req-a".to_string(),
            capability: cap_a.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let request_b = chio_kernel::ToolCallRequest {
            request_id: "req-b".to_string(),
            capability: cap_b.clone(),
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        // Exhaust cap-a.
        {
            let ctx = guard_ctx(&request_a, &scope, &agent, &server, Some(0));
            guard.evaluate(&ctx).expect("should not error");
        }
        {
            let ctx = guard_ctx(&request_a, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Deny, "cap-a second request denied");
        }

        // cap-b should be unaffected.
        {
            let ctx = guard_ctx(&request_b, &scope, &agent, &server, Some(0));
            let r = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(r, Verdict::Allow, "cap-b first request should allow");
        }
    }

    #[test]
    fn returns_verdict_deny_not_err_when_rate_limited() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: Some(1),
            max_spend_per_window: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-deny-type");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust.
        {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            guard.evaluate(&ctx).expect("should not error");
        }

        // The result must be Ok(GuardDecision::deny(Vec::new())), not Err.
        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        let result = guard.evaluate(&ctx);
        assert!(result.is_ok(), "rate limit must return Ok, not Err");
        assert_eq!(result.expect("ok"), Verdict::Deny, "must be Verdict::Deny");
    }

    #[test]
    fn spend_velocity_allows_up_to_limit() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(300),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend");
        let scope = spend_scope(100);
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for i in 0..3 {
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(
                result,
                Verdict::Allow,
                "spend request {i} should be allowed"
            );
        }

        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Deny, "4th spend request should be denied");
    }

    #[test]
    fn spend_velocity_consumes_planned_cost_units() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(250),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend-costed");
        let scope = spend_scope(125);
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let first = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(first.expect("first spend request"), Verdict::Allow);

        let second = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(second.expect("second spend request"), Verdict::Allow);

        let third = guard.evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)));
        assert_eq!(third.expect("third spend request"), Verdict::Deny);
    }

    #[test]
    fn spend_velocity_requires_cost_metadata_on_matched_grant() {
        let guard = VelocityGuard::new(VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(10),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-spend-missing-cost");
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let error = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)))
            .expect_err("missing cost metadata should fail closed");
        assert!(
            error.to_string().contains("max_cost_per_invocation"),
            "unexpected error: {error}"
        );
    }
}
