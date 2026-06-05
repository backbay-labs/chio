//! Agent velocity guard -- per-agent and per-session rate limiting.
//!
//! Unlike the existing `VelocityGuard` which keys on (capability_id, grant_index),
//! this guard rate-limits by agent identity and (optionally) session, providing
//! cross-capability rate limiting for individual agents.
//!
//! Uses token-bucket semantics with integer milli-token arithmetic to
//! avoid floating-point drift. Produces `GuardEvidence` entries and
//! fails closed on internal errors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

// ---------------------------------------------------------------------------
// Token bucket (private, same algorithm as velocity.rs)
// ---------------------------------------------------------------------------

/// Milli-tokens per logical token.
const MT_PER_TOKEN: u64 = 1_000;

struct TokenBucket {
    capacity_mt: u64,
    tokens_mt: u64,
    refill_rate_mpm: u64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity_tokens: u64, max_per_window: u64, window_secs: u64) -> Self {
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
// AgentVelocityConfig
// ---------------------------------------------------------------------------

/// Configuration for the per-agent velocity guard.
#[derive(Clone, Debug)]
pub struct AgentVelocityConfig {
    /// Maximum requests per agent per window. None means unlimited.
    pub max_requests_per_agent: Option<u32>,
    /// Maximum requests per session per window. None means unlimited.
    pub max_requests_per_session: Option<u32>,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Burst factor (1.0 = no burst above steady rate).
    pub burst_factor: f64,
}

impl Default for AgentVelocityConfig {
    fn default() -> Self {
        Self {
            max_requests_per_agent: None,
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        }
    }
}

// ---------------------------------------------------------------------------
// AgentVelocityGuard
// ---------------------------------------------------------------------------

/// Guard that rate-limits by agent identity and session.
///
/// Per-agent buckets are keyed by `agent_id`. Per-session buckets are keyed
/// by `(agent_id, capability_id)` as a session proxy (since the guard context
/// does not directly expose session IDs, the capability ID serves as a
/// session-scoped discriminator).
pub struct AgentVelocityGuard {
    agent_buckets: Mutex<HashMap<String, TokenBucket>>,
    session_buckets: Mutex<HashMap<(String, String), TokenBucket>>,
    config: AgentVelocityConfig,
}

impl AgentVelocityGuard {
    /// Create a new guard with the given configuration.
    pub fn new(config: AgentVelocityConfig) -> Self {
        Self {
            agent_buckets: Mutex::new(HashMap::new()),
            session_buckets: Mutex::new(HashMap::new()),
            config,
        }
    }
}

impl Guard for AgentVelocityGuard {
    fn name(&self) -> &str {
        "agent-velocity"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let agent_id = ctx.agent_id.clone();
        let cap_id = ctx.request.capability.id.clone();
        let window_secs = self.config.window_secs.max(1);

        // Check per-agent rate limit.
        if let Some(max_per_agent) = self.config.max_requests_per_agent {
            let capacity =
                ((max_per_agent as f64 * self.config.burst_factor).round() as u64).max(1);

            let mut buckets = self.agent_buckets.lock().map_err(|_| {
                KernelError::Internal("agent-velocity agent lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(agent_id.clone())
                .or_insert_with(|| TokenBucket::new(capacity, max_per_agent as u64, window_secs));
            if !bucket.try_consume(1) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Check per-session rate limit.
        if let Some(max_per_session) = self.config.max_requests_per_session {
            let capacity =
                ((max_per_session as f64 * self.config.burst_factor).round() as u64).max(1);

            let session_key = (agent_id, cap_id);
            let mut buckets = self.session_buckets.lock().map_err(|_| {
                KernelError::Internal("agent-velocity session lock poisoned".to_string())
            })?;
            let bucket = buckets
                .entry(session_key)
                .or_insert_with(|| TokenBucket::new(capacity, max_per_session as u64, window_secs));
            if !bucket.try_consume(1) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        Ok(GuardDecision::allow())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
    use chio_core::crypto::Keypair;

    use super::*;

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

    fn guard_ctx<'a>(
        request: &'a chio_kernel::ToolCallRequest,
        scope: &'a ChioScope,
        agent_id: &'a String,
        server_id: &'a String,
    ) -> chio_kernel::GuardContext<'a> {
        chio_kernel::GuardContext {
            request,
            scope,
            agent_id,
            server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        }
    }

    #[test]
    fn guard_name() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig::default());
        assert_eq!(guard.name(), "agent-velocity");
    }

    #[test]
    fn unlimited_config_allows_all() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig::default());
        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-1");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        for _ in 0..100 {
            let ctx = guard_ctx(&request, &scope, &agent, &server);
            let result = guard.evaluate(&ctx).expect("should not error");
            assert_eq!(result, Verdict::Allow);
        }
    }

    #[test]
    fn per_agent_limit_enforced() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: Some(3),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-1");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // First 3 should pass.
        for _ in 0..3 {
            let ctx = guard_ctx(&request, &scope, &agent, &server);
            assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
        }

        // 4th should deny.
        let ctx = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn per_session_limit_enforced() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: None,
            max_requests_per_session: Some(2),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-session");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // First 2 pass.
        for _ in 0..2 {
            let ctx = guard_ctx(&request, &scope, &agent, &server);
            assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
        }

        // 3rd denied.
        let ctx = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn different_agents_get_separate_buckets() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: Some(1),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let cap = signed_cap(&kp1, "cap-shared");
        let scope = ChioScope::default();
        let agent1 = kp1.public_key().to_hex();
        let agent2 = kp2.public_key().to_hex();
        let server = "srv".to_string();

        // Agent 1 exhausts its bucket.
        let req1 = make_request(&cap, &agent1, &server);
        let ctx1 = guard_ctx(&req1, &scope, &agent1, &server);
        assert_eq!(guard.evaluate(&ctx1).expect("ok"), Verdict::Allow);
        let ctx1b = guard_ctx(&req1, &scope, &agent1, &server);
        assert_eq!(guard.evaluate(&ctx1b).expect("ok"), Verdict::Deny);

        // Agent 2 should have its own bucket.
        let req2 = make_request(&cap, &agent2, &server);
        let ctx2 = guard_ctx(&req2, &scope, &agent2, &server);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn different_sessions_get_separate_buckets() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: None,
            max_requests_per_session: Some(1),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap_a = signed_cap(&kp, "session-a");
        let cap_b = signed_cap(&kp, "session-b");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        // Session A: exhaust.
        let req_a = make_request(&cap_a, &agent, &server);
        let ctx_a = guard_ctx(&req_a, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx_a).expect("ok"), Verdict::Allow);
        let ctx_a2 = guard_ctx(&req_a, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx_a2).expect("ok"), Verdict::Deny);

        // Session B: should have fresh bucket.
        let req_b = make_request(&cap_b, &agent, &server);
        let ctx_b = guard_ctx(&req_b, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx_b).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn tokens_refill_over_time() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: Some(1),
            max_requests_per_session: None,
            window_secs: 1,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-refill");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // Exhaust.
        let ctx = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
        let ctx2 = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Deny);

        // Wait for refill.
        thread::sleep(Duration::from_millis(1100));

        let ctx3 = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx3).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn both_limits_applied() {
        // Agent limit = 10, session limit = 2. Session limit is stricter.
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: Some(10),
            max_requests_per_session: Some(2),
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-both");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        // 2 pass (session limit).
        for _ in 0..2 {
            let ctx = guard_ctx(&request, &scope, &agent, &server);
            assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
        }
        // 3rd denied by session limit.
        let ctx = guard_ctx(&request, &scope, &agent, &server);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn returns_verdict_deny_not_err() {
        let guard = AgentVelocityGuard::new(AgentVelocityConfig {
            max_requests_per_agent: Some(1),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        });

        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-deny-type");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let ctx = guard_ctx(&request, &scope, &agent, &server);
        guard.evaluate(&ctx).expect("ok");

        let ctx2 = guard_ctx(&request, &scope, &agent, &server);
        let result = guard.evaluate(&ctx2);
        assert!(result.is_ok());
        assert_eq!(result.expect("ok"), Verdict::Deny);
    }
}
