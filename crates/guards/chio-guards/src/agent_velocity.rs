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

    /// Refill, then report whether `amount_tokens` are available WITHOUT
    /// consuming them. Split from [`Self::consume`] so the guard can peek BOTH the
    /// agent and session buckets before consuming from EITHER (reserve-both-then-
    /// consume), avoiding partial consumption when one limit denies.
    fn can_consume(&mut self, amount_tokens: u64) -> bool {
        self.refill();
        let cost_mt = amount_tokens.saturating_mul(MT_PER_TOKEN);
        self.tokens_mt >= cost_mt
    }

    /// Deduct `amount_tokens`, saturating at zero. Only call after
    /// [`Self::can_consume`] returned true for the same amount under the same lock.
    fn consume(&mut self, amount_tokens: u64) {
        let cost_mt = amount_tokens.saturating_mul(MT_PER_TOKEN);
        self.tokens_mt = self.tokens_mt.saturating_sub(cost_mt);
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

    /// Report whether the bucket has refilled back to its full capacity,
    /// projecting the pending refill from elapsed time without mutating state
    /// (mirrors the arithmetic in [`Self::refill`]). A bucket at capacity carries
    /// no live rate-limit history: it is indistinguishable from a freshly created
    /// bucket, so it is the only state in which dropping and later recreating the
    /// bucket cannot hand its subject an unearned allowance. A bucket that spent
    /// part of its burst allowance and then sat idle is only partially refilled --
    /// recovering a burst of `capacity` tokens takes `capacity / refill_rate` of
    /// elapsed time, which exceeds one window whenever the burst ceiling sits above
    /// the steady per-window rate -- so it still carries live state.
    fn is_fully_refilled(&self) -> bool {
        let elapsed_ms = self.last_refill.elapsed().as_millis() as u64;
        let projected = self
            .tokens_mt
            .saturating_add(elapsed_ms.saturating_mul(self.refill_rate_mpm));
        projected >= self.capacity_mt
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
///
/// Both bucket maps live behind ONE mutex and the COMBINED distinct-key count is
/// bounded by `bucket_cap`, so a flood of distinct agent/capability ids saturates
/// rather than growing memory without bound. When the table is full of buckets
/// still carrying live rate-limit state a new key is DENIED fail-closed rather
/// than evicting one (evicting a bucket that still holds live state would reset
/// its per-window limit, the same reset-by-eviction bypass class closed in
/// [`crate::velocity::VelocityGuard`]). Buckets that have refilled back to full
/// capacity are pruned first to reclaim slots.
pub struct AgentVelocityGuard {
    state: Mutex<AgentVelocityState>,
    config: AgentVelocityConfig,
    bucket_cap: usize,
}

/// Combined bucket state guarded by a single mutex (see [`AgentVelocityGuard`]).
struct AgentVelocityState {
    agent_buckets: HashMap<String, TokenBucket>,
    session_buckets: HashMap<(String, String), TokenBucket>,
}

impl AgentVelocityGuard {
    /// Create a new guard with the given configuration and the bounded-memory
    /// default bucket cap sourced from
    /// [`chio_kernel::MemoryBudgetConfig`]'s `velocity_bucket_cap`, so the cap is
    /// single-sourced with the process memory budget. Deployments that thread a
    /// configured budget use [`Self::from_memory_budget`].
    pub fn new(config: AgentVelocityConfig) -> Self {
        Self::with_bucket_cap(
            config,
            chio_kernel::MemoryBudgetConfig::defaults().velocity_bucket_cap,
        )
    }

    /// Create an `AgentVelocityGuard` whose combined-bucket cap comes from a
    /// CONFIGURED process memory budget. Threading the operator's
    /// [`chio_kernel::MemoryBudgetConfig`] (rather than a fresh `defaults()` read
    /// inside [`Self::new`]) means lowering `velocity_bucket_cap` actually tightens
    /// this long-lived collection on the policy-compiled and origin-budget paths
    /// instead of being silently ignored.
    pub fn from_memory_budget(
        config: AgentVelocityConfig,
        budget: &chio_kernel::MemoryBudgetConfig,
    ) -> Self {
        Self::with_bucket_cap(config, budget.velocity_bucket_cap)
    }

    /// Create an `AgentVelocityGuard` with an explicit TOTAL bucket cap across
    /// BOTH the agent and session maps. Because both maps share one mutex, the
    /// combined-cap check and the insert are atomic: no evaluate() reads a stale
    /// sibling-map size, so the combined bucket count is bounded by `bucket_cap`
    /// even under concurrent evaluate() calls for distinct ids.
    pub fn with_bucket_cap(config: AgentVelocityConfig, bucket_cap: usize) -> Self {
        Self {
            state: Mutex::new(AgentVelocityState {
                agent_buckets: HashMap::new(),
                session_buckets: HashMap::new(),
            }),
            config,
            bucket_cap: bucket_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn combined_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.agent_buckets.len() + g.session_buckets.len(),
            Err(poisoned) => {
                let g = poisoned.into_inner();
                g.agent_buckets.len() + g.session_buckets.len()
            }
        }
    }
}

impl AgentVelocityState {
    /// Combined bucket count across both maps.
    fn combined_len(&self) -> usize {
        self.agent_buckets
            .len()
            .saturating_add(self.session_buckets.len())
    }

    /// Drop buckets that have refilled back to full capacity from BOTH maps to
    /// reclaim slots. A bucket at capacity carries no live rate-limit state, so it
    /// is semantically identical to a fresh bucket: dropping it can never reset an
    /// in-flight limit, and recreating its key later cannot hand the subject an
    /// unearned burst. A bucket that is only partially refilled (it spent part of
    /// its burst allowance and has not yet recovered to capacity) is retained, so a
    /// drained burst cannot be reset by reaping and recreating the key. Bounded:
    /// touches at most the live buckets (<= `bucket_cap` once saturated).
    fn prune_refilled(&mut self) {
        self.agent_buckets
            .retain(|_, bucket| !bucket.is_fully_refilled());
        self.session_buckets
            .retain(|_, bucket| !bucket.is_fully_refilled());
    }

    /// Reserve `new_slots` free slots in the COMBINED table (across both maps)
    /// without exceeding `bucket_cap`. Returns `true` when the caller may insert
    /// that many genuinely-new keys, `false` when the guard must DENY fail-closed.
    /// A request with both limits enabled needs TWO new slots for a brand-new
    /// (agent, session) pair, so they are reserved TOGETHER; a request that cannot
    /// fit both is denied before inserting either. Buckets that have refilled back
    /// to capacity are pruned first; if only buckets still carrying live rate-limit
    /// state remain the request is DENIED rather than evicting one and resetting
    /// its per-window limit.
    fn reserve_slots(&mut self, new_slots: usize, bucket_cap: usize) -> bool {
        if new_slots == 0 {
            return true;
        }
        if self.combined_len().saturating_add(new_slots) > bucket_cap {
            self.prune_refilled();
            if self.combined_len().saturating_add(new_slots) > bucket_cap {
                return false;
            }
        }
        true
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

        let agent_limit = self.config.max_requests_per_agent;
        let session_limit = self.config.max_requests_per_session;
        let session_key = (agent_id.clone(), cap_id);

        // Both maps share ONE lock, held for the whole evaluate, so the
        // combined-cap check and the insert are atomic across both maps.
        let mut state = self.state.lock().map_err(|_| {
            KernelError::Internal("agent-velocity guard state lock poisoned".to_string())
        })?;

        // Phase 1 - RESERVE. Secure a slot for EVERY genuinely-new bucket this
        // request needs across BOTH maps before consuming from EITHER, so a request
        // denied for lack of capacity never inserts an unpaired bucket or burns a
        // token for a call that never ran.
        let agent_new = agent_limit.is_some() && !state.agent_buckets.contains_key(&agent_id);
        let session_new =
            session_limit.is_some() && !state.session_buckets.contains_key(&session_key);
        let new_slots = usize::from(agent_new) + usize::from(session_new);
        if !state.reserve_slots(new_slots, self.bucket_cap) {
            return Ok(GuardDecision::deny(Vec::new()));
        }

        // Phase 2 - obtain both buckets (creating the reserved new ones).
        let state = &mut *state;
        let mut agent_bucket: Option<&mut TokenBucket> = match agent_limit {
            Some(max_per_agent) => {
                let capacity =
                    ((max_per_agent as f64 * self.config.burst_factor).round() as u64).max(1);
                Some(state.agent_buckets.entry(agent_id).or_insert_with(|| {
                    TokenBucket::new(capacity, max_per_agent as u64, window_secs)
                }))
            }
            None => None,
        };
        let mut session_bucket: Option<&mut TokenBucket> = match session_limit {
            Some(max_per_session) => {
                let capacity =
                    ((max_per_session as f64 * self.config.burst_factor).round() as u64).max(1);
                Some(state.session_buckets.entry(session_key).or_insert_with(|| {
                    TokenBucket::new(capacity, max_per_session as u64, window_secs)
                }))
            }
            None => None,
        };

        // Phase 3 - peek BOTH before consuming from EITHER, then commit both.
        let agent_ok = agent_bucket
            .as_mut()
            .map(|b| b.can_consume(1))
            .unwrap_or(true);
        let session_ok = session_bucket
            .as_mut()
            .map(|b| b.can_consume(1))
            .unwrap_or(true);
        if !agent_ok || !session_ok {
            return Ok(GuardDecision::deny(Vec::new()));
        }
        if let Some(bucket) = agent_bucket.as_mut() {
            bucket.consume(1);
        }
        if let Some(bucket) = session_bucket.as_mut() {
            bucket.consume(1);
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

    use chio_core::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
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

    #[test]
    fn from_memory_budget_bounds_combined_bucket_table() {
        // The CONFIGURED process memory budget must bound the COMBINED agent+session
        // bucket table. A budget that lowers `velocity_bucket_cap` to 4 must cap the
        // table at 4 even under a flood of distinct agent + capability ids;
        // otherwise the maps grow one entry per distinct id without bound.
        let budget = chio_kernel::MemoryBudgetConfig {
            velocity_bucket_cap: 4,
            ..chio_kernel::MemoryBudgetConfig::defaults()
        };
        let guard = AgentVelocityGuard::from_memory_budget(
            AgentVelocityConfig {
                max_requests_per_agent: Some(1000),
                max_requests_per_session: Some(1000),
                window_secs: 60,
                burst_factor: 1.0,
            },
            &budget,
        );
        let scope = ChioScope::default();
        let server = "srv".to_string();
        // Distinct agent id AND distinct capability id per iteration, so each
        // mints both an agent bucket and a session bucket.
        for i in 0..500u64 {
            let kp = Keypair::generate();
            let agent = format!("{}-{i}", kp.public_key().to_hex());
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server);
            let _ = guard.evaluate(&ctx);
        }
        assert!(
            guard.combined_bucket_count() <= 4,
            "configured velocity_bucket_cap did not bound the agent-velocity table: {} buckets",
            guard.combined_bucket_count()
        );
    }

    #[test]
    fn burst_drained_agent_bucket_is_not_reset_after_one_idle_window() {
        // A drained agent burst refills only at the steady per-window rate, so with
        // a burst ceiling above that rate it needs several idle windows to recover
        // to capacity, not one. Reaping it after a single idle window and recreating
        // the agent key would hand the agent a fresh full burst, bypassing the
        // per-agent limit. The partially refilled bucket must survive a prune
        // triggered by a competing agent key, which is denied instead.
        let config = AgentVelocityConfig {
            max_requests_per_agent: Some(2),
            max_requests_per_session: None,
            window_secs: 1,
            burst_factor: 2.0, // capacity 4, steady refill 2 per window
        };
        let guard = AgentVelocityGuard::with_bucket_cap(config, 1);
        let kp = Keypair::generate();
        let scope = ChioScope::default();
        let server = "srv".to_string();
        let agent_x = format!("{}-x", kp.public_key().to_hex());
        let cap = signed_cap(&kp, "cap-1");
        let req_x = make_request(&cap, &agent_x, &server);

        // Drain the full burst of 4 tokens.
        for _ in 0..4 {
            assert_eq!(
                guard
                    .evaluate(&guard_ctx(&req_x, &scope, &agent_x, &server))
                    .expect("burst request"),
                Verdict::Allow,
            );
        }
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_x, &scope, &agent_x, &server))
                .expect("drained request"),
            Verdict::Deny,
            "the burst is drained",
        );
        assert_eq!(guard.combined_bucket_count(), 1);

        // Idle for exactly one window: the bucket refills to 2 of 4 tokens, still
        // short of its burst ceiling.
        thread::sleep(Duration::from_millis(1100));

        // A competing new agent trips the cap and attempts a prune. The partially
        // refilled bucket carries live state, so it is retained and the new agent is
        // denied rather than reaping the burst victim.
        let agent_y = format!("{}-y", kp.public_key().to_hex());
        let req_y = make_request(&cap, &agent_y, &server);
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_y, &scope, &agent_y, &server))
                .expect("competing agent"),
            Verdict::Deny,
            "a partially refilled burst bucket must not be reaped to admit a new agent",
        );
        assert_eq!(
            guard.combined_bucket_count(),
            1,
            "the burst victim was reaped to admit the competing agent",
        );

        // The victim regained only the steady per-window amount (2 tokens), not a
        // fresh full burst (4): exactly two more requests succeed before it denies.
        for _ in 0..2 {
            assert_eq!(
                guard
                    .evaluate(&guard_ctx(&req_x, &scope, &agent_x, &server))
                    .expect("refilled request"),
                Verdict::Allow,
            );
        }
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_x, &scope, &agent_x, &server))
                .expect("post-refill request"),
            Verdict::Deny,
            "the agent burst was reset to full capacity instead of the steady refill",
        );
    }
}
