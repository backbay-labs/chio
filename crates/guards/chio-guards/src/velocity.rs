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

    /// Refill, then report whether `amount_tokens` logical tokens are available
    /// WITHOUT consuming them. Split from [`Self::consume`] so a guard evaluating
    /// two buckets under one lock can check BOTH can satisfy the request before
    /// consuming from EITHER (reserve-both-then-consume), avoiding partial
    /// consumption when one limit denies. Refilling here and again inside the
    /// paired [`Self::consume`] adds ~0 tokens (near-zero elapsed under the same
    /// lock), so the peek cannot inflate the balance.
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
    /// Both bucket maps live behind ONE mutex so the combined-cap check and the
    /// insert are atomic across both maps: no evaluate() ever samples a stale
    /// sibling-map size, so the combined `invocation + spend` bucket count stays
    /// bounded by `bucket_cap` even under concurrent evaluate() calls for
    /// distinct capability ids. A single lock also removes any cross-map lock
    /// ordering, so there is no deadlock.
    state: Mutex<VelocityState>,
    config: VelocityConfig,
    bucket_cap: usize,
}

/// Combined bucket state guarded by a single mutex (see [`VelocityGuard::state`]).
struct VelocityState {
    invocation_buckets: HashMap<(String, usize), TokenBucket>,
    spend_buckets: HashMap<(String, usize), TokenBucket>,
}

impl VelocityGuard {
    /// Create a new `VelocityGuard` with the given configuration and the
    /// bounded-memory default bucket cap, sourced from
    /// [`chio_kernel::MemoryBudgetConfig`]'s `velocity_bucket_cap` so the cap is
    /// single-sourced with the process memory budget rather than a duplicated
    /// literal. Deployments that need a tighter cap use
    /// [`Self::with_bucket_cap`].
    pub fn new(config: VelocityConfig) -> Self {
        Self::with_bucket_cap(
            config,
            chio_kernel::MemoryBudgetConfig::defaults().velocity_bucket_cap,
        )
    }

    /// Create a `VelocityGuard` whose total-bucket cap comes from a CONFIGURED
    /// process memory budget. Threading the operator's
    /// [`chio_kernel::MemoryBudgetConfig`] (rather than a fresh `defaults()` read
    /// inside [`Self::new`]) means lowering `velocity_bucket_cap` on the process
    /// memory budget actually tightens this long-lived collection instead of being
    /// silently ignored on the policy-compiled path.
    pub fn from_memory_budget(
        config: VelocityConfig,
        budget: &chio_kernel::MemoryBudgetConfig,
    ) -> Self {
        Self::with_bucket_cap(config, budget.velocity_bucket_cap)
    }

    /// Create a `VelocityGuard` with an explicit total-bucket cap so a
    /// self-minted-leaf flood saturates rather than growing. The cap is a TOTAL
    /// across BOTH the invocation and spend maps. Because both maps
    /// share one mutex, the combined-cap check and the insert are atomic: no
    /// evaluate() reads a stale sibling-map size, so the combined bucket count is
    /// bounded by `bucket_cap` even under concurrent evaluate() calls for distinct
    /// capability ids, rather than the un-folded `2 * bucket_cap` or an unbounded
    /// concurrent overshoot. When the table is full of in-window buckets a new key
    /// is DENIED fail-closed rather than evicting an active bucket, so the bound is
    /// tight for all `bucket_cap >= 1`.
    pub fn with_bucket_cap(config: VelocityConfig, bucket_cap: usize) -> Self {
        Self {
            state: Mutex::new(VelocityState {
                invocation_buckets: HashMap::new(),
                spend_buckets: HashMap::new(),
            }),
            config,
            bucket_cap: bucket_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn invocation_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.invocation_buckets.len(),
            Err(poisoned) => poisoned.into_inner().invocation_buckets.len(),
        }
    }

    #[cfg(test)]
    pub(crate) fn spend_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.spend_buckets.len(),
            Err(poisoned) => poisoned.into_inner().spend_buckets.len(),
        }
    }

    /// Combined bucket count across BOTH maps read under the single lock, so it is
    /// a consistent snapshot (never a torn read across two separate locks).
    #[cfg(test)]
    pub(crate) fn combined_bucket_count(&self) -> usize {
        match self.state.lock() {
            Ok(g) => g.invocation_buckets.len() + g.spend_buckets.len(),
            Err(poisoned) => {
                let g = poisoned.into_inner();
                g.invocation_buckets.len() + g.spend_buckets.len()
            }
        }
    }
}

impl VelocityState {
    /// Combined bucket count across both maps.
    fn combined_len(&self) -> usize {
        self.invocation_buckets
            .len()
            .saturating_add(self.spend_buckets.len())
    }

    /// Drop buckets that have refilled back to full capacity from BOTH maps to
    /// reclaim slots. A bucket at capacity carries no live rate-limit state, so it
    /// is semantically identical to a fresh bucket: dropping it can never reset an
    /// in-flight rate/spend limit, and recreating its key later cannot hand the
    /// subject an unearned burst. A bucket that is only partially refilled (it
    /// spent part of its burst allowance and has not yet recovered to capacity) is
    /// retained, so a drained burst cannot be reset by reaping and recreating the
    /// key. Bounded: touches at most the live buckets (<= `bucket_cap` once
    /// saturated).
    fn prune_refilled(&mut self) {
        self.invocation_buckets
            .retain(|_, bucket| !bucket.is_fully_refilled());
        self.spend_buckets
            .retain(|_, bucket| !bucket.is_fully_refilled());
    }

    /// Reserve `new_slots` free slots in the COMBINED table (across both maps)
    /// without exceeding `bucket_cap`. Returns `true` when the caller may insert
    /// that many genuinely-new keys, `false` when the guard must DENY fail-closed.
    /// Run under the single state lock, so `combined_len()` is always the true
    /// current total (never a stale sibling snapshot).
    ///
    /// A request with both invocation and spend limits enabled needs TWO new
    /// slots for a brand-new key (one per map), so it must reserve them TOGETHER:
    /// checking one slot at a time would let a request pass the invocation check
    /// on the last free slot and then fail the spend check, wedging an unpaired
    /// invocation bucket in the final slot and burning a token for a call that
    /// never ran. Reserving 0 slots (all keys already exist) always succeeds, so
    /// a repeat request for an already-tracked capability never evicts and
    /// recreates its own bucket with a full token balance.
    ///
    /// When the reservation would exceed the cap, buckets that have refilled back
    /// to full capacity are pruned from BOTH maps first; if only buckets still
    /// carrying live rate-limit state (not yet refilled to capacity) remain, the
    /// request is DENIED rather than evicting one. Evicting a bucket that still
    /// holds live state would reset its per-window rate/spend limit, letting a
    /// caller who can mint many distinct capability ids force a depleted (or
    /// partially refilled) bucket out and reuse the id for a fresh full-burst
    /// `TokenBucket`, a fail-open rate-limit bypass. Denying keeps memory bounded
    /// (cap unchanged) without the bypass: a distinct-capability flood saturates at
    /// `bucket_cap`.
    fn reserve_slots(&mut self, new_slots: usize, bucket_cap: usize) -> bool {
        if new_slots == 0 {
            return true;
        }
        // Inserting `new_slots` new buckets must keep the combined total within
        // `bucket_cap`. `combined_len()` is the true total under this lock, so
        // there is no stale-snapshot overshoot.
        if self.combined_len().saturating_add(new_slots) > bucket_cap {
            self.prune_refilled();
            if self.combined_len().saturating_add(new_slots) > bucket_cap {
                return false;
            }
        }
        true
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

        // Both maps share ONE lock, held for the whole evaluate, so the
        // combined-cap check and the insert are atomic across both maps: no
        // evaluate() ever reads a stale sibling-map size, so the combined bucket
        // count cannot overshoot under concurrency. A single lock means no
        // cross-map lock ordering and no deadlock. If spend limiting fails closed
        // below, the guard drops cleanly (no panic, no poison).
        let mut state = self
            .state
            .lock()
            .map_err(|_| KernelError::Internal("velocity guard state lock poisoned".to_string()))?;

        let inv_limit = self.config.max_invocations_per_window;
        let spend_limit = self.config.max_spend_per_window;

        // Resolve the planned spend cost up front. This can fail closed (missing
        // grant cost metadata) with an Err, which must surface BEFORE any bucket
        // is created or consumed, so a denied-by-metadata request never burns a
        // sibling invocation token.
        let spend_units = match spend_limit {
            Some(_) => Some(planned_spend_units(ctx)?),
            None => None,
        };

        // A planned spend larger than the spend bucket's burst ceiling can never
        // be admitted, however long the caller waits. Deny it before reserving or
        // creating any bucket: a bucket for a spend that can never fit would only
        // occupy a slot in the bounded table until the idle sweep reclaims it, and
        // creating one here would also burn a reservation for a call that is
        // certain to be denied.
        if let (Some(max_spend), Some(cost)) = (spend_limit, spend_units) {
            if cost > burst_capacity(max_spend, self.config.burst_factor) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Phase 1 - RESERVE. Secure a slot for EVERY genuinely-new bucket this
        // request needs across BOTH maps before consuming from EITHER. A brand-new
        // key with both limits enabled needs two slots (one per map); reserving
        // them together means a request that will be denied for lack of capacity
        // never inserts an unpaired invocation bucket into the final slot or burns
        // an invocation token for a call denied at the spend limit (reserve-both,
        // no partial consumption).
        let inv_new = inv_limit.is_some() && !state.invocation_buckets.contains_key(&key);
        let spend_new = spend_limit.is_some() && !state.spend_buckets.contains_key(&key);
        let new_slots = usize::from(inv_new) + usize::from(spend_new);
        if !state.reserve_slots(new_slots, self.bucket_cap) {
            return Ok(GuardDecision::deny(Vec::new()));
        }

        // Phase 2 - obtain both buckets (creating the reserved new ones). Borrow
        // the two disjoint maps through one `&mut VelocityState` so both bucket
        // handles can be held at once.
        let state = &mut *state;
        let mut inv_bucket: Option<&mut TokenBucket> = match inv_limit {
            Some(max_inv) => {
                let capacity = burst_capacity(max_inv as u64, self.config.burst_factor);
                Some(
                    state
                        .invocation_buckets
                        .entry(key.clone())
                        .or_insert_with(|| TokenBucket::new(capacity, max_inv as u64, window_secs)),
                )
            }
            None => None,
        };
        let mut spend_bucket: Option<&mut TokenBucket> = match spend_limit {
            Some(max_spend) => {
                let capacity = burst_capacity(max_spend, self.config.burst_factor);
                Some(
                    state
                        .spend_buckets
                        .entry(key)
                        .or_insert_with(|| TokenBucket::new(capacity, max_spend, window_secs)),
                )
            }
            None => None,
        };

        // Phase 3 - check BOTH buckets can satisfy the request before consuming
        // from EITHER, then commit both. Peeking (`can_consume`) before consuming
        // means a denial from one limit never depletes the other bucket.
        let spend_cost = spend_units.unwrap_or(0);
        let inv_ok = inv_bucket
            .as_mut()
            .map(|b| b.can_consume(1))
            .unwrap_or(true);
        let spend_ok = spend_bucket
            .as_mut()
            .map(|b| b.can_consume(spend_cost))
            .unwrap_or(true);
        if !inv_ok || !spend_ok {
            return Ok(GuardDecision::deny(Vec::new()));
        }
        if let Some(bucket) = inv_bucket.as_mut() {
            bucket.consume(1);
        }
        if let Some(bucket) = spend_bucket.as_mut() {
            bucket.consume(spend_cost);
        }

        Ok(GuardDecision::allow())
    }
}

/// Burst ceiling in whole tokens: the steady per-window allowance scaled by the
/// configured burst factor, rounded to the nearest token and floored at 1 so a
/// bucket can always hold at least one token.
fn burst_capacity(per_window: u64, burst_factor: f64) -> u64 {
    ((per_window as f64 * burst_factor).round() as u64).max(1)
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
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            aggregate_invocation_budget: None,
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
    fn idle_buckets_are_swept_and_key_count_is_capped() {
        // Cap tiny so the flood saturates rather than grows.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 8);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        // Drive many distinct capability ids (the self-minted-leaf flood): each
        // makes a new bucket, but the cap holds the total.
        for i in 0..500u64 {
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let scope = ChioScope::default();
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let _ = guard.evaluate(&ctx);
        }
        assert!(
            guard.invocation_bucket_count() <= 8,
            "bucket map grew past cap: {}",
            guard.invocation_bucket_count()
        );
    }

    #[test]
    fn both_bucket_maps_together_stay_within_total_cap() {
        // With both invocation and spend limits enabled the bucket cap is a TOTAL
        // across both maps. Flooding distinct capability ids (each mints an
        // invocation AND a spend bucket) must not let invocation + spend buckets
        // exceed the cap; a per-map cap would reach twice the intended total.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            max_spend_per_window: Some(1000),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let cap_total = 8;
        let guard = VelocityGuard::with_bucket_cap(config, cap_total);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        // A grant with max_cost_per_invocation so the spend path mints buckets.
        let scope = spend_scope(1);
        for i in 0..500u64 {
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            let _ = guard.evaluate(&ctx);
        }
        let combined = guard.invocation_bucket_count() + guard.spend_bucket_count();
        assert!(
            combined <= cap_total,
            "combined bucket count {combined} exceeded total cap {cap_total} (inv={}, spend={})",
            guard.invocation_bucket_count(),
            guard.spend_bucket_count(),
        );
        // Both maps are genuinely populated, so the bound is meaningful.
        assert!(
            guard.invocation_bucket_count() > 0 && guard.spend_bucket_count() > 0,
            "test is vacuous: one of the maps stayed empty"
        );
    }

    #[test]
    fn combined_cap_holds_under_concurrent_distinct_capability_flood() {
        // With both maps under one lock the combined-cap check and insert are
        // atomic, so the combined bucket count never exceeds `bucket_cap` even
        // when concurrent evaluate() calls race on distinct capability ids. This
        // test hammers the guard from many threads with distinct capability ids
        // (each mints an invocation AND a spend bucket) and asserts the combined
        // count stays within the cap at every observation.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            max_spend_per_window: Some(1000),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let bucket_cap = 16usize;
        let guard = Arc::new(VelocityGuard::with_bucket_cap(config, bucket_cap));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let threads = 8usize;
        let per_thread = 400u64;
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let guard = Arc::clone(&guard);
                let max_observed = Arc::clone(&max_observed);
                thread::spawn(move || {
                    let kp = Keypair::generate();
                    let agent = kp.public_key().to_hex();
                    let server = "srv".to_string();
                    let scope = spend_scope(1);
                    for i in 0..per_thread {
                        // Distinct capability id per (thread, iteration): each is a
                        // brand-new key, exercising the new-key insert + cap path.
                        let cap = signed_cap(&kp, &format!("cap-{t}-{i}"));
                        let request = make_request(&cap, &agent, &server);
                        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
                        let _ = guard.evaluate(&ctx);
                        // Observe the combined count under the single lock: it must
                        // never exceed the cap under concurrent inserts.
                        let combined = guard.combined_bucket_count();
                        max_observed.fetch_max(combined, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let observed = max_observed.load(Ordering::Relaxed);
        assert!(
            observed <= bucket_cap,
            "combined bucket count {observed} exceeded the total cap {bucket_cap} under concurrency"
        );
        // The bound is meaningful only if buckets were actually created.
        assert!(
            observed > 0,
            "test is vacuous: no buckets were ever created"
        );
    }

    #[test]
    fn updating_existing_bucket_at_cap_is_not_evicted() {
        // Cap of 1 with a 1-per-window limit: the first request for a capability
        // consumes its only token; a second request for the SAME capability must
        // find the preserved (now empty) bucket and be denied, not evict and
        // recreate it with a full balance.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1),
            window_secs: 60,
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 1);
        let kp = Keypair::generate();
        let cap = signed_cap(&kp, "cap-update");
        let scope = ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let request = make_request(&cap, &agent, &server);

        let first = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)))
            .expect("first request should not error");
        assert_eq!(first, Verdict::Allow, "first request should be allowed");

        let second = guard
            .evaluate(&guard_ctx(&request, &scope, &agent, &server, Some(0)))
            .expect("second request should not error");
        assert_eq!(
            second,
            Verdict::Deny,
            "second request must hit the preserved (empty) bucket, not a fresh one"
        );
        assert_eq!(
            guard.invocation_bucket_count(),
            1,
            "the bucket being consumed must not be evicted and recreated"
        );
    }

    #[test]
    fn full_table_of_active_buckets_denies_new_key_without_eviction() {
        // When the combined bucket table is full of IN-WINDOW (active) buckets, a
        // new distinct capability must be DENIED fail-closed, NOT admitted by
        // evicting an active victim. Evicting an active bucket would reset the
        // victim's
        // per-window limit, letting a caller who mints many distinct capability ids
        // force a depleted bucket out and reuse the id within the same window for a
        // fresh TokenBucket. Two in-window capabilities fill a cap of 2; a third is
        // denied and the two actives keep their (depleted) buckets intact.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1),
            window_secs: 60,
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 2);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let scope = ChioScope::default();

        let cap_a = signed_cap(&kp, "cap-a");
        let cap_b = signed_cap(&kp, "cap-b");
        let cap_c = signed_cap(&kp, "cap-c");
        let req_a = make_request(&cap_a, &agent, &server);
        let req_b = make_request(&cap_b, &agent, &server);
        let req_c = make_request(&cap_c, &agent, &server);

        // a and b each spend their single token; the table is now full of two
        // active buckets.
        let a1 = guard
            .evaluate(&guard_ctx(&req_a, &scope, &agent, &server, Some(0)))
            .expect("a first");
        assert_eq!(a1, Verdict::Allow);
        let b1 = guard
            .evaluate(&guard_ctx(&req_b, &scope, &agent, &server, Some(0)))
            .expect("b first");
        assert_eq!(b1, Verdict::Allow);
        assert_eq!(guard.combined_bucket_count(), 2);

        // c trips the cap while a and b are both in-window: c must be DENIED and no
        // active bucket may be evicted.
        let c1 = guard
            .evaluate(&guard_ctx(&req_c, &scope, &agent, &server, Some(0)))
            .expect("c");
        assert_eq!(
            c1,
            Verdict::Deny,
            "new key must be denied when the table is full of active buckets, not admitted by eviction"
        );
        assert_eq!(
            guard.combined_bucket_count(),
            2,
            "an active bucket was wrongly evicted to admit the new key"
        );

        // a retained its (now empty) bucket: re-evaluating it must still be denied.
        // Were c allowed to evict a, this would return a fresh allowed bucket.
        let a2 = guard
            .evaluate(&guard_ctx(&req_a, &scope, &agent, &server, Some(0)))
            .expect("a replay");
        assert_eq!(
            a2,
            Verdict::Deny,
            "active bucket a was reset by eviction (rate-limit bypass regressed)"
        );
    }

    #[test]
    fn burst_drained_bucket_is_not_reaped_after_one_idle_window() {
        // A bucket whose burst allowance was drained refills only at the steady
        // per-window rate, so with a burst ceiling above that rate it needs several
        // idle windows to recover to capacity, not one. Reaping it after a single
        // idle window and recreating its key would hand the subject a fresh full
        // burst, resetting a limit it had not yet earned back. A partially refilled
        // bucket must therefore survive a prune triggered by a competing new key,
        // and the new key is denied instead.
        let config = VelocityConfig {
            max_invocations_per_window: Some(2),
            window_secs: 1,
            burst_factor: 2.0, // capacity 4, steady refill 2 per window
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 1);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let scope = ChioScope::default();

        let cap_x = signed_cap(&kp, "cap-x");
        let req_x = make_request(&cap_x, &agent, &server);

        // Drain the full burst of 4 tokens.
        for _ in 0..4 {
            assert_eq!(
                guard
                    .evaluate(&guard_ctx(&req_x, &scope, &agent, &server, Some(0)))
                    .expect("burst request"),
                Verdict::Allow,
            );
        }
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_x, &scope, &agent, &server, Some(0)))
                .expect("drained request"),
            Verdict::Deny,
            "the burst is drained",
        );
        assert_eq!(guard.combined_bucket_count(), 1);

        // Idle for exactly one window: the bucket refills to 2 of 4 tokens, still
        // short of its burst ceiling.
        thread::sleep(Duration::from_millis(1100));

        // A competing new key trips the cap and attempts a prune. The partially
        // refilled bucket carries live state, so it is retained and the new key is
        // denied rather than reaping the burst victim.
        let cap_y = signed_cap(&kp, "cap-y");
        let req_y = make_request(&cap_y, &agent, &server);
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_y, &scope, &agent, &server, Some(0)))
                .expect("competing key"),
            Verdict::Deny,
            "a partially refilled burst bucket must not be reaped to admit a new key",
        );
        assert_eq!(
            guard.combined_bucket_count(),
            1,
            "the burst victim was reaped to admit the competing key",
        );

        // The victim regained only the steady per-window amount (2 tokens), not a
        // fresh full burst (4): exactly two more requests succeed before it denies.
        for _ in 0..2 {
            assert_eq!(
                guard
                    .evaluate(&guard_ctx(&req_x, &scope, &agent, &server, Some(0)))
                    .expect("refilled request"),
                Verdict::Allow,
            );
        }
        assert_eq!(
            guard
                .evaluate(&guard_ctx(&req_x, &scope, &agent, &server, Some(0)))
                .expect("post-refill request"),
            Verdict::Deny,
            "the burst was reset to full capacity instead of the steady refill",
        );
    }

    #[test]
    fn spend_denial_does_not_wedge_or_deplete_invocation_bucket() {
        // With both limits enabled and a combined cap that has only one free slot,
        // a brand-new key needs TWO slots (one invocation, one spend). The guard
        // must reserve both BEFORE consuming from either, so a request that will be
        // denied at the spend reservation never inserts an invocation-only bucket
        // into the final slot or burns an invocation token for a call that never
        // ran. Without reserve-both, the invocation bucket would be inserted and
        // consumed before the spend reservation failed, wedging the table at the
        // cap with an unpaired invocation bucket.
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            max_spend_per_window: Some(1000),
            window_secs: 60,
            burst_factor: 1.0,
        };
        // Odd cap: two fully tracked keys use four slots (inv+spend each), leaving
        // exactly one free slot.
        let guard = VelocityGuard::with_bucket_cap(config, 5);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let scope = spend_scope(1);

        for id in ["cap-a", "cap-b"] {
            let cap = signed_cap(&kp, id);
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
            assert_eq!(
                guard.evaluate(&ctx).expect("tracked key should be allowed"),
                Verdict::Allow,
            );
        }
        assert_eq!(guard.invocation_bucket_count(), 2);
        assert_eq!(guard.spend_bucket_count(), 2);
        assert_eq!(guard.combined_bucket_count(), 4);

        // A third brand-new key needs two slots but only one is free: it must be
        // DENIED without creating an invocation-only bucket in the last slot.
        let cap_c = signed_cap(&kp, "cap-c");
        let request_c = make_request(&cap_c, &agent, &server);
        let ctx_c = guard_ctx(&request_c, &scope, &agent, &server, Some(0));
        assert_eq!(
            guard.evaluate(&ctx_c).expect("third key eval"),
            Verdict::Deny,
            "a new key that cannot fit BOTH buckets must be denied"
        );

        // The table was NOT wedged: no unpaired invocation bucket was inserted, and
        // no invocation token was burned for the spend-denied request.
        assert_eq!(
            guard.invocation_bucket_count(),
            2,
            "spend-denied request wedged an invocation-only bucket in the final slot"
        );
        assert_eq!(guard.spend_bucket_count(), 2);
        assert_eq!(guard.combined_bucket_count(), 4);
    }

    #[test]
    fn impossible_spend_denies_without_creating_a_bucket() {
        // When a grant's per-invocation cost exceeds the spend bucket's burst
        // ceiling the spend can never fit, so the request is always denied. It must
        // NOT create a bucket: a bucket for a never-allowable spend would occupy a
        // slot in the bounded table for a limit that can never fire.
        let config = VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(10),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let guard = VelocityGuard::with_bucket_cap(config, 4);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        // Cost 100 exceeds the burst ceiling of 10 (max_spend 10 * burst 1.0).
        let scope = spend_scope(100);

        let cap = signed_cap(&kp, "cap-impossible");
        let request = make_request(&cap, &agent, &server);
        let ctx = guard_ctx(&request, &scope, &agent, &server, Some(0));
        assert_eq!(
            guard.evaluate(&ctx).expect("impossible spend eval"),
            Verdict::Deny,
            "a spend larger than the burst ceiling can never fit and must be denied"
        );
        assert_eq!(
            guard.spend_bucket_count(),
            0,
            "a never-allowable spend must not leave a bucket occupying a slot"
        );
        assert_eq!(guard.combined_bucket_count(), 0);
    }

    #[test]
    fn impossible_spend_flood_does_not_populate_the_bounded_table() {
        // A flood of distinct capability keys whose spend can never fit must not
        // consume the bounded bucket table. Because no bucket is created for an
        // impossible spend, a later affordable key still finds a free slot.
        let config = VelocityConfig {
            max_invocations_per_window: None,
            max_spend_per_window: Some(10),
            window_secs: 60,
            burst_factor: 1.0,
        };
        let guard = VelocityGuard::with_bucket_cap(config, 2);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let impossible = spend_scope(100);

        for i in 0..100u64 {
            let cap = signed_cap(&kp, &format!("cap-impossible-{i}"));
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &impossible, &agent, &server, Some(0));
            assert_eq!(
                guard.evaluate(&ctx).expect("impossible spend eval"),
                Verdict::Deny,
            );
        }
        assert_eq!(
            guard.spend_bucket_count(),
            0,
            "a flood of never-allowable spends populated the bounded table"
        );

        // An affordable key (cost 5 <= ceiling 10) still fits and is allowed.
        let affordable = spend_scope(5);
        let cap = signed_cap(&kp, "cap-affordable");
        let request = make_request(&cap, &agent, &server);
        let ctx = guard_ctx(&request, &affordable, &agent, &server, Some(0));
        assert_eq!(
            guard.evaluate(&ctx).expect("affordable spend eval"),
            Verdict::Allow,
            "an affordable key must not be starved by never-allowable spends"
        );
    }

    #[test]
    fn fully_refilled_bucket_is_pruned_to_admit_new_key() {
        // The bounded path reclaims slots from buckets that have refilled back to
        // full capacity: such a bucket is indistinguishable from a fresh one, so
        // pruning it to admit a new key cannot reset an in-flight limit. With a 1s
        // window, a unit steady rate, and a cap of 1, the first capability's bucket
        // refills to capacity after one idle window, so a second distinct
        // capability is admitted (not denied).
        let config = VelocityConfig {
            max_invocations_per_window: Some(1),
            window_secs: 1,
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::with_bucket_cap(config, 1);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let scope = ChioScope::default();

        let cap_a = signed_cap(&kp, "cap-a");
        let cap_b = signed_cap(&kp, "cap-b");
        let req_a = make_request(&cap_a, &agent, &server);
        let req_b = make_request(&cap_b, &agent, &server);

        let a1 = guard
            .evaluate(&guard_ctx(&req_a, &scope, &agent, &server, Some(0)))
            .expect("a first");
        assert_eq!(a1, Verdict::Allow);
        assert_eq!(guard.combined_bucket_count(), 1);

        // Idle strictly past the window so a's bucket refills back to full capacity
        // (a unit rate reaches capacity after one window).
        thread::sleep(Duration::from_millis(1200));

        // b is a new distinct key at the cap: the fully refilled bucket is pruned to
        // reclaim a's slot, so b is admitted rather than denied, and the table still
        // holds exactly one bucket (bounded).
        let b1 = guard
            .evaluate(&guard_ctx(&req_b, &scope, &agent, &server, Some(0)))
            .expect("b first");
        assert_eq!(
            b1,
            Verdict::Allow,
            "an expired bucket must be pruned to make room for a new key"
        );
        assert_eq!(
            guard.combined_bucket_count(),
            1,
            "the expired bucket was not pruned; table exceeded the cap"
        );
    }

    #[test]
    fn from_memory_budget_honors_lowered_velocity_bucket_cap() {
        // The CONFIGURED process memory budget must reach this guard. A budget that
        // lowers `velocity_bucket_cap` to 4 must cap the combined bucket table at
        // 4, not the compiled-in default of 65_536. `from_memory_budget` threads
        // the budget through where `new` would read `defaults()`.
        let budget = chio_kernel::MemoryBudgetConfig {
            velocity_bucket_cap: 4,
            ..chio_kernel::MemoryBudgetConfig::defaults()
        };
        let config = VelocityConfig {
            max_invocations_per_window: Some(1000),
            window_secs: 60,
            ..VelocityConfig::default()
        };
        let guard = VelocityGuard::from_memory_budget(config, &budget);
        let kp = Keypair::generate();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();
        let scope = ChioScope::default();
        for i in 0..200u64 {
            let cap = signed_cap(&kp, &format!("cap-{i}"));
            let request = make_request(&cap, &agent, &server);
            let ctx = guard_ctx(&request, &scope, &agent, &server, None);
            let _ = guard.evaluate(&ctx);
        }
        assert!(
            guard.combined_bucket_count() <= 4,
            "configured velocity_bucket_cap did not take effect: {} buckets",
            guard.combined_bucket_count()
        );
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
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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
