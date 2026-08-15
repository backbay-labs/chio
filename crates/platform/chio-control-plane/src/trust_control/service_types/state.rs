use super::*;

#[derive(Clone)]
pub(crate) struct TrustServiceState {
    pub(crate) config: TrustServiceConfig,
    /// Present only when a trusted, already-provisioned joint budget/revocation
    /// authority was injected. Configured database paths alone never enable the
    /// structured authority surface.
    pub(crate) joint_authority_store: Option<Arc<SqliteAuthorityStore>>,
    pub(crate) fiscal_runtime: Option<Arc<TrustFiscalRuntime>>,
    pub(crate) budget_store: Option<Arc<SqliteBudgetStore>>,
    pub(crate) revocation_store: Option<Arc<SqliteRevocationStore>>,
    pub(crate) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(crate) verifier_policy_registry: Option<Arc<VerifierPolicyRegistry>>,
    pub(crate) federation_admission_rate_limiter: Arc<Mutex<FederationAdmissionRateLimiter>>,
    pub(crate) cluster: Option<Arc<Mutex<ClusterRuntimeState>>>,
    /// Progress signal for the single background cluster-sync loop. `Some`
    /// exactly when `cluster` is `Some`. A budget-write handler parks on this
    /// watch instead of driving its own inline sync.
    pub(crate) cluster_progress: Option<Arc<ClusterProgress>>,
    /// Evidenced rail seam for finding-market fee collection;
    /// `None` fails activation closed.
    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) finding_rail: Option<Arc<dyn super::super::finding_handlers::FindingRailObserver>>,
    /// Explicit deployment adapter for the end-to-end finding purchase.
    /// Absent by default so the public route fails closed until the seller,
    /// coordinator, durable store, and purchase-aware kernel are wired.
    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) finding_purchase_executor:
        Option<super::super::finding_purchase_routes::SharedFindingPurchaseExecutor>,
    /// Explicit durable challenge-submission dependency. It is absent in the
    /// default runtime because public configuration does not carry the private
    /// signing keys or published-artifact resolver required to construct the
    /// coordinator. The HTTP route fails closed while it is absent.
    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) finding_challenge_executor: Option<
        Arc<dyn super::super::finding_challenge_handlers::FindingChallengeSubmissionExecutor>,
    >,
}

/// Coordinates the single background cluster-sync loop with budget-write
/// waiters. `tick` increments once per completed sync round (waiters watch it);
/// `kick` lets a waiter ask the loop to run a round now instead of sleeping out
/// its interval. The loop is the sole driver of cursor and ack advancement, so
/// N concurrent writes share one sync stream rather than each spawning its own.
pub(crate) struct ClusterProgress {
    tick: tokio::sync::watch::Sender<u64>,
    kick: tokio::sync::Notify,
}

impl ClusterProgress {
    pub(crate) fn new() -> Self {
        let (tick, _rx) = tokio::sync::watch::channel(0);
        Self {
            tick,
            kick: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn notify_round_complete(&self) {
        self.tick
            .send_modify(|value| *value = value.wrapping_add(1));
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.tick.subscribe()
    }

    pub(crate) fn request_sync(&self) {
        self.kick.notify_one();
    }

    pub(crate) async fn awaited_kick(&self) {
        self.kick.notified().await;
    }
}

#[derive(Clone)]
pub struct TrustControlClient {
    pub(crate) endpoints: Arc<Vec<String>>,
    pub(crate) preferred_index: Arc<Mutex<usize>>,
    pub(crate) token: Arc<str>,
    pub(crate) http: Agent,
    pub(crate) cluster_peer_auth: Option<ClusterPeerClientAuth>,
}

#[derive(Clone)]
pub(crate) struct ClusterPeerClientAuth {
    pub(crate) node_id: Arc<str>,
}

pub(crate) struct RemoteCapabilityAuthority {
    pub(crate) client: TrustControlClient,
    pub(crate) cache: Mutex<AuthorityKeyCache>,
    pub(crate) refresh_lock: Mutex<()>,
}

pub(crate) struct AuthorityKeyCache {
    pub(crate) current: Option<PublicKey>,
    pub(crate) trusted: Vec<PublicKey>,
    pub(crate) generation: Option<u64>,
    pub(crate) rotated_at: Option<u64>,
    pub(crate) refreshed_at: Instant,
}

pub(crate) struct RemoteRevocationStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteReceiptStore {
    pub(crate) client: TrustControlClient,
    /// Fixed-size worker pool that bounds concurrent blocking writes to a stalled
    /// control plane, so a slow `--control-url` cannot accumulate one parked
    /// thread per write.
    pub(crate) writer: crate::trust_control::service_runtime::remote_stores::BoundedReceiptWriter,
}

pub(crate) struct RemoteBudgetStore {
    pub(crate) client: TrustControlClient,
    pub(crate) cached_usage: Mutex<HashMap<(String, usize), CachedBudgetUsage>>,
}

/// A cached usage projection together with whether its monetary totals were actually
/// observed. Partial responses such as `try_increment` carry only the invocation
/// count, so their entries default the cost fields to zero; serving one as real usage
/// would report no spend for a grant that has some.
#[derive(Clone)]
pub(crate) struct CachedBudgetUsage {
    pub(crate) record: BudgetUsageRecord,
    pub(crate) cost_authoritative: bool,
}

impl TrustServiceState {
    pub(crate) fn optional_budget_store(&self) -> Result<Option<SqliteBudgetStore>, &'static str> {
        if let Some(authority_store) = self.joint_authority_store.as_ref() {
            if self.cluster.is_some() {
                return Err(
                    "joint budget and revocation authority cannot run with the legacy cluster coordinator",
                );
            }
            return Ok(Some(authority_store.budget_store()));
        }
        Ok(self.budget_store.as_deref().cloned())
    }

    pub(crate) fn budget_store(&self) -> Result<SqliteBudgetStore, Response> {
        self.optional_budget_store()
            .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error))?
            .ok_or_else(|| {
                plain_http_error(
                    StatusCode::CONFLICT,
                    "trust control service requires --budget-db",
                )
            })
    }

    pub(crate) fn optional_revocation_store(
        &self,
    ) -> Result<Option<SqliteRevocationStore>, &'static str> {
        if let Some(authority_store) = self.joint_authority_store.as_ref() {
            if self.cluster.is_some() {
                return Err(
                    "joint budget and revocation authority cannot run with the legacy cluster coordinator",
                );
            }
            return Ok(Some(authority_store.revocation_store()));
        }
        Ok(self.revocation_store.as_deref().cloned())
    }

    pub(crate) fn revocation_store(&self) -> Result<SqliteRevocationStore, Response> {
        self.optional_revocation_store()
            .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error))?
            .ok_or_else(|| {
                plain_http_error(
                    StatusCode::CONFLICT,
                    "trust control service requires --revocation-db",
                )
            })
    }

    pub(crate) fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    pub(crate) fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }

    pub(crate) fn verifier_policy_registry(&self) -> Option<&VerifierPolicyRegistry> {
        self.verifier_policy_registry.as_deref()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterRuntimeState {
    pub(crate) self_url: String,
    pub(crate) peers: HashMap<String, PeerSyncState>,
    pub(crate) election_term: u64,
    pub(crate) last_leader_url: Option<String>,
    pub(crate) term_started_at: Option<u64>,
    pub(crate) lease_expires_at: Option<u64>,
    pub(crate) lease_ttl_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerSyncState {
    pub(crate) health: PeerHealth,
    pub(crate) partitioned: bool,
    pub(crate) last_error: Option<String>,
    pub(crate) last_contact_at: Option<u64>,
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    pub(crate) revocation_cursor: Option<RevocationCursor>,
    pub(crate) budget_cursor: Option<BudgetCursor>,
    pub(crate) budget_import_acks: BTreeMap<String, u64>,
    pub(crate) delta_records_since_snapshot: u64,
    pub(crate) snapshot_applied_count: u64,
    pub(crate) last_snapshot_at: Option<u64>,
    pub(crate) force_snapshot: bool,
}

/// One subject's in-window attempt timestamps together with the window (in
/// seconds) of the policy that recorded them. The window is stored PER BUCKET so
/// cross-policy pruning uses each bucket's own window rather than the current
/// request's: when the limiter is shared across federation policies with
/// different `window_seconds`, a short-window request must not delete timestamps
/// that are still active for a longer-window policy, which would reset that
/// subject's limit and let more admissions through in the long window.
#[derive(Debug, Default)]
struct SubjectAttempts {
    window_seconds: u64,
    timestamps: Vec<u64>,
}

impl SubjectAttempts {
    /// Lower bound below which this bucket's timestamps are out-of-window, using
    /// THIS bucket's own window (not the caller's).
    fn lower_bound(&self, now: u64) -> u64 {
        now.saturating_sub(self.window_seconds)
    }

    /// Drop this bucket's out-of-window timestamps using its own window.
    fn prune(&mut self, now: u64) {
        let lower_bound = self.lower_bound(now);
        self.timestamps.retain(|t| *t > lower_bound);
    }
}

#[derive(Debug)]
pub(crate) struct FederationAdmissionRateLimiter {
    // Per-subject in-window attempt timestamps, keyed by `policy:subject`. Each
    // bucket carries the window of the policy that recorded it, so pruning across
    // policies respects each bucket's own window (see [`SubjectAttempts`]). The
    // distinct-key set is bounded fail-closed by `key_cap`: EXPIRED (out-of-
    // window) subjects are pruned first, and once the table holds `key_cap`
    // ACTIVE (in-window) subjects a new subject is DENIED rather than evicting an
    // active bucket. Never evicting an ACTIVE bucket closes the reset-by-eviction
    // bypass (an attacker cannot force its own active bucket out with throwaway
    // subjects and then reuse its subject with a fresh limit in the same window),
    // while still saturating instead of growing under a distinct-subject flood. A
    // subject is removed only when its window fully empties.
    attempts: HashMap<String, SubjectAttempts>,
    key_cap: usize,
}

impl Default for FederationAdmissionRateLimiter {
    fn default() -> Self {
        // Single-sourced with the process memory budget instead of a duplicated
        // literal; tighter caps use `with_key_cap`.
        Self::from_memory_budget(&chio_kernel::MemoryBudgetConfig::defaults())
    }
}

impl FederationAdmissionRateLimiter {
    /// Build a limiter whose key cap comes from a CONFIGURED process memory
    /// budget. Threading the operator's `MemoryBudgetConfig` (rather than a
    /// fresh `defaults()` read) means lowering `admission_key_cap` on the trust
    /// service config actually tightens this guard instead of being silently
    /// ignored.
    pub(crate) fn from_memory_budget(budget: &chio_kernel::MemoryBudgetConfig) -> Self {
        Self::with_key_cap(budget.admission_key_cap)
    }

    pub(crate) fn with_key_cap(key_cap: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            key_cap: key_cap.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn key_count(&self) -> usize {
        self.attempts.len()
    }

    /// Drop subjects whose entire attempt window has expired, freeing slots for
    /// new subjects. Each bucket is pruned against ITS OWN window (not the
    /// caller's `now - window`), so a short-window policy request never evicts
    /// timestamps that are still active for a longer-window policy sharing this
    /// limiter. Bounded: touches at most the live keys (<= `key_cap` once
    /// saturated).
    fn prune_expired(&mut self, now: u64) {
        self.attempts.retain(|_, entry| {
            entry.prune(now);
            !entry.timestamps.is_empty()
        });
    }

    pub(crate) fn check_and_record(
        &mut self,
        policy_id: &str,
        subject_key: &str,
        limit: &FederationAdmissionRateLimit,
        now: u64,
    ) -> FederationAdmissionRateLimitStatus {
        let key = format!("{policy_id}:{subject_key}");
        let lower_bound = now.saturating_sub(limit.window_seconds);

        let is_new_key = !self.attempts.contains_key(&key);
        // Key cap. When the table is full and this is a new subject, prune
        // EXPIRED (out-of-window) subjects first to reclaim slots. Each bucket is
        // pruned against its OWN window, so a short-window request does not evict
        // a longer-window policy's still-active subject. If every remaining slot
        // still holds an ACTIVE (in-window) subject, DENY the new subject
        // fail-closed rather than evicting an active bucket: evicting an active
        // bucket would reset its per-window limit, so an attacker could reset its
        // own limit by flooding throwaway subjects to force its eviction, then
        // reusing its subject in the same window. Denying keeps memory bounded
        // (cap unchanged) without the bypass, and a distinct-subject flood still
        // saturates instead of growing.
        if is_new_key && self.attempts.len() >= self.key_cap {
            self.prune_expired(now);
            if self.attempts.len() >= self.key_cap {
                return FederationAdmissionRateLimitStatus {
                    limit: limit.max_requests,
                    window_seconds: limit.window_seconds,
                    remaining: 0,
                    retry_after_seconds: Some(limit.window_seconds.max(1)),
                };
            }
        }

        let entry = self.attempts.entry(key.clone()).or_default();
        // Record this bucket's window so later cross-policy prunes use it rather
        // than an unrelated policy's window.
        entry.window_seconds = limit.window_seconds;
        entry
            .timestamps
            .retain(|timestamp| *timestamp > lower_bound);
        if entry.timestamps.len() >= limit.max_requests as usize {
            let retry_after_seconds = entry
                .timestamps
                .first()
                .map(|oldest| {
                    oldest
                        .saturating_add(limit.window_seconds)
                        .saturating_sub(now)
                })
                .unwrap_or(limit.window_seconds);
            return FederationAdmissionRateLimitStatus {
                limit: limit.max_requests,
                window_seconds: limit.window_seconds,
                remaining: 0,
                retry_after_seconds: Some(retry_after_seconds.max(1)),
            };
        }
        entry.timestamps.push(now);

        // Drop-empty maintenance: prune any subject whose window has fully
        // emptied so a fresh subject costs nothing once its window empties. Each
        // bucket uses its own window, so this never resets a longer-window
        // policy's active subject. Bounded: touches at most `key_cap` keys. The
        // subject just recorded above retains its `now` timestamp, so it survives.
        self.prune_expired(now);

        FederationAdmissionRateLimitStatus {
            limit: limit.max_requests,
            window_seconds: limit.window_seconds,
            remaining: limit.max_requests.saturating_sub(
                self.attempts
                    .get(&key)
                    .map(|v| v.timestamps.len())
                    .unwrap_or(0) as u32,
            ),
            retry_after_seconds: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PeerHealth {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub(crate) struct RevocationCursor {
    pub(crate) revoked_at: i64,
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct BudgetCursor {
    pub(crate) seq: u64,
    pub(crate) updated_at: i64,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterConsensusView {
    pub(crate) self_url: String,
    pub(crate) leader_url: Option<String>,
    pub(crate) role: &'static str,
    pub(crate) has_quorum: bool,
    pub(crate) quorum_size: usize,
    pub(crate) reachable_nodes: usize,
    pub(crate) election_term: u64,
}

impl Default for PeerSyncState {
    fn default() -> Self {
        Self {
            health: PeerHealth::Unknown,
            partitioned: false,
            last_error: None,
            last_contact_at: None,
            tool_seq: 0,
            child_seq: 0,
            lineage_seq: 0,
            revocation_cursor: None,
            budget_cursor: None,
            budget_import_acks: BTreeMap::new(),
            delta_records_since_snapshot: 0,
            snapshot_applied_count: 0,
            last_snapshot_at: None,
            force_snapshot: true,
        }
    }
}

impl PeerHealth {
    pub(crate) fn is_reachable(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[cfg(test)]
mod admission_bound_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn limit() -> FederationAdmissionRateLimit {
        FederationAdmissionRateLimit {
            max_requests: 5,
            window_seconds: 60,
        }
    }

    #[test]
    fn distinct_subject_flood_saturates_at_key_cap() {
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(8);
        for i in 0..1000u64 {
            let subject = format!("subject-{i}");
            let _ = limiter.check_and_record("policy", &subject, &limit(), 100);
        }
        assert!(
            limiter.key_count() <= 8,
            "attempts map grew past key cap: {}",
            limiter.key_count()
        );
    }

    #[test]
    fn expired_subjects_do_not_leak_keys() {
        // Distinct subjects, each in its own window (1000s apart, far past the
        // 60s window), stay below `key_cap`. The drop-empty maintenance pass must
        // prune expired subjects from `attempts` or the map grows one key per
        // subject without bound.
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        for i in 0..1000u64 {
            let subject = format!("subject-{i}");
            let now = 100 + i * 1000;
            let _ = limiter.check_and_record("policy", &subject, &limit(), now);
        }
        assert!(
            limiter.key_count() <= 8,
            "attempts leaked stale keys: {}",
            limiter.key_count()
        );
    }

    #[test]
    fn emptied_window_key_leaves_no_residue() {
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        let _ = limiter.check_and_record("policy", "s", &limit(), 100);
        assert_eq!(limiter.key_count(), 1);
        // A later call whose window has fully passed prunes the old timestamp;
        // the drop-empty maintenance pass then removes the residual key from the
        // unrelated emptied subject, so only "s2" remains.
        let _ = limiter.check_and_record("policy", "s2", &limit(), 100_000);
        assert_eq!(limiter.key_count(), 1, "emptied-window key left residue");
    }

    #[test]
    fn lowered_admission_key_cap_from_memory_budget_takes_effect() {
        // The CONFIGURED process memory budget must reach this guard. A budget
        // that lowers `admission_key_cap` to 3 must cap the limiter at 3 live
        // keys, not the compiled-in default of 4096.
        let budget = chio_kernel::MemoryBudgetConfig {
            admission_key_cap: 3,
            ..chio_kernel::MemoryBudgetConfig::defaults()
        };
        let mut limiter = FederationAdmissionRateLimiter::from_memory_budget(&budget);
        for i in 0..200u64 {
            let subject = format!("subject-{i}");
            let _ = limiter.check_and_record("policy", &subject, &limit(), 100);
        }
        assert!(
            limiter.key_count() <= 3,
            "configured admission_key_cap did not take effect: {} live keys",
            limiter.key_count()
        );
    }

    #[test]
    fn single_subject_reactivation_keeps_one_key() {
        // A single subject that empties its window and re-bursts must stay exactly
        // one key (keyed by `policy:subject`), never leaking a residual entry.
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        let l = limit();
        let _ = limiter.check_and_record("policy", "solo", &l, 100);
        // Idle strictly past the window, then burst again.
        let _ = limiter.check_and_record("policy", "solo", &l, 100 + l.window_seconds + 1);
        assert_eq!(limiter.key_count(), 1);
    }

    #[test]
    fn full_table_of_active_subjects_denies_new_subject_without_eviction() {
        // The cap must never evict an ACTIVE (in-window) subject to admit a new
        // one; the new subject is DENIED fail-closed instead. Two in-window
        // subjects fill a cap of 2, so a third distinct subject is denied and the
        // two actives keep their buckets intact.
        let l = limit();
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(2);
        let a = limiter.check_and_record("policy", "a", &l, 100);
        let b = limiter.check_and_record("policy", "b", &l, 100);
        assert!(a.retry_after_seconds.is_none() && b.retry_after_seconds.is_none());

        // "c" trips the cap while a and b are both in-window: c is denied, and no
        // active bucket is evicted.
        let c = limiter.check_and_record("policy", "c", &l, 100);
        assert_eq!(c.remaining, 0);
        assert!(
            c.retry_after_seconds.is_some(),
            "new subject must be denied when the table is full of active buckets, not admitted by eviction"
        );
        assert_eq!(
            limiter.key_count(),
            2,
            "an active bucket was wrongly evicted"
        );

        // "a" retained its bucket: re-recording it reflects its two in-window
        // attempts (remaining = 5 - 2 = 3), proving it was not reset by eviction.
        let a2 = limiter.check_and_record("policy", "a", &l, 100);
        assert_eq!(a2.remaining, 3, "active subject a was reset by eviction");
    }

    #[test]
    fn cross_policy_prune_preserves_longer_window_active_subject() {
        // When one limiter is shared by policies with different windows, a
        // short-window request must not prune timestamps that are still active
        // for a longer-window policy and thereby reset that subject's limit. A big
        // cap keeps this about the WINDOW, not the key cap.
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(4096);
        let long = FederationAdmissionRateLimit {
            max_requests: 1,
            window_seconds: 3600,
        };
        let short = FederationAdmissionRateLimit {
            max_requests: 5,
            window_seconds: 10,
        };

        // Subject S under the long-window policy spends its single allowed request.
        let first = limiter.check_and_record("policy-long", "S", &long, 100);
        assert_eq!(first.remaining, 0);
        assert!(
            first.retry_after_seconds.is_none(),
            "the first long-window request must be allowed"
        );

        // A later short-window request for a DIFFERENT subject triggers the
        // drop-empty maintenance prune. With the per-request lower bound applied to
        // every bucket, S's timestamp (100) would be deleted (200 - 10 = 190 > 100),
        // resetting the long-window limit. Per-bucket windows keep S (100 is well
        // inside the 3600s window).
        let _ = limiter.check_and_record("policy-short", "T", &short, 200);

        // S reused under the long-window policy IN THE SAME 3600s window must stay
        // rate-limited: the short-window prune must not have reset S.
        let replay = limiter.check_and_record("policy-long", "S", &long, 210);
        assert_eq!(replay.remaining, 0);
        assert!(
            replay.retry_after_seconds.is_some(),
            "long-window subject was reset by a short-window policy's prune (cross-policy bypass)"
        );
    }

    #[test]
    fn active_bucket_not_evicted_by_throwaway_subject_flood() {
        // With max_requests=1 and a small key cap, a subject must not be able to
        // reset its own in-window rate limit by flooding a throwaway subject to
        // force its bucket's eviction, then reusing its own subject in the same
        // window.
        let l = FederationAdmissionRateLimit {
            max_requests: 1,
            window_seconds: 1000,
        };
        let mut limiter = FederationAdmissionRateLimiter::with_key_cap(1);
        let now = 100;

        // The attacker spends its single allowed request for the window.
        let first = limiter.check_and_record("policy", "attacker", &l, now);
        assert_eq!(first.remaining, 0);
        assert!(
            first.retry_after_seconds.is_none(),
            "the first request must be allowed"
        );

        // A throwaway subject tries to evict the attacker's ACTIVE bucket. The
        // table is full of an active bucket, so the throwaway is DENIED (not
        // admitted by evicting the attacker).
        let throwaway = limiter.check_and_record("policy", "throwaway", &l, now);
        assert!(
            throwaway.retry_after_seconds.is_some(),
            "throwaway must be denied, not admitted by evicting the active bucket"
        );
        assert_eq!(
            limiter.key_count(),
            1,
            "the attacker's active bucket must survive the throwaway flood"
        );

        // The attacker reuses its subject in the SAME window: it must stay
        // rate-limited. The throwaway flood must not have evicted the attacker's
        // active bucket and reset its limit.
        let replay = limiter.check_and_record("policy", "attacker", &l, now);
        assert_eq!(replay.remaining, 0);
        assert!(
            replay.retry_after_seconds.is_some(),
            "attacker must stay rate-limited in-window; eviction bypass regressed"
        );
    }
}
