use super::*;

#[derive(Clone)]
pub(crate) struct TrustServiceState {
    pub(crate) config: TrustServiceConfig,
    pub(crate) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(crate) verifier_policy_registry: Option<Arc<VerifierPolicyRegistry>>,
    pub(crate) federation_admission_rate_limiter: Arc<Mutex<FederationAdmissionRateLimiter>>,
    pub(crate) cluster: Option<Arc<Mutex<ClusterRuntimeState>>>,
    /// Progress signal for the single background cluster-sync loop. `Some`
    /// exactly when `cluster` is `Some`. A budget-write handler parks on this
    /// watch instead of driving its own inline sync.
    pub(crate) cluster_progress: Option<Arc<ClusterProgress>>,
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
}

pub(crate) struct AuthorityKeyCache {
    pub(crate) current: Option<PublicKey>,
    pub(crate) trusted: Vec<PublicKey>,
    pub(crate) refreshed_at: Instant,
}

pub(crate) struct RemoteRevocationStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteReceiptStore {
    pub(crate) client: TrustControlClient,
}

pub(crate) struct RemoteBudgetStore {
    pub(crate) client: TrustControlClient,
    pub(crate) cached_usage: Mutex<HashMap<(String, u32), BudgetUsageRecord>>,
}

impl TrustServiceState {
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

#[derive(Debug, Default)]
pub(crate) struct FederationAdmissionRateLimiter {
    attempts: HashMap<String, Vec<u64>>,
}

impl FederationAdmissionRateLimiter {
    pub(crate) fn check_and_record(
        &mut self,
        policy_id: &str,
        subject_key: &str,
        limit: &FederationAdmissionRateLimit,
        now: u64,
    ) -> FederationAdmissionRateLimitStatus {
        let key = format!("{policy_id}:{subject_key}");
        let lower_bound = now.saturating_sub(limit.window_seconds);
        let entry = self.attempts.entry(key).or_default();
        entry.retain(|timestamp| *timestamp > lower_bound);
        if entry.len() >= limit.max_requests as usize {
            let retry_after_seconds = entry
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
        entry.push(now);
        FederationAdmissionRateLimitStatus {
            limit: limit.max_requests,
            window_seconds: limit.window_seconds,
            remaining: limit.max_requests.saturating_sub(entry.len() as u32),
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
