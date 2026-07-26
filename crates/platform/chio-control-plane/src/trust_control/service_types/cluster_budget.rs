use super::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterStatusResponse {
    pub(crate) self_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_url: Option<String>,
    pub(crate) role: String,
    pub(crate) has_quorum: bool,
    pub(crate) quorum_size: usize,
    pub(crate) reachable_nodes: usize,
    pub(crate) election_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
    pub(crate) replication: ClusterReplicationHeadsView,
    pub(crate) peers: Vec<PeerStatusView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_ack_heads: Vec<BudgetOriginAck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetOriginAck {
    pub(crate) origin_id: String,
    /// Contiguous ack head: the highest event_seq S from origin_id such that
    /// every event in (floor..S] is present (no gap) down to the durable
    /// trusted floor. NOT MAX(event_seq), NOT anchored on MIN(present).
    pub(crate) event_seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PeerStatusView {
    pub(crate) peer_url: String,
    pub(crate) health: String,
    pub(crate) partitioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_contact_at: Option<u64>,
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_cursor: Option<RevocationCursorView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_cursor: Option<BudgetCursorView>,
    pub(crate) snapshot_applied_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_snapshot_at: Option<u64>,
    pub(crate) delta_records_since_snapshot: u64,
    pub(crate) force_snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterReplicationHeadsView {
    pub(crate) tool_seq: u64,
    pub(crate) child_seq: u64,
    pub(crate) lineage_seq: u64,
    pub(crate) budget_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_cursor: Option<RevocationCursorView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterStateSnapshotResponse {
    pub(crate) generated_at: u64,
    #[serde(default)]
    pub(crate) election_term: u64,
    pub(crate) replication: ClusterReplicationHeadsView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<AuthoritySnapshotView>,
    pub(crate) revocations: Vec<RevocationRecordView>,
    pub(crate) tool_receipts: Vec<StoredReceiptView>,
    pub(crate) child_receipts: Vec<StoredReceiptView>,
    pub(crate) lineage: Vec<StoredLineageView>,
    pub(crate) budgets: Vec<BudgetUsageView>,
    /// Immutable pre-history usage projections needed to validate snapshots whose
    /// retained mutation stream starts after an imported usage baseline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_usage_history_anchors: Vec<BudgetUsageView>,
    /// Authenticated, leader-signed inclusion chain for the exact immutable
    /// migration-anchor set. Required before a fresh follower may install wire
    /// anchors that are not already present in its local budget database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_anchor_provenance: Option<BudgetSnapshotAnchorProvenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_mutation_events: Vec<BudgetMutationEventView>,
    /// Abandoned/tombstoned budget event_seqs (rolled-back-then-re-appended
    /// writes' original seqs), range-encoded as inclusive `(start, end)` runs.
    /// Carried so a fresh follower treats these slots as filled and its contiguous
    /// ack head does not stall at the hole. Range-encoded rather than one entry per
    /// seq so a rollback storm - which abandons a long contiguous run - stays a
    /// handful of small pairs instead of millions of integers that would push the
    /// snapshot body past MAX_PEER_RESPONSE_BYTES and permanently break the
    /// force-snapshot recovery path. Additive and default-empty: a mixed-version
    /// peer that omits it simply relies on the delete-trigger path, never on a
    /// wrong value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_abandoned_seq_ranges: Vec<AbandonedSeqRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) budget_origin_ack_heads: Vec<BudgetOriginAck>,
}

/// A contiguous run of abandoned/tombstoned budget event_seqs, inclusive on both
/// ends. The cluster snapshot carries the abandoned set as a list of these runs so
/// a rollback storm collapses to a few small pairs rather than an unbounded integer
/// list that could exceed MAX_PEER_RESPONSE_BYTES. Lossless: a follower expands each
/// run to the identical seq set, preserving the filled-or-abandoned head-advance
/// semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AbandonedSeqRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterPartitionRequest {
    #[serde(default)]
    pub(crate) blocked_peer_urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterPartitionResponse {
    pub(crate) self_url: String,
    pub(crate) blocked_peer_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_url: Option<String>,
    pub(crate) role: String,
    pub(crate) has_quorum: bool,
    pub(crate) reachable_nodes: usize,
    pub(crate) quorum_size: usize,
    pub(crate) election_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority_lease: Option<ClusterAuthorityLeaseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterAuthorityLeaseView {
    pub(crate) authority_id: String,
    pub(crate) leader_url: String,
    pub(crate) term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) term_started_at: Option<u64>,
    pub(crate) lease_expires_at: u64,
    pub(crate) lease_ttl_ms: u64,
    pub(crate) lease_valid: bool,
}

/// Trust-control heartbeat that refreshes a held authority lease before it
/// expires. Wire shape mirrors
/// `spec/schemas/chio-wire/v1/trust-control/heartbeat.schema.json`: the lease
/// is named by (`leaseId`, `leaseEpoch`), the leader claiming continued
/// ownership by `leaderUrl`, and the observation instant by `observedAt`
/// (unix milliseconds). Deserialization is fail-closed: unknown fields are
/// rejected and the non-negative integer fields decode as unsigned so a
/// negative timestamp or epoch cannot be smuggled in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseHeartbeatRequest {
    pub lease_id: String,
    pub lease_epoch: u64,
    pub leader_url: String,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_expires_at: Option<u64>,
}

/// Typed reason carried by a [`LeaseTerminateRequest`]. Mirrors the `reason`
/// enum in `spec/schemas/chio-wire/v1/trust-control/terminate.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseTerminationReason {
    /// Planned reassignment of the lease to a successor leader.
    LeaderHandoff,
    /// Detected loss of cluster quorum.
    QuorumLost,
    /// Explicit operator-initiated stepdown.
    OperatorStepdown,
    /// A higher election term superseded the lease.
    TermAdvanced,
}

/// Trust-control request that voluntarily releases a held authority lease
/// before its TTL expires. Wire shape mirrors
/// `spec/schemas/chio-wire/v1/trust-control/terminate.schema.json`: the lease
/// is named by (`leaseId`, `leaseEpoch`), the releasing leader by `leaderUrl`,
/// and a typed `reason` distinguishes leader handoff from quorum loss or
/// operator stepdown. Deserialization is fail-closed (unknown fields rejected,
/// non-negative integers decode as unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseTerminateRequest {
    pub lease_id: String,
    pub lease_epoch: u64,
    pub leader_url: String,
    pub reason: LeaseTerminationReason,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_leader_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationCursorView {
    pub(crate) revoked_at: i64,
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetCursorView {
    pub(crate) seq: u64,
    pub(crate) updated_at: i64,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetMutationAuthorityView {
    pub(crate) authority_id: String,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetMutationEventView {
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hold_id: Option<String>,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) allowed: Option<bool>,
    #[serde(flatten)]
    pub(crate) lifecycle: BudgetMutationLifecycleView,
    pub(crate) recorded_at: i64,
    pub(crate) event_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage_seq: Option<u64>,
    pub(crate) exposure_units: u64,
    pub(crate) realized_spend_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_invocations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_cost_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) invocation_count_after: u32,
    pub(crate) total_cost_exposed_after: u64,
    pub(crate) total_cost_realized_spend_after: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<BudgetMutationAuthorityView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthoritySnapshotView {
    pub(crate) public_key_hex: String,
    pub(crate) generation: u64,
    pub(crate) rotated_at: u64,
    pub(crate) trusted_keys: Vec<AuthorityTrustedKeyView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorityTrustedKeyView {
    pub(crate) public_key_hex: String,
    pub(crate) generation: u64,
    pub(crate) activated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationDeltaQuery {
    #[serde(default)]
    pub(crate) after_revoked_at: Option<i64>,
    #[serde(default)]
    pub(crate) after_capability_id: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevocationDeltaResponse {
    pub(crate) records: Vec<RevocationRecordView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptDeltaQuery {
    #[serde(default)]
    pub(crate) after_seq: Option<u64>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredReceiptView {
    pub(crate) seq: u64,
    pub(crate) receipt: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReceiptDeltaResponse {
    pub(crate) records: Vec<StoredReceiptView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredLineageView {
    pub(crate) seq: u64,
    pub(crate) snapshot: CapabilitySnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LineageDeltaResponse {
    pub(crate) records: Vec<StoredLineageView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetDeltaQuery {
    #[serde(default)]
    pub(crate) after_seq: Option<u64>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetDeltaResponse {
    pub(crate) records: Vec<BudgetUsageView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mutation_events: Vec<BudgetMutationEventView>,
    /// Abandoned/tombstoned event_seqs above the cursor, so the puller can treat
    /// those slots as filled when verifying the pulled page is gap-free and does
    /// not demote a leader whose stream legitimately skips a rolled-back seq.
    /// Additive and default-empty for mixed-version peers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) abandoned_seqs: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetWriteCommitView {
    pub(crate) budget_seq: u64,
    pub(crate) commit_index: u64,
    pub(crate) quorum_committed: bool,
    pub(crate) quorum_size: usize,
    pub(crate) committed_nodes: usize,
    pub(crate) witness_urls: Vec<String>,
    pub(crate) authority_id: String,
    pub(crate) budget_term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetAuthorityMetadataView {
    pub(crate) authority_id: String,
    pub(crate) leader_url: String,
    pub(crate) budget_term: u64,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
    pub(crate) lease_expires_at: u64,
    pub(crate) lease_ttl_ms: u64,
    pub(crate) guarantee_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit_index: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TryIncrementBudgetRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) max_invocations: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TryIncrementBudgetResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
}

#[derive(Debug)]
pub(crate) struct TryChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) max_invocations: Option<u32>,
    pub(crate) cost_units: u64,
    pub(crate) max_cost_per_invocation: Option<u64>,
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct TryChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) allowed: bool,
    pub(crate) decision: BudgetAuthorizeExposureDecision,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
    pub(crate) exposure_units: Option<u64>,
    pub(crate) realized_spend_units: Option<u64>,
    pub(crate) mutation_invocation_count_after: Option<u32>,
    pub(crate) mutation_committed_cost_units_after: Option<u64>,
    pub(crate) usage_seq: Option<u64>,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetAuthorizeExposureDecision {
    Authorized,
    Denied,
    AlreadyCaptured,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureInvocationRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureInvocationDecision {
    Captured,
    AlreadyCaptured,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureInvocationResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) decision: CaptureInvocationDecision,
    pub(crate) exposure_units: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) usage_invocation_count: u32,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) total_cost_exposed_after: u64,
    pub(crate) total_cost_realized_spend_after: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) structured_projection: Option<StructuredBudgetMutationResponse>,
}

#[derive(Debug)]
pub(crate) struct ReverseChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) cost_units: u64,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ReverseChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) usage_seq: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
    pub(crate) structured_projection: Option<StructuredBudgetMutationResponse>,
}

#[derive(Debug)]
pub(crate) struct ReduceChargeCostRequest {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) cost_units: u64,
    pub(crate) exposure_units: Option<u64>,
    pub(crate) realized_spend_units: Option<u64>,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ReduceChargeCostResponse {
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: Option<String>,
    pub(crate) event_id: Option<String>,
    pub(crate) invocation_count: Option<u32>,
    pub(crate) total_cost_exposed: Option<u64>,
    pub(crate) total_cost_realized_spend: Option<u64>,
    pub(crate) released_exposure_units: Option<u64>,
    pub(crate) usage_seq: Option<u64>,
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
    pub(crate) structured_projection: Option<StructuredBudgetMutationResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_invocations: Option<u32>,
    exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_exposure_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_total_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    max_invocations: Option<u32>,
    #[serde(default)]
    exposure_units: Option<u64>,
    #[serde(default)]
    max_exposure_per_invocation: Option<u64>,
    #[serde(default)]
    max_total_exposure_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl Serialize for TryChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TryChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            max_invocations: self.max_invocations,
            exposure_units: self.cost_units,
            max_exposure_per_invocation: self.max_cost_per_invocation,
            max_total_exposure_units: self.max_total_cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TryChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TryChargeCostRequestWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            max_invocations: wire.max_invocations,
            cost_units: super::responses::require_budget_amount(
                wire.exposure_units,
                "`exposureUnits`",
            )?,
            max_cost_per_invocation: wire.max_exposure_per_invocation,
            max_total_cost_units: wire.max_total_exposure_units,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    allowed: bool,
    decision: BudgetAuthorizeExposureDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    realized_spend_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation_invocation_count_after: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation_committed_cost_units_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    usage_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    allowed: bool,
    #[serde(default)]
    decision: Option<BudgetAuthorizeExposureDecision>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    exposure_units: Option<u64>,
    #[serde(default)]
    realized_spend_units: Option<u64>,
    #[serde(default)]
    mutation_invocation_count_after: Option<u32>,
    #[serde(default)]
    mutation_committed_cost_units_after: Option<u64>,
    #[serde(default)]
    usage_seq: Option<u64>,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
}

impl Serialize for TryChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        TryChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            allowed: self.allowed,
            decision: self.decision,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
            exposure_units: self.exposure_units,
            realized_spend_units: self.realized_spend_units,
            mutation_invocation_count_after: self.mutation_invocation_count_after,
            mutation_committed_cost_units_after: self.mutation_committed_cost_units_after,
            usage_seq: self.usage_seq,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TryChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TryChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            allowed: wire.allowed,
            decision: wire.decision.unwrap_or(if wire.allowed {
                BudgetAuthorizeExposureDecision::Authorized
            } else {
                BudgetAuthorizeExposureDecision::Denied
            }),
            hold_id: wire.hold_id,
            event_id: wire.event_id,
            exposure_units: wire.exposure_units,
            realized_spend_units: wire.realized_spend_units,
            mutation_invocation_count_after: wire.mutation_invocation_count_after,
            mutation_committed_cost_units_after: wire.mutation_committed_cost_units_after,
            usage_seq: wire.usage_seq,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    exposure_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl Serialize for ReverseChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReverseChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            exposure_units: self.cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReverseChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReverseChargeCostRequestWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            cost_units: super::responses::require_budget_amount(
                wire.exposure_units,
                "`exposureUnits`",
            )?,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    usage_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    structured_projection: Option<&'a StructuredBudgetMutationResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    usage_seq: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
    #[serde(default)]
    structured_projection: Option<StructuredBudgetMutationResponse>,
}

impl Serialize for ReverseChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReverseChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            usage_seq: self.usage_seq,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
            structured_projection: self.structured_projection.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReverseChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReverseChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            usage_seq: wire.usage_seq,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
            structured_projection: wire.structured_projection,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostRequestWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    realized_spend_units: Option<u64>,
    reduction_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostRequestWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    authorized_exposure_units: Option<u64>,
    #[serde(default)]
    realized_spend_units: Option<u64>,
    #[serde(default)]
    reduction_units: Option<u64>,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
}

impl ReduceChargeCostRequest {
    pub(crate) fn release_units(&self) -> u64 {
        self.cost_units
    }
}

impl Serialize for ReduceChargeCostRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReduceChargeCostRequestWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            authorized_exposure_units: self.exposure_units,
            realized_spend_units: self.realized_spend_units,
            reduction_units: self.cost_units,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReduceChargeCostRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReduceChargeCostRequestWireInput::deserialize(deserializer)?;
        let exposure_units = wire.authorized_exposure_units;
        let cost_units = match wire.reduction_units {
            Some(cost_units) => cost_units,
            None => {
                let authorized_exposure_units = exposure_units.ok_or_else(|| {
                    serde::de::Error::missing_field(
                        "one of `reductionUnits` or `authorizedExposureUnits`",
                    )
                })?;
                let realized_spend_units = wire
                    .realized_spend_units
                    .ok_or_else(|| serde::de::Error::missing_field("`realizedSpendUnits`"))?;
                authorized_exposure_units
                    .checked_sub(realized_spend_units)
                    .ok_or_else(|| {
                        serde::de::Error::custom(
                            "`realizedSpendUnits` cannot exceed `authorizedExposureUnits`",
                        )
                    })?
            }
        };
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            cost_units,
            exposure_units,
            realized_spend_units: wire.realized_spend_units,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostResponseWire<'a> {
    capability_id: &'a str,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hold_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    released_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_exposure_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    usage_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_authority: Option<&'a BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_commit: Option<&'a BudgetWriteCommitView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    structured_projection: Option<&'a StructuredBudgetMutationResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostResponseWireInput {
    capability_id: String,
    grant_index: usize,
    #[serde(default)]
    hold_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    invocation_count: Option<u32>,
    #[serde(default)]
    released_exposure_units: Option<u64>,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    #[serde(default)]
    usage_seq: Option<u64>,
    #[serde(default)]
    budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default)]
    budget_commit: Option<BudgetWriteCommitView>,
    #[serde(default)]
    structured_projection: Option<StructuredBudgetMutationResponse>,
}

impl Serialize for ReduceChargeCostResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReduceChargeCostResponseWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            hold_id: self.hold_id.as_deref(),
            event_id: self.event_id.as_deref(),
            invocation_count: self.invocation_count,
            released_exposure_units: self.released_exposure_units,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: self.total_cost_realized_spend,
            usage_seq: self.usage_seq,
            budget_authority: self.budget_authority.as_ref(),
            budget_commit: self.budget_commit.as_ref(),
            structured_projection: self.structured_projection.as_ref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReduceChargeCostResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReduceChargeCostResponseWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            hold_id: wire.hold_id,
            event_id: wire.event_id,
            invocation_count: wire.invocation_count,
            total_cost_exposed: wire.total_exposure_charged,
            total_cost_realized_spend: wire.total_realized_spend,
            released_exposure_units: wire.released_exposure_units,
            usage_seq: wire.usage_seq,
            budget_authority: wire.budget_authority,
            budget_commit: wire.budget_commit,
            structured_projection: wire.structured_projection,
        })
    }
}

#[cfg(test)]
mod cluster_lease_rpc_tests {
    use chio_test_support::prelude::*;

    use super::{LeaseHeartbeatRequest, LeaseTerminateRequest, LeaseTerminationReason};

    #[test]
    fn lease_heartbeat_request_round_trips_camel_case() {
        let request = LeaseHeartbeatRequest {
            lease_id: "lease-7".to_string(),
            lease_epoch: 3,
            leader_url: "https://node-a.example/v1".to_string(),
            observed_at: 1_700_000_000_000,
            proposed_expires_at: Some(1_700_000_030_000),
        };
        let value = serde_json::to_value(&request).test_unwrap();
        assert_eq!(value["leaseId"], "lease-7");
        assert_eq!(value["leaseEpoch"], 3);
        assert_eq!(value["leaderUrl"], "https://node-a.example/v1");
        assert_eq!(value["observedAt"], 1_700_000_000_000u64);
        assert_eq!(value["proposedExpiresAt"], 1_700_000_030_000u64);

        let decoded: LeaseHeartbeatRequest = serde_json::from_value(value).test_unwrap();
        assert_eq!(decoded.lease_id, request.lease_id);
        assert_eq!(decoded.lease_epoch, request.lease_epoch);
        assert_eq!(decoded.proposed_expires_at, request.proposed_expires_at);
    }

    #[test]
    fn lease_heartbeat_request_optional_expiry_is_omitted_when_absent() {
        let json =
            r#"{"leaseId":"lease-1","leaseEpoch":0,"leaderUrl":"https://n/1","observedAt":1}"#;
        let decoded: LeaseHeartbeatRequest = serde_json::from_str(json).test_unwrap();
        assert!(decoded.proposed_expires_at.is_none());
        let reserialized = serde_json::to_value(&decoded).test_unwrap();
        assert!(reserialized.get("proposedExpiresAt").is_none());
    }

    #[test]
    fn lease_heartbeat_request_rejects_unknown_field() {
        let json = r#"{"leaseId":"lease-1","leaseEpoch":0,"leaderUrl":"https://n/1","observedAt":1,"rogue":true}"#;
        assert!(serde_json::from_str::<LeaseHeartbeatRequest>(json).is_err());
    }

    #[test]
    fn lease_heartbeat_request_rejects_negative_epoch() {
        let json =
            r#"{"leaseId":"lease-1","leaseEpoch":-1,"leaderUrl":"https://n/1","observedAt":1}"#;
        assert!(serde_json::from_str::<LeaseHeartbeatRequest>(json).is_err());
    }

    #[test]
    fn lease_terminate_request_round_trips_with_typed_reason() {
        let request = LeaseTerminateRequest {
            lease_id: "lease-9".to_string(),
            lease_epoch: 5,
            leader_url: "https://node-b.example/v1".to_string(),
            reason: LeaseTerminationReason::LeaderHandoff,
            observed_at: 1_700_000_100_000,
            successor_leader_url: Some("https://node-c.example/v1".to_string()),
        };
        let value = serde_json::to_value(&request).test_unwrap();
        assert_eq!(value["reason"], "leader_handoff");
        assert_eq!(value["successorLeaderUrl"], "https://node-c.example/v1");

        let decoded: LeaseTerminateRequest = serde_json::from_value(value).test_unwrap();
        assert_eq!(decoded.reason, LeaseTerminationReason::LeaderHandoff);
        assert_eq!(decoded.successor_leader_url, request.successor_leader_url);
    }

    #[test]
    fn lease_termination_reason_variants_use_snake_case() {
        for (reason, wire) in [
            (LeaseTerminationReason::LeaderHandoff, "leader_handoff"),
            (LeaseTerminationReason::QuorumLost, "quorum_lost"),
            (
                LeaseTerminationReason::OperatorStepdown,
                "operator_stepdown",
            ),
            (LeaseTerminationReason::TermAdvanced, "term_advanced"),
        ] {
            assert_eq!(serde_json::to_value(reason).test_unwrap(), wire);
            let decoded: LeaseTerminationReason =
                serde_json::from_value(serde_json::json!(wire)).test_unwrap();
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn lease_terminate_request_rejects_unknown_reason() {
        let json = r#"{"leaseId":"l","leaseEpoch":0,"leaderUrl":"https://n/1","reason":"mutiny","observedAt":1}"#;
        assert!(serde_json::from_str::<LeaseTerminateRequest>(json).is_err());
    }

    #[test]
    fn lease_terminate_request_rejects_unknown_field() {
        let json = r#"{"leaseId":"l","leaseEpoch":0,"leaderUrl":"https://n/1","reason":"quorum_lost","observedAt":1,"rogue":1}"#;
        assert!(serde_json::from_str::<LeaseTerminateRequest>(json).is_err());
    }
}
