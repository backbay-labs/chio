use super::report_rendering::{
    authority_snapshot_from_view, authority_snapshot_view, budget_cursor_view,
    json_response_with_leader_visibility, json_response_with_leader_visibility_and_budget_commit,
    revocation_cursor_from_view, revocation_cursor_view, stored_child_receipt_views,
    stored_lineage_views, stored_tool_receipt_views,
};
use super::report_validation::{
    normalize_cluster_config_url, normalize_cluster_url, validate_cluster_peer_auth,
};
use super::*;

#[path = "cluster/consensus.rs"]
mod consensus;
#[path = "cluster/deltas.rs"]
mod deltas;
#[path = "cluster/partition.rs"]
mod partition;
#[path = "cluster/pull_budget.rs"]
mod pull_budget;
#[path = "cluster/snapshots.rs"]
mod snapshots;

pub(crate) use consensus::{
    budget_authority_guarantee_level, budget_authority_metadata_view, build_cluster_state,
    cluster_authority_lease_view, cluster_consensus_view, cluster_self_url,
    compute_cluster_consensus_locked, current_budget_event_authority, current_leader_url,
    handle_internal_cluster_status,
};
pub(crate) use deltas::{
    budget_cursor_from_event, budget_mutation_event_view, budget_mutation_record_from_view,
    budget_usage_record_from_view, handle_internal_budgets_delta,
    handle_internal_child_receipts_delta, handle_internal_lineage_delta,
    handle_internal_revocations_delta, handle_internal_tool_receipts_delta, merge_budget_cursor,
    observe_capability_revocation_lag, respond_after_budget_write_quorum_commit,
    respond_after_leader_visible_write, rollback_budget_authorize_exposure, run_cluster_sync_loop,
    wait_for_budget_write_quorum_commit, BudgetWriteToken,
};
pub(crate) use partition::{
    clamp_down_peer_budget_acks, handle_internal_cluster_partition, peer_budget_cursor,
    peer_child_seq, peer_is_partitioned, peer_lineage_seq, peer_revocation_cursor,
    peer_should_force_snapshot, peer_tool_seq, request_peer_snapshot_recovery,
    update_peer_budget_acks, update_peer_budget_cursor, update_peer_child_seq,
    update_peer_delta_records, update_peer_failure, update_peer_lineage_seq, update_peer_reachable,
    update_peer_revocation_cursor, update_peer_state, update_peer_success, update_peer_sync_error,
    update_peer_tool_seq,
};
pub(crate) use pull_budget::{
    ensure_revocation_page_ascending, require_contiguous_page, require_forward_progress,
    PeerProtocolError, PullError, PullRoundBudget, PEER_ROUND_WALL_CLOCK_BUDGET,
};
pub(crate) use snapshots::{
    apply_cluster_snapshot, cluster_replication_heads, handle_internal_authority_snapshot,
    handle_internal_cluster_snapshot,
};

#[cfg(test)]
pub(crate) use consensus::{authority_lease_ttl, cluster_authority_lease_view_locked};

#[cfg(test)]
pub(crate) use deltas::{
    budget_write_progress_closed_outcome, budget_write_quorum_commit_view,
    collect_budget_mutation_event_views_after_seq, finalize_peer_sync_round,
    import_budget_delta_response, notify_cluster_progress, peer_was_demoted, route_pull,
};

// Non-test: peer_was_demoted (in deltas) reads peer health via with_peer_state.
pub(crate) use partition::with_peer_state;

#[cfg(test)]
pub(crate) use snapshots::build_cluster_state_snapshot;
