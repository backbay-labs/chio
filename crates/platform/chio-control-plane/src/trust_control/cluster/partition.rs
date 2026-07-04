use super::*;

pub(crate) async fn handle_internal_cluster_partition(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ClusterPartitionRequest>,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CLUSTER_PARTITION_PATH)
    {
        return response;
    }
    let Some(cluster) = state.cluster.as_ref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    };

    let blocked_peer_urls = match payload
        .blocked_peer_urls
        .iter()
        .map(|peer_url| normalize_cluster_url(peer_url))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(urls) => urls,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };

    let consensus = match cluster.lock() {
        Ok(mut guard) => {
            let self_url = guard.self_url.clone();
            let blocked = blocked_peer_urls
                .iter()
                .filter(|peer_url| **peer_url != self_url)
                .cloned()
                .collect::<HashSet<_>>();
            for (peer_url, peer_state) in &mut guard.peers {
                let was_partitioned = peer_state.partitioned;
                peer_state.partitioned = blocked.contains(peer_url);
                if peer_state.partitioned {
                    peer_state.last_error =
                        Some("cluster peer intentionally partitioned".to_string());
                    peer_state.force_snapshot = true;
                } else if was_partitioned {
                    peer_state.health = PeerHealth::Unknown;
                    peer_state.last_error = None;
                    peer_state.force_snapshot = true;
                    peer_state.delta_records_since_snapshot = 0;
                }
            }
            compute_cluster_consensus_locked(&mut guard)
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let self_url = guard.self_url.clone();
            let blocked = blocked_peer_urls
                .iter()
                .filter(|peer_url| **peer_url != self_url)
                .cloned()
                .collect::<HashSet<_>>();
            for (peer_url, peer_state) in &mut guard.peers {
                let was_partitioned = peer_state.partitioned;
                peer_state.partitioned = blocked.contains(peer_url);
                if peer_state.partitioned {
                    peer_state.last_error =
                        Some("cluster peer intentionally partitioned".to_string());
                    peer_state.force_snapshot = true;
                } else if was_partitioned {
                    peer_state.health = PeerHealth::Unknown;
                    peer_state.last_error = None;
                    peer_state.force_snapshot = true;
                    peer_state.delta_records_since_snapshot = 0;
                }
            }
            compute_cluster_consensus_locked(&mut guard)
        }
    };

    Json(ClusterPartitionResponse {
        self_url: consensus.self_url,
        blocked_peer_urls,
        leader_url: consensus.leader_url,
        role: consensus.role.to_string(),
        has_quorum: consensus.has_quorum,
        reachable_nodes: consensus.reachable_nodes,
        quorum_size: consensus.quorum_size,
        election_term: consensus.election_term,
        authority_lease: cluster_authority_lease_view(&state),
    })
    .into_response()
}

pub(crate) fn update_peer_success(state: &TrustServiceState, peer_url: &str) {
    if let Some(cluster) = state.cluster.as_ref() {
        let now = unix_timestamp_now();
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Healthy;
                    peer.last_contact_at = Some(now);
                    if !peer.partitioned {
                        peer.last_error = None;
                    }
                    peer.force_snapshot = false;
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Healthy;
                    peer.last_contact_at = Some(now);
                    if !peer.partitioned {
                        peer.last_error = None;
                    }
                    peer.force_snapshot = false;
                }
            }
        }
    }
}

pub(crate) fn update_peer_reachable(state: &TrustServiceState, peer_url: &str) {
    let now = unix_timestamp_now();
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
        peer.last_contact_at = Some(now);
    });
}

pub(crate) fn update_peer_failure(state: &TrustServiceState, peer_url: &str, error: String) {
    if let Some(cluster) = state.cluster.as_ref() {
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Unhealthy;
                    peer.last_error = Some(error.clone());
                    peer.force_snapshot = true;
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Unhealthy;
                    peer.last_error = Some(error);
                    peer.force_snapshot = true;
                }
            }
        }
    }
}

pub(crate) fn update_peer_sync_error(state: &TrustServiceState, peer_url: &str, error: String) {
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
        peer.last_error = Some(error);
    });
}

pub(crate) fn peer_revocation_cursor(
    state: &TrustServiceState,
    peer_url: &str,
) -> Option<RevocationCursor> {
    with_peer_state(state, peer_url, |peer| peer.revocation_cursor.clone()).flatten()
}

pub(crate) fn peer_budget_cursor(
    state: &TrustServiceState,
    peer_url: &str,
) -> Option<BudgetCursor> {
    with_peer_state(state, peer_url, |peer| peer.budget_cursor.clone()).flatten()
}

pub(crate) fn peer_tool_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.tool_seq).unwrap_or(0)
}

pub(crate) fn peer_child_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.child_seq).unwrap_or(0)
}

pub(crate) fn peer_lineage_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.lineage_seq).unwrap_or(0)
}

pub(crate) fn update_peer_revocation_cursor(
    state: &TrustServiceState,
    peer_url: &str,
    cursor: RevocationCursor,
) {
    update_peer_state(state, peer_url, |peer| {
        peer.revocation_cursor = Some(cursor)
    });
}

pub(crate) fn update_peer_budget_cursor(
    state: &TrustServiceState,
    peer_url: &str,
    cursor: BudgetCursor,
) {
    update_peer_state(state, peer_url, |peer| peer.budget_cursor = Some(cursor));
}

pub(crate) fn update_peer_tool_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.tool_seq = seq);
}

pub(crate) fn update_peer_child_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.child_seq = seq);
}

pub(crate) fn update_peer_lineage_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.lineage_seq = seq);
}

pub(crate) fn update_peer_delta_records(state: &TrustServiceState, peer_url: &str, count: u64) {
    if count == 0 {
        return;
    }
    update_peer_state(state, peer_url, |peer| {
        peer.delta_records_since_snapshot = peer.delta_records_since_snapshot.saturating_add(count);
        if peer.delta_records_since_snapshot >= CLUSTER_SNAPSHOT_RECORD_THRESHOLD {
            peer.force_snapshot = true;
        }
    });
}

pub(crate) fn peer_is_partitioned(state: &TrustServiceState, peer_url: &str) -> bool {
    with_peer_state(state, peer_url, |peer| peer.partitioned).unwrap_or(false)
}

pub(crate) fn peer_should_force_snapshot(state: &TrustServiceState, peer_url: &str) -> bool {
    with_peer_state(state, peer_url, |peer| {
        peer.force_snapshot
            || peer.delta_records_since_snapshot >= CLUSTER_SNAPSHOT_RECORD_THRESHOLD
    })
    .unwrap_or(false)
}

pub(crate) fn with_peer_state<T, F>(state: &TrustServiceState, peer_url: &str, map: F) -> Option<T>
where
    F: FnOnce(&PeerSyncState) -> T,
{
    let cluster = state.cluster.as_ref()?;
    match cluster.lock() {
        Ok(guard) => guard.peers.get(peer_url).map(map),
        Err(poisoned) => poisoned.into_inner().peers.get(peer_url).map(map),
    }
}

pub(crate) fn update_peer_state<F>(state: &TrustServiceState, peer_url: &str, update: F)
where
    F: FnOnce(&mut PeerSyncState),
{
    if let Some(cluster) = state.cluster.as_ref() {
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    update(peer);
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    update(peer);
                }
            }
        }
    }
}
