use super::*;

pub(crate) async fn handle_internal_cluster_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CLUSTER_SNAPSHOT_PATH)
    {
        return response;
    }
    if state.cluster.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    }
    match build_cluster_state_snapshot(&state) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_internal_authority_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_AUTHORITY_SNAPSHOT_PATH)
    {
        return response;
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = match SqliteCapabilityAuthority::open(path) {
            Ok(authority) => authority,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        let snapshot = match authority.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        return Json(authority_snapshot_view(snapshot)).into_response();
    }

    plain_http_error(
        StatusCode::CONFLICT,
        "clustered authority replication requires --authority-db",
    )
}

pub(crate) fn cluster_replication_heads(
    state: &TrustServiceState,
) -> Result<ClusterReplicationHeadsView, CliError> {
    let (tool_seq, child_seq, lineage_seq) =
        if let Some(path) = state.config.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)?;
            (
                store.max_tool_receipt_seq()?,
                store.max_child_receipt_seq()?,
                store.max_lineage_seq()?,
            )
        } else {
            (0, 0, 0)
        };
    let budget_seq = match state
        .optional_budget_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        Some(store) => store.budget_snapshot_covered_head()?,
        None => 0,
    };
    let revocation_cursor = match state
        .optional_revocation_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        Some(store) => store.latest_revocation_cursor()?,
        None => None,
    };
    Ok(ClusterReplicationHeadsView {
        tool_seq,
        child_seq,
        lineage_seq,
        budget_seq,
        revocation_cursor: revocation_cursor.map(|(revoked_at, capability_id)| {
            RevocationCursorView {
                revoked_at,
                capability_id,
            }
        }),
    })
}

pub(crate) fn build_cluster_state_snapshot(
    state: &TrustServiceState,
) -> Result<ClusterStateSnapshotResponse, CliError> {
    let generated_at = unix_timestamp_now();
    let consensus = cluster_consensus_view(state);
    let authority_lease = cluster_authority_lease_view(state);
    let authority = if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open(path)?;
        Some(authority_snapshot_view(authority.snapshot()?))
    } else {
        None
    };

    let revocations = if let Some(store) = state
        .optional_revocation_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        collect_revocation_views(&store)?
    } else {
        Vec::new()
    };

    let (tool_receipts, child_receipts, lineage) =
        if let Some(path) = state.config.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)?;
            let read_context = ReceiptReadContext::admin_service();
            (
                collect_tool_receipt_views(&store, &read_context)?,
                collect_child_receipt_views(&store, &read_context)?,
                collect_lineage_views(&store)?,
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

    let (
        budgets,
        budget_usage_history_anchors,
        budget_anchor_provenance,
        budget_mutation_events,
        budget_abandoned_seq_ranges,
        budget_covered_head,
        budget_origin_ack_heads,
    ) = if let Some(store) = state
        .optional_budget_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        let snapshot = store.export_budget_snapshot()?;
        let budget_anchor_provenance = if snapshot.usage_history_anchors.is_empty() {
            None
        } else {
            let self_url = cluster_self_url(state);
            let leader_url = current_leader_url(state);
            if self_url.is_some() && self_url == leader_url {
                let leader_url = leader_url.ok_or_else(|| {
                    CliError::cli_other_error(
                        "budget snapshot anchor provenance requires an elected leader".to_string(),
                    )
                })?;
                let authority_path =
                    state.config.authority_db_path.as_deref().ok_or_else(|| {
                        CliError::cli_other_error(
                            "budget snapshot anchor provenance requires --authority-db".to_string(),
                        )
                    })?;
                let anchor_set_digest =
                    budget_snapshot_anchor_set_digest(&snapshot.usage_history_anchors)?;
                let authority = SqliteCapabilityAuthority::open(authority_path)?;
                let chain = authority.commit_budget_snapshot_anchor_set(
                    &anchor_set_digest,
                    &leader_url,
                    consensus
                        .as_ref()
                        .map(|view| view.election_term)
                        .unwrap_or(0),
                    generated_at,
                )?;
                let cluster_authenticator =
                    budget_snapshot_anchor_authenticator(&state.config.service_token, &chain)?;
                Some(BudgetSnapshotAnchorProvenance {
                    schema: "chio.budget-snapshot-anchor-provenance.v1".to_string(),
                    chain,
                    cluster_authenticator,
                })
            } else {
                None
            }
        };
        (
            snapshot.usages.into_iter().map(budget_usage_view).collect(),
            snapshot
                .usage_history_anchors
                .into_iter()
                .map(budget_usage_view)
                .collect(),
            budget_anchor_provenance,
            snapshot
                .mutation_events
                .into_iter()
                .map(budget_mutation_event_view)
                .collect::<Result<Vec<_>, CliError>>()?,
            snapshot
                .abandoned_seq_ranges
                .into_iter()
                .map(|(start, end)| AbandonedSeqRange { start, end })
                .collect(),
            snapshot.covered_head,
            snapshot
                .origin_ack_heads
                .into_iter()
                .map(|(origin_id, event_seq)| BudgetOriginAck {
                    origin_id,
                    event_seq,
                })
                .collect(),
        )
    } else {
        (
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            0,
            Vec::new(),
        )
    };
    // Range-encode the abandoned seqs (inclusive (start, end) runs) so a rollback
    // storm's long contiguous abandoned window stays a few small pairs rather than an
    // unbounded integer list that would push the snapshot body past
    // MAX_PEER_RESPONSE_BYTES and permanently break force-snapshot recovery. Computed
    // in SQL, so the full seq set is never materialized here either.
    let replication = ClusterReplicationHeadsView {
        tool_seq: tool_receipts.last().map(|record| record.seq).unwrap_or(0),
        child_seq: child_receipts.last().map(|record| record.seq).unwrap_or(0),
        lineage_seq: lineage.last().map(|record| record.seq).unwrap_or(0),
        budget_seq: budget_covered_head,
        revocation_cursor: revocations.last().map(|record| RevocationCursorView {
            revoked_at: record.revoked_at,
            capability_id: record.capability_id.clone(),
        }),
    };

    Ok(ClusterStateSnapshotResponse {
        generated_at,
        election_term: consensus
            .as_ref()
            .map(|view| view.election_term)
            .unwrap_or(0),
        replication,
        authority_lease,
        authority,
        revocations,
        tool_receipts,
        child_receipts,
        lineage,
        budgets,
        budget_usage_history_anchors,
        budget_anchor_provenance,
        budget_mutation_events,
        budget_abandoned_seq_ranges,
        budget_origin_ack_heads,
    })
}

pub(crate) fn apply_cluster_snapshot(
    state: &TrustServiceState,
    peer_url: &str,
    snapshot: ClusterStateSnapshotResponse,
) -> Result<(), CliError> {
    let ClusterStateSnapshotResponse {
        generated_at,
        election_term,
        replication,
        authority_lease,
        authority,
        revocations,
        tool_receipts,
        child_receipts,
        lineage,
        budgets,
        budget_usage_history_anchors,
        budget_anchor_provenance,
        budget_mutation_events,
        budget_abandoned_seq_ranges,
        budget_origin_ack_heads,
    } = snapshot;

    if let (Some(path), Some(authority_view)) =
        (state.config.authority_db_path.as_deref(), authority)
    {
        let authority = SqliteCapabilityAuthority::open(path)?;
        authority.apply_snapshot(&authority_snapshot_from_view(authority_view))?;
    }

    if let Some(store) = state
        .optional_revocation_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        for record in &revocations {
            store.upsert_revocation(&RevocationRecord {
                capability_id: record.capability_id.clone(),
                revoked_at: record.revoked_at,
            })?;
        }
    }

    if let Some(path) = state.config.receipt_db_path.as_deref() {
        let mut store = SqliteReceiptStore::open(path)?;
        for record in &tool_receipts {
            let receipt: ChioReceipt = serde_json::from_value(record.receipt.clone())?;
            store.append_chio_receipt(&receipt)?;
        }
        for record in &child_receipts {
            let receipt: ChildRequestReceipt = serde_json::from_value(record.receipt.clone())?;
            store.append_child_receipt(&receipt)?;
        }
        for record in &lineage {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        }
    }

    let mut budget_cursor = None;
    if let Some(store) = state
        .optional_budget_store()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        let usage_records = budgets
            .iter()
            .map(budget_usage_record_from_view)
            .collect::<Vec<_>>();
        let usage_history_anchors = budget_usage_history_anchors
            .iter()
            .map(budget_usage_record_from_view)
            .collect::<Vec<_>>();
        let mutation_records = budget_mutation_events
            .iter()
            .map(budget_mutation_record_from_view)
            .collect::<Result<Vec<_>, _>>()?;
        let abandoned_ranges = budget_abandoned_seq_ranges
            .iter()
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>();
        let budget_snapshot = BudgetStoreSnapshot {
            usages: usage_records,
            usage_history_anchors,
            mutation_events: mutation_records,
            abandoned_seq_ranges: abandoned_ranges,
            covered_head: replication.budget_seq,
            origin_ack_heads: budget_origin_ack_heads
                .iter()
                .map(|head| (head.origin_id.clone(), head.event_seq))
                .collect(),
        };
        if let Some(provenance) = budget_anchor_provenance.as_ref() {
            let elected_leader = current_leader_url(state).ok_or_else(|| {
                CliError::cli_other_error(
                    "budget snapshot anchor provenance arrived without an elected leader"
                        .to_string(),
                )
            })?;
            let local_term = cluster_consensus_view(state)
                .map(|view| view.election_term)
                .unwrap_or(0);
            if peer_url != elected_leader {
                return Err(CliError::cli_other_error(format!(
                    "budget snapshot anchor provenance came from `{peer_url}`, not elected leader `{elected_leader}`"
                )));
            }
            store
                .import_budget_snapshot_with_anchor_provenance(
                    &budget_snapshot,
                    provenance,
                    &elected_leader,
                    local_term,
                    &state.config.service_token,
                )
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        } else {
            store
                .import_budget_snapshot(&budget_snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        }
        for event in &budget_mutation_events {
            budget_cursor = Some(merge_budget_cursor(
                budget_cursor,
                budget_cursor_from_event(event),
            ));
        }
        budget_cursor = snapshot_budget_cursor(
            budget_cursor,
            replication.budget_seq,
            &budget_usage_history_anchors,
            &budgets,
        );
    }

    seed_cluster_authority_from_snapshot(state, election_term, authority_lease.as_ref())?;

    update_peer_state(state, peer_url, |peer| {
        peer.tool_seq = replication.tool_seq;
        peer.child_seq = replication.child_seq;
        peer.lineage_seq = replication.lineage_seq;
        peer.revocation_cursor = replication
            .revocation_cursor
            .clone()
            .map(revocation_cursor_from_view);
        peer.budget_cursor = budget_cursor.clone();
        peer.snapshot_applied_count = peer.snapshot_applied_count.saturating_add(1);
        peer.last_snapshot_at = Some(generated_at);
        peer.delta_records_since_snapshot = 0;
        // Clear the peer's cached witness acks ATOMICALLY with clearing
        // `force_snapshot`. `force_snapshot` was the ONLY thing excluding this peer's stale
        // ack head from the witness set (`budget_write_quorum_commit_view`), and this
        // is the single site that clears it WITHOUT going through
        // `finalize_peer_sync_round` (which re-records a validated ack via
        // `update_peer_budget_acks`). If we cleared `force_snapshot` here but left the
        // old (stale-high) ack map in place, ANY early return after this point (an
        // authority-sync error, a puller error, a transient failure) would skip
        // finalize and leave a Healthy, not-force_snapshot peer WITNESSING at an ack
        // head that this round never validated - an OVER-COUNT / budget double-spend.
        // Snapshot recovery is precisely our admission that our incremental view of
        // this peer was broken, so the peer must start witnessing NOTHING until a
        // completed pull round's finalize re-records a validated ack. Fail-closed and
        // strictly under-count-safe: this can only SHRINK the witness set.
        peer.budget_import_acks.clear();
        peer.force_snapshot = false;
    });

    Ok(())
}

fn seed_cluster_authority_from_snapshot(
    state: &TrustServiceState,
    snapshot_election_term: u64,
    authority_lease: Option<&ClusterAuthorityLeaseView>,
) -> Result<(), CliError> {
    let Some(cluster) = state.cluster.as_ref() else {
        return Ok(());
    };

    let snapshot_term = authority_lease
        .map(|lease| lease.term)
        .unwrap_or(snapshot_election_term);
    if snapshot_term == 0 {
        return Ok(());
    }

    let snapshot_leader = authority_lease.map(|lease| lease.leader_url.clone());
    if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open(path)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        authority
            .seed_cluster_fence(snapshot_leader.as_deref(), snapshot_term)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    let seed_guard = |guard: &mut ClusterRuntimeState| {
        let conflicting_same_term_self_leader = snapshot_term == guard.election_term
            && guard
                .last_leader_url
                .as_deref()
                .is_some_and(|leader| leader == guard.self_url)
            && snapshot_leader
                .as_deref()
                .is_some_and(|leader| leader != guard.self_url);
        if conflicting_same_term_self_leader {
            let now = unix_timestamp_now();
            guard.election_term = guard.election_term.saturating_add(1);
            guard.last_leader_url = Some(guard.self_url.clone());
            guard.term_started_at = Some(now);
            guard.lease_expires_at = Some(now.saturating_add(guard.lease_ttl_ms / 1000));
            return;
        }

        if snapshot_term > guard.election_term
            || (snapshot_term == guard.election_term
                && guard.last_leader_url.is_none()
                && snapshot_leader.is_some())
        {
            guard.election_term = snapshot_term;
            guard.last_leader_url = snapshot_leader.clone();
            guard.term_started_at = authority_lease.and_then(|lease| lease.term_started_at);
            guard.lease_expires_at = authority_lease.map(|lease| lease.lease_expires_at);
        }
    };

    match cluster.lock() {
        Ok(mut guard) => {
            seed_guard(&mut guard);
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            seed_guard(&mut guard);
        }
    }
    Ok(())
}

fn collect_revocation_views(
    store: &SqliteRevocationStore,
) -> Result<Vec<RevocationRecordView>, CliError> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let batch = store.list_revocations_after(
            MAX_LIST_LIMIT,
            cursor
                .as_ref()
                .map(|value: &RevocationCursor| value.revoked_at),
            cursor
                .as_ref()
                .map(|value: &RevocationCursor| value.capability_id.as_str()),
        )?;
        if batch.is_empty() {
            break;
        }
        for record in batch {
            cursor = Some(RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id.clone(),
            });
            records.push(RevocationRecordView {
                capability_id: record.capability_id,
                revoked_at: record.revoked_at,
            });
        }
    }
    Ok(records)
}

fn collect_tool_receipt_views(
    store: &SqliteReceiptStore,
    read_context: &ReceiptReadContext,
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_tool_receipts_after_seq_with_context(
            read_context,
            after_seq,
            MAX_LIST_LIMIT,
        )?;
        if batch.is_empty() {
            break;
        }
        let mut views = stored_tool_receipt_views(batch)?;
        after_seq = views.last().map(|record| record.seq).unwrap_or(after_seq);
        records.append(&mut views);
    }
    Ok(records)
}

fn collect_child_receipt_views(
    store: &SqliteReceiptStore,
    read_context: &ReceiptReadContext,
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_child_receipts_after_seq_with_context(
            read_context,
            after_seq,
            MAX_LIST_LIMIT,
        )?;
        if batch.is_empty() {
            break;
        }
        let mut views = stored_child_receipt_views(batch)?;
        after_seq = views.last().map(|record| record.seq).unwrap_or(after_seq);
        records.append(&mut views);
    }
    Ok(records)
}

fn collect_lineage_views(store: &SqliteReceiptStore) -> Result<Vec<StoredLineageView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store
            .list_capability_snapshots_after_seq(after_seq, MAX_LIST_LIMIT)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if batch.is_empty() {
            break;
        }
        after_seq = batch.last().map(|record| record.seq).unwrap_or(after_seq);
        records.extend(stored_lineage_views(batch));
    }
    Ok(records)
}

fn budget_usage_view(usage: chio_kernel::BudgetUsageRecord) -> BudgetUsageView {
    BudgetUsageView {
        capability_id: usage.capability_id,
        grant_index: usage.grant_index,
        invocation_count: usage.invocation_count,
        total_cost_exposed: usage.total_cost_exposed,
        total_cost_realized_spend: usage.total_cost_realized_spend,
        updated_at: usage.updated_at,
        seq: Some(usage.seq),
    }
}

fn snapshot_budget_cursor(
    current: Option<BudgetCursor>,
    covered_head: u64,
    anchors: &[BudgetUsageView],
    usages: &[BudgetUsageView],
) -> Option<BudgetCursor> {
    if covered_head == 0 {
        return None;
    }
    if current
        .as_ref()
        .is_some_and(|cursor| cursor.seq == covered_head)
    {
        return current;
    }
    let projection = usages
        .iter()
        .chain(anchors.iter())
        .max_by_key(|usage| usage.seq.unwrap_or(0));
    Some(BudgetCursor {
        seq: covered_head,
        updated_at: projection.map(|usage| usage.updated_at).unwrap_or(0),
        capability_id: projection
            .map(|usage| usage.capability_id.clone())
            .unwrap_or_default(),
        grant_index: projection.map(|usage| usage.grant_index).unwrap_or(0),
    })
}
