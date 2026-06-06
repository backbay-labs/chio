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

pub(crate) async fn handle_internal_cluster_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CLUSTER_STATUS_PATH)
    {
        return response;
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    };
    let consensus = cluster_consensus_view(&state).unwrap_or_else(|| ClusterConsensusView {
        self_url: String::new(),
        leader_url: None,
        role: "standalone",
        has_quorum: false,
        quorum_size: 1,
        reachable_nodes: 1,
        election_term: 0,
    });
    let replication = match cluster_replication_heads(&state) {
        Ok(replication) => replication,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let peers = match cluster.lock() {
        Ok(guard) => guard
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                partitioned: peer_state.partitioned,
                last_error: peer_state.last_error.clone(),
                last_contact_at: peer_state.last_contact_at,
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
                snapshot_applied_count: peer_state.snapshot_applied_count,
                last_snapshot_at: peer_state.last_snapshot_at,
                delta_records_since_snapshot: peer_state.delta_records_since_snapshot,
                force_snapshot: peer_state.force_snapshot,
            })
            .collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                partitioned: peer_state.partitioned,
                last_error: peer_state.last_error.clone(),
                last_contact_at: peer_state.last_contact_at,
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
                snapshot_applied_count: peer_state.snapshot_applied_count,
                last_snapshot_at: peer_state.last_snapshot_at,
                delta_records_since_snapshot: peer_state.delta_records_since_snapshot,
                force_snapshot: peer_state.force_snapshot,
            })
            .collect::<Vec<_>>(),
    };

    Json(ClusterStatusResponse {
        self_url: consensus.self_url,
        leader_url: consensus.leader_url,
        role: consensus.role.to_string(),
        has_quorum: consensus.has_quorum,
        quorum_size: consensus.quorum_size,
        reachable_nodes: consensus.reachable_nodes,
        election_term: consensus.election_term,
        authority_lease: cluster_authority_lease_view(&state),
        replication,
        peers,
    })
    .into_response()
}

fn internal_cluster_http_error(context: &'static str, error: &dyn std::fmt::Display) -> Response {
    warn!(error = %error, "{context}");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, context)
}

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

pub(crate) async fn handle_internal_revocations_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_REVOCATIONS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store.list_revocations_after(
        list_limit(query.limit),
        query.after_revoked_at,
        query.after_capability_id.as_deref(),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(RevocationDeltaResponse {
        records: records
            .into_iter()
            .map(|record| RevocationRecordView {
                capability_id: record.capability_id,
                revoked_at: record.revoked_at,
            })
            .collect(),
    })
    .into_response()
}

pub(crate) async fn handle_internal_tool_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_TOOL_RECEIPTS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let records = match store.list_tool_receipts_after_seq_with_context(
        &read_context,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let records = match stored_tool_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

pub(crate) async fn handle_internal_child_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_CHILD_RECEIPTS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let read_context = ReceiptReadContext::admin_service();
    let records = match store.list_child_receipts_after_seq_with_context(
        &read_context,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let records = match stored_child_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

pub(crate) async fn handle_internal_budgets_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_BUDGETS_DELTA_PATH)
    {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let mutation_events = match collect_budget_mutation_event_views_after_seq(
        &store,
        query.after_seq.unwrap_or(0),
        list_limit(query.limit),
    ) {
        Ok(events) => events,
        Err(error) => {
            return internal_cluster_http_error("failed to collect budget mutation deltas", &error);
        }
    };
    let records = if mutation_events.is_empty() {
        Vec::new()
    } else {
        match collect_budget_projection_views_for_events(&store, &mutation_events) {
            Ok(records) => records,
            Err(error) => {
                return internal_cluster_http_error(
                    "failed to collect budget projection deltas",
                    &error,
                );
            }
        }
    };
    Json(BudgetDeltaResponse {
        records,
        mutation_events,
    })
    .into_response()
}

pub(crate) async fn handle_internal_lineage_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_LINEAGE_DELTA_PATH)
    {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store
        .list_capability_snapshots_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(LineageDeltaResponse {
        records: stored_lineage_views(records),
    })
    .into_response()
}

pub(crate) async fn run_cluster_sync_loop(state: TrustServiceState) {
    loop {
        let sync_state = state.clone();
        match tokio::task::spawn_blocking(move || sync_cluster_once(&sync_state)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(error = %error, "trust-control cluster sync failed");
            }
            Err(error) => {
                warn!(error = %error, "trust-control cluster sync task panicked");
            }
        }
        tokio::time::sleep(state.config.cluster_sync_interval).await;
    }
}

fn sync_cluster_once(state: &TrustServiceState) -> Result<(), CliError> {
    let Some(cluster) = state.cluster.as_ref() else {
        return Ok(());
    };
    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.keys().cloned().collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
    };
    for peer_url in peers {
        let _ = sync_peer(state, &peer_url);
    }
    Ok(())
}

fn sync_peer(state: &TrustServiceState, peer_url: &str) -> Result<(), CliError> {
    if peer_is_partitioned(state, peer_url) {
        return Ok(());
    }
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(());
    };
    let client = service_runtime::client::build_cluster_peer_client(
        peer_url,
        &state.config.service_token,
        &self_url,
    )?;
    if let Err(error) = client.cluster_status() {
        update_peer_failure(state, peer_url, error.to_string());
        return Err(error);
    }
    update_peer_reachable(state, peer_url);
    if peer_should_force_snapshot(state, peer_url) {
        let snapshot = client.cluster_snapshot()?;
        apply_cluster_snapshot(state, peer_url, snapshot)?;
    }
    if let Err(error) = sync_peer_authority(state, &client) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    let mut delta_records = 0u64;
    if let Err(error) = sync_peer_revocations(state, &client, peer_url).map(|count| {
        delta_records = delta_records.saturating_add(count);
    }) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_tool_receipts(state, &client, peer_url).map(|count| {
        delta_records = delta_records.saturating_add(count);
    }) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_child_receipts(state, &client, peer_url).map(|count| {
        delta_records = delta_records.saturating_add(count);
    }) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_lineage(state, &client, peer_url).map(|count| {
        delta_records = delta_records.saturating_add(count);
    }) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_budgets(state, &client, peer_url).map(|count| {
        delta_records = delta_records.saturating_add(count);
    }) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    update_peer_delta_records(state, peer_url, delta_records);
    update_peer_success(state, peer_url);
    Ok(())
}

fn sync_peer_authority(
    state: &TrustServiceState,
    client: &TrustControlClient,
) -> Result<(), CliError> {
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    let authority = SqliteCapabilityAuthority::open(path)?;
    let snapshot = authority_snapshot_from_view(client.authority_snapshot()?);
    authority.apply_snapshot(&snapshot)?;
    Ok(())
}

fn sync_peer_revocations(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<u64, CliError> {
    let Some(path) = state.config.revocation_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteRevocationStore::open(path)?;
    let mut applied = 0u64;
    loop {
        let cursor = peer_revocation_cursor(state, peer_url);
        let response = client.revocation_deltas(&RevocationDeltaQuery {
            after_revoked_at: cursor.as_ref().map(|value| value.revoked_at),
            after_capability_id: cursor.as_ref().map(|value| value.capability_id.clone()),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_cursor = None;
        for record in response.records {
            store.upsert_revocation(&RevocationRecord {
                capability_id: record.capability_id.clone(),
                revoked_at: record.revoked_at,
            })?;
            applied = applied.saturating_add(1);
            last_cursor = Some(RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id,
            });
        }
        if let Some(cursor) = last_cursor {
            update_peer_revocation_cursor(state, peer_url, cursor);
        }
    }
    Ok(applied)
}

fn sync_peer_tool_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<u64, CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_tool_seq(state, peer_url);
        let response = client.tool_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChioReceipt = serde_json::from_value(record.receipt)?;
            store.append_chio_receipt(&receipt)?;
            last_seq = record.seq;
            applied = applied.saturating_add(1);
        }
        update_peer_tool_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn sync_peer_child_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<u64, CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_child_seq(state, peer_url);
        let response = client.child_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChildRequestReceipt = serde_json::from_value(record.receipt)?;
            store.append_child_receipt(&receipt)?;
            last_seq = record.seq;
            applied = applied.saturating_add(1);
        }
        update_peer_child_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn sync_peer_budgets(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<u64, CliError> {
    let Some(path) = state.config.budget_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteBudgetStore::open(path)?;
    let mut applied = 0u64;
    loop {
        let cursor = peer_budget_cursor(state, peer_url);
        let response = client.budget_deltas(&BudgetDeltaQuery {
            after_seq: cursor.as_ref().map(|value| value.seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        let outcome = import_budget_delta_response(&mut store, &response, cursor)?;
        applied = applied.saturating_add(outcome.applied_count);
        if let Some(cursor) = outcome.next_cursor {
            update_peer_budget_cursor(state, peer_url, cursor);
        }
        if !outcome.should_continue {
            break;
        }
    }
    Ok(applied)
}

pub(crate) struct BudgetDeltaImportOutcome {
    pub(crate) applied_count: u64,
    pub(crate) next_cursor: Option<BudgetCursor>,
    pub(crate) should_continue: bool,
}

pub(crate) fn import_budget_delta_response(
    store: &mut SqliteBudgetStore,
    response: &BudgetDeltaResponse,
    current_cursor: Option<BudgetCursor>,
) -> Result<BudgetDeltaImportOutcome, CliError> {
    if response.records.is_empty() && response.mutation_events.is_empty() {
        return Ok(BudgetDeltaImportOutcome {
            applied_count: 0,
            next_cursor: current_cursor,
            should_continue: false,
        });
    }
    let record_count = response
        .records
        .len()
        .saturating_add(response.mutation_events.len());
    if record_count > BUDGET_DELTA_MAX_RECORDS {
        return Err(CliError::cli_other_error(format!(
            "budget delta response contains {record_count} records, maximum is {BUDGET_DELTA_MAX_RECORDS}"
        )));
    }

    let usage_records = response
        .records
        .iter()
        .map(budget_usage_record_from_view)
        .collect::<Vec<_>>();
    let mutation_records = response
        .mutation_events
        .iter()
        .map(budget_mutation_record_from_view)
        .collect::<Result<Vec<_>, _>>()?;
    store.import_snapshot_records(&usage_records, &mutation_records)?;

    let previous_cursor_seq = current_cursor
        .as_ref()
        .map(|cursor| cursor.seq)
        .unwrap_or(0);
    let mut next_cursor = current_cursor;
    for event in &response.mutation_events {
        next_cursor = Some(merge_budget_cursor(
            next_cursor,
            budget_cursor_from_event(event),
        ));
    }
    if response.mutation_events.is_empty() {
        for usage in &response.records {
            if let Some(cursor) = budget_cursor_from_usage(usage) {
                next_cursor = Some(merge_budget_cursor(next_cursor, cursor));
            }
        }
    }

    let cursor_advanced = next_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.seq > previous_cursor_seq);
    let applied_count = if mutation_records.is_empty() {
        usage_records.len()
    } else {
        mutation_records.len()
    } as u64;

    Ok(BudgetDeltaImportOutcome {
        applied_count,
        next_cursor,
        should_continue: !response.mutation_events.is_empty() || cursor_advanced,
    })
}

fn sync_peer_lineage(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<u64, CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteReceiptStore::open(path)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_lineage_seq(state, peer_url);
        let response = client.lineage_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            last_seq = record.seq;
            applied = applied.saturating_add(1);
        }
        update_peer_lineage_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

pub(crate) fn build_cluster_state(
    config: &TrustServiceConfig,
    local_addr: SocketAddr,
) -> Result<Option<Arc<Mutex<ClusterRuntimeState>>>, CliError> {
    config.validate()?;
    if !config.peer_urls.is_empty() && config.authority_seed_path.is_some() {
        return Err(CliError::cli_other_error(
            "clustered trust control requires --authority-db instead of --authority-seed-file"
                .to_string(),
        ));
    }

    if config.peer_urls.is_empty() {
        return Ok(None);
    }

    let self_url = normalize_cluster_config_url(
        config
            .advertise_url
            .as_deref()
            .unwrap_or(&format!("http://{local_addr}")),
        config.allow_local_peer_urls,
    )?;
    let mut peers = HashMap::new();
    for peer_url in &config.peer_urls {
        let peer_url = normalize_cluster_config_url(peer_url, config.allow_local_peer_urls)?;
        if peer_url != self_url {
            peers.insert(peer_url, PeerSyncState::default());
        }
    }
    if peers.is_empty() {
        return Ok(None);
    }
    let mut persisted_term = 0u64;
    let mut persisted_leader_url = None;
    if let Some(path) = config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open(path)?;
        let status = authority.status()?;
        let fence = authority.cluster_fence()?;
        if fence.authority_generation == status.generation
            && fence.authority_rotated_at == status.rotated_at
        {
            persisted_term = fence.election_term;
            persisted_leader_url = fence
                .leader_url
                .and_then(|leader_url| normalize_cluster_url(&leader_url).ok())
                .filter(|leader_url| leader_url == &self_url || peers.contains_key(leader_url));
        } else if fence.election_term > 0 || fence.leader_url.is_some() {
            warn!(
                fence_generation = fence.authority_generation,
                authority_generation = status.generation,
                fence_rotated_at = fence.authority_rotated_at,
                authority_rotated_at = status.rotated_at,
                "discarding stale persisted authority fence after authority rotation"
            );
        }
    }
    Ok(Some(Arc::new(Mutex::new(ClusterRuntimeState {
        self_url,
        peers,
        election_term: persisted_term,
        last_leader_url: persisted_leader_url,
        term_started_at: None,
        lease_expires_at: None,
        lease_ttl_ms: authority_lease_ttl(config.cluster_sync_interval).as_millis() as u64,
    }))))
}

pub(crate) fn cluster_self_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(guard) => guard.self_url.clone(),
        Err(poisoned) => poisoned.into_inner().self_url.clone(),
    })
}

pub(crate) fn current_leader_url(state: &TrustServiceState) -> Option<String> {
    cluster_consensus_view(state).and_then(|view| view.leader_url)
}

pub(crate) fn authority_lease_ttl(sync_interval: Duration) -> Duration {
    let scaled = sync_interval
        .checked_mul(3)
        .unwrap_or_else(|| Duration::from_secs(5));
    scaled
        .max(Duration::from_millis(500))
        .min(Duration::from_secs(5))
}

pub(crate) fn cluster_authority_lease_view_locked(
    cluster: &mut ClusterRuntimeState,
    consensus: &ClusterConsensusView,
) -> Option<ClusterAuthorityLeaseView> {
    let leader_url = consensus.leader_url.clone()?;
    let lease_epoch = consensus.election_term;
    let lease_id = format!("{leader_url}#term-{lease_epoch}");
    Some(ClusterAuthorityLeaseView {
        authority_id: leader_url.clone(),
        leader_url,
        term: consensus.election_term,
        lease_id,
        lease_epoch,
        term_started_at: cluster.term_started_at,
        lease_expires_at: cluster.lease_expires_at?,
        lease_ttl_ms: cluster.lease_ttl_ms,
        lease_valid: consensus.has_quorum
            && cluster
                .lease_expires_at
                .is_some_and(|expires_at| expires_at >= unix_timestamp_now()),
    })
}

pub(crate) fn cluster_authority_lease_view(
    state: &TrustServiceState,
) -> Option<ClusterAuthorityLeaseView> {
    let cluster = state.cluster.as_ref()?;
    match cluster.lock() {
        Ok(mut guard) => {
            let consensus = compute_cluster_consensus_locked(&mut guard);
            cluster_authority_lease_view_locked(&mut guard, &consensus)
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let consensus = compute_cluster_consensus_locked(&mut guard);
            cluster_authority_lease_view_locked(&mut guard, &consensus)
        }
    }
}

pub(crate) fn current_budget_event_authority(
    state: &TrustServiceState,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if state.cluster.is_none() {
        return Ok(None);
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for budget writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before budget write could start",
        ));
    }
    Ok(Some(BudgetEventAuthority {
        authority_id: authority_lease.authority_id,
        lease_id: authority_lease.lease_id,
        lease_epoch: authority_lease.lease_epoch,
    }))
}

pub(crate) fn budget_authority_metadata_view(
    state: &TrustServiceState,
    budget_commit_index: Option<u64>,
    guarantee_level: &'static str,
) -> Option<BudgetAuthorityMetadataView> {
    let authority_lease = cluster_authority_lease_view(state)?;
    Some(BudgetAuthorityMetadataView {
        authority_id: authority_lease.authority_id,
        leader_url: authority_lease.leader_url,
        budget_term: authority_lease.term,
        lease_id: authority_lease.lease_id,
        lease_epoch: authority_lease.lease_epoch,
        lease_expires_at: authority_lease.lease_expires_at,
        lease_ttl_ms: authority_lease.lease_ttl_ms,
        guarantee_level: guarantee_level.to_string(),
        budget_commit_index,
    })
}

pub(crate) fn budget_authority_guarantee_level(
    state: &TrustServiceState,
    budget_commit_index: Option<u64>,
) -> &'static str {
    if state.cluster.is_some() {
        if budget_commit_index.is_some() {
            "ha_quorum_commit"
        } else {
            "ha_leader_visible"
        }
    } else {
        "single_node_atomic"
    }
}

fn budget_authorize_compensation_event_id(
    payload: &TryChargeCostRequest,
    budget_seq: u64,
) -> String {
    if let Some(event_id) = payload.event_id.as_deref() {
        return format!("{event_id}:rollback:{budget_seq}");
    }
    if let Some(hold_id) = payload.hold_id.as_deref() {
        return format!("{hold_id}:rollback:{budget_seq}");
    }
    format!(
        "rollback:{}:{}:{}",
        payload.capability_id, payload.grant_index, budget_seq
    )
}

pub(crate) fn rollback_budget_authorize_exposure(
    state: &TrustServiceState,
    payload: &TryChargeCostRequest,
    authority: Option<&BudgetEventAuthority>,
) -> Result<(), BudgetStoreError> {
    let store = open_budget_store(&state.config).map_err(|response| {
        BudgetStoreError::Invariant(format!(
            "failed to reopen budget store for compensation: {}",
            response.status()
        ))
    })?;
    let usage = store.get_usage(&payload.capability_id, payload.grant_index)?;
    let Some(usage) = usage else {
        return Ok(());
    };
    if usage.total_cost_exposed == 0 {
        return Ok(());
    }
    let rollback_event_id = budget_authorize_compensation_event_id(payload, usage.seq);
    store.reverse_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
        payload.hold_id.as_deref(),
        Some(&rollback_event_id),
        authority,
    )?;
    Ok(())
}

pub(crate) async fn respond_after_budget_write_quorum_commit<T>(
    state: &TrustServiceState,
    failure_message: &'static str,
    payload: Option<(T, u64)>,
) -> Response
where
    T: Serialize,
{
    let Some((payload, budget_seq)) = payload else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    let budget_commit = match wait_for_budget_write_quorum_commit(state, budget_seq).await {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    json_response_with_leader_visibility_and_budget_commit(state, payload, budget_commit)
}

pub(crate) fn respond_after_leader_visible_write<T, F>(
    state: &TrustServiceState,
    failure_message: &'static str,
    verify: F,
) -> Response
where
    T: Serialize,
    F: FnOnce() -> Result<Option<T>, Response>,
{
    let Some(payload) = (match verify() {
        Ok(payload) => payload,
        Err(response) => return response,
    }) else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    json_response_with_leader_visibility(state, payload)
}

pub(crate) fn budget_write_quorum_commit_view(
    state: &TrustServiceState,
    budget_seq: u64,
) -> Option<BudgetWriteCommitView> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => budget_write_quorum_commit_view_locked(&mut guard, budget_seq),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            budget_write_quorum_commit_view_locked(&mut guard, budget_seq)
        }
    })
}

fn budget_write_quorum_commit_view_locked(
    cluster: &mut ClusterRuntimeState,
    budget_seq: u64,
) -> BudgetWriteCommitView {
    let consensus = compute_cluster_consensus_locked(cluster);
    let mut witness_urls = BTreeSet::from([cluster.self_url.clone()]);
    for (peer_url, peer_state) in &cluster.peers {
        let committed = peer_state
            .budget_cursor
            .as_ref()
            .map(|cursor| cursor.seq >= budget_seq)
            .unwrap_or(false);
        if peer_state.health.is_reachable() && !peer_state.partitioned && committed {
            witness_urls.insert(peer_url.clone());
        }
    }
    let committed_nodes = witness_urls.len();
    let authority_id = consensus
        .leader_url
        .clone()
        .unwrap_or_else(|| cluster.self_url.clone());
    let budget_term = consensus.election_term;
    let lease_epoch = budget_term;
    let lease_id = format!("{authority_id}#term-{lease_epoch}");
    BudgetWriteCommitView {
        budget_seq,
        commit_index: budget_seq,
        quorum_committed: committed_nodes >= consensus.quorum_size,
        quorum_size: consensus.quorum_size,
        committed_nodes,
        witness_urls: witness_urls.into_iter().collect(),
        authority_id,
        budget_term,
        lease_id,
        lease_epoch,
    }
}

fn budget_write_quorum_commit_timeout(sync_interval: Duration) -> Duration {
    let scaled = sync_interval
        .checked_mul(20)
        .unwrap_or_else(|| Duration::from_secs(30));
    scaled
        .max(Duration::from_secs(5))
        .min(Duration::from_secs(30))
}

pub(crate) async fn wait_for_budget_write_quorum_commit(
    state: &TrustServiceState,
    budget_seq: u64,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    if state.cluster.is_none() {
        return Ok(None);
    }

    let timeout = budget_write_quorum_commit_timeout(state.config.cluster_sync_interval);
    let poll_interval = Duration::from_millis(250);
    let deadline = Instant::now() + timeout;
    loop {
        let Some(commit_view) = budget_write_quorum_commit_view(state, budget_seq) else {
            return Ok(None);
        };
        if commit_view.quorum_committed {
            return Ok(Some(commit_view));
        }
        if !cluster_consensus_view(state).is_some_and(|consensus| consensus.has_quorum) {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "budget write became leader-visible at commit index {budget_seq} for authority term {} but cluster quorum disappeared before commit",
                    commit_view.budget_term,
                ),
            ));
        }
        let sync_state = state.clone();
        match tokio::task::spawn_blocking(move || sync_cluster_once(&sync_state)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(error = %error, "trust-control budget quorum sync failed");
            }
            Err(error) => {
                warn!(error = %error, "trust-control budget quorum sync task panicked");
            }
        }
        let Some(commit_view) = budget_write_quorum_commit_view(state, budget_seq) else {
            return Ok(None);
        };
        if commit_view.quorum_committed {
            return Ok(Some(commit_view));
        }
        if Instant::now() >= deadline {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "budget write became leader-visible at commit index {budget_seq} for authority term {} but only {}/{} quorum witnesses observed before timeout",
                    commit_view.budget_term, commit_view.committed_nodes, commit_view.quorum_size
                ),
            ));
        }
        tokio::time::sleep(poll_interval).await;
    }
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

fn peer_is_partitioned(state: &TrustServiceState, peer_url: &str) -> bool {
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

fn update_peer_state<F>(state: &TrustServiceState, peer_url: &str, update: F)
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

pub(crate) fn cluster_consensus_view(state: &TrustServiceState) -> Option<ClusterConsensusView> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => compute_cluster_consensus_locked(&mut guard),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            compute_cluster_consensus_locked(&mut guard)
        }
    })
}

pub(crate) fn compute_cluster_consensus_locked(
    cluster: &mut ClusterRuntimeState,
) -> ClusterConsensusView {
    let now = unix_timestamp_now();
    let lease_ttl_secs = Duration::from_millis(cluster.lease_ttl_ms).as_secs().max(1);
    let quorum_size = cluster.peers.len().div_ceil(2) + 1;
    let mut candidates = vec![cluster.self_url.clone()];
    for (peer_url, peer_state) in &cluster.peers {
        let contact_is_fresh = peer_state
            .last_contact_at
            .is_some_and(|last_contact_at| now <= last_contact_at.saturating_add(lease_ttl_secs));
        if peer_state.health.is_reachable() && !peer_state.partitioned && contact_is_fresh {
            candidates.push(peer_url.clone());
        }
    }
    candidates.sort();
    let reachable_nodes = candidates.len();
    let has_quorum = reachable_nodes >= quorum_size;
    let leader_url = if has_quorum {
        candidates.first().cloned()
    } else {
        None
    };
    if cluster.last_leader_url != leader_url {
        cluster.election_term = cluster.election_term.saturating_add(1);
        cluster.last_leader_url = leader_url.clone();
        cluster.term_started_at = leader_url.as_ref().map(|_| now);
    }
    cluster.lease_expires_at = if has_quorum {
        Some(now.saturating_add(lease_ttl_secs))
    } else {
        None
    };
    if !has_quorum {
        cluster.term_started_at = None;
    }
    let role = if !has_quorum {
        "candidate"
    } else if leader_url.as_deref() == Some(cluster.self_url.as_str()) {
        "leader"
    } else {
        "follower"
    };
    ClusterConsensusView {
        self_url: cluster.self_url.clone(),
        leader_url,
        role,
        has_quorum,
        quorum_size,
        reachable_nodes,
        election_term: cluster.election_term,
    }
}

fn cluster_replication_heads(
    state: &TrustServiceState,
) -> Result<ClusterReplicationHeadsView, CliError> {
    let snapshot = build_cluster_state_snapshot(state)?;
    Ok(snapshot.replication)
}

pub(crate) fn build_cluster_state_snapshot(
    state: &TrustServiceState,
) -> Result<ClusterStateSnapshotResponse, CliError> {
    let consensus = cluster_consensus_view(state);
    let authority_lease = cluster_authority_lease_view(state);
    let authority = if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = SqliteCapabilityAuthority::open(path)?;
        Some(authority_snapshot_view(authority.snapshot()?))
    } else {
        None
    };

    let revocations = if let Some(path) = state.config.revocation_db_path.as_deref() {
        let store = SqliteRevocationStore::open(path)?;
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

    let budgets = if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        collect_budget_views(&store)?
    } else {
        Vec::new()
    };
    let budget_mutation_events = if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        collect_budget_mutation_event_views(&store)?
    } else {
        Vec::new()
    };

    let replication = ClusterReplicationHeadsView {
        tool_seq: tool_receipts.last().map(|record| record.seq).unwrap_or(0),
        child_seq: child_receipts.last().map(|record| record.seq).unwrap_or(0),
        lineage_seq: lineage.last().map(|record| record.seq).unwrap_or(0),
        budget_seq: budget_mutation_events
            .last()
            .map(|event| event.event_seq)
            .unwrap_or(0),
        revocation_cursor: revocations.last().map(|record| RevocationCursorView {
            revoked_at: record.revoked_at,
            capability_id: record.capability_id.clone(),
        }),
    };

    Ok(ClusterStateSnapshotResponse {
        generated_at: unix_timestamp_now(),
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
        budget_mutation_events,
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
        budget_mutation_events,
    } = snapshot;

    if let (Some(path), Some(authority_view)) =
        (state.config.authority_db_path.as_deref(), authority)
    {
        let authority = SqliteCapabilityAuthority::open(path)?;
        authority.apply_snapshot(&authority_snapshot_from_view(authority_view))?;
    }

    if let Some(path) = state.config.revocation_db_path.as_deref() {
        let store = SqliteRevocationStore::open(path)?;
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
    if let Some(path) = state.config.budget_db_path.as_deref() {
        let store = SqliteBudgetStore::open(path)?;
        let usage_records = budgets
            .iter()
            .map(budget_usage_record_from_view)
            .collect::<Vec<_>>();
        let mutation_records = budget_mutation_events
            .iter()
            .map(budget_mutation_record_from_view)
            .collect::<Result<Vec<_>, _>>()?;
        store
            .import_snapshot_records(&usage_records, &mutation_records)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        for event in &budget_mutation_events {
            budget_cursor = Some(merge_budget_cursor(
                budget_cursor,
                budget_cursor_from_event(event),
            ));
        }
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

fn collect_budget_views(store: &SqliteBudgetStore) -> Result<Vec<BudgetUsageView>, CliError> {
    let mut after_seq = None;
    let mut records = Vec::new();
    loop {
        let batch = store.list_usages_after(MAX_LIST_LIMIT, after_seq)?;
        if batch.is_empty() {
            break;
        }
        after_seq = batch.last().map(|record| record.seq);
        records.extend(batch.into_iter().map(|usage| BudgetUsageView {
            capability_id: usage.capability_id,
            grant_index: usage.grant_index,
            invocation_count: usage.invocation_count,
            total_cost_exposed: usage.total_cost_exposed,
            total_cost_realized_spend: usage.total_cost_realized_spend,
            updated_at: usage.updated_at,
            seq: Some(usage.seq),
        }));
    }
    Ok(records)
}

fn collect_budget_mutation_event_views(
    store: &SqliteBudgetStore,
) -> Result<Vec<BudgetMutationEventView>, CliError> {
    Ok(store
        .list_mutation_events(i64::MAX as usize, None, None)?
        .into_iter()
        .map(budget_mutation_event_view)
        .collect())
}

pub(crate) fn collect_budget_mutation_event_views_after_seq(
    store: &SqliteBudgetStore,
    after_seq: u64,
    limit: usize,
) -> Result<Vec<BudgetMutationEventView>, CliError> {
    Ok(store
        .list_mutation_events_after_seq(limit, after_seq)?
        .into_iter()
        .map(budget_mutation_event_view)
        .collect())
}

fn collect_budget_projection_views_for_events(
    store: &SqliteBudgetStore,
    events: &[BudgetMutationEventView],
) -> Result<Vec<BudgetUsageView>, CliError> {
    let mut latest = BTreeMap::<(String, u32), BudgetUsageView>::new();
    for event in events {
        let Some(usage) = store.get_usage(&event.capability_id, event.grant_index as usize)? else {
            continue;
        };
        latest.insert(
            (usage.capability_id.clone(), usage.grant_index),
            BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
                updated_at: usage.updated_at,
                seq: Some(usage.seq),
            },
        );
    }
    Ok(latest.into_values().collect())
}

fn budget_mutation_event_view(record: BudgetMutationRecord) -> BudgetMutationEventView {
    BudgetMutationEventView {
        event_id: record.event_id,
        hold_id: record.hold_id,
        capability_id: record.capability_id,
        grant_index: record.grant_index,
        kind: record.kind.as_str().to_string(),
        allowed: record.allowed,
        recorded_at: record.recorded_at,
        event_seq: record.event_seq,
        usage_seq: record.usage_seq,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        max_invocations: record.max_invocations,
        max_cost_per_invocation: record.max_cost_per_invocation,
        max_total_cost_units: record.max_total_cost_units,
        invocation_count_after: record.invocation_count_after,
        total_cost_exposed_after: record.total_cost_exposed_after,
        total_cost_realized_spend_after: record.total_cost_realized_spend_after,
        authority: record
            .authority
            .map(|authority| BudgetMutationAuthorityView {
                authority_id: authority.authority_id,
                lease_id: authority.lease_id,
                lease_epoch: authority.lease_epoch,
            }),
    }
}

fn budget_usage_record_from_view(usage: &BudgetUsageView) -> chio_kernel::BudgetUsageRecord {
    chio_kernel::BudgetUsageRecord {
        capability_id: usage.capability_id.clone(),
        grant_index: usage.grant_index,
        invocation_count: usage.invocation_count,
        updated_at: usage.updated_at,
        seq: usage.seq.unwrap_or(0),
        total_cost_exposed: usage.total_cost_exposed,
        total_cost_realized_spend: usage.total_cost_realized_spend,
    }
}

pub(crate) fn budget_cursor_from_event(event: &BudgetMutationEventView) -> BudgetCursor {
    BudgetCursor {
        seq: event.event_seq,
        updated_at: event.recorded_at,
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
    }
}

fn budget_cursor_from_usage(usage: &BudgetUsageView) -> Option<BudgetCursor> {
    Some(BudgetCursor {
        seq: usage.seq?,
        updated_at: usage.updated_at,
        capability_id: usage.capability_id.clone(),
        grant_index: usage.grant_index,
    })
}

fn merge_budget_cursor(current: Option<BudgetCursor>, candidate: BudgetCursor) -> BudgetCursor {
    match current {
        Some(existing)
            if existing.seq > candidate.seq
                || (existing.seq == candidate.seq
                    && existing.updated_at >= candidate.updated_at) =>
        {
            existing
        }
        _ => candidate,
    }
}

fn budget_event_authority_from_view(
    authority: &BudgetMutationAuthorityView,
) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority.authority_id.clone(),
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    }
}

fn budget_mutation_record_from_view(
    event: &BudgetMutationEventView,
) -> Result<BudgetMutationRecord, CliError> {
    let kind = BudgetMutationKind::parse(&event.kind).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "unknown budget mutation kind `{}` in cluster snapshot",
            event.kind
        ))
    })?;

    Ok(BudgetMutationRecord {
        event_id: event.event_id.clone(),
        hold_id: event.hold_id.clone(),
        capability_id: event.capability_id.clone(),
        grant_index: event.grant_index,
        kind,
        allowed: event.allowed,
        recorded_at: event.recorded_at,
        event_seq: event.event_seq,
        usage_seq: event.usage_seq,
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        max_invocations: event.max_invocations,
        max_cost_per_invocation: event.max_cost_per_invocation,
        max_total_cost_units: event.max_total_cost_units,
        invocation_count_after: event.invocation_count_after,
        total_cost_exposed_after: event.total_cost_exposed_after,
        total_cost_realized_spend_after: event.total_cost_realized_spend_after,
        authority: event
            .authority
            .as_ref()
            .map(budget_event_authority_from_view),
    })
}
