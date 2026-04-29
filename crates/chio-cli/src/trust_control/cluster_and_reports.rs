async fn handle_internal_cluster_status(
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
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

fn internal_cluster_http_error(
    context: &'static str,
    error: &dyn std::fmt::Display,
) -> Response {
    warn!(error = %error, "{context}");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, context)
}

async fn handle_internal_cluster_snapshot(
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

async fn handle_internal_cluster_partition(
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

async fn handle_internal_authority_snapshot(
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
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
        let snapshot = match authority.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
        return Json(authority_snapshot_view(snapshot)).into_response();
    }

    plain_http_error(
        StatusCode::CONFLICT,
        "clustered authority replication requires --authority-db",
    )
}

async fn handle_internal_revocations_delta(
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
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

async fn handle_internal_tool_receipts_delta(
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
    let records = match store
        .list_tool_receipts_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let records = match stored_tool_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

async fn handle_internal_child_receipts_delta(
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
    let records = match store
        .list_child_receipts_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let records = match stored_child_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

async fn handle_internal_budgets_delta(
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
            return internal_cluster_http_error("failed to collect budget mutation deltas", &error)
        }
    };
    let records = if mutation_events.is_empty() {
        Vec::new()
    } else {
        match collect_budget_projection_views_for_events(&store, &mutation_events) {
            Ok(records) => records,
            Err(error) => {
                return internal_cluster_http_error("failed to collect budget projection deltas", &error)
            }
        }
    };
    Json(BudgetDeltaResponse {
        records,
        mutation_events,
    })
    .into_response()
}

async fn handle_internal_lineage_delta(
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(LineageDeltaResponse {
        records: stored_lineage_views(records),
    })
    .into_response()
}

async fn run_cluster_sync_loop(state: TrustServiceState) {
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
    let client = build_cluster_peer_client(peer_url, &state.config.service_token, &self_url)?;
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

struct BudgetDeltaImportOutcome {
    applied_count: u64,
    next_cursor: Option<BudgetCursor>,
    should_continue: bool,
}

fn import_budget_delta_response(
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
        return Err(CliError::Other(format!(
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

    let previous_cursor_seq = current_cursor.as_ref().map(|cursor| cursor.seq).unwrap_or(0);
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
                .map_err(|error| CliError::Other(error.to_string()))?;
            last_seq = record.seq;
            applied = applied.saturating_add(1);
        }
        update_peer_lineage_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}

fn build_cluster_state(
    config: &TrustServiceConfig,
    local_addr: SocketAddr,
) -> Result<Option<Arc<Mutex<ClusterRuntimeState>>>, CliError> {
    if !config.peer_urls.is_empty() && config.authority_seed_path.is_some() {
        return Err(CliError::Other(
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

fn cluster_self_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(guard) => guard.self_url.clone(),
        Err(poisoned) => poisoned.into_inner().self_url.clone(),
    })
}

fn current_leader_url(state: &TrustServiceState) -> Option<String> {
    cluster_consensus_view(state).and_then(|view| view.leader_url)
}

fn authority_lease_ttl(sync_interval: Duration) -> Duration {
    let scaled = sync_interval
        .checked_mul(3)
        .unwrap_or_else(|| Duration::from_secs(5));
    scaled
        .max(Duration::from_millis(500))
        .min(Duration::from_secs(5))
}

fn cluster_authority_lease_view_locked(
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

fn cluster_authority_lease_view(state: &TrustServiceState) -> Option<ClusterAuthorityLeaseView> {
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

fn current_budget_event_authority(
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

fn budget_authority_metadata_view(
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

fn budget_authority_guarantee_level(
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

fn rollback_budget_authorize_exposure(
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

async fn respond_after_budget_write_quorum_commit<T>(
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

fn respond_after_leader_visible_write<T, F>(
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

fn json_response_with_leader_visibility<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
) -> Response {
    json_response_with_leader_visibility_and_budget_commit(state, payload, None)
}

fn json_response_with_leader_visibility_and_budget_commit<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
    budget_commit: Option<BudgetWriteCommitView>,
) -> Response {
    let mut value = match serde_json::to_value(payload) {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to serialize trust control response: {error}"),
            )
        }
    };
    let Value::Object(map) = &mut value else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust control success responses must be JSON objects",
        );
    };
    if let Some(self_url) = cluster_self_url(state) {
        let leader_url = current_leader_url(state).unwrap_or_else(|| self_url.clone());
        map.insert("handledBy".to_string(), Value::String(self_url));
        map.insert("leaderUrl".to_string(), Value::String(leader_url));
        map.insert("visibleAtLeader".to_string(), Value::Bool(true));
        if let Some(authority_lease) = cluster_authority_lease_view(state) {
            let authority_lease = match serde_json::to_value(authority_lease) {
                Ok(value) => value,
                Err(error) => {
                    return plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to serialize cluster authority lease metadata: {error}"),
                    )
                }
            };
            map.insert("clusterAuthority".to_string(), authority_lease);
        }
    }
    if let Some(budget_commit) = budget_commit {
        let budget_commit = match serde_json::to_value(budget_commit) {
            Ok(value) => value,
            Err(error) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to serialize budget quorum commit metadata: {error}"),
                )
            }
        };
        map.insert("budgetCommit".to_string(), budget_commit);
    }
    Json(value).into_response()
}

fn budget_write_quorum_commit_view(
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

async fn wait_for_budget_write_quorum_commit(
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

fn update_peer_success(state: &TrustServiceState, peer_url: &str) {
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

fn update_peer_reachable(state: &TrustServiceState, peer_url: &str) {
    let now = unix_timestamp_now();
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
        peer.last_contact_at = Some(now);
    });
}

fn update_peer_failure(state: &TrustServiceState, peer_url: &str, error: String) {
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

fn update_peer_sync_error(state: &TrustServiceState, peer_url: &str, error: String) {
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
        peer.last_error = Some(error);
    });
}

fn peer_revocation_cursor(state: &TrustServiceState, peer_url: &str) -> Option<RevocationCursor> {
    with_peer_state(state, peer_url, |peer| peer.revocation_cursor.clone()).flatten()
}

fn peer_budget_cursor(state: &TrustServiceState, peer_url: &str) -> Option<BudgetCursor> {
    with_peer_state(state, peer_url, |peer| peer.budget_cursor.clone()).flatten()
}

fn peer_tool_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.tool_seq).unwrap_or(0)
}

fn peer_child_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.child_seq).unwrap_or(0)
}

fn peer_lineage_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.lineage_seq).unwrap_or(0)
}

fn update_peer_revocation_cursor(
    state: &TrustServiceState,
    peer_url: &str,
    cursor: RevocationCursor,
) {
    update_peer_state(state, peer_url, |peer| {
        peer.revocation_cursor = Some(cursor)
    });
}

fn update_peer_budget_cursor(state: &TrustServiceState, peer_url: &str, cursor: BudgetCursor) {
    update_peer_state(state, peer_url, |peer| peer.budget_cursor = Some(cursor));
}

fn update_peer_tool_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.tool_seq = seq);
}

fn update_peer_child_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.child_seq = seq);
}

fn update_peer_lineage_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.lineage_seq = seq);
}

fn update_peer_delta_records(state: &TrustServiceState, peer_url: &str, count: u64) {
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

fn peer_should_force_snapshot(state: &TrustServiceState, peer_url: &str) -> bool {
    with_peer_state(state, peer_url, |peer| {
        peer.force_snapshot
            || peer.delta_records_since_snapshot >= CLUSTER_SNAPSHOT_RECORD_THRESHOLD
    })
    .unwrap_or(false)
}

fn with_peer_state<T, F>(state: &TrustServiceState, peer_url: &str, map: F) -> Option<T>
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

fn authority_snapshot_view(snapshot: AuthoritySnapshot) -> AuthoritySnapshotView {
    AuthoritySnapshotView {
        public_key_hex: snapshot.public_key_hex,
        generation: snapshot.generation,
        rotated_at: snapshot.rotated_at,
        trusted_keys: snapshot
            .trusted_keys
            .into_iter()
            .map(|trusted_key| AuthorityTrustedKeyView {
                public_key_hex: trusted_key.public_key_hex,
                generation: trusted_key.generation,
                activated_at: trusted_key.activated_at,
            })
            .collect(),
    }
}

fn revocation_cursor_view(cursor: RevocationCursor) -> RevocationCursorView {
    RevocationCursorView {
        revoked_at: cursor.revoked_at,
        capability_id: cursor.capability_id,
    }
}

fn budget_cursor_view(cursor: BudgetCursor) -> BudgetCursorView {
    BudgetCursorView {
        seq: cursor.seq,
        updated_at: cursor.updated_at,
        capability_id: cursor.capability_id,
        grant_index: cursor.grant_index,
    }
}

fn authority_snapshot_from_view(view: AuthoritySnapshotView) -> AuthoritySnapshot {
    AuthoritySnapshot {
        public_key_hex: view.public_key_hex,
        generation: view.generation,
        rotated_at: view.rotated_at,
        trusted_keys: view
            .trusted_keys
            .into_iter()
            .map(|trusted_key| chio_kernel::AuthorityTrustedKeySnapshot {
                public_key_hex: trusted_key.public_key_hex,
                generation: trusted_key.generation,
                activated_at: trusted_key.activated_at,
            })
            .collect(),
    }
}

fn revocation_cursor_from_view(view: RevocationCursorView) -> RevocationCursor {
    RevocationCursor {
        revoked_at: view.revoked_at,
        capability_id: view.capability_id,
    }
}

fn stored_tool_receipt_views(
    records: Vec<StoredToolReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

fn stored_child_receipt_views(
    records: Vec<StoredChildReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

fn stored_lineage_views(records: Vec<StoredCapabilitySnapshot>) -> Vec<StoredLineageView> {
    records
        .into_iter()
        .map(|record| StoredLineageView {
            seq: record.seq,
            snapshot: record.snapshot,
        })
        .collect()
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

fn budget_visibility_matches(
    allowed: bool,
    invocation_count: Option<u32>,
    max_invocations: Option<u32>,
) -> bool {
    match (allowed, invocation_count, max_invocations) {
        (true, Some(_), _) => true,
        (true, None, _) => false,
        (false, Some(count), Some(max)) => count >= max,
        (false, Some(_), None) => true,
        (false, None, Some(0)) => true,
        (false, None, Some(_)) => false,
        (false, None, None) => false,
    }
}

fn normalize_cluster_url(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::Other("cluster URL must not be empty".to_string()));
    }
    Ok(normalized.to_string())
}

fn normalize_cluster_config_url(value: &str, allow_local: bool) -> Result<String, CliError> {
    let normalized = normalize_cluster_url(value)?;
    let parsed = Url::parse(&normalized)
        .map_err(|error| CliError::Other(format!("cluster URL must be valid: {error}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CliError::Other(format!(
                "cluster URL scheme `{scheme}` is not allowed"
            )))
        }
    }
    if allow_local {
        return Ok(normalized);
    }
    validate_cluster_url_host(&parsed)?;
    Ok(normalized)
}

fn validate_cluster_url_host(parsed: &Url) -> Result<(), CliError> {
    match parsed.host() {
        Some(Host::Ipv4(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V4(address)) {
                return Err(CliError::Other(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Ipv6(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V6(address)) {
                return Err(CliError::Other(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Domain(host)) => {
            let lower = host.to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                return Err(CliError::Other(
                    "cluster URL must not target localhost without --allow-local-peer-urls"
                        .to_string(),
                ));
            }
            let port = parsed.port_or_known_default().ok_or_else(|| {
                CliError::Other("cluster URL must include a resolvable port".to_string())
            })?;
            let addrs = (host, port).to_socket_addrs().map_err(|error| {
                CliError::Other(format!("cluster URL host `{host}` could not be resolved: {error}"))
            })?;
            for addr in addrs {
                if chio_external_guards::denied_external_guard_ip(addr.ip()) {
                    return Err(CliError::Other(format!(
                        "cluster URL host `{host}` resolved to disallowed address `{}` without --allow-local-peer-urls",
                        addr.ip()
                    )));
                }
            }
        }
        None => {
            return Err(CliError::Other(
                "cluster URL must include a host".to_string(),
            ))
        }
    }
    Ok(())
}

fn cluster_consensus_view(state: &TrustServiceState) -> Option<ClusterConsensusView> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => compute_cluster_consensus_locked(&mut guard),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            compute_cluster_consensus_locked(&mut guard)
        }
    })
}

fn compute_cluster_consensus_locked(cluster: &mut ClusterRuntimeState) -> ClusterConsensusView {
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

fn build_cluster_state_snapshot(
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
            (
                collect_tool_receipt_views(&store)?,
                collect_child_receipt_views(&store)?,
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

fn apply_cluster_snapshot(
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
                .map_err(|error| CliError::Other(error.to_string()))?;
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
            .map_err(|error| CliError::Other(error.to_string()))?;
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
            .map_err(|error| CliError::Other(error.to_string()))?;
        authority
            .seed_cluster_fence(snapshot_leader.as_deref(), snapshot_term)
            .map_err(|error| CliError::Other(error.to_string()))?;
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
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_tool_receipts_after_seq(after_seq, MAX_LIST_LIMIT)?;
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
) -> Result<Vec<StoredReceiptView>, CliError> {
    let mut after_seq = 0u64;
    let mut records = Vec::new();
    loop {
        let batch = store.list_child_receipts_after_seq(after_seq, MAX_LIST_LIMIT)?;
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
            .map_err(|error| CliError::Other(error.to_string()))?;
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

fn collect_budget_mutation_event_views_after_seq(
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

fn budget_cursor_from_event(event: &BudgetMutationEventView) -> BudgetCursor {
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
                || (existing.seq == candidate.seq && existing.updated_at >= candidate.updated_at) =>
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
        CliError::Other(format!(
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

fn forwarded_control_response(response: ureq::Response) -> Result<Response, CliError> {
    let status = StatusCode::from_u16(response.status()).map_err(|error| {
        CliError::Other(format!(
            "failed to map forwarded trust-control response status: {error}"
        ))
    })?;
    let content_type = response.header(CONTENT_TYPE.as_str()).map(str::to_owned);
    let body = response.into_string().map_err(|error| {
        CliError::Other(format!(
            "failed to decode forwarded trust-control response body: {error}"
        ))
    })?;

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder.body(axum::body::Body::from(body)).map_err(|error| {
        CliError::Other(format!(
            "failed to build forwarded trust-control response: {error}"
        ))
    })
}

fn post_json_to_control_service<B: Serialize>(
    client: &TrustControlClient,
    path: &str,
    body: &B,
) -> Result<Response, CliError> {
    let json = serde_json::to_value(body).map_err(|error| {
        CliError::Other(format!(
            "failed to serialize forwarded trust control request: {error}"
        ))
    })?;
    let endpoint = client.endpoints.first().ok_or_else(|| {
        CliError::Other("trust control client requires at least one endpoint".to_string())
    })?;
    let url = format!("{endpoint}{path}");
    match client
        .http
        .post(&url)
        .set(AUTHORIZATION.as_str(), &format!("Bearer {}", client.token))
        .send_json(json)
    {
        Ok(response) => forwarded_control_response(response),
        Err(ureq::Error::Status(_, response)) => forwarded_control_response(response),
        Err(ureq::Error::Transport(error)) => Err(CliError::Other(format!(
            "trust control service transport failed: {error}"
        ))),
    }
}

async fn forward_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for trust-control writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before trust-control write forwarding",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = build_client(&leader_url, &state.config.service_token).map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        match post_json_to_control_service(&client, path, body) {
            Ok(response) => return Ok(Some(response)),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_authority_lease) = cluster_authority_lease_view(state) else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease is unavailable for trust-control writes",
                    ));
                };
                if !next_authority_lease.lease_valid {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease expired before trust-control write forwarding",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward control-plane write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward control-plane write to cluster leader",
    ))
}

async fn forward_authority_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for authority writes",
        ));
    }
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease is unavailable for authority writes",
        ));
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority write forwarding",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for authority writes",
        ));
    };
    let mut authority_term = authority_lease.term;
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = build_cluster_peer_client(&leader_url, &state.config.service_token, &self_url)
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        if let Ok(status) = client.cluster_status() {
            update_peer_reachable(state, &leader_url);
            if status.has_quorum
                && status.leader_url.as_deref() == Some(leader_url.as_str())
            {
                if let Some(lease) = status.authority_lease.as_ref() {
                    if lease.lease_valid && lease.leader_url == leader_url {
                        authority_term = lease.term;
                    }
                }
            }
        }
        match client.post_internal_json::<_, Value>(path, body, Some(authority_term)) {
            Ok(value) => return Ok(Some(Json(value).into_response())),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for authority writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for authority writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                let Some(next_authority_lease) = cluster_authority_lease_view(state) else {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease is unavailable for authority writes",
                    ));
                };
                if !next_authority_lease.lease_valid {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster authority lease expired before authority write forwarding",
                    ));
                }
                if next_leader == leader_url && next_authority_lease.term == authority_term {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward authority write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
                authority_term = next_authority_lease.term;
            }
        }
    }

    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward authority write to cluster leader",
    ))
}

async fn forward_scim_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = build_client(&leader_url, &state.config.service_token).map_err(|error| {
            scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        match client.post_json::<_, Value>(path, body) {
            Ok(value) => return Ok(Some(scim_json_response(StatusCode::CREATED, &value))),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward scim write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(scim_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward scim write to cluster leader",
    ))
}

async fn forward_scim_delete_to_leader(
    state: &TrustServiceState,
    path: &str,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(consensus) = cluster_consensus_view(state) else {
        return Ok(None);
    };
    if !consensus.has_quorum {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster quorum is unavailable for trust-control writes",
        ));
    }
    let Some(mut leader_url) = consensus.leader_url else {
        return Err(scim_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster leader is unavailable for trust-control writes",
        ));
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = build_client(&leader_url, &state.config.service_token).map_err(|error| {
            scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        match client.delete_json::<Value>(path) {
            Ok(value) => return Ok(Some(scim_json_response(StatusCode::OK, &value))),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_consensus) = cluster_consensus_view(state) else {
                    return Ok(None);
                };
                if !next_consensus.has_quorum {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster quorum is unavailable for trust-control writes",
                    ));
                }
                let Some(next_leader) = next_consensus.leader_url else {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "cluster leader is unavailable for trust-control writes",
                    ));
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(scim_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward scim delete to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(scim_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward scim delete to cluster leader",
    ))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if !provided.is_empty() {
        return Ok(provided.to_string());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid issuance bearer token",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"chio-passport-issuance\""),
    );
    Err(response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClusterPeerAuthContext {
    node_id: String,
    issued_at: i64,
    term: Option<u64>,
}

static CLUSTER_PEER_AUTH_FAILURES: LazyLock<Mutex<HashMap<String, Vec<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_cluster_peer_auth_failures(failures: &mut Vec<u64>, now: u64) {
    let cutoff = now.saturating_sub(CLUSTER_AUTH_FAILURE_WINDOW_SECS);
    failures.retain(|recorded_at| *recorded_at >= cutoff);
}

fn cluster_peer_auth_is_rate_limited(node_id: &str, now: u64) -> bool {
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return false;
    };
    let Some(history) = failures.get_mut(node_id) else {
        return false;
    };
    prune_cluster_peer_auth_failures(history, now);
    if history.is_empty() {
        failures.remove(node_id);
        return false;
    }
    history.len() >= CLUSTER_AUTH_FAILURE_BURST
}

fn record_cluster_peer_auth_failure(node_id: &str) {
    let now = unix_timestamp_now();
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return;
    };
    let history = failures.entry(node_id.to_string()).or_default();
    prune_cluster_peer_auth_failures(history, now);
    history.push(now);
}

fn clear_cluster_peer_auth_failures(node_id: &str) {
    if let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() {
        failures.remove(node_id);
    }
}

fn cluster_peer_auth_unverified_failure_key(
    node_id: &str,
    endpoint: &str,
) -> String {
    let payload = format!("{node_id}\0{endpoint}");
    format!("unverified:{}", sha256_hex(payload.as_bytes()))
}

fn cluster_peer_auth_signature(
    service_token: &str,
    node_id: &str,
    endpoint: &str,
    issued_at: i64,
    term: Option<u64>,
) -> Result<String, CliError> {
    let payload = canonical_json_bytes(&json!({
        "scheme": CLUSTER_AUTH_SCHEME,
        "serviceToken": service_token,
        "nodeId": node_id,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "term": term,
    }))
    .map_err(|error| {
        CliError::Other(format!(
            "failed to encode cluster peer auth payload: {error}"
        ))
    })?;
    Ok(sha256_hex(&payload))
}

fn validate_cluster_peer_auth(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    endpoint: &str,
) -> Result<ClusterPeerAuthContext, Response> {
    let node_id = headers
        .get(CLUSTER_NODE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| normalize_cluster_url(value).ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let issued_at = headers
        .get(CLUSTER_AUTH_ISSUED_AT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let signature = headers
        .get(CLUSTER_AUTH_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(cluster_peer_auth_error)?;
    let term = headers
        .get(CLUSTER_AUTH_TERM_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                plain_http_error(StatusCode::UNAUTHORIZED, "invalid cluster peer term header")
            })
        })
        .transpose()?;
    let unverified_failure_key = cluster_peer_auth_unverified_failure_key(&node_id, endpoint);
    let allowlisted = config
        .peer_urls
        .iter()
        .filter_map(|peer_url| normalize_cluster_url(peer_url).ok())
        .any(|peer_url| peer_url == node_id);
    if !allowlisted {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "cluster peer is not in the configured allowlist",
        ));
    }
    let now = unix_timestamp_now() as i64;
    let expected =
        cluster_peer_auth_signature(&config.service_token, &node_id, endpoint, issued_at, term)
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
    if !bool::from(signature.as_bytes().ct_eq(expected.as_bytes())) {
        if cluster_peer_auth_is_rate_limited(&unverified_failure_key, now as u64) {
            let mut response = plain_http_error(
                StatusCode::TOO_MANY_REQUESTS,
                "cluster peer authentication temporarily rate limited after repeated invalid signatures",
            );
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("60"),
            );
            return Err(response);
        }
        record_cluster_peer_auth_failure(&unverified_failure_key);
        return Err(cluster_peer_auth_error());
    }
    if cluster_peer_auth_is_rate_limited(&node_id, now as u64) {
        let mut response = plain_http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "cluster peer authentication temporarily rate limited after repeated verified failures",
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("60"),
        );
        return Err(response);
    }
    if issued_at > now.saturating_add(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp is in the future",
        ));
    }
    if issued_at < now.saturating_sub(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp expired outside the allowed skew window",
        ));
    }
    clear_cluster_peer_auth_failures(&node_id);
    Ok(ClusterPeerAuthContext {
        node_id,
        issued_at,
        term,
    })
}

fn cluster_peer_auth_error() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid cluster peer authentication",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(CLUSTER_AUTH_SCHEME),
    );
    response
}

fn validate_authority_mutation_auth(
    headers: &HeaderMap,
    state: &TrustServiceState,
    endpoint: &str,
) -> Result<Option<ClusterPeerAuthContext>, Response> {
    let has_cluster_peer_headers = headers.contains_key(CLUSTER_NODE_ID_HEADER)
        || headers.contains_key(CLUSTER_AUTH_ISSUED_AT_HEADER)
        || headers.contains_key(CLUSTER_AUTH_SIGNATURE_HEADER)
        || headers.contains_key(CLUSTER_AUTH_TERM_HEADER);
    if has_cluster_peer_headers {
        let peer = validate_cluster_peer_auth(headers, &state.config, endpoint)?;
        let Some(term) = peer.term else {
            return Err(plain_http_error(
                StatusCode::UNAUTHORIZED,
                "cluster authority mutation is missing the forwarded term",
            ));
        };
        let Some(authority_lease) = cluster_authority_lease_view(state) else {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster authority lease is unavailable for authority mutation",
            ));
        };
        if !authority_lease.lease_valid {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster authority lease expired before authority mutation",
            ));
        }
        if term != authority_lease.term {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "cluster authority mutation term does not match the current lease",
            ));
        }
        return Ok(Some(peer));
    }
    validate_service_auth(headers, &state.config.service_token)?;
    Ok(None)
}

fn enforce_authority_mutation_fence(
    state: &TrustServiceState,
) -> Result<Option<ClusterAuthorityLeaseView>, Response> {
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(None);
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority mutation",
        ));
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        SqliteCapabilityAuthority::open(path)
            .and_then(|authority| {
                authority.enforce_cluster_fence(&authority_lease.leader_url, authority_lease.term)
            })
            .map_err(|error| plain_http_error(StatusCode::CONFLICT, &error.to_string()))?;
    }
    Ok(Some(authority_lease))
}

fn refresh_authority_mutation_fence(state: &TrustServiceState) -> Result<(), Response> {
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(());
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority fence refresh",
        ));
    }
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    SqliteCapabilityAuthority::open(path)
        .and_then(|authority| {
            authority.seed_cluster_fence(Some(&authority_lease.leader_url), authority_lease.term)
        })
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    Ok(())
}

fn validate_service_auth(headers: &HeaderMap, service_token: &str) -> Result<(), Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if bool::from(provided.as_bytes().ct_eq(service_token.as_bytes())) {
        return Ok(());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid control bearer token",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    Err(response)
}

fn validate_metered_billing_reconciliation_request(
    request: &MeteredBillingReconciliationUpdateRequest,
) -> Result<(), String> {
    if request.receipt_id.trim().is_empty() {
        return Err("receiptId must not be empty".to_string());
    }
    if request.adapter_kind.trim().is_empty() {
        return Err("adapterKind must not be empty".to_string());
    }
    if request.evidence_id.trim().is_empty() {
        return Err("evidenceId must not be empty".to_string());
    }
    if request.observed_units == 0 {
        return Err("observedUnits must be greater than zero".to_string());
    }
    if request.billed_cost.units == 0 {
        return Err("billedCost.units must be greater than zero".to_string());
    }
    if request.billed_cost.currency.trim().is_empty() {
        return Err("billedCost.currency must not be empty".to_string());
    }
    if request.recorded_at == 0 {
        return Err("recordedAt must be greater than zero".to_string());
    }
    if request
        .evidence_sha256
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("evidenceSha256 must not be empty when provided".to_string());
    }
    Ok(())
}

fn load_capability_authority(
    config: &TrustServiceConfig,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    match (config.authority_seed_path.as_deref(), config.authority_db_path.as_deref()) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)
                .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
            Ok(issuance::wrap_capability_authority(
                Box::new(LocalCapabilityAuthority::new(keypair)),
                config.issuance_policy.clone(),
                config.runtime_assurance_policy.clone(),
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            ))
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open(path)
            .map(|authority| {
                issuance::wrap_capability_authority(
                    Box::new(authority),
                    config.issuance_policy.clone(),
                    config.runtime_assurance_policy.clone(),
                    config.receipt_db_path.as_deref(),
                    config.budget_db_path.as_deref(),
                )
            })
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }),
        (None, None) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        )),
    }
}

fn load_authority_status(config: &TrustServiceConfig) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Ok(TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        });
    };
    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Ok(None) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn rotate_authority(config: &TrustServiceConfig) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        ));
    };
    match rotate_authority_keypair(path) {
        Ok(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn authority_status_response(backend: String, status: AuthorityStatus) -> TrustAuthorityStatus {
    TrustAuthorityStatus {
        configured: true,
        backend: Some(backend),
        public_key: Some(status.public_key.to_hex()),
        generation: Some(status.generation),
        rotated_at: Some(status.rotated_at),
        applies_to_future_sessions_only: true,
        trusted_public_keys: status
            .trusted_public_keys
            .into_iter()
            .map(|public_key| public_key.to_hex())
            .collect(),
    }
}

#[derive(Default)]
struct ResolvedBudgetGrant {
    tool_server: Option<String>,
    tool_name: Option<String>,
    max_invocations: Option<u32>,
    max_total_cost_units: Option<u64>,
    currency: Option<String>,
    scope_resolved: bool,
    scope_resolution_error: Option<String>,
}

fn build_operator_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<OperatorReport, Response> {
    let activity = receipt_store
        .query_receipt_analytics(&query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let cost_attribution = receipt_store
        .query_cost_attribution_report(&query.to_cost_attribution_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let budget_utilization = build_budget_utilization_report(receipt_store, budget_store, query)?;
    let compliance = receipt_store
        .query_compliance_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let settlement_reconciliation = receipt_store
        .query_settlement_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let metered_billing_reconciliation = receipt_store
        .query_metered_billing_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let authorization_context = receipt_store
        .query_authorization_context_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;

    Ok(OperatorReport {
        generated_at: unix_timestamp_now(),
        filters: query.clone(),
        activity,
        cost_attribution,
        budget_utilization,
        compliance,
        settlement_reconciliation,
        metered_billing_reconciliation,
        authorization_context,
        shared_evidence,
    })
}

pub fn build_signed_behavioral_feed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
) -> Result<SignedBehavioralFeed, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_behavioral_feed_report(&receipt_store, receipt_db_path, budget_db_path, query)
            .map_err(|response| CliError::Other(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedBehavioralFeed::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_runtime_attestation_appraisal_report(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
    let report = build_runtime_attestation_appraisal_report(runtime_assurance_policy, evidence)
        .map_err(|response| CliError::Other(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedRuntimeAttestationAppraisalReport::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_runtime_attestation_appraisal_result(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    request: &RuntimeAttestationAppraisalResultExportRequest,
) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
    let result = build_runtime_attestation_appraisal_result(runtime_assurance_policy, request)
        .map_err(|response| CliError::Other(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedRuntimeAttestationAppraisalResult::sign(result, &keypair).map_err(Into::into)
}

fn build_runtime_attestation_appraisal_report(
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisalReport, Response> {
    let appraisal = derive_runtime_attestation_appraisal(evidence)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let trust_policy =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy.as_ref());
    let policy_outcome = match trust_policy {
        Some(policy) => {
            match evidence.resolve_effective_runtime_assurance(Some(policy), generated_at) {
                Ok(resolved) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: true,
                    effective_tier: resolved.effective_tier,
                    reason: None,
                },
                Err(error) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: false,
                    effective_tier: RuntimeAssuranceTier::None,
                    reason: Some(error.to_string()),
                },
            }
        }
        None => RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: true,
            effective_tier: evidence.tier,
            reason: None,
        },
    };

    Ok(RuntimeAttestationAppraisalReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
        generated_at,
        appraisal,
        policy_outcome,
    })
}

fn build_runtime_attestation_appraisal_result(
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    request: &RuntimeAttestationAppraisalResultExportRequest,
) -> Result<RuntimeAttestationAppraisalResult, Response> {
    let report = build_runtime_attestation_appraisal_report(
        runtime_assurance_policy,
        &request.runtime_attestation,
    )?;
    RuntimeAttestationAppraisalResult::from_report(&request.issuer, &report)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))
}

pub fn build_runtime_attestation_appraisal_import_report(
    request: &RuntimeAttestationAppraisalImportRequest,
    now: u64,
) -> RuntimeAttestationAppraisalImportReport {
    evaluate_imported_runtime_attestation_appraisal(request, now)
}

fn build_behavioral_feed_report(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
) -> Result<BehavioralFeedReport, Response> {
    let normalized_query = query.normalized();
    let operator_query = normalized_query.to_operator_report_query();
    let activity = receipt_store
        .query_receipt_analytics(&operator_query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let compliance = receipt_store
        .query_compliance_report(&operator_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&operator_query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let (settlements, governed_actions, metered_billing, selection) = receipt_store
        .query_behavioral_feed_receipts(&normalized_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let reputation = match normalized_query.agent_subject.as_deref() {
        Some(subject_key) => Some(
            reputation::build_behavioral_feed_reputation_summary(
                receipt_db_path,
                budget_db_path,
                subject_key,
                normalized_query.since,
                normalized_query.until,
                generated_at,
            )
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?,
        ),
        None => None,
    };

    Ok(BehavioralFeedReport {
        schema: BEHAVIORAL_FEED_SCHEMA.to_string(),
        generated_at,
        filters: normalized_query,
        privacy: BehavioralFeedPrivacyBoundary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: selection.receipts.len() as u64,
            direct_evidence_export_supported: compliance.direct_evidence_export_supported,
            child_receipt_scope: compliance.child_receipt_scope,
            proofs_complete: compliance.proofs_complete,
            export_query: compliance.export_query,
            export_scope_note: compliance.export_scope_note,
        },
        decisions: BehavioralFeedDecisionSummary {
            allow_count: activity.summary.allow_count,
            deny_count: activity.summary.deny_count,
            cancelled_count: activity.summary.cancelled_count,
            incomplete_count: activity.summary.incomplete_count,
        },
        settlements,
        governed_actions,
        metered_billing,
        reputation,
        shared_evidence: shared_evidence.summary,
        receipts: selection.receipts,
    })
}

pub fn build_signed_exposure_ledger_report(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedExposureLedgerReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_exposure_ledger_report(&receipt_store, query).map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedExposureLedgerReport::sign(report, &keypair).map_err(Into::into)
}

fn build_economic_completion_flow_report(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
) -> Result<EconomicCompletionFlowReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    receipt_store
        .query_economic_completion_flow_report(&normalized_query)
        .map_err(trust_http_error_from_receipt_store)
}

fn build_exposure_ledger_report(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
) -> Result<ExposureLedgerReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let decision_report = receipt_store
        .query_underwriting_decisions(&UnderwritingDecisionQuery {
            decision_id: None,
            capability_id: normalized_query.capability_id.clone(),
            agent_subject: normalized_query.agent_subject.clone(),
            tool_server: normalized_query.tool_server.clone(),
            tool_name: normalized_query.tool_name.clone(),
            outcome: None,
            lifecycle_state: None,
            appeal_status: None,
            limit: normalized_query.decision_limit,
        })
        .map_err(trust_http_error_from_receipt_store)?;

    let mut positions_by_currency = BTreeMap::<String, ExposureLedgerCurrencyPosition>::new();
    let mut receipts = Vec::with_capacity(selection.receipts.len());
    let mut actionable_receipts = 0_u64;
    let mut pending_settlement_receipts = 0_u64;
    let mut failed_settlement_receipts = 0_u64;

    for receipt in &selection.receipts {
        let entry = build_exposure_ledger_receipt_entry(receipt)?;
        let settlement_status = entry.settlement_status.clone();
        if entry.action_required {
            actionable_receipts += 1;
        }
        match &settlement_status {
            SettlementStatus::Pending => pending_settlement_receipts += 1,
            SettlementStatus::Failed => failed_settlement_receipts += 1,
            SettlementStatus::NotApplicable | SettlementStatus::Settled => {}
        }
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.governed_max_amount.as_ref(),
            |position, amount| {
                position.governed_max_exposure_units = position
                    .governed_max_exposure_units
                    .saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.reserve_required_amount.as_ref(),
            |position, amount| {
                position.reserved_units = position.reserved_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.provisional_loss_amount.as_ref(),
            |position, amount| {
                position.provisional_loss_units =
                    position.provisional_loss_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.recovered_amount.as_ref(),
            |position, amount| {
                position.recovered_units = position.recovered_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.financial_amount.as_ref(),
            |position, amount| match settlement_status {
                SettlementStatus::Settled => {
                    position.settled_units = position.settled_units.saturating_add(amount.units);
                }
                SettlementStatus::Pending => {
                    position.pending_units = position.pending_units.saturating_add(amount.units);
                }
                SettlementStatus::Failed => {
                    position.failed_units = position.failed_units.saturating_add(amount.units);
                }
                SettlementStatus::NotApplicable => {}
            },
        );
        receipts.push(entry);
    }

    let mut decisions = Vec::with_capacity(decision_report.decisions.len());
    for row in &decision_report.decisions {
        let entry = build_exposure_ledger_decision_entry(row);
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.quoted_premium_amount.as_ref(),
            |position, amount| {
                position.quoted_premium_units =
                    position.quoted_premium_units.saturating_add(amount.units);
                if entry.lifecycle_state == chio_kernel::UnderwritingDecisionLifecycleState::Active {
                    position.active_quoted_premium_units = position
                        .active_quoted_premium_units
                        .saturating_add(amount.units);
                }
            },
        );
        decisions.push(entry);
    }

    let currencies = positions_by_currency.keys().cloned().collect::<Vec<_>>();
    Ok(ExposureLedgerReport {
        schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: normalized_query,
        support_boundary: ExposureLedgerSupportBoundary::default(),
        summary: ExposureLedgerSummary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: receipts.len() as u64,
            matching_decisions: decision_report.summary.matching_decisions,
            returned_decisions: decisions.len() as u64,
            active_decisions: decision_report.summary.active_decisions,
            superseded_decisions: decision_report.summary.superseded_decisions,
            actionable_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
            currencies: currencies.clone(),
            mixed_currency_book: currencies.len() > 1,
            truncated_receipts: selection.matching_receipts > receipts.len() as u64,
            truncated_decisions: decision_report.summary.matching_decisions
                > decisions.len() as u64,
        },
        positions: positions_by_currency.into_values().collect(),
        receipts,
        decisions,
    })
}

pub fn build_signed_credit_scorecard_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedCreditScorecardReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_credit_scorecard_report(&receipt_store, receipt_db_path, budget_db_path, None, query)
            .map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCreditScorecardReport::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_capital_book_report(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &CapitalBookQuery,
) -> Result<SignedCapitalBookReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_capital_book_report_from_store(&receipt_store, query).map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCapitalBookReport::sign(report, &keypair).map_err(Into::into)
}

pub fn issue_signed_capital_execution_instruction(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CapitalExecutionInstructionRequest,
) -> Result<SignedCapitalExecutionInstruction, CliError> {
    issue_signed_capital_execution_instruction_detailed(
        receipt_db_path,
        authority_seed_path,
        authority_db_path,
        request,
    )
    .map_err(CliError::from)
}

fn issue_signed_capital_execution_instruction_detailed(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CapitalExecutionInstructionRequest,
) -> Result<SignedCapitalExecutionInstruction, TrustHttpError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let artifact =
        build_capital_execution_instruction_artifact_from_store(&receipt_store, request)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCapitalExecutionInstruction::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))
}

pub fn issue_signed_capital_allocation_decision(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
) -> Result<SignedCapitalAllocationDecision, CliError> {
    issue_signed_capital_allocation_decision_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        request,
    )
    .map_err(CliError::from)
}

fn issue_signed_capital_allocation_decision_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
) -> Result<SignedCapitalAllocationDecision, TrustHttpError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let artifact = build_capital_allocation_decision_artifact_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        request,
    )?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCapitalAllocationDecision::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))
}

#[allow(clippy::too_many_lines)]
fn build_capital_allocation_decision_artifact_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &CapitalAllocationDecisionRequest,
) -> Result<CapitalAllocationDecisionArtifact, TrustHttpError> {
    let issued_at = unix_timestamp_now();
    let normalized_query = request.query.normalized();
    normalized_query
        .validate()
        .map_err(TrustHttpError::bad_request)?;
    validate_capital_execution_envelope(
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        issued_at,
    )?;

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let governed_receipt =
        select_capital_allocation_receipt(&selection.receipts, request.receipt_id.as_deref())?;
    let governed_metadata = governed_receipt.governed.as_ref().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital allocation receipt `{}` is missing governed metadata",
                governed_receipt.receipt_id
            ),
        )
    })?;
    let requested_amount = governed_metadata.max_amount.clone().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital allocation receipt `{}` is missing governed max_amount",
                governed_receipt.receipt_id
            ),
        )
    })?;
    let exposure_receipt = build_exposure_ledger_receipt_entry(governed_receipt)?;
    let exposure = build_exposure_ledger_report(receipt_store, &normalized_query.exposure_query())?;
    let capital_book = build_capital_book_report_from_store(receipt_store, &normalized_query)?;
    let active_facility = latest_active_granted_credit_facility(
        receipt_store,
        normalized_query.capability_id.as_deref(),
        normalized_query.agent_subject.as_deref(),
        normalized_query.tool_server.as_deref(),
        normalized_query.tool_name.as_deref(),
    )?;
    let fallback_facility_report = if active_facility.is_none() {
        Some(build_credit_facility_report_from_store(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            None,
            &normalized_query.exposure_query(),
        )?)
    } else {
        None
    };
    let facility_disposition = active_facility.as_ref().map_or_else(
        || {
            fallback_facility_report
                .as_ref()
                .map(|report| report.disposition)
                .unwrap_or(CreditFacilityDisposition::ManualReview)
        },
        |_| CreditFacilityDisposition::Grant,
    );
    let facility_source = capital_book
        .sources
        .iter()
        .find(|source| source.kind == CapitalBookSourceKind::FacilityCommitment);
    let reserve_source = capital_book
        .sources
        .iter()
        .find(|source| source.kind == CapitalBookSourceKind::ReserveBook);

    ensure_capital_execution_custodian_authority(&request.authority_chain, &request.rail)?;
    if let Some(source) = facility_source {
        ensure_capital_execution_owner_authority(
            &request.authority_chain,
            capital_execution_role_from_book_role(source.owner_role),
        )?;
    }

    let position = exposure
        .positions
        .iter()
        .find(|position| position.currency == requested_amount.currency);
    let current_outstanding_units = position.map(credit_bond_outstanding_units).unwrap_or(0);
    let current_outstanding_amount =
        amount_if_nonzero(current_outstanding_units, &requested_amount.currency);

    let facility_terms = active_facility
        .as_ref()
        .and_then(|facility| facility.body.report.terms.as_ref())
        .or_else(|| {
            fallback_facility_report
                .as_ref()
                .and_then(|report| report.terms.as_ref())
        });
    let utilization_ceiling_units = facility_terms
        .map(|terms| {
            capital_allocation_ceiling_units(
                terms.credit_limit.units,
                terms.utilization_ceiling_bps,
            )
        })
        .unwrap_or(0);
    let concentration_cap_units = facility_terms
        .map(|terms| {
            capital_allocation_ceiling_units(terms.credit_limit.units, terms.concentration_cap_bps)
        })
        .unwrap_or(0);
    let current_reserve_units = reserve_source
        .and_then(|source| source.held_amount.as_ref().map(|amount| amount.units))
        .unwrap_or(0);
    let required_reserve_units = facility_terms
        .map(|terms| credit_bond_reserve_units(current_outstanding_units, terms.reserve_ratio_bps))
        .unwrap_or(0);
    let reserve_delta_units = required_reserve_units.saturating_sub(current_reserve_units);

    let mut evidence_refs =
        capital_book_evidence_from_exposure_refs(&exposure_receipt.evidence_refs);
    if let Some(source) = facility_source {
        if let Some(facility_id) = source.facility_id.as_ref() {
            push_unique_capital_book_evidence(
                &mut evidence_refs,
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditFacility,
                    reference_id: facility_id.clone(),
                    observed_at: Some(issued_at),
                    locator: Some(format!("credit-facility:{facility_id}")),
                },
            );
        }
    }
    if let Some(source) = reserve_source {
        if let Some(bond_id) = source.bond_id.as_ref() {
            push_unique_capital_book_evidence(
                &mut evidence_refs,
                CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditBond,
                    reference_id: bond_id.clone(),
                    observed_at: Some(issued_at),
                    locator: Some(format!("credit-bond:{bond_id}")),
                },
            );
        }
    }

    let mut findings = Vec::new();
    let mut instruction_drafts = Vec::new();
    let outcome = match facility_disposition {
        CreditFacilityDisposition::Deny => {
            findings.push(CapitalAllocationDecisionFinding {
                code: CapitalAllocationDecisionReasonCode::FacilityDenied,
                description:
                    "facility policy denied live capital allocation for the governed action"
                        .to_string(),
                evidence_refs: evidence_refs.clone(),
            });
            CapitalAllocationDecisionOutcome::Deny
        }
        CreditFacilityDisposition::ManualReview => {
            findings.push(CapitalAllocationDecisionFinding {
                code: CapitalAllocationDecisionReasonCode::FacilityManualReview,
                description:
                    "facility policy requires manual review before Chio can allocate live capital"
                        .to_string(),
                evidence_refs: evidence_refs.clone(),
            });
            CapitalAllocationDecisionOutcome::ManualReview
        }
        CreditFacilityDisposition::Grant => {
            let facility_terms = facility_terms.ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "capital allocation requires facility grant terms when disposition is grant",
                )
            })?;
            if facility_terms.credit_limit.currency != requested_amount.currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital allocation facility currency `{}` does not match requested currency `{}`",
                        facility_terms.credit_limit.currency, requested_amount.currency
                    ),
                ));
            }
            if facility_terms.capital_source == CreditFacilityCapitalSource::ManualProviderReview {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ManualCapitalSource,
                    description:
                        "the granted facility still resolves to manual provider review rather than operator-internal live allocation"
                            .to_string(),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::ManualReview
            } else if requested_amount.units > concentration_cap_units {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ConcentrationCapExceeded,
                    description: format!(
                        "requested governed amount {} exceeds the single-allocation concentration cap {}",
                        requested_amount.units, concentration_cap_units
                    ),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::Deny
            } else if current_outstanding_units > utilization_ceiling_units {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::UtilizationCeilingExceeded,
                    description: format!(
                        "current outstanding exposure {} exceeds the live utilization ceiling {}",
                        current_outstanding_units, utilization_ceiling_units
                    ),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::Queue
            } else if reserve_delta_units > 0 && reserve_source.is_none() {
                findings.push(CapitalAllocationDecisionFinding {
                    code: CapitalAllocationDecisionReasonCode::ReserveBookMissing,
                    description:
                        "allocation would require additional reserve backing, but no current reserve book is available for custody-neutral execution"
                            .to_string(),
                    evidence_refs: evidence_refs.clone(),
                });
                CapitalAllocationDecisionOutcome::ManualReview
            } else {
                let facility_source = facility_source.ok_or_else(|| {
                    TrustHttpError::new(
                        StatusCode::CONFLICT,
                        "capital allocation requires a current facility source after facility grant",
                    )
                })?;
                instruction_drafts.push(CapitalAllocationInstructionDraft {
                    source_id: facility_source.source_id.clone(),
                    source_kind: CapitalBookSourceKind::FacilityCommitment,
                    action: CapitalExecutionInstructionAction::TransferFunds,
                    amount: requested_amount.clone(),
                    description:
                        "transfer the governed amount from the selected committed capital source"
                            .to_string(),
                });
                if reserve_delta_units > 0 {
                    let reserve_source = reserve_source.ok_or_else(|| {
                        TrustHttpError::new(
                            StatusCode::CONFLICT,
                            "capital allocation requires a current reserve source for additional reserve movement",
                        )
                    })?;
                    instruction_drafts.push(CapitalAllocationInstructionDraft {
                        source_id: reserve_source.source_id.clone(),
                        source_kind: CapitalBookSourceKind::ReserveBook,
                        action: CapitalExecutionInstructionAction::LockReserve,
                        amount: MonetaryAmount {
                            units: reserve_delta_units,
                            currency: requested_amount.currency.clone(),
                        },
                        description:
                            "lock incremental reserve required by the selected governed action"
                                .to_string(),
                    });
                }
                CapitalAllocationDecisionOutcome::Allocate
            }
        }
    };

    let description = request.description.clone().unwrap_or_else(|| {
        format!(
            "{:?} live capital allocation for governed receipt `{}`",
            outcome, governed_receipt.receipt_id
        )
    });
    let allocation_id_input = canonical_json_bytes(&(
        CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA,
        &normalized_query,
        &governed_receipt.receipt_id,
        &requested_amount,
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        &outcome,
        &instruction_drafts,
        &description,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let allocation_id = format!("cad-{}", sha256_hex(&allocation_id_input));

    Ok(CapitalAllocationDecisionArtifact {
        schema: CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA.to_string(),
        allocation_id,
        issued_at,
        query: normalized_query,
        subject_key: governed_receipt
            .subject_key
            .clone()
            .or_else(|| request.query.agent_subject.clone())
            .ok_or_else(|| {
                TrustHttpError::bad_request(
                    "capital allocation requires --agent-subject for subject-scoped capital truth",
                )
            })?,
        governed_receipt_id: governed_receipt.receipt_id.clone(),
        intent_id: governed_metadata.intent_id.clone(),
        approval_token_id: governed_metadata
            .approval
            .as_ref()
            .map(|approval| approval.token_id.clone()),
        capability_id: governed_receipt.capability_id.clone(),
        tool_server: governed_receipt.tool_server.clone(),
        tool_name: governed_receipt.tool_name.clone(),
        requested_amount: requested_amount.clone(),
        facility_id: facility_source.and_then(|source| source.facility_id.clone()),
        bond_id: reserve_source
            .and_then(|source| source.bond_id.clone())
            .or_else(|| facility_source.and_then(|source| source.bond_id.clone())),
        source_id: facility_source.map(|source| source.source_id.clone()),
        source_kind: facility_source.map(|source| source.kind),
        reserve_source_id: reserve_source.map(|source| source.source_id.clone()),
        outcome,
        authority_chain: request.authority_chain.clone(),
        execution_window: request.execution_window.clone(),
        rail: request.rail.clone(),
        current_outstanding_amount: current_outstanding_amount.clone(),
        projected_outstanding_amount: current_outstanding_amount,
        current_reserve_amount: amount_if_nonzero(
            current_reserve_units,
            &requested_amount.currency,
        ),
        required_reserve_amount: amount_if_nonzero(
            required_reserve_units,
            &requested_amount.currency,
        ),
        reserve_delta_amount: amount_if_nonzero(reserve_delta_units, &requested_amount.currency),
        utilization_ceiling_amount: amount_if_nonzero(
            utilization_ceiling_units,
            &requested_amount.currency,
        ),
        concentration_cap_amount: amount_if_nonzero(
            concentration_cap_units,
            &requested_amount.currency,
        ),
        instruction_drafts,
        support_boundary: CapitalAllocationDecisionSupportBoundary::default(),
        findings,
        evidence_refs,
        description,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod cluster_and_reports_tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn base_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().expect("parse listen addr"),
            service_token: "token".to_string(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
        }
    }

    fn state_with_cluster(
        advertise_url: &str,
        peer_urls: &[&str],
        receipt_db_path: Option<PathBuf>,
        revocation_db_path: Option<PathBuf>,
        budget_db_path: Option<PathBuf>,
    ) -> TrustServiceState {
        let mut config = base_config();
        config.advertise_url = Some(advertise_url.to_string());
        config.peer_urls = peer_urls.iter().map(|value| value.to_string()).collect();
        config.receipt_db_path = receipt_db_path;
        config.revocation_db_path = revocation_db_path;
        config.budget_db_path = budget_db_path;
        let cluster =
            build_cluster_state(&config, config.listen).expect("build cluster runtime state");
        TrustServiceState {
            config,
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            cluster,
        }
    }

    fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }

    fn sample_tool_receipt(id: &str, capability_id: &str) -> ChioReceipt {
        let keypair = Keypair::generate();
        let parameters = json!({"message": "cluster"});
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp: 11,
                capability_id: capability_id.to_string(),
                tool_server: "wrapped-http-mock".to_string(),
                tool_name: "echo_json".to_string(),
                action: ToolCallAction::from_parameters(parameters).expect("hash parameters"),
                decision: Decision::Allow,
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign tool receipt")
    }

    fn sample_child_receipt(id: &str, suffix: &str) -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            chio_core::receipt::ChildRequestReceiptBody {
                id: id.to_string(),
                timestamp: 13,
                session_id: chio_core::session::SessionId::new(&format!("sess-{suffix}")),
                parent_request_id: chio_core::session::RequestId::new(&format!("parent-{suffix}")),
                request_id: chio_core::session::RequestId::new(&format!("child-{suffix}")),
                operation_kind: chio_core::session::OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                metadata: Some(json!({ "source": "cluster-test" })),
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign child receipt")
    }

    fn sample_capability(id: &str) -> CapabilityToken {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        CapabilityToken::sign(
            chio_core::capability::CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .expect("sign capability token")
    }

    #[test]
    fn build_cluster_state_validates_inputs_and_normalizes_peers() {
        let mut invalid = base_config();
        invalid.advertise_url = Some("http://127.0.0.1:3200".to_string());
        invalid.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
        invalid.authority_seed_path = Some(unique_temp_path("authority", "seed"));

        let error = build_cluster_state(&invalid, invalid.listen)
            .expect_err("clustered mode should reject authority seed files");
        assert!(error
            .to_string()
            .contains("--authority-db instead of --authority-seed-file"));

        assert!(
            build_cluster_state(&base_config(), "127.0.0.1:0".parse().unwrap())
                .expect("standalone without advertise URL")
                .is_none()
        );

        let mut standalone_advertised = base_config();
        standalone_advertised.allow_local_peer_urls = false;
        standalone_advertised.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        assert!(
            build_cluster_state(&standalone_advertised, standalone_advertised.listen)
                .expect("standalone advertise URL should not enable cluster validation")
                .is_none()
        );

        let mut config = base_config();
        config.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        config.peer_urls = vec![
            "http://127.0.0.1:3200/".to_string(),
            " http://127.0.0.1:3300/ ".to_string(),
            "http://127.0.0.1:3300".to_string(),
        ];

        let cluster = build_cluster_state(&config, config.listen)
            .expect("build cluster state")
            .expect("cluster should be enabled");
        let guard = cluster.lock().expect("cluster guard");
        assert_eq!(guard.self_url, "http://127.0.0.1:3200");
        assert_eq!(guard.peers.len(), 1);
        assert!(guard.peers.contains_key("http://127.0.0.1:3300"));
    }

    #[test]
    fn cluster_peer_url_validation_rejects_local_networks_by_default() {
        let error = normalize_cluster_config_url("http://127.0.0.1:3300", false)
            .expect_err("loopback cluster URLs require explicit local mode");
        assert!(error.to_string().contains("--allow-local-peer-urls"));

        let normalized = normalize_cluster_config_url(" http://127.0.0.1:3300/ ", true)
            .expect("local cluster mode permits loopback URLs");
        assert_eq!(normalized, "http://127.0.0.1:3300");
    }

    #[test]
    fn compute_cluster_consensus_tracks_role_quorum_and_election_terms() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([
                ("http://node-b".to_string(), PeerSyncState::default()),
                ("http://node-c".to_string(), PeerSyncState::default()),
            ]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let initial = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(initial.role, "candidate");
        assert!(!initial.has_quorum);
        assert_eq!(initial.quorum_size, 2);
        assert_eq!(initial.reachable_nodes, 1);
        assert_eq!(initial.election_term, 0);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &initial).is_none());

        cluster.peers.get_mut("http://node-b").unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-b")
            .unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let with_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(with_quorum.role, "leader");
        assert!(with_quorum.has_quorum);
        assert_eq!(with_quorum.leader_url.as_deref(), Some("http://node-a"));
        assert_eq!(with_quorum.reachable_nodes, 2);
        assert_eq!(with_quorum.election_term, 1);
        let with_quorum_lease = cluster_authority_lease_view_locked(&mut cluster, &with_quorum)
            .expect("authority lease");
        assert_eq!(with_quorum_lease.lease_epoch, 1);
        assert!(with_quorum_lease.lease_id.contains("http://node-a"));
        assert!(with_quorum_lease.lease_expires_at >= unix_timestamp_now());

        cluster.peers.get_mut("http://node-c").unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-c")
            .unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let stable = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(stable.role, "leader");
        assert_eq!(stable.election_term, 1);
        assert_eq!(stable.reachable_nodes, 3);

        cluster.peers.get_mut("http://node-b").unwrap().health = PeerHealth::Unhealthy;
        cluster.peers.get_mut("http://node-c").unwrap().health = PeerHealth::Unhealthy;
        let lost_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(lost_quorum.role, "candidate");
        assert!(!lost_quorum.has_quorum);
        assert_eq!(lost_quorum.election_term, 2);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &lost_quorum).is_none());
    }

    #[test]
    fn compute_cluster_consensus_drops_stale_peers_after_authority_lease_timeout() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([(
                "http://node-b".to_string(),
                PeerSyncState {
                    health: PeerHealth::Healthy,
                    last_contact_at: Some(unix_timestamp_now().saturating_sub(5)),
                    ..PeerSyncState::default()
                },
            )]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let consensus = compute_cluster_consensus_locked(&mut cluster);
        assert!(!consensus.has_quorum);
        assert_eq!(consensus.reachable_nodes, 1);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &consensus).is_none());
    }

    #[tokio::test]
    async fn leader_visibility_responses_add_cluster_metadata_and_reject_scalars() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");

        let response = json_response_with_leader_visibility(&state, json!({ "stored": true }));
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read JSON response body");
        let body: Value = serde_json::from_slice(&body).expect("decode JSON body");
        assert_eq!(body["stored"], Value::Bool(true));
        assert_eq!(
            body["handledBy"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(
            body["leaderUrl"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["visibleAtLeader"], Value::Bool(true));
        assert_eq!(
            body["clusterAuthority"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["clusterAuthority"]["term"], Value::from(1));
        assert_eq!(body["clusterAuthority"]["leaseValid"], Value::Bool(true));

        let scalar = json_response_with_leader_visibility(&state, "not-an-object");
        assert_eq!(scalar.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(scalar.into_body(), usize::MAX)
            .await
            .expect("read scalar error body");
        let text = String::from_utf8(body.to_vec()).expect("decode error body");
        assert!(text.contains("success responses must be JSON objects"));
    }

    #[tokio::test]
    async fn budget_quorum_commit_metadata_tracks_quorum_witnesses() {
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        update_peer_budget_cursor(
            &state,
            "http://node-b",
            BudgetCursor {
                seq: 9,
                updated_at: 14,
                capability_id: "cap-1".to_string(),
                grant_index: 0,
            },
        );
        update_peer_budget_cursor(
            &state,
            "http://node-c",
            BudgetCursor {
                seq: 7,
                updated_at: 12,
                capability_id: "cap-1".to_string(),
                grant_index: 0,
            },
        );

        let commit = budget_write_quorum_commit_view(&state, 8).expect("budget quorum commit");
        assert!(commit.quorum_committed);
        assert_eq!(commit.quorum_size, 2);
        assert_eq!(commit.committed_nodes, 2);
        assert_eq!(
            commit.witness_urls,
            vec!["http://node-a".to_string(), "http://node-b".to_string()]
        );

        let response = json_response_with_leader_visibility_and_budget_commit(
            &state,
            json!({ "allowed": true }),
            Some(commit),
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read quorum commit response body");
        let body: Value = serde_json::from_slice(&body).expect("decode quorum commit body");
        assert_eq!(body["budgetCommit"]["budgetSeq"], Value::from(8));
        assert_eq!(body["budgetCommit"]["commitIndex"], Value::from(8));
        assert_eq!(body["budgetCommit"]["quorumCommitted"], Value::Bool(true));
        assert_eq!(body["budgetCommit"]["committedNodes"], Value::from(2));
        assert_eq!(
            body["budgetCommit"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["budgetCommit"]["budgetTerm"], Value::from(1));
        assert_eq!(
            body["budgetCommit"]["witnessUrls"],
            json!(["http://node-a", "http://node-b"])
        );
    }

    #[test]
    fn peer_state_helpers_update_health_cursors_and_snapshot_thresholds() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);

        update_peer_reachable(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );

        update_peer_sync_error(&state, "http://node-b", "lagging".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.last_error.clone()),
            Some(Some("lagging".to_string()))
        );

        update_peer_failure(&state, "http://node-b", "offline".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("unhealthy")
        );
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_success(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_revocation_cursor(
            &state,
            "http://node-b",
            RevocationCursor {
                revoked_at: 5,
                capability_id: "cap-1".to_string(),
            },
        );
        update_peer_budget_cursor(
            &state,
            "http://node-b",
            BudgetCursor {
                seq: 8,
                updated_at: 13,
                capability_id: "cap-1".to_string(),
                grant_index: 2,
            },
        );
        update_peer_tool_seq(&state, "http://node-b", 3);
        update_peer_child_seq(&state, "http://node-b", 4);
        update_peer_lineage_seq(&state, "http://node-b", 5);
        update_peer_delta_records(
            &state,
            "http://node-b",
            CLUSTER_SNAPSHOT_RECORD_THRESHOLD - 1,
        );
        assert_eq!(peer_tool_seq(&state, "http://node-b"), 3);
        assert_eq!(peer_child_seq(&state, "http://node-b"), 4);
        assert_eq!(peer_lineage_seq(&state, "http://node-b"), 5);
        assert_eq!(
            peer_revocation_cursor(&state, "http://node-b")
                .expect("revocation cursor")
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            peer_budget_cursor(&state, "http://node-b")
                .expect("budget cursor")
                .grant_index,
            2
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_delta_records(&state, "http://node-b", 1);
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        assert!(budget_visibility_matches(true, Some(1), Some(2)));
        assert!(!budget_visibility_matches(true, None, Some(2)));
        assert!(budget_visibility_matches(false, Some(2), Some(2)));
        assert!(budget_visibility_matches(false, Some(1), None));
        assert!(!budget_visibility_matches(false, None, Some(3)));
    }

    #[test]
    fn auth_helpers_and_metered_billing_validation_cover_error_paths() {
        let mut headers = HeaderMap::new();
        let auth_error = bearer_token_from_headers(&headers).expect_err("missing bearer token");
        assert_eq!(auth_error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            auth_error
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"chio-passport-issuance\"")
        );

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer issue-token"),
        );
        assert_eq!(
            bearer_token_from_headers(&headers).expect("extract bearer token"),
            "issue-token"
        );
        assert!(validate_service_auth(&headers, "issue-token").is_ok());

        let invalid_auth = validate_service_auth(&headers, "other-token")
            .expect_err("mismatched control token should fail");
        assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            invalid_auth
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let cluster_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            None,
        )
        .expect("cluster peer signature");
        headers.clear();
        headers.insert(
            CLUSTER_NODE_ID_HEADER,
            HeaderValue::from_static("http://node-b"),
        );
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).expect("issued-at header"),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).expect("signature header"),
        );
        let peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .expect("validate allowlisted cluster peer");
        assert_eq!(peer.node_id, "http://node-b");

        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef"),
        );
        let invalid_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .expect_err("invalid cluster peer signature should fail");
        assert_eq!(invalid_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let expired_issued_at = issued_at - (CLUSTER_AUTH_MAX_SKEW_SECS as i64) - 1;
        let expired_signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            expired_issued_at,
            None,
        )
        .expect("expired cluster peer signature");
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&expired_issued_at.to_string()).expect("expired issued-at"),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&expired_signature).expect("expired signature header"),
        );
        let expired_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .expect_err("expired cluster peer auth should fail");
        assert_eq!(expired_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures("http://node-b");

        for attempt in 0..CLUSTER_AUTH_FAILURE_BURST {
            let invalid_issued_at = issued_at + attempt as i64;
            headers.insert(
                CLUSTER_AUTH_ISSUED_AT_HEADER,
                HeaderValue::from_str(&invalid_issued_at.to_string()).expect("issued-at header"),
            );
            headers.insert(
                CLUSTER_AUTH_SIGNATURE_HEADER,
                HeaderValue::from_str(&format!("deadbeef-{attempt}"))
                    .expect("invalid signature header"),
            );
            let response = validate_cluster_peer_auth(
                &headers,
                &cluster_state.config,
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .expect_err("invalid cluster peer signature should fail");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let limited_issued_at = issued_at + CLUSTER_AUTH_FAILURE_BURST as i64;
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&limited_issued_at.to_string()).expect("issued-at header"),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef-final"),
        );
        let limited_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .expect_err("repeated failures should trip rate limit");
        assert_eq!(limited_peer.status(), StatusCode::TOO_MANY_REQUESTS);
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).expect("issued-at header"),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).expect("signature header"),
        );
        let peer_after_spoofed_failures = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .expect("spoofed invalid signatures must not rate limit the verified peer");
        assert_eq!(peer_after_spoofed_failures.node_id, "http://node-b");
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));
        clear_cluster_peer_auth_failures("http://node-b");

        let mut request = MeteredBillingReconciliationUpdateRequest {
            receipt_id: "receipt-1".to_string(),
            adapter_kind: "usage-adapter".to_string(),
            evidence_id: "evidence-1".to_string(),
            observed_units: 3,
            billed_cost: MonetaryAmount {
                units: 25,
                currency: "USD".to_string(),
            },
            evidence_sha256: Some("digest".to_string()),
            recorded_at: 44,
            reconciliation_state: MeteredBillingReconciliationState::Open,
            note: None,
        };
        assert!(validate_metered_billing_reconciliation_request(&request).is_ok());

        request.receipt_id.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("receiptId must not be empty".to_string())
        );
        request.receipt_id = "receipt-1".to_string();
        request.observed_units = 0;
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("observedUnits must be greater than zero".to_string())
        );
        request.observed_units = 3;
        request.billed_cost.currency.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("billedCost.currency must not be empty".to_string())
        );
        request.billed_cost.currency = "USD".to_string();
        request.evidence_sha256 = Some(String::new());
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("evidenceSha256 must not be empty when provided".to_string())
        );
    }

    #[test]
    fn cluster_snapshot_round_trip_copies_receipts_revocations_lineage_and_budgets() {
        let source_receipt_db = unique_temp_path("cluster-source-receipts", "sqlite3");
        let source_revocation_db = unique_temp_path("cluster-source-revocations", "sqlite3");
        let source_budget_db = unique_temp_path("cluster-source-budgets", "sqlite3");
        let target_receipt_db = unique_temp_path("cluster-target-receipts", "sqlite3");
        let target_revocation_db = unique_temp_path("cluster-target-revocations", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            Some(source_receipt_db.clone()),
            Some(source_revocation_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(target_receipt_db.clone()),
            Some(target_revocation_db.clone()),
            Some(target_budget_db.clone()),
        );

        {
            let revocation_store = SqliteRevocationStore::open(&source_revocation_db)
                .expect("open source revocation db");
            revocation_store
                .upsert_revocation(&RevocationRecord {
                    capability_id: "cap-1".to_string(),
                    revoked_at: 17,
                })
                .expect("write revocation");
        }
        {
            let receipt_store =
                SqliteReceiptStore::open(&source_receipt_db).expect("open source receipt db");
            receipt_store
                .append_chio_receipt(&sample_tool_receipt("tool-1", "cap-1"))
                .expect("append tool receipt");
            receipt_store
                .append_child_receipt(&sample_child_receipt("child-1", "alpha"))
                .expect("append child receipt");
            receipt_store
                .record_capability_snapshot(&sample_capability("cap-1"), None)
                .expect("record capability snapshot");
        }
        {
            let budget_store =
                SqliteBudgetStore::open(&source_budget_db).expect("open source budget db");
            budget_store
                .try_charge_cost_with_ids(
                    "cap-1",
                    0,
                    Some(4),
                    9,
                    Some(9),
                    Some(32),
                    Some("hold-1"),
                    Some("hold-1:authorize"),
                )
                .expect("authorize budget exposure");
            budget_store
                .reduce_charge_cost_with_ids("cap-1", 0, 4, Some("hold-1"), Some("hold-1:release"))
                .expect("release budget exposure");
        }

        let snapshot = build_cluster_state_snapshot(&source_state).expect("build cluster snapshot");
        assert_eq!(snapshot.replication.tool_seq, 1);
        assert_eq!(snapshot.replication.child_seq, 1);
        assert_eq!(snapshot.replication.lineage_seq, 1);
        assert_eq!(snapshot.replication.budget_seq, 2);
        assert_eq!(snapshot.budget_mutation_events.len(), 2);
        assert_eq!(
            snapshot
                .budget_mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );
        assert_eq!(
            snapshot
                .replication
                .revocation_cursor
                .as_ref()
                .expect("revocation cursor")
                .capability_id,
            "cap-1"
        );

        let generated_at = snapshot.generated_at;
        apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
            .expect("apply cluster snapshot");

        let revocations = SqliteRevocationStore::open(&target_revocation_db)
            .expect("open target revocation db")
            .list_revocations_after(MAX_LIST_LIMIT, None, None)
            .expect("list replicated revocations");
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].capability_id, "cap-1");

        let receipt_store =
            SqliteReceiptStore::open(&target_receipt_db).expect("open target receipt db");
        assert_eq!(
            receipt_store
                .list_tool_receipts_after_seq(0, MAX_LIST_LIMIT)
                .expect("list replicated tool receipts")
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_child_receipts_after_seq(0, MAX_LIST_LIMIT)
                .expect("list replicated child receipts")
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_capability_snapshots_after_seq(0, MAX_LIST_LIMIT)
                .expect("list replicated lineage")
                .len(),
            1
        );

        let budgets = SqliteBudgetStore::open(&target_budget_db)
            .expect("open target budget db")
            .list_usages_after(MAX_LIST_LIMIT, None)
            .expect("list replicated budgets");
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0].invocation_count, 1);
        assert_eq!(budgets[0].total_cost_exposed, 5);
        assert_eq!(budgets[0].total_cost_realized_spend, 0);
        let mutation_events = SqliteBudgetStore::open(&target_budget_db)
            .expect("open target budget db")
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .expect("list replicated mutation events");
        assert_eq!(
            mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );

        assert_eq!(peer_tool_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_child_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_lineage_seq(&target_state, "http://node-a"), 1);
        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .expect("replicated budget cursor")
                .seq,
            2
        );
        assert_eq!(
            peer_revocation_cursor(&target_state, "http://node-a")
                .expect("replicated revocation cursor")
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer
                .snapshot_applied_count),
            Some(1)
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer.last_snapshot_at),
            Some(Some(generated_at))
        );
        assert!(!peer_should_force_snapshot(&target_state, "http://node-a"));
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_denied_budget_events_without_usage_rows() {
        let source_budget_db = unique_temp_path("cluster-source-denied-budgets", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-denied-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
            Some(target_budget_db.clone()),
        );

        {
            let budget_store =
                SqliteBudgetStore::open(&source_budget_db).expect("open source budget db");
            let allowed = budget_store
                .try_charge_cost_with_ids(
                    "cap-denied-only",
                    0,
                    Some(1),
                    25,
                    Some(50),
                    Some(10),
                    Some("cap-denied-only-hold-1"),
                    Some("cap-denied-only-hold-1:authorize"),
                )
                .expect("record denied budget mutation");
            assert!(!allowed);
            assert!(budget_store
                .list_usages_after(MAX_LIST_LIMIT, None)
                .expect("list source usages")
                .is_empty());
            let delta =
                collect_budget_mutation_event_views_after_seq(&budget_store, 0, MAX_LIST_LIMIT)
                    .expect("collect denied event delta");
            assert_eq!(delta.len(), 1);
            assert_eq!(delta[0].event_seq, 1);
            assert_eq!(delta[0].allowed, Some(false));
            assert_eq!(delta[0].usage_seq, None);
            assert!(collect_budget_mutation_event_views_after_seq(
                &budget_store,
                1,
                MAX_LIST_LIMIT
            )
            .expect("collect empty denied event delta")
            .is_empty());
        }

        let snapshot = build_cluster_state_snapshot(&source_state).expect("build cluster snapshot");
        assert_eq!(snapshot.replication.budget_seq, 1);
        assert!(snapshot.budgets.is_empty());
        assert_eq!(snapshot.budget_mutation_events.len(), 1);
        assert_eq!(
            snapshot.budget_mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(snapshot.budget_mutation_events[0].event_seq, 1);
        assert_eq!(snapshot.budget_mutation_events[0].allowed, Some(false));
        assert_eq!(snapshot.budget_mutation_events[0].usage_seq, None);

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
            .expect("apply cluster snapshot");

        let target_store =
            SqliteBudgetStore::open(&target_budget_db).expect("open target budget db");
        assert!(target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .expect("list target usages")
            .is_empty());
        let mutation_events = target_store
            .list_mutation_events(10, Some("cap-denied-only"), Some(0))
            .expect("list replicated denied events");
        assert_eq!(mutation_events.len(), 1);
        assert_eq!(
            mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(mutation_events[0].event_seq, 1);
        assert_eq!(mutation_events[0].allowed, Some(false));
        assert_eq!(mutation_events[0].usage_seq, None);
        drop(target_store);

        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .expect("replicated denied budget cursor")
                .seq,
            1
        );
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_budget_usage_rows_without_mutation_events() {
        let source_budget_db = unique_temp_path("cluster-source-budget-usage-only", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budget-usage-only", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
            Some(target_budget_db.clone()),
        );

        {
            let budget_store =
                SqliteBudgetStore::open(&source_budget_db).expect("open source budget db");
            budget_store
                .upsert_usage(&chio_kernel::BudgetUsageRecord {
                    capability_id: "cap-usage-only".to_string(),
                    grant_index: 0,
                    invocation_count: 7,
                    updated_at: 1_717_171_717,
                    seq: 42,
                    total_cost_exposed: 550,
                    total_cost_realized_spend: 375,
                })
                .expect("seed source usage row");
            assert!(budget_store
                .list_mutation_events(10, Some("cap-usage-only"), Some(0))
                .expect("list source mutation events")
                .is_empty());
        }

        update_peer_budget_cursor(
            &target_state,
            "http://node-a",
            BudgetCursor {
                seq: 99,
                updated_at: 1_717_171_718,
                capability_id: "stale-capability".to_string(),
                grant_index: 7,
            },
        );

        let snapshot = build_cluster_state_snapshot(&source_state).expect("build cluster snapshot");
        assert_eq!(snapshot.replication.budget_seq, 0);
        assert_eq!(snapshot.budgets.len(), 1);
        assert!(snapshot.budget_mutation_events.is_empty());
        assert_eq!(snapshot.budgets[0].capability_id, "cap-usage-only");
        assert_eq!(snapshot.budgets[0].seq, Some(42));

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
            .expect("apply cluster snapshot");

        let target_store =
            SqliteBudgetStore::open(&target_budget_db).expect("open target budget db");
        let usages = target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .expect("list target usages");
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].capability_id, "cap-usage-only");
        assert_eq!(usages[0].invocation_count, 7);
        assert_eq!(usages[0].seq, 42);
        assert_eq!(usages[0].total_cost_exposed, 550);
        assert_eq!(usages[0].total_cost_realized_spend, 375);
        assert!(target_store
            .list_mutation_events(10, Some("cap-usage-only"), Some(0))
            .expect("list replicated mutation events")
            .is_empty());
        drop(target_store);

        assert!(
            peer_budget_cursor(&target_state, "http://node-a").is_none(),
            "usage-only snapshots should clear any stale mutation cursor"
        );
    }

    #[test]
    fn budget_cursor_from_event_uses_mutation_event_sequence() {
        let cursor = budget_cursor_from_event(&BudgetMutationEventView {
            event_id: "evt-1".to_string(),
            hold_id: Some("hold-1".to_string()),
            capability_id: "cap-1".to_string(),
            grant_index: 2,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: 1_717_171_717,
            event_seq: 4,
            usage_seq: Some(9),
            exposure_units: 10,
            realized_spend_units: 0,
            max_invocations: Some(5),
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(50),
            invocation_count_after: 1,
            total_cost_exposed_after: 10,
            total_cost_realized_spend_after: 0,
            authority: None,
        });

        assert_eq!(cursor.seq, 4);
        assert_eq!(cursor.capability_id, "cap-1");
        assert_eq!(cursor.grant_index, 2);
    }

    #[test]
    fn budget_delta_import_preserves_record_only_legacy_deltas() {
        let budget_db = unique_temp_path("cluster-legacy-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).expect("open budget db");
        let response = BudgetDeltaResponse {
            records: vec![BudgetUsageView {
                capability_id: "cap-legacy".to_string(),
                grant_index: 0,
                invocation_count: 3,
                total_cost_exposed: 55,
                total_cost_realized_spend: 21,
                updated_at: 1_717_171_717,
                seq: Some(42),
            }],
            mutation_events: Vec::new(),
        };

        let outcome = import_budget_delta_response(&mut store, &response, None)
            .expect("import legacy record-only budget delta");
        assert_eq!(outcome.applied_count, 1);
        assert!(outcome.should_continue);
        assert_eq!(outcome.next_cursor.expect("legacy cursor").seq, 42);

        let usage = store
            .get_usage("cap-legacy", 0)
            .expect("load imported usage")
            .expect("legacy usage row");
        assert_eq!(usage.invocation_count, 3);
        assert_eq!(usage.seq, 42);
        assert_eq!(usage.total_cost_exposed, 55);
        assert_eq!(usage.total_cost_realized_spend, 21);
        assert!(store
            .list_mutation_events(10, Some("cap-legacy"), Some(0))
            .expect("list mutation events")
            .is_empty());
    }

    #[test]
    fn budget_delta_import_rejects_oversized_peer_payloads() {
        let budget_db = unique_temp_path("cluster-oversized-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).expect("open budget db");
        let response = BudgetDeltaResponse {
            records: (0..=BUDGET_DELTA_MAX_RECORDS)
                .map(|idx| BudgetUsageView {
                    capability_id: format!("cap-{idx}"),
                    grant_index: 0,
                    invocation_count: 1,
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                    updated_at: 1_717_171_717,
                    seq: Some(idx as u64 + 1),
                })
                .collect(),
            mutation_events: Vec::new(),
        };

        let result = import_budget_delta_response(&mut store, &response, None);
        let Err(error) = result else {
            panic!("oversized peer budget deltas should fail closed");
        };
        assert!(error.to_string().contains("budget delta response contains"));
    }

    #[test]
    fn apply_cluster_snapshot_seeds_authority_term_for_late_joiner_budget_writes() {
        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-0",
            &["http://node-a", "http://node-b"],
            None,
            None,
            None,
        );

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().expect("cluster state");
            let mut guard = cluster.lock().expect("cluster guard");
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let initial_target_consensus =
            cluster_consensus_view(&target_state).expect("initial target consensus");
        assert_eq!(
            initial_target_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(initial_target_consensus.election_term, 1);

        let snapshot = build_cluster_state_snapshot(&source_state).expect("build cluster snapshot");
        assert_eq!(snapshot.election_term, 1);
        assert_eq!(
            snapshot
                .authority_lease
                .as_ref()
                .expect("snapshot authority lease")
                .leader_url,
            "http://node-a"
        );

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
            .expect("apply cluster snapshot");

        let seeded_consensus =
            cluster_consensus_view(&target_state).expect("seeded target consensus");
        assert_eq!(
            seeded_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(seeded_consensus.election_term, 2);
        let seeded_lease = cluster_authority_lease_view(&target_state).expect("seeded lease");
        assert_eq!(seeded_lease.authority_id, "http://node-0");
        assert_eq!(seeded_lease.lease_epoch, 2);
    }

    #[test]
    fn build_cluster_state_seeds_persisted_authority_fence_term() {
        let authority_db_path = unique_temp_path("cluster-authority-fence", "sqlite3");
        let authority =
            SqliteCapabilityAuthority::open(&authority_db_path).expect("open authority db");
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .expect("seed persisted authority fence");

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .expect("build cluster with persisted authority fence")
            .expect("cluster enabled");
        let guard = cluster.lock().expect("cluster guard");
        assert_eq!(guard.election_term, 7);
        assert_eq!(guard.last_leader_url.as_deref(), Some("http://node-b"));

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_for_unknown_leader() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-unknown-leader", "sqlite3");
        let authority =
            SqliteCapabilityAuthority::open(&authority_db_path).expect("open authority db");
        authority
            .seed_cluster_fence(Some("http://node-z"), 7)
            .expect("seed persisted authority fence");

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .expect("build cluster with persisted authority fence")
            .expect("cluster enabled");
        let guard = cluster.lock().expect("cluster guard");
        assert_eq!(guard.election_term, 7);
        assert!(
            guard.last_leader_url.is_none(),
            "unknown persisted leader should be cleared"
        );

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_after_rotation() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-stale-generation", "sqlite3");
        let authority =
            SqliteCapabilityAuthority::open(&authority_db_path).expect("open authority db");
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .expect("seed persisted authority fence");
        authority.rotate().expect("rotate authority");

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .expect("build cluster with stale persisted authority fence")
            .expect("cluster enabled");
        let guard = cluster.lock().expect("cluster guard");
        assert_eq!(guard.election_term, 0);
        assert!(guard.last_leader_url.is_none());

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn apply_cluster_snapshot_fails_when_authority_fence_persistence_fails() {
        let authority_db_path = unique_temp_path("cluster-authority-fence-dir", "d");
        std::fs::create_dir_all(&authority_db_path).expect("create authority directory");

        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(authority_db_path.clone()),
            None,
            None,
        );

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().expect("cluster state");
            let mut guard = cluster.lock().expect("cluster guard");
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let snapshot = build_cluster_state_snapshot(&source_state).expect("build cluster snapshot");
        let error = apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
            .expect_err("snapshot apply should fail when authority fence persistence fails");
        let error_text = error.to_string();
        assert!(
            error_text.contains("directory") || error_text.contains("open database file"),
            "unexpected error: {error_text}"
        );

        let _ = std::fs::remove_dir_all(authority_db_path);
    }
}
