use super::*;

fn internal_cluster_http_error(context: &'static str, error: &dyn std::fmt::Display) -> Response {
    warn!(error = %error, "{context}");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, context)
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

pub(crate) fn sync_cluster_once(state: &TrustServiceState) -> Result<(), CliError> {
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

pub(crate) fn budget_mutation_event_view(record: BudgetMutationRecord) -> BudgetMutationEventView {
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

pub(crate) fn budget_usage_record_from_view(
    usage: &BudgetUsageView,
) -> chio_kernel::BudgetUsageRecord {
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

pub(crate) fn merge_budget_cursor(
    current: Option<BudgetCursor>,
    candidate: BudgetCursor,
) -> BudgetCursor {
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

pub(crate) fn budget_mutation_record_from_view(
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
