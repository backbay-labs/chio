use super::*;

fn internal_cluster_http_error(context: &'static str, error: &dyn std::fmt::Display) -> Response {
    warn!(error = %error, "{context}");
    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, context)
}

/// Observe capability-revocation propagation lag from a capability revoke path.
/// `revoked_at` is the unix-seconds instant the capability was revoked; the lag
/// is how long ago that was relative to now, clamped at zero. A locally
/// originated revoke is ~0; a revoke propagated from a peer carries the real
/// propagation delay. This is emitted from the capability revoke paths (local
/// revoke and cluster-delta upserts) so the capability-revocation SLO reflects
/// real capability revocations rather than passport lifecycle events.
pub(crate) fn observe_capability_revocation_lag(revoked_at: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let lag_seconds = now.saturating_sub(revoked_at).max(0) as f64;
    chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG
        .observe(&["control_plane"], lag_seconds);
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
    // Abandoned/tombstoned seqs within the pulled range, so the puller can treat
    // those slots as filled (no demote on a legitimately gappy stream). Bounded to
    // the page's max event so the puller only verifies contiguity up to what it is
    // importing, AND capped at BUDGET_DELTA_MAX_RECORDS + 1 rows so a rollback storm
    // that packs an enormous abandoned window before the next live event cannot blow
    // past MAX_PEER_RESPONSE_BYTES. An importable page carries at most
    // BUDGET_DELTA_MAX_RECORDS records total, so its abandoned list is never
    // truncated (limit > cap); a truncated list only ever occurs on an over-cap
    // window, and returning cap + 1 abandoned rows guarantees the client's
    // `record_count > BUDGET_DELTA_MAX_RECORDS` check trips ForceSnapshot (snapshot
    // recovery) BEFORE the contiguity guard runs, so truncation can never demote an
    // honest peer or exceed the byte cap.
    let abandoned_seqs = if mutation_events.is_empty() {
        Vec::new()
    } else {
        let page_max = mutation_events
            .iter()
            .map(|event| event.event_seq)
            .max()
            .unwrap_or(0);
        let abandoned_limit = BUDGET_DELTA_MAX_RECORDS.saturating_add(1);
        match store.list_abandoned_event_seqs_in_range(
            query.after_seq.unwrap_or(0),
            page_max,
            abandoned_limit,
        ) {
            Ok(seqs) => seqs,
            Err(error) => {
                return internal_cluster_http_error(
                    "failed to collect budget abandoned-seq deltas",
                    &error,
                );
            }
        }
    };
    Json(BudgetDeltaResponse {
        records,
        mutation_events,
        abandoned_seqs,
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
        if let Some(progress) = state.cluster_progress.as_ref() {
            progress.notify_round_complete();
        }
        // The loop is the sole sync driver: race the inter-round sleep against a
        // writer kick so a waiting budget write is served promptly without
        // spawning its own sync storm.
        match state.cluster_progress.as_ref() {
            Some(progress) => {
                tokio::select! {
                    _ = tokio::time::sleep(state.config.cluster_sync_interval) => {}
                    _ = progress.awaited_kick() => {}
                }
            }
            None => tokio::time::sleep(state.config.cluster_sync_interval).await,
        }
    }
}

/// Bump the cluster-progress tick so any parked budget-write waiter rechecks the
/// quorum view now. Safe to call mid-round: it drives no sync, just wakes waiters
/// (the same tick the background loop bumps at round end).
pub(crate) fn notify_cluster_progress(state: &TrustServiceState) {
    if let Some(progress) = state.cluster_progress.as_ref() {
        progress.notify_round_complete();
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
    let peer_status = match client.cluster_status() {
        Ok(status) => status,
        Err(error) => {
            update_peer_failure(state, peer_url, error.to_string());
            return Err(error);
        }
    };
    update_peer_reachable(state, peer_url);
    // Apply any DECREASE/CLEAR in the freshly-advertised acks IMMEDIATELY, before
    // any witness-visible pulling or parking check this round. A peer that
    // lost/restored its budget DB now advertises a lower (or absent) head, so the
    // recorded head must not keep witnessing writes the peer no longer durably
    // holds. `clamp_down_peer_budget_acks` only ever SHRINKS the recorded acks
    // (recorded = min(recorded, advertised), dropped origins removed); an INCREASE
    // stays deferred to finalize_peer_sync_round below until this peer's pull round
    // validates.
    clamp_down_peer_budget_acks(state, peer_url, &peer_status.budget_ack_heads);
    // Do NOT record or wake on the peer's freshly-advertised budget acks yet: a high
    // ack head advertised via cluster_status must not be counted for a quorum
    // commit until this peer's pull round completes WITHOUT demotion. Recording it
    // here (before the pullers run) and waking parked writers let a writer commit
    // on an ack from a peer that then hit a Protocol violation and was removed from
    // the witness set. The advertised heads are captured in `peer_status` and
    // recorded only in `finalize_peer_sync_round`, after the pull round.
    if peer_should_force_snapshot(state, peer_url) {
        let snapshot = client.cluster_snapshot()?;
        apply_cluster_snapshot(state, peer_url, snapshot)?;
    }
    if let Err(error) = sync_peer_authority(state, &client) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    let mut delta_records = 0u64;
    // Lane 1: the budget/receipt/lineage streams share ONE per-peer round budget,
    // budget FIRST (quorum-critical). Run each puller only while round budget
    // remains; once a stream exhausts the shared budget (pages/records/deadline),
    // skip the rest so we do not issue more blocking peer fetches just to
    // rediscover the same exhausted budget. A Protocol
    // violation demotes the peer; on ANY stream error the shared lane stops (break)
    // but revocations (lane 2) still run below unless the peer was demoted.
    let mut round = PullRoundBudget::new();
    for puller in peer_pullers() {
        if round.is_exhausted() {
            break;
        }
        if route_pull(
            state,
            peer_url,
            puller(state, &client, peer_url, &mut round),
            &mut delta_records,
        )
        .is_err()
        {
            break;
        }
    }
    // Lane 2: revocations replicate on their OWN round budget, INDEPENDENT of the
    // shared budget/receipt round, so a sustained budget backlog (shared-round
    // exhaustion) or a broken/slow budget-delta endpoint can never starve
    // security-critical revocation propagation. It is skipped ONLY when the peer was
    // demoted by lane 1 (fail-closed: a peer that violated the wire contract is
    // untrusted, so we pull nothing more from it).
    if !peer_was_demoted(state, peer_url) {
        let mut revocation_round = PullRoundBudget::new();
        let _ = route_pull(
            state,
            peer_url,
            sync_peer_revocations(state, &client, peer_url, &mut revocation_round),
            &mut delta_records,
        );
    }
    // Record the peer's advertised acks, mark it successful, and wake parked
    // writers - fail-closed for a demoted or force-snapshot peer (see
    // finalize_peer_sync_round). A transient/force-snapshot error on either lane
    // leaves the peer Healthy, so its status-advertised acks (which come from
    // cluster_status, not the delta pull) are still recorded: a broken delta
    // endpoint must not starve budget ack convergence.
    finalize_peer_sync_round(
        state,
        peer_url,
        &peer_status.budget_ack_heads,
        delta_records,
    );
    Ok(())
}

/// Whether the peer was demoted to `Unhealthy` this round.
///
/// Only a `PullError::Protocol` violation demotes a peer (`update_peer_failure`
/// sets `Unhealthy`); a transient error or force-snapshot keeps it `Healthy`. By
/// the time a round reaches `finalize_peer_sync_round` the peer was marked
/// `Healthy` (`update_peer_reachable`) at the top of the round, so a non-reachable
/// status here means a puller demoted it.
pub(crate) fn peer_was_demoted(state: &TrustServiceState, peer_url: &str) -> bool {
    !with_peer_state(state, peer_url, |peer| peer.health.is_reachable()).unwrap_or(false)
}

/// Record a peer's freshly-advertised budget acks, mark it successful, and wake
/// parked budget-write waiters - the SINGLE site that records a peer's acks, run
/// AFTER its pull round.
///
/// Fail-closed: skips every success side effect when the peer was demoted this
/// round (its fresh, unvalidated ack must never be counted for a quorum commit -
/// that would be an over-count / budget double-spend) or is pending a forced
/// snapshot (it is excluded from witnesses until it re-syncs, and
/// `update_peer_success` would prematurely clear that pending-snapshot flag).
/// Deferring the ack record to here closes the window where an
/// early progress wake let a parked writer commit on an ack the fail-closed path
/// was about to remove.
pub(crate) fn finalize_peer_sync_round(
    state: &TrustServiceState,
    peer_url: &str,
    advertised_budget_acks: &[BudgetOriginAck],
    delta_records: u64,
) {
    if peer_was_demoted(state, peer_url) || peer_should_force_snapshot(state, peer_url) {
        return;
    }
    update_peer_delta_records(state, peer_url, delta_records);
    update_peer_budget_acks(state, peer_url, advertised_budget_acks);
    update_peer_success(state, peer_url);
    notify_cluster_progress(state);
}

/// Fold one puller's result into the round: on success accumulate the applied
/// count; on `PullError::Protocol` demote the peer to Unhealthy (fail-closed,
/// leaves consensus and witness sets); on `PullError::Transient` keep the peer
/// Healthy but record the error; on `PullError::ForceSnapshot` keep the peer
/// Healthy but flag it for a full snapshot resync (an honest, unpageable delta
/// window). Every error arm short-circuits the round BEFORE `update_peer_success`
/// runs, so a `ForceSnapshot` flag survives to the next round's snapshot probe.
pub(crate) fn route_pull(
    state: &TrustServiceState,
    peer_url: &str,
    outcome: Result<u64, PullError>,
    delta_records: &mut u64,
) -> Result<(), CliError> {
    match outcome {
        Ok(count) => {
            *delta_records = delta_records.saturating_add(count);
            Ok(())
        }
        Err(PullError::Protocol(error)) => {
            let message = error.to_string();
            update_peer_failure(state, peer_url, message.clone());
            Err(CliError::cli_other_error(message))
        }
        Err(PullError::Transient(error)) => {
            update_peer_sync_error(state, peer_url, error.to_string());
            Err(error)
        }
        Err(PullError::ForceSnapshot(error)) => {
            // The delta stream cannot make forward progress incrementally (an
            // oversized/unpageable window). Flag the peer for a full snapshot
            // resync WITHOUT demoting it (this is honest backlog, not misbehavior);
            // the next round's snapshot probe resets the cursor to the source head,
            // skipping the window WITHOUT a delta cursor jump. Returning Err
            // short-circuits the round before update_peer_success would clear the
            // flag. A force_snapshot peer is excluded from witnesses until it
            // re-syncs, so this cannot over-count.
            request_peer_snapshot_recovery(state, peer_url, error.to_string());
            Err(error)
        }
    }
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
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.revocation_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteRevocationStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        // Check the shared round budget BEFORE the next blocking fetch so an
        // exhausted stream stops without one more peer request.
        if round.is_exhausted() {
            break;
        }
        let cursor = peer_revocation_cursor(state, peer_url);
        let response = client.revocation_deltas(&RevocationDeltaQuery {
            after_revoked_at: cursor.as_ref().map(|value| value.revoked_at),
            after_capability_id: cursor.as_ref().map(|value| value.capability_id.clone()),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        // Stop the round (not demote) when the local per-round pull cap is hit:
        // a large well-ordered backlog resumes next sync round.
        if round.charge_page(response.records.len() as u64).is_err() {
            break;
        }
        // The revocation delta endpoint promises ascending (revoked_at,
        // capability_id) order and we persist the page HEAD as the next cursor, so
        // require the page to be STRICTLY ascending from the current cursor. A
        // reorder (e.g. [high, low]) is a protocol violation that demotes the peer,
        // rather than silently persisting a cursor behind page_max and replaying
        // already-applied revocations every round. The returned head equals page_max.
        let page_head = ensure_revocation_page_ascending(cursor.as_ref(), &response.records)?;
        for record in &response.records {
            store
                .upsert_revocation(&RevocationRecord {
                    capability_id: record.capability_id.clone(),
                    revoked_at: record.revoked_at,
                })
                .map_err(CliError::from)?;
            // A cluster-delta upsert applies a capability revoke propagated from a
            // peer; observe the propagation lag against its recorded revoke instant.
            observe_capability_revocation_lag(record.revoked_at);
            applied = applied.saturating_add(1);
        }
        update_peer_revocation_cursor(state, peer_url, page_head);
    }
    Ok(applied)
}

fn sync_peer_tool_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        if round.is_exhausted() {
            break;
        }
        let after_seq = peer_tool_seq(state, peer_url);
        let response = client.tool_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        // Stop the round (not demote) when the local per-round pull cap is hit:
        // a large well-ordered backlog resumes next sync round.
        if round.charge_page(response.records.len() as u64).is_err() {
            break;
        }
        // Tool receipts are a NON-DENSE append-only seq stream: `seq` is an
        // INTEGER PRIMARY KEY AUTOINCREMENT written with ON CONFLICT DO NOTHING
        // and pruned by retention, so legitimate gaps (rows 1 and 3, no 2)
        // occur. A gap-free contiguity guard would demote an honest peer, so
        // only forward progress + within-page monotonicity is required; a
        // legitimate gap is accepted.
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChioReceipt =
                serde_json::from_value(record.receipt).map_err(CliError::from)?;
            store
                .append_chio_receipt(&receipt)
                .map_err(CliError::from)?;
            last_seq = last_seq.max(record.seq);
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
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        if round.is_exhausted() {
            break;
        }
        let after_seq = peer_child_seq(state, peer_url);
        let response = client.child_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        // Stop the round (not demote) when the local per-round pull cap is hit:
        // a large well-ordered backlog resumes next sync round.
        if round.charge_page(response.records.len() as u64).is_err() {
            break;
        }
        // Child receipts are a NON-DENSE append-only seq stream (AUTOINCREMENT +
        // ON CONFLICT DO NOTHING, retention-pruned), so gaps are legitimate.
        // Require only forward progress + within-page monotonicity; a gap-free
        // guard would demote an honest peer.
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChildRequestReceipt =
                serde_json::from_value(record.receipt).map_err(CliError::from)?;
            store
                .append_child_receipt(&receipt)
                .map_err(CliError::from)?;
            last_seq = last_seq.max(record.seq);
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
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.budget_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteBudgetStore::open(path).map_err(CliError::from)?;
    let cursor = peer_budget_cursor(state, peer_url);
    drain_budget_delta_pages(
        &mut store,
        round,
        cursor,
        |after_seq, limit| {
            client.budget_deltas(&BudgetDeltaQuery {
                after_seq,
                limit: Some(limit),
            })
        },
        |cursor| update_peer_budget_cursor(state, peer_url, cursor),
    )
}

/// Drain a peer's budget delta stream page by page, SHRINKING the requested event
/// limit before ever force-snapshotting.
///
/// A page can exceed `BUDGET_DELTA_MAX_RECORDS` merely because we asked for a full
/// `MAX_LIST_LIMIT` window of events: each event also drags in its paired usage
/// projection and any abandoned/tombstoned seqs in the covered range, so e.g. 200
/// events + 200 usages + one abandoned seq = 401 records trips the cap even though
/// a 199-event page would import fine. Routing that STRAIGHT to a full snapshot is
/// wasteful and, in a large ledger whose full snapshot itself exceeds the response
/// byte cap, is a permanent stall: the snapshot fetch fails and the cursor repeats
/// the same over-large incremental page forever.
///
/// So on `PullError::ForceSnapshot` (the over-cap signal from
/// `import_budget_delta_response`) we RETRY the same cursor with a SMALLER event
/// limit (halving the returned event count) whenever the page carried more than one
/// event, delivering a merely-large-but-pageable window incrementally. Only a
/// MINIMAL single-event page that STILL overflows (a dense rollback burst packs
/// more abandoned seqs than the cap before the next live event, and an events-empty
/// page is rejected upstream) is a genuinely unpageable window: we propagate
/// `ForceSnapshot` and let the peer resync via the snapshot backstop.
///
/// Never over-counts and never skips a row: every retried page (large or small) is
/// still contiguity-checked and cursor-advance-checked by
/// `import_budget_delta_response`, and a smaller page covers a shorter global-seq
/// range that is still gap-free from the cursor. Shrinking only reduces how MUCH of
/// the contiguous stream one page carries, never which seqs are trusted as filled.
fn drain_budget_delta_pages<Fetch, Commit>(
    store: &mut SqliteBudgetStore,
    round: &mut PullRoundBudget,
    mut cursor: Option<BudgetCursor>,
    mut fetch: Fetch,
    mut commit_cursor: Commit,
) -> Result<u64, PullError>
where
    Fetch: FnMut(Option<u64>, usize) -> Result<BudgetDeltaResponse, CliError>,
    Commit: FnMut(BudgetCursor),
{
    let mut applied = 0u64;
    let mut event_limit = MAX_LIST_LIMIT;
    loop {
        if round.is_exhausted() {
            break;
        }
        let after_seq = cursor.as_ref().map(|value| value.seq);
        let response = fetch(after_seq, event_limit)?;
        match import_budget_delta_response(store, &response, cursor.clone(), round) {
            Ok(outcome) => {
                applied = applied.saturating_add(outcome.applied_count);
                if let Some(next) = outcome.next_cursor {
                    commit_cursor(next.clone());
                    cursor = Some(next);
                }
                if !outcome.should_continue {
                    break;
                }
                // A fresh window may be normal-sized; reopen the throttle so we do not
                // permanently page in tiny increments after one dense window.
                event_limit = MAX_LIST_LIMIT;
            }
            Err(PullError::ForceSnapshot(error)) => {
                // Over-cap. Retry a smaller page only if this one carried more than a
                // single event (so a smaller event window genuinely shrinks the record
                // count). A one-event page that still overflows is unpageable: route to
                // full snapshot recovery. The cursor is unchanged (ForceSnapshot is an
                // Err, so no next_cursor was committed), so the retry refetches from the
                // same position.
                if response.mutation_events.len() > 1 {
                    event_limit = (response.mutation_events.len() / 2).max(1);
                    continue;
                }
                return Err(PullError::ForceSnapshot(error));
            }
            Err(other) => return Err(other),
        }
    }
    Ok(applied)
}

#[derive(Debug)]
pub(crate) struct BudgetDeltaImportOutcome {
    pub(crate) applied_count: u64,
    pub(crate) next_cursor: Option<BudgetCursor>,
    pub(crate) should_continue: bool,
}

pub(crate) fn import_budget_delta_response(
    store: &mut SqliteBudgetStore,
    response: &BudgetDeltaResponse,
    current_cursor: Option<BudgetCursor>,
    round: &mut PullRoundBudget,
) -> Result<BudgetDeltaImportOutcome, PullError> {
    if response.records.is_empty() && response.mutation_events.is_empty() {
        return Ok(BudgetDeltaImportOutcome {
            applied_count: 0,
            next_cursor: current_cursor,
            should_continue: false,
        });
    }
    // Honest budget deltas pair usage projections with the mutation events they
    // derive from; a records-only page can never advance the global event cursor
    // without importing unverified events, so reject it as a protocol violation
    // (demote) rather than pinning the cursor past unreplicated seqs. Checked
    // BEFORE the oversized-page cap below so a malformed records-only page always
    // DEMOTES and never gets routed to snapshot recovery: the ForceSnapshot path
    // is reserved for honest, genuinely unpageable event windows.
    if response.mutation_events.is_empty() {
        return Err(PullError::Protocol(
            PeerProtocolError::RecordsWithoutMutationEvents {
                record_count: response.records.len(),
            },
        ));
    }
    let record_count = response
        .records
        .len()
        .saturating_add(response.mutation_events.len())
        .saturating_add(response.abandoned_seqs.len());
    if record_count > BUDGET_DELTA_MAX_RECORDS {
        // This fetched page exceeds the record cap (events + usage projections +
        // abandoned/tombstoned slots over the covered global-seq range). Signal it to
        // the caller as ForceSnapshot; the caller (drain_budget_delta_pages) FIRST
        // retries the same cursor with a SMALLER event limit, because a page often
        // overflows only because we asked for a full MAX_LIST_LIMIT window of events
        // (a 199-event page would import fine). ForceSnapshot is honored as a genuine
        // full-resync ONLY when even a MINIMAL one-event page still overflows: a dense
        // rollback burst can pack more than BUDGET_DELTA_MAX_RECORDS abandoned seqs
        // BEFORE the next live event (and an events-empty page is rejected above), so
        // no cursor-anchored page makes forward progress. Routing THAT window through
        // the snapshot path (which resets the cursor to the source's global head)
        // rather than a bare Transient is what lets recovery proceed: a Transient
        // neither advances the cursor nor bumps delta_records_since_snapshot, so
        // force_snapshot recovery would never trigger. Fail-
        // closed and sound: the snapshot skips the window WITHOUT a delta cursor jump,
        // so it cannot over-count or skip unreplicated rows, and a force_snapshot peer
        // is excluded from witnesses until it re-syncs.
        return Err(PullError::ForceSnapshot(CliError::cli_other_error(format!(
            "budget delta response contains {record_count} records, maximum is {BUDGET_DELTA_MAX_RECORDS}; routing peer through full snapshot recovery"
        ))));
    }
    // Local per-round pull cap: stop the round WITHOUT demoting; the next sync
    // round resumes from the unchanged cursor.
    if round.charge_page(record_count as u64).is_err() {
        return Ok(BudgetDeltaImportOutcome {
            applied_count: 0,
            next_cursor: current_cursor,
            should_continue: false,
        });
    }

    let previous_cursor_seq = current_cursor
        .as_ref()
        .map(|cursor| cursor.seq)
        .unwrap_or(0);

    // Budget mutation events are a single STORE-WIDE, dense append-only
    // event_seq stream: every allocation yields exactly one event, so each
    // authority's events are a sparse subsequence of one global sequence and the
    // budget pull cursor is a single GLOBAL event_seq. Enforce STRICT global
    // contiguity from the cursor: the pulled page, in global-seq order, must run
    // gap-free from previous_cursor_seq + 1 with no skipped global seq.
    //
    // A per-origin compaction floor MUST NOT authorize a jump here: the cursor
    // spans all origins, so anchoring at the floor of the
    // authority on the page head could advance the global cursor past global
    // seqs owned by a DIFFERENT origin that this node has not yet replicated,
    // permanently omitting them. A genuine global floor (a seq below which ALL
    // origins are provably covered) does not exist as a primitive, so the
    // fail-closed behavior is strict contiguity: a jump is a protocol violation
    // that demotes the peer and pins the cursor. A follower legitimately behind
    // a leader that compacted below its cursor heals via the force-snapshot path
    // (demotion -> Unhealthy -> full snapshot resets the cursor to the
    // snapshot's global head), not via a floor-authorized delta jump.
    if !response.mutation_events.is_empty() {
        let event_seqs = response
            .mutation_events
            .iter()
            .map(|event| event.event_seq)
            .collect::<Vec<_>>();
        // Events must arrive in strictly ASCENDING received order: the importer
        // applies them in order, so a release-before-authorize reorder must be
        // rejected. Forward progress and gap-freeness are
        // checked by the union guard below.
        let mut previous: Option<u64> = None;
        for &seq in &event_seqs {
            if let Some(prev) = previous {
                if seq <= prev {
                    return Err(PullError::Protocol(PeerProtocolError::NonContiguousPage {
                        expected_seq: prev.saturating_add(1),
                        found_seq: seq,
                    }));
                }
            }
            previous = Some(seq);
        }
        // The UNION of imported events and the page's abandoned/tombstoned slots
        // must be gap-free from the cursor. An abandoned seq legitimately fills a
        // hole left by a rolled-back-then-re-appended write, so it is NOT a skip;
        // a seq that is neither an event nor abandoned IS a skip and stays a
        // NonContiguousPage that demotes the peer.
        //
        // TRUST BOUNDARY: honoring the source peer's
        // `abandoned_seqs` lets it make THIS follower skip seq S (treat S as filled
        // without importing an event for it) with NO independent verification that S
        // is genuinely abandoned. This is SAFE ONLY under the crash-fault
        // (honest-peer) trust model that governs cluster replication: an honest peer
        // reports a seq as abandoned only after it durably tombstoned a
        // rolled-back-then-re-appended write, so S carries no live row anywhere. It
        // is deliberately OUTSIDE the strict-contiguity guarantee that
        // `require_contiguous_page` otherwise provides (that a peer cannot make a
        // follower skip an unreplicated row): a Byzantine or buggy source could
        // report a live seq as abandoned and induce this follower to skip it and
        // then over-advertise its contiguous ack head. Under crash-fault that cannot
        // happen; the periodic full snapshot (`apply_cluster_snapshot`) is the
        // backstop that reconverges a follower that ever diverged. Widening the trust
        // model to Byzantine would require signed, independently-verifiable
        // abandonment proofs here, which this deployment does not assume.
        let mut filled = event_seqs;
        filled.extend(
            response
                .abandoned_seqs
                .iter()
                .copied()
                .filter(|&seq| seq > previous_cursor_seq),
        );
        filled.sort_unstable();
        filled.dedup();
        require_contiguous_page(previous_cursor_seq.saturating_add(1), &filled)?;
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
        .collect::<Result<Vec<_>, CliError>>()?;
    store
        .import_snapshot_records(&usage_records, &mutation_records)
        .map_err(CliError::from)?;
    // Record the page's abandoned slots so this follower's contiguous ack head
    // treats them as filled even if it never held (and so never deleted) the
    // original event. This trusts the source peer's
    // abandonment claim without independent verification; see the TRUST BOUNDARY
    // note at the contiguity union above: it is sound only
    // under the crash-fault honest-peer model and sits outside the strict
    // require_contiguous_page guarantee, with the periodic snapshot as backstop.
    if !response.abandoned_seqs.is_empty() {
        store
            .record_abandoned_event_seqs(&response.abandoned_seqs)
            .map_err(CliError::from)?;
    }

    // The global event cursor advances ONLY from mutation events (guaranteed
    // non-empty here: a records-only page was rejected above). Usage `seq`s never
    // move the event cursor, so a peer cannot pin the cursor past unimported
    // events via usage projections alone.
    let mut next_cursor = current_cursor;
    for event in &response.mutation_events {
        next_cursor = Some(merge_budget_cursor(
            next_cursor,
            budget_cursor_from_event(event),
        ));
    }

    let cursor_advanced = next_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.seq > previous_cursor_seq);
    // Fail-closed: a non-empty page that does not advance the merged cursor past
    // the caller's position is a replaying or buggy peer, not a continuation.
    if !cursor_advanced {
        let page_max_seq = next_cursor.as_ref().map(|cursor| cursor.seq).unwrap_or(0);
        return Err(PullError::Protocol(PeerProtocolError::NonAdvancingPage {
            after_seq: previous_cursor_seq,
            page_max_seq,
        }));
    }
    let applied_count = mutation_records.len() as u64;

    Ok(BudgetDeltaImportOutcome {
        applied_count,
        next_cursor,
        should_continue: cursor_advanced,
    })
}

fn sync_peer_lineage(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let mut store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        if round.is_exhausted() {
            break;
        }
        let after_seq = peer_lineage_seq(state, peer_url);
        let response = client.lineage_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        // Stop the round (not demote) when the local per-round pull cap is hit:
        // a large well-ordered backlog resumes next sync round.
        if round.charge_page(response.records.len() as u64).is_err() {
            break;
        }
        // Lineage snapshots paginate on the capability_lineage rowid, which is
        // NON-DENSE: an upsert on an existing capability_id keeps its rowid and
        // deletes leave holes, so gaps are legitimate. Require only forward
        // progress + within-page monotonicity; a gap-free guard would demote an
        // honest peer.
        let seqs = response
            .records
            .iter()
            .map(|record| record.seq)
            .collect::<Vec<_>>();
        require_forward_progress(after_seq, &seqs)?;
        let mut last_seq = after_seq;
        for record in response.records {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            last_seq = last_seq.max(record.seq);
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
    payload: Option<(T, BudgetWriteToken)>,
) -> Response
where
    T: Serialize,
{
    let Some((payload, write)) = payload else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    let budget_commit = match wait_for_budget_write_quorum_commit(state, write).await {
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

/// Identifies a specific budget write for the quorum witness: the origin
/// authority that wrote the mutation event, the event's own event_seq (NOT
/// usage.seq), and the budget term (lease epoch) it was written under.
#[derive(Debug, Clone)]
pub(crate) struct BudgetWriteToken {
    pub(crate) origin_id: String,
    pub(crate) event_seq: u64,
    pub(crate) budget_term: u64,
}

pub(crate) fn budget_write_quorum_commit_view(
    state: &TrustServiceState,
    write: &BudgetWriteToken,
) -> Option<BudgetWriteCommitView> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(mut guard) => budget_write_quorum_commit_view_locked(&mut guard, write),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            budget_write_quorum_commit_view_locked(&mut guard, write)
        }
    })
}

fn budget_write_quorum_commit_view_locked(
    cluster: &mut ClusterRuntimeState,
    write: &BudgetWriteToken,
) -> BudgetWriteCommitView {
    let consensus = compute_cluster_consensus_locked(cluster);
    let mut witness_urls = BTreeSet::from([cluster.self_url.clone()]);
    for (peer_url, peer_state) in &cluster.peers {
        // A peer counts only when its contiguous ack head for THIS write's
        // origin is at least the write's event_seq. An event from a different
        // origin is grouped under a different key and cannot witness; a legacy
        // NULL-authority event is excluded from budget_ack_heads and so never
        // witnesses.
        let acked = peer_state
            .budget_import_acks
            .get(&write.origin_id)
            .is_some_and(|imported_seq| *imported_seq >= write.event_seq);
        // A peer pending a forced snapshot (demoted by a protocol error, then
        // probed reachable again before its snapshot + delta re-sync completed)
        // carries stale, untrusted ack heads: it must NOT witness until it has
        // re-synced, even though a bare reachability probe flipped it Healthy.
        if peer_state.health.is_reachable()
            && !peer_state.partitioned
            && !peer_state.force_snapshot
            && acked
        {
            witness_urls.insert(peer_url.clone());
        }
    }
    let committed_nodes = witness_urls.len();
    // The commit metadata (authority_id / lease_id) must name the authority that
    // AUTHORED this write, not the current consensus leader: leadership can change
    // while the write waits (a lex-earlier node becomes reachable), and pairing
    // the write's term with a different leader would mint a lease_id for an
    // authority that never wrote the event. The write
    // token already carries origin_id; fall back to the consensus leader only for
    // a placeholder (unclustered) token that has no origin.
    let authority_id = if write.origin_id.is_empty() {
        consensus
            .leader_url
            .clone()
            .unwrap_or_else(|| cluster.self_url.clone())
    } else {
        write.origin_id.clone()
    };
    let lease_epoch = write.budget_term;
    let lease_id = format!("{authority_id}#term-{lease_epoch}");
    BudgetWriteCommitView {
        budget_seq: write.event_seq,
        commit_index: write.event_seq,
        quorum_committed: committed_nodes >= consensus.quorum_size,
        quorum_size: consensus.quorum_size,
        committed_nodes,
        witness_urls: witness_urls.into_iter().collect(),
        authority_id,
        budget_term: write.budget_term,
        lease_id,
        lease_epoch,
    }
}

type Puller = fn(
    &TrustServiceState,
    &TrustControlClient,
    &str,
    &mut PullRoundBudget,
) -> Result<u64, PullError>;

/// The per-peer SHARED-ROUND pull order. Budget replication is quorum-critical
/// (HA budget writes wait on peers' budget_ack_heads), so it is pulled FIRST: a
/// sustained receipt/lineage backlog must not spend the shared round budget and
/// starve the budget pull, timing out otherwise-committable writes.
///
/// Revocations are NOT in this shared list: they replicate on their own
/// independent round budget in `sync_peer` so budget churn (shared-round
/// exhaustion) or a broken budget endpoint cannot starve security-critical
/// revocation propagation.
fn peer_pullers() -> [Puller; 4] {
    [
        sync_peer_budgets,
        sync_peer_tool_receipts,
        sync_peer_child_receipts,
        sync_peer_lineage,
    ]
}

/// Number of configured cluster peers (0 when unclustered).
fn cluster_peer_count(state: &TrustServiceState) -> usize {
    let Some(cluster) = state.cluster.as_ref() else {
        return 0;
    };
    match cluster.lock() {
        Ok(guard) => guard.peers.len(),
        Err(poisoned) => poisoned.into_inner().peers.len(),
    }
}

/// How long a budget write waits for peer acks to reach quorum.
///
/// The single background sync loop visits peers SERIALLY, and one `sync_peer`
/// visit is FAR more than a single HTTP call: it performs cluster_status, an
/// optional cluster_snapshot, an authority_snapshot, and then the delta pull
/// rounds (a shared budget/receipt/lineage round and an independent revocation
/// round), each blocking call up to `CONTROL_HTTP_TIMEOUT` and each delta round
/// bounded by its wall-clock budget. If a slow-but-reachable peer is visited
/// before the peer whose ack makes quorum, the wait must outlast a full serial
/// visit for every preceding peer, or it 503s a write the next peer would have
/// committed in the same round. The bound must account for a fetch to every peer,
/// not just one `CONTROL_HTTP_TIMEOUT`.
///
/// The bound scales with the peer count (inherently bounded by cluster size) and
/// is capped so a misconfigured huge peer list cannot make it unbounded. A GENUINE
/// partition still returns 503 promptly via the has-quorum check inside the wait
/// loop, so this longer bound only delays the "quorum reachable but a preceding
/// peer is slow" case, never a real partition.
fn budget_write_quorum_commit_timeout(sync_interval: Duration, peer_count: usize) -> Duration {
    // Absolute ceiling so a misconfigured huge peer list cannot make the wait
    // unbounded (a real partition still 503s promptly via the has-quorum check).
    const MAX_QUORUM_COMMIT_TIMEOUT: Duration = Duration::from_secs(300);
    let scaled = sync_interval
        .checked_mul(20)
        .unwrap_or(Duration::from_secs(30))
        .max(Duration::from_secs(5))
        .min(Duration::from_secs(30));
    // Worst-case cost of ONE serial sync_peer visit that must complete for every
    // peer preceding the quorum peer: the three fixed blocking HTTP stages
    // (cluster_status, cluster_snapshot, authority_snapshot) each up to
    // CONTROL_HTTP_TIMEOUT, plus the two wall-clock-bounded delta pull rounds (the
    // shared budget/receipt/lineage round and the independent revocation round).
    let per_peer_sync = CONTROL_HTTP_TIMEOUT
        .checked_mul(3)
        .unwrap_or(Duration::from_secs(45))
        .saturating_add(PEER_ROUND_WALL_CLOCK_BUDGET)
        .saturating_add(PEER_ROUND_WALL_CLOCK_BUDGET);
    // One worst-case cycle over all peers preceding the quorum peer, plus one extra
    // cycle for a mid-cycle write arrival.
    let cycles = (peer_count as u32).saturating_add(1);
    let peer_bound = per_peer_sync
        .checked_mul(cycles)
        .unwrap_or(MAX_QUORUM_COMMIT_TIMEOUT)
        .saturating_add(sync_interval)
        .min(MAX_QUORUM_COMMIT_TIMEOUT);
    scaled.max(peer_bound)
}

/// Outcome when the `ClusterProgress` watch closes while a budget write is
/// parked on it (the sync/progress task died mid-wait).
///
/// Fail-closed: a node that is STILL clustered must return a 503
/// so the caller (`handle_try_charge_cost`) rolls back the local exposure. The
/// caller only rolls back on `Err`; returning `Ok(None)` here would render as a
/// successful leader-visible write with NO `budgetCommit`, indistinguishable
/// from a genuinely unclustered node, so an HA budget write could be acked
/// without ever reaching quorum. Only a node that has since dropped its cluster
/// (`state.cluster` is `None`) returns the legitimately-unclustered `Ok(None)`.
pub(crate) fn budget_write_progress_closed_outcome(
    state: &TrustServiceState,
    write: &BudgetWriteToken,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    if state.cluster.is_some() {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "budget write became leader-visible at commit index {} for authority term {} but the cluster progress channel closed before quorum",
                write.event_seq, write.budget_term
            ),
        ));
    }
    Ok(None)
}

pub(crate) async fn wait_for_budget_write_quorum_commit(
    state: &TrustServiceState,
    write: BudgetWriteToken,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    let Some(progress) = state.cluster_progress.as_ref() else {
        return Ok(None); // not clustered
    };
    let peer_count = cluster_peer_count(state);
    let timeout =
        budget_write_quorum_commit_timeout(state.config.cluster_sync_interval, peer_count);
    let mut rx = progress.subscribe();
    progress.request_sync();

    // Park on the progress watch under a single wall-clock bound and drive no
    // sync directly: the background loop is the sole sync driver, so one slow
    // peer can no longer multiply N concurrent writes into N sync storms; the
    // write waits out the bound and fails closed.
    let waited = tokio::time::timeout(timeout, async {
        loop {
            let Some(view) = budget_write_quorum_commit_view(state, &write) else {
                return Ok::<_, Response>(None);
            };
            if view.quorum_committed {
                return Ok(Some(view));
            }
            if !cluster_consensus_view(state).is_some_and(|consensus| consensus.has_quorum) {
                return Err(plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "budget write became leader-visible at commit index {} for authority term {} but cluster quorum disappeared before commit",
                        write.event_seq, write.budget_term
                    ),
                ));
            }
            if rx.changed().await.is_err() {
                // The ClusterProgress sender was dropped: the sync/progress task
                // died mid-write. Fail closed while still clustered;
                // see budget_write_progress_closed_outcome.
                return budget_write_progress_closed_outcome(state, &write);
            }
        }
    })
    .await;

    match waited {
        Ok(inner) => inner,
        Err(_elapsed) => {
            let observed = budget_write_quorum_commit_view(state, &write);
            Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "budget write became leader-visible at commit index {} for authority term {} but quorum acks did not arrive before timeout ({}/{})",
                    write.event_seq,
                    write.budget_term,
                    observed.as_ref().map(|v| v.committed_nodes).unwrap_or(0),
                    observed.as_ref().map(|v| v.quorum_size).unwrap_or(0),
                ),
            ))
        }
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

#[cfg(test)]
mod capability_revocation_lag_tests {
    use super::observe_capability_revocation_lag;

    fn lag_count() -> u64 {
        let mut rendered = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut rendered);
        rendered
            .lines()
            .find(|line| {
                line.starts_with(
                    "chio_capability_revocation_lag_seconds_count{authority=\"control_plane\"}",
                )
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// A capability revoke path observes the capability-revocation lag family, so
    /// a backdated (propagated) revoke advances the SLO histogram.
    #[test]
    fn capability_revoke_observes_revocation_lag() {
        let before = lag_count();
        // Backdate the revoke instant by 45 seconds relative to now.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        observe_capability_revocation_lag(now.saturating_sub(45));
        assert!(
            lag_count() > before,
            "a capability revoke must observe a capability-revocation lag sample"
        );
    }
}

#[cfg(test)]
mod deltas_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn budget_pull_is_prioritized_first() {
        // Budget replication is pulled FIRST so a receipt/lineage backlog cannot
        // spend the shared round budget and starve the quorum-critical budget pull.
        assert_eq!(
            peer_pullers()[0] as usize,
            sync_peer_budgets as Puller as usize,
            "the budget pull must run first in the per-peer pull order"
        );
    }

    #[test]
    fn revocations_are_not_in_the_shared_budget_round() {
        // Revocations must replicate on their OWN round budget in sync_peer, NOT
        // share the budget/receipt round. If they were in this shared list a
        // sustained budget backlog (shared-round exhaustion) or a broken budget
        // endpoint could starve security-critical revocation propagation. Budget
        // stays first here.
        let shared = peer_pullers();
        assert_eq!(
            shared[0] as usize, sync_peer_budgets as Puller as usize,
            "budget remains first in the shared round"
        );
        assert!(
            !shared
                .iter()
                .any(|puller| *puller as usize == sync_peer_revocations as Puller as usize),
            "revocations must be pulled on an independent round budget, not the shared one"
        );
    }

    #[test]
    fn quorum_commit_timeout_covers_full_per_peer_sync_and_is_bounded() {
        // The wait must outlast a FULL serial sync_peer visit for every peer
        // preceding the quorum peer, not just one CONTROL_HTTP_TIMEOUT per peer. A
        // full visit is the three fixed blocking stages plus the two
        // wall-clock-bounded delta rounds.
        let interval = Duration::from_millis(25);
        let per_peer_sync =
            CONTROL_HTTP_TIMEOUT * 3 + PEER_ROUND_WALL_CLOCK_BUDGET + PEER_ROUND_WALL_CLOCK_BUDGET;

        assert!(budget_write_quorum_commit_timeout(interval, 0) >= Duration::from_secs(5));

        // One preceding peer must be budgeted a full sync_peer visit. A bound of one
        // CONTROL_HTTP_TIMEOUT per peer would give only 30s here, far short of it.
        let one = budget_write_quorum_commit_timeout(interval, 1);
        assert!(
            one >= per_peer_sync,
            "one preceding peer must allow a full serial sync_peer visit, got {one:?}"
        );

        // Still bounded by a fixed ceiling so a misconfigured huge peer list cannot
        // make the wait unbounded.
        assert!(budget_write_quorum_commit_timeout(interval, 10_000) <= Duration::from_secs(300));
    }

    fn storm_event(seq: u64) -> BudgetMutationEventView {
        BudgetMutationEventView {
            event_id: format!("evt-{seq}"),
            hold_id: None,
            capability_id: "cap-page".to_string(),
            grant_index: 0,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: seq as i64,
            event_seq: seq,
            usage_seq: Some(seq),
            exposure_units: 1,
            realized_spend_units: 0,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            invocation_count_after: 1,
            total_cost_exposed_after: 1,
            total_cost_realized_spend_after: 0,
            authority: Some(BudgetMutationAuthorityView {
                authority_id: "http://origin-page".to_string(),
                lease_id: "http://origin-page#term-1".to_string(),
                lease_epoch: 1,
            }),
        }
    }

    fn temp_budget_db(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("chio-{tag}-{nonce}.sqlite3"))
    }

    #[test]
    fn oversized_budget_page_retries_smaller_before_snapshotting() {
        // A page can exceed BUDGET_DELTA_MAX_RECORDS just because we asked for a full
        // MAX_LIST_LIMIT window (events + their usages + abandoned seqs). Such a
        // large-but-PAGEABLE window must be delivered incrementally via a SMALLER
        // event limit, not routed straight to a full snapshot: the drain refetches
        // the SAME cursor with a smaller limit and imports the window (still
        // contiguity-checked, so no skip / no over-count).
        use chio_test_support::prelude::*;
        let db = temp_budget_db("retry-smaller-budget-page");
        let mut store = SqliteBudgetStore::open(&db).test_unwrap();

        // The oversized first page: MAX_LIST_LIMIT events plus a dense abandoned burst,
        // so record_count > BUDGET_DELTA_MAX_RECORDS. It carries MANY events, so it is
        // reducible: a smaller event window would fit under the cap.
        let over_cap = || BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events: (1..=MAX_LIST_LIMIT as u64).map(storm_event).collect(),
            abandoned_seqs: ((MAX_LIST_LIMIT as u64 + 1)..=(BUDGET_DELTA_MAX_RECORDS as u64 + 1))
                .collect(),
        };
        // The smaller retry page: a short contiguous run that imports cleanly.
        let small = || BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events: (1..=3).map(storm_event).collect(),
            abandoned_seqs: Vec::new(),
        };

        let calls = std::cell::RefCell::new(Vec::<(Option<u64>, usize)>::new());
        let result = drain_budget_delta_pages(
            &mut store,
            &mut PullRoundBudget::new(),
            None,
            |after_seq, limit| {
                calls.borrow_mut().push((after_seq, limit));
                Ok(match (after_seq, limit) {
                    // First fetch: full limit from the head -> the oversized window.
                    (None, l) if l >= MAX_LIST_LIMIT => over_cap(),
                    // Retry from the SAME head at a reduced limit -> the pageable window.
                    (None, _) => small(),
                    // Cursor advanced past the imported window -> the stream is drained.
                    _ => BudgetDeltaResponse {
                        records: Vec::new(),
                        mutation_events: Vec::new(),
                        abandoned_seqs: Vec::new(),
                    },
                })
            },
            |_cursor| {},
        );

        // The window drained incrementally; no ForceSnapshot escaped the drain.
        let applied = match result {
            Ok(applied) => applied,
            Err(other) => {
                panic!("a large-but-pageable window must drain, not force-snapshot: {other:?}")
            }
        };
        assert_eq!(applied, 3, "the smaller page's events were imported");
        // The drain retried the same cursor with a limit strictly below
        // MAX_LIST_LIMIT before ever force-snapshotting.
        let calls = calls.into_inner();
        assert!(
            calls
                .iter()
                .any(|(after, limit)| after.is_none() && *limit < MAX_LIST_LIMIT),
            "the drain must retry the SAME cursor with a smaller event limit before snapshotting, got {calls:?}"
        );
        // The follower actually holds the imported events (contiguity preserved).
        assert_eq!(store.max_mutation_event_seq().test_unwrap(), 3);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn unpageable_single_event_budget_page_still_force_snapshots() {
        // A GENUINELY unpageable window - a single live event preceded by a dense
        // rollback burst of abandoned seqs that alone exceeds the record cap -
        // cannot be split smaller, so the drain must still route the peer to full
        // snapshot recovery (ForceSnapshot) rather than shrink-looping forever.
        use chio_test_support::prelude::*;
        let db = temp_budget_db("unpageable-budget-page");
        let mut store = SqliteBudgetStore::open(&db).test_unwrap();

        let fetches = std::cell::RefCell::new(0usize);
        let result = drain_budget_delta_pages(
            &mut store,
            &mut PullRoundBudget::new(),
            None,
            |_after_seq, _limit| {
                *fetches.borrow_mut() += 1;
                Ok(BudgetDeltaResponse {
                    records: Vec::new(),
                    // ONE event; the abandoned burst ALONE exceeds the record cap, so
                    // no smaller event page can bring the count under the cap.
                    mutation_events: vec![storm_event(1)],
                    abandoned_seqs: (2..=(BUDGET_DELTA_MAX_RECORDS as u64 + 2)).collect(),
                })
            },
            |_cursor| {},
        );

        match result {
            Err(PullError::ForceSnapshot(_)) => {}
            other => {
                panic!("a minimal one-event over-cap page must force-snapshot, got {other:?}")
            }
        }
        // A single-event page is not reducible, so it force-snapshots after exactly
        // ONE fetch: no unbounded shrink-retry loop.
        assert_eq!(
            fetches.into_inner(),
            1,
            "no shrink-retry for an unpageable single-event page"
        );

        let _ = std::fs::remove_file(&db);
    }
}
