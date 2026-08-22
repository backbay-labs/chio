use super::cluster::{
    cluster_authority_lease_view, cluster_consensus_view, cluster_self_url, current_leader_url,
    update_peer_failure, update_peer_reachable,
};
use super::*;

pub(crate) fn json_response_with_leader_visibility<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
) -> Response {
    json_response_with_leader_visibility_and_budget_commit(state, payload, None)
}

pub(crate) fn json_response_with_leader_visibility_and_budget_commit<T: Serialize>(
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
            );
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
                    );
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
                );
            }
        };
        map.insert("budgetCommit".to_string(), budget_commit);
    }
    Json(value).into_response()
}

pub(crate) fn authority_snapshot_view(snapshot: AuthoritySnapshot) -> AuthoritySnapshotView {
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

pub(crate) fn revocation_cursor_view(cursor: RevocationCursor) -> RevocationCursorView {
    RevocationCursorView {
        seq: cursor.seq,
        revoked_at: cursor.revoked_at,
        capability_id: cursor.capability_id,
    }
}

pub(crate) fn budget_cursor_view(cursor: BudgetCursor) -> BudgetCursorView {
    BudgetCursorView {
        seq: cursor.seq,
        updated_at: cursor.updated_at,
        capability_id: cursor.capability_id,
        grant_index: cursor.grant_index,
    }
}

pub(crate) fn authority_snapshot_from_view(view: AuthoritySnapshotView) -> AuthoritySnapshot {
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

pub(crate) fn revocation_cursor_from_view(view: RevocationCursorView) -> RevocationCursor {
    RevocationCursor {
        seq: view.seq,
        revoked_at: view.revoked_at,
        capability_id: view.capability_id,
    }
}

pub(crate) fn stored_tool_receipt_views(
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

pub(crate) fn stored_child_receipt_views(
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

pub(crate) fn stored_lineage_views(
    records: Vec<StoredCapabilitySnapshot>,
) -> Vec<StoredLineageView> {
    records
        .into_iter()
        .map(|record| StoredLineageView {
            seq: record.seq,
            snapshot: record.snapshot,
        })
        .collect()
}

fn decision_kind(decision: Option<&Decision>) -> &'static str {
    match decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

/// Mirror of the store-side `receipt_decision_kind` logic so that
/// CLI-driven filter queries against `chio_tool_receipts.decision_kind`
/// see the same value that was persisted at write time.
///
/// Trace and advisory receipts carry no `Decision` and store their
/// semantics-derived kind (e.g. `trace_observation`) in the column,
/// so a plain `decision_kind(receipt.decision)` would produce `"none"`
/// and miss those rows.
pub(crate) fn receipt_decision_kind(receipt: &ChioReceipt) -> &'static str {
    let semantics = receipt.semantic_fields();
    if !semantics.is_authorized(receipt.decision.as_ref())
        && matches!(&receipt.decision, Some(Decision::Allow))
    {
        return semantics.receipt_kind.as_str();
    }
    match receipt.decision.as_ref() {
        Some(decision) => decision_kind(Some(decision)),
        None => semantics.receipt_kind.as_str(),
    }
}

pub(crate) fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

fn forwarded_control_response(response: ureq::Response) -> Result<Response, CliError> {
    let status = StatusCode::from_u16(response.status()).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to map forwarded trust-control response status: {error}"
        ))
    })?;
    let content_type = response.header(CONTENT_TYPE.as_str()).map(str::to_owned);
    let body = response.into_string().map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to decode forwarded trust-control response body: {error}"
        ))
    })?;

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder.body(axum::body::Body::from(body)).map_err(|error| {
        CliError::cli_other_error(format!(
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
        CliError::cli_other_error(format!(
            "failed to serialize forwarded trust control request: {error}"
        ))
    })?;
    let endpoint = client.endpoints.first().ok_or_else(|| {
        CliError::cli_other_error("trust control client requires at least one endpoint".to_string())
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
        Err(ureq::Error::Transport(error)) => Err(CliError::cli_other_error(format!(
            "trust control service transport failed: {error}"
        ))),
    }
}

pub(crate) async fn forward_post_to_leader<B: Serialize>(
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
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
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

pub(crate) async fn forward_authority_post_to_leader<B: Serialize>(
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
        let client = service_runtime::client::build_cluster_peer_client(
            &leader_url,
            &state.config.service_token,
            &self_url,
        )
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
        if let Ok(status) = client.cluster_status() {
            update_peer_reachable(state, &leader_url);
            if status.has_quorum && status.leader_url.as_deref() == Some(leader_url.as_str()) {
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

pub(crate) async fn forward_scim_post_to_leader<B: Serialize>(
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
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
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

pub(crate) async fn forward_scim_delete_to_leader(
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
        let client =
            service_runtime::client::build_client(&leader_url, &state.config.service_token)
                .map_err(|error| {
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
