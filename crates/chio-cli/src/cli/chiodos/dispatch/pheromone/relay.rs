use super::*;

#[derive(Clone)]
pub(crate) struct CliRelayBatchReceiver {
    pub(crate) store: std::path::PathBuf,
    pub(crate) transit_policy: chio_federation::PheromoneTransitPolicy,
    pub(crate) receiver_config: chio_pheromone_runtime::PheromoneReceiverConfig,
    pub(crate) resolver: chio_pheromone_runtime::VerifiedChiodosWorkflowResolver,
}

#[async_trait::async_trait]
impl chio_pheromone_relay::RelayBatchReceiver for CliRelayBatchReceiver {
    async fn receive_batch(
        &self,
        batch: chio_federation::PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, chio_pheromone_relay::PheromoneRelayError>
    {
        let mut config = self.receiver_config.clone();
        config.authenticated_sender_kernel_id = authenticated_sender_kernel_id;
        config.validation_context.now_unix_ms = received_at_unix_ms;
        let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(&self.store)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))?;
        let receiver =
            chio_pheromone_runtime::PheromoneReceiver::new(store, self.resolver.clone(), config);
        receiver
            .receive_batch(&batch, &self.transit_policy)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayTrustedIssuersDocument {
    pub(crate) issuers: Vec<RelayTrustedIssuerDocument>,
    pub(crate) min_version: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayTrustedIssuerDocument {
    pub(crate) issuer: String,
    pub(crate) key_id: String,
    pub(crate) public_key: chio_core::crypto::PublicKey,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelaySigningKeyDocument {
    pub(crate) kernel_id: String,
    pub(crate) seed_hex: String,
}

pub(crate) fn cmd_chiodos_pheromone_relay_lint(
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    report: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let result = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    );
    let (accepted, code, detail, local_kernel_id, peer_directory_version) = match result {
        Ok(directory) => (
            true,
            "accepted".to_string(),
            "peer directory satisfies relay profile".to_string(),
            directory.local_kernel_id().to_string(),
            directory.version(),
        ),
        Err(error) => (
            false,
            "relay_profile_denied".to_string(),
            error.to_string(),
            "unknown".to_string(),
            None,
        ),
    };
    let lint_report = chio_pheromone_relay::RelayHealthReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA.to_string(),
        accepted,
        code: code.clone(),
        detail,
        local_kernel_id,
        generated_at_unix_ms: now,
        peer_directory_version,
        queue_depth: 0,
        oldest_pending_age_ms: None,
        retry_count: 0,
        dead_letter_count: 0,
        inbox_count: 0,
        cursor_count: 0,
        stale_lease_count: 0,
        checks: vec![chio_pheromone_relay::RelayHealthCheck {
            code,
            accepted,
            detail: "relay profile lint".to_string(),
        }],
    };
    let json = serde_json::to_string_pretty(&lint_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay lint: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_pheromone_relay_serve(
    listen: &str,
    store: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report_dir: &Path,
    operator_token_env: Option<&str>,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to create Chiodos pheromone relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let operator_token = if let Some(env_name) = operator_token_env {
        Some(std::env::var(env_name).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos pheromone relay operator token env {env_name}: {error}"
            ))
        })?)
    } else {
        None
    };
    if matches!(profile, chio_pheromone_relay::RelayProfile::Production)
        && operator_token.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(CliError::cli_other_error(
            "Chiodos pheromone relay production serve requires --operator-token-env".to_string(),
        ));
    }
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let policy_json = read_utf8_json_file(transit_policy, "Chiodos pheromone transit policy")?;
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(&policy_json, now).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone runtime policy: {error}"))
        })?;
    let package_json = read_utf8_json_file(proof_package, "Chiodos proof package")?;
    let package = chio_chiodos::proof_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle, "Chiodos verifier trust bundle")?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context, "Chiodos verification context")?;
    let context = chio_chiodos::verification_context_from_json(&context_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
    let resolver = chio_pheromone_runtime::VerifiedChiodosWorkflowResolver::from_verified_package(
        &package,
        &trust_bundle,
        &context,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos workflow resolver: {error}")))?;
    let relay_store = std::sync::Arc::new(
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}"))
        })?,
    );
    let receiver = std::sync::Arc::new(CliRelayBatchReceiver {
        store: store.to_path_buf(),
        transit_policy,
        receiver_config,
        resolver,
    });
    let service = chio_pheromone_relay::PheromoneRelayService::new(
        chio_pheromone_relay::PheromoneRelayConfig {
            local_kernel_id: peer_directory.local_kernel_id().to_string(),
            profile,
            now_unix_ms: now,
            freshness_window_ms: 60_000,
            max_body_bytes: 1_048_576,
            use_system_clock: true,
            operator_token,
            report_dir: Some(report_dir.to_path_buf()),
        },
        peer_directory,
        receiver,
        relay_store,
    );
    let address = listen.parse::<std::net::SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("Chiodos pheromone relay listen address: {error}"))
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay runtime: {error}")))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await.map_err(|error| {
            CliError::cli_other_error(format!("Chiodos pheromone relay bind: {error}"))
        })?;
        service
            .serve(listener)
            .await
            .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone relay: {error}")))
    })
}

pub(crate) fn cmd_chiodos_pheromone_relay_enqueue(
    store: &Path,
    batch: &Path,
    transit_policy: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now_unix_ms,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let batch_json = read_utf8_json_file(batch, "Chiodos pheromone relay batch")?;
    let batch: chio_federation::PheromoneGossipBatch = serde_json::from_str(&batch_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay batch: {error}")))?;
    let transit_policy_json =
        read_utf8_json_file(transit_policy, "Chiodos pheromone relay transit policy")?;
    let transit_policy: chio_federation::PheromoneTransitPolicy =
        serde_json::from_str(&transit_policy_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos relay transit policy: {error}"))
        })?;
    validate_relay_enqueue_batch(&directory, &batch, &transit_policy, now_unix_ms)?;
    let peer_entry = directory.peer(&batch.recipient_kernel_id).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay enqueue peer directory: {error}"))
    })?;
    if !peer_entry
        .treaty_subscriptions
        .iter()
        .any(|id| id == &batch.treaty_id)
    {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay enqueue peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} is not subscribed to treaty {}",
                batch.recipient_kernel_id, batch.treaty_id
            ))
        )));
    }
    if batch.frames.len() > peer_entry.max_batch_frames {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay enqueue peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::RelayProfileDenied(format!(
                "batch frame count {} exceeds peer bound {}",
                batch.frames.len(),
                peer_entry.max_batch_frames
            ))
        )));
    }
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    relay_store
        .enqueue_batch(
            directory.local_kernel_id(),
            &batch.recipient_kernel_id,
            &batch.treaty_id,
            &batch,
            now_unix_ms,
        )
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay enqueue: {error}")))?;
    let status = relay_store
        .operator_report(directory.local_kernel_id(), now_unix_ms)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay enqueue: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_pheromone_relay_tick(
    store: &Path,
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: Option<u64>,
    max_batches: usize,
    signing_key: &Path,
    report: &Path,
    report_dir: Option<&Path>,
) -> Result<(), CliError> {
    let now_unix_ms = now_unix_ms.unwrap_or_else(unix_now_ms);
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now_unix_ms,
        profile,
        trusted_issuers,
        "Chiodos peer directory",
    )?;
    let (sender_kernel_id, keypair) = load_relay_signing_key(signing_key)?;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay runtime: {error}")))?;
    let tick_report = runtime
        .block_on(chio_pheromone_relay::deliver_due_batches(
            &relay_store,
            peer_directory,
            keypair,
            &sender_kernel_id,
            now_unix_ms,
            max_batches,
        ))
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay tick: {error}")))?;
    let json = serde_json::to_string_pretty(&tick_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))?;
    if let Some(report_dir) = report_dir {
        write_relay_outbound_event_report(
            report_dir,
            &sender_kernel_id,
            now_unix_ms,
            &tick_report,
        )?;
    }
    Ok(())
}

pub(crate) fn write_relay_outbound_event_report(
    report_dir: &Path,
    local_kernel_id: &str,
    generated_at_unix_ms: u64,
    tick_report: &chio_pheromone_relay::RelayTickReport,
) -> Result<(), CliError> {
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay event report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let code = if tick_report.accepted {
        "accepted".to_string()
    } else {
        tick_report
            .failures
            .first()
            .and_then(|failure| failure.split_once(": "))
            .map(|(_, code)| code.to_string())
            .unwrap_or_else(|| "outbound_delivery_failed".to_string())
    };
    let detail = format!(
        "delivered={} retried={} deadLettered={} duplicateIdempotent={}",
        tick_report.delivered,
        tick_report.retried,
        tick_report.dead_lettered,
        tick_report.duplicate_idempotent
    );
    let report = chio_pheromone_relay::RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: tick_report.accepted,
        code: code.clone(),
        detail,
        local_kernel_id: local_kernel_id.to_string(),
        generated_at_unix_ms,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: if tick_report.accepted {
            None
        } else {
            Some(code)
        },
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay event report: {error}")))?;
    let path = report_dir.join(format!("{generated_at_unix_ms}-outbound-delivery.json"));
    write_json_string(&path, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_pheromone_relay_catchup(
    store: &Path,
    peer: &str,
    peer_directory_state: Option<&Path>,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    now_unix_ms: Option<u64>,
    treaty: &str,
    after_cursor: &str,
    limit: usize,
    report: &Path,
) -> Result<(), CliError> {
    let state_path = peer_directory_state.ok_or_else(|| {
        CliError::cli_other_error(
            "Chiodos catch-up peer directory: --peer-directory-state is required".to_string(),
        )
    })?;
    let directory = load_relay_peer_directory_from_paths(
        None,
        Some(state_path),
        now_unix_ms.unwrap_or_else(unix_now_ms),
        profile,
        trusted_issuers,
        "Chiodos peer directory state",
    )?;
    let peer_entry = directory.peer(peer).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos catch-up peer directory: {error}"))
    })?;
    if !peer_entry.treaty_subscriptions.iter().any(|id| id == treaty) {
        return Err(CliError::cli_other_error(format!(
            "Chiodos catch-up peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                "peer {peer} is not subscribed to treaty {treaty}"
            ))
        )));
    }
    if limit > peer_entry.max_catchup_frames {
        return Err(CliError::cli_other_error(format!(
            "Chiodos catch-up peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                "requested limit {limit} exceeds peer bound {}",
                peer_entry.max_catchup_frames
            ))
        )));
    }
    let max_catchup_bytes = peer_entry.max_catchup_bytes;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}"))
    })?;
    let (frames, next_cursor) = relay_store
        .catchup_batches(peer, treaty, after_cursor, limit, max_catchup_bytes)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos catch-up: {error}")))?;
    let catchup = chio_pheromone_relay::CatchupResponse {
        schema: chio_pheromone_relay::PHEROMONE_CATCHUP_RESPONSE_SCHEMA.to_string(),
        accepted: true,
        responder_kernel_id: directory.local_kernel_id().to_string(),
        requester_kernel_id: peer.to_string(),
        treaty_id: treaty.to_string(),
        frames,
        next_cursor,
        code: format!("accepted_limit_{limit}"),
    };
    let json = serde_json::to_string_pretty(&catchup)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos catch-up report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn validate_relay_enqueue_batch(
    directory: &chio_pheromone_relay::PeerDirectory,
    batch: &chio_federation::PheromoneGossipBatch,
    transit_policy: &chio_federation::PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), CliError> {
    if batch.schema != chio_federation::PHEROMONE_GOSSIP_BATCH_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay enqueue batch: unsupported schema {}",
            batch.schema
        )));
    }
    let verification_context = chio_federation::PheromoneGossipBatchVerificationContext {
        now_unix_ms,
        recipient_kernel_id: batch.recipient_kernel_id.clone(),
        authenticated_sender_kernel_id: directory.local_kernel_id().to_string(),
    };
    chio_federation::verify_pheromone_gossip_batch(batch, transit_policy, &verification_context)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos relay enqueue batch: {error}"))
        })?;
    Ok(())
}

pub(crate) fn cmd_chiodos_pheromone_relay_status(store: &Path, report: &Path) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let status = relay_store
        .operator_report("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay status: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_pheromone_relay_observe(
    store: &Path,
    peer_directory_state: &Path,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: &Path,
    report_dir: &Path,
    limit: usize,
    report: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to create Chiodos relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let state_json = read_utf8_json_file(peer_directory_state, "Chiodos peer-directory state")?;
    let state = chio_pheromone_relay::peer_directory_state_from_json(&state_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let directory = state
        .active_directory(&trust)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))?;
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let report_document = relay_store
        .relay_observability_report(chio_pheromone_relay::RelayObservabilityInput {
            local_kernel_id: directory.local_kernel_id(),
            generated_at_unix_ms: now,
            peer_directory: Some(&directory),
            peer_directory_state: Some(&state),
            profile,
            recent_failure_limit: limit,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay observability: {error}")))?;
    write_pretty_json(report, &report_document, "Chiodos relay observability")
}

pub(crate) fn cmd_chiodos_pheromone_relay_metrics(
    store: &Path,
    format: chio_pheromone_relay::RelayMetricsFormat,
    output: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store = chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos pheromone relay store: {error}")),
    )?;
    let snapshot = relay_store
        .relay_metrics_snapshot("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay metrics: {error}")))?;
    write_json_string(output, &snapshot.render(format))
}



pub(crate) fn cmd_chiodos_pheromone_relay_trend(
    reports_dir: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let reports = read_relay_observability_reports(reports_dir)?;
    let events = read_relay_event_reports(event_dir)?;
    let trend = chio_pheromone_relay::generate_relay_trend_report(
        chio_pheromone_relay::RelayTrendInput {
            local_kernel_id: &profile.local_kernel_id,
            observability_reports: &reports,
            event_reports: &events,
            routing_profile: &profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend: {error}")))?;
    write_pretty_json(report, &trend, "Chiodos relay trend report")
}

pub(crate) fn read_relay_observability_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayObservabilityReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay observability report",
        chio_pheromone_relay::PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    )
}

pub(crate) fn read_relay_event_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayEventReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay event report",
        chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA,
    )
}
