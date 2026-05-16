fn cmd_chiodos_pheromone_receive(
    batch: &Path,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    store: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let batch_json = read_utf8_json_file(batch, "Chiodos pheromone gossip batch")?;
    let batch: chio_federation::PheromoneGossipBatch = serde_json::from_str(&batch_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone batch: {error}")))?;
    let policy_json = read_utf8_json_file(transit_policy, "Chiodos pheromone transit policy")?;
    let now_unix_ms = now_unix_ms.unwrap_or(batch.flushed_at_unix_ms);
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(&policy_json, now_unix_ms).map_err(
            |error| {
                CliError::cli_other_error(format!("Chiodos pheromone runtime policy: {error}"))
            },
        )?;
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
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let receiver = chio_pheromone_runtime::PheromoneReceiver::new(
        store,
        resolver,
        receiver_config,
    );
    let receive_report = receiver
        .receive_batch(&batch, &transit_policy)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone receive: {error}")))?;
    let report_json = serde_json::to_string_pretty(&receive_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))?;
    if receive_report.accepted {
        Ok(())
    } else {
        let failure = receive_report
            .frames
            .iter()
            .find(|frame| !frame.accepted)
            .map_or_else(
                || "unknown pheromone receiver rejection".to_string(),
                |frame| format!("{}: {}", frame.code, frame.detail),
            );
        Err(CliError::cli_other_error(format!(
            "Chiodos pheromone receive rejected batch: {failure}"
        )))
    }
}

fn cmd_chiodos_pheromone_query(
    store: &Path,
    subject_class: &str,
    namespace: &str,
    reputation_epoch: u64,
    peer_weights: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let weights_json = read_utf8_json_file(peer_weights, "Chiodos pheromone peer weights")?;
    let weights = chio_pheromone_runtime::peer_weights_from_json(&weights_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer weights: {error}")))?;
    let validation_context = chio_pheromone::PheromoneValidationContext {
        now_unix_ms: now_unix_ms.unwrap_or_else(unix_now_ms),
        replay_window_ms: 0,
        active_peers_in_treaty: 0,
        known_reputation_epochs: vec![reputation_epoch],
        passports: Vec::new(),
        kernel_public_keys: Vec::new(),
        subject_classes: Vec::new(),
        max_deposits_per_pair: 0,
    };
    let concentration = chio_pheromone_runtime::PheromoneRuntimeStore::query_concentration(
        &store,
        subject_class,
        namespace,
        validation_context.now_unix_ms,
        reputation_epoch,
        &validation_context,
        &weights,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone query: {error}")))?;
    let query_report = chio_pheromone_runtime::PheromoneQueryReport {
        schema: chio_pheromone_runtime::PHEROMONE_QUERY_REPORT_SCHEMA.to_string(),
        accepted: true,
        concentration,
    };
    let report_json = serde_json::to_string_pretty(&query_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))
}

#[derive(Clone)]
struct CliRelayBatchReceiver {
    store: std::path::PathBuf,
    transit_policy: chio_federation::PheromoneTransitPolicy,
    receiver_config: chio_pheromone_runtime::PheromoneReceiverConfig,
    resolver: chio_pheromone_runtime::VerifiedChiodosWorkflowResolver,
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
struct RelayTrustedIssuersDocument {
    issuers: Vec<RelayTrustedIssuerDocument>,
    min_version: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayTrustedIssuerDocument {
    issuer: String,
    key_id: String,
    public_key: chio_core::crypto::PublicKey,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelaySigningKeyDocument {
    kernel_id: String,
    seed_hex: String,
}

fn cmd_chiodos_pheromone_relay_lint(
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

fn cmd_chiodos_pheromone_relay_serve(
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

fn cmd_chiodos_pheromone_relay_enqueue(
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

fn cmd_chiodos_pheromone_relay_tick(
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

fn write_relay_outbound_event_report(
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

fn cmd_chiodos_pheromone_relay_catchup(
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

fn validate_relay_enqueue_batch(
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

fn cmd_chiodos_pheromone_relay_status(store: &Path, report: &Path) -> Result<(), CliError> {
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

fn cmd_chiodos_pheromone_relay_observe(
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

fn cmd_chiodos_pheromone_relay_metrics(
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

fn cmd_chiodos_pheromone_relay_alert_evaluate(
    observability_report: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    suppression_state: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let observability: chio_pheromone_relay::RelayObservabilityReport = serde_json::from_str(
        &read_utf8_json_file(observability_report, "Chiodos relay observability report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay observability report: {error}"))
    })?;
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let suppression = chio_pheromone_relay::relay_alert_suppression_state_from_json(
        &read_utf8_json_file(suppression_state, "Chiodos relay alert suppression state")?,
        &profile,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert suppression state: {error}"))
    })?;
    let events = read_relay_event_reports(event_dir)?;
    let alert_report =
        chio_pheromone_relay::evaluate_relay_alerts(chio_pheromone_relay::RelayAlertEvaluationInput {
            observability: &observability,
            routing_profile: &profile,
            suppression_state: Some(&suppression),
            event_reports: &events,
            now_unix_ms,
            expected_source_report_sha256: None,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert evaluate: {error}")))?;
    write_pretty_json(report, &alert_report, "Chiodos relay alert report")
}

fn cmd_chiodos_pheromone_relay_alert_handoff(
    alert_report: &Path,
    trend_report: &Path,
    routing_profile: &Path,
    handoff_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let alert_report: chio_pheromone_relay::RelayAlertReport = serde_json::from_str(
        &read_utf8_json_file(alert_report, "Chiodos relay alert report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert report: {error}")))?;
    let trend_report: chio_pheromone_relay::RelayTrendReport = serde_json::from_str(
        &read_utf8_json_file(trend_report, "Chiodos relay trend report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend report: {error}")))?;
    let routing_profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chiodos relay alert routing profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert routing profile: {error}"))
    })?;
    let handoff_profile = chio_pheromone_relay::relay_alert_handoff_profile_from_json(
        &read_utf8_json_file(handoff_profile, "Chiodos relay alert handoff profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff profile: {error}"))
    })?;
    let handoff_report = chio_pheromone_relay::evaluate_relay_alert_handoff(
        chio_pheromone_relay::RelayAlertHandoffInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            routing_profile: &routing_profile,
            handoff_profile: &handoff_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert handoff: {error}")))?;
    write_pretty_json(
        report,
        &handoff_report,
        "Chiodos relay alert handoff report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_normalize(
    profile: &Path,
    input_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile: chio_pheromone_relay::RelayAlertNormalizationProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            profile,
            "Chiodos relay alert normalization profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization profile: {error}"
            ))
        })?;
    let sources = read_relay_alert_normalization_sources(input_dir)?;
    let normalization =
        chio_pheromone_relay::normalize_relay_alert_delivery_evidence(
            chio_pheromone_relay::RelayAlertNormalizationInput {
                profile: &profile,
                sources: &sources,
                now_unix_ms,
            },
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos relay alert normalize: {error}"))
        })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos relay alert normalized evidence dir {}: {error}",
            out_dir.display()
        ))
    })?;
    for (index, evidence) in normalization.evidence.iter().enumerate() {
        let path = out_dir.join(format!("relay-alert-delivery-evidence-{index:03}.json"));
        write_pretty_json(&path, evidence, "Chiodos relay alert delivery evidence")?;
    }
    write_pretty_json(
        report,
        &normalization,
        "Chiodos relay alert normalization report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_import(
    handoff_report: &Path,
    delivery_profile: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let evidence = read_relay_alert_delivery_evidence(evidence_dir)?;
    let delivery_report = chio_pheromone_relay::evaluate_relay_alert_delivery(
        chio_pheromone_relay::RelayAlertDeliveryInput {
            handoff_report: &handoff_report,
            delivery_profile: &delivery_profile,
            evidence: &evidence,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery import: {error}"))
    })?;
    write_pretty_json(
        report,
        &delivery_report,
        "Chiodos relay alert delivery report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_acknowledge(
    handoff_report: &Path,
    delivery_report: &Path,
    delivery_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let acknowledgement_report = chio_pheromone_relay::evaluate_relay_alert_acknowledgement(
        chio_pheromone_relay::RelayAlertAcknowledgementInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            delivery_profile: &delivery_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert delivery acknowledgement: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &acknowledgement_report,
        "Chiodos relay alert acknowledgement report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_drift(
    handoff_reports_dir: &Path,
    delivery_reports_dir: &Path,
    delivery_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let handoff_reports = read_relay_alert_handoff_reports(handoff_reports_dir)?;
    let delivery_reports = read_relay_alert_delivery_reports(delivery_reports_dir)?;
    let drift_report = chio_pheromone_relay::generate_relay_alert_handoff_drift_report(
        chio_pheromone_relay::RelayAlertHandoffDriftInput {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery drift: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chiodos relay alert handoff drift report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_delivery_drift_window(
    handoff_reports_dir: &Path,
    delivery_reports_dir: &Path,
    delivery_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let delivery_profile = chio_pheromone_relay::relay_alert_delivery_profile_from_json(
        &read_utf8_json_file(delivery_profile, "Chiodos relay alert delivery profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery profile: {error}"))
    })?;
    let handoff_reports = read_relay_alert_handoff_reports(handoff_reports_dir)?;
    let delivery_reports = read_relay_alert_delivery_reports(delivery_reports_dir)?;
    let drift_report = chio_pheromone_relay::generate_relay_alert_delivery_drift_report_v2(
        chio_pheromone_relay::RelayAlertDeliveryDriftInputV2 {
            handoff_reports: &handoff_reports,
            delivery_reports: &delivery_reports,
            delivery_profile: &delivery_profile,
            since_unix_ms,
            until_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery drift-window: {error}"))
    })?;
    write_pretty_json(
        report,
        &drift_report,
        "Chiodos relay alert delivery drift report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_review(
    handoff_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    route_owner_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        serde_json::from_str(&read_utf8_json_file(
            drift_report,
            "Chiodos relay alert delivery drift report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery drift report: {error}"
            ))
        })?;
    let route_owner_profile: chio_pheromone_relay::RelayAlertRouteOwnerProfileDocument =
        serde_json::from_str(&read_utf8_json_file(
            route_owner_profile,
            "Chiodos relay alert route-owner profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert route-owner profile: {error}"
            ))
        })?;
    let review_packet = chio_pheromone_relay::generate_relay_alert_route_review_packet(
        chio_pheromone_relay::RelayAlertRouteReviewInput {
            handoff_report: &handoff_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            route_owner_profile: &route_owner_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert review: {error}")))?;
    write_pretty_json(
        report,
        &review_packet,
        "Chiodos relay alert route review packet",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_package(
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let alert_report: chio_pheromone_relay::RelayAlertReport = serde_json::from_str(
        &read_utf8_json_file(alert_report, "Chiodos relay alert report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay alert report: {error}")))?;
    let trend_report: chio_pheromone_relay::RelayTrendReport = serde_json::from_str(
        &read_utf8_json_file(trend_report, "Chiodos relay trend report")?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos relay trend report: {error}")))?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport = serde_json::from_str(
        &read_utf8_json_file(handoff_report, "Chiodos relay alert handoff report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert handoff report: {error}"))
    })?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        serde_json::from_str(&read_utf8_json_file(
            normalization_report,
            "Chiodos relay alert normalization report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization report: {error}"
            ))
        })?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport = serde_json::from_str(
        &read_utf8_json_file(delivery_report, "Chiodos relay alert delivery report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert delivery report: {error}"))
    })?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        serde_json::from_str(&read_utf8_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert acknowledgement report: {error}"
            ))
        })?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        serde_json::from_str(&read_utf8_json_file(
            drift_report,
            "Chiodos relay alert delivery drift report",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery drift report: {error}"
            ))
        })?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket = serde_json::from_str(
        &read_utf8_json_file(review_packet, "Chiodos relay alert route review packet")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert route review packet: {error}"))
    })?;
    let package = chio_pheromone_relay::generate_relay_alert_assurance_package(
        chio_pheromone_relay::RelayAlertAssuranceInput {
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance package: {error}"))
    })?;
    write_pretty_json(
        report,
        &package,
        "Chiodos relay alert assurance package",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_export(
    package: &Path,
    alert_report: &Path,
    trend_report: &Path,
    handoff_report: &Path,
    normalization_report: &Path,
    delivery_report: &Path,
    acknowledgement_report: &Path,
    drift_report: &Path,
    review_packet: &Path,
    retention_profile: &Path,
    signing_key: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let assurance_package: chio_pheromone_relay::RelayAlertAssurancePackage =
        read_json_file(package, "Chiodos relay alert assurance package")?;
    let alert_report: chio_pheromone_relay::RelayAlertReport =
        read_json_file(alert_report, "Chiodos relay alert report")?;
    let trend_report: chio_pheromone_relay::RelayTrendReport =
        read_json_file(trend_report, "Chiodos relay trend report")?;
    let handoff_report: chio_pheromone_relay::RelayAlertHandoffReport =
        read_json_file(handoff_report, "Chiodos relay alert handoff report")?;
    let normalization_report: chio_pheromone_relay::RelayAlertNormalizationReport =
        read_json_file(normalization_report, "Chiodos relay alert normalization report")?;
    let delivery_report: chio_pheromone_relay::RelayAlertDeliveryReport =
        read_json_file(delivery_report, "Chiodos relay alert delivery report")?;
    let acknowledgement_report: chio_pheromone_relay::RelayAlertAcknowledgementReport =
        read_json_file(
            acknowledgement_report,
            "Chiodos relay alert acknowledgement report",
        )?;
    let drift_report: chio_pheromone_relay::RelayAlertDeliveryDriftReportV2 =
        read_json_file(drift_report, "Chiodos relay alert delivery drift report")?;
    let review_packet: chio_pheromone_relay::RelayAlertRouteReviewPacket =
        read_json_file(review_packet, "Chiodos relay alert route review packet")?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let (exporter_id, signing_key) = load_relay_signing_key(signing_key)?;
    let bundle = chio_pheromone_relay::sign_relay_alert_assurance_export_bundle(
        chio_pheromone_relay::RelayAlertAssuranceExportBuildInput {
            bundle_id: "relay-alert-assurance-export",
            exporter_id: &exporter_id,
            exporter_key_id: "default",
            signing_key: &signing_key,
            alert_report: &alert_report,
            trend_report: &trend_report,
            handoff_report: &handoff_report,
            normalization_report: &normalization_report,
            delivery_report: &delivery_report,
            acknowledgement_report: &acknowledgement_report,
            drift_report: &drift_report,
            review_packet: &review_packet,
            assurance_package: &assurance_package,
            normalized_delivery_evidence: &normalization_report.evidence,
            retention_profile: &retention_profile,
            exported_at_unix_ms: now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance export: {error}"))
    })?;
    write_relay_alert_assurance_bundle(out_dir, &bundle)?;
    write_pretty_json(report, &bundle.report, "Chiodos relay alert assurance export report")
}

fn cmd_chiodos_pheromone_relay_alert_assurance_verify(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let verify_report = chio_pheromone_relay::verify_relay_alert_assurance_export_bundle(
        &bundle,
        &trusted_exporters,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance verify: {error}"))
    })?;
    write_pretty_json(
        report,
        &verify_report,
        "Chiodos relay alert assurance export report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_replay(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let replay_report = chio_pheromone_relay::generate_relay_alert_assurance_replay_report(
        chio_pheromone_relay::RelayAlertAssuranceReplayInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay alert assurance replay: {error}"))
    })?;
    write_pretty_json(
        report,
        &replay_report,
        "Chiodos relay alert assurance replay report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_retention_plan(
    bundle_root: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_bundle_root(bundle_root)?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let retention_report = chio_pheromone_relay::generate_relay_alert_assurance_retention_report(
        chio_pheromone_relay::RelayAlertAssuranceRetentionInput {
            bundles: &bundles,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance retention plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &retention_report,
        "Chiodos relay alert assurance retention report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_recovery_drill(
    bundle_dir: &Path,
    trusted_exporters: &Path,
    case_id: &str,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = read_relay_alert_assurance_bundle(bundle_dir)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let drill_report = chio_pheromone_relay::generate_relay_alert_assurance_recovery_drill_report(
        chio_pheromone_relay::RelayAlertAssuranceRecoveryDrillInput {
            bundle: &bundle,
            trusted_exporters: &trusted_exporters,
            case_id,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance recovery drill: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &drill_report,
        "Chiodos relay alert assurance recovery drill report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_archive_plan(
    bundle_root: &Path,
    trusted_exporters: &Path,
    archive_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let archive_profile: chio_pheromone_relay::RelayAlertAssuranceArchiveProfileDocument =
        read_json_file(
            archive_profile,
            "Chiodos relay alert assurance archive profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let archive_report = chio_pheromone_relay::generate_relay_alert_assurance_archive_report(
        chio_pheromone_relay::RelayAlertAssuranceArchiveInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            archive_profile: &archive_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance archive plan: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &archive_report,
        "Chiodos relay alert assurance archive report",
    )
}

fn cmd_chiodos_pheromone_relay_alert_assurance_closeout_review(
    bundle_root: &Path,
    trusted_exporters: &Path,
    closeout_profile: &Path,
    retention_profile: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundles = read_relay_alert_assurance_archive_candidates(bundle_root)?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chiodos relay alert assurance trusted exporters",
        )?;
    let closeout_profile: chio_pheromone_relay::RelayAlertAssuranceCloseoutProfileDocument =
        read_json_file(
            closeout_profile,
            "Chiodos relay alert assurance closeout profile",
        )?;
    let retention_profile: chio_pheromone_relay::RelayAlertAssuranceRetentionProfileDocument =
        read_json_file(retention_profile, "Chiodos relay alert assurance retention profile")?;
    let closeout_report = chio_pheromone_relay::generate_relay_alert_assurance_closeout_report(
        chio_pheromone_relay::RelayAlertAssuranceCloseoutInput {
            bundles: &bundles,
            trusted_exporters: &trusted_exporters,
            closeout_profile: &closeout_profile,
            retention_profile: &retention_profile,
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos relay alert assurance closeout review: {error}"
        ))
    })?;
    write_pretty_json(
        report,
        &closeout_report,
        "Chiodos relay alert assurance closeout report",
    )
}

fn cmd_chiodos_pheromone_relay_trend(
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

fn read_relay_observability_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayObservabilityReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay observability report",
        chio_pheromone_relay::PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    )
}

fn read_relay_event_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayEventReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay event report",
        chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA,
    )
}

fn read_relay_alert_delivery_evidence(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryEvidence>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert delivery evidence dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert delivery evidence dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut evidence = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert delivery evidence")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert delivery evidence {}: {error}",
                path.display()
            ))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str())
            != Some(chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
        {
            continue;
        }
        evidence.push(
            chio_pheromone_relay::relay_alert_delivery_evidence_from_json(&json).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos relay alert delivery evidence {}: {error}",
                        path.display()
                    ))
                },
            )?,
        );
    }
    Ok(evidence)
}

fn read_relay_alert_normalization_sources(
    dir: &Path,
) -> Result<Vec<serde_json::Value>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert normalization input dir {}: {error}",
            dir.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert normalization input dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut sources = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, "relay alert normalization input")?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos relay alert normalization input {}: {error}",
                path.display()
            ))
        })?;
        sources.push(value);
    }
    Ok(sources)
}

fn read_relay_alert_handoff_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertHandoffReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert handoff report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    )
}

fn read_relay_alert_delivery_reports(
    dir: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertDeliveryReport>, CliError> {
    read_json_documents_from_dir(
        dir,
        "relay alert delivery report",
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    )
}

fn read_json_documents_from_dir<T: DeserializeOwned>(
    dir: &Path,
    label: &str,
    schema: &str,
) -> Result<Vec<T>, CliError> {
    let entries = fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!("failed to read Chiodos {label} dir {}: {error}", dir.display()))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos {label} dir entry {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        let json = read_utf8_json_file(&path, label)?;
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        if value.get("schema").and_then(|schema| schema.as_str()) != Some(schema) {
            continue;
        }
        let document = serde_json::from_str(&json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos {label} {}: {error}", path.display()))
        })?;
        documents.push(document);
    }
    Ok(documents)
}

fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, CliError> {
    serde_json::from_str(&read_utf8_json_file(path, label)?)
        .map_err(|error| CliError::cli_other_error(format!("{label} {}: {error}", path.display())))
}

fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    ensure_clean_output_dir(out_dir)?;
    write_pretty_json(
        &out_dir.join("manifest.json"),
        &bundle.manifest,
        "Chiodos relay alert assurance export manifest",
    )?;
    write_pretty_json(
        &out_dir.join("relay-alert-assurance-export-report.json"),
        &bundle.report,
        "Chiodos relay alert assurance export report",
    )?;
    for file in &bundle.files {
        let path = safe_bundle_path(out_dir, &file.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chiodos relay alert assurance export dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &file.bytes).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write Chiodos relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn read_relay_alert_assurance_bundle(
    bundle_dir: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    let manifest: chio_pheromone_relay::RelayAlertAssuranceExportManifest = read_json_file(
        &bundle_dir.join("manifest.json"),
        "Chiodos relay alert assurance export manifest",
    )?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport = read_json_file(
        &bundle_dir.join("relay-alert-assurance-export-report.json"),
        "Chiodos relay alert assurance export report",
    )?;
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = safe_bundle_path(bundle_dir, &artifact.path)?;
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
        files.push(chio_pheromone_relay::RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes,
        });
    }
    Ok(chio_pheromone_relay::RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

fn read_relay_alert_assurance_bundle_root(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceExportBundle>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_bundle(bundle_root)?]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut bundles = Vec::new();
    for dir in dirs {
        bundles.push(read_relay_alert_assurance_bundle(&dir)?);
    }
    if bundles.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(bundles)
}

fn read_relay_alert_assurance_archive_candidates(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_archive_candidate(
            bundle_root,
        )]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut candidates = Vec::new();
    for dir in dirs {
        candidates.push(read_relay_alert_assurance_archive_candidate(&dir));
    }
    if candidates.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(candidates)
}

fn read_relay_alert_assurance_archive_candidate(
    bundle_dir: &Path,
) -> chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
    let bundle_path = relay_alert_assurance_bundle_label(bundle_dir);
    match read_relay_alert_assurance_bundle(bundle_dir) {
        Ok(bundle) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: Some(bundle),
            error_code: None,
            error_detail: None,
        },
        Err(error) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: None,
            error_code: Some("bundle_read_failed".to_string()),
            error_detail: Some(error.to_string()),
        },
    }
}

fn relay_alert_assurance_bundle_label(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("export-bundle")
        .to_string()
}

fn ensure_clean_output_dir(out_dir: &Path) -> Result<(), CliError> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries.next().transpose().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?.is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chiodos output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chiodos output directory {}: {error}",
                out_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn safe_bundle_path(root: &Path, relative: &str) -> Result<PathBuf, CliError> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || Path::new(relative).is_absolute()
    {
        return Err(CliError::cli_other_error(format!(
            "Chiodos relay alert assurance export path {relative} is not relative"
        )));
    }
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "Chiodos relay alert assurance export path {relative} is unsafe"
            )));
        }
        path.push(segment);
    }
    Ok(path)
}

fn cmd_chiodos_pheromone_relay_directory_inspect(
    state: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let json = read_utf8_json_file(state, "Chiodos peer-directory state")?;
    let state = chio_pheromone_relay::peer_directory_state_from_json(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos peer-directory state: {error}"))
    })?;
    let inspection = chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: state.active.is_some(),
        code: if state.active.is_some() {
            "accepted".to_string()
        } else {
            "peer_directory_state_invalid".to_string()
        },
        detail: if state.active.is_some() {
            "peer-directory state has an active directory".to_string()
        } else {
            "peer-directory state has no active directory".to_string()
        },
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: unix_now_ms(),
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: state
            .candidate
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: state
            .active
            .as_ref()
            .map(|entry| entry.removed_peer_ids.clone())
            .unwrap_or_default(),
    };
    write_pretty_json(report, &inspection, "Chiodos peer-directory inspection")
}

fn cmd_chiodos_pheromone_relay_directory_promote(
    state: &Path,
    candidate: &Path,
    trusted_issuers: &Path,
    profile: chio_pheromone_relay::RelayProfile,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let result = chio_pheromone_relay::promote_peer_directory_candidate(
        &mut state_document,
        candidate,
        &trust,
        now,
    );
    let report_document = match result {
        Ok(report_document) => report_document,
        Err(error) => {
            let report_document =
                peer_directory_rotation_error_report(&state_document, now, &error);
            write_peer_directory_state(state, &state_document)?;
            write_pretty_json(report, &report_document, "Chiodos peer-directory rotation")?;
            return Err(CliError::cli_other_error(format!(
                "Chiodos peer-directory candidate promote: {error}"
            )));
        }
    };
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chiodos peer-directory rotation")
}

fn cmd_chiodos_pheromone_relay_directory_reject(
    state: &Path,
    candidate: &Path,
    reason: &str,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let now = now_unix_ms.unwrap_or_else(unix_now_ms);
    let candidate = load_relay_peer_directory_bundle(candidate)?;
    let mut state_document = load_or_create_peer_directory_state(state, &candidate, now)?;
    let report_document = chio_pheromone_relay::reject_peer_directory_candidate(
        &mut state_document,
        candidate,
        reason,
        now,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos peer-directory candidate reject: {error}"))
    })?;
    write_peer_directory_state(state, &state_document)?;
    write_pretty_json(report, &report_document, "Chiodos peer-directory rejection")
}

fn cmd_chiodos_pheromone_relay_supervisor_lint(
    profile: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile_json = read_utf8_json_file(profile, "Chiodos relay supervisor profile")?;
    let lint_report = match chio_pheromone_relay::relay_supervisor_profile_from_json(&profile_json)
    {
        Ok(profile_document) => {
            chio_pheromone_relay::lint_relay_supervisor_profile(&profile_document, unix_now_ms())
        }
        Err(error) => chio_pheromone_relay::RelayDrillReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_DRILL_REPORT_SCHEMA.to_string(),
            accepted: false,
            code: error.code().to_string(),
            detail: error.to_string(),
            generated_at_unix_ms: unix_now_ms(),
            checks: vec![chio_pheromone_relay::RelayDrillCheck {
                code: error.code().to_string(),
                accepted: false,
                detail: "relay supervisor profile could not be parsed".to_string(),
            }],
        },
    };
    write_pretty_json(report, &lint_report, "Chiodos relay supervisor lint")
}

fn load_relay_peer_directory_from_paths(
    peer_directory: Option<&Path>,
    peer_directory_state: Option<&Path>,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<&Path>,
    label: &str,
) -> Result<chio_pheromone_relay::PeerDirectory, CliError> {
    if let Some(state_path) = peer_directory_state {
        let state_json = read_utf8_json_file(state_path, "Chiodos peer-directory state")?;
        let state = chio_pheromone_relay::peer_directory_state_from_json(&state_json)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
        let trusted_issuers = trusted_issuers.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "{label}: signed peer-directory state requires trusted issuers"
            ))
        })?;
        let trust = build_peer_directory_bundle_trust(trusted_issuers, now_unix_ms, profile)?;
        return state
            .active_directory(&trust)
            .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")));
    }
    let peer_directory = peer_directory.ok_or_else(|| {
        CliError::cli_other_error(format!("{label}: peer directory or state is required"))
    })?;
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(CliError::cli_other_error(format!(
            "{label}: production profile requires peer-directory state"
        )));
    }
    let json = read_utf8_json_file(peer_directory, label)?;
    let trusted = load_optional_relay_trusted_issuers(trusted_issuers)?;
    parse_relay_peer_directory_json(&json, now_unix_ms, profile, trusted)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))
}

fn parse_relay_peer_directory_json(
    json: &str,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
    trusted_issuers: Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>,
) -> Result<chio_pheromone_relay::PeerDirectory, chio_pheromone_relay::PheromoneRelayError> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
        chio_pheromone_relay::PheromoneRelayError::Json(error.to_string())
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if schema == chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA {
        let bundle: chio_pheromone_relay::PeerDirectoryBundleDocument =
            serde_json::from_value(value).map_err(chio_pheromone_relay::PheromoneRelayError::from)?;
        let (issuers, min_version) = trusted_issuers.ok_or_else(|| {
            chio_pheromone_relay::PheromoneRelayError::UnknownPeerDirectoryIssuer(
                "signed peer-directory bundle requires trusted issuers".to_string(),
            )
        })?;
        let trust = chio_pheromone_relay::PeerDirectoryBundleTrust {
            issuers,
            min_version,
            now_unix_ms,
            profile,
            limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
        };
        return bundle.verify(&trust);
    }
    if profile == chio_pheromone_relay::RelayProfile::Production {
        return Err(chio_pheromone_relay::PheromoneRelayError::PeerDirectoryUnsigned(
            "production profile requires a signed peer-directory bundle".to_string(),
        ));
    }
    chio_pheromone_relay::peer_directory_from_json_with_profile(
        json,
        now_unix_ms,
        profile,
        &chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    )
}

fn load_optional_relay_trusted_issuers(
    path: Option<&Path>,
) -> Result<Option<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64)>, CliError> {
    path.map(load_relay_trusted_issuers).transpose()
}

fn load_relay_trusted_issuers(
    path: &Path,
) -> Result<(Vec<chio_pheromone_relay::TrustedPeerDirectoryIssuer>, u64), CliError> {
    let json = read_utf8_json_file(path, "Chiodos relay trusted issuers")?;
    let document: RelayTrustedIssuersDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay trusted issuers: {error}"))
    })?;
    let issuers = document
        .issuers
        .into_iter()
        .map(|issuer| chio_pheromone_relay::TrustedPeerDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect();
    Ok((issuers, document.min_version.unwrap_or(0)))
}

fn build_peer_directory_bundle_trust(
    trusted_issuers: &Path,
    now_unix_ms: u64,
    profile: chio_pheromone_relay::RelayProfile,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleTrust, CliError> {
    let (issuers, min_version) = load_relay_trusted_issuers(trusted_issuers)?;
    Ok(chio_pheromone_relay::PeerDirectoryBundleTrust {
        issuers,
        min_version,
        now_unix_ms,
        profile,
        limits: chio_pheromone_relay::RelayProfileLimits::production_defaults(),
    })
}

fn load_relay_peer_directory_bundle(
    path: &Path,
) -> Result<chio_pheromone_relay::PeerDirectoryBundleDocument, CliError> {
    let json = read_utf8_json_file(path, "Chiodos peer-directory bundle")?;
    serde_json::from_str(&json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory bundle: {error}")))
}

fn load_or_create_peer_directory_state(
    path: &Path,
    candidate: &chio_pheromone_relay::PeerDirectoryBundleDocument,
    now_unix_ms: u64,
) -> Result<chio_pheromone_relay::PeerDirectoryStateDocument, CliError> {
    if path.exists() {
        let json = read_utf8_json_file(path, "Chiodos peer-directory state")?;
        chio_pheromone_relay::peer_directory_state_from_json(&json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos peer-directory state: {error}")))
    } else {
        Ok(chio_pheromone_relay::PeerDirectoryStateDocument::new(
            &candidate.directory.local_kernel_id,
            now_unix_ms,
        ))
    }
}

fn write_peer_directory_state(
    path: &Path,
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
) -> Result<(), CliError> {
    write_pretty_json(path, state, "Chiodos peer-directory state")
}

fn peer_directory_rotation_error_report(
    state: &chio_pheromone_relay::PeerDirectoryStateDocument,
    now_unix_ms: u64,
    error: &chio_pheromone_relay::PheromoneRelayError,
) -> chio_pheromone_relay::PeerDirectoryRotationReport {
    let rejected = state.rejected.last();
    chio_pheromone_relay::PeerDirectoryRotationReport {
        schema: chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: error.code().to_string(),
        detail: error.to_string(),
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        previous_version: state.active.as_ref().map(|entry| entry.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|entry| entry.bundle_sha256.clone()),
        candidate_bundle_sha256: rejected.and_then(|entry| entry.bundle_sha256.clone()),
        removed_peer_ids: Vec::new(),
    }
}

fn write_pretty_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
    label: &str,
) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    write_json_string(path, &format!("{json}\n"))
}

fn load_relay_signing_key(path: &Path) -> Result<(String, Keypair), CliError> {
    let json = read_utf8_json_file(path, "Chiodos relay signing key")?;
    let document: RelaySigningKeyDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos relay signing key: {error}"))
    })?;
    if document.kernel_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "Chiodos relay signing key: kernel id is empty",
        ));
    }
    let keypair = Keypair::from_seed_hex(document.seed_hex.trim())
        .map_err(|error| CliError::cli_other_error(format!("Chiodos relay signing key: {error}")))?;
    Ok((document.kernel_id, keypair))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

