use super::{
    build_iroh_outbound_endpoint, build_iroh_router, build_peer_directory_bundle_trust,
    iroh_transport_metrics_prometheus, load_chio_verified_workflow_resolver,
    load_chio_workflow_verifier_trust_bundle, load_iroh_serve_inputs,
    load_relay_peer_directory_from_paths, load_relay_signing_key, note_router_liveness,
    read_json_documents_from_dir, read_utf8_json_file, run_directory_reloader, unix_now_ms,
    write_json_string, write_pretty_json, DirectoryReloadConfig, IrohServeInputs,
};
use crate::CliError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Clone)]
pub(crate) struct CliRelayBatchReceiver {
    pub(crate) store: std::path::PathBuf,
    pub(crate) transit_policy: chio_federation::pheromone_gossip::PheromoneTransitPolicy,
    pub(crate) receiver_config: chio_pheromone_runtime::PheromoneReceiverConfig,
    pub(crate) resolver: chio_pheromone_runtime::VerifiedChioWorkflowResolver,
}

#[async_trait::async_trait]
impl chio_pheromone_relay::RelayBatchReceiver for CliRelayBatchReceiver {
    async fn receive_batch(
        &self,
        batch: chio_federation::pheromone_gossip::PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<
        chio_pheromone_runtime::PheromoneReceiveReport,
        chio_pheromone_relay::PheromoneRelayError,
    > {
        let mut config = self.receiver_config.clone();
        config.authenticated_sender_kernel_id = authenticated_sender_kernel_id;
        config.validation_context.now_unix_ms = received_at_unix_ms;
        let store = chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore::open(&self.store)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))?;
        let receiver =
            chio_pheromone_runtime::PheromoneReceiver::new(store, self.resolver.clone(), config);
        receiver
            .receive_batch(&batch, &self.transit_policy)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))
    }

    async fn recorded_report_for_batch(
        &self,
        batch_sha256: &str,
        authenticated_sender_kernel_id: &str,
    ) -> Result<
        Option<chio_pheromone_runtime::PheromoneReceiveReport>,
        chio_pheromone_relay::PheromoneRelayError,
    > {
        // Consult the same runtime store receive_batch opens: surface a
        // durably-committed verdict for this (batch, sender) pair without re-running
        // receive_batch. The sender scope is applied at the query
        // level so a cross-sender verdict for the same bytes is never returned. Store
        // errors map to the Json variant, the same internal-error shape receive_batch
        // uses for a store-open failure above.
        let store = chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore::open(&self.store)
            .map_err(|error| chio_pheromone_relay::PheromoneRelayError::Json(error.to_string()))?;
        store
            .lookup_receive_report_by_batch(batch_sha256, authenticated_sender_kernel_id)
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

pub(crate) fn cmd_chio_pheromone_relay_lint(
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
        "Chio peer directory",
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
        .map_err(|error| CliError::cli_other_error(format!("Chio relay lint: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_chio_pheromone_relay_serve(
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
    iroh_enable: bool,
    iroh_transport_directory: Option<&Path>,
    iroh_transport_directory_state: Option<&Path>,
    iroh_transport_key: Option<&Path>,
    iroh_bind_addr: &str,
    iroh_relay_url: &[String],
    iroh_lanes: &str,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    // DEPLOYABILITY (opt-in, DUAL): load + verify the iroh federation-transport
    // inputs up front. Fail-closed: with --iroh-enable set, any bad input aborts
    // serve before the endpoint binds; with it unset this returns None WITHOUT
    // touching any file, so the serve path below is byte-for-byte unchanged.
    let iroh_inputs = load_iroh_serve_inputs(
        iroh_enable,
        iroh_transport_directory,
        iroh_transport_directory_state,
        trusted_issuers,
        iroh_transport_key,
        iroh_bind_addr,
        iroh_relay_url,
        iroh_lanes,
        now,
    )?;
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to create Chio pheromone relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let operator_token = if let Some(env_name) = operator_token_env {
        Some(std::env::var(env_name).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio pheromone relay operator token env {env_name}: {error}"
            ))
        })?)
    } else {
        None
    };
    if matches!(profile, chio_pheromone_relay::RelayProfile::Production)
        && operator_token.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(CliError::cli_other_error(
            "Chio pheromone relay production serve requires --operator-token-env".to_string(),
        ));
    }
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now,
        profile,
        trusted_issuers,
        "Chio peer directory",
    )?;
    let policy_json = read_utf8_json_file(transit_policy, "Chio pheromone transit policy")?;
    let workflow_trust_bundle = load_chio_workflow_verifier_trust_bundle(trust_bundle)?;
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(
            &policy_json,
            now,
            workflow_trust_bundle.runtime_policy_issuer_public_keys(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone runtime policy: {error}"))
        })?;
    let resolver = load_chio_verified_workflow_resolver(proof_package, trust_bundle, context)?;
    let relay_store = std::sync::Arc::new(
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?,
    );
    let receiver = std::sync::Arc::new(CliRelayBatchReceiver {
        store: store.to_path_buf(),
        transit_policy,
        receiver_config,
        resolver,
    });
    // Share the SAME receiver + store the HTTP relay uses (one receiver, one store,
    // two transports) with the optional iroh mount, BEFORE the service takes
    // ownership of them below. The peer directory is cloned here (also before the
    // service takes ownership) so the iroh ingress handler enforces the SAME inbound
    // directory-scope gate the HTTP relay applies. `None` when --iroh-enable is off.
    let relay_limits = relay_service_limits_for_profile(profile);
    let iroh_ingress_max_body_bytes = relay_limits.max_body_bytes;
    let iroh_mount_plan = iroh_inputs.map(|inputs| {
        let receiver: std::sync::Arc<dyn chio_pheromone_relay::RelayBatchReceiver> =
            receiver.clone();
        (inputs, receiver, relay_store.clone(), peer_directory.clone())
    });
    let mut service = chio_pheromone_relay::PheromoneRelayService::new(
        chio_pheromone_relay::PheromoneRelayConfig {
            local_kernel_id: peer_directory.local_kernel_id().to_string(),
            profile,
            now_unix_ms: now,
            freshness_window_ms: relay_limits.freshness_window_ms,
            max_body_bytes: relay_limits.max_body_bytes,
            use_system_clock: true,
            operator_token,
            report_dir: Some(report_dir.to_path_buf()),
        },
        peer_directory,
        receiver,
        relay_store,
    );
    // DEPLOYABILITY (opt-in, DUAL): when the iroh transport is mounted, expose its
    // process-global metric families on the SAME live relay /metrics endpoint for
    // the whole process lifetime (not just a shutdown-time debug snapshot). The
    // hook is a plain render function pointer; chio-pheromone-relay never depends
    // on the iroh transport crate (that would be a dependency cycle) - it only
    // calls the injected callback. With --iroh-enable off, iroh_mount_plan is None,
    // so no hook is attached and the /metrics response is byte-for-byte unchanged.
    if iroh_mount_plan.is_some() {
        service = service.with_extra_metrics_hook(std::sync::Arc::new(
            iroh_transport_metrics_prometheus as fn() -> String,
        ));
    }
    let address = listen.parse::<std::net::SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone relay listen address: {error}"))
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chio relay runtime: {error}")))?;
    runtime.block_on(async move {
        // Mount the iroh federation-transport lanes ALONGSIDE the axum serve (DUAL:
        // the HTTP relay always keeps running). `None` when --iroh-enable is off, in
        // which case this closure behaves exactly as before. Fail-closed: an iroh
        // setup error aborts startup rather than silently serving HTTP-only.
        let iroh_mount = match iroh_mount_plan {
            Some((inputs, receiver, relay_store, peer_directory)) => {
                let mount = build_iroh_router(
                    inputs,
                    receiver,
                    relay_store,
                    peer_directory,
                    iroh_ingress_max_body_bytes,
                )
                .await?;
                // DEPLOYABILITY: print the ACTUAL bound address(es) + the EndpointId
                // (short + full) + the enabled lanes so the operator knows exactly
                // what to configure on peers. With the default ephemeral
                // --iroh-bind-addr this is the only place the reachable port surfaces.
                tracing::info!(
                    target: "chio.iroh.transport",
                    endpoint_id = %mount.endpoint_id,
                    endpoint_id_short = %mount.endpoint_id.fmt_short(),
                    bound_sockets = ?mount.bound_sockets,
                    lanes = ?mount.enabled_lanes,
                    "iroh federation-transport mounted alongside the HTTP relay (DUAL, opt-in \
                     --iroh-enable); configure peers with this EndpointId and one of the bound \
                     socket addresses (for a durable deployment set a stable --iroh-bind-addr \
                     plus discovery/--iroh-relay-url)"
                );
                Some(mount)
            }
            None => None,
        };
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio pheromone relay bind: {error}"))
            })?;

        // Spawn the directory reloader and the router-liveness watchdog alongside the
        // serve when the iroh transport is mounted. Both are dedicated tasks feeding
        // shared state, aborted before the router teardown below.
        let iroh_background = iroh_mount.as_ref().map(|mount| {
            let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            chio_federation_transport_iroh::metrics::set_router_alive(true);

            // Re-verify the directory bundle every interval, fail closed on expiry.
            let reloader = match (iroh_transport_directory, trusted_issuers) {
                (Some(bundle_path), Some(issuers_path)) => {
                    let reload_config = DirectoryReloadConfig {
                        interval: std::time::Duration::from_secs(60),
                        bundle_path: bundle_path.to_path_buf(),
                        trusted_issuers_path: issuers_path.to_path_buf(),
                        // This node's actual bound transport endpoint. The reloader
                        // rechecks every re-verified successor against it and fails
                        // closed to deny-all if the successor tombstones or rotates
                        // this binding.
                        local_transport_endpoint: mount.endpoint_id,
                        // This node's localKernelId, so the recheck requires the
                        // successor to bind THIS kernel to THIS endpoint (mirroring the
                        // startup check), not merely that the endpoint resolves to some
                        // kernel.
                        local_kernel_id: mount.transport_local_kernel_id.clone(),
                    };
                    Some(tokio::spawn(run_directory_reloader(
                        mount.gate.clone(),
                        reload_config,
                        std::sync::Arc::new(unix_now_ms),
                        std::sync::Arc::clone(&alive),
                    )))
                }
                _ => None,
            };

            // A panicked accept task kills the whole Router while HTTP keeps
            // serving; poll liveness and make the freeze loud.
            let router = mount.router.clone();
            let watchdog_alive = std::sync::Arc::clone(&alive);
            let watchdog = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    if router.is_shutdown() || router.endpoint().is_closed() {
                        note_router_liveness(false);
                        watchdog_alive.store(false, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                }
            });
            (reloader, watchdog)
        });

        let serve_result = service
            .serve(listener)
            .await
            .map_err(|error| CliError::cli_other_error(format!("Chio pheromone relay: {error}")));
        if let Some((reloader, watchdog)) = iroh_background {
            if let Some(reloader) = reloader {
                reloader.abort();
            }
            watchdog.abort();
        }
        if let Some(mount) = iroh_mount {
            // The live iroh federation-transport metrics are scraped on the relay's
            // own /metrics endpoint for the whole process lifetime (see the
            // with_extra_metrics_hook wiring above), so teardown just stops the
            // router; no post-mortem snapshot is needed.
            let _ = mount.router.shutdown().await;
        }
        serve_result
    })
}

pub(crate) fn cmd_chio_pheromone_relay_enqueue(
    store: &Path,
    batch: &Path,
    transit_policy: &Path,
    trust_bundle: &Path,
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
        "Chio peer directory",
    )?;
    let batch_json = read_utf8_json_file(batch, "Chio pheromone relay batch")?;
    let batch: chio_federation::pheromone_gossip::PheromoneGossipBatch = serde_json::from_str(&batch_json)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay batch: {error}")))?;
    let transit_policy_json =
        read_utf8_json_file(transit_policy, "Chio pheromone relay transit policy")?;
    let workflow_trust_bundle = load_chio_workflow_verifier_trust_bundle(trust_bundle)?;
    let (transit_policy, _receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(
            &transit_policy_json,
            now_unix_ms,
            workflow_trust_bundle.runtime_policy_issuer_public_keys(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio relay transit policy: {error}"))
        })?;
    validate_relay_enqueue_batch(&directory, &batch, &transit_policy, now_unix_ms)?;
    let peer_entry = directory
        .peer(&batch.recipient_kernel_id)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio relay enqueue peer directory: {error}"))
        })?;
    if !peer_entry
        .treaty_subscriptions
        .iter()
        .any(|id| id == &batch.treaty_id)
    {
        return Err(CliError::cli_other_error(format!(
            "Chio relay enqueue peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} is not subscribed to treaty {}",
                batch.recipient_kernel_id, batch.treaty_id
            ))
        )));
    }
    if batch.frames.len() > peer_entry.max_batch_frames {
        return Err(CliError::cli_other_error(format!(
            "Chio relay enqueue peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::RelayProfileDenied(format!(
                "batch frame count {} exceeds peer bound {}",
                batch.frames.len(),
                peer_entry.max_batch_frames
            ))
        )));
    }
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    relay_store
        .enqueue_batch(
            directory.local_kernel_id(),
            &batch.recipient_kernel_id,
            &batch.treaty_id,
            &batch,
            now_unix_ms,
        )
        .map_err(|error| CliError::cli_other_error(format!("Chio relay enqueue: {error}")))?;
    let status = relay_store
        .operator_report(directory.local_kernel_id(), now_unix_ms)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay enqueue: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_chio_pheromone_relay_tick(
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
    iroh_enable: bool,
    iroh_transport_directory: Option<&Path>,
    iroh_transport_directory_state: Option<&Path>,
    iroh_transport_key: Option<&Path>,
    iroh_bind_addr: &str,
    iroh_relay_url: &[String],
    iroh_peer_addr: &[String],
    iroh_lanes: &str,
) -> Result<(), CliError> {
    let now_unix_ms = now_unix_ms.unwrap_or_else(unix_now_ms);
    let peer_directory = load_relay_peer_directory_from_paths(
        peer_directory,
        peer_directory_state,
        now_unix_ms,
        profile,
        trusted_issuers,
        "Chio peer directory",
    )?;
    let (sender_kernel_id, keypair) = load_relay_signing_key(signing_key)?;
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    // DUAL outbound transport (opt-in, default OFF): with --iroh-enable this tick drains
    // due batches over the iroh federation transport INSTEAD of HTTP, mirroring how
    // deliver_due_batches is scheduled (a one-shot operator/cron tick). Fail-closed:
    // with the flag set, any bad iroh input aborts before draining; with it unset this
    // returns None WITHOUT touching any file, so the HTTP path below is byte-for-byte
    // unchanged. Running an iroh tick and an HTTP tick against the SAME store would
    // both lease the same outbox rows, so a single invocation drains over exactly ONE
    // transport (the operator picks per tick).
    let iroh_inputs = load_iroh_serve_inputs(
        iroh_enable,
        iroh_transport_directory,
        iroh_transport_directory_state,
        trusted_issuers,
        iroh_transport_key,
        iroh_bind_addr,
        iroh_relay_url,
        iroh_lanes,
        now_unix_ms,
    )?;
    let tick_report = if let Some(iroh_inputs) = iroh_inputs {
        // Fail-closed signing/transport identity binding for the iroh drain. The drain
        // leases + drains outbox rows keyed on `sender_kernel_id` (the relay SIGNING
        // key's kernelId from load_relay_signing_key), but the outbound iroh endpoint
        // authenticates as the peer/transport directory's LOCAL identity
        // (`peer_directory.local_kernel_id()`, which build_iroh_outbound_endpoint pins to
        // the verified transport directory's localKernelId). Recipients verify pheromone
        // frames against the AUTHENTICATED transport sender, NOT the signing-key id, so if
        // these differ the queued rows for the signing key are drained yet
        // rejected/dead-lettered by recipients. Require the relay's signing identity and
        // its transport/directory local identity to be the SAME kernel BEFORE leasing or
        // draining any row.
        if sender_kernel_id.as_str() != peer_directory.local_kernel_id() {
            return Err(CliError::cli_other_error(format!(
                "Chio relay iroh tick: the relay signing key's kernel id '{}' does not match the \
                 peer/transport directory local kernel id '{}'; the outbound iroh endpoint \
                 authenticates as the directory local identity, so queued rows for the signing key \
                 would be rejected/dead-lettered by recipients (the relay's signing identity and \
                 its transport/directory local identity must be the same kernel)",
                sender_kernel_id,
                peer_directory.local_kernel_id()
            )));
        }
        // Direct-address book (relay-disabled / direct-address deployment): parse the
        // repeated --iroh-peer-addr entries into kernel_id -> dialable socket(s).
        // Parsed only on the iroh path so an HTTP-only tick is untouched; fail-closed
        // on any malformed entry.
        let peer_addr_book = parse_iroh_peer_addr_book(iroh_peer_addr)?;
        drain_due_batches_over_iroh(
            &relay_store,
            peer_directory,
            iroh_inputs,
            peer_addr_book,
            &sender_kernel_id,
            now_unix_ms,
            max_batches,
        )?
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CliError::cli_other_error(format!("Chio relay runtime: {error}")))?;
        runtime
            .block_on(chio_pheromone_relay::deliver_due_batches(
                &relay_store,
                peer_directory,
                keypair,
                &sender_kernel_id,
                now_unix_ms,
                max_batches,
            ))
            .map_err(|error| CliError::cli_other_error(format!("Chio relay tick: {error}")))?
    };
    let json = serde_json::to_string_pretty(&tick_report)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay report: {error}")))?;
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

/// Parse the repeated `--iroh-peer-addr` entries (`KERNEL_ID=HOST:PORT`) into a
/// `kernel_id -> dialable socket(s)` book for the direct-address deployment.
///
/// Fail-closed: any entry missing the `=` separator, with an empty kernel id, or whose
/// value is not a parseable socket address aborts the tick. Repeating a `KERNEL_ID`
/// appends another socket (a multi-homed recipient), de-duplicating identical sockets.
fn parse_iroh_peer_addr_book(
    entries: &[String],
) -> Result<HashMap<String, Vec<SocketAddr>>, CliError> {
    let mut book: HashMap<String, Vec<SocketAddr>> = HashMap::new();
    for entry in entries {
        let (kernel_id, addr) = entry.split_once('=').ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chio iroh peer address '{entry}': expected KERNEL_ID=HOST:PORT"
            ))
        })?;
        let kernel_id = kernel_id.trim();
        if kernel_id.is_empty() {
            return Err(CliError::cli_other_error(format!(
                "Chio iroh peer address '{entry}': empty kernel id"
            )));
        }
        let socket = addr.trim().parse::<SocketAddr>().map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio iroh peer address '{entry}': invalid socket address: {error}"
            ))
        })?;
        let sockets = book.entry(kernel_id.to_string()).or_default();
        if !sockets.contains(&socket) {
            sockets.push(socket);
        }
    }
    Ok(book)
}

/// Resolve a recipient `kernel_id` to a dialable [`iroh::EndpointAddr`] for the drain.
///
/// The EndpointId is resolved from the issuer-verified transport directory (fail-closed
/// to `None` for a removed/unknown recipient), then any direct socket(s) from the
/// out-of-band `--iroh-peer-addr` book are threaded onto it so a relay-disabled /
/// direct-address deployment dials directly. The EndpointId binding always comes from
/// the verified directory, and iroh authenticates it at the handshake, so a socket hint
/// can never redirect delivery to an unauthorized peer. With no book entry the returned
/// address is id-only (dialable where discovery / `--iroh-relay-url` is configured).
fn resolve_dialable_transport_addr(
    directory: &chio_federation_transport_iroh::identity::VerifiedDirectory,
    peer_addr_book: &HashMap<String, Vec<SocketAddr>>,
    kernel_id: &str,
) -> Option<iroh::EndpointAddr> {
    let endpoint_id = directory.resolve_transport_endpoint(kernel_id)?;
    let mut addr = iroh::EndpointAddr::new(endpoint_id);
    if let Some(sockets) = peer_addr_book.get(kernel_id) {
        for socket in sockets {
            addr = addr.with_ip_addr(*socket);
        }
    }
    Some(addr)
}

/// Drain due outbox batches over the iroh federation transport for one tick, the iroh
/// analogue of `deliver_due_batches`.
///
/// Binds an outbound-only gated endpoint, resolves each recipient's dialable address
/// from the issuer-verified transport directory, applies the IDENTICAL outbound
/// directory-scope gate the HTTP tick applies (`enforce_outbound_peer_batch_directory_scope`),
/// and runs `drain_outbox_over_iroh`. Leasing, retry/backoff, and dead-lettering all
/// reuse the shipped store, so an unresolvable/undialable recipient folds into the
/// durable retry/dead-letter path fail-closed rather than being dropped. The
/// `OutboxDrainReport` is mapped onto the shipped `RelayTickReport` so the report file
/// shape is identical to the HTTP tick's.
///
/// `peer_addr_book` supplies out-of-band direct dialable socket(s) per recipient
/// (`--iroh-peer-addr`) for the relay-disabled / direct-address deployment: the
/// verified directory binds only `kernel_id -> transport EndpointId`, so its socket(s)
/// are threaded onto the resolved EndpointId here. An empty book keeps the id-only
/// resolution (dialable where discovery / `--iroh-relay-url` is configured).
fn drain_due_batches_over_iroh(
    relay_store: &chio_pheromone_relay::SqlitePheromoneRelayStore,
    peer_directory: chio_pheromone_relay::PeerDirectory,
    iroh_inputs: IrohServeInputs,
    peer_addr_book: HashMap<String, Vec<SocketAddr>>,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<chio_pheromone_relay::RelayTickReport, CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("Chio relay iroh runtime: {error}")))?;
    runtime.block_on(async move {
        let relay_local_kernel_id = peer_directory.local_kernel_id().to_string();
        let (endpoint, directory) =
            build_iroh_outbound_endpoint(iroh_inputs, &relay_local_kernel_id).await?;

        // resolve_addr: recipient kernel_id -> dialable transport address, derived from
        // the issuer-verified transport directory (the outbound side of the same
        // binding the inbound gate authorizes). A removed/unknown recipient resolves to
        // None and folds into the durable retry path fail-closed. When the direct-address
        // book carries socket(s) for the recipient they are threaded onto the resolved
        // EndpointId so a direct-address deployment dials directly; the EndpointId itself
        // still comes from the verified directory (and iroh authenticates it at the
        // handshake), so a socket hint can never redirect delivery to an unauthorized
        // peer. No book entry keeps the id-only address (dialable under discovery/relay).
        let resolve_directory = directory.clone();
        let resolve_addr = move |kernel_id: &str| -> Option<iroh::EndpointAddr> {
            resolve_dialable_transport_addr(&resolve_directory, &peer_addr_book, kernel_id)
        };

        // scope_check: the SAME outbound directory-scope gate the HTTP tick applies
        // before post_batch, evaluated against the CURRENT peer directory (fail-closed).
        let scope_check = move |recipient: &str,
                                batch: &chio_federation::pheromone_gossip::PheromoneGossipBatch| {
            chio_pheromone_relay::enforce_outbound_peer_batch_directory_scope(
                &peer_directory,
                recipient,
                batch,
            )
        };

        let drain = chio_federation_transport_iroh::lanes::pheromone::drain_outbox_over_iroh(
            relay_store,
            &endpoint,
            resolve_addr,
            scope_check,
            sender_kernel_id,
            now_unix_ms,
            max_batches,
        )
        .await
        .map_err(|error| CliError::cli_other_error(format!("Chio relay iroh drain: {error}")))?;
        endpoint.close().await;

        Ok(chio_pheromone_relay::RelayTickReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_TICK_REPORT_SCHEMA.to_string(),
            accepted: drain.failures.is_empty(),
            delivered: drain.delivered,
            retried: drain.retried,
            dead_lettered: drain.dead_lettered,
            duplicate_idempotent: 0,
            failures: drain.failures,
        })
    })
}

pub(crate) fn write_relay_outbound_event_report(
    report_dir: &Path,
    local_kernel_id: &str,
    generated_at_unix_ms: u64,
    tick_report: &chio_pheromone_relay::RelayTickReport,
) -> Result<(), CliError> {
    std::fs::create_dir_all(report_dir).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio relay event report directory {}: {error}",
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
    let json = serde_json::to_string_pretty(&report).map_err(|error| {
        CliError::cli_other_error(format!("Chio relay event report: {error}"))
    })?;
    let path = report_dir.join(format!("{generated_at_unix_ms}-outbound-delivery.json"));
    write_json_string(&path, &format!("{json}\n"))
}

pub(crate) fn cmd_chio_pheromone_relay_catchup(
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
            "Chio catch-up peer directory: --peer-directory-state is required".to_string(),
        )
    })?;
    let directory = load_relay_peer_directory_from_paths(
        None,
        Some(state_path),
        now_unix_ms.unwrap_or_else(unix_now_ms),
        profile,
        trusted_issuers,
        "Chio peer directory state",
    )?;
    let peer_entry = directory.peer(peer).map_err(|error| {
        CliError::cli_other_error(format!("Chio catch-up peer directory: {error}"))
    })?;
    if !peer_entry
        .treaty_subscriptions
        .iter()
        .any(|id| id == treaty)
    {
        return Err(CliError::cli_other_error(format!(
            "Chio catch-up peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                "peer {peer} is not subscribed to treaty {treaty}"
            ))
        )));
    }
    if limit > peer_entry.max_catchup_frames {
        return Err(CliError::cli_other_error(format!(
            "Chio catch-up peer directory: {}",
            chio_pheromone_relay::PheromoneRelayError::CatchupDenied(format!(
                "requested limit {limit} exceeds peer bound {}",
                peer_entry.max_catchup_frames
            ))
        )));
    }
    let max_catchup_bytes = peer_entry.max_catchup_bytes;
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    let (frames, next_cursor) = relay_store
        .catchup_batches(peer, treaty, after_cursor, limit, max_catchup_bytes)
        .map_err(|error| CliError::cli_other_error(format!("Chio catch-up: {error}")))?;
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
        .map_err(|error| CliError::cli_other_error(format!("Chio catch-up report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn validate_relay_enqueue_batch(
    directory: &chio_pheromone_relay::PeerDirectory,
    batch: &chio_federation::pheromone_gossip::PheromoneGossipBatch,
    transit_policy: &chio_federation::pheromone_gossip::PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), CliError> {
    if batch.schema != chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "Chio relay enqueue batch: unsupported schema {}",
            batch.schema
        )));
    }
    let verification_context = chio_federation::pheromone_gossip::PheromoneGossipBatchVerificationContext {
        now_unix_ms,
        recipient_kernel_id: batch.recipient_kernel_id.clone(),
        authenticated_sender_kernel_id: directory.local_kernel_id().to_string(),
    };
    chio_federation::pheromone_gossip::verify_pheromone_gossip_batch(batch, transit_policy, &verification_context)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio relay enqueue batch: {error}"))
        })?;
    Ok(())
}

pub(crate) fn cmd_chio_pheromone_relay_status(
    store: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    let status = relay_store
        .operator_report("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay status: {error}")))?;
    let json = serde_json::to_string_pretty(&status)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay report: {error}")))?;
    write_json_string(report, &format!("{json}\n"))
}

pub(crate) fn cmd_chio_pheromone_relay_observe(
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
            "failed to create Chio relay report directory {}: {error}",
            report_dir.display()
        ))
    })?;
    let state_json = read_utf8_json_file(peer_directory_state, "Chio peer-directory state")?;
    let state =
        chio_pheromone_relay::peer_directory_state_from_json(&state_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio peer-directory state: {error}"))
        })?;
    let trust = build_peer_directory_bundle_trust(trusted_issuers, now, profile)?;
    let directory = state.active_directory(&trust).map_err(|error| {
        CliError::cli_other_error(format!("Chio peer-directory state: {error}"))
    })?;
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    let report_document = relay_store
        .relay_observability_report(chio_pheromone_relay::RelayObservabilityInput {
            local_kernel_id: directory.local_kernel_id(),
            generated_at_unix_ms: now,
            peer_directory: Some(&directory),
            peer_directory_state: Some(&state),
            profile,
            recent_failure_limit: limit,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio relay observability: {error}"))
        })?;
    write_pretty_json(report, &report_document, "Chio relay observability")
}

pub(crate) fn cmd_chio_pheromone_relay_metrics(
    store: &Path,
    format: chio_pheromone_relay::RelayMetricsFormat,
    output: &Path,
) -> Result<(), CliError> {
    let now = unix_now_ms();
    let relay_store =
        chio_pheromone_relay::SqlitePheromoneRelayStore::open(store).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone relay store: {error}"))
        })?;
    let snapshot = relay_store
        .relay_metrics_snapshot("local", now)
        .map_err(|error| CliError::cli_other_error(format!("Chio relay metrics: {error}")))?;
    write_json_string(output, &snapshot.render(format))
}

pub(crate) fn relay_service_limits_for_profile(
    profile: chio_pheromone_relay::RelayProfile,
) -> chio_pheromone_relay::RelayProfileLimits {
    let mut limits = chio_pheromone_relay::RelayProfileLimits::production_defaults();
    match profile {
        chio_pheromone_relay::RelayProfile::Production => limits,
        chio_pheromone_relay::RelayProfile::LocalDev => {
            limits.max_body_bytes = 1_048_576;
            limits
        }
    }
}

pub(crate) fn cmd_chio_pheromone_relay_trend(
    reports_dir: &Path,
    event_dir: &Path,
    routing_profile: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_pheromone_relay::relay_alert_routing_profile_from_json(
        &read_utf8_json_file(routing_profile, "Chio relay alert routing profile")?,
        until_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio relay alert routing profile: {error}"))
    })?;
    let reports = read_relay_observability_reports(reports_dir)?;
    let events = read_relay_event_reports(event_dir)?;
    let trend =
        chio_pheromone_relay::generate_relay_trend_report(chio_pheromone_relay::RelayTrendInput {
            local_kernel_id: &profile.local_kernel_id,
            observability_reports: &reports,
            event_reports: &events,
            routing_profile: &profile,
            since_unix_ms,
            until_unix_ms,
        })
        .map_err(|error| CliError::cli_other_error(format!("Chio relay trend: {error}")))?;
    write_pretty_json(report, &trend, "Chio relay trend report")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_relay_service_limits_use_profile_body_bound() {
        let limits =
            relay_service_limits_for_profile(chio_pheromone_relay::RelayProfile::Production);

        assert_eq!(
            limits.max_body_bytes,
            chio_pheromone_relay::RelayProfileLimits::production_defaults().max_body_bytes
        );
    }

    #[test]
    fn local_dev_relay_service_limits_keep_existing_body_bound() {
        let limits = relay_service_limits_for_profile(chio_pheromone_relay::RelayProfile::LocalDev);

        assert_eq!(limits.max_body_bytes, 1_048_576);
    }

    #[test]
    fn parse_iroh_peer_addr_book_parses_and_groups_multi_homed_recipients() {
        let entries = vec![
            "did:chio:bob=203.0.113.7:4433".to_string(),
            "did:chio:bob=203.0.113.8:4433".to_string(),
            "did:chio:carol=[2001:db8::1]:5000".to_string(),
            // A duplicate socket for the same kernel is de-duplicated.
            "did:chio:bob=203.0.113.7:4433".to_string(),
        ];
        let book = parse_iroh_peer_addr_book(&entries).expect("valid entries parse");
        assert_eq!(
            book.get("did:chio:bob").unwrap(),
            &vec![
                "203.0.113.7:4433".parse::<SocketAddr>().unwrap(),
                "203.0.113.8:4433".parse::<SocketAddr>().unwrap(),
            ],
        );
        assert_eq!(
            book.get("did:chio:carol").unwrap(),
            &vec!["[2001:db8::1]:5000".parse::<SocketAddr>().unwrap()],
        );
    }

    #[test]
    fn parse_iroh_peer_addr_book_is_empty_for_no_entries() {
        assert!(parse_iroh_peer_addr_book(&[]).unwrap().is_empty());
    }

    #[test]
    fn parse_iroh_peer_addr_book_rejects_malformed_entries_fail_closed() {
        // Missing '=' separator.
        assert!(parse_iroh_peer_addr_book(&["did:chio:bob 203.0.113.7:4433".to_string()]).is_err());
        // Empty kernel id.
        assert!(parse_iroh_peer_addr_book(&["=203.0.113.7:4433".to_string()]).is_err());
        // Unparseable socket address (no port).
        assert!(parse_iroh_peer_addr_book(&["did:chio:bob=203.0.113.7".to_string()]).is_err());
        // Empty socket address.
        assert!(parse_iroh_peer_addr_book(&["did:chio:bob=".to_string()]).is_err());
    }

    mod iroh_tick {
        use super::*;
        use chio_core_types::canonical_json_bytes;
        use chio_core_types::sha256_hex;
        use chio_core_types::Keypair;
        use chio_federation::pheromone_gossip::PheromoneGossipBatch;
        use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
        use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
        use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
        use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
        use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
        use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
        use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
        use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
        use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
        use chio_pheromone_relay::PeerDirectory;
        use chio_pheromone_relay::PeerDirectoryDocument;
        use chio_pheromone_relay::PeerDirectoryEntry;
        use chio_pheromone_relay::RelayRole;
        use chio_pheromone_relay::SqlitePheromoneRelayStore;
        use chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_SCHEMA;
        use iroh::EndpointId;
        use iroh::SecretKey;

        const NOW: u64 = 2_000_000;

        fn endpoint_from_seed(seed: u8) -> EndpointId {
            SecretKey::from_bytes(&[seed; 32]).public()
        }

        /// The transport seed the bundle endorses for its own `localKernelId`
        /// (`did:chio:relay`). Its `EndpointId` MUST equal the public key of the seed the
        /// test key file carries (`0x11` bytes, i.e. `"11".repeat(32)`), so
        /// `load_iroh_serve_inputs`'s local-transport-key binding check passes and the
        /// drain path is actually reached.
        const LOCAL_TRANSPORT_SEED: u8 = 0x11;

        /// A well-formed, non-removed transport-directory entry binding `kernel_id` to the
        /// transport `EndpointId` derived from `transport_seed`, self-endorsed by a
        /// per-kernel passport.
        fn directory_entry(
            kernel_id: &str,
            passport_seed: u8,
            transport_seed: u8,
        ) -> TransportDirectoryEntry {
            let passport = Keypair::from_seed(&[passport_seed; 32]);
            let transport = endpoint_from_seed(transport_seed);
            TransportDirectoryEntry {
                kernel_id: kernel_id.to_string(),
                passport_public_key: passport.public_key(),
                transport_endpoint_id: transport,
                passport_endorsement: passport
                    .sign(&transport_endorsement_preimage(kernel_id, &transport)),
                revocation_signers: Vec::new(),
                removed: false,
            }
        }

        /// A signed, verifiable transport-directory bundle whose directory carries BOTH
        /// the bundle's own `localKernelId` (`did:chio:relay`) bound to
        /// [`LOCAL_TRANSPORT_SEED`] (so `load_iroh_serve_inputs`'s local-transport-key
        /// binding check passes against the `0x11` key file the tests write) AND a
        /// SEPARATE `admitted_kernel` peer at `transport_seed` (the recipient the drain's
        /// address resolver exercises). Returns the issuer keypair whose public key the
        /// trusted-issuers file must pin.
        fn signed_bundle_json(admitted_kernel: &str, transport_seed: u8) -> (String, Keypair) {
            let issuer = Keypair::from_seed(&[240u8; 32]);
            // The local relay's OWN transport binding: did:chio:relay -> seed 0x11. The
            // local-transport-key binding check added to load_iroh_serve_inputs in a prior
            // round resolves THIS entry and rejects a bundle missing it, so without this
            // entry the drain path would never be reached.
            let local_relay_entry = directory_entry("did:chio:relay", 8, LOCAL_TRANSPORT_SEED);
            // A SEPARATE admitted peer (NOT the local relay): the drain's recipient
            // resolver returns this endpoint for an admitted peer, or None for a recipient
            // (e.g. did:chio:buyer) NOT admitted here, which is the fail-closed
            // unresolvable case the tick test asserts folds into the durable retry path.
            let admitted_entry = directory_entry(admitted_kernel, 7, transport_seed);
            let directory = TransportDirectoryDocument {
                schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
                local_kernel_id: "did:chio:relay".to_string(),
                peers: vec![local_relay_entry, admitted_entry],
                treaties: Vec::new(),
            };
            let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
            let body = TransportDirectoryBundleBody {
                schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
                issuer: "did:chio:issuer".to_string(),
                key_id: "issuer-key-1".to_string(),
                directory_sha256,
                version: 1,
                previous_version_sha256: None,
                issued_at_unix_ms: NOW - 1,
                expires_at_unix_ms: NOW + 1,
            };
            let (signature, _) = issuer.sign_canonical(&body).unwrap();
            let bundle = TransportDirectoryBundleDocument {
                schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
                body,
                directory,
                signature,
            };
            (serde_json::to_string(&bundle).unwrap(), issuer)
        }

        /// A peer directory admitting `recipient` as a Receiver subscribed to
        /// `treaty:test` (so the outbound scope gate passes for it).
        fn peer_directory_receiving(recipient: &str) -> PeerDirectory {
            let passport = Keypair::from_seed(&[9u8; 32]);
            let document = PeerDirectoryDocument {
                schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
                local_kernel_id: "did:chio:relay".to_string(),
                issued_at_unix_ms: NOW - 1,
                expires_at_unix_ms: NOW + 1,
                peers: vec![PeerDirectoryEntry {
                    kernel_id: recipient.to_string(),
                    public_key: passport.public_key(),
                    endpoint: "https://peer.example/relay".to_string(),
                    treaty_subscriptions: vec!["treaty:test".to_string()],
                    relay_role: RelayRole::Receiver,
                    allowed_subject_class_namespaces: Vec::new(),
                    accepted_ladder_refs: Vec::new(),
                    max_batch_frames: 128,
                    max_catchup_frames: 128,
                    max_catchup_bytes: 1_048_576,
                }],
            };
            PeerDirectory::from_document(document, NOW).expect("peer directory builds")
        }

        fn empty_batch(recipient: &str) -> PheromoneGossipBatch {
            PheromoneGossipBatch {
                schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
                recipient_kernel_id: recipient.to_string(),
                treaty_id: "treaty:test".to_string(),
                frames: Vec::new(),
                flushed_at_unix_ms: NOW,
            }
        }

        #[test]
        fn iroh_tick_drains_the_outbox_and_folds_an_unresolvable_recipient_into_retry() {
            // Proves the tick's iroh outbound wiring end-to-end: the endpoint binds, the
            // outbound directory-scope gate PASSES for an admitted Receiver, the transport
            // resolver returns None for a recipient NOT in the transport directory, and the
            // drain folds that into the durable retry path fail-closed (never dropped) -
            // all surfaced through the shipped RelayTickReport shape.
            let dir = tempfile::tempdir().unwrap();
            let bundle_path = dir.path().join("bundle.json");
            let issuers_path = dir.path().join("issuers.json");
            let key_path = dir.path().join("key.json");

            // The transport directory admits ONLY did:chio:other, so the queued
            // recipient did:chio:buyer does not resolve to a dialable endpoint.
            let (bundle_json, issuer) = signed_bundle_json("did:chio:other", 24);
            std::fs::write(&bundle_path, &bundle_json).unwrap();
            let issuers = serde_json::json!({
                "issuers": [{
                    "issuer": "did:chio:issuer",
                    "keyId": "issuer-key-1",
                    "publicKey": issuer.public_key(),
                }],
            });
            std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
            std::fs::write(
                &key_path,
                "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}",
            )
            .unwrap();

            let inputs = load_iroh_serve_inputs(
                true,
                Some(&bundle_path),
                None,
                Some(&issuers_path),
                Some(&key_path),
                "127.0.0.1:0",
                &[],
                "pheromone",
                NOW,
            )
            .expect("iroh inputs load")
            .expect("iroh enabled produces inputs");

            let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
            let batch = empty_batch("did:chio:buyer");
            store
                .enqueue_batch(
                    "did:chio:sender",
                    "did:chio:buyer",
                    "treaty:test",
                    &batch,
                    NOW,
                )
                .expect("batch enqueues");

            let peer_directory = peer_directory_receiving("did:chio:buyer");
            let report = drain_due_batches_over_iroh(
                &store,
                peer_directory,
                inputs,
                HashMap::new(),
                "did:chio:sender",
                NOW,
                10,
            )
            .expect("iroh drain tick runs");

            assert_eq!(report.delivered, 0, "nothing is delivered to an unlisted peer");
            assert_eq!(report.retried, 1, "the batch folds into the durable retry path");
            assert!(!report.accepted, "a retried tick is not fully accepted");
            assert!(
                report.failures.iter().any(|line| line.contains("unknown_peer")),
                "the failure must be the fail-closed unknown_peer code, got {:?}",
                report.failures
            );
        }

        /// Verify a signed bundle admitting `admitted_kernel` and return the
        /// load-time-verified directory the resolver reads.
        fn verified_directory(
            admitted_kernel: &str,
            transport_seed: u8,
        ) -> chio_federation_transport_iroh::identity::VerifiedDirectory {
            let (bundle_json, issuer) = signed_bundle_json(admitted_kernel, transport_seed);
            let bundle: TransportDirectoryBundleDocument =
                serde_json::from_str(&bundle_json).unwrap();
            let trust = TransportDirectoryBundleTrust {
                issuers: vec![TrustedTransportDirectoryIssuer {
                    issuer: "did:chio:issuer".to_string(),
                    key_id: "issuer-key-1".to_string(),
                    public_key: issuer.public_key(),
                }],
                version_floor: 0,
                expected_previous_version_sha256: None,
                now_unix_ms: NOW,
            };
            bundle.verify_bundle(&trust).expect("bundle verifies")
        }

        #[test]
        fn direct_address_book_threads_the_socket_onto_the_resolved_endpoint() {
            // In a relay-disabled / direct-address deployment the resolver must thread
            // the --iroh-peer-addr socket onto the resolved
            // EndpointId so the drain can dial a peer known only by EndpointId + socket,
            // while an id-only resolution still works where discovery/relay is configured.
            let directory = verified_directory("did:chio:buyer", 24);
            let expected_endpoint = endpoint_from_seed(24);

            // No book entry: id-only address (dialable under discovery/relay), no socket.
            let empty_book: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            let id_only =
                resolve_dialable_transport_addr(&directory, &empty_book, "did:chio:buyer")
                    .expect("admitted recipient resolves");
            assert_eq!(id_only.id, expected_endpoint, "the directory EndpointId is kept");
            assert!(
                id_only.ip_addrs().next().is_none(),
                "with no book entry the address is id-only"
            );

            // Book entry: the direct socket(s) are threaded onto the SAME EndpointId.
            let socket_a: SocketAddr = "203.0.113.7:4433".parse().unwrap();
            let socket_b: SocketAddr = "203.0.113.8:4433".parse().unwrap();
            let mut book: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            book.insert("did:chio:buyer".to_string(), vec![socket_a, socket_b]);
            let direct = resolve_dialable_transport_addr(&directory, &book, "did:chio:buyer")
                .expect("admitted recipient resolves");
            assert_eq!(
                direct.id, expected_endpoint,
                "the EndpointId still comes from the verified directory, not the book"
            );
            let dialable: Vec<SocketAddr> = direct.ip_addrs().copied().collect();
            assert!(dialable.contains(&socket_a) && dialable.contains(&socket_b));

            // A recipient NOT in the transport directory resolves to None even with a
            // book entry: the EndpointId binding is fail-closed against the directory, so
            // a socket hint can never fabricate a dialable address for an unadmitted peer.
            let mut ghost_book: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            ghost_book.insert("did:chio:ghost".to_string(), vec![socket_a]);
            assert!(
                resolve_dialable_transport_addr(&directory, &ghost_book, "did:chio:ghost")
                    .is_none(),
                "an unadmitted recipient never resolves, even with a direct-address entry"
            );
        }
    }
}
