use super::super::cluster::{build_cluster_state, run_cluster_sync_loop};
use super::super::*;
use super::router;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, MaxConnListener, ServeHygieneConfig,
    ShutdownController,
};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[cfg(feature = "cognition-market-experimental")]
pub(crate) async fn serve_async(
    config: TrustServiceConfig,
    injected_joint_authority_store: Option<Arc<SqliteAuthorityStore>>,
    finding_challenge_executor: Option<
        Arc<dyn super::super::finding_challenge_handlers::FindingChallengeSubmissionExecutor>,
    >,
) -> Result<(), CliError> {
    serve_async_inner(
        config,
        injected_joint_authority_store,
        None,
        finding_challenge_executor,
    )
    .await
}

#[cfg(not(feature = "cognition-market-experimental"))]
pub(crate) async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    serve_async_inner(config).await
}

#[cfg(feature = "cognition-market-experimental")]
pub(crate) async fn serve_async_with_finding_purchase_executor(
    config: TrustServiceConfig,
    executor: super::super::finding_purchase_routes::SharedFindingPurchaseExecutor,
) -> Result<(), CliError> {
    serve_async_inner(config, None, Some(executor), None).await
}

async fn serve_async_inner(
    config: TrustServiceConfig,
    #[cfg(feature = "cognition-market-experimental")] injected_joint_authority_store: Option<
        Arc<SqliteAuthorityStore>,
    >,
    #[cfg(feature = "cognition-market-experimental")] finding_purchase_executor: Option<
        super::super::finding_purchase_routes::SharedFindingPurchaseExecutor,
    >,
    #[cfg(feature = "cognition-market-experimental")] finding_challenge_executor: Option<
        Arc<dyn super::super::finding_challenge_handlers::FindingChallengeSubmissionExecutor>,
    >,
) -> Result<(), CliError> {
    config.validate()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    #[cfg(feature = "cognition-market-experimental")]
    let joint_authority_store = match injected_joint_authority_store {
        Some(store) => {
            validate_injected_joint_authority_store(&config, &store)?;
            Some(store)
        }
        None => open_configured_joint_authority_store(&config)?,
    };
    #[cfg(not(feature = "cognition-market-experimental"))]
    let joint_authority_store = open_configured_joint_authority_store(&config)?;
    let fiscal_runtime = compose_trust_fiscal_runtime(
        joint_authority_store.as_ref(),
        config.fiscal_runtime.as_ref(),
    )?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let budget_store = config
        .budget_db_path
        .as_deref()
        .map(SqliteBudgetStore::open)
        .transpose()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to open trust-control budget store: {error}"
            ))
        })?
        .map(Arc::new);
    let revocation_store = config
        .revocation_db_path
        .as_deref()
        .map(SqliteRevocationStore::open)
        .transpose()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to open trust-control revocation store: {error}"
            ))
        })?
        .map(Arc::new);
    let cluster = build_cluster_state(&config, local_addr)?;
    // Thread the operator-configured memory budget into the admission guard so a
    // lowered `admission_key_cap` actually tightens it. Read the cap before
    // `config` is moved into the state.
    let federation_admission_rate_limiter = Arc::new(Mutex::new(
        FederationAdmissionRateLimiter::from_memory_budget(&config.memory_budget),
    ));
    let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
    // The evidenced rail is present exactly when the finding market
    // is configured, so activation fails closed on unconfigured venues.
    #[cfg(feature = "cognition-market-experimental")]
    let finding_rail: Option<Arc<dyn super::super::finding_handlers::FindingRailObserver>> =
        config.finding_market.as_ref().map(|_| {
            Arc::new(super::super::finding_handlers::VenueLedgerRailObserver)
                as Arc<dyn super::super::finding_handlers::FindingRailObserver>
        });
    let state = TrustServiceState {
        config,
        joint_authority_store,
        fiscal_runtime,
        budget_store,
        revocation_store,
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter,
        cluster,
        cluster_progress,
        #[cfg(feature = "cognition-market-experimental")]
        finding_rail,
        #[cfg(feature = "cognition-market-experimental")]
        finding_purchase_executor,
        #[cfg(feature = "cognition-market-experimental")]
        finding_challenge_executor,
    };
    let controller = ShutdownController::install();
    let cluster_sync_task = state
        .cluster
        .is_some()
        .then(|| tokio::spawn(run_cluster_sync_loop(state.clone(), controller.subscribe())));

    // Record when the stop signal fires so the post-drain cluster-loop join can
    // share the one drain budget with the HTTP drain instead of adding a second
    // wait on top of it (see the join below). The observer sets the instant once,
    // the moment shutdown is requested.
    let shutdown_at: Arc<OnceLock<Instant>> = Arc::new(OnceLock::new());
    {
        let shutdown_at = Arc::clone(&shutdown_at);
        let signalled = controller.signalled();
        tokio::spawn(async move {
            signalled.await;
            let _ = shutdown_at.set(Instant::now());
        });
    }

    // Trust-control is the single service hosting capability revocation and
    // budget authority for the cluster, so it takes a body cap, the concurrency
    // limit with load-shed, and the connection cap.
    //
    // The generic per-request timeout is deliberately left off. An HA budget
    // authorize parks in the rollback-aware quorum wait, which is bounded on its
    // own (scaled to the cluster's serial per-peer sync cost) and can legitimately
    // outrun any single request ceiling; a blanket timeout firing after the local
    // exposure write but before that wait returns would drop the handler before its
    // rollback branch, leaving a charged, leader-visible write that the client only
    // saw fail. Every other handler is a bounded local store operation or a
    // leader-forward already capped by the peer HTTP timeout, and the drain
    // deadline bounds any handler still running at shutdown.
    let hygiene = ServeHygieneConfig {
        max_body_bytes: Some(1024 * 1024),
        request_timeout: None,
        ..ServeHygieneConfig::default()
    };
    let router = apply_server_hygiene(router::build_router(state), &hygiene);

    info!(listen_addr = %local_addr, "serving Chio trust control service");
    eprintln!("Chio trust control service listening on http://{local_addr}");

    let listener = MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
    let server = axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

    // Trust-control writes budget and revocation state synchronously inside its
    // handlers, so completing in-flight requests during the drain is the whole
    // fix; there is no async commit actor to flush.
    let serve_result = run_until_drained(
        server,
        controller.subscribe(),
        hygiene.drain_timeout,
        async { Ok::<(), String>(()) },
    )
    .await;

    // The cluster sync loop watches the same shutdown signal and reacts to it
    // concurrently with the HTTP drain. Once the server has drained, join the loop
    // within whatever remains of the drain window, never a fresh wait on top of it:
    // one in-flight peer call can outlast any bound worth waiting for, and outbound
    // peer sync is best-effort catch-up that resumes on the next boot, so abandoning
    // a still-running call at the deadline never loses a receipt. Anchoring the join
    // at the stop signal keeps the whole teardown inside one drain budget, which the
    // platform stop grace is already sized to cover.
    if let Some(task) = cluster_sync_task {
        let join_budget = shutdown_at.get().map_or(hygiene.drain_timeout, |observed| {
            cluster_join_budget(hygiene.drain_timeout, observed.elapsed())
        });
        let _ = tokio::time::timeout(join_budget, task).await;
    }

    serve_result.map(|_outcome| ()).map_err(|error| {
        CliError::cli_other_error(format!("trust control service failed: {error}"))
    })
}

#[cfg(feature = "cognition-market-experimental")]
fn validate_injected_joint_authority_store(
    config: &TrustServiceConfig,
    store: &SqliteAuthorityStore,
) -> Result<(), CliError> {
    let configured_path = config.joint_authority_db_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "injected finding challenge authority requires a configured joint authority database"
                .to_string(),
        )
    })?;
    store.verify_database_path(configured_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "injected finding challenge authority does not match the configured joint authority database: {error}"
        ))
    })
}

fn open_configured_joint_authority_store(
    config: &TrustServiceConfig,
) -> Result<Option<Arc<SqliteAuthorityStore>>, CliError> {
    let Some(path) = config.joint_authority_db_path.as_deref() else {
        return Ok(None);
    };
    let lock_root = crate::durable_admission_lock_root(path)?;
    std::fs::create_dir_all(&lock_root)?;
    SqliteAuthorityStore::provision(path, &lock_root)?;
    Ok(Some(Arc::new(SqliteAuthorityStore::open_serving(
        path, &lock_root,
    )?)))
}

/// Time budget for the post-drain cluster-loop join: whatever remains of the
/// drain window once the HTTP drain returns. `elapsed` is measured from the stop
/// signal, and the HTTP drain returns within `drain_timeout` of that signal, so
/// the drain time already spent plus this budget never exceeds one drain window.
/// Both teardown phases therefore share the single deadline the platform stop
/// grace is sized to cover, instead of stacking two independent waits.
fn cluster_join_budget(drain_timeout: Duration, elapsed_since_signal: Duration) -> Duration {
    drain_timeout.saturating_sub(elapsed_since_signal)
}

#[cfg(test)]
mod tests {
    use super::cluster_join_budget;
    #[cfg(feature = "cognition-market-experimental")]
    use super::{
        validate_injected_joint_authority_store, SqliteAuthorityStore, TrustServiceConfig,
    };
    #[cfg(feature = "cognition-market-experimental")]
    use std::collections::BTreeMap;
    #[cfg(feature = "cognition-market-experimental")]
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[cfg(feature = "cognition-market-experimental")]
    fn test_config(joint_authority_db_path: PathBuf) -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("fixed loopback address must parse: {error}")),
            service_token: "service-token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            joint_authority_db_path: Some(joint_authority_db_path),
            fiscal_runtime: None,
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
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            finding_market: None,
        }
    }

    #[cfg(all(feature = "cognition-market-experimental", unix))]
    fn secure_directory(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }

    /// The cluster-loop join must not add a second wait on top of the HTTP drain:
    /// for every point at which the drain could return, the drain time already
    /// spent plus the join budget it hands out stays within one drain window, so
    /// the whole teardown fits the platform stop grace rather than overrunning it
    /// and being escalated to a kill.
    #[test]
    fn cluster_join_never_extends_teardown_past_the_drain_window() {
        let drain = Duration::from_secs(25);
        // A drain that ran to its deadline leaves no budget at all.
        assert_eq!(cluster_join_budget(drain, drain), Duration::ZERO);
        for elapsed_ms in [0u64, 1_000, 12_500, 24_000, 25_000] {
            let elapsed = Duration::from_millis(elapsed_ms).min(drain);
            assert!(
                elapsed + cluster_join_budget(drain, elapsed) <= drain,
                "teardown at elapsed={elapsed:?} must stay within the drain window"
            );
        }
    }

    #[cfg(all(feature = "cognition-market-experimental", unix))]
    #[test]
    fn injected_challenge_authority_must_match_configured_database(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        secure_directory(temp.path())?;
        let configured_database = temp.path().join("configured.db");
        let configured_locks = temp.path().join("configured-locks");
        let injected_database = temp.path().join("injected.db");
        let injected_locks = temp.path().join("injected-locks");
        std::fs::create_dir(&configured_locks)?;
        secure_directory(&configured_locks)?;
        std::fs::create_dir(&injected_locks)?;
        secure_directory(&injected_locks)?;
        SqliteAuthorityStore::provision(&configured_database, &configured_locks)?;
        SqliteAuthorityStore::provision(&injected_database, &injected_locks)?;
        let injected = SqliteAuthorityStore::open_serving(&injected_database, &injected_locks)?;

        let matching = test_config(injected_database);
        validate_injected_joint_authority_store(&matching, &injected)?;

        let mismatched = test_config(configured_database);
        let error = match validate_injected_joint_authority_store(&mismatched, &injected) {
            Ok(()) => panic!("a different configured authority database must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("does not match"));
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_authority_tests {
    use super::*;

    #[tokio::test]
    async fn trust_service_rejects_windows_before_creating_joint_authority_state(
    ) -> Result<(), CliError> {
        let directory = tempfile::tempdir()?;
        let state_parent = directory.path().join("state");
        let database = state_parent.join("joint-authority.sqlite3");
        let lock_root = crate::durable_admission_lock_root(&database)?;
        let config = TrustServiceConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            service_token: "service-token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            joint_authority_db_path: Some(database.clone()),
            fiscal_runtime: None,
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
            allow_local_peer_urls: false,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        };

        let Err(error) = serve_async(config).await else {
            return Err(CliError::cli_other_error(
                "Windows trust service unexpectedly started with a joint authority database",
            ));
        };

        assert!(error
            .to_string()
            .contains("sqlite authority serving requires Unix file identity and positioned I/O"));
        assert!(!state_parent.exists());
        assert!(!database.exists());
        assert!(!lock_root.exists());
        assert!(std::fs::read_dir(directory.path())?.next().is_none());
        Ok(())
    }
}
