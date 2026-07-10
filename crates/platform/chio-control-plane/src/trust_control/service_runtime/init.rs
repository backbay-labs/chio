use super::super::cluster::{build_cluster_state, run_cluster_sync_loop};
use super::super::*;
use super::router;

pub(crate) async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    config.validate()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    let cluster = build_cluster_state(&config, local_addr)?;
    let cluster_progress = cluster.as_ref().map(|_| Arc::new(ClusterProgress::new()));
    let state = TrustServiceState {
        config,
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster,
        cluster_progress,
    };
    if state.cluster.is_some() {
        tokio::spawn(run_cluster_sync_loop(state.clone()));
    }

    let router = router::build_router(state);

    info!(listen_addr = %local_addr, "serving Chio trust control service");
    eprintln!("Chio trust control service listening on http://{local_addr}");

    axum::serve(listener, router).await.map_err(|error| {
        CliError::cli_other_error(format!("trust control service failed: {error}"))
    })
}
