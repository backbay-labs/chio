use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use chio_control_plane::trust_control::finding_hosted_profile::FindingHostedProfile;
use chio_core_types::canonical_json_bytes;
use chio_finding_hosted_edge::{
    HostedCircuitBreaker, HostedCircuitBreakerConfig, HostedDependency, HostedReadiness,
};
use chio_finding_market_store_postgres::{
    HostedPostgresConfig, HostedTenantId, HostedTenantLimits, PostgresFindingMarketStore,
};
use chio_finding_worker::{
    HostedFindingWorker, HostedWorkerJobEvidence, HostedWorkerRun, HostedWorkerServiceError,
};
use clap::Parser;
use nix::libc;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const RETRY_BASE_SECS: u64 = 5;
const DATABASE_FAILURE_THRESHOLD: u32 = 3;
const DATABASE_BREAKER_OPEN_SECS: u64 = 30;
const TENANT_BREAKER_OPEN_SECS: u64 = 30;

#[derive(Debug, Parser)]
#[command(name = "chio-finding-worker")]
#[command(about = "Run the hosted cognition-market isolated worker")]
struct Args {
    /// Canonical private hosted operator profile.
    #[arg(long)]
    profile: PathBuf,
    /// Stable unique identity for this worker replica.
    #[arg(long)]
    worker_id: String,
    /// Process one bounded pass and exit.
    #[arg(long)]
    once: bool,
    /// Delay between queue scans when running continuously.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_millis: u64,
}

#[derive(Debug, thiserror::Error)]
enum DaemonError {
    #[error("worker_arguments_invalid")]
    Arguments,
    #[error("worker_profile_invalid")]
    Profile,
    #[error("worker_self_integrity_failed")]
    SelfIntegrity,
    #[error("worker_custody_preflight_failed")]
    Custody,
    #[error("worker_host_preflight_failed")]
    Host,
    #[error("worker_database_preflight_failed")]
    Database,
    #[error("worker_tenant_preflight_failed")]
    Tenant,
    #[error("worker_execution_failed")]
    Execution,
    #[error("worker_shutdown_handler_failed")]
    Shutdown,
    #[error("worker_report_failed")]
    Report,
}

#[derive(Clone)]
struct TenantRuntime {
    tenant_id: HostedTenantId,
    limits: HostedTenantLimits,
}

#[derive(Clone, Copy, Default)]
struct TenantFailureState {
    consecutive_failures: u32,
    open_until: u64,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerTickReport {
    schema: &'static str,
    worker_id: String,
    ready: bool,
    dependency_error: Option<&'static str>,
    tenant_count: u32,
    tenants_visited: u32,
    claimed: u32,
    completed: u32,
    guest_rejected: u32,
    retried: u32,
    exhausted: u32,
    cancelled: u32,
    claimed_job_ids: Vec<String>,
    completed_job_ids: Vec<String>,
    jobs: Vec<HostedWorkerJobEvidence>,
}

struct WorkerTickSpec<'a> {
    worker: &'a HostedFindingWorker,
    tenants: &'a [TenantRuntime],
    worker_id: &'a str,
    first: usize,
    max_tenants: u32,
    max_jobs: u32,
    tenant_failure_threshold: u32,
    cancellation: &'a CancellationToken,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), DaemonError> {
    validate_arguments(&args)?;
    let profile = read_profile(&args.profile)?;
    profile.validate().map_err(|_| DaemonError::Profile)?;
    require_current_binary(&profile.worker.worker_binary)?;
    require_trusted_ca(Path::new(&profile.database.ca_certificate_path))?;

    let executor = profile
        .load_worker_executor()
        .map_err(|_| DaemonError::Custody)?;
    executor.preflight_host().map_err(|_| DaemonError::Host)?;
    let store = connect_store(&profile).await?;
    let tenants = enabled_tenants(&profile)?;
    for tenant in &tenants {
        executor
            .preflight_tenant_artifact_store(&tenant.tenant_id)
            .map_err(|_| DaemonError::Tenant)?;
        store
            .verify_tenant_limits(&tenant.tenant_id, &tenant.limits)
            .await
            .map_err(|_| DaemonError::Tenant)?;
    }
    let worker = HostedFindingWorker::new(
        store,
        executor,
        args.worker_id.clone(),
        profile.worker.lease_duration_secs,
        profile.worker.lease_heartbeat_secs,
        profile.worker.max_attempts,
        RETRY_BASE_SECS,
    )
    .map_err(|_| DaemonError::Arguments)?;

    if args.once {
        let cancellation = CancellationToken::new();
        let mut report = run_tick(
            WorkerTickSpec {
                worker: &worker,
                tenants: &tenants,
                worker_id: &args.worker_id,
                first: 0,
                max_tenants: profile.worker.max_tenants_per_tick,
                max_jobs: profile.worker.max_jobs_per_tick,
                tenant_failure_threshold: profile.worker.tenant_failure_threshold,
                cancellation: &cancellation,
            },
            &mut BTreeMap::new(),
        )
        .await?;
        report.ready = true;
        return write_report(&report);
    }

    let database_breaker = HostedCircuitBreaker::new(HostedCircuitBreakerConfig {
        failure_threshold: DATABASE_FAILURE_THRESHOLD,
        open_secs: DATABASE_BREAKER_OPEN_SECS,
    })
    .map_err(|_| DaemonError::Arguments)?;
    let readiness = HostedReadiness::new([
        HostedDependency::Database,
        HostedDependency::Signer,
        HostedDependency::Worker,
    ])
    .map_err(|_| DaemonError::Arguments)?;
    readiness
        .record(HostedDependency::Database, true)
        .and_then(|()| readiness.record(HostedDependency::Signer, true))
        .and_then(|()| readiness.record(HostedDependency::Worker, true))
        .map_err(|_| DaemonError::Execution)?;
    let mut next_tenant = 0_usize;
    let mut tenant_failures = BTreeMap::new();
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        let now = current_unix_secs()?;
        if database_breaker
            .admit(HostedDependency::Database, now)
            .is_err()
        {
            readiness
                .record(HostedDependency::Database, false)
                .map_err(|_| DaemonError::Execution)?;
            write_report(&dependency_failure_report(
                &args.worker_id,
                &tenants,
                "database_circuit_open",
            )?)?;
            if wait_or_shutdown(
                &mut shutdown,
                Duration::from_secs(DATABASE_BREAKER_OPEN_SECS),
            )
            .await?
            {
                write_report(&dependency_failure_report(
                    &args.worker_id,
                    &tenants,
                    "shutdown",
                )?)?;
                return Ok(());
            }
            continue;
        }
        let cancellation = CancellationToken::new();
        let tick = run_tick(
            WorkerTickSpec {
                worker: &worker,
                tenants: &tenants,
                worker_id: &args.worker_id,
                first: next_tenant,
                max_tenants: profile.worker.max_tenants_per_tick,
                max_jobs: profile.worker.max_jobs_per_tick,
                tenant_failure_threshold: profile.worker.tenant_failure_threshold,
                cancellation: &cancellation,
            },
            &mut tenant_failures,
        );
        tokio::pin!(tick);
        let tick_result = tokio::select! {
            result = &mut tick => result,
            signal = &mut shutdown => {
                signal?;
                cancellation.cancel();
                let timed = tokio::time::timeout(
                    Duration::from_secs(profile.worker.shutdown_grace_secs),
                    &mut tick,
                )
                .await;
                let Ok(result) = timed else {
                    write_report(&dependency_failure_report(
                        &args.worker_id,
                        &tenants,
                        "shutdown_timeout",
                    )?)?;
                    return Err(DaemonError::Shutdown);
                };
                let mut report = result?;
                report.ready = false;
                report.dependency_error = Some("shutdown");
                write_report(&report)?;
                return Ok(());
            }
        };
        match tick_result {
            Ok(mut report) => {
                database_breaker
                    .record_success(HostedDependency::Database)
                    .map_err(|_| DaemonError::Execution)?;
                readiness
                    .record(HostedDependency::Database, true)
                    .map_err(|_| DaemonError::Execution)?;
                report.ready = readiness.snapshot().ready;
                write_report(&report)?;
                let visited =
                    usize::try_from(report.tenants_visited).map_err(|_| DaemonError::Execution)?;
                next_tenant = (next_tenant + visited.max(1)) % tenants.len();
            }
            Err(DaemonError::Database) => {
                database_breaker
                    .record_failure(HostedDependency::Database, now)
                    .map_err(|_| DaemonError::Execution)?;
                readiness
                    .record(HostedDependency::Database, false)
                    .map_err(|_| DaemonError::Execution)?;
                write_report(&dependency_failure_report(
                    &args.worker_id,
                    &tenants,
                    "database_unavailable",
                )?)?;
            }
            Err(error) => return Err(error),
        }
        if wait_or_shutdown(
            &mut shutdown,
            Duration::from_millis(args.poll_interval_millis),
        )
        .await?
        {
            write_report(&dependency_failure_report(
                &args.worker_id,
                &tenants,
                "shutdown",
            )?)?;
            return Ok(());
        }
    }
}

async fn wait_or_shutdown(
    shutdown: &mut std::pin::Pin<Box<impl std::future::Future<Output = Result<(), DaemonError>>>>,
    delay: Duration,
) -> Result<bool, DaemonError> {
    tokio::select! {
        result = shutdown => result.map(|()| true),
        () = tokio::time::sleep(delay) => Ok(false),
    }
}

fn current_unix_secs() -> Result<u64, DaemonError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DaemonError::Execution)
}

fn validate_arguments(args: &Args) -> Result<(), DaemonError> {
    if !args.profile.is_absolute()
        || args.worker_id.is_empty()
        || args.worker_id.len() > 256
        || !args.worker_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        || !(100..=60_000).contains(&args.poll_interval_millis)
    {
        return Err(DaemonError::Arguments);
    }
    Ok(())
}

fn read_profile(path: &Path) -> Result<FindingHostedProfile, DaemonError> {
    let (mut file, metadata) = open_private_regular(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES {
        return Err(DaemonError::Profile);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| DaemonError::Profile)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| DaemonError::Profile)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| DaemonError::Profile)?;
    let canonical =
        chio_core_types::canonical_json_bytes_from_str(raw).map_err(|_| DaemonError::Profile)?;
    if canonical != bytes {
        return Err(DaemonError::Profile);
    }
    serde_json::from_slice(&bytes).map_err(|_| DaemonError::Profile)
}

fn open_private_regular(path: &Path) -> Result<(File, Metadata), DaemonError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| DaemonError::Profile)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.mode() & 0o077 != 0
        || before.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(DaemonError::Profile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::Profile)?;
    let after = file.metadata().map_err(|_| DaemonError::Profile)?;
    if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(DaemonError::Profile);
    }
    Ok((file, after))
}

fn require_current_binary(configured: &str) -> Result<(), DaemonError> {
    let current = std::env::current_exe().map_err(|_| DaemonError::SelfIntegrity)?;
    let current = std::fs::metadata(current).map_err(|_| DaemonError::SelfIntegrity)?;
    let configured_link =
        std::fs::symlink_metadata(configured).map_err(|_| DaemonError::SelfIntegrity)?;
    if configured_link.file_type().is_symlink() || !configured_link.is_file() {
        return Err(DaemonError::SelfIntegrity);
    }
    let configured = std::fs::metadata(configured).map_err(|_| DaemonError::SelfIntegrity)?;
    if current.dev() != configured.dev() || current.ino() != configured.ino() {
        return Err(DaemonError::SelfIntegrity);
    }
    Ok(())
}

fn require_trusted_ca(path: &Path) -> Result<(), DaemonError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| DaemonError::Database)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 4 * 1024 * 1024
        || metadata.mode() & 0o022 != 0
    {
        return Err(DaemonError::Database);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DaemonError::Database)?;
    let opened = file.metadata().map_err(|_| DaemonError::Database)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(DaemonError::Database);
    }
    Ok(())
}

async fn connect_store(
    profile: &FindingHostedProfile,
) -> Result<PostgresFindingMarketStore, DaemonError> {
    let database_url =
        std::env::var(&profile.database.url_env).map_err(|_| DaemonError::Database)?;
    if database_url.is_empty()
        || database_url.len() > 16 * 1024
        || database_url.chars().any(char::is_control)
    {
        return Err(DaemonError::Database);
    }
    let max_jobs =
        i64::try_from(profile.database.max_jobs_per_tenant).map_err(|_| DaemonError::Database)?;
    let config = HostedPostgresConfig::new(database_url)
        .and_then(|config| config.with_ca_certificate(profile.database.ca_certificate_path.clone()))
        .and_then(|config| config.with_max_connections(profile.database.max_connections))
        .and_then(|config| config.with_max_jobs_per_tenant(max_jobs))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .map_err(|_| DaemonError::Database)?;
    PostgresFindingMarketStore::connect_worker(&config)
        .await
        .map_err(|_| DaemonError::Database)
}

fn enabled_tenants(profile: &FindingHostedProfile) -> Result<Vec<TenantRuntime>, DaemonError> {
    let tenants = profile
        .tenants
        .iter()
        .filter(|tenant| tenant.enabled)
        .map(|tenant| {
            Ok(TenantRuntime {
                tenant_id: HostedTenantId::new(tenant.tenant_id.clone())
                    .map_err(|_| DaemonError::Tenant)?,
                limits: HostedTenantLimits::new(
                    tenant.max_concurrent_jobs,
                    tenant.max_queued_jobs,
                    tenant.max_monthly_spend_units,
                    profile.release.configuration_revision.clone(),
                )
                .map_err(|_| DaemonError::Tenant)?,
            })
        })
        .collect::<Result<Vec<_>, DaemonError>>()?;
    if tenants.is_empty() {
        return Err(DaemonError::Tenant);
    }
    Ok(tenants)
}

async fn run_tick(
    spec: WorkerTickSpec<'_>,
    tenant_failures: &mut BTreeMap<HostedTenantId, TenantFailureState>,
) -> Result<WorkerTickReport, DaemonError> {
    let mut report = WorkerTickReport {
        schema: "chio.finding.worker-tick.v1",
        worker_id: spec.worker_id.to_owned(),
        tenant_count: u32::try_from(spec.tenants.len()).map_err(|_| DaemonError::Execution)?,
        ..WorkerTickReport::default()
    };
    let tenant_budget = usize::try_from(spec.max_tenants)
        .map_err(|_| DaemonError::Execution)?
        .min(spec.tenants.len());
    let mut remaining_jobs = spec.max_jobs;
    let now = current_unix_secs()?;
    for offset in 0..tenant_budget {
        if spec.cancellation.is_cancelled() || remaining_jobs == 0 {
            break;
        }
        let index = (spec.first + offset) % spec.tenants.len();
        let tenant = &spec.tenants[index];
        let failure = tenant_failures.entry(tenant.tenant_id.clone()).or_default();
        if !admit_tenant(failure, now) {
            report.tenants_visited = report
                .tenants_visited
                .checked_add(1)
                .ok_or(DaemonError::Execution)?;
            continue;
        }
        let claim_limit = tenant.limits.max_concurrent_jobs().min(remaining_jobs);
        let run = spec
            .worker
            .run_once_with_limit_cancellable(&tenant.tenant_id, claim_limit, spec.cancellation)
            .await
            .map_err(map_worker_error)?;
        let tenant_failed = run.guest_rejected > 0 || run.exhausted > 0;
        if tenant_failed {
            record_tenant_failure(failure, spec.tenant_failure_threshold, now);
        } else if run.claimed > 0 {
            *failure = TenantFailureState::default();
        }
        remaining_jobs = remaining_jobs
            .checked_sub(run.claimed)
            .ok_or(DaemonError::Execution)?;
        add_run(&mut report, run)?;
        report.tenants_visited = report
            .tenants_visited
            .checked_add(1)
            .ok_or(DaemonError::Execution)?;
    }
    Ok(report)
}

fn admit_tenant(state: &mut TenantFailureState, now: u64) -> bool {
    if state.open_until > now {
        return false;
    }
    if state.open_until != 0 {
        *state = TenantFailureState::default();
    }
    true
}

fn record_tenant_failure(state: &mut TenantFailureState, threshold: u32, now: u64) {
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.consecutive_failures >= threshold {
        state.open_until = now.saturating_add(TENANT_BREAKER_OPEN_SECS);
    }
}

fn map_worker_error(error: HostedWorkerServiceError) -> DaemonError {
    match error {
        HostedWorkerServiceError::Store => DaemonError::Database,
        HostedWorkerServiceError::Configuration | HostedWorkerServiceError::Clock => {
            DaemonError::Execution
        }
    }
}

fn dependency_failure_report(
    worker_id: &str,
    tenants: &[TenantRuntime],
    error_code: &'static str,
) -> Result<WorkerTickReport, DaemonError> {
    Ok(WorkerTickReport {
        schema: "chio.finding.worker-tick.v1",
        worker_id: worker_id.to_owned(),
        ready: false,
        dependency_error: Some(error_code),
        tenant_count: u32::try_from(tenants.len()).map_err(|_| DaemonError::Execution)?,
        ..WorkerTickReport::default()
    })
}

fn add_run(report: &mut WorkerTickReport, run: HostedWorkerRun) -> Result<(), DaemonError> {
    report.claimed_job_ids.extend(run.claimed_job_ids);
    report.completed_job_ids.extend(run.completed_job_ids);
    report.jobs.extend(run.jobs);
    report.claimed = report
        .claimed
        .checked_add(run.claimed)
        .ok_or(DaemonError::Execution)?;
    report.completed = report
        .completed
        .checked_add(run.completed)
        .ok_or(DaemonError::Execution)?;
    report.guest_rejected = report
        .guest_rejected
        .checked_add(run.guest_rejected)
        .ok_or(DaemonError::Execution)?;
    report.retried = report
        .retried
        .checked_add(run.retried)
        .ok_or(DaemonError::Execution)?;
    report.exhausted = report
        .exhausted
        .checked_add(run.exhausted)
        .ok_or(DaemonError::Execution)?;
    report.cancelled = report
        .cancelled
        .checked_add(run.cancelled)
        .ok_or(DaemonError::Execution)?;
    Ok(())
}

fn write_report(report: &WorkerTickReport) -> Result<(), DaemonError> {
    let bytes = canonical_json_bytes(report).map_err(|_| DaemonError::Report)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&bytes).map_err(|_| DaemonError::Report)?;
    lock.write_all(b"\n").map_err(|_| DaemonError::Report)?;
    lock.flush().map_err(|_| DaemonError::Report)
}

async fn shutdown_signal() -> Result<(), DaemonError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| DaemonError::Shutdown)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|_| DaemonError::Shutdown),
        value = terminate.recv() => value.ok_or(DaemonError::Shutdown).map(|_| ()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_arguments_are_closed_and_bounded() {
        let valid = Args {
            profile: PathBuf::from("/etc/chio/finding-hosted.json"),
            worker_id: "worker:blue-1".to_owned(),
            once: false,
            poll_interval_millis: 1_000,
        };
        assert!(validate_arguments(&valid).is_ok());
        let invalid_id = Args {
            worker_id: "worker blue".to_owned(),
            ..valid
        };
        assert!(validate_arguments(&invalid_id).is_err());
    }

    #[test]
    fn only_store_failures_trip_the_database_boundary() {
        assert!(matches!(
            map_worker_error(HostedWorkerServiceError::Store),
            DaemonError::Database
        ));
        for error in [
            HostedWorkerServiceError::Configuration,
            HostedWorkerServiceError::Clock,
        ] {
            assert!(matches!(map_worker_error(error), DaemonError::Execution));
        }
    }

    #[test]
    fn dependency_failure_report_is_closed_and_unready() {
        let tenants = vec![TenantRuntime {
            tenant_id: HostedTenantId::new("tenant-a").unwrap_or_else(|_| unreachable!()),
            limits: HostedTenantLimits::new(1, 10, 100, "revision-1")
                .unwrap_or_else(|_| unreachable!()),
        }];
        let report = dependency_failure_report("worker:blue-1", &tenants, "database_circuit_open");
        assert!(report.is_ok());
        if let Ok(report) = report {
            assert!(!report.ready);
            assert_eq!(report.dependency_error, Some("database_circuit_open"));
            assert_eq!(report.tenant_count, 1);
            assert_eq!(report.claimed, 0);
        }
    }

    #[test]
    fn tenant_breaker_opens_at_threshold_and_recovers_after_window() {
        let mut state = TenantFailureState::default();
        assert!(admit_tenant(&mut state, 100));
        record_tenant_failure(&mut state, 2, 100);
        assert!(admit_tenant(&mut state, 101));
        record_tenant_failure(&mut state, 2, 101);
        assert!(!admit_tenant(&mut state, 129));
        assert!(admit_tenant(&mut state, 131));
        assert_eq!(state.consecutive_failures, 0);
    }
}
