use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core_types::{
    canonical_json_bytes, sha256_hex, PublicKey, SigningAlgorithm, SigningBackend,
};
use chio_finding_market_store_postgres::{HostedMarketJob, HostedTenantId};
use nix::unistd::{fchown, geteuid, Gid, Uid};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::protocol::{
    sign_attested_result, verify_attested_result, FindingWorkerAttestedResult,
    FindingWorkerExitClassification, FindingWorkerInputDescriptor, FindingWorkerInputEnd,
    FindingWorkerInputKind, FindingWorkerRequest, FindingWorkerResourceLimits,
    FindingWorkerResourceUsage, FindingWorkerResult, FINDING_WORKER_INPUT_END_SCHEMA,
    FINDING_WORKER_INPUT_SCHEMA,
};

const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const VSOCK_GUEST_CID: u32 = 3;
const VSOCK_PATH: &str = "/worker.vsock";
const VM_CONFIG_PATH: &str = "/vm-config.json";
const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
const TENANT_CAS_DOMAIN: &str = "chio.finding.worker-tenant-cas.v1";
const CGROUP_CPU_PERIOD_MICROS: u64 = 100_000;
const CGROUP_MIN_CPU_QUOTA_MICROS: u64 = 1_000;
const MIB_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirecrackerIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug)]
pub struct FirecrackerWorkerConfig {
    pub worker_binary: PathBuf,
    pub worker_binary_sha256: String,
    pub firecracker_binary: PathBuf,
    pub firecracker_sha256: String,
    pub jailer_binary: PathBuf,
    pub jailer_sha256: String,
    pub kernel_image: PathBuf,
    pub kernel_sha256: String,
    pub rootfs_image: PathBuf,
    pub rootfs_sha256: String,
    pub artifact_store_root: PathBuf,
    pub jail_root: PathBuf,
    pub identities: Vec<FirecrackerIdentity>,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub execution_timeout: Duration,
    pub max_frame_bytes: u32,
    pub max_file_size_bytes: u64,
    pub max_open_files: u32,
    pub guest_vsock_port: u32,
    pub capability_authority: PublicKey,
}

impl FirecrackerWorkerConfig {
    pub fn validate(&self) -> Result<(), WorkerExecutionError> {
        for path in [
            &self.worker_binary,
            &self.firecracker_binary,
            &self.jailer_binary,
            &self.kernel_image,
            &self.rootfs_image,
            &self.artifact_store_root,
            &self.jail_root,
        ] {
            validate_absolute_path(path)?;
        }
        if !valid_digest(&self.worker_binary_sha256)
            || !valid_digest(&self.firecracker_sha256)
            || !valid_digest(&self.jailer_sha256)
            || !valid_digest(&self.kernel_sha256)
            || !valid_digest(&self.rootfs_sha256)
            || self.capability_authority.algorithm() != SigningAlgorithm::Ed25519
            || self.capability_authority.is_weak_ed25519()
            || self.identities.is_empty()
            || self.identities.len() > 1_024
            || !(1..=32).contains(&self.vcpu_count)
            || !(128..=131_072).contains(&self.memory_mib)
            || !(1..=3_600).contains(&self.execution_timeout.as_secs())
            || !(1_024..=4_194_304).contains(&self.max_frame_bytes)
            || !(1_048_576..=1_073_741_824).contains(&self.max_file_size_bytes)
            || !(32..=4_096).contains(&self.max_open_files)
            || !(1_024..=65_535).contains(&self.guest_vsock_port)
        {
            return Err(WorkerExecutionError::Configuration);
        }
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        for identity in &self.identities {
            if identity.uid == 0
                || identity.gid == 0
                || !uids.insert(identity.uid)
                || !gids.insert(identity.gid)
            {
                return Err(WorkerExecutionError::Configuration);
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerExecutionError {
    #[error("finding worker configuration is invalid")]
    Configuration,
    #[error("finding worker host preflight failed")]
    HostPreflight,
    #[error("finding worker asset integrity failed")]
    AssetIntegrity,
    #[error("finding worker artifact store failed")]
    ArtifactStore,
    #[error("finding worker jail staging failed")]
    Staging,
    #[error("finding worker process failed")]
    Process,
    #[error("finding worker execution timed out")]
    Timeout,
    #[error("finding worker protocol failed")]
    Protocol,
    #[error("finding worker guest rejected the request")]
    GuestRejected,
    #[error("finding worker capacity is unavailable")]
    Capacity,
    #[error("finding worker execution was cancelled")]
    Cancelled,
}

impl WorkerExecutionError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "worker_configuration",
            Self::HostPreflight => "worker_host_preflight",
            Self::AssetIntegrity => "worker_asset_integrity",
            Self::ArtifactStore => "worker_artifact_store",
            Self::Staging => "worker_staging",
            Self::Process => "worker_process",
            Self::Timeout => "worker_timeout",
            Self::Protocol => "worker_protocol",
            Self::GuestRejected => "worker_guest_rejected",
            Self::Capacity => "worker_capacity",
            Self::Cancelled => "worker_cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EnforcedJobLimits {
    wall_time: Duration,
    cpu_quota_micros: u64,
    memory_bytes: u64,
    memory_mib: u32,
    output_bytes: u64,
    process_count: u32,
    open_files: u32,
}

impl EnforcedJobLimits {
    fn new(
        config: &FirecrackerWorkerConfig,
        limits: &FindingWorkerResourceLimits,
    ) -> Result<Self, WorkerExecutionError> {
        let configured_memory = u64::from(config.memory_mib)
            .checked_mul(MIB_BYTES)
            .ok_or(WorkerExecutionError::Configuration)?;
        let configured_wall_millis = u64::try_from(config.execution_timeout.as_millis())
            .map_err(|_| WorkerExecutionError::Configuration)?;
        if limits.memory_bytes > configured_memory
            || limits.wall_time_millis > configured_wall_millis
            || limits.output_bytes > config.max_file_size_bytes
            || limits.open_files > config.max_open_files
        {
            return Err(WorkerExecutionError::Configuration);
        }
        let memory_mib = limits
            .memory_bytes
            .checked_add(MIB_BYTES - 1)
            .and_then(|bytes| bytes.checked_div(MIB_BYTES))
            .and_then(|mib| u32::try_from(mib).ok())
            .ok_or(WorkerExecutionError::Configuration)?;
        let requested_quota = limits
            .cpu_time_millis
            .checked_mul(CGROUP_CPU_PERIOD_MICROS)
            .and_then(|scaled| scaled.checked_add(limits.wall_time_millis - 1))
            .and_then(|scaled| scaled.checked_div(limits.wall_time_millis))
            .ok_or(WorkerExecutionError::Configuration)?;
        if requested_quota < CGROUP_MIN_CPU_QUOTA_MICROS {
            return Err(WorkerExecutionError::Configuration);
        }
        let configured_quota = u64::from(config.vcpu_count)
            .checked_mul(CGROUP_CPU_PERIOD_MICROS)
            .ok_or(WorkerExecutionError::Configuration)?;
        Ok(Self {
            wall_time: Duration::from_millis(limits.wall_time_millis),
            cpu_quota_micros: requested_quota.min(configured_quota),
            memory_bytes: limits.memory_bytes,
            memory_mib,
            output_bytes: limits.output_bytes,
            process_count: limits.process_count,
            open_files: limits.open_files,
        })
    }
}

struct ExecutorInner {
    config: FirecrackerWorkerConfig,
    signer: Arc<dyn SigningBackend>,
    capacity: Arc<Semaphore>,
    identities: Mutex<Vec<FirecrackerIdentity>>,
}

#[derive(Clone)]
pub struct FirecrackerExecutor {
    inner: Arc<ExecutorInner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirecrackerExecutionResult {
    pub envelope_json: Vec<u8>,
    pub guest_classification: FindingWorkerExitClassification,
}

impl FirecrackerExecutor {
    pub fn new(
        config: FirecrackerWorkerConfig,
        signer: Arc<dyn SigningBackend>,
    ) -> Result<Self, WorkerExecutionError> {
        config.validate()?;
        if signer.algorithm() != chio_core_types::SigningAlgorithm::Ed25519
            || signer.public_key().is_weak_ed25519()
        {
            return Err(WorkerExecutionError::Configuration);
        }
        Ok(Self {
            inner: Arc::new(ExecutorInner {
                capacity: Arc::new(Semaphore::new(config.identities.len())),
                identities: Mutex::new(config.identities.clone()),
                signer,
                config,
            }),
        })
    }

    #[must_use]
    pub fn max_instances(&self) -> usize {
        self.inner.config.identities.len()
    }

    #[must_use]
    pub fn execution_timeout(&self) -> Duration {
        self.inner.config.execution_timeout
    }

    /// Verify host privilege, KVM availability, trusted parent ownership,
    /// and every pinned executable and image before the service claims work.
    pub fn preflight_host(&self) -> Result<(), WorkerExecutionError> {
        self.preflight(&CancellationToken::new(), None)
    }

    /// Verify that one tenant's opaque CAS namespace was provisioned with
    /// the same ownership boundary as the host-wide artifact root.
    pub fn preflight_tenant_artifact_store(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<(), WorkerExecutionError> {
        require_trusted_directory(&tenant_cas_root(
            &self.inner.config.artifact_store_root,
            tenant.as_str(),
        ))
    }

    pub async fn execute(
        &self,
        job: &HostedMarketJob,
        now: u64,
    ) -> Result<FirecrackerExecutionResult, WorkerExecutionError> {
        self.execute_cancellable(job, now, &CancellationToken::new())
            .await
    }

    pub async fn execute_cancellable(
        &self,
        job: &HostedMarketJob,
        now: u64,
        cancellation: &CancellationToken,
    ) -> Result<FirecrackerExecutionResult, WorkerExecutionError> {
        if cancellation.is_cancelled() {
            return Err(WorkerExecutionError::Cancelled);
        }
        let started = Instant::now();
        let deadline = now
            .checked_add(self.inner.config.execution_timeout.as_secs())
            .ok_or(WorkerExecutionError::Configuration)?;
        let request = FindingWorkerRequest::from_job(
            job,
            deadline,
            &self.inner.config.capability_authority,
            now,
        )
        .map_err(|_| WorkerExecutionError::Protocol)?;
        let request_bytes =
            canonical_json_bytes(&request).map_err(|_| WorkerExecutionError::Protocol)?;
        validate_frame_payload(&request_bytes, self.inner.config.max_frame_bytes)?;
        let enforced_limits = self.admit_job_limits(&request)?;
        let preflight_budget = self
            .inner
            .config
            .execution_timeout
            .min(enforced_limits.wall_time)
            .checked_sub(started.elapsed())
            .ok_or(WorkerExecutionError::Timeout)?;
        let preflight_executor = self.clone();
        let preflight_cancellation = cancellation.clone();
        tokio::task::spawn_blocking(move || {
            preflight_executor.preflight(
                &preflight_cancellation,
                Some(Instant::now() + preflight_budget),
            )
        })
        .await
        .map_err(|_| WorkerExecutionError::HostPreflight)??;
        let identity = self.acquire_identity(cancellation).await?;
        let jail_id = format!("chio-{}", Uuid::new_v4().simple());
        let config = self.inner.config.clone();
        let staging_budget = config
            .execution_timeout
            .min(enforced_limits.wall_time)
            .checked_sub(started.elapsed())
            .ok_or(WorkerExecutionError::Timeout)?;
        let staging_cancellation = cancellation.clone();
        let mut staged = tokio::task::spawn_blocking(move || {
            stage_jail(
                &config,
                &jail_id,
                identity.id,
                enforced_limits,
                Instant::now() + staging_budget,
                &staging_cancellation,
            )
        })
        .await
        .map_err(|_| WorkerExecutionError::Staging)??;
        let jail = staged.cleanup.take().ok_or(WorkerExecutionError::Staging)?;
        if cancellation.is_cancelled() {
            let cleanup = jail.cleanup();
            drop(identity);
            cleanup?;
            return Err(WorkerExecutionError::Cancelled);
        }
        let mut child = staged.plan.spawn()?;
        let remaining = enforced_limits
            .wall_time
            .checked_sub(started.elapsed())
            .ok_or(WorkerExecutionError::Timeout)?;
        let result = tokio::select! {
            result = exchange_with_guest(
                &mut child,
                &staged.vsock_path,
                self.inner.config.guest_vsock_port,
                &request,
                &self.inner.config.artifact_store_root,
                self.inner.config.max_frame_bytes,
                remaining,
            ) => result,
            () = cancellation.cancelled() => Err(WorkerExecutionError::Cancelled),
        };
        let execution_elapsed = started.elapsed();
        terminate_child(&mut child).await;
        let host_usage = result
            .as_ref()
            .ok()
            .map(|guest| jail.observe_usage(execution_elapsed, guest))
            .transpose();
        let cleanup = jail.cleanup();
        drop(identity);
        let (mut guest, observed) = match (result, host_usage, cleanup) {
            (Ok(result), Ok(Some(observed)), Ok(())) => Ok((result, observed)),
            (Err(error), _, _) => Err(error),
            (Ok(_), Err(error), _) | (Ok(_), _, Err(error)) => Err(error),
            (Ok(_), Ok(None), Ok(())) => Err(WorkerExecutionError::Protocol),
        }?;
        reconcile_host_usage(&mut guest, observed, &request)?;
        let completed_at = unix_time()?;
        let guest_classification = guest.classification;
        let body = FindingWorkerAttestedResult::from_guest(
            &request,
            guest,
            self.inner.config.worker_binary_sha256.clone(),
            self.inner.config.firecracker_sha256.clone(),
            self.inner.config.jailer_sha256.clone(),
            self.inner.config.kernel_sha256.clone(),
            self.inner.config.rootfs_sha256.clone(),
            completed_at,
        )
        .map_err(|_| WorkerExecutionError::Protocol)?;
        let signer = Arc::clone(&self.inner.signer);
        let envelope =
            tokio::task::spawn_blocking(move || sign_attested_result(body, signer.as_ref()))
                .await
                .map_err(|_| WorkerExecutionError::Process)?
                .map_err(|_| WorkerExecutionError::Process)?;
        verify_attested_result(&envelope, &request, &self.inner.signer.public_key())
            .map_err(|_| WorkerExecutionError::Protocol)?;
        let envelope_json =
            canonical_json_bytes(&envelope).map_err(|_| WorkerExecutionError::Protocol)?;
        Ok(FirecrackerExecutionResult {
            envelope_json,
            guest_classification,
        })
    }

    fn preflight(
        &self,
        cancellation: &CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<(), WorkerExecutionError> {
        check_execution_control(cancellation, deadline)?;
        self.inner.config.validate()?;
        if !geteuid().is_root() {
            return Err(WorkerExecutionError::HostPreflight);
        }
        for path in [
            &self.inner.config.worker_binary,
            &self.inner.config.firecracker_binary,
            &self.inner.config.jailer_binary,
            &self.inner.config.kernel_image,
            &self.inner.config.rootfs_image,
            &self.inner.config.artifact_store_root,
            &self.inner.config.jail_root,
        ] {
            require_trusted_parent_chain(path)?;
        }
        require_trusted_file_digest(
            &self.inner.config.worker_binary,
            true,
            &self.inner.config.worker_binary_sha256,
            MAX_BINARY_BYTES,
            cancellation,
            deadline,
        )?;
        require_trusted_file_digest(
            &self.inner.config.firecracker_binary,
            true,
            &self.inner.config.firecracker_sha256,
            MAX_BINARY_BYTES,
            cancellation,
            deadline,
        )?;
        require_trusted_file_digest(
            &self.inner.config.jailer_binary,
            true,
            &self.inner.config.jailer_sha256,
            MAX_BINARY_BYTES,
            cancellation,
            deadline,
        )?;
        require_trusted_file_digest(
            &self.inner.config.kernel_image,
            false,
            &self.inner.config.kernel_sha256,
            MAX_IMAGE_BYTES,
            cancellation,
            deadline,
        )?;
        require_trusted_file_digest(
            &self.inner.config.rootfs_image,
            false,
            &self.inner.config.rootfs_sha256,
            MAX_IMAGE_BYTES,
            cancellation,
            deadline,
        )?;
        require_trusted_directory(&self.inner.config.jail_root)?;
        require_trusted_directory(&self.inner.config.artifact_store_root)?;
        let kvm = fs::metadata("/dev/kvm").map_err(|_| WorkerExecutionError::HostPreflight)?;
        if !kvm.file_type().is_char_device() {
            return Err(WorkerExecutionError::HostPreflight);
        }
        Ok(())
    }

    fn admit_job_limits(
        &self,
        request: &FindingWorkerRequest,
    ) -> Result<EnforcedJobLimits, WorkerExecutionError> {
        let limits = &request.job.resource_limits;
        if !input_files_within_limit(
            self.inner.config.max_file_size_bytes,
            request.job.repository.archive_size_bytes,
            request
                .job
                .input_artifacts
                .iter()
                .map(|artifact| artifact.size_bytes),
        ) {
            return Err(WorkerExecutionError::Configuration);
        }
        EnforcedJobLimits::new(&self.inner.config, limits)
    }

    async fn acquire_identity(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<IdentityLease, WorkerExecutionError> {
        let acquisition = Arc::clone(&self.inner.capacity).acquire_owned();
        let permit = tokio::select! {
            permit = acquisition => permit.map_err(|_| WorkerExecutionError::Capacity)?,
            () = cancellation.cancelled() => return Err(WorkerExecutionError::Cancelled),
        };
        let id = self
            .inner
            .identities
            .lock()
            .map_err(|_| WorkerExecutionError::Capacity)?
            .pop()
            .ok_or(WorkerExecutionError::Capacity)?;
        Ok(IdentityLease {
            id,
            identities: Arc::clone(&self.inner),
            _permit: permit,
        })
    }
}

fn input_files_within_limit(
    maximum: u64,
    repository_size: u64,
    artifact_sizes: impl IntoIterator<Item = u64>,
) -> bool {
    repository_size <= maximum && artifact_sizes.into_iter().all(|size| size <= maximum)
}

struct IdentityLease {
    id: FirecrackerIdentity,
    identities: Arc<ExecutorInner>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for IdentityLease {
    fn drop(&mut self) {
        if let Ok(mut identities) = self.identities.identities.lock() {
            identities.push(self.id);
        }
    }
}

struct JailerCommandPlan {
    program: PathBuf,
    args: Vec<OsString>,
}

impl JailerCommandPlan {
    fn spawn(&self) -> Result<Child, WorkerExecutionError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.spawn().map_err(|_| WorkerExecutionError::Process)
    }
}

struct StagedJail {
    cleanup: Option<JailGuard>,
    vsock_path: PathBuf,
    plan: JailerCommandPlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostResourceUsage {
    wall_time_millis: u64,
    cpu_time_millis: u64,
    peak_memory_bytes: u64,
    output_bytes: u64,
    process_peak: u32,
}

fn reconcile_host_usage(
    guest: &mut FindingWorkerResult,
    observed: HostResourceUsage,
    request: &FindingWorkerRequest,
) -> Result<(), WorkerExecutionError> {
    reconcile_resource_usage(
        &mut guest.resource_usage,
        observed,
        &request.job.resource_limits,
    )?;
    guest
        .validate_for(request)
        .map_err(|_| WorkerExecutionError::Protocol)
}

fn reconcile_resource_usage(
    usage: &mut FindingWorkerResourceUsage,
    observed: HostResourceUsage,
    limits: &FindingWorkerResourceLimits,
) -> Result<(), WorkerExecutionError> {
    if observed.wall_time_millis > limits.wall_time_millis
        || observed.cpu_time_millis > limits.cpu_time_millis
        || observed.peak_memory_bytes > limits.memory_bytes
        || observed.output_bytes > limits.output_bytes
        || observed.process_peak > limits.process_count
    {
        return Err(WorkerExecutionError::Protocol);
    }
    usage.wall_time_millis = usage.wall_time_millis.max(observed.wall_time_millis);
    usage.cpu_time_millis = usage.cpu_time_millis.max(observed.cpu_time_millis);
    usage.peak_memory_bytes = usage.peak_memory_bytes.max(observed.peak_memory_bytes);
    usage.output_bytes = observed.output_bytes;
    usage.process_peak = usage.process_peak.max(observed.process_peak);
    Ok(())
}

fn stage_jail(
    config: &FirecrackerWorkerConfig,
    jail_id: &str,
    identity: FirecrackerIdentity,
    limits: EnforcedJobLimits,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<StagedJail, WorkerExecutionError> {
    if cancellation.is_cancelled() {
        return Err(WorkerExecutionError::Cancelled);
    }
    if jail_id.len() > 64
        || !jail_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(WorkerExecutionError::Staging);
    }
    let executable_name = config
        .firecracker_binary
        .file_name()
        .ok_or(WorkerExecutionError::Configuration)?;
    let executable_dir = config.jail_root.join(executable_name);
    create_or_validate_root_directory(&executable_dir)?;
    let job_dir = executable_dir.join(jail_id);
    fs::create_dir(&job_dir).map_err(|_| WorkerExecutionError::Staging)?;
    fs::set_permissions(&job_dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| WorkerExecutionError::Staging)?;
    let mut staging = StagingGuard::new(job_dir.clone(), executable_dir.clone());
    let root = job_dir.join("root");
    fs::create_dir(&root).map_err(|_| WorkerExecutionError::Staging)?;

    let kernel_path = root.join("kernel");
    copy_verified(
        &config.kernel_image,
        &kernel_path,
        &config.kernel_sha256,
        identity,
        deadline,
        cancellation,
    )?;
    let rootfs_path = root.join("rootfs.ext4");
    copy_verified(
        &config.rootfs_image,
        &rootfs_path,
        &config.rootfs_sha256,
        identity,
        deadline,
        cancellation,
    )?;
    if cancellation.is_cancelled() {
        return Err(WorkerExecutionError::Cancelled);
    }
    let vm_config = canonical_json_bytes(&GuestMachineConfig::new(config, limits))
        .map_err(|_| WorkerExecutionError::Staging)?;
    write_owned_file(&root.join("vm-config.json"), &vm_config, identity)?;

    let vsock_path = root.join("worker.vsock");
    let args = jailer_args(config, jail_id, identity, limits)?;
    staging.disarm();
    let cgroup_parent = Path::new("/sys/fs/cgroup").join(executable_name);
    let cgroup_dir = cgroup_parent.join(jail_id);
    Ok(StagedJail {
        cleanup: Some(JailGuard::new(
            job_dir,
            executable_dir,
            cgroup_dir,
            cgroup_parent,
        )),
        vsock_path,
        plan: JailerCommandPlan {
            program: config.jailer_binary.clone(),
            args,
        },
    })
}

fn jailer_args(
    config: &FirecrackerWorkerConfig,
    jail_id: &str,
    identity: FirecrackerIdentity,
    limits: EnforcedJobLimits,
) -> Result<Vec<OsString>, WorkerExecutionError> {
    Ok(vec![
        "--id".into(),
        jail_id.into(),
        "--exec-file".into(),
        config.firecracker_binary.as_os_str().to_owned(),
        "--uid".into(),
        identity.uid.to_string().into(),
        "--gid".into(),
        identity.gid.to_string().into(),
        "--chroot-base-dir".into(),
        config.jail_root.as_os_str().to_owned(),
        "--new-pid-ns".into(),
        "--cgroup-version".into(),
        "2".into(),
        "--cgroup".into(),
        format!("memory.max={}", limits.memory_bytes).into(),
        "--cgroup".into(),
        format!("pids.max={}", limits.process_count).into(),
        "--cgroup".into(),
        format!(
            "cpu.max={} {CGROUP_CPU_PERIOD_MICROS}",
            limits.cpu_quota_micros
        )
        .into(),
        "--resource-limit".into(),
        format!("fsize={}", limits.output_bytes).into(),
        "--resource-limit".into(),
        format!("no-file={}", limits.open_files).into(),
        "--".into(),
        "--no-api".into(),
        "--config-file".into(),
        VM_CONFIG_PATH.into(),
    ])
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct GuestMachineConfig {
    boot_source: BootSource,
    drives: [Drive; 1],
    machine_config: MachineConfig,
    vsock: Vsock,
}

impl GuestMachineConfig {
    fn new(config: &FirecrackerWorkerConfig, limits: EnforcedJobLimits) -> Self {
        Self {
            boot_source: BootSource {
                kernel_image_path: "/kernel",
                boot_args: "reboot=k panic=1 pci=off 8250.nr_uarts=0 quiet loglevel=1",
            },
            drives: [Drive {
                drive_id: "rootfs",
                path_on_host: "/rootfs.ext4",
                is_root_device: true,
                is_read_only: true,
            }],
            machine_config: MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: limits.memory_mib,
                smt: false,
                track_dirty_pages: false,
            },
            vsock: Vsock {
                guest_cid: VSOCK_GUEST_CID,
                uds_path: VSOCK_PATH,
            },
        }
    }
}

#[derive(Serialize)]
struct BootSource {
    kernel_image_path: &'static str,
    boot_args: &'static str,
}

#[derive(Serialize)]
struct Drive {
    drive_id: &'static str,
    path_on_host: &'static str,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Serialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
    smt: bool,
    track_dirty_pages: bool,
}

#[derive(Serialize)]
struct Vsock {
    guest_cid: u32,
    uds_path: &'static str,
}

async fn exchange_with_guest(
    child: &mut Child,
    socket_path: &Path,
    port: u32,
    request: &FindingWorkerRequest,
    artifact_store_root: &Path,
    max_frame_bytes: u32,
    execution_timeout: Duration,
) -> Result<FindingWorkerResult, WorkerExecutionError> {
    let started = Instant::now();
    let mut stream = loop {
        if started.elapsed() >= execution_timeout {
            return Err(WorkerExecutionError::Timeout);
        }
        if child
            .try_wait()
            .map_err(|_| WorkerExecutionError::Process)?
            .is_some()
        {
            return Err(WorkerExecutionError::Process);
        }
        match UnixStream::connect(socket_path).await {
            Ok(stream) => break stream,
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    };
    let remaining = execution_timeout
        .checked_sub(started.elapsed())
        .ok_or(WorkerExecutionError::Timeout)?;
    timeout(remaining, async {
        let tenant_artifact_root = tenant_cas_root(artifact_store_root, &request.tenant_id);
        require_trusted_directory(&tenant_artifact_root)?;
        stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .await
            .map_err(|_| WorkerExecutionError::Protocol)?;
        let acknowledgement = read_line_bounded(&mut stream, 64).await?;
        if acknowledgement != format!("OK {port}\n") {
            return Err(WorkerExecutionError::Protocol);
        }
        let request_bytes =
            canonical_json_bytes(request).map_err(|_| WorkerExecutionError::Protocol)?;
        write_frame(&mut stream, &request_bytes, max_frame_bytes).await?;
        let ready = read_line_bounded(&mut stream, 80).await?;
        if ready != format!("READY {}\n", request.request_sha256) {
            return Err(WorkerExecutionError::Protocol);
        }
        transfer_inputs(&mut stream, request, &tenant_artifact_root, max_frame_bytes).await?;
        let response = read_frame(&mut stream, max_frame_bytes).await?;
        let raw = std::str::from_utf8(&response).map_err(|_| WorkerExecutionError::Protocol)?;
        let canonical = chio_core_types::canonical_json_bytes_from_str(raw)
            .map_err(|_| WorkerExecutionError::Protocol)?;
        if canonical != response {
            return Err(WorkerExecutionError::Protocol);
        }
        let result: FindingWorkerResult =
            serde_json::from_slice(&response).map_err(|_| WorkerExecutionError::Protocol)?;
        result
            .validate_for(request)
            .map_err(|_| WorkerExecutionError::Protocol)?;
        receive_outputs(&mut stream, &result, &tenant_artifact_root, max_frame_bytes).await?;
        let done = read_line_bounded(&mut stream, 80).await?;
        if done != format!("DONE {}\n", request.request_sha256) {
            return Err(WorkerExecutionError::Protocol);
        }
        Ok(result)
    })
    .await
    .map_err(|_| WorkerExecutionError::Timeout)?
}

async fn transfer_inputs(
    stream: &mut UnixStream,
    request: &FindingWorkerRequest,
    artifact_store_root: &Path,
    max_frame_bytes: u32,
) -> Result<(), WorkerExecutionError> {
    let repository = FindingWorkerInputDescriptor {
        schema: FINDING_WORKER_INPUT_SCHEMA.to_owned(),
        kind: FindingWorkerInputKind::Repository,
        name: "repository.archive".to_owned(),
        sha256: request.job.repository.archive_sha256.clone(),
        size_bytes: request.job.repository.archive_size_bytes,
    };
    transfer_input(stream, artifact_store_root, &repository, max_frame_bytes).await?;
    let mut total_size = repository.size_bytes;
    for artifact in &request.job.input_artifacts {
        let descriptor = FindingWorkerInputDescriptor {
            schema: FINDING_WORKER_INPUT_SCHEMA.to_owned(),
            kind: FindingWorkerInputKind::Artifact,
            name: artifact.name.clone(),
            sha256: artifact.sha256.clone(),
            size_bytes: artifact.size_bytes,
        };
        transfer_input(stream, artifact_store_root, &descriptor, max_frame_bytes).await?;
        total_size = total_size
            .checked_add(descriptor.size_bytes)
            .ok_or(WorkerExecutionError::Protocol)?;
    }
    let input_count = u32::try_from(request.job.input_artifacts.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(WorkerExecutionError::Protocol)?;
    let end = FindingWorkerInputEnd {
        schema: FINDING_WORKER_INPUT_END_SCHEMA.to_owned(),
        input_count,
        total_size_bytes: total_size,
    };
    end.validate().map_err(|_| WorkerExecutionError::Protocol)?;
    let bytes = canonical_json_bytes(&end).map_err(|_| WorkerExecutionError::Protocol)?;
    write_frame(stream, &bytes, max_frame_bytes).await
}

async fn transfer_input(
    stream: &mut UnixStream,
    artifact_store_root: &Path,
    descriptor: &FindingWorkerInputDescriptor,
    max_frame_bytes: u32,
) -> Result<(), WorkerExecutionError> {
    descriptor
        .validate()
        .map_err(|_| WorkerExecutionError::Protocol)?;
    let path = cas_path(artifact_store_root, &descriptor.sha256)?;
    let file = open_cas_input(&path, descriptor.size_bytes)?;
    let mut file = tokio::fs::File::from_std(file);
    verify_async_cas_input(&mut file, &descriptor.sha256).await?;
    let descriptor_bytes =
        canonical_json_bytes(descriptor).map_err(|_| WorkerExecutionError::Protocol)?;
    write_frame(stream, &descriptor_bytes, max_frame_bytes).await?;
    let frame_limit = usize::try_from(max_frame_bytes)
        .map_err(|_| WorkerExecutionError::Protocol)?
        .min(TRANSFER_CHUNK_BYTES);
    let mut remaining = descriptor.size_bytes;
    let mut buffer = vec![0_u8; frame_limit];
    let mut digest = Sha256::new();
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(frame_limit as u64))
            .map_err(|_| WorkerExecutionError::Protocol)?;
        let read = file
            .read(&mut buffer[..wanted])
            .await
            .map_err(|_| WorkerExecutionError::ArtifactStore)?;
        if read == 0 {
            return Err(WorkerExecutionError::AssetIntegrity);
        }
        digest.update(&buffer[..read]);
        write_frame(stream, &buffer[..read], max_frame_bytes).await?;
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| WorkerExecutionError::Protocol)?)
            .ok_or(WorkerExecutionError::Protocol)?;
    }
    if format!("{:x}", digest.finalize()) != descriptor.sha256 {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    Ok(())
}

async fn receive_outputs(
    stream: &mut UnixStream,
    result: &FindingWorkerResult,
    artifact_store_root: &Path,
    max_frame_bytes: u32,
) -> Result<(), WorkerExecutionError> {
    for artifact in &result.output_artifacts {
        receive_output(
            stream,
            artifact_store_root,
            &artifact.sha256,
            artifact.size_bytes,
            max_frame_bytes,
        )
        .await?;
    }
    Ok(())
}

async fn receive_output(
    stream: &mut UnixStream,
    artifact_store_root: &Path,
    expected_digest: &str,
    expected_size: u64,
    max_frame_bytes: u32,
) -> Result<(), WorkerExecutionError> {
    let target = cas_path(artifact_store_root, expected_digest)?;
    let parent = target.parent().ok_or(WorkerExecutionError::ArtifactStore)?;
    create_or_validate_artifact_directory(parent)?;
    let temporary = parent.join(format!(".chio-{}.tmp", Uuid::new_v4().simple()));
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    let guard = TemporaryArtifact::new(temporary.clone());
    let mut output = tokio::fs::File::from_std(output);
    let mut digest = Sha256::new();
    let mut remaining = expected_size;
    while remaining != 0 {
        let frame = read_frame(stream, max_frame_bytes).await?;
        let frame_size = u64::try_from(frame.len()).map_err(|_| WorkerExecutionError::Protocol)?;
        if frame_size > remaining {
            return Err(WorkerExecutionError::Protocol);
        }
        digest.update(&frame);
        output
            .write_all(&frame)
            .await
            .map_err(|_| WorkerExecutionError::ArtifactStore)?;
        remaining = remaining
            .checked_sub(frame_size)
            .ok_or(WorkerExecutionError::Protocol)?;
    }
    output
        .sync_all()
        .await
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    drop(output);
    if format!("{:x}", digest.finalize()) != expected_digest {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    match fs::hard_link(&temporary, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_verified_cas_input(&target, expected_digest, expected_size)?;
        }
        Err(_) => return Err(WorkerExecutionError::ArtifactStore),
    }
    guard.remove()?;
    sync_directory(parent)
}

fn cas_path(root: &Path, digest: &str) -> Result<PathBuf, WorkerExecutionError> {
    if !valid_digest(digest) {
        return Err(WorkerExecutionError::Protocol);
    }
    Ok(root.join(&digest[..2]).join(digest))
}

fn tenant_cas_root(root: &Path, tenant_id: &str) -> PathBuf {
    let digest = sha256_hex(format!("{TENANT_CAS_DOMAIN}\0{tenant_id}").as_bytes());
    root.join(digest)
}

fn open_verified_cas_input(
    path: &Path,
    expected_digest: &str,
    expected_size: u64,
) -> Result<File, WorkerExecutionError> {
    let parent = path.parent().ok_or(WorkerExecutionError::ArtifactStore)?;
    require_trusted_directory(parent)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    let metadata = file
        .metadata()
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    if !trusted_file_metadata(&metadata, false) || metadata.len() != expected_size {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WorkerExecutionError::ArtifactStore)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != expected_digest {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    use std::io::Seek as _;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    Ok(file)
}

fn open_cas_input(path: &Path, expected_size: u64) -> Result<File, WorkerExecutionError> {
    let parent = path.parent().ok_or(WorkerExecutionError::ArtifactStore)?;
    require_trusted_directory(parent)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    let metadata = file
        .metadata()
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    if !trusted_file_metadata(&metadata, false) || metadata.len() != expected_size {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    Ok(file)
}

async fn verify_async_cas_input(
    file: &mut tokio::fs::File,
    expected_digest: &str,
) -> Result<(), WorkerExecutionError> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| WorkerExecutionError::ArtifactStore)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != expected_digest {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|_| WorkerExecutionError::ArtifactStore)?;
    Ok(())
}

fn create_or_validate_artifact_directory(path: &Path) -> Result<(), WorkerExecutionError> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| WorkerExecutionError::ArtifactStore)?;
            require_trusted_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_trusted_directory(path)
        }
        Err(_) => Err(WorkerExecutionError::ArtifactStore),
    }
}

fn sync_directory(path: &Path) -> Result<(), WorkerExecutionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WorkerExecutionError::ArtifactStore)
}

struct TemporaryArtifact {
    path: PathBuf,
}

impl TemporaryArtifact {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn remove(mut self) -> Result<(), WorkerExecutionError> {
        fs::remove_file(&self.path).map_err(|_| WorkerExecutionError::ArtifactStore)?;
        self.path.clear();
        Ok(())
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

async fn read_line_bounded(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<String, WorkerExecutionError> {
    let mut bytes = Vec::with_capacity(maximum);
    while bytes.len() < maximum {
        let byte = stream
            .read_u8()
            .await
            .map_err(|_| WorkerExecutionError::Protocol)?;
        bytes.push(byte);
        if byte == b'\n' {
            return String::from_utf8(bytes).map_err(|_| WorkerExecutionError::Protocol);
        }
    }
    Err(WorkerExecutionError::Protocol)
}

async fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    maximum: u32,
) -> Result<(), WorkerExecutionError> {
    let length = validate_frame_payload(bytes, maximum)?;
    stream
        .write_u32(length)
        .await
        .map_err(|_| WorkerExecutionError::Protocol)?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| WorkerExecutionError::Protocol)
}

fn validate_frame_payload(bytes: &[u8], maximum: u32) -> Result<u32, WorkerExecutionError> {
    let length = u32::try_from(bytes.len()).map_err(|_| WorkerExecutionError::Protocol)?;
    if length == 0 || length > maximum {
        return Err(WorkerExecutionError::Protocol);
    }
    Ok(length)
}

async fn read_frame(
    stream: &mut UnixStream,
    maximum: u32,
) -> Result<Vec<u8>, WorkerExecutionError> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| WorkerExecutionError::Protocol)?;
    if length == 0 || length > maximum {
        return Err(WorkerExecutionError::Protocol);
    }
    let mut bytes = vec![0_u8; length as usize];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| WorkerExecutionError::Protocol)?;
    Ok(bytes)
}

async fn terminate_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
}

fn create_or_validate_root_directory(path: &Path) -> Result<(), WorkerExecutionError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| WorkerExecutionError::Staging),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_trusted_directory(path)
        }
        Err(_) => Err(WorkerExecutionError::Staging),
    }
}

fn copy_verified(
    source: &Path,
    target: &Path,
    expected_sha256: &str,
    identity: FirecrackerIdentity,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), WorkerExecutionError> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|_| WorkerExecutionError::AssetIntegrity)?;
    let metadata = input
        .metadata()
        .map_err(|_| WorkerExecutionError::AssetIntegrity)?;
    if !trusted_file_metadata(&metadata, false)
        || metadata.len() == 0
        || metadata.len() > MAX_IMAGE_BYTES
    {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC)
        .open(target)
        .map_err(|_| WorkerExecutionError::Staging)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        if cancellation.is_cancelled() {
            return Err(WorkerExecutionError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(WorkerExecutionError::Timeout);
        }
        let read = input
            .read(&mut buffer)
            .map_err(|_| WorkerExecutionError::AssetIntegrity)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|_| WorkerExecutionError::Staging)?;
    }
    if format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    if cancellation.is_cancelled() {
        return Err(WorkerExecutionError::Cancelled);
    }
    output
        .sync_all()
        .map_err(|_| WorkerExecutionError::Staging)?;
    chown_file(&output, identity)?;
    Ok(())
}

fn write_owned_file(
    path: &Path,
    bytes: &[u8],
    identity: FirecrackerIdentity,
) -> Result<(), WorkerExecutionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WorkerExecutionError::Staging)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| WorkerExecutionError::Staging)?;
    chown_file(&file, identity)
}

fn chown_file(file: &File, identity: FirecrackerIdentity) -> Result<(), WorkerExecutionError> {
    fchown(
        file,
        Some(Uid::from_raw(identity.uid)),
        Some(Gid::from_raw(identity.gid)),
    )
    .map_err(|_| WorkerExecutionError::Staging)
}

fn require_trusted_file_digest(
    path: &Path,
    executable: bool,
    expected_sha256: &str,
    maximum_bytes: u64,
    cancellation: &CancellationToken,
    deadline: Option<Instant>,
) -> Result<(), WorkerExecutionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| WorkerExecutionError::HostPreflight)?;
    let metadata = file
        .metadata()
        .map_err(|_| WorkerExecutionError::HostPreflight)?;
    if !trusted_file_metadata(&metadata, executable)
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(WorkerExecutionError::HostPreflight);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        check_execution_control(cancellation, deadline)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| WorkerExecutionError::HostPreflight)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err(WorkerExecutionError::AssetIntegrity);
    }
    Ok(())
}

fn check_execution_control(
    cancellation: &CancellationToken,
    deadline: Option<Instant>,
) -> Result<(), WorkerExecutionError> {
    if cancellation.is_cancelled() {
        return Err(WorkerExecutionError::Cancelled);
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(WorkerExecutionError::Timeout);
    }
    Ok(())
}

fn require_trusted_directory(path: &Path) -> Result<(), WorkerExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkerExecutionError::HostPreflight)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(WorkerExecutionError::HostPreflight);
    }
    Ok(())
}

fn require_trusted_parent_chain(path: &Path) -> Result<(), WorkerExecutionError> {
    for parent in path.ancestors().skip(1) {
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| WorkerExecutionError::HostPreflight)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(WorkerExecutionError::HostPreflight);
        }
    }
    Ok(())
}

fn trusted_file_metadata(metadata: &fs::Metadata, executable: bool) -> bool {
    metadata.is_file()
        && metadata.uid() == 0
        && metadata.nlink() == 1
        && metadata.mode() & 0o022 == 0
        && (!executable || metadata.mode() & 0o111 != 0)
}

fn unix_time() -> Result<u64, WorkerExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WorkerExecutionError::Protocol)
}

struct StagingGuard {
    job_dir: PathBuf,
    job_parent: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn new(job_dir: PathBuf, job_parent: PathBuf) -> Self {
        Self {
            job_dir,
            job_parent,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_jail(&self.job_dir, &self.job_parent);
        }
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), WorkerExecutionError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(WorkerExecutionError::Configuration);
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct JailGuard {
    job_dir: PathBuf,
    job_parent: PathBuf,
    cgroup_dir: PathBuf,
    cgroup_parent: PathBuf,
    armed: bool,
}

impl JailGuard {
    fn new(
        job_dir: PathBuf,
        job_parent: PathBuf,
        cgroup_dir: PathBuf,
        cgroup_parent: PathBuf,
    ) -> Self {
        Self {
            job_dir,
            job_parent,
            cgroup_dir,
            cgroup_parent,
            armed: true,
        }
    }

    fn cleanup(mut self) -> Result<(), WorkerExecutionError> {
        cleanup_cgroup(&self.cgroup_dir, &self.cgroup_parent)?;
        cleanup_jail(&self.job_dir, &self.job_parent)?;
        self.armed = false;
        Ok(())
    }

    fn observe_usage(
        &self,
        elapsed: Duration,
        guest: &FindingWorkerResult,
    ) -> Result<HostResourceUsage, WorkerExecutionError> {
        let cpu_stat = fs::read_to_string(self.cgroup_dir.join("cpu.stat"))
            .map_err(|_| WorkerExecutionError::Protocol)?;
        let cpu_micros = cpu_stat
            .lines()
            .find_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                (fields.next() == Some("usage_usec"))
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .ok_or(WorkerExecutionError::Protocol)?;
        let memory_peak = read_cgroup_counter(&self.cgroup_dir.join("memory.peak"))?;
        let process_peak = read_cgroup_counter(&self.cgroup_dir.join("pids.peak"))
            .and_then(|value| u32::try_from(value).map_err(|_| WorkerExecutionError::Protocol))?;
        let output_bytes = guest
            .output_artifacts
            .iter()
            .try_fold(0_u64, |total, artifact| {
                total.checked_add(artifact.size_bytes)
            })
            .ok_or(WorkerExecutionError::Protocol)?;
        let elapsed_micros =
            u64::try_from(elapsed.as_micros()).map_err(|_| WorkerExecutionError::Protocol)?;
        let wall_time_millis = elapsed_micros
            .checked_add(999)
            .and_then(|micros| micros.checked_div(1_000))
            .ok_or(WorkerExecutionError::Protocol)?;
        let cpu_time_millis = cpu_micros
            .checked_add(999)
            .and_then(|micros| micros.checked_div(1_000))
            .ok_or(WorkerExecutionError::Protocol)?;
        let observed = HostResourceUsage {
            wall_time_millis,
            cpu_time_millis,
            peak_memory_bytes: memory_peak,
            output_bytes,
            process_peak,
        };
        Ok(observed)
    }
}

fn read_cgroup_counter(path: &Path) -> Result<u64, WorkerExecutionError> {
    let value = fs::read_to_string(path).map_err(|_| WorkerExecutionError::Protocol)?;
    if value.len() > 64 {
        return Err(WorkerExecutionError::Protocol);
    }
    value
        .trim_end()
        .parse::<u64>()
        .map_err(|_| WorkerExecutionError::Protocol)
}

impl Drop for JailGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_cgroup(&self.cgroup_dir, &self.cgroup_parent);
            let _ = cleanup_jail(&self.job_dir, &self.job_parent);
        }
    }
}

fn cleanup_cgroup(path: &Path, expected_parent: &Path) -> Result<(), WorkerExecutionError> {
    if !is_generated_job_path(path, expected_parent) {
        return Err(WorkerExecutionError::Staging);
    }
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WorkerExecutionError::Staging),
    }
}

fn cleanup_jail(path: &Path, expected_parent: &Path) -> Result<(), WorkerExecutionError> {
    if !is_generated_job_path(path, expected_parent) {
        return Err(WorkerExecutionError::Staging);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WorkerExecutionError::Staging),
    }
}

fn is_generated_job_path(path: &Path, expected_parent: &Path) -> bool {
    path.is_absolute()
        && expected_parent.is_absolute()
        && path.parent() == Some(expected_parent)
        && path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.starts_with("chio-")
                && name.len() == 37
                && name[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path) -> FirecrackerWorkerConfig {
        FirecrackerWorkerConfig {
            worker_binary: root.join("chio-finding-worker"),
            worker_binary_sha256: "0".repeat(64),
            firecracker_binary: root.join("firecracker"),
            firecracker_sha256: "1".repeat(64),
            jailer_binary: root.join("jailer"),
            jailer_sha256: "2".repeat(64),
            kernel_image: root.join("kernel"),
            kernel_sha256: "3".repeat(64),
            rootfs_image: root.join("rootfs"),
            rootfs_sha256: "4".repeat(64),
            artifact_store_root: root.join("artifacts"),
            jail_root: root.join("jails"),
            identities: vec![FirecrackerIdentity {
                uid: 1001,
                gid: 1001,
            }],
            vcpu_count: 2,
            memory_mib: 512,
            execution_timeout: Duration::from_secs(30),
            max_frame_bytes: 1024 * 1024,
            max_file_size_bytes: 16 * 1024 * 1024,
            max_open_files: 128,
            guest_vsock_port: 7000,
            capability_authority: chio_core_types::Ed25519Backend::generate().public_key(),
        }
    }

    fn job_limits() -> FindingWorkerResourceLimits {
        FindingWorkerResourceLimits {
            wall_time_millis: 10_000,
            cpu_time_millis: 5_000,
            memory_bytes: 256 * MIB_BYTES,
            workspace_bytes: 64 * MIB_BYTES,
            output_bytes: 8 * MIB_BYTES,
            process_count: 32,
            open_files: 64,
        }
    }

    #[test]
    fn config_requires_distinct_nonroot_identities() {
        let temporary = tempfile::tempdir().ok();
        assert!(temporary.is_some());
        if let Some(temporary) = temporary {
            let mut config = config(temporary.path());
            config.identities.push(FirecrackerIdentity {
                uid: 1001,
                gid: 1002,
            });
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn machine_config_has_no_network_and_keeps_default_seccomp() {
        let temporary = tempfile::tempdir().ok();
        assert!(temporary.is_some());
        if let Some(temporary) = temporary {
            let config = config(temporary.path());
            let limits = EnforcedJobLimits::new(&config, &job_limits());
            assert!(limits.is_ok());
            if let Ok(limits) = limits {
                let value = serde_json::to_value(GuestMachineConfig::new(&config, limits));
                assert!(value.is_ok());
                if let Ok(value) = value {
                    assert!(value.get("network-interfaces").is_none());
                    assert!(value.get("vsock").is_some());
                    assert_eq!(value["machine-config"]["mem_size_mib"], 256);
                }
            }
        }
    }

    #[test]
    fn every_worker_input_obeys_the_host_file_ceiling() {
        assert!(input_files_within_limit(10, 10, [1, 10]));
        assert!(!input_files_within_limit(10, 11, [1, 2]));
        assert!(!input_files_within_limit(10, 1, [2, 11]));
    }

    #[test]
    fn request_frame_is_rejected_before_execution_when_it_exceeds_the_protocol_limit() {
        assert_eq!(
            validate_frame_payload(&[1_u8; 1_024], 1_024).ok(),
            Some(1_024)
        );
        assert!(matches!(
            validate_frame_payload(&[1_u8; 1_025], 1_024),
            Err(WorkerExecutionError::Protocol)
        ));
    }

    #[test]
    fn jailer_plan_enforces_namespaces_cgroups_and_default_seccomp() {
        let temporary = tempfile::tempdir().ok();
        assert!(temporary.is_some());
        if let Some(temporary) = temporary {
            let config = config(temporary.path());
            let limits = EnforcedJobLimits::new(&config, &job_limits());
            assert!(limits.is_ok());
            let args = limits.and_then(|limits| {
                jailer_args(
                    &config,
                    "chio-00000000000000000000000000000000",
                    config.identities[0],
                    limits,
                )
            });
            assert!(args.is_ok());
            if let Ok(args) = args {
                let text = args
                    .iter()
                    .map(|arg| arg.to_string_lossy())
                    .collect::<Vec<_>>();
                assert!(text.contains(&std::borrow::Cow::Borrowed("--new-pid-ns")));
                assert!(text.contains(&std::borrow::Cow::Borrowed("--cgroup-version")));
                assert!(text.contains(&std::borrow::Cow::Borrowed("--no-api")));
                assert!(!text.iter().any(|arg| arg.as_ref() == "--no-seccomp"));
                assert!(!text.iter().any(|arg| arg.as_ref() == "--netns"));
                assert!(text
                    .iter()
                    .any(|arg| arg.as_ref() == "memory.max=268435456"));
                assert!(text.iter().any(|arg| arg.as_ref() == "pids.max=32"));
                assert!(text
                    .iter()
                    .any(|arg| arg.as_ref() == "cpu.max=50000 100000"));
                assert!(text.iter().any(|arg| arg.as_ref() == "fsize=8388608"));
                assert!(text.iter().any(|arg| arg.as_ref() == "no-file=64"));
            }
        }
    }

    #[test]
    fn cancelled_staging_stops_before_touching_the_jail() {
        let temporary = tempfile::tempdir().ok();
        assert!(temporary.is_some());
        if let Some(temporary) = temporary {
            let config = config(temporary.path());
            let limits = EnforcedJobLimits::new(&config, &job_limits());
            assert!(limits.is_ok());
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            if let Ok(limits) = limits {
                let result = stage_jail(
                    &config,
                    "chio-00000000000000000000000000000000",
                    config.identities[0],
                    limits,
                    Instant::now() + Duration::from_secs(1),
                    &cancellation,
                );
                assert!(matches!(result, Err(WorkerExecutionError::Cancelled)));
                assert!(!config.jail_root.exists());
            }
        }
    }

    #[test]
    fn signed_usage_cannot_underreport_host_counters() {
        let limits = job_limits();
        let mut usage = FindingWorkerResourceUsage {
            wall_time_millis: 1,
            cpu_time_millis: 1,
            peak_memory_bytes: 1,
            workspace_bytes: 1,
            output_bytes: 1,
            process_peak: 1,
            open_files_peak: 1,
        };
        let observed = HostResourceUsage {
            wall_time_millis: 2_000,
            cpu_time_millis: 1_000,
            peak_memory_bytes: 128 * MIB_BYTES,
            output_bytes: 4_096,
            process_peak: 4,
        };
        assert!(reconcile_resource_usage(&mut usage, observed, &limits).is_ok());
        assert_eq!(usage.wall_time_millis, observed.wall_time_millis);
        assert_eq!(usage.cpu_time_millis, observed.cpu_time_millis);
        assert_eq!(usage.peak_memory_bytes, observed.peak_memory_bytes);
        assert_eq!(usage.output_bytes, observed.output_bytes);
        assert_eq!(usage.process_peak, observed.process_peak);

        let over_limit = HostResourceUsage {
            peak_memory_bytes: limits.memory_bytes + 1,
            ..observed
        };
        assert!(reconcile_resource_usage(&mut usage, over_limit, &limits).is_err());
    }

    #[test]
    fn cleanup_path_guard_binds_generated_names_to_exact_parent() {
        let expected_parent = Path::new("/srv/jailer/firecracker");
        assert!(is_generated_job_path(
            Path::new("/srv/jailer/firecracker/chio-00000000000000000000000000000000"),
            expected_parent,
        ));
        for path in [
            "/srv/jailer/firecracker",
            "/srv/jailer/firecracker/chio-../escape",
            "/srv/jailer/firecracker/chio-0000000000000000000000000000000g",
            "/srv/jailer/firecracker/not-chio-00000000000000000000000000000000",
            "/srv/other/chio-00000000000000000000000000000000",
        ] {
            assert!(!is_generated_job_path(Path::new(path), expected_parent));
        }
        assert!(!is_generated_job_path(
            Path::new("chio-00000000000000000000000000000000"),
            Path::new("."),
        ));
    }

    #[test]
    fn tenant_cas_namespaces_are_opaque_and_distinct() {
        let root = Path::new("/srv/chio/artifacts");
        let alpha = tenant_cas_root(root, "tenant/alpha");
        let beta = tenant_cas_root(root, "tenant/alpha-2");
        assert_ne!(alpha, beta);
        assert_eq!(alpha.parent(), Some(root));
        assert_eq!(
            alpha
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::len),
            Some(64)
        );
        assert!(!alpha.to_string_lossy().contains("tenant/alpha"));
        assert!(cas_path(&alpha, &"a".repeat(64)).is_ok());
        assert!(cas_path(&alpha, "../escape").is_err());
    }
}
