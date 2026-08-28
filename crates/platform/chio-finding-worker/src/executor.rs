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

use chio_core_types::{canonical_json_bytes, SigningBackend};
use chio_finding_market_store_postgres::HostedMarketJob;
use nix::unistd::{fchown, geteuid, Gid, Uid};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::protocol::{
    sign_attested_result, verify_attested_result, FindingWorkerAttestedResult,
    FindingWorkerRequest, FindingWorkerResult, FindingWorkerResultStatus,
};

const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const VSOCK_GUEST_CID: u32 = 3;
const VSOCK_PATH: &str = "/worker.vsock";
const VM_CONFIG_PATH: &str = "/vm-config.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirecrackerIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug)]
pub struct FirecrackerWorkerConfig {
    pub firecracker_binary: PathBuf,
    pub jailer_binary: PathBuf,
    pub kernel_image: PathBuf,
    pub kernel_sha256: String,
    pub rootfs_image: PathBuf,
    pub rootfs_sha256: String,
    pub jail_root: PathBuf,
    pub identities: Vec<FirecrackerIdentity>,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub execution_timeout: Duration,
    pub max_frame_bytes: u32,
    pub max_file_size_bytes: u64,
    pub max_open_files: u32,
    pub guest_vsock_port: u32,
}

impl FirecrackerWorkerConfig {
    pub fn validate(&self) -> Result<(), WorkerExecutionError> {
        for path in [
            &self.firecracker_binary,
            &self.jailer_binary,
            &self.kernel_image,
            &self.rootfs_image,
            &self.jail_root,
        ] {
            validate_absolute_path(path)?;
        }
        if !valid_digest(&self.kernel_sha256)
            || !valid_digest(&self.rootfs_sha256)
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
}

impl WorkerExecutionError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "worker_configuration",
            Self::HostPreflight => "worker_host_preflight",
            Self::AssetIntegrity => "worker_asset_integrity",
            Self::Staging => "worker_staging",
            Self::Process => "worker_process",
            Self::Timeout => "worker_timeout",
            Self::Protocol => "worker_protocol",
            Self::GuestRejected => "worker_guest_rejected",
            Self::Capacity => "worker_capacity",
        }
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
    pub guest_status: FindingWorkerResultStatus,
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

    pub async fn execute(
        &self,
        job: &HostedMarketJob,
        now: u64,
    ) -> Result<FirecrackerExecutionResult, WorkerExecutionError> {
        let started = Instant::now();
        self.preflight()?;
        let identity = self.acquire_identity().await?;
        let deadline = now
            .checked_add(self.inner.config.execution_timeout.as_secs())
            .ok_or(WorkerExecutionError::Configuration)?;
        let request = FindingWorkerRequest::from_job(job, deadline)
            .map_err(|_| WorkerExecutionError::Protocol)?;
        let jail_id = format!("chio-{}", Uuid::new_v4().simple());
        let config = self.inner.config.clone();
        let staging_budget = config
            .execution_timeout
            .checked_sub(started.elapsed())
            .ok_or(WorkerExecutionError::Timeout)?;
        let staged = tokio::task::spawn_blocking(move || {
            stage_jail(
                &config,
                &jail_id,
                identity.id,
                Instant::now() + staging_budget,
            )
        })
        .await
        .map_err(|_| WorkerExecutionError::Staging)??;
        let jail = JailGuard::new(staged.job_dir.clone(), staged.cgroup_dir.clone());
        let mut child = staged.plan.spawn()?;
        let remaining = self
            .inner
            .config
            .execution_timeout
            .checked_sub(started.elapsed())
            .ok_or(WorkerExecutionError::Timeout)?;
        let result = exchange_with_guest(
            &mut child,
            &staged.vsock_path,
            self.inner.config.guest_vsock_port,
            &request,
            self.inner.config.max_frame_bytes,
            remaining,
        )
        .await;
        terminate_child(&mut child).await;
        let cleanup = jail.cleanup();
        drop(identity);
        let guest = match (result, cleanup) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }?;
        let completed_at = unix_time()?;
        let guest_status = guest.status;
        let body = FindingWorkerAttestedResult::from_guest(
            &request,
            guest,
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
            guest_status,
        })
    }

    fn preflight(&self) -> Result<(), WorkerExecutionError> {
        self.inner.config.validate()?;
        if !geteuid().is_root() {
            return Err(WorkerExecutionError::HostPreflight);
        }
        for path in [
            &self.inner.config.firecracker_binary,
            &self.inner.config.jailer_binary,
            &self.inner.config.kernel_image,
            &self.inner.config.rootfs_image,
            &self.inner.config.jail_root,
        ] {
            require_trusted_parent_chain(path)?;
        }
        require_trusted_file(&self.inner.config.firecracker_binary, true)?;
        require_trusted_file(&self.inner.config.jailer_binary, true)?;
        require_trusted_file(&self.inner.config.kernel_image, false)?;
        require_trusted_file(&self.inner.config.rootfs_image, false)?;
        require_trusted_directory(&self.inner.config.jail_root)?;
        let kvm = fs::metadata("/dev/kvm").map_err(|_| WorkerExecutionError::HostPreflight)?;
        if !kvm.file_type().is_char_device() {
            return Err(WorkerExecutionError::HostPreflight);
        }
        Ok(())
    }

    async fn acquire_identity(&self) -> Result<IdentityLease, WorkerExecutionError> {
        let permit = Arc::clone(&self.inner.capacity)
            .acquire_owned()
            .await
            .map_err(|_| WorkerExecutionError::Capacity)?;
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
    job_dir: PathBuf,
    cgroup_dir: PathBuf,
    vsock_path: PathBuf,
    plan: JailerCommandPlan,
}

fn stage_jail(
    config: &FirecrackerWorkerConfig,
    jail_id: &str,
    identity: FirecrackerIdentity,
    deadline: Instant,
) -> Result<StagedJail, WorkerExecutionError> {
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
    let mut staging = StagingGuard::new(job_dir.clone());
    let root = job_dir.join("root");
    fs::create_dir(&root).map_err(|_| WorkerExecutionError::Staging)?;

    let kernel_path = root.join("kernel");
    copy_verified(
        &config.kernel_image,
        &kernel_path,
        &config.kernel_sha256,
        identity,
        deadline,
    )?;
    let rootfs_path = root.join("rootfs.ext4");
    copy_verified(
        &config.rootfs_image,
        &rootfs_path,
        &config.rootfs_sha256,
        identity,
        deadline,
    )?;
    let vm_config = canonical_json_bytes(&GuestMachineConfig::new(config))
        .map_err(|_| WorkerExecutionError::Staging)?;
    write_owned_file(&root.join("vm-config.json"), &vm_config, identity)?;

    let vsock_path = root.join("worker.vsock");
    let args = jailer_args(config, jail_id, identity)?;
    staging.disarm();
    Ok(StagedJail {
        job_dir,
        cgroup_dir: Path::new("/sys/fs/cgroup")
            .join(executable_name)
            .join(jail_id),
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
) -> Result<Vec<OsString>, WorkerExecutionError> {
    let memory_bytes = u64::from(config.memory_mib)
        .checked_mul(1024 * 1024)
        .ok_or(WorkerExecutionError::Configuration)?;
    let cpu_quota = u64::from(config.vcpu_count) * 100_000;
    let pids = u64::from(config.vcpu_count) + 8;
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
        format!("memory.max={memory_bytes}").into(),
        "--cgroup".into(),
        format!("pids.max={pids}").into(),
        "--cgroup".into(),
        format!("cpu.max={cpu_quota} 100000").into(),
        "--resource-limit".into(),
        format!("fsize={}", config.max_file_size_bytes).into(),
        "--resource-limit".into(),
        format!("no-file={}", config.max_open_files).into(),
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
    fn new(config: &FirecrackerWorkerConfig) -> Self {
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
                mem_size_mib: config.memory_mib,
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
        Ok(result)
    })
    .await
    .map_err(|_| WorkerExecutionError::Timeout)?
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
    let length = u32::try_from(bytes.len()).map_err(|_| WorkerExecutionError::Protocol)?;
    if length == 0 || length > maximum {
        return Err(WorkerExecutionError::Protocol);
    }
    stream
        .write_u32(length)
        .await
        .map_err(|_| WorkerExecutionError::Protocol)?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| WorkerExecutionError::Protocol)
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

fn require_trusted_file(path: &Path, executable: bool) -> Result<(), WorkerExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkerExecutionError::HostPreflight)?;
    if metadata.file_type().is_symlink() || !trusted_file_metadata(&metadata, executable) {
        return Err(WorkerExecutionError::HostPreflight);
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
    armed: bool,
}

impl StagingGuard {
    fn new(job_dir: PathBuf) -> Self {
        Self {
            job_dir,
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
            let _ = cleanup_jail(&self.job_dir);
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
    cgroup_dir: PathBuf,
    armed: bool,
}

impl JailGuard {
    fn new(job_dir: PathBuf, cgroup_dir: PathBuf) -> Self {
        Self {
            job_dir,
            cgroup_dir,
            armed: true,
        }
    }

    fn cleanup(mut self) -> Result<(), WorkerExecutionError> {
        cleanup_cgroup(&self.cgroup_dir)?;
        cleanup_jail(&self.job_dir)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for JailGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_cgroup(&self.cgroup_dir);
            let _ = cleanup_jail(&self.job_dir);
        }
    }
}

fn cleanup_cgroup(path: &Path) -> Result<(), WorkerExecutionError> {
    if !is_generated_job_path(path) {
        return Err(WorkerExecutionError::Staging);
    }
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WorkerExecutionError::Staging),
    }
}

fn cleanup_jail(path: &Path) -> Result<(), WorkerExecutionError> {
    if !is_generated_job_path(path) {
        return Err(WorkerExecutionError::Staging);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WorkerExecutionError::Staging),
    }
}

fn is_generated_job_path(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
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
            firecracker_binary: root.join("firecracker"),
            jailer_binary: root.join("jailer"),
            kernel_image: root.join("kernel"),
            kernel_sha256: "1".repeat(64),
            rootfs_image: root.join("rootfs"),
            rootfs_sha256: "2".repeat(64),
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
            let value = serde_json::to_value(GuestMachineConfig::new(&config));
            assert!(value.is_ok());
            if let Ok(value) = value {
                assert!(value.get("network-interfaces").is_none());
                assert!(value.get("vsock").is_some());
            }
        }
    }

    #[test]
    fn jailer_plan_enforces_namespaces_cgroups_and_default_seccomp() {
        let temporary = tempfile::tempdir().ok();
        assert!(temporary.is_some());
        if let Some(temporary) = temporary {
            let config = config(temporary.path());
            let args = jailer_args(
                &config,
                "chio-00000000000000000000000000000000",
                config.identities[0],
            );
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
            }
        }
    }

    #[test]
    fn cleanup_path_guard_accepts_only_generated_leaf_names() {
        assert!(is_generated_job_path(Path::new(
            "/srv/jailer/firecracker/chio-00000000000000000000000000000000"
        )));
        for path in [
            "/srv/jailer/firecracker",
            "/srv/jailer/firecracker/chio-../escape",
            "/srv/jailer/firecracker/chio-0000000000000000000000000000000g",
            "/srv/jailer/firecracker/not-chio-00000000000000000000000000000000",
        ] {
            assert!(!is_generated_job_path(Path::new(path)));
        }
    }
}
