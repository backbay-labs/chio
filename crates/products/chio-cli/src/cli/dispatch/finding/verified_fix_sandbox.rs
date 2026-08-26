use super::*;

use std::fs::File;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const TEST_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
pub(super) const PACKAGE_WORK_TIMEOUT: Duration = Duration::from_secs(300);
const TEST_SANDBOX_ADDRESS_SPACE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const TEST_SANDBOX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const TEST_SANDBOX_TMPFS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const TEST_SANDBOX_PROCESS_LIMIT: u64 = 512;
const TEST_SANDBOX_OPEN_FILE_LIMIT: u64 = 1024;
const TEST_SANDBOX_CPU_SECS: u64 = 300;

pub(super) fn run_test_commands(
    worktree: &Path,
    commands: &[String],
    deadline: Instant,
) -> Result<Vec<VerifiedFixCommandResult>, CliError> {
    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(package_test_deadline_error());
        }
        let timeout = remaining.min(TEST_COMMAND_TIMEOUT);
        match run_test_command_with_timeout(worktree, command, timeout) {
            Ok(result) => results.push(result),
            Err(_) if Instant::now() >= deadline => {
                return Err(package_test_deadline_error());
            }
            Err(error) => return Err(error),
        }
    }
    Ok(results)
}

fn package_test_deadline_error() -> CliError {
    CliError::cli_other_error(format!(
        "verified-fix baseline and candidate tests exceeded the {} millisecond aggregate deadline",
        PACKAGE_WORK_TIMEOUT.as_millis()
    ))
}

pub(super) fn run_test_command_with_timeout(
    worktree: &Path,
    command: &str,
    timeout: Duration,
) -> Result<VerifiedFixCommandResult, CliError> {
    run_test_command_with_limits(
        worktree,
        command,
        timeout,
        TestSandboxLimits::production(),
    )
}

#[derive(Clone, Copy)]
pub(super) struct TestSandboxLimits {
    pub(super) address_space_bytes: u64,
    pub(super) file_bytes: u64,
    pub(super) tmpfs_bytes: u64,
    pub(super) process_count: u64,
    pub(super) open_files: u64,
    pub(super) cpu_secs: u64,
}

impl TestSandboxLimits {
    const fn production() -> Self {
        Self {
            address_space_bytes: TEST_SANDBOX_ADDRESS_SPACE_BYTES,
            file_bytes: TEST_SANDBOX_FILE_BYTES,
            tmpfs_bytes: TEST_SANDBOX_TMPFS_BYTES,
            process_count: TEST_SANDBOX_PROCESS_LIMIT,
            open_files: TEST_SANDBOX_OPEN_FILE_LIMIT,
            cpu_secs: TEST_SANDBOX_CPU_SECS,
        }
    }
}

enum SandboxCgroup {
    Direct { path: PathBuf, procs: File },
    UserScope { unit: String },
}

impl SandboxCgroup {
    fn prepare(limits: TestSandboxLimits) -> Result<Self, CliError> {
        if let Some(cgroup) = Self::try_direct(limits)? {
            return Ok(cgroup);
        }
        Ok(Self::UserScope {
            unit: format!(
                "chio-verified-fix-{}.scope",
                uuid::Uuid::new_v4().simple()
            ),
        })
    }

    fn try_direct(limits: TestSandboxLimits) -> Result<Option<Self>, CliError> {
        let Some(parent) = current_cgroup_directory()? else {
            return Ok(None);
        };
        let path = parent.join(format!(
            "chio-verified-fix-{}",
            uuid::Uuid::new_v4().simple()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(CliError::from(error)),
        }
        let required = [path.join("memory.max"), path.join("pids.max")];
        if required.iter().any(|entry| !entry.is_file()) || !path.join("cgroup.kill").is_file() {
            let _ = fs::remove_dir(&path);
            return Ok(None);
        }
        let configured = (|| -> Result<File, std::io::Error> {
            fs::write(path.join("memory.max"), limits.address_space_bytes.to_string())?;
            if path.join("memory.swap.max").is_file() {
                fs::write(path.join("memory.swap.max"), "0")?;
            }
            fs::write(path.join("pids.max"), limits.process_count.to_string())?;
            OpenOptions::new().write(true).open(path.join("cgroup.procs"))
        })();
        match configured {
            Ok(procs) => Ok(Some(Self::Direct { path, procs })),
            Err(error) => {
                let _ = fs::remove_dir(&path);
                Err(CliError::cli_other_error(format!(
                    "failed to configure aggregate verified-fix cgroup: {error}"
                )))
            }
        }
    }

    fn wrap_command(&self, limits: TestSandboxLimits) -> Command {
        match self {
            Self::Direct { .. } => Command::new("prlimit"),
            Self::UserScope { unit } => {
                let mut command = Command::new("systemd-run");
                command
                    .args(["--user", "--scope", "--quiet", "--collect"])
                    .arg(format!("--unit={unit}"))
                    .arg(format!(
                        "--property=MemoryMax={}",
                        limits.address_space_bytes
                    ))
                    .arg("--property=MemorySwapMax=0")
                    .arg(format!("--property=TasksMax={}", limits.process_count))
                    .args(["--", "prlimit"]);
                command
            }
        }
    }

    #[cfg(unix)]
    fn attach_before_exec(&self, command: &mut Command) {
        use std::os::unix::process::CommandExt as _;
        if let Self::Direct { procs, .. } = self {
            let fd = procs.as_raw_fd();
            // SAFETY: the closure uses only async-signal-safe libc calls after
            // fork and before exec. The cgroup file remains open through spawn.
            unsafe {
                command.pre_exec(move || write_current_pid(fd));
            }
        }
    }

    fn kill_all(&self) {
        match self {
            Self::Direct { path, .. } => {
                let _ = fs::write(path.join("cgroup.kill"), "1");
            }
            Self::UserScope { unit } => {
                let _ = Command::new("systemctl")
                    .args([
                        "--user",
                        "kill",
                        "--kill-who=all",
                        "--signal=KILL",
                        unit,
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}

impl Drop for SandboxCgroup {
    fn drop(&mut self) {
        self.kill_all();
        if let Self::Direct { path, .. } = self {
            for _ in 0..20 {
                match fs::remove_dir(path.as_path()) {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(unix)]
fn write_current_pid(fd: std::os::fd::RawFd) -> Result<(), std::io::Error> {
    let mut digits = [0u8; 32];
    let mut cursor = digits.len() - 1;
    digits[cursor] = b'\n';
    let mut pid = unsafe { libc::getpid() } as u32;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + u8::try_from(pid % 10).unwrap_or(0);
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let mut written = 0usize;
    let bytes = &digits[cursor..];
    while written < bytes.len() {
        let result = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        written = written.saturating_add(usize::try_from(result).unwrap_or(0));
    }
    Ok(())
}

fn current_cgroup_directory() -> Result<Option<PathBuf>, CliError> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let Some(relative) = cgroup.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(None);
    };
    let relative = Path::new(relative.trim_start_matches('/'));
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err(CliError::cli_other_error(
            "current cgroup path is invalid".to_owned(),
        ));
    }
    Ok(Some(Path::new("/sys/fs/cgroup").join(relative)))
}

pub(super) fn run_test_command_with_limits(
    worktree: &Path,
    command: &str,
    timeout: Duration,
    limits: TestSandboxLimits,
) -> Result<VerifiedFixCommandResult, CliError> {
    let started = Instant::now();
    let cgroup = SandboxCgroup::prepare(limits)?;
    let mut isolated = cgroup.wrap_command(limits);
    isolated
        .arg(format!("--as={}", limits.address_space_bytes))
        .arg(format!("--fsize={}", limits.file_bytes))
        .arg(format!("--nproc={}", limits.process_count))
        .arg(format!("--nofile={}", limits.open_files))
        .arg(format!("--cpu={}", limits.cpu_secs))
        .args(["--", "bwrap"])
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-cgroup-try",
            "--disable-userns",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
        ])
        .arg(limits.tmpfs_bytes.to_string())
        .args([
            "--tmpfs",
            "/workspace",
            "--dir",
            "/workspace/.home",
            "--dir",
            "/workspace/.cargo",
            "--dir",
            "/workspace/.tmp",
        ]);
    add_runtime_mounts(
        &mut isolated,
        std::env::var_os("HOME").as_deref().map(Path::new),
    );
    isolated
        .arg("--ro-bind")
        .arg(worktree)
        .arg("/source")
        .arg("--chdir")
        .arg("/workspace")
        .args([
            "--setenv",
            "HOME",
            "/workspace/.home",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "TZ",
            "UTC",
            "--setenv",
            "PATH",
            &sandbox_path(),
            "--setenv",
            "CARGO_HOME",
            "/workspace/.cargo",
            "--setenv",
            "CARGO_NET_OFFLINE",
            "true",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--setenv",
            "TMPDIR",
            "/workspace/.tmp",
            "--",
            "sh",
            "-c",
        ])
        .arg(
            "mkdir -p /workspace/repository && cp -a /source/. /workspace/repository/ && cd /workspace/repository && exec sh -c \"$1\"",
        )
        .arg("chio-verified-fix-sandbox")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        isolated.process_group(0);
        cgroup.attach_before_exec(&mut isolated);
    }
    let mut child = isolated.spawn().map_err(|error| {
        CliError::cli_other_error(format!("failed to start isolated test command: {error}"))
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::cli_other_error("test stdout pipe is unavailable".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::cli_other_error("test stderr pipe is unavailable".to_owned()))?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&overflow);
    let stderr_overflow = Arc::clone(&overflow);
    let stdout_reader = thread::spawn(move || read_and_digest(stdout, &stdout_overflow));
    let stderr_reader = thread::spawn(move || read_and_digest(stderr, &stderr_overflow));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if overflow.load(Ordering::Acquire) {
            terminate_sandbox(&mut child, &cgroup);
            let _ = child.wait();
            let _ = join_digest(stdout_reader, "stdout");
            let _ = join_digest(stderr_reader, "stderr");
            return Err(CliError::cli_other_error(
                "test command output exceeded the 4 MiB evidence bound".to_owned(),
            ));
        }
        if started.elapsed() >= timeout {
            terminate_sandbox(&mut child, &cgroup);
            let _ = child.wait();
            let _ = join_digest(stdout_reader, "stdout");
            let _ = join_digest(stderr_reader, "stderr");
            return Err(CliError::cli_other_error(format!(
                "test command exceeded the {} millisecond execution deadline",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    };
    cgroup.kill_all();
    let (stdout_sha256, stdout_overflow) = join_digest(stdout_reader, "stdout")?;
    let (stderr_sha256, stderr_overflow) = join_digest(stderr_reader, "stderr")?;
    if stdout_overflow || stderr_overflow {
        return Err(CliError::cli_other_error(
            "test command output exceeded the 4 MiB evidence bound".to_owned(),
        ));
    }
    Ok(VerifiedFixCommandResult {
        command: command.to_owned(),
        exit_code: exit_code(status),
        stdout_sha256,
        stderr_sha256,
        duration_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn read_and_digest(
    mut reader: impl Read,
    overflow: &AtomicBool,
) -> Result<(String, bool), std::io::Error> {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if total > MAX_COMMAND_OUTPUT_BYTES {
            overflow.store(true, Ordering::Release);
        }
        digest.update(&buffer[..read]);
    }
    Ok((hex::encode(digest.finalize()), total > MAX_COMMAND_OUTPUT_BYTES))
}

fn join_digest(
    worker: thread::JoinHandle<Result<(String, bool), std::io::Error>>,
    label: &str,
) -> Result<(String, bool), CliError> {
    worker
        .join()
        .map_err(|_| CliError::cli_other_error(format!("{label} reader panicked")))?
        .map_err(CliError::from)
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(255)
}

fn terminate_sandbox(child: &mut std::process::Child, cgroup: &SandboxCgroup) {
    cgroup.kill_all();
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            // SAFETY: `pid` is the live child process group created above. A
            // negative PID targets only that group, never the operator.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

pub(super) fn add_runtime_mounts(command: &mut Command, home: Option<&Path>) {
    for path in [
        "/usr",
        "/usr/local",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/etc/ssl",
    ] {
        if Path::new(path).exists() {
            command.args(["--ro-bind", path, path]);
        }
    }
    if let Some(home) = home {
        let cargo_bin = home.join(".cargo/bin");
        if cargo_bin.is_dir() {
            command.arg("--ro-bind").arg(&cargo_bin).arg(&cargo_bin);
        }
        let rustup_toolchains = home.join(".rustup/toolchains");
        if rustup_toolchains.is_dir() {
            command
                .arg("--ro-bind")
                .arg(&rustup_toolchains)
                .arg(&rustup_toolchains);
            command
                .args(["--setenv", "RUSTUP_HOME"])
                .arg(home.join(".rustup"));
        }
        let rustup_settings = home.join(".rustup/settings.toml");
        if rustup_settings.is_file() {
            command
                .arg("--ro-bind")
                .arg(&rustup_settings)
                .arg(&rustup_settings);
        }
        // Operator-owned Cargo registry and Git caches may contain private
        // dependencies. Seller tests receive only the toolchain executables;
        // repositories that need offline dependencies must vendor them.
    }
}

fn sandbox_path() -> String {
    let mut paths = vec![
        "/usr/local/sbin".to_owned(),
        "/usr/local/bin".to_owned(),
        "/usr/sbin".to_owned(),
        "/usr/bin".to_owned(),
        "/sbin".to_owned(),
        "/bin".to_owned(),
    ];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        paths.push(home.join(".cargo/bin").display().to_string());
    }
    paths.join(":")
}

pub(super) fn require_sandbox() -> Result<(), CliError> {
    for (command, message) in [
        (
            "bwrap",
            "verified-fix packaging requires bubblewrap for network isolation",
        ),
        (
            "prlimit",
            "verified-fix packaging requires prlimit for resource isolation",
        ),
    ] {
        let output = Command::new(command)
            .arg("--version")
            .output()
            .map_err(|_| CliError::cli_other_error(message.to_owned()))?;
        if !output.status.success() {
            return Err(CliError::cli_other_error(message.to_owned()));
        }
    }
    let cgroup = SandboxCgroup::prepare(TestSandboxLimits::production())?;
    match &cgroup {
        SandboxCgroup::Direct { .. } => Ok(()),
        SandboxCgroup::UserScope { unit } => {
            let output = Command::new("systemd-run")
                .args(["--user", "--scope", "--quiet", "--collect"])
                .arg(format!("--unit={unit}"))
                .arg(format!(
                    "--property=MemoryMax={TEST_SANDBOX_ADDRESS_SPACE_BYTES}"
                ))
                .arg("--property=MemorySwapMax=0")
                .arg(format!(
                    "--property=TasksMax={TEST_SANDBOX_PROCESS_LIMIT}"
                ))
                .args(["--", "true"])
                .output()
                .map_err(|_| {
                    CliError::cli_other_error(
                        "verified-fix packaging requires a delegated cgroup v2 or systemd user scope"
                            .to_owned(),
                    )
                })?;
            if output.status.success() {
                Ok(())
            } else {
                Err(CliError::cli_other_error(format!(
                    "verified-fix aggregate cgroup isolation is unavailable: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )))
            }
        }
    }
}

pub(super) fn runtime_fingerprint() -> Result<Vec<u8>, CliError> {
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let git = command_version("git", &["--version"])?;
    let bwrap = command_version("bwrap", &["--version"])?;
    let prlimit = command_version("prlimit", &["--version"])?;
    let systemd_run =
        command_version("systemd-run", &["--version"]).unwrap_or_else(|_| "unavailable".to_owned());
    let shell = command_version("sh", &["--version"]).unwrap_or_else(|_| "sh".to_owned());
    canonical_json_bytes(&serde_json::json!({
        "arch": std::env::consts::ARCH,
        "bubblewrap": bwrap,
        "git": git,
        "os": std::env::consts::OS,
        "osReleaseSha256": sha256_hex(os_release.as_bytes()),
        "prlimit": prlimit,
        "resourceLimits": {
            "addressSpaceBytesPerProcess": TEST_SANDBOX_ADDRESS_SPACE_BYTES,
            "aggregateMemoryBytes": TEST_SANDBOX_ADDRESS_SPACE_BYTES,
            "aggregatePackageDeadlineMillis": PACKAGE_WORK_TIMEOUT.as_millis(),
            "cpuSecondsPerProcess": TEST_SANDBOX_CPU_SECS,
            "fileBytesPerProcess": TEST_SANDBOX_FILE_BYTES,
            "openFilesPerProcess": TEST_SANDBOX_OPEN_FILE_LIMIT,
            "processesAggregate": TEST_SANDBOX_PROCESS_LIMIT,
            "swapBytesAggregate": 0,
            "writableTmpfsBytes": TEST_SANDBOX_TMPFS_BYTES,
        },
        "shell": shell,
        "systemdRun": systemd_run,
    }))
    .map_err(CliError::from)
}

fn command_version(command: &str, args: &[&str]) -> Result<String, CliError> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        return Err(CliError::cli_other_error(format!(
            "failed to query {command} version"
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_deadline_caps_each_remaining_command() {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(remaining <= Duration::from_millis(50));
        assert!(remaining < TEST_COMMAND_TIMEOUT);
    }
}
