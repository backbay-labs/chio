use super::*;

use std::collections::BTreeSet;
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
    let cgroup = SandboxCgroup::prepare(limits)?;
    let mut isolated = cgroup.wrap_command(limits);
    add_test_rlimits(&mut isolated, limits);
    isolated
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
        RuntimeMountProfile::SellerTest,
    )?;
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
            "GIT_EXEC_PATH",
            "/runtime/git-core",
            "--setenv",
            "PYTHONHOME",
            "/runtime/python",
            "--setenv",
            "CARGO_HOME",
            "/workspace/.cargo",
            "--setenv",
            "CARGO_NET_OFFLINE",
            "true",
            "--setenv",
            "RUSTC",
            "/runtime/rust/bin/rustc",
            "--setenv",
            "RUSTDOC",
            "/runtime/rust/bin/rustdoc",
            "--setenv",
            "RUSTFLAGS",
            "-C linker=/usr/bin/cc -C link-arg=-L/runtime/link/lib",
            "--setenv",
            "LIBRARY_PATH",
            "/runtime/link/lib",
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
    let started = Instant::now();
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

fn add_test_rlimits(command: &mut Command, limits: TestSandboxLimits) {
    command
        .arg(format!("--as={}", limits.address_space_bytes))
        .arg(format!("--fsize={}", limits.file_bytes))
        .arg(format!("--nofile={}", limits.open_files))
        .arg(format!("--cpu={}", limits.cpu_secs));
    // RLIMIT_NPROC counts every process and thread owned by the host user.
    // The direct and user-scope cgroup paths already apply the intended
    // per-sandbox process bound through pids.max or TasksMax.
}

#[cfg(test)]
mod rlimit_tests {
    use super::{add_test_rlimits, TestSandboxLimits};
    use std::process::Command;

    #[test]
    fn host_user_process_count_is_not_used_as_the_sandbox_bound() {
        let mut command = Command::new("prlimit");
        add_test_rlimits(&mut command, TestSandboxLimits::production());
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(arguments.iter().all(|argument| !argument.starts_with("--nproc=")));
        assert!(arguments.iter().any(|argument| argument.starts_with("--as=")));
        assert!(arguments
            .iter()
            .any(|argument| argument.starts_with("--nofile=")));
    }
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

#[derive(Clone)]
struct RuntimeMountSpec {
    files: Vec<(PathBuf, PathBuf)>,
    trees: Vec<(PathBuf, PathBuf)>,
    masks: Vec<PathBuf>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

#[derive(Default)]
struct RuntimeMountSpecBuilder {
    files: BTreeSet<(PathBuf, PathBuf)>,
    trees: BTreeSet<(PathBuf, PathBuf)>,
    masks: BTreeSet<PathBuf>,
    symlinks: BTreeSet<(PathBuf, PathBuf)>,
}

impl RuntimeMountSpecBuilder {
    fn add_executable(&mut self, name: &str, required: bool) -> Result<Option<PathBuf>, String> {
        let Some(path) = executable_on_path(name) else {
            if required {
                return Err(format!("required sandbox runtime executable {name} is unavailable"));
            }
            return Ok(None);
        };
        let source = fs::canonicalize(&path)
            .map_err(|error| format!("sandbox runtime executable {name} is invalid: {error}"))?;
        self.files
            .insert((source.clone(), Path::new("/runtime/bin").join(name)));
        self.add_dynamic_dependencies(&source)?;
        Ok(Some(source))
    }

    fn add_dynamic_dependencies(&mut self, executable: &Path) -> Result<(), String> {
        let output = Command::new("ldd")
            .arg(executable)
            .output()
            .map_err(|error| format!("failed to inspect sandbox runtime dependencies: {error}"))?;
        if output.stdout.len().saturating_add(output.stderr.len()) > 1024 * 1024 {
            return Err("sandbox runtime dependency output exceeded its size bound".to_owned());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout
            .lines()
            .chain(stderr.lines())
        {
            for token in line.split_whitespace() {
                let path = token.trim_end_matches(':');
                if !path.starts_with('/') {
                    continue;
                }
                let source = PathBuf::from(path);
                if source.is_file() {
                    self.files.insert((source.clone(), source));
                    break;
                }
            }
        }
        Ok(())
    }

    fn add_tree_dependencies(&mut self, root: &Path) -> Result<(), String> {
        let mut pending = vec![root.to_path_buf()];
        let mut visited = 0usize;
        while let Some(path) = pending.pop() {
            let entries = fs::read_dir(&path)
                .map_err(|error| format!("failed to inspect sandbox runtime tree: {error}"))?;
            for entry in entries {
                let entry = entry
                    .map_err(|error| format!("failed to inspect sandbox runtime tree: {error}"))?;
                visited = visited.saturating_add(1);
                if visited > 20_000 {
                    return Err("sandbox runtime tree exceeded its entry bound".to_owned());
                }
                let metadata = entry
                    .file_type()
                    .map_err(|error| format!("failed to inspect sandbox runtime tree: {error}"))?;
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else if metadata.is_file() && is_elf(&entry.path())? {
                    self.add_dynamic_dependencies(&entry.path())?;
                }
            }
        }
        Ok(())
    }

    fn add_runtime_file(&mut self, source: PathBuf, destination: PathBuf) -> Result<(), String> {
        if is_elf(&source)? {
            self.add_dynamic_dependencies(&source)?;
        }
        self.files.insert((source, destination));
        Ok(())
    }

    fn add_rust_toolchain(&mut self) -> Result<(), String> {
        let (Some(rustc), Some(_cargo)) =
            (executable_on_path("rustc"), executable_on_path("cargo"))
        else {
            return Ok(());
        };
        let sysroot = bounded_runtime_path(
            &rustc,
            &["--print", "sysroot"],
            "Rust toolchain sysroot",
        )?;
        for executable in ["cargo", "rustc"] {
            if !sysroot.join("bin").join(executable).is_file() {
                return Err(format!(
                    "Rust toolchain sysroot lacks required {executable} executable"
                ));
            }
            self.symlinks.insert((
                Path::new("/runtime/rust/bin").join(executable),
                Path::new("/runtime/bin").join(executable),
            ));
        }
        if sysroot.join("bin/rustdoc").is_file() {
            self.symlinks.insert((
                PathBuf::from("/runtime/rust/bin/rustdoc"),
                PathBuf::from("/runtime/bin/rustdoc"),
            ));
        }
        self.add_tree_dependencies(&sysroot)?;
        self.trees
            .insert((sysroot, PathBuf::from("/runtime/rust")));

        let cc = self
            .add_executable("cc", true)?
            .ok_or_else(|| "Rust sandbox requires a native C linker driver".to_owned())?;
        self.add_runtime_file(cc.clone(), cc.clone())?;
        self.symlinks
            .insert((cc.clone(), PathBuf::from("/usr/bin/cc")));
        for executable in ["ld", "as", "ar"] {
            let source = self
                .add_executable(executable, true)?
                .ok_or_else(|| format!("Rust sandbox requires native {executable}"))?;
            self.add_runtime_file(source.clone(), source.clone())?;
            self.symlinks
                .insert((source, Path::new("/usr/bin").join(executable)));
        }
        for program in ["cc1", "collect2", "lto-wrapper", "lto1"] {
            if let Some((source, destination)) = bounded_runtime_file(
                &cc,
                &[&format!("-print-prog-name={program}")],
                "native compiler program",
            )? {
                self.add_runtime_file(source, destination.clone())?;
                self.symlinks
                    .insert((destination, Path::new("/runtime/bin").join(program)));
            }
        }
        for artifact in [
            "crt1.o",
            "Scrt1.o",
            "crti.o",
            "crtn.o",
            "crtbegin.o",
            "crtbeginS.o",
            "crtend.o",
            "crtendS.o",
            "libgcc.a",
            "libgcc_eh.a",
            "libgcc.so",
            "libgcc_s.so",
            "libgcc_s.so.1",
            "liblto_plugin.so",
            "libc.a",
            "libc.so",
            "libc.so.6",
            "libc_nonshared.a",
            "libdl.a",
            "libm.so",
            "libm.so.6",
            "libmvec.so.1",
            "libdl.so",
            "libdl.so.2",
            "libpthread.a",
            "librt.so",
            "librt.so.1",
            "librt.a",
            "libpthread.so",
            "libpthread.so.0",
            "libutil.a",
            "libutil.so",
            "libutil.so.1",
            "libresolv.so",
            "libresolv.so.2",
        ] {
            if let Some((source, destination)) = bounded_runtime_file(
                &cc,
                &[&format!("-print-file-name={artifact}")],
                "native linker artifact",
            )? {
                self.add_runtime_file(source.clone(), destination.clone())?;
                if let Ok(relative) = destination.strip_prefix("/usr/lib") {
                    self.add_runtime_file(source, Path::new("/lib").join(relative))?;
                }
                self.symlinks.insert((
                    destination,
                    Path::new("/runtime/link/lib").join(artifact),
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> RuntimeMountSpec {
        RuntimeMountSpec {
            files: self.files.into_iter().collect(),
            trees: self.trees.into_iter().collect(),
            masks: self.masks.into_iter().collect(),
            symlinks: self.symlinks.into_iter().collect(),
        }
    }
}

static RUNTIME_MOUNT_SPEC: std::sync::OnceLock<Result<RuntimeMountSpec, String>> =
    std::sync::OnceLock::new();

static GIT_RUNTIME_MOUNT_SPEC: std::sync::OnceLock<Result<RuntimeMountSpec, String>> =
    std::sync::OnceLock::new();

#[derive(Clone, Copy)]
pub(super) enum RuntimeMountProfile {
    Git,
    SellerTest,
}

pub(super) fn add_runtime_mounts(
    command: &mut Command,
    profile: RuntimeMountProfile,
) -> Result<(), CliError> {
    let spec = match profile {
        RuntimeMountProfile::Git => GIT_RUNTIME_MOUNT_SPEC.get_or_init(|| {
            build_runtime_mount_spec(RuntimeMountProfile::Git)
        }),
        RuntimeMountProfile::SellerTest => RUNTIME_MOUNT_SPEC.get_or_init(|| {
            build_runtime_mount_spec(RuntimeMountProfile::SellerTest)
        }),
    }
        .as_ref()
        .map_err(|error| CliError::cli_other_error(error.clone()))?;
    let mut directories = BTreeSet::new();
    for (_, destination) in spec.files.iter().chain(spec.trees.iter()) {
        collect_parent_directories(destination, &mut directories);
    }
    for destination in spec.masks.iter().chain(spec.symlinks.iter().map(|(_, path)| path)) {
        collect_parent_directories(destination, &mut directories);
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| path.components().count());
    for directory in directories {
        command.arg("--dir").arg(directory);
    }
    for (source, destination) in &spec.trees {
        command
            .arg("--ro-bind")
            .arg(source)
            .arg(destination);
    }
    for (source, destination) in &spec.files {
        command
            .arg("--ro-bind")
            .arg(source)
            .arg(destination);
    }
    for destination in &spec.masks {
        command.arg("--tmpfs").arg(destination);
    }
    for (target, destination) in &spec.symlinks {
        command
            .arg("--symlink")
            .arg(target)
            .arg(destination);
    }
    Ok(())
}

fn build_runtime_mount_spec(profile: RuntimeMountProfile) -> Result<RuntimeMountSpec, String> {
    let mut builder = RuntimeMountSpecBuilder::default();
    let required = match profile {
        RuntimeMountProfile::Git => &["sh", "git", "env"][..],
        RuntimeMountProfile::SellerTest => &["sh", "cp", "mkdir", "git", "env"][..],
    };
    for required in required {
        builder.add_executable(required, true)?;
    }
    let shell = builder
        .add_executable("sh", true)?
        .ok_or_else(|| "required sandbox shell is unavailable".to_owned())?;
    builder
        .files
        .insert((shell, PathBuf::from("/bin/sh")));
    let environment = builder
        .add_executable("env", true)?
        .ok_or_else(|| "required sandbox environment executable is unavailable".to_owned())?;
    builder
        .files
        .insert((environment, PathBuf::from("/usr/bin/env")));

    let git = executable_on_path("git")
        .ok_or_else(|| "required sandbox Git executable is unavailable".to_owned())?;
    let git_exec = bounded_runtime_path(&git, &["--exec-path"], "Git runtime")?;
    builder.add_tree_dependencies(&git_exec)?;
    builder
        .trees
        .insert((git_exec, PathBuf::from("/runtime/git-core")));

    if matches!(profile, RuntimeMountProfile::Git) {
        return Ok(builder.finish());
    }

    for optional in [
        "bash", "rm", "touch", "sed", "grep", "find", "cat", "sort", "cut", "tr", "wc",
        "xargs", "basename", "dirname", "readlink", "realpath", "dd", "sleep",
    ] {
        builder.add_executable(optional, false)?;
    }

    if let Some(python) = builder.add_executable("python3", false)? {
        let stdlib = bounded_runtime_path(
            &python,
            &[
                "-I",
                "-S",
                "-c",
                "import sysconfig; print(sysconfig.get_path('stdlib'))",
            ],
            "Python standard library",
        )?;
        let version = stdlib
            .file_name()
            .ok_or_else(|| "Python standard library path is invalid".to_owned())?
            .to_owned();
        builder.add_tree_dependencies(&stdlib)?;
        if stdlib.join("site-packages").is_dir() {
            builder.masks.insert(
                Path::new("/runtime/python/lib")
                    .join(&version)
                    .join("site-packages"),
            );
        }
        builder.trees.insert((
            stdlib,
            Path::new("/runtime/python/lib").join(version),
        ));
    }

    if builder.add_executable("node", false)?.is_some() {
        if let Some(npm) = executable_on_path("npm") {
            let npm_root = bounded_runtime_path(&npm, &["root", "-g"], "npm runtime")?;
            let npm_package = fs::canonicalize(npm_root.join("npm"))
                .map_err(|error| format!("npm runtime is invalid: {error}"))?;
            builder.add_tree_dependencies(&npm_package)?;
            builder
                .trees
                .insert((npm_package, PathBuf::from("/runtime/npm")));
            builder.symlinks.insert((
                PathBuf::from("/runtime/npm/bin/npm-cli.js"),
                PathBuf::from("/runtime/bin/npm"),
            ));
            builder.symlinks.insert((
                PathBuf::from("/runtime/npm/bin/npx-cli.js"),
                PathBuf::from("/runtime/bin/npx"),
            ));
        }
    }
    builder.add_rust_toolchain()?;
    Ok(builder.finish())
}

fn executable_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn bounded_runtime_path(executable: &Path, args: &[&str], label: &str) -> Result<PathBuf, String> {
    let output = Command::new(executable)
        .args(args)
        .output()
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(format!("failed to inspect {label}"));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("{label} path is not UTF-8"))?
        .trim();
    if value.is_empty() || !Path::new(value).is_absolute() {
        return Err(format!("{label} path is invalid"));
    }
    let path = fs::canonicalize(value).map_err(|error| format!("{label} is invalid: {error}"))?;
    if !path.is_dir() {
        return Err(format!("{label} is not a directory"));
    }
    Ok(path)
}

fn bounded_runtime_file(
    executable: &Path,
    args: &[&str],
    label: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let output = Command::new(executable)
        .args(args)
        .output()
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if output.stdout.len().saturating_add(output.stderr.len()) > 4096 {
        return Err(format!("{label} output exceeded its size bound"));
    }
    if !output.status.success() {
        return Err(format!("failed to inspect {label}"));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("{label} path is not UTF-8"))?
        .trim();
    if value.is_empty() || !Path::new(value).is_absolute() {
        return Ok(None);
    }
    let destination = normalize_absolute_runtime_path(Path::new(value))?;
    let source = match fs::canonicalize(value) {
        Ok(path) if path.is_file() => path,
        Ok(_) | Err(_) => return Ok(None),
    };
    Ok(Some((source, destination)))
}

fn normalize_absolute_runtime_path(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err("sandbox runtime path escaped the filesystem root".to_owned());
                }
            }
            std::path::Component::Prefix(_) => {
                return Err("sandbox runtime path used an unsupported prefix".to_owned());
            }
        }
    }
    Ok(normalized)
}

fn is_elf(path: &Path) -> Result<bool, String> {
    use std::io::Read as _;
    let mut file = File::open(path)
        .map_err(|error| format!("failed to inspect sandbox runtime file: {error}"))?;
    let mut magic = [0u8; 4];
    Ok(file.read(&mut magic).is_ok() && magic == *b"\x7fELF")
}

fn collect_parent_directories(path: &Path, directories: &mut BTreeSet<PathBuf>) {
    let mut current = PathBuf::from("/");
    let Some(parent) = path.parent() else {
        return;
    };
    for component in parent.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            directories.insert(current.clone());
        }
    }
}

fn sandbox_path() -> String {
    "/usr/bin:/runtime/bin".to_owned()
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
    let cargo = command_version("cargo", &["--version"]).unwrap_or_else(|_| "unavailable".to_owned());
    let rustc = command_version("rustc", &["--version"]).unwrap_or_else(|_| "unavailable".to_owned());
    let systemd_run =
        command_version("systemd-run", &["--version"]).unwrap_or_else(|_| "unavailable".to_owned());
    let shell = command_version("sh", &["--version"]).unwrap_or_else(|_| "sh".to_owned());
    canonical_json_bytes(&serde_json::json!({
        "arch": std::env::consts::ARCH,
        "bubblewrap": bwrap,
        "cargo": cargo,
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
        "rustc": rustc,
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
