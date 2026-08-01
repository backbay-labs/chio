use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    generate_markdown_report, load_results_from_dir, load_scenarios_from_dir, CompatibilityReport,
};

const SERVER_STARTUP_ATTEMPTS: usize = 900;
const SERVER_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTarget {
    Js,
    Python,
    Go,
    Cpp,
}

impl PeerTarget {
    pub fn label(self) -> &'static str {
        match self {
            Self::Js => "js",
            Self::Python => "python",
            Self::Go => "go",
            Self::Cpp => "cpp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceAuthMode {
    StaticBearer,
    LocalOAuth,
}

#[derive(Debug, Clone)]
pub struct ConformanceRunOptions {
    pub repo_root: PathBuf,
    pub scenarios_dir: PathBuf,
    pub results_dir: PathBuf,
    pub report_output: PathBuf,
    pub policy_path: PathBuf,
    pub upstream_server_script: PathBuf,
    pub auth_mode: ConformanceAuthMode,
    pub auth_token: String,
    pub admin_token: String,
    pub auth_scope: String,
    pub listen: Option<SocketAddr>,
    pub peers: Vec<PeerTarget>,
    pub node_binary: OsString,
    pub python_binary: OsString,
    pub go_binary: OsString,
    pub cargo_binary: OsString,
    pub peer_binaries: Vec<(PeerTarget, PathBuf)>,
}

#[derive(Debug, Clone)]
pub struct ConformanceRunSummary {
    pub listen: SocketAddr,
    pub results_dir: PathBuf,
    pub report_output: PathBuf,
    pub peer_result_files: Vec<PathBuf>,
}

struct ConformanceRuntimeState {
    // Keep durable runtime state out of publishable artifacts and retain it
    // until the child server has been stopped.
    _directory: tempfile::TempDir,
    auth_server_seed_path: PathBuf,
    session_db_path: PathBuf,
}

impl ConformanceRuntimeState {
    fn create() -> Result<Self, std::io::Error> {
        let mut builder = tempfile::Builder::new();
        builder.prefix("chio-conformance-runtime-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let auth_server_seed_path = directory.path().join("auth-server.seed");
        let session_db_path = directory.path().join("mcp-session.sqlite3");
        Ok(Self {
            _directory: directory,
            auth_server_seed_path,
            session_db_path,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to spawn process `{command}`: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("process `{command}` exited unsuccessfully with status {status}; see {log_path}")]
    ProcessFailed {
        command: String,
        status: i32,
        log_path: String,
    },

    #[error("timeout while waiting for MCP edge on {listen}")]
    ServerStartupTimeout { listen: SocketAddr },

    #[error("failed to load generated artifacts: {0}")]
    Load(#[from] crate::load::LoadError),

    #[error("peer result generation produced no JSON files in {path}")]
    NoResults { path: String },
}

fn conformance_fixture_root_from_manifest_dir(manifest_dir: &Path) -> PathBuf {
    let workspace_root = manifest_dir
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.to_path_buf());
    if workspace_root
        .join("tests/conformance/scenarios/mcp_core")
        .is_dir()
        && workspace_root
            .join("tests/conformance/fixtures/mcp_core/policy.yaml")
            .is_file()
    {
        return workspace_root;
    }

    manifest_dir.to_path_buf()
}

pub fn default_repo_root() -> PathBuf {
    conformance_fixture_root_from_manifest_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
}

/// Read a conformance harness token from `var`, or return a local-only default.
///
/// When the env var is unset, the fallback uses the `dev-only-conformance-*`
/// prefix plus a short random suffix. Set `CHIO_CONFORMANCE_AUTH_TOKEN` and
/// `CHIO_CONFORMANCE_ADMIN_TOKEN` for CI or shared environments.
fn conformance_token_from_env(var: &str, role: &str) -> String {
    if let Ok(value) = env::var(var) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("dev-only-conformance-{role}-{nonce}")
}

/// Pass conformance tokens through child env vars so shared CI runners do not
/// expose secrets via `/proc/<pid>/cmdline`.
fn apply_conformance_auth_env(
    command: &mut Command,
    options: &ConformanceRunOptions,
    auth_mode: ConformanceAuthMode,
) {
    command
        .env("CHIO_CONFORMANCE_AUTH_TOKEN", &options.auth_token)
        .env("CHIO_CONFORMANCE_ADMIN_TOKEN", &options.admin_token);
    match auth_mode {
        ConformanceAuthMode::StaticBearer => {
            command.env("CHIO_AUTH_TOKEN", &options.auth_token);
        }
        ConformanceAuthMode::LocalOAuth => {
            command
                .env_remove("CHIO_AUTH_TOKEN")
                .env_remove("CHIO_MCP_AUTH_TOKEN")
                .env_remove("CHIO_MCP_ADMIN_TOKEN");
            command.env("CHIO_ADMIN_TOKEN", &options.admin_token);
        }
    }
}

pub fn default_run_options() -> ConformanceRunOptions {
    let repo_root = default_repo_root();
    ConformanceRunOptions {
        scenarios_dir: repo_root.join("tests/conformance/scenarios/mcp_core"),
        results_dir: repo_root.join("tests/conformance/results/generated/mcp-core-live"),
        report_output: repo_root.join("tests/conformance/reports/generated/mcp-core-live.md"),
        policy_path: repo_root.join("tests/conformance/fixtures/mcp_core/policy.yaml"),
        upstream_server_script: repo_root
            .join("tests/conformance/fixtures/mcp_core/mock_mcp_server.py"),
        auth_mode: ConformanceAuthMode::StaticBearer,
        auth_token: conformance_token_from_env("CHIO_CONFORMANCE_AUTH_TOKEN", "auth"),
        admin_token: conformance_token_from_env("CHIO_CONFORMANCE_ADMIN_TOKEN", "admin"),
        auth_scope: "mcp:invoke".to_string(),
        listen: None,
        peers: vec![PeerTarget::Js, PeerTarget::Python],
        node_binary: OsString::from("node"),
        python_binary: OsString::from("python3"),
        go_binary: OsString::from("go"),
        cargo_binary: OsString::from("cargo"),
        peer_binaries: Vec::new(),
        repo_root,
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

pub fn run_conformance_harness(
    options: &ConformanceRunOptions,
) -> Result<ConformanceRunSummary, RunnerError> {
    if options.results_dir.exists() {
        fs::remove_dir_all(&options.results_dir)?;
    }
    fs::create_dir_all(&options.results_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&options.results_dir, fs::Permissions::from_mode(0o700))?;
    }
    if let Some(parent) = options.report_output.parent() {
        fs::create_dir_all(parent)?;
    }

    let artifacts_dir = options.results_dir.join("artifacts");
    create_private_directory(&artifacts_dir)?;
    let logs_dir = artifacts_dir.join("logs");
    fs::create_dir_all(&logs_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&artifacts_dir, fs::Permissions::from_mode(0o700))?;
    }

    let listen = match options.listen {
        Some(listen) => listen,
        None => reserve_listen_addr()?,
    };
    let chio_executable = ensure_chio_executable(&options.repo_root, &options.cargo_binary)?;
    let runtime_state = ConformanceRuntimeState::create()?;
    let server_log_path = logs_dir.join("chio-mcp-serve-http.log");
    let server = spawn_remote_edge(
        &chio_executable,
        options,
        listen,
        &runtime_state,
        &server_log_path,
    )?;
    let mut server_guard = ChildGuard { child: server };
    wait_for_server(listen, &mut server_guard.child, &server_log_path)?;

    let mut peer_result_files = Vec::new();
    for peer in &options.peers {
        let peer_results_path = options
            .results_dir
            .join(format!("{}-remote-http.json", peer.label()));
        let peer_artifacts_dir = artifacts_dir.join(peer.label());
        let peer_log_path = logs_dir.join(format!("{}-peer.log", peer.label()));
        fs::create_dir_all(&peer_artifacts_dir)?;
        run_peer(
            *peer,
            options,
            listen,
            &peer_results_path,
            &peer_artifacts_dir,
            &peer_log_path,
        )?;
        peer_result_files.push(peer_results_path);
    }

    let results = load_results_from_dir(&options.results_dir)?;
    if results.is_empty() {
        return Err(RunnerError::NoResults {
            path: options.results_dir.display().to_string(),
        });
    }
    let report = CompatibilityReport {
        scenarios: load_scenarios_from_dir(&options.scenarios_dir)?,
        results,
    };
    fs::write(&options.report_output, generate_markdown_report(&report))?;

    Ok(ConformanceRunSummary {
        listen,
        results_dir: options.results_dir.clone(),
        report_output: options.report_output.clone(),
        peer_result_files,
    })
}

fn ensure_chio_executable(
    repo_root: &Path,
    cargo_binary: &OsString,
) -> Result<PathBuf, RunnerError> {
    let candidates = chio_executable_candidates(repo_root);
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    let status = Command::new(cargo_binary)
        .current_dir(repo_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("chio-cli")
        .status()
        .map_err(|source| RunnerError::Spawn {
            command: "cargo build -q -p chio-cli".to_string(),
            source,
        })?;
    if !status.success() {
        return Err(RunnerError::ProcessFailed {
            command: "cargo build -q -p chio-cli".to_string(),
            status: status.code().unwrap_or(1),
            log_path: "<stderr>".to_string(),
        });
    }
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    let checked = candidates
        .iter()
        .map(|candidate| candidate.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(RunnerError::ProcessFailed {
        command: "cargo build -q -p chio-cli".to_string(),
        status: 1,
        log_path: format!("<stderr>; checked {checked}"),
    })
}

fn chio_binary_name() -> &'static str {
    if cfg!(windows) {
        "chio.exe"
    } else {
        "chio"
    }
}

fn chio_executable_candidates(repo_root: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = env::current_exe() {
        if current_exe.file_name().and_then(|name| name.to_str()) == Some(chio_binary_name()) {
            push_chio_candidate(&mut candidates, current_exe);
        }
    }
    if let Some(target_dir) = env::var_os("CARGO_TARGET_DIR") {
        push_chio_candidate(
            &mut candidates,
            PathBuf::from(target_dir)
                .join("debug")
                .join(chio_binary_name()),
        );
    }
    push_chio_candidate(
        &mut candidates,
        repo_root
            .join("target")
            .join("debug")
            .join(chio_binary_name()),
    );
    candidates
}

fn push_chio_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

fn spawn_remote_edge(
    chio_executable: &Path,
    options: &ConformanceRunOptions,
    listen: SocketAddr,
    runtime_state: &ConformanceRuntimeState,
    log_path: &Path,
) -> Result<Child, RunnerError> {
    let log = fs::File::create(log_path)?;
    let log_clone = log.try_clone()?;
    let mut command = Command::new(chio_executable);
    command
        .current_dir(&options.repo_root)
        .arg("mcp")
        .arg("serve-http")
        .arg("--policy")
        .arg(&options.policy_path)
        .arg("--server-id")
        .arg("conformance-mcp-core")
        .arg("--server-name")
        .arg("Conformance Fixture")
        .arg("--server-version")
        .arg("0.1.0")
        .arg("--listen")
        .arg(listen.to_string());

    let public_base_url = format!("http://{listen}");
    command
        .arg("--session-db")
        .arg(&runtime_state.session_db_path);
    let mut command_description = format!(
        "{} mcp serve-http --policy {} --server-id conformance-mcp-core --listen {} --session-db {}",
        chio_executable.display(),
        options.policy_path.display(),
        listen,
        runtime_state.session_db_path.display()
    );

    apply_conformance_auth_env(&mut command, options, options.auth_mode);

    match options.auth_mode {
        ConformanceAuthMode::StaticBearer => {
            command_description.push_str(" (auth via CHIO_AUTH_TOKEN env)");
        }
        ConformanceAuthMode::LocalOAuth => {
            command
                .arg("--public-base-url")
                .arg(&public_base_url)
                .arg("--auth-server-seed-file")
                .arg(&runtime_state.auth_server_seed_path)
                .arg("--auth-jwt-audience")
                .arg(format!("{public_base_url}/mcp"))
                .arg("--auth-scope")
                .arg(&options.auth_scope);
            command_description.push_str(&format!(
                " --public-base-url {} --auth-server-seed-file {} --auth-jwt-audience {}/mcp --auth-scope {} (admin via CHIO_ADMIN_TOKEN env)",
                public_base_url,
                runtime_state.auth_server_seed_path.display(),
                public_base_url,
                options.auth_scope
            ));
        }
    }

    command
        .arg("--")
        .arg(&options.python_binary)
        .arg(&options.upstream_server_script)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_clone))
        .spawn()
        .map_err(|source| RunnerError::Spawn {
            command: format!(
                "{} -- {} {}",
                command_description,
                PathBuf::from(&options.python_binary).display(),
                options.upstream_server_script.display()
            ),
            source,
        })
}

fn run_peer(
    peer: PeerTarget,
    options: &ConformanceRunOptions,
    listen: SocketAddr,
    results_output: &Path,
    artifacts_dir: &Path,
    log_path: &Path,
) -> Result<(), RunnerError> {
    let log = fs::File::create(log_path)?;
    let log_clone = log.try_clone()?;
    let base_url = format!("http://{listen}");
    let command_description;
    let mut command = if let Some(binary) = peer_binary_override(peer, options) {
        command_description = binary.display().to_string();
        let mut command = Command::new(binary);
        command.current_dir(&options.repo_root);
        command
    } else {
        match peer {
            PeerTarget::Js => {
                let script = options
                    .repo_root
                    .join("tests/conformance/peers/js/client.mjs");
                command_description = format!(
                    "{} {}",
                    PathBuf::from(&options.node_binary).display(),
                    script.display()
                );
                let mut command = Command::new(&options.node_binary);
                command.current_dir(&options.repo_root).arg(script);
                command
            }
            PeerTarget::Python => {
                let script = options
                    .repo_root
                    .join("tests/conformance/peers/python/client.py");
                command_description = format!(
                    "{} {}",
                    PathBuf::from(&options.python_binary).display(),
                    script.display()
                );
                let mut command = Command::new(&options.python_binary);
                command.current_dir(&options.repo_root).arg(script);
                command
            }
            PeerTarget::Go => {
                command_description = format!(
                    "{} run ./cmd/conformance-peer",
                    PathBuf::from(&options.go_binary).display()
                );
                let mut command = Command::new(&options.go_binary);
                command
                    .current_dir(options.repo_root.join("sdks/go/chio-go"))
                    .arg("run")
                    .arg("./cmd/conformance-peer");
                command
            }
            PeerTarget::Cpp => {
                let executable = ensure_cpp_peer_executable(&options.repo_root)?;
                command_description = executable.display().to_string();
                let mut command = Command::new(executable);
                command.current_dir(&options.repo_root);
                command
            }
        }
    };

    apply_conformance_auth_env(&mut command, options, options.auth_mode);

    let status = command
        .arg("--base-url")
        .arg(base_url)
        .arg("--auth-mode")
        .arg(match options.auth_mode {
            ConformanceAuthMode::StaticBearer => "static-bearer",
            ConformanceAuthMode::LocalOAuth => "oauth-local",
        })
        .arg("--auth-scope")
        .arg(&options.auth_scope)
        .arg("--scenarios-dir")
        .arg(&options.scenarios_dir)
        .arg("--results-output")
        .arg(results_output)
        .arg("--artifacts-dir")
        .arg(artifacts_dir)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_clone))
        .status()
        .map_err(|source| RunnerError::Spawn {
            command: format!(
                "{} --base-url http://{} --scenarios-dir {} --results-output {}",
                command_description,
                listen,
                options.scenarios_dir.display(),
                results_output.display()
            ),
            source,
        })?;

    if !status.success() {
        return Err(RunnerError::ProcessFailed {
            command: command_description,
            status: status.code().unwrap_or(1),
            log_path: log_path.display().to_string(),
        });
    }
    Ok(())
}

fn peer_binary_override(peer: PeerTarget, options: &ConformanceRunOptions) -> Option<&Path> {
    options
        .peer_binaries
        .iter()
        .find_map(|(target, path)| (*target == peer).then_some(path.as_path()))
}

fn ensure_cpp_peer_executable(repo_root: &Path) -> Result<PathBuf, RunnerError> {
    let build_dir = repo_root.join("target/chio-cpp-conformance");
    let build_config = "Debug";
    let executable_name = format!("chio_cpp_conformance_peer{}", std::env::consts::EXE_SUFFIX);
    let executable_candidates = [
        build_dir.join(&executable_name),
        build_dir.join(build_config).join(&executable_name),
    ];
    let source_dir = repo_root.join("sdks/cpp/chio-cpp");
    let configure_status = Command::new("cmake")
        .current_dir(repo_root)
        .arg("-S")
        .arg(&source_dir)
        .arg("-B")
        .arg(&build_dir)
        .arg("-DCHIO_CPP_BUILD_TESTS=OFF")
        .arg("-DCHIO_CPP_BUILD_EXAMPLES=OFF")
        .arg("-DCHIO_CPP_ENABLE_CURL=ON")
        .arg("-DCHIO_CPP_BUILD_CONFORMANCE_PEER=ON")
        .arg("-DCMAKE_BUILD_TYPE=Debug")
        .status()
        .map_err(|source| RunnerError::Spawn {
            command: "cmake configure chio_cpp_conformance_peer".to_string(),
            source,
        })?;
    if !configure_status.success() {
        return Err(RunnerError::ProcessFailed {
            command: "cmake configure chio_cpp_conformance_peer".to_string(),
            status: configure_status.code().unwrap_or(1),
            log_path: "<stderr>".to_string(),
        });
    }

    let build_status = Command::new("cmake")
        .current_dir(repo_root)
        .arg("--build")
        .arg(&build_dir)
        .arg("--target")
        .arg("chio_cpp_conformance_peer")
        .arg("--config")
        .arg(build_config)
        .status()
        .map_err(|source| RunnerError::Spawn {
            command: "cmake --build chio_cpp_conformance_peer".to_string(),
            source,
        })?;
    if !build_status.success() {
        return Err(RunnerError::ProcessFailed {
            command: "cmake --build chio_cpp_conformance_peer".to_string(),
            status: build_status.code().unwrap_or(1),
            log_path: "<stderr>".to_string(),
        });
    }

    for executable in executable_candidates {
        if executable.exists() {
            return Ok(executable);
        }
    }
    Err(RunnerError::ProcessFailed {
        command: "cmake --build chio_cpp_conformance_peer".to_string(),
        status: 1,
        log_path: "<stderr>".to_string(),
    })
}

fn reserve_listen_addr() -> Result<SocketAddr, RunnerError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn wait_for_server(
    listen: SocketAddr,
    server: &mut Child,
    log_path: &Path,
) -> Result<(), RunnerError> {
    for _ in 0..SERVER_STARTUP_ATTEMPTS {
        if TcpStream::connect(listen).is_ok() {
            thread::sleep(SERVER_STARTUP_POLL_INTERVAL);
            return Ok(());
        }
        if let Some(status) = server.try_wait()? {
            return Err(RunnerError::ProcessFailed {
                command: "chio mcp serve-http".to_string(),
                status: status.code().unwrap_or(1),
                log_path: log_path.display().to_string(),
            });
        }
        thread::sleep(SERVER_STARTUP_POLL_INTERVAL);
    }
    Err(RunnerError::ServerStartupTimeout { listen })
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn unique_run_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_conformance_auth_env, conformance_fixture_root_from_manifest_dir,
        default_run_options, ConformanceAuthMode, ConformanceRuntimeState,
    };
    use std::ffi::OsStr;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn command_env(command: &Command, key: &str) -> Option<Option<String>> {
        command.get_envs().find_map(|(name, value)| {
            if name == OsStr::new(key) {
                return Some(value.map(|raw| raw.to_string_lossy().into_owned()));
            }
            None
        })
    }

    fn unique_test_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "chio-conformance-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn create_default_fixture_tree(root: &Path) {
        let scenarios = root.join("tests/conformance/scenarios/mcp_core");
        let fixtures = root.join("tests/conformance/fixtures/mcp_core");
        if let Err(error) = fs::create_dir_all(&scenarios) {
            panic!("failed to create {}: {error}", scenarios.display());
        }
        if let Err(error) = fs::create_dir_all(&fixtures) {
            panic!("failed to create {}: {error}", fixtures.display());
        }
        if let Err(error) = fs::write(scenarios.join("initialize.json"), "{}\n") {
            panic!("failed to write scenario fixture: {error}");
        }
        if let Err(error) = fs::write(fixtures.join("policy.yaml"), "version: 1\n") {
            panic!("failed to write policy fixture: {error}");
        }
    }

    #[test]
    fn runtime_state_is_private_and_removed_after_the_run() {
        let runtime_state = ConformanceRuntimeState::create()
            .unwrap_or_else(|error| panic!("create conformance runtime state: {error}"));
        let runtime_root = runtime_state._directory.path().to_path_buf();
        assert_eq!(
            runtime_state.session_db_path.parent(),
            Some(runtime_root.as_path())
        );
        assert_eq!(
            runtime_state.auth_server_seed_path.parent(),
            Some(runtime_root.as_path())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&runtime_root)
                .unwrap_or_else(|error| panic!("read runtime directory metadata: {error}"));
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        drop(runtime_state);
        assert!(!runtime_root.exists());
    }

    #[test]
    fn store_less_fixture_opts_into_ephemeral_revocation() {
        // The harness launches `chio mcp serve-http` with no `--revocation-db`,
        // so the kernel's revocation store is the in-memory default. Durable
        // persistence is the default posture, so a mediated tool call is denied
        // by the revocation durability gate unless the policy opts into an
        // ephemeral revocation store. A fixture that opts into an ephemeral
        // receipt log (the store-less scaffold posture) must therefore also opt
        // into an ephemeral revocation store, or the whole suite denies before
        // it can run.
        #[derive(serde::Deserialize)]
        struct KernelSection {
            #[serde(default)]
            allow_ephemeral_receipt_log: bool,
            #[serde(default)]
            allow_ephemeral_revocation_store: bool,
        }
        #[derive(serde::Deserialize)]
        struct FixturePolicy {
            kernel: KernelSection,
        }

        let fixture_root =
            conformance_fixture_root_from_manifest_dir(Path::new(env!("CARGO_MANIFEST_DIR")));
        let policy_path = fixture_root.join("tests/conformance/fixtures/mcp_core/policy.yaml");
        let raw = fs::read_to_string(&policy_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", policy_path.display()));
        let policy: FixturePolicy = serde_yaml::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", policy_path.display()));

        if policy.kernel.allow_ephemeral_receipt_log {
            assert!(
                policy.kernel.allow_ephemeral_revocation_store,
                "a store-less conformance fixture that allows an ephemeral receipt log must also \
                 allow an ephemeral revocation store, or mediated tool calls are denied by the \
                 revocation durability gate"
            );
        }
    }

    #[test]
    fn fixture_root_prefers_workspace_tree_when_present() {
        let root = unique_test_dir("workspace");
        let manifest_dir = root.join("crates/tooling/chio-conformance");
        create_default_fixture_tree(&root);
        if let Err(error) = fs::create_dir_all(&manifest_dir) {
            panic!("failed to create {}: {error}", manifest_dir.display());
        }

        assert_eq!(
            conformance_fixture_root_from_manifest_dir(&manifest_dir),
            root
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fixture_root_falls_back_to_packaged_crate_tree() {
        let package_root = unique_test_dir("package");
        create_default_fixture_tree(&package_root);

        assert_eq!(
            conformance_fixture_root_from_manifest_dir(&package_root),
            package_root
        );

        let _ = fs::remove_dir_all(package_root);
    }

    #[test]
    fn local_oauth_child_env_removes_inherited_static_bearer_token() {
        let mut options = default_run_options();
        options.auth_mode = ConformanceAuthMode::LocalOAuth;
        options.auth_token = "local-auth-token".to_string();
        options.admin_token = "local-admin-token".to_string();
        let mut command = Command::new("chio");
        command.env("CHIO_AUTH_TOKEN", "parent-static-token");
        command.env("CHIO_MCP_AUTH_TOKEN", "parent-mcp-static-token");
        command.env("CHIO_MCP_ADMIN_TOKEN", "parent-mcp-admin-token");

        apply_conformance_auth_env(&mut command, &options, options.auth_mode);

        assert_eq!(command_env(&command, "CHIO_AUTH_TOKEN"), Some(None));
        assert_eq!(command_env(&command, "CHIO_MCP_AUTH_TOKEN"), Some(None));
        assert_eq!(command_env(&command, "CHIO_MCP_ADMIN_TOKEN"), Some(None));
        assert_eq!(
            command_env(&command, "CHIO_ADMIN_TOKEN"),
            Some(Some("local-admin-token".to_string()))
        );
        assert_eq!(
            command_env(&command, "CHIO_CONFORMANCE_AUTH_TOKEN"),
            Some(Some("local-auth-token".to_string()))
        );
        assert_eq!(
            command_env(&command, "CHIO_CONFORMANCE_ADMIN_TOKEN"),
            Some(Some("local-admin-token".to_string()))
        );
    }
}
