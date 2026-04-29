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
}

#[derive(Debug, Clone)]
pub struct ConformanceRunSummary {
    pub listen: SocketAddr,
    pub results_dir: PathBuf,
    pub report_output: PathBuf,
    pub peer_result_files: Vec<PathBuf>,
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

pub fn default_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
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
        auth_token: "conformance-token".to_string(),
        admin_token: "conformance-admin-token".to_string(),
        auth_scope: "mcp:invoke".to_string(),
        listen: None,
        peers: vec![PeerTarget::Js, PeerTarget::Python],
        node_binary: OsString::from("node"),
        python_binary: OsString::from("python3"),
        go_binary: OsString::from("go"),
        cargo_binary: OsString::from("cargo"),
        repo_root,
    }
}

pub fn run_conformance_harness(
    options: &ConformanceRunOptions,
) -> Result<ConformanceRunSummary, RunnerError> {
    if options.results_dir.exists() {
        fs::remove_dir_all(&options.results_dir)?;
    }
    fs::create_dir_all(&options.results_dir)?;
    if let Some(parent) = options.report_output.parent() {
        fs::create_dir_all(parent)?;
    }

    let artifacts_dir = options.results_dir.join("artifacts");
    let logs_dir = artifacts_dir.join("logs");
    fs::create_dir_all(&logs_dir)?;

    let listen = match options.listen {
        Some(listen) => listen,
        None => reserve_listen_addr()?,
    };
    let chio_executable = ensure_chio_executable(&options.repo_root, &options.cargo_binary)?;
    let server_log_path = logs_dir.join("chio-mcp-serve-http.log");
    let server = spawn_remote_edge(&chio_executable, options, listen, &server_log_path)?;
    let _server_guard = ChildGuard { child: server };
    wait_for_server(listen)?;

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
    let auth_server_seed_path = options.results_dir.join("artifacts/auth-server.seed");
    let mut command_description = format!(
        "{} mcp serve-http --policy {} --server-id conformance-mcp-core --listen {}",
        chio_executable.display(),
        options.policy_path.display(),
        listen
    );

    match options.auth_mode {
        ConformanceAuthMode::StaticBearer => {
            command.arg("--auth-token").arg(&options.auth_token);
            command_description.push_str(&format!(" --auth-token {}", options.auth_token));
        }
        ConformanceAuthMode::LocalOAuth => {
            command
                .arg("--public-base-url")
                .arg(&public_base_url)
                .arg("--auth-server-seed-file")
                .arg(&auth_server_seed_path)
                .arg("--auth-jwt-audience")
                .arg(format!("{public_base_url}/mcp"))
                .arg("--auth-scope")
                .arg(&options.auth_scope)
                .arg("--admin-token")
                .arg(&options.admin_token);
            command_description.push_str(&format!(
                " --public-base-url {} --auth-server-seed-file {} --auth-jwt-audience {}/mcp --auth-scope {} --admin-token {}",
                public_base_url,
                auth_server_seed_path.display(),
                public_base_url,
                options.auth_scope,
                options.admin_token
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
    let mut command = match peer {
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
                .current_dir(options.repo_root.join("packages/sdk/chio-go"))
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
    };

    let status = command
        .arg("--base-url")
        .arg(base_url)
        .arg("--auth-mode")
        .arg(match options.auth_mode {
            ConformanceAuthMode::StaticBearer => "static-bearer",
            ConformanceAuthMode::LocalOAuth => "oauth-local",
        })
        .arg("--auth-token")
        .arg(&options.auth_token)
        .arg("--admin-token")
        .arg(&options.admin_token)
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

fn ensure_cpp_peer_executable(repo_root: &Path) -> Result<PathBuf, RunnerError> {
    let build_dir = repo_root.join("target/chio-cpp-conformance");
    let build_config = "Debug";
    let executable_name = format!("chio_cpp_conformance_peer{}", std::env::consts::EXE_SUFFIX);
    let executable_candidates = [
        build_dir.join(&executable_name),
        build_dir.join(build_config).join(&executable_name),
    ];
    let source_dir = repo_root.join("packages/sdk/chio-cpp");
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

fn wait_for_server(listen: SocketAddr) -> Result<(), RunnerError> {
    for _ in 0..100 {
        if TcpStream::connect(listen).is_ok() {
            thread::sleep(Duration::from_millis(100));
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
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
