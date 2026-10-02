//! Reproduce the native Hermes installation without borrowing a personal venv.
use super::{
    connections,
    launcher::{Agent, Installation},
};
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

const CHIO: &str = "6753edbc365f5ea820224b96a59940feedbfca94";
const HERMES: &str = "175054c14b54404663d8614a178280cffe6062eb";
const PYTHON: &str = "3.11.16";
const UV_ARCHIVE: &str =
    "https://github.com/astral-sh/uv/releases/download/0.12.11/uv-aarch64-apple-darwin.tar.gz";
const UV_SHA256: &str = "e01b69ee15e81918d5e8fc9cf39b3db7f59c5576e5e306cd9b7aeb2c7b7321c3";
const GATEWAY: &str = "4c3edf80163a5108b054c743b062ad74051fdf8360579cbaed3bf01e2586d622";

async fn uv(
    tool: &Path,
    args: &[&str],
    stage: &Path,
    project: Option<&Path>,
    log: &std::fs::File,
) -> Result<()> {
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir(stage)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env(
            "HOME",
            std::env::var_os("HOME").context("HOME unavailable")?,
        )
        .env("TMPDIR", stage.join("tmp"))
        .env("XDG_CONFIG_HOME", stage.join("config"))
        .env("UV_CACHE_DIR", stage.join("cache"))
        .env("UV_PYTHON_INSTALL_DIR", stage.join("python"))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .kill_on_drop(true);
    if let Some(environment) = project {
        command.env("UV_PROJECT_ENVIRONMENT", environment);
    }
    let result = tokio::time::timeout(Duration::from_secs(600), command.status())
        .await
        .context("Hermes preparation timed out; the setup log is retained")??;
    anyhow::ensure!(
        result.success(),
        "Hermes preparation stopped; inspect its retained setup log"
    );
    Ok(())
}

fn path(path: &Path) -> Result<&str> {
    path.to_str().context("Installation path is not UTF-8")
}

async fn checkout(
    stage: &Path,
    name: &str,
    url: &str,
    revision: &str,
    sparse: &[&str],
    log: &std::fs::File,
) -> Result<PathBuf> {
    let git = connections::executable("git")?;
    connections::run(&git, &["init", name], stage, log).await?;
    let root = stage.join(name);
    connections::run(&git, &["remote", "add", "origin", url], &root, log).await?;
    if !sparse.is_empty() {
        connections::run(&git, &["sparse-checkout", "init", "--cone"], &root, log).await?;
        let mut args = vec!["sparse-checkout", "set"];
        args.extend_from_slice(sparse);
        connections::run(&git, &args, &root, log).await?;
    }
    connections::run(
        &git,
        &[
            "fetch",
            "--no-tags",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            revision,
        ],
        &root,
        log,
    )
    .await?;
    connections::run(&git, &["checkout", "--detach", "FETCH_HEAD"], &root, log).await?;
    Ok(root)
}

pub async fn prepare() -> Result<()> {
    anyhow::ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "Managed Hermes currently requires Apple Silicon macOS"
    );
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    let auth = home.join(".codex/auth.json");
    anyhow::ensure!(
        auth.is_file(),
        "Run codex login with your existing ChatGPT account, then connect Hermes"
    );
    let root = std::path::absolute(connections::directory()?)?;
    files::private_directory(&root)?;
    let target = root.join("hermes");
    let installed = target.join("installation.json");
    if crate::read::<Installation>(&installed)
        .is_ok_and(|installation| connections::validate(&installation).is_ok())
    {
        println!(
            "Hermes is prepared; its native launcher checks the existing login when work starts"
        );
        return Ok(());
    }
    let stage = root.join(format!(".prepare-hermes-{}", uuid::Uuid::new_v4()));
    files::private_directory(&stage)?;
    for name in ["tmp", "config", "tools"] {
        files::private_directory(&stage.join(name))?;
    }
    files::create(&stage.join("setup.log"), b"")?;
    let log = std::fs::OpenOptions::new()
        .append(true)
        .open(stage.join("setup.log"))?;
    println!(
        "Preparing Hermes, its Python runtime, and the Chio launcher in isolated environments"
    );
    let result = install(&stage, auth, &log).await;
    let installation =
        result.with_context(|| format!("Hermes setup retained at {}", stage.display()))?;
    files::private_directory(&target)?;
    // Publish only the validated connection. Previous runtimes remain available
    // to missions that already retained their exact installation paths.
    if installed.exists() {
        files::replace(&installed, &serde_json::to_vec_pretty(&installation)?)?;
    } else {
        crate::retain(&installed, &installation)?;
    }
    println!("Hermes prepared. Its native sessions use the existing ChatGPT login.");
    Ok(())
}

async fn install(stage: &Path, auth: PathBuf, log: &std::fs::File) -> Result<Installation> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;
    let mut response = client.get(UV_ARCHIVE).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= 64_000_000,
            "uv archive exceeds its size bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    anyhow::ensure!(
        chio_core::sha256_hex(&bytes) == UV_SHA256,
        "Pinned uv archive checksum mismatch"
    );
    files::create(&stage.join("tools/uv.tar.gz"), &bytes)?;
    connections::run(
        &connections::executable("tar")?,
        &["-xzf", "uv.tar.gz", "--strip-components=1"],
        &stage.join("tools"),
        log,
    )
    .await?;
    let tool = stage.join("tools/uv");
    uv(
        &tool,
        &["python", "install", PYTHON, "--no-bin", "--no-registry"],
        stage,
        None,
        log,
    )
    .await?;
    let python = stage.join("python").join(format!(
        "cpython-{PYTHON}-macos-aarch64-none/bin/python3.11"
    ));
    anyhow::ensure!(
        python.is_file(),
        "Managed Python installation has an unexpected layout"
    );
    let host = checkout(
        stage,
        "hermes-source",
        "https://github.com/NousResearch/hermes-agent.git",
        HERMES,
        &[],
        log,
    )
    .await?;
    uv(
        &tool,
        &[
            "sync",
            "--project",
            path(&host)?,
            "--python",
            path(&python)?,
            "--locked",
            "--extra",
            "mcp",
            "--no-dev",
            "--no-python-downloads",
        ],
        stage,
        Some(&stage.join("host-venv")),
        log,
    )
    .await?;
    let chio = checkout(
        stage,
        "chio-source",
        "https://github.com/backbay-labs/chio.git",
        CHIO,
        &[
            "sdks/python/chio-hermes",
            "sdks/python/chio-adapter-base",
            "sdks/python/chio-code-agent",
            "sdks/python/chio-sdk-python",
        ],
        log,
    )
    .await?;
    let launcher_project = chio.join("sdks/python/chio-hermes");
    let environment = stage.join("launcher-venv");
    uv(
        &tool,
        &[
            "venv",
            path(&environment)?,
            "--python",
            path(&python)?,
            "--no-python-downloads",
        ],
        stage,
        None,
        log,
    )
    .await?;
    files::create(
        &stage.join("build-tools.lock"),
        include_bytes!("hermes-build.lock"),
    )?;
    uv(
        &tool,
        &[
            "pip",
            "install",
            "--python",
            path(&environment.join("bin/python"))?,
            "--require-hashes",
            "-r",
            path(&stage.join("build-tools.lock"))?,
        ],
        stage,
        None,
        log,
    )
    .await?;
    uv(
        &tool,
        &[
            "sync",
            "--project",
            path(&launcher_project)?,
            "--python",
            path(&python)?,
            "--locked",
            "--no-dev",
            "--no-editable",
            "--no-build-isolation",
            "--inexact",
            "--no-python-downloads",
        ],
        stage,
        Some(&environment),
        log,
    )
    .await?;
    for environment in [stage.join("host-venv"), environment.clone()] {
        uv(
            &tool,
            &[
                "pip",
                "check",
                "--python",
                path(&environment.join("bin/python"))?,
            ],
            stage,
            None,
            log,
        )
        .await?;
    }
    // Reuse the same pinned, self-contained bridge shipped by the existing
    // Codex integration. It is a transport dependency, not another agent.
    let bridge_source = checkout(
        stage,
        "bridge-source",
        "https://github.com/backbay-labs/chio-codex-plugin.git",
        "deefb3a85001ee47a22fcfbb43ab6749c4944004",
        &[],
        log,
    )
    .await?;
    let npm = connections::executable("npm")?;
    connections::run(
        &npm,
        &["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        &bridge_source,
        log,
    )
    .await?;
    connections::run(&npm, &["run", "pack:release"], &bridge_source, log).await?;
    let consumer = stage.join("bridge");
    files::private_directory(&consumer)?;
    files::create(&consumer.join("package.json"), b"{\"private\":true}")?;
    connections::run(
        &npm,
        &[
            "install",
            "--offline",
            "--ignore-scripts",
            "--install-strategy=nested",
            "--no-audit",
            "--no-fund",
            path(&bridge_source.join("artifacts/chio-codex-plugin-0.3.0.tgz"))?,
        ],
        &consumer,
        log,
    )
    .await?;
    let installation = Installation {
        agent: Agent::Hermes,
        package: consumer.join("node_modules/@chio/codex-plugin"),
        host: stage.join("host-venv/bin/python"),
        host_sha256: super::launcher::sha256(&python)?,
        gateway_sha256: GATEWAY.into(),
        node: connections::executable("node")?,
        auth_file: Some(auth),
        launcher: Some(stage.join("launcher-venv/bin/chio-hermes-restricted")),
        host_root: Some(host.clone()),
    };
    connections::validate(&installation)?;
    crate::retain(
        &stage.join("provenance.json"),
        &json!({
            "hermes_revision": HERMES,
            "chio_revision": CHIO,
            "python": PYTHON,
            "uv_archive_sha256": UV_SHA256,
            "hermes_lock_sha256": super::launcher::sha256(&host.join("uv.lock"))?,
            "launcher_lock_sha256": super::launcher::sha256(&launcher_project.join("uv.lock"))?,
            "build_tools_sha256": chio_core::sha256_hex(include_bytes!("hermes-build.lock")),
            "host_sha256": installation.host_sha256,
            "gateway_sha256": GATEWAY,
        }),
    )?;
    Ok(installation)
}
