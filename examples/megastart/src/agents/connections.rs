//! Prepare pinned, isolated installations of the existing native integrations.
//!
//! Connection preparation never starts inference, copies a login, or changes a
//! personal agent installation. Restricted launchers continue to own login use.
use super::{
    launcher::{Agent, Installation},
    mission::Configuration,
};
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

const CLAUDE_HOST: &str = "a681f3008f0050029aeebcab3af51bb6a55ddeb625a3af3141a4416d43cd2558";
const CLAUDE_GATEWAY: &str = "6ef1dfdf0fc822685574bc1a0d6a3d37764772a2401afd14a8f2706d904c47cf";
const GATEWAY: &str = "4c3edf80163a5108b054c743b062ad74051fdf8360579cbaed3bf01e2586d622";
const CODEX_HOST: &str = "b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3";
const PI_HOST: &str = "f49ba53cb044aa42dfba49eef229a6c2badaa4238d146d7b5cb1c6716ff2b0c1";

pub fn directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("MEGASTART_CONNECTIONS") {
        return Ok(PathBuf::from(path));
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("HOME is unavailable")?)
            .join(".local/share/chio/megastart/connections"),
    )
}

fn name(agent: Agent) -> &'static str {
    match agent {
        Agent::Claude => "claude",
        Agent::Codex => "codex",
        Agent::Hermes => "hermes",
        Agent::Pi => "pi",
    }
}

fn check_hash(path: &Path, expected: &str) -> Result<()> {
    anyhow::ensure!(
        super::launcher::sha256(path)? == expected,
        "Prepared native artifact changed; reconnect this agent"
    );
    Ok(())
}

pub fn validate(installation: &Installation) -> Result<()> {
    anyhow::ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "This native mission combination requires Apple Silicon macOS"
    );
    check_hash(&installation.host, &installation.host_sha256)?;
    let bridge = installation
        .package
        .join("node_modules/@chio/bridge/dist/gateway-http.js");
    let gateway = if matches!(installation.agent, Agent::Claude) {
        installation.package.join("dist/gateway-http.js")
    } else {
        bridge
    };
    check_hash(&gateway, &installation.gateway_sha256)?;
    anyhow::ensure!(
        installation.node.is_file(),
        "Node is unavailable; reconnect this agent"
    );
    if !matches!(installation.agent, Agent::Claude) {
        anyhow::ensure!(
            installation
                .auth_file
                .as_ref()
                .is_some_and(|path| path.is_file()),
            "Run codex login with your existing ChatGPT account, then reconnect"
        );
    }
    if matches!(installation.agent, Agent::Hermes) {
        anyhow::ensure!(
            installation
                .launcher
                .as_ref()
                .is_some_and(|path| path.is_file())
                && installation
                    .host_root
                    .as_ref()
                    .is_some_and(|path| path.join("run_agent.py").is_file()),
            "Hermes runtime or restricted launcher is unavailable; reconnect Hermes"
        );
    }
    Ok(())
}

/// Browser projection deliberately excludes local installation and login paths.
pub fn snapshot() -> Result<Value> {
    let root = directory()?;
    let mut entries = Vec::new();
    for (agent, label) in [
        (Agent::Claude, "Claude Code"),
        (Agent::Codex, "Codex"),
        (Agent::Hermes, "Hermes"),
        (Agent::Pi, "Pi"),
    ] {
        let path = root.join(name(agent)).join("installation.json");
        let prepared = path.exists()
            && crate::read::<Installation>(&path).is_ok_and(|i| {
                i.host.is_file()
                    && i.node.is_file()
                    && i.package.is_dir()
                    && (matches!(i.agent, Agent::Claude)
                        || i.auth_file.is_some_and(|p| p.is_file()))
            });
        entries.push(json!({"id":name(agent),"name":label,"prepared":prepared,"can_prepare":true,"login":if matches!(agent,Agent::Claude){"Existing Claude login"}else{"Existing ChatGPT login"}}));
    }
    Ok(json!({"available":cfg!(all(target_os="macos",target_arch="aarch64")),"agents":entries}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub research: Agent,
    pub implementation: Agent,
    pub review: Agent,
}

pub fn configuration(selection: Selection) -> Result<Configuration> {
    let mut swarms = BTreeMap::new();
    for (role, agent) in [
        ("research", selection.research),
        ("implementation", selection.implementation),
        ("review", selection.review),
    ] {
        let installation: Installation =
            crate::read(&directory()?.join(name(agent)).join("installation.json"))
                .context("Connect the selected agent before creating a mission")?;
        anyhow::ensure!(
            name(installation.agent) == name(agent),
            "Stored connection belongs to another agent"
        );
        validate(&installation)?;
        swarms.insert(role.to_owned(), installation);
    }
    // Reserve a free contiguous range before retaining configuration. Endpoint
    // binding remains authoritative if another process wins the race afterward.
    for _ in 0..64 {
        let first = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let port = first.local_addr()?.port();
        if port > 65529 {
            continue;
        }
        let rest = (1..6)
            .map(|offset| {
                std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port + offset))
            })
            .collect::<std::io::Result<Vec<_>>>();
        if rest.is_ok() {
            return Ok(Configuration {
                first_port: port,
                swarms,
            });
        }
    }
    anyhow::bail!("No free native endpoint range; close an unused local mission and retry")
}

pub(super) fn executable(name: &str) -> Result<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(name))
        .find(|p| p.is_file())
        .context(format!("Install {name} before connecting an agent"))
}

pub(super) async fn run(
    program: &Path,
    args: &[&str],
    cwd: &Path,
    log: &std::fs::File,
) -> Result<()> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(600), command.status())
        .await
        .context("Connection preparation timed out; inspect its retained setup log")??;
    anyhow::ensure!(
        status.success(),
        "Connection preparation stopped; inspect its retained setup log"
    );
    Ok(())
}

/// Fetch immutable public integration source and use its own release packager.
/// The installation marker is committed only after all artifact checks pass.
pub async fn prepare(agent: Agent) -> Result<()> {
    if matches!(agent, Agent::Hermes) {
        return super::hermes::prepare().await;
    }
    anyhow::ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "Native setup currently requires Apple Silicon macOS"
    );
    let (repository, revision, archive) = match agent {
        Agent::Claude => (
            "chio-claude-code-plugin",
            "65ac8390c57a5292c055fba50caa1aafbd915848",
            "chio-claude-code-plugin-0.3.1-rc.1.tgz",
        ),
        Agent::Codex => (
            "chio-codex-plugin",
            "deefb3a85001ee47a22fcfbb43ab6749c4944004",
            "chio-codex-plugin-0.3.0.tgz",
        ),
        Agent::Pi => (
            "chio-pi-plugin",
            "cd3dbf90974687d30f23f989173bd8c155b016d3",
            "chio-pi-plugin-0.1.0.tgz",
        ),
        _ => anyhow::bail!(
            "Managed preparation for this agent is awaiting its native mission acceptance"
        ),
    };
    let node = executable("node")?;
    let npm = executable("npm")?;
    let git = executable("git")?;
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is unavailable")?);
    let auth = home.join(".codex/auth.json");
    if !matches!(agent, Agent::Claude) {
        anyhow::ensure!(auth.is_file(), "Run codex login with your existing ChatGPT account, then reconnect. No API billing fallback is used.");
    }
    let root = directory()?;
    files::private_directory(&root)?;
    let target = root.join(name(agent));
    if target.join("installation.json").exists() {
        validate(&crate::read(&target.join("installation.json"))?)?;
        println!(
            "{} connection is prepared; login will be checked by the native launcher",
            name(agent)
        );
        return Ok(());
    }
    let stage = root.join(format!(".prepare-{}-{}", name(agent), uuid::Uuid::new_v4()));
    files::private_directory(&stage)?;
    files::create(&stage.join("setup.log"), b"")?;
    let log = std::fs::OpenOptions::new()
        .append(true)
        .open(stage.join("setup.log"))?;
    println!("Preparing {} in an isolated installation", name(agent));
    let result: Result<Installation> = async {
        run(&git, &["init", "source"], &stage, &log).await?;
        let source = stage.join("source");
        let url = format!("https://github.com/backbay-labs/{repository}.git");
        run(&git, &["fetch", "--depth=1", &url, revision], &source, &log).await?;
        run(&git, &["checkout", "--detach", "FETCH_HEAD"], &source, &log).await?;
        run(
            &npm,
            &["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            &source,
            &log,
        )
        .await?;
        run(&npm, &["run", "pack:release"], &source, &log).await?;
        let consumer = stage.join("consumer");
        files::private_directory(&consumer)?;
        files::create(&consumer.join("package.json"), b"{\"private\":true}")?;
        if matches!(agent, Agent::Pi) {
            run(
                &npm,
                &[
                    "install",
                    "--install-strategy=nested",
                    "--save-exact",
                    "--no-audit",
                    "--no-fund",
                    "@earendil-works/pi-coding-agent@0.85.1",
                ],
                &consumer,
                &log,
            )
            .await?;
        }
        let artifact = source.join("artifacts").join(archive);
        run(
            &npm,
            &[
                "install",
                "--offline",
                "--ignore-scripts",
                "--install-strategy=nested",
                "--no-audit",
                "--no-fund",
                artifact.to_str().context("Non-UTF8 artifact path")?,
            ],
            &consumer,
            &log,
        )
        .await?;
        let package = consumer.join("node_modules/@chio").join(match agent {
            Agent::Claude => "claude-code-plugin",
            Agent::Codex => "codex-plugin",
            _ => "pi-plugin",
        });
        let host =
            if matches!(agent, Agent::Claude) {
                let native = stage.join("host");
                files::private_directory(&native)?;
                run(
                &executable("curl")?,
                &[
                    "--fail", "--location", "--proto", "=https", "--tlsv1.2",
                    "--max-time", "300", "--output", "claude",
                    "https://downloads.claude.ai/claude-code-releases/2.1.267/darwin-arm64/claude",
                ],
                &native, &log,
            ).await?;
                let binary = native.join("claude");
                check_hash(&binary, CLAUDE_HOST)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
                }
                binary
            } else if matches!(agent, Agent::Codex) {
                let native = stage.join("host");
                files::private_directory(&native)?;
                run(
                    &npm,
                    &[
                        "pack",
                        "--ignore-scripts",
                        "@openai/codex@0.153.4-darwin-arm64",
                    ],
                    &native,
                    &log,
                )
                .await?;
                run(
                    &executable("tar")?,
                    &["-xzf", "openai-codex-0.153.4-darwin-arm64.tgz"],
                    &native,
                    &log,
                )
                .await?;
                native.join("package/vendor/aarch64-apple-darwin/bin/codex")
            } else {
                package.join("dist/protected-cli.js")
            };
        let installation = Installation {
            agent,
            package,
            host,
            host_sha256: match agent {
                Agent::Claude => CLAUDE_HOST,
                Agent::Codex => CODEX_HOST,
                _ => PI_HOST,
            }
            .into(),
            gateway_sha256: if matches!(agent, Agent::Claude) {
                CLAUDE_GATEWAY
            } else {
                GATEWAY
            }
            .into(),
            node,
            auth_file: if matches!(agent, Agent::Claude) {
                None
            } else {
                Some(auth)
            },
            launcher: None,
            host_root: None,
        };
        validate(&installation)?;
        Ok(installation)
    }
    .await;
    let mut installation =
        result.with_context(|| format!("Preparation retained at {}", stage.display()))?;
    // Keep the immutable preparation directory in place: Node dependency paths
    // and release provenance continue to refer to the exact installed artifacts.
    installation.package = installation.package.canonicalize()?;
    installation.host = installation.host.canonicalize()?;
    files::private_directory(&target)?;
    crate::retain(&target.join("installation.json"), &installation)?;
    crate::retain(
        &target.join("provenance.json"),
        &json!({"repository":repository,"revision":revision,"preparation":stage,"host_sha256":installation.host_sha256,"gateway_sha256":installation.gateway_sha256}),
    )?;
    println!(
        "{} prepared. Your native launcher will use the existing {} login.",
        name(agent),
        if matches!(agent, Agent::Claude) {
            "Claude"
        } else {
            "ChatGPT"
        }
    );
    Ok(())
}
