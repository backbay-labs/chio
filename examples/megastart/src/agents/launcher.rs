//! Supervise existing restricted launchers; their bridge owns delivery and recovery.
use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Agent {
    Claude,
    Codex,
    Hermes,
    Pi,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub agent: Agent,
    pub package: PathBuf,
    pub host: PathBuf,
    pub host_sha256: String,
    pub gateway_sha256: String,
    pub node: PathBuf,
    pub auth_file: Option<PathBuf>,
    pub launcher: Option<PathBuf>,
    pub host_root: Option<PathBuf>,
}

pub(super) fn sha256(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() < 512_000_000,
        "Invalid selected artifact"
    );
    Ok(chio_core::sha256_hex(&std::fs::read(path)?))
}

/// A new task gets a fresh native profile and a journal bound to the retained
/// worker capability. A failed task directory is never reused automatically.
pub async fn task(worker: &Path, installation: &Installation, prompt: &str) -> Result<Value> {
    task_bound(
        worker,
        installation,
        prompt,
        &uuid::Uuid::new_v4().to_string(),
    )
    .await
}

/// Assignment identities survive restart. An interrupted task is never relaunched.
pub async fn task_bound(
    worker: &Path,
    installation: &Installation,
    prompt: &str,
    assignment: &str,
) -> Result<Value> {
    uuid::Uuid::parse_str(assignment)?;
    anyhow::ensure!(
        sha256(&installation.host)? == installation.host_sha256,
        "Native executable changed; qualify the selected version"
    );
    let bridge = installation.package.join("node_modules/@chio/bridge");
    let gateway = match installation.agent {
        Agent::Claude => installation.package.join("dist/gateway-http.js"),
        Agent::Codex | Agent::Hermes | Agent::Pi => bridge.join("dist/gateway-http.js"),
    };
    anyhow::ensure!(
        sha256(&gateway)? == installation.gateway_sha256,
        "Selected gateway changed"
    );
    let worker = worker.canonicalize()?;
    let operator: Value = crate::read(&worker.join("operator.json"))?;
    let task = worker.join(format!("task-{assignment}"));
    let identity = json!({"assignment":assignment,"prompt_sha256":chio_core::sha256_hex(prompt.as_bytes()),"agent":installation.agent,"host_sha256":installation.host_sha256,"gateway_sha256":installation.gateway_sha256,"capability":operator["capability"]});
    if task.exists() {
        anyhow::ensure!(
            crate::read::<Value>(&task.join("identity.json"))? == identity,
            "Retained native assignment changed"
        );
        let result: Value = crate::read(&task.join("result.json"))
            .context("Native task interrupted; reconcile its existing journal before proceeding")?;
        anyhow::ensure!(
            result["unresolved"] == false,
            "Native task has unresolved operations; preserve its existing operation fence"
        );
        return Ok(result);
    }
    files::private_directory(&task)?;
    crate::retain(&task.join("identity.json"), &identity)?;
    files::private_directory(&task.join("workspace"))?;
    files::create(&task.join("prompt.txt"), prompt.as_bytes())?;
    let session = uuid::Uuid::new_v4().to_string();
    let preparation = json!({
        "endpoint":format!("http://127.0.0.1:{}",operator["port"].as_u64().context("Missing worker port")?),
        "bearerToken":operator["agentToken"],"adminToken":operator["adminToken"],
        "credentialTtlSeconds":900,"trustedSigners":[operator["signer"]],"serverId":"fs",
        "sessionId":session,"journalDir":task.join("journal"),"allowedTools":super::service::TOOLS,
    });
    crate::retain(&task.join("prepare.json"), &preparation)?;
    let config = task.join("gateway.json");
    let status = Command::new(&installation.node)
        .arg(bridge.join("dist/prepare-gateway.js"))
        .arg(task.join("prepare.json"))
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(private_log(&task.join("prepare.stdout"))?)
        .stderr(private_log(&task.join("prepare.stderr"))?)
        .kill_on_drop(true)
        .status()
        .await?;
    anyhow::ensure!(
        status.success(),
        "Worker preparation failed; retained diagnostics: {}",
        task.display()
    );
    let prepared: Value = crate::read(&config)?;
    anyhow::ensure!(
        prepared["execution"]["capabilityId"] == operator["capability"],
        "Prepared session replaced the retained worker grant"
    );
    let mut command = Command::new(&installation.node);
    match installation.agent {
        Agent::Claude => {
            command
                .arg(installation.package.join("scripts/restricted.mjs"))
                .arg("--host")
                .arg(&installation.host)
                .arg("--host-sha256")
                .arg(&installation.host_sha256)
                .arg("--gateway-sha256")
                .arg(&installation.gateway_sha256)
                .arg("--gateway-config")
                .arg(&config)
                .arg("--profile")
                .arg(task.join("profile"))
                .arg("--workspace")
                .arg(task.join("workspace"))
                .args(["--model-auth", "claude-login", "--model", "claude-sonnet-5"]);
        }
        Agent::Codex => {
            command
                .arg(installation.package.join("dist/cli/main.js"))
                .arg("restricted")
                .arg("--gateway-config")
                .arg(&config)
                .arg("--codex-binary")
                .arg(&installation.host)
                .arg("--model-auth-file")
                .arg(
                    installation
                        .auth_file
                        .as_ref()
                        .context("Select the native ChatGPT login cache")?,
                )
                .arg("--evidence-dir")
                .arg(task.join("native"))
                .arg("--prompt")
                .arg(prompt);
        }
        Agent::Pi => {
            command
                .arg(installation.package.join("dist/protected-cli.js"))
                .arg("--config")
                .arg(&config)
                .arg("--profile")
                .arg(task.join("profile"))
                .arg("--cwd")
                .arg(task.join("workspace"))
                .args(["--provider", "openai-codex", "--model", "gpt-5.5"])
                .arg("--codex-auth")
                .arg(
                    installation
                        .auth_file
                        .as_ref()
                        .context("Select the native ChatGPT login cache")?,
                )
                .arg("--prompt")
                .arg(prompt);
        }
        Agent::Hermes => {
            command = Command::new(
                installation
                    .launcher
                    .as_ref()
                    .context("Select the installed restricted Hermes launcher")?,
            );
            command
                .arg("--host-python")
                .arg(&installation.host)
                .arg("--host-root")
                .arg(
                    installation
                        .host_root
                        .as_ref()
                        .context("Select the pinned Hermes source installation")?,
                )
                .arg("--node")
                .arg(&installation.node)
                .arg("--gateway-script")
                .arg(&gateway)
                .arg("--gateway-config")
                .arg(&config)
                .arg("--state-dir")
                .arg(task.join("native"))
                .arg("--query-file")
                .arg(task.join("prompt.txt"))
                .args(["--model", "gpt-5.5", "--model-auth", "codex-subscription"])
                .arg("--codex-auth-file")
                .arg(
                    installation
                        .auth_file
                        .as_ref()
                        .context("Select the native ChatGPT login cache")?,
                );
        }
    }
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "CLAUDE_CONFIG_DIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .current_dir(task.join("workspace"))
        .stdin(Stdio::piped())
        .stdout(private_log(&task.join("native.stdout.jsonl"))?)
        .stderr(private_log(&task.join("native.stderr"))?)
        .kill_on_drop(true)
        .spawn()
        .context("Start restricted native session")?;
    let pid = child.id().context("Native process has no PID")?;
    crate::retain(
        &task.join("task.json"),
        &json!({"schema":"chio.megastart.native-task.v1","agent":installation.agent,"worker":operator["worker"],"session":session,"capability":operator["capability"],"family":operator["family"],"host_sha256":installation.host_sha256,"pid":pid}),
    )?;
    if let Some(mut input) = child.stdin.take() {
        if matches!(installation.agent, Agent::Claude) {
            input.write_all(prompt.as_bytes()).await?;
        }
        input.shutdown().await?;
    }
    let status = match tokio::time::timeout(Duration::from_secs(300), child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            // Let the existing launcher close its host, relay and gateway. The
            // journal remains authoritative when cancellation crosses an effect.
            Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .await?;
            if tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .is_err()
            {
                child.kill().await?;
                child.wait().await?;
            }
            anyhow::bail!(
                "Native session interrupted; inspect retained task {} before recovery",
                task.display()
            );
        }
    };
    let mut records = Vec::new();
    for entry in std::fs::read_dir(task.join("journal"))? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let record: Value = crate::read(&path)?;
        if record["requestId"].is_string() {
            records.push(record);
        }
    }
    let unresolved = records.iter().any(|record| {
        matches!(record["state"].as_str(), Some("pending" | "unknown"))
            || record["state"] == "completed"
                && (record["acknowledged"] != true || record["hostDeliveryConfirmed"] != true)
    });
    let result = json!({"agent":installation.agent,"session":session,"worker":operator["worker"],"task":task,"native_exit":status.code(),"unresolved":unresolved,"operations":records});
    crate::retain(&task.join("result.json"), &result)?;
    anyhow::ensure!(
        !unresolved,
        "Native result remains unresolved; retain {} and use the existing bridge recovery commands",
        task.display()
    );
    // Refusal exercises legitimately have a nonzero native exit. Preserve it
    // alongside original records; the mission checks required artifacts itself.
    Ok(result)
}

fn private_log(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
