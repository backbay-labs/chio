mod client;
mod ui;

use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use client::Operator;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Parser)]
#[command(about = "Your agents. A system built on Chio. Operated through Herdr.")]
struct Cli {
    /// Private connection descriptor; never put its contents in pane metadata.
    #[arg(long, global = true)]
    connection: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Start or reconnect to a detached mission host and open its terminal board.
    Open {
        #[arg(long)]
        mission: Option<PathBuf>,
        #[arg(long, default_value = "megastart")]
        megastart: PathBuf,
    },
    /// Observe actual retained work. Closing this view leaves the host running.
    Board {
        #[arg(long, default_value = "mission")]
        view: String,
    },
    /// Read the same authenticated state as the browser (without credentials).
    Status,
    /// Open the browser connected to the same host and mission.
    Browser,
    /// Open an inspector through a declared Herdr pane entrypoint.
    Pane {
        #[arg(value_parser = ["decisions", "candidate", "resume"])]
        entrypoint: String,
    },
}

fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir(),
            "State path must be a real directory"
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "Choose an owner-only state directory (mode 0700); existing directory permissions are preserved"
        );
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn default_connection() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CHIO_HERDR_CONNECTION") {
        return Ok(path.into());
    }
    let dir = binding_directory()?;
    let active = dir.join("active.json");
    if active.is_file() {
        ensure!(
            fs::metadata(&active)?.len() <= 8192,
            "Invalid workspace binding"
        );
        let path: PathBuf = serde_json::from_slice(&fs::read(active)?)?;
        ensure!(path.is_absolute(), "Workspace connection must be absolute");
        return Ok(path);
    }
    Ok(dir.join("connection.json"))
}

fn binding_directory() -> Result<PathBuf> {
    // CLI attachment and manifest actions must resolve the same binding even
    // when only one entrypoint receives HERDR_PLUGIN_STATE_DIR.
    let root = PathBuf::from(std::env::var_os("HOME").context("HOME is unavailable")?)
        .join(".local/share/chio/herdr");
    // Scope bindings to the server and workspace, never another client's focus.
    let scope = format!(
        "{}:{}",
        std::env::var("HERDR_SOCKET_PATH").unwrap_or_default(),
        std::env::var("HERDR_WORKSPACE_ID").unwrap_or_else(|_| "standalone".into())
    );
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    scope.hash(&mut hash);
    let dir = root.join(format!("workspace-{:016x}", hash.finish()));
    private_dir(&dir)?;
    Ok(dir)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.connection {
        Some(path) => std::path::absolute(path)?,
        None => default_connection()?,
    };
    match cli.command {
        Cmd::Open { mission, megastart } => {
            start_host(&path, mission, &megastart)?;
            if std::env::var("HERDR_ENV").as_deref() == Ok("1") {
                let active = binding_directory()?.join("active.json");
                let temporary = active.with_extension("tmp");
                let mut file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&temporary)?;
                file.write_all(&serde_json::to_vec(&path)?)?;
                file.sync_all()?;
                fs::rename(temporary, active)?;
                open_pane(&path, "board")
            } else {
                ui::run(&path, "mission")
            }
        }
        Cmd::Board { view } => ui::run(&path, &view),
        Cmd::Status => {
            let operator = Operator::connect(&path)?;
            let snapshot = operator.snapshot()?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"protocol_version":snapshot.protocol_version,"state":snapshot.state,"busy":snapshot.busy})
                )?
            );
            Ok(())
        }
        Cmd::Browser => browser(&Operator::connect(&path)?),
        Cmd::Pane { entrypoint } => {
            Operator::connect(&path)?.snapshot()?;
            if std::env::var("HERDR_ENV").as_deref() == Ok("1") {
                open_pane(&path, &entrypoint)
            } else {
                ui::run(&path, &entrypoint)
            }
        }
    }
}

fn start_host(path: &Path, mission: Option<PathBuf>, executable: &Path) -> Result<()> {
    let parent = path.parent().context("Connection path needs a parent")?;
    private_dir(parent)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(parent.join("launch.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    if let Ok(operator) = Operator::connect(path) {
        if operator.snapshot().is_ok() {
            if let Some(mission) = mission {
                ensure!(std::path::absolute(mission)? == operator.connection.mission_root, "This workspace already has a different mission; use a separate connection descriptor");
            }
            return Ok(());
        }
    }
    let existing = if path.exists() {
        Some(Operator::connect(path)?.connection.mission_root)
    } else {
        None
    };
    let root = std::path::absolute(
        mission
            .or(existing)
            .unwrap_or_else(|| parent.join("mission")),
    )?;
    let log_path = parent.join("host.log");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let mut command = Command::new(executable);
    command
        .arg("--state")
        .arg(&root)
        .args(["console", "--no-open", "--connection-file"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // A new process group still belongs to Herdr's terminal session. Detach
    // the session itself so closing that PTY cannot terminate the mission.
    // SAFETY: setsid is an async-signal-safe syscall; this closure allocates
    // nothing and performs no locking between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("HERDR_") || key == "CHIO_HERDR_CONNECTION" {
            command.env_remove(key);
        }
    }
    let mut child = command
        .spawn()
        .context("Install Megastart or supply --megastart with its executable path")?;
    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "Mission host exited ({status}); inspect {}",
                log_path.display()
            );
        }
        if let Ok(operator) = Operator::connect(path) {
            if operator.connection.mission_root == root && operator.snapshot().is_ok() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!(
        "Host startup is unconfirmed; inspect {} before retrying",
        log_path.display()
    )
}

fn herdr(args: &[&str]) -> Result<Value> {
    ensure!(
        std::env::var("HERDR_ENV").as_deref() == Ok("1"),
        "Open this action inside Herdr"
    );
    ensure!(
        std::env::var_os("HERDR_SOCKET_PATH").is_some(),
        "Missing explicit Herdr session socket"
    );
    let output = Command::new(std::env::var_os("HERDR_BIN_PATH").unwrap_or_else(|| "herdr".into()))
        .args(args)
        .output()?;
    ensure!(
        output.status.success(),
        "Herdr refused workspace action: {}",
        client::text(&String::from_utf8_lossy(&output.stderr))
    );
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn open_pane(path: &Path, entrypoint: &str) -> Result<()> {
    let workspace =
        std::env::var("HERDR_WORKSPACE_ID").context("Open Chio from a specific workspace")?;
    let binding = path.with_extension(format!("{entrypoint}.pane.json"));
    if binding.exists() {
        let saved: Value = serde_json::from_slice(&fs::read(&binding)?)?;
        if saved["workspace"] == workspace {
            if let Some(id) = saved["pane"].as_str() {
                let executable = std::env::current_exe()?;
                let alive = herdr(&["pane", "process-info", "--pane", id])
                    .is_ok_and(|value| board_is_running(&value, &executable));
                if alive {
                    println!("Chio mission is already open in {id}. Select that pane to continue.");
                    return Ok(());
                }
            }
        }
    }
    let env = format!("CHIO_HERDR_CONNECTION={}", path.display());
    let placement = if entrypoint == "board" {
        "tab"
    } else {
        "overlay"
    };
    let result = herdr(&[
        "plugin",
        "pane",
        "open",
        "--plugin",
        "chio.megastart",
        "--entrypoint",
        entrypoint,
        "--placement",
        placement,
        "--workspace",
        &workspace,
        "--env",
        &env,
        "--focus",
    ])?;
    fn pane_id(value: &Value) -> Option<&str> {
        if let Some(id) = value.get("pane_id").and_then(Value::as_str) {
            return Some(id);
        }
        value.as_object()?.values().find_map(pane_id)
    }
    if let Some(id) = pane_id(&result) {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(binding)?;
        file.write_all(&serde_json::to_vec(
            &json!({"workspace":workspace,"pane":id}),
        )?)?;
    }
    Ok(())
}

fn board_is_running(value: &Value, executable: &Path) -> bool {
    value["result"]["process_info"]["foreground_processes"]
        .as_array()
        .is_some_and(|processes| {
            processes.iter().any(|process| {
                let argv = process["argv"].as_array();
                argv.is_some_and(|args| {
                    args.first()
                        .and_then(Value::as_str)
                        .is_some_and(|p| Path::new(p) == executable)
                        && args.iter().any(|arg| arg == "board")
                })
            })
        })
}

pub fn browser(operator: &Operator) -> Result<()> {
    let url = format!(
        "{}/#{}",
        operator.connection.endpoint, operator.connection.token
    );
    let status = Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    })
    .arg(url)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()?;
    ensure!(status.success(), "Could not open the browser");
    Ok(())
}

pub fn notify(path: &Path, snapshot: &client::Snapshot) -> Result<()> {
    if std::env::var("HERDR_ENV").as_deref() != Ok("1") {
        return Ok(());
    }
    let phase = snapshot.state["phase"].as_str().unwrap_or("");
    let title = match phase {
        "awaiting_review" => "Chio · candidate ready for your review",
        "blocked" | "interrupted" => "Chio · mission needs attention",
        "published" => "Chio · exact candidate published locally",
        _ => return Ok(()),
    };
    let record = path.with_extension("attention.json");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path.with_extension("attention.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let identity =
        json!({"phase":phase,"candidate":snapshot.state["proposal"]["candidate_sha256"]});
    if record.is_file() && serde_json::from_slice::<Value>(&fs::read(&record)?)? == identity {
        return Ok(());
    }
    // Coalesce across views and reconnects, including a failed delivery attempt.
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(record)?;
    file.write_all(&serde_json::to_vec(&identity)?)?;
    herdr(&[
        "notification",
        "show",
        title,
        "--body",
        "Open your Chio mission to inspect the retained decision.",
        "--sound",
        "none",
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_shell_is_not_a_live_mission_board() {
        let process =
            |argv| json!({"result":{"process_info":{"foreground_processes":[{"argv":argv}]}}});
        assert!(board_is_running(
            &process(json!(["/plugin/chio-herdr", "board"])),
            Path::new("/plugin/chio-herdr")
        ));
        assert!(!board_is_running(
            &process(json!(["/bin/zsh"])),
            Path::new("/plugin/chio-herdr")
        ));
        assert!(!board_is_running(
            &process(json!(["/other/chio-herdr", "board"])),
            Path::new("/plugin/chio-herdr")
        ));
    }
}
