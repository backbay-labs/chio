use anyhow::{Context, Result};
use chio_megastart::{
    mission::{inspect, Mission},
    read,
};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Bring up a governed system of research, implementation, and review workers"
)]
struct Cli {
    #[arg(long, default_value = "mission", global = true)]
    state: PathBuf,
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Print the installer compatibility contract without opening a workspace.
    WorkshopVersion,
    /// Prepare a pinned native integration using your existing login.
    #[cfg(feature = "native-agents")]
    Connect {
        #[arg(value_enum)]
        agent: chio_megastart::agents::launcher::Agent,
    },
    #[cfg(feature = "native-agents")]
    #[command(hide = true)]
    NativeInit {
        configuration: PathBuf,
        #[arg(long, default_value = "project")]
        project: PathBuf,
        #[arg(long, default_value_t = 64)]
        allowance: u32,
    },
    #[cfg(feature = "native-agents")]
    #[command(hide = true)]
    NativeTask {
        worker: PathBuf,
        installation: PathBuf,
        prompt: PathBuf,
    },
    #[cfg(feature = "native-agents")]
    #[command(hide = true)]
    NativeResource { root: PathBuf },
    #[cfg(feature = "native-agents")]
    #[command(hide = true)]
    NativeCheckpoint {
        #[arg(long, default_value = "project")]
        project: PathBuf,
        #[arg(long, default_value_t = 59330)]
        port: u16,
        #[arg(long, default_value_t = 64)]
        allowance: u32,
    },
    /// Open a retained local workshop. Importing a setup never starts work.
    Workshop {
        #[arg(long, conflicts_with = "workspace")]
        setup: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Open the local operating console; this is the default command.
    Console {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_open: bool,
        /// Write a private, versioned connection descriptor for operator clients.
        #[arg(long)]
        connection_file: Option<PathBuf>,
    },
    /// Inspect the candidate and explicitly approve local publication.
    Review,
    /// Run protection exercises in a separate reference mission.
    Exercise,
    /// Reconnect to retained work without minting a new allowance.
    Resume,
    /// Copy a trusted Rust regression project and allocate one mission allowance.
    Init {
        #[arg(long, default_value = "project")]
        project: PathBuf,
        #[arg(long, default_value_t = 6)]
        allowance: u32,
    },
    /// Start the processes and run the mission to its publication proposal.
    Run {
        #[arg(long)]
        crash_after_repair: bool,
    },
    /// Reconcile completed operations before continuing an interrupted mission.
    Recover,
    /// Exercise a real request that must stop at admission.
    Drill {
        #[arg(value_parser = ["authority", "allowance", "approval"])]
        kind: String,
    },
    /// Inspect the exact candidate and its retained review before approval.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// The local release owner signs a decision bound to this candidate.
    Approve {
        #[arg(long)]
        candidate: String,
    },
    /// Verify retained outcomes with an independently selected signer key.
    Verify {
        #[arg(long)]
        trusted_key: String,
    },
    /// Export the evidence without the original database or private keys.
    Export {
        #[arg(long, default_value = "evidence")]
        output: PathBuf,
    },
    /// Print this mission's kernel public key for independent trust selection.
    Key,
    #[command(hide = true)]
    Coordinator { name: String },
    #[cfg(feature = "native-agents")]
    #[command(hide = true)]
    NativeCoordinator { name: String },
    #[command(hide = true)]
    Worker { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Action::Console {
        port: 0,
        no_open: false,
        connection_file: None,
    }) {
        Action::WorkshopVersion => {
            println!("chio-workshop-pair-v1 {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        #[cfg(feature = "native-agents")]
        Action::Connect { agent } => {
            return chio_megastart::agents::connections::prepare(agent).await
        }
        Action::Workshop {
            setup,
            workspace,
            port,
            no_open,
        } => {
            let setup = setup
                .as_deref()
                .map(chio_megastart::workshop::setup::Setup::decode)
                .transpose()?;
            let root = chio_megastart::workshop::workspace::launch(setup, workspace.as_deref())?;
            return chio_megastart::operator::serve_workspace(root, port, !no_open).await;
        }
        Action::Console {
            port,
            no_open,
            connection_file,
        } => {
            return chio_megastart::operator::serve_connected(
                cli.state,
                port,
                !no_open,
                connection_file,
            )
            .await
        }
        #[cfg(feature = "native-agents")]
        Action::NativeInit {
            configuration,
            project,
            allowance,
        } => {
            let selected: chio_megastart::agents::mission::Configuration = read(&configuration)?;
            selected.validate()?;
            Mission::initialize(&cli.state, &project, allowance)?;
            let path = cli.state.join("mission.json");
            let mut config: chio_megastart::mission::Config = read(&path)?;
            config.native = Some(selected);
            chio_agent_os_shared::runtime::files::replace(
                &path,
                &serde_json::to_vec_pretty(&config)?,
            )?;
            return Ok(());
        }
        #[cfg(feature = "native-agents")]
        Action::NativeResource { root } => {
            return chio_megastart::agents::resource::serve(&root).await
        }
        #[cfg(feature = "native-agents")]
        Action::NativeCheckpoint {
            project,
            port,
            allowance,
        } => {
            return chio_megastart::agents::service::checkpoint(
                &cli.state, &project, port, allowance,
            )
            .await
        }
        #[cfg(feature = "native-agents")]
        Action::NativeTask {
            worker,
            installation,
            prompt,
        } => {
            let selected = read(&installation)?;
            let prompt = chio_agent_os_shared::runtime::files::read_text(&prompt, 64_000)?;
            let result =
                chio_megastart::agents::launcher::task(&worker, &selected, &prompt).await?;
            println!(
                "{}",
                serde_json::json!({"agent":result["agent"],"worker":result["worker"],"session":result["session"],"native_exit":result["native_exit"],"unresolved":result["unresolved"],"task":result["task"],"operations":result["operations"].as_array().map(Vec::len)})
            );
            return Ok(());
        }
        Action::Review => return chio_megastart::operator::review(&cli.state).await,
        Action::Exercise => return exercise(&cli.state).await,
        #[cfg(feature = "native-agents")]
        Action::NativeCoordinator { name } => {
            return chio_megastart::protocol::native_coordinator(&name).await
        }
        Action::Coordinator { name } => return chio_megastart::protocol::coordinator(&name).await,
        Action::Worker { name } => return chio_megastart::protocol::worker(&name).await,
        Action::Init { project, allowance } => {
            return Mission::initialize(&cli.state, &project, allowance)
        }
        Action::Export { output } => return chio_megastart::mission::export(&cli.state, &output),
        Action::Key => {
            let key: Value = read(&cli.state.join("kernel/trusted-kernel.json"))?;
            println!(
                "{}",
                key["public_key"]
                    .as_str()
                    .context("No retained public key")?
            );
            return Ok(());
        }
        Action::Verify { trusted_key } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&inspect(&cli.state, &trusted_key)?)?
            );
            return Ok(());
        }
        Action::Status { json } => return chio_megastart::operator::status(&cli.state, json),
        action => {
            let mission = Mission::open(&cli.state)?;
            let work = async {
                match action {
                    Action::Run { crash_after_repair } => mission.run(crash_after_repair).await,
                    Action::Recover | Action::Resume => mission.run(false).await,
                    Action::Drill { kind } if kind == "approval" => {
                        let proposal: Value = read(&cli.state.join("proposal.json"))?;
                        mission
                            .publish(
                                proposal["candidate_sha256"]
                                    .as_str()
                                    .context("No reviewed candidate")?,
                                false,
                            )
                            .await
                    }
                    Action::Drill { kind } => mission.drill(&kind).await,
                    Action::Approve { candidate } => mission.publish(&candidate, true).await,
                    _ => unreachable!("non-executing commands returned above"),
                }
            };
            tokio::select! {
                result = work => result,
                result = tokio::signal::ctrl_c() => {
                    result?;
                    anyhow::bail!("Interrupted. State is retained; use recover before retrying operations.")
                }
            }
        }
    }
}

async fn exercise(root: &std::path::Path) -> Result<()> {
    let exercise = root.with_file_name(format!("megastart-exercise-{}", uuid::Uuid::new_v4()));
    chio_megastart::operator::initialize(&exercise, None, false)?;
    chio_megastart::journal::emit(
        root,
        "exercise.started",
        "owner",
        serde_json::json!({"mission":exercise}),
    )?;
    let exe = std::env::current_exe()?;
    let status = tokio::process::Command::new(&exe)
        .arg("--state")
        .arg(&exercise)
        .args(["run", "--crash-after-repair"])
        .status()
        .await?;
    anyhow::ensure!(
        status.code() == Some(75),
        "Exercise did not reach its documented interruption"
    );
    let retained = effect_hashes(&exercise)?;
    anyhow::ensure!(
        retained.len() == 4,
        "Interruption must retain four completed effects"
    );
    chio_megastart::journal::emit(
        root,
        "exercise.interrupted",
        "host",
        serde_json::json!({"mission":exercise,"retained_effects":retained.len(),"next":"Reconcile original operations before continuing"}),
    )?;
    for args in [
        vec!["recover"],
        vec!["drill", "authority"],
        vec!["drill", "allowance"],
        vec!["drill", "approval"],
    ] {
        let status = tokio::process::Command::new(&exe)
            .arg("--state")
            .arg(&exercise)
            .args(&args)
            .status()
            .await?;
        anyhow::ensure!(
            status.success(),
            "Protection exercise failed; inspect the retained exercise mission"
        );
        let after = effect_hashes(&exercise)?;
        anyhow::ensure!(
            retained
                .iter()
                .all(|(name, hash)| after.get(name) == Some(hash)),
            "Recovery or refusal changed an original completed effect"
        );
        anyhow::ensure!(
            after.len() == 6,
            "Expected exactly six completed effects after recovery"
        );
        chio_megastart::journal::emit(
            root,
            if args[0] == "recover" {
                "exercise.recovered"
            } else {
                "exercise.refused"
            },
            "host",
            serde_json::json!({"mission":exercise,"check":args.last(),"retained_effects_unchanged":retained.len(),"completed_effects":after.len()}),
        )?;
    }
    chio_megastart::journal::emit(
        root,
        "exercise.completed",
        "owner",
        serde_json::json!({"mission":exercise,"recovery":"Original completed operations reconciled","authority":"Protected file unchanged","allowance":"No additional effect","publication":"Not authorized"}),
    )?;
    println!("Exercises passed: refused effects, shared allowance, recovery, and approval. Your working mission is unchanged.");
    Ok(())
}

fn effect_hashes(root: &std::path::Path) -> Result<std::collections::BTreeMap<String, String>> {
    let mut hashes = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(root.join("effects"))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let bytes = chio_agent_os_shared::runtime::files::read_bounded(&path, 2_000_000)?;
            hashes.insert(
                path.file_name()
                    .context("Effect has no name")?
                    .to_string_lossy()
                    .into_owned(),
                chio_core::sha256_hex(&bytes),
            );
        }
    }
    Ok(hashes)
}
