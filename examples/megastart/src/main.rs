use anyhow::{Context, Result};
use chio_megastart::{
    mission::{inspect, Mission},
    read,
};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Bring up a governed system of research, implementation, and review workers")]
struct Cli {
    #[arg(long, default_value = "mission", global = true)]
    state: PathBuf,
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Open the local operating console; this is the default command.
    Console {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_open: bool,
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
    #[command(hide = true)]
    Worker { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Action::Console {
        port: 0,
        no_open: false,
    }) {
        Action::Console { port, no_open } => {
            return chio_megastart::operator::serve(cli.state, port, !no_open).await
        }
        Action::Review => return chio_megastart::operator::review(&cli.state).await,
        Action::Exercise => return exercise(&cli.state).await,
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
    for args in [
        vec!["recover"],
        vec!["drill", "authority"],
        vec!["drill", "allowance"],
        vec!["drill", "approval"],
    ] {
        let status = tokio::process::Command::new(&exe)
            .arg("--state")
            .arg(&exercise)
            .args(args)
            .status()
            .await?;
        anyhow::ensure!(
            status.success(),
            "Protection exercise failed; inspect the retained exercise mission"
        );
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
