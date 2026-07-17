use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod commands;
mod metrics_server;
mod registry_metrics_sink;

/// Chio-Wall control-path tooling on top of Chio.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: human-readable or JSON.
    #[arg(long, global = true, default_value = "false")]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Export or validate the bounded Chio-Wall control-path package.
    ControlPath {
        #[command(subcommand)]
        command: ControlPathCommands,
    },

    /// Run the SIEM export serve loop (at-least-once, persisted high-water mark)
    /// against a receipt database until interrupted.
    SiemExport {
        /// Path to the Chio kernel receipt SQLite database (read-only).
        #[arg(long)]
        receipt_db: PathBuf,

        /// Path to the SIEM-owned RW cursor store for the per-exporter
        /// high-water mark (created if absent).
        #[arg(long)]
        cursor_db: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControlPathCommands {
    /// Export the bounded control-path package and Chio evidence bundle.
    Export {
        /// Output directory for the generated Chio-Wall control-path package.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate the validation report and explicit expansion decision.
    Validate {
        /// Output directory for the generated Chio-Wall validation package.
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> Result<(), chio_control_plane::CliError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::ControlPath { command } => match command {
            ControlPathCommands::Export { output } => {
                commands::cmd_chio_wall_control_path_export(&output, cli.json)
            }
            ControlPathCommands::Validate { output } => {
                commands::cmd_chio_wall_control_path_validate(&output, cli.json)
            }
        },
        Commands::SiemExport {
            receipt_db,
            cursor_db,
        } => commands::cmd_chio_wall_siem_export(&receipt_db, &cursor_db),
    }
}
