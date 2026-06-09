use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod commands;

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
    }
}
