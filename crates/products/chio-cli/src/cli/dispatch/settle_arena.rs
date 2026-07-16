// Dispatch handlers for the `chio settle` and `chio arena` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_settle(
    command: SettleCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    settlement_driver: &str,
) -> Result<(), CliError> {
    match command {
            SettleCommands::Status { store, json } => {
                let resolved = store.or_else(|| receipt_db.clone());
                match resolved {
                    Some(path) => match settle::cmd_settle_status(&path, json || json_output) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(CliError::Other(format!("settle status: {err}"))),
                    },
                    None => Err(CliError::Other(
                        "settle status: no store path supplied; pass --store or set --receipt-db"
                            .to_string(),
                    )),
                }
            }
            SettleCommands::Drive { store, batch, json } => {
                // The driver defaults to none so nothing changes until an
                // operator opts in explicitly.
                match settlement_driver {
                    "ops" => {}
                    "none" => {
                        return Err(CliError::Other(
                            "settle drive: the settlement driver is disabled; pass \
                             --settlement-driver ops to run the reference driver"
                                .to_string(),
                        ))
                    }
                    other => {
                        return Err(CliError::Other(format!(
                            "settle drive: unknown settlement driver `{other}` \
                             (expected `none` or `ops`)"
                        )))
                    }
                }
                let resolved = store.or_else(|| receipt_db.clone());
                match resolved {
                    Some(path) => {
                        match settle::cmd_settle_drive(&path, batch, json || json_output) {
                            Ok(_) => Ok(()),
                            Err(err) => Err(CliError::Other(format!("settle drive: {err}"))),
                        }
                    }
                    None => Err(CliError::Other(
                        "settle drive: no store path supplied; pass --store or set --receipt-db"
                            .to_string(),
                    )),
                }
            }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_arena(
    command: ArenaCommands,
    json_output: bool,
) -> Result<(), CliError> {
    match command {
            ArenaCommands::Run {
                scenario,
                output_root,
                json,
            } => cmd_arena_run(&scenario, output_root.as_deref(), json || json_output),
            ArenaCommands::Replay {
                scenario_id,
                output_root,
                bundle_dir,
                json,
            } => cmd_arena_replay(
                &scenario_id,
                output_root.as_deref(),
                bundle_dir.as_deref(),
                json || json_output,
            ),
            ArenaCommands::Evolve {
                seed,
                generations,
                wall_seconds,
                output_root,
                json,
            } => cmd_arena_evolve(
                &seed,
                generations,
                wall_seconds,
                output_root.as_deref(),
                json || json_output,
            ),
    }
}
