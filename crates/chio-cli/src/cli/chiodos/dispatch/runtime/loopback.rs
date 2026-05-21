use std::path::Path;

use crate::CliError;

pub(crate) fn cmd_chiodos_runtime_run_loopback(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), CliError> {
    cmd_chio_runtime_run_loopback(scenario, store_dir, now_unix_ms, out_dir)
}

pub(crate) fn cmd_chio_runtime_run_loopback(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), CliError> {
    chio_chiodos_runtime_harness::run_runtime_loopback_scenario(
        scenario,
        store_dir,
        now_unix_ms,
        out_dir,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio runtime loopback: {error}")))
}
