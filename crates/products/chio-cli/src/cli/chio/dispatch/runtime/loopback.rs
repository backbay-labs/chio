use std::fs;
use std::path::Path;

use crate::CliError;

pub(crate) fn cmd_chio_runtime_run_loopback(
    scenario: &Path,
    static_package: Option<&Path>,
    static_report: Option<&Path>,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), CliError> {
    match (static_package, static_report) {
        (Some(static_package), Some(static_report)) => {
            let static_package_json =
                read_runtime_loopback_baseline(static_package, "static proof package")?;
            let static_report_json =
                read_runtime_loopback_baseline(static_report, "static verifier report")?;
            chio_runtime_harness::run_runtime_loopback_scenario_with_static_artifacts(
                scenario,
                store_dir,
                now_unix_ms,
                out_dir,
                &static_package_json,
                &static_report_json,
            )
        }
        (None, None) => chio_runtime_harness::run_runtime_loopback_scenario(
            scenario,
            store_dir,
            now_unix_ms,
            out_dir,
        ),
        _ => {
            return Err(CliError::cli_other_error(
                "Chio runtime loopback requires --static-package and --static-report together",
            ))
        }
    }
    .map_err(|error| CliError::cli_other_error(format!("Chio runtime loopback: {error}")))
}

fn read_runtime_loopback_baseline(path: &Path, label: &str) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio runtime loopback {label} {}: {error}",
            path.display()
        ))
    })
}
