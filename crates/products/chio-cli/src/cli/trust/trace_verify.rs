use super::*;
use crate::types_cli::TrustTraceSpec;

pub(crate) fn cmd_trust_trace_verify(
    log: &Path,
    trusted_keys: &[String],
    _spec: TrustTraceSpec,
    apalache_bin: &Path,
    timeout_secs: u64,
    itf_output: Option<&Path>,
    report_output: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let trusted_observer_keys = trusted_keys
        .iter()
        .map(|key| chio_core::crypto::PublicKey::from_hex(key).map_err(CliError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let report = chio_trace_validate::validate_file(&chio_trace_validate::ValidationOptions {
        log_path: log.to_path_buf(),
        trusted_observer_keys,
        apalache_bin: apalache_bin.to_path_buf(),
        timeout_secs,
        itf_output: itf_output.map(Path::to_path_buf),
        witness_output: None,
        minimum_revoke: 0,
        minimum_post_revocation_evaluate: 0,
    })
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    if let Some(path) = report_output {
        chio_trace_validate::write_report(path, &report)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
        );
    } else {
        println!(
            "{}: {}; trace length {}; invariants {}",
            report.spec,
            report.status.as_str(),
            report.trace_length,
            report.invariants.join(", ")
        );
    }

    if report.status == chio_trace_validate::ValidationStatus::Failed {
        let divergence = report.divergence.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "failed trace report is missing divergence details".to_string(),
            )
        })?;
        return Err(CliError::cli_other_error(format!(
            "trace diverged at step {} ({}); projected step {}; last reachable state {}; triage with {}",
            divergence.step,
            divergence.failed_conjunct,
            divergence.projected_step,
            divergence.last_reachable_state,
            divergence.triage_template
        )));
    }
    Ok(())
}
