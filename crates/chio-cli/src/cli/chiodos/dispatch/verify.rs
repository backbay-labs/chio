use crate::CliError;
use std::fs;
use std::path::Path;

pub(crate) fn cmd_chiodos_verify(
    package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report: &Path,
) -> Result<(), CliError> {
    cmd_chio_attest_legacy_chiodos_v1_verify(package, trust_bundle, context, report)
}

pub(crate) fn cmd_chio_attest_legacy_chiodos_v1_verify(
    package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let package_bytes = fs::read(package).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio legacy Chiodos v1 proof package {}: {error}",
            package.display()
        ))
    })?;
    let package = chio_chiodos::proof_package_from_json(
        std::str::from_utf8(&package_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio legacy Chiodos v1 proof package {} is not UTF-8 JSON: {error}",
                package.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio legacy package parse: {error}")))?;
    let trust_bundle_bytes = fs::read(trust_bundle).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio legacy Chiodos v1 verifier trust bundle {}: {error}",
            trust_bundle.display()
        ))
    })?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(
        std::str::from_utf8(&trust_bundle_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio legacy Chiodos v1 verifier trust bundle {} is not UTF-8 JSON: {error}",
                trust_bundle.display()
            ))
        })?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio legacy trust bundle parse: {error}"))
    })?;
    let context_bytes = fs::read(context).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio legacy Chiodos v1 verification context {}: {error}",
            context.display()
        ))
    })?;
    let context = chio_chiodos::verification_context_from_json(
        std::str::from_utf8(&context_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio legacy Chiodos v1 verification context {} is not UTF-8 JSON: {error}",
                context.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio legacy context parse: {error}")))?;
    let verifier_report = chio_chiodos::verify_package_report(&package, &trust_bundle, &context);
    if let Some(parent) = report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create report directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    let report_json = chio_chiodos::report_json(&verifier_report)
        .map_err(|error| CliError::cli_other_error(format!("Chio legacy report JSON: {error}")))?;
    fs::write(report, report_json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chio legacy Chiodos v1 verifier report {}: {error}",
            report.display()
        ))
    })?;
    if verifier_report.accepted {
        Ok(())
    } else {
        let failure = verifier_report.failure.as_ref().map_or_else(
            || "unknown verifier rejection".to_string(),
            |failure| format!("{}: {}", failure.code, failure.detail),
        );
        Err(CliError::cli_other_error(format!(
            "Chio legacy Chiodos v1 verify rejected package: {failure}"
        )))
    }
}
