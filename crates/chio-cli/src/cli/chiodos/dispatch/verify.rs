fn cmd_chiodos_verify(
    package: &Path,
    trust_bundle: &Path,
    context: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let package_bytes = fs::read(package).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos proof package {}: {error}",
            package.display()
        ))
    })?;
    let package = chio_chiodos::proof_package_from_json(
        std::str::from_utf8(&package_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos proof package {} is not UTF-8 JSON: {error}",
                package.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_bytes = fs::read(trust_bundle).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos verifier trust bundle {}: {error}",
            trust_bundle.display()
        ))
    })?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(
        std::str::from_utf8(&trust_bundle_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos verifier trust bundle {} is not UTF-8 JSON: {error}",
                trust_bundle.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}")))?;
    let context_bytes = fs::read(context).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos verification context {}: {error}",
            context.display()
        ))
    })?;
    let context = chio_chiodos::verification_context_from_json(
        std::str::from_utf8(&context_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos verification context {} is not UTF-8 JSON: {error}",
                context.display()
            ))
        })?,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
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
        .map_err(|error| CliError::cli_other_error(format!("Chiodos report JSON: {error}")))?;
    fs::write(report, report_json).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to write Chiodos verifier report {}: {error}",
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
            "Chiodos verify rejected package: {failure}"
        )))
    }
}

