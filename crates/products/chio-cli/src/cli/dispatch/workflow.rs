use super::*;

pub(crate) fn dispatch_workflow(
    command: WorkflowCommands,
    json_output: bool,
) -> Result<(), CliError> {
    match command {
        WorkflowCommands::Preflight { plan } => run_workflow_preflight(&plan, json_output),
    }
}

fn run_workflow_preflight(path: &Path, json_output: bool) -> Result<(), CliError> {
    let bytes = fs::read(path)?;
    let plan: chio_workflow::WorkflowPreflightPlan = serde_json::from_slice(&bytes)?;
    let report = chio_workflow::evaluate_workflow_preflight(&plan)
        .map_err(|error| CliError::cli_other_error(format!("workflow preflight: {error}")))?;

    if report.verdict == chio_workflow::WorkflowPreflightVerdict::Rejected {
        if json_output {
            let mut stdout = std::io::stdout();
            serde_json::to_writer(&mut stdout, &report)?;
            stdout.write_all(b"\n")?;
        }
        let reason = report
            .rejected_checks
            .first()
            .map(|check| check.message.as_str())
            .unwrap_or("preflight verifier rejected the plan");
        return Err(CliError::cli_other_error(format!(
            "workflow preflight rejected: {reason}"
        )));
    }

    let mut stdout = std::io::stdout();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
