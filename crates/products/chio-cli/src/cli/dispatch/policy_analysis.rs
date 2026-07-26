use super::*;

const ANALYSIS_EXIT_FINDINGS: i32 = 1;
const ANALYSIS_EXIT_FAILURE: i32 = 2;
const ANALYSIS_ERROR_SCHEMA: &str = "chio.policy-analysis.error.v1";

pub(super) fn dispatch_policy(command: PolicyCommands, json_output: bool) -> Result<(), CliError> {
    match command {
        PolicyCommands::Analyze {
            policy,
            against,
            fail_on,
            format,
            max_atoms,
        } => {
            let json_output = json_output || matches!(format, Some(OutputFormat::Json));
            let options = chio_policy::AnalysisOptions {
                max_atoms,
                ..chio_policy::AnalysisOptions::default()
            };
            let report = (|| {
                let policy = chio_policy::resolve_from_path(&policy)
                    .map_err(|error| format!("failed to load {}: {error}", policy.display()))?;
                match against.as_ref() {
                    Some(against_path) => {
                        let against =
                            chio_policy::resolve_from_path(against_path).map_err(|error| {
                                format!(
                                    "failed to load comparison policy {}: {error}",
                                    against_path.display()
                                )
                            })?;
                        chio_policy::analyze_against(&policy, &against, options)
                            .map_err(|error| error.to_string())
                    }
                    None => {
                        chio_policy::analyze(&policy, options).map_err(|error| error.to_string())
                    }
                }
            })();

            let report = match report {
                Ok(report) => report,
                Err(error) => exit_analysis_failure(&error, json_output),
            };
            if let Err(error) = write_analysis_report(&report, json_output) {
                exit_analysis_failure(
                    &format!("failed to write analysis report: {error}"),
                    json_output,
                );
            }

            let threshold = match fail_on {
                PolicyAnalysisFailOn::Notice => chio_policy::AnalysisSeverity::Notice,
                PolicyAnalysisFailOn::Warning => chio_policy::AnalysisSeverity::Warning,
                PolicyAnalysisFailOn::Error => chio_policy::AnalysisSeverity::Error,
            };
            if report.has_at_or_above(threshold) {
                std::process::exit(ANALYSIS_EXIT_FINDINGS);
            }
            Ok(())
        }
    }
}

fn write_analysis_report(
    report: &chio_policy::AnalysisReport,
    json_output: bool,
) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    if json_output {
        serde_json::to_writer_pretty(&mut stdout, report).map_err(std::io::Error::other)?;
        writeln!(stdout)?;
        return Ok(());
    }

    writeln!(stdout, "policy_sha256  {}", report.policy_sha256)?;
    if let Some(against) = &report.against_sha256 {
        writeln!(stdout, "against_sha256 {}", against)?;
    }
    if let Some(refinement) = &report.refinement {
        writeln!(stdout, "refinement     {}", refinement.status.as_str())?;
    }
    writeln!(stdout)?;
    writeln!(
        stdout,
        "ID           SEVERITY  KIND                  BLOCK                 RULE"
    )?;
    for finding in &report.findings {
        writeln!(
            stdout,
            "{:<12} {:<9} {:<21} {:<21} {}[{}]",
            finding.id,
            finding.severity.as_str(),
            finding.kind.as_str(),
            finding.block,
            finding.rule_ref.field,
            finding.rule_ref.index
        )?;
        writeln!(stdout, "                      {}", finding.message)?;
        if let Some(witness) = &finding.witness {
            writeln!(
                stdout,
                "                      witness: {} target={}",
                witness.action_type,
                serde_json::to_string(&witness.target).map_err(std::io::Error::other)?
            )?;
        }
    }
    for coverage in &report.not_analyzed {
        writeln!(
            stdout,
            "-            notice    not_analyzed          {:<21} {}",
            coverage.block, coverage.field
        )?;
        writeln!(stdout, "                      {}", coverage.reason)?;
    }
    writeln!(
        stdout,
        "\nsummary: {} error(s), {} warning(s), {} notice(s)",
        report.summary.errors, report.summary.warnings, report.summary.notices
    )
}

fn exit_analysis_failure(error: &str, json_output: bool) -> ! {
    if json_output {
        let payload = serde_json::json!({
            "schema": ANALYSIS_ERROR_SCHEMA,
            "error": error,
        });
        let mut stderr = std::io::stderr().lock();
        let _ = serde_json::to_writer(&mut stderr, &payload);
        let _ = writeln!(stderr);
    } else {
        eprintln!("policy analysis failed: {error}");
    }
    std::process::exit(ANALYSIS_EXIT_FAILURE);
}
