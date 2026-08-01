// `chio doctor` clap subcommand glue.
//
// Included from `crates/products/chio-cli/src/main.rs`. Owns the `DoctorArgs`
// type, the rendering of probe reports, and the entry point
// `cmd_doctor` invoked from `dispatch.rs`.
//
// `Write` is already brought in by `cli/types.rs`; this file is
// `include!`-d into the same module so no additional `use` is needed.

use super::*;

use crate::doctor::{DoctorRun, DoctorRunner, ProbeConfig, ProbeReport, ProbeSeverity};

/// Arguments for `chio doctor`.
#[derive(clap::Args, Debug)]
pub struct DoctorArgs {
    /// Emit a structured JSON report on stdout instead of human text.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Run idempotent repairs after probes complete. Destructive
    /// repairs are explicitly rejected.
    #[arg(long, default_value_t = false)]
    pub fix: bool,

    /// Skip probes that would otherwise reach the network. Useful in
    /// CI sandboxes; equivalent to `CHIO_DOCTOR_SKIP_NETWORK=1`.
    #[arg(long, default_value_t = false)]
    pub skip_network: bool,
}

/// Entry point invoked from `dispatch.rs`.
///
/// `cmd_doctor` short-circuits the generic `dispatch.rs` `exit(1)` path
/// so the process exit code matches the contract documented on
/// `Commands::Doctor` and on `DoctorRun::exit_code()`: 0 for ok / info /
/// warning, 1 for error, 2 for fatal. The doctor JSON envelope reports
/// the same numeric code via the `exit_code` field, so downstream CI
/// gates that branch on Fatal vs Error stay consistent with both
/// channels.
pub fn cmd_doctor(args: &DoctorArgs, json_output: bool) -> Result<(), CliError> {
    let config = ProbeConfig {
        skip_network: args.skip_network || std::env::var("CHIO_DOCTOR_SKIP_NETWORK").is_ok(),
        fix_enabled: args.fix,
        workdir: None,
    };
    let runner = DoctorRunner::standard(config);
    let run = runner.run();

    let render_json = args.json || json_output;
    {
        let mut stdout = std::io::stdout().lock();
        if render_json {
            render_doctor_json(&mut stdout, &run).map_err(|err| {
                CliError::cli_other_error(format!("doctor: failed to render JSON output: {err}"))
            })?;
        } else {
            render_doctor_human(&mut stdout, &run).map_err(|err| {
                CliError::cli_other_error(format!("doctor: failed to render human output: {err}"))
            })?;
        }
    }

    let code = run.exit_code();
    if code == 0 {
        Ok(())
    } else {
        // Bypass the generic `dispatch.rs` error renderer + exit(1) so
        // the worst-severity exit code (1 for Error, 2 for Fatal)
        // reaches the process and stays in lockstep with the
        // `exit_code` field already serialized in the JSON envelope.
        std::process::exit(code);
    }
}

pub(crate) fn render_doctor_json(writer: &mut impl Write, run: &DoctorRun) -> std::io::Result<()> {
    let payload = serde_json::json!({
        "schema": "chio.doctor.v1",
        "worst": run.worst,
        "exit_code": run.exit_code(),
        "reports": run.reports,
    });
    serde_json::to_writer(&mut *writer, &payload).map_err(std::io::Error::other)?;
    writeln!(writer)
}

pub(crate) fn render_doctor_human(writer: &mut impl Write, run: &DoctorRun) -> std::io::Result<()> {
    writeln!(writer, "chio doctor")?;
    for report in &run.reports {
        write_doctor_report(writer, report)?;
    }
    writeln!(writer)?;
    writeln!(
        writer,
        "summary: worst severity = {}, exit code = {}",
        run.worst,
        run.exit_code()
    )
}

pub(crate) fn write_doctor_report(
    writer: &mut impl Write,
    report: &ProbeReport,
) -> std::io::Result<()> {
    let marker = match report.severity {
        ProbeSeverity::Ok => "[ok]",
        ProbeSeverity::Info => "[info]",
        ProbeSeverity::Warning => "[warn]",
        ProbeSeverity::Error => "[error]",
        ProbeSeverity::Fatal => "[fatal]",
    };
    writeln!(
        writer,
        "  {marker} {} ({}): {}",
        report.probe, report.code, report.message
    )?;
    if let Some(help) = &report.help {
        writeln!(writer, "    help: {help}")?;
    }
    for ctx in &report.context {
        writeln!(writer, "    {}: {}", ctx.key, ctx.value)?;
    }
    if report.repaired {
        writeln!(writer, "    repaired: yes")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod doctor_cli_tests {
    use super::*;
    use crate::doctor::{DoctorRun, ProbeReport, ProbeSeverity};

    #[test]
    fn render_json_emits_schema_envelope() {
        let run = DoctorRun {
            reports: vec![ProbeReport::ok("toolchain", "ok")],
            worst: ProbeSeverity::Ok,
        };
        let mut buf = Vec::new();
        render_doctor_json(&mut buf, &run).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["schema"], "chio.doctor.v1");
        assert_eq!(parsed["worst"], "ok");
        assert_eq!(parsed["exit_code"], 0);
    }

    #[test]
    fn render_human_includes_marker_and_summary() {
        let run = DoctorRun {
            reports: vec![ProbeReport::fail(
                "toolchain",
                ProbeSeverity::Error,
                "urn:chio:error:cli:doctor-toolchain-mismatch",
                "boom",
            )],
            worst: ProbeSeverity::Error,
        };
        let mut buf = Vec::new();
        render_doctor_human(&mut buf, &run).unwrap();
        let body = String::from_utf8(buf).unwrap();
        assert!(body.contains("[error]"));
        assert!(body.contains("urn:chio:error:cli:doctor-toolchain-mismatch"));
        assert!(body.contains("worst severity = error"));
    }
}
