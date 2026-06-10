use std::path::PathBuf;

use chio_conformance::{
    default_native_run_options, run_native_conformance_suite, NativeConformanceRunSummary,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = default_native_run_options();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--scenarios-dir" => options.scenarios_dir = next_path(&mut args, &flag)?,
            "--results-output" => options.results_output = next_path(&mut args, &flag)?,
            "--report-output" => options.report_output = next_path(&mut args, &flag)?,
            "--peer-label" => options.peer_label = next_string(&mut args, &flag)?,
            "--stdio-command" => options.stdio_command = Some(next_path(&mut args, &flag)?),
            "--http-base-url" => options.http_base_url = Some(next_string(&mut args, &flag)?),
            other => return Err(format!("unexpected flag: {other}").into()),
        }
    }

    let summary = run_native_conformance_suite(&options)?;
    print_summary(&summary);
    Ok(())
}

fn print_summary(summary: &NativeConformanceRunSummary) {
    println!("scenarios: {}", summary.scenario_count);
    println!("results:   {}", summary.results_output.display());
    println!("report:    {}", summary.report_output.display());
}

fn next_path(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(next_string(args, flag)?))
}

fn next_string(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}
