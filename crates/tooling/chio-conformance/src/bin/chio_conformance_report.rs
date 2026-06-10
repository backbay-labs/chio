use std::fs;
use std::path::PathBuf;

use chio_conformance::{
    generate_markdown_report, load_results_from_dir, load_scenarios_from_dir, CompatibilityReport,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let scenarios_dir = next_path(&mut args, "--scenarios-dir")?;
    let results_dir = next_path(&mut args, "--results-dir")?;
    let output_path = next_path(&mut args, "--output")?;

    if args.next().is_some() {
        return Err("unexpected trailing arguments".into());
    }

    let report = CompatibilityReport {
        scenarios: load_scenarios_from_dir(&scenarios_dir)?,
        results: load_results_from_dir(&results_dir)?,
    };
    let markdown = generate_markdown_report(&report);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, markdown)?;
    Ok(())
}

fn next_path(
    args: &mut impl Iterator<Item = String>,
    expected_flag: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match args.next() {
        Some(flag) if flag == expected_flag => match args.next() {
            Some(value) => Ok(PathBuf::from(value)),
            None => Err(format!("missing value for {expected_flag}").into()),
        },
        Some(flag) => Err(format!("expected {expected_flag}, got {flag}").into()),
        None => Err(format!("expected {expected_flag}").into()),
    }
}
