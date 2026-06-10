//! `ttfrh-bench` binary entry point.
//!
//! The TTFRH gate invokes:
//!
//! ```text
//! cargo run -p ttfrh-bench --release -- --all --p99-budget-ms 60000
//! ```
//!
//! followed by a workflow grep for `required: true`. This binary parses
//! the CLI surface (no clap dep), runs every configured template
//! plan against the configured budget, and prints a per-template line.
//! Exit code 1 indicates at least one breach.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use ttfrh_bench::{run_all, Budget, BudgetError, RunnerReport, TemplateRunner};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    All,
    One(TemplateRunner),
}

#[derive(Debug, Clone, Copy)]
struct CliArgs {
    selection: Selection,
    budget: Budget,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("expected value after {0}")]
    MissingValue(&'static str),
    #[error("invalid budget value: {0}")]
    InvalidBudget(String),
    #[error("invalid buffer value: {0}")]
    InvalidBuffer(String),
    #[error("unknown template '{0}'")]
    UnknownTemplate(String),
    #[error("unknown argument '{0}'")]
    UnknownArg(String),
    #[error(transparent)]
    Budget(#[from] BudgetError),
}

fn parse_args(argv: &[String]) -> Result<CliArgs, CliError> {
    let mut selection = Selection::All;
    let mut budget_ms: u64 = ttfrh_bench::DEFAULT_BUDGET_MS;
    let mut buffer_pct: u8 = ttfrh_bench::DEFAULT_BUFFER_PCT;
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--all" => selection = Selection::All,
            "--template" => {
                let value = iter.next().ok_or(CliError::MissingValue("--template"))?;
                selection = Selection::One(parse_template(value)?);
            }
            "--p99-budget-ms" => {
                let value = iter
                    .next()
                    .ok_or(CliError::MissingValue("--p99-budget-ms"))?;
                budget_ms = value
                    .parse::<u64>()
                    .map_err(|_| CliError::InvalidBudget(value.clone()))?;
            }
            "--buffer-pct" => {
                let value = iter.next().ok_or(CliError::MissingValue("--buffer-pct"))?;
                buffer_pct = value
                    .parse::<u8>()
                    .map_err(|_| CliError::InvalidBuffer(value.clone()))?;
            }
            other => return Err(CliError::UnknownArg(other.to_owned())),
        }
    }
    let budget = Budget::new(budget_ms, buffer_pct)?;
    Ok(CliArgs { selection, budget })
}

fn parse_template(value: &str) -> Result<TemplateRunner, CliError> {
    for template in TemplateRunner::ALL {
        if template.slug() == value {
            return Ok(template);
        }
    }
    Err(CliError::UnknownTemplate(value.to_owned()))
}

fn print_report(report: &RunnerReport, budget: Budget) {
    let status = if report.within_budget { "ok" } else { "FAIL" };
    println!(
        "[{}] {} p50={}ms p99={}ms budget={}ms+{}% effective={}ms samples={}",
        status,
        report.template,
        report.p50.as_millis(),
        report.p99.as_millis(),
        budget.budget_ms,
        budget.buffer_pct,
        budget.effective_ms(),
        report.samples,
    );
}

fn run(argv: &[String]) -> Result<bool, CliError> {
    let args = parse_args(argv)?;
    let reports: Vec<RunnerReport> = match args.selection {
        Selection::All => run_all(args.budget),
        Selection::One(template) => ttfrh_bench::runner_plans()
            .iter()
            .filter(|plan| plan.template == template)
            .map(|plan| ttfrh_bench::run_plan(plan, args.budget))
            .collect(),
    };
    let mut all_ok = true;
    for report in &reports {
        if !report.within_budget {
            all_ok = false;
        }
        print_report(report, args.budget);
    }
    Ok(all_ok)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("ttfrh-bench: at least one template breached the gate");
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("ttfrh-bench: {err}");
            ExitCode::from(2)
        }
    }
}
