use std::path::PathBuf;

use chio_core_types::crypto::PublicKey;
use chio_trace_validate::{
    validate_file, write_report, TraceError, ValidationOptions, ValidationStatus,
};
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TraceSpec {
    RevocationPropagation,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(long)]
    log: PathBuf,

    #[arg(long = "trusted-key", required = true)]
    trusted_keys: Vec<String>,

    #[arg(long, value_enum, default_value_t = TraceSpec::RevocationPropagation)]
    spec: TraceSpec,

    #[arg(long, default_value = "apalache-mc")]
    apalache_bin: PathBuf,

    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,

    #[arg(long)]
    itf_output: Option<PathBuf>,

    #[arg(long)]
    witness_output: Option<PathBuf>,

    #[arg(long)]
    report_output: Option<PathBuf>,

    #[arg(long, default_value_t = 0)]
    require_revoke: u64,

    #[arg(long, default_value_t = 0)]
    require_post_revocation_evaluate: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), TraceError> {
    let args = Args::parse();
    let _spec = args.spec;
    let trusted_observer_keys = args
        .trusted_keys
        .iter()
        .map(|key| PublicKey::from_hex(key).map_err(TraceError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let report = validate_file(&ValidationOptions {
        log_path: args.log,
        trusted_observer_keys,
        apalache_bin: args.apalache_bin,
        timeout_secs: args.timeout_secs,
        itf_output: args.itf_output,
        witness_output: args.witness_output,
        minimum_revoke: args.require_revoke,
        minimum_post_revocation_evaluate: args.require_post_revocation_evaluate,
    })?;
    if let Some(path) = args.report_output {
        write_report(&path, &report)?;
    }
    println!(
        "{}: {}; trace length {}; invariants {}",
        report.spec,
        report.status.as_str(),
        report.trace_length,
        report.invariants.join(", ")
    );
    if report.status == ValidationStatus::Failed {
        let divergence = report.divergence.as_ref().ok_or_else(|| {
            TraceError::InvalidInput("failed report is missing divergence details".to_string())
        })?;
        return Err(TraceError::InvalidInput(format!(
            "trace diverged at step {} ({})\nprojected step: {}\nlast reachable state: {}\ntriage with {}",
            divergence.step,
            divergence.failed_conjunct,
            divergence.projected_step,
            divergence.last_reachable_state,
            divergence.triage_template
        )));
    }
    Ok(())
}
