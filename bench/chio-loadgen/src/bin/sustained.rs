//! Sustained-p99 gate binary: boots the real Chio stack, paces dispatches for a
//! configured duration, emits the [`LoadReport`] as JSON on stdout, and returns
//! a nonzero [`ExitCode`] when the measured run breaches its latency or
//! resident-set budget.
//!
//! Every fallible step (env parse, work-dir creation, boot, run, serialize,
//! budget enforcement) denies by printing a typed message to stderr and
//! returning [`ExitCode::FAILURE`]; there is no panic path and no silent
//! success.
//!
//! Env knobs: `CHIO_SUSTAINED_P99_SECONDS` (run duration, default 30),
//! `CHIO_LOADGEN_RATE_HZ` (target dispatch rate, default 200),
//! `CHIO_LOADGEN_P99_BUDGET_MS` (p99 ceiling, default 50),
//! `CHIO_LOADGEN_RSS_BUDGET_MB` (resident-set growth ceiling, default 64).

#![forbid(unsafe_code)]

use std::env::VarError;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_loadgen::{enforce_budget, run_sustained, LoadgenConfig, StackHarness, StoreBacking};

const DEFAULT_SECONDS: u64 = 30;
const DEFAULT_RATE_HZ: u32 = 200;
const DEFAULT_P99_BUDGET_MS: u64 = 50;
const DEFAULT_RSS_BUDGET_MB: u64 = 64;

/// Highest arrival rate the nanosecond pacer can resolve (one dispatch per
/// nanosecond). A rate above this floors the per-tick interval to zero, so the
/// runner would dispatch uncapped; reject it at parse time.
const MAX_RATE_HZ: u32 = 1_000_000_000;

const BYTES_PER_MEBIBYTE: u64 = 1024 * 1024;

/// Per-invoke fixture tool-server latency. Held nonzero so the measured dispatch
/// path has a floor above sub-millisecond truncation: a zero-latency fixture
/// could report a p99 of zero, which would let a `CHIO_LOADGEN_P99_BUDGET_MS=0`
/// gate pass despite a real dispatch cost. It also models a minimal downstream
/// tool cost, and stays well under the arrival interval at the default rate.
const TOOL_LATENCY: Duration = Duration::from_millis(2);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let workdir = create_workdir()?;
    let outcome = gated_run(&workdir);
    // Best-effort cleanup: the run's verdict, not the temp-dir teardown, is the
    // gate signal, so a failed removal must not mask the outcome.
    let _ = std::fs::remove_dir_all(&workdir);
    outcome
}

fn gated_run(workdir: &Path) -> Result<(), String> {
    let config = LoadgenConfig {
        arrival_rate_hz: parse_env("CHIO_LOADGEN_RATE_HZ", DEFAULT_RATE_HZ)?,
        duration: Duration::from_secs(parse_env("CHIO_SUSTAINED_P99_SECONDS", DEFAULT_SECONDS)?),
        tool_latency: TOOL_LATENCY,
        store: StoreBacking::Sqlite {
            path: workdir.join("receipts.sqlite"),
        },
        p99_budget: Duration::from_millis(parse_env(
            "CHIO_LOADGEN_P99_BUDGET_MS",
            DEFAULT_P99_BUDGET_MS,
        )?),
        rss_growth_budget_bytes: {
            // Fail closed on an unrepresentable budget: a mebibyte value large
            // enough to overflow u64 bytes would, under saturation, silently
            // become u64::MAX and disable the RSS growth check entirely, so a
            // typo with extra digits could let a memory regression pass.
            let budget_mb = parse_env("CHIO_LOADGEN_RSS_BUDGET_MB", DEFAULT_RSS_BUDGET_MB)?;
            budget_mb.checked_mul(BYTES_PER_MEBIBYTE).ok_or_else(|| {
                format!(
                    "CHIO_LOADGEN_RSS_BUDGET_MB={budget_mb} overflows u64 when converted to bytes"
                )
            })?
        },
    };

    // Fail closed before booting the stack: a zero rate would drive an uncapped
    // max-rate loop, not an idle one. An uncapped run is spelled as a large rate.
    if config.arrival_rate_hz == 0 {
        return Err(
            "CHIO_LOADGEN_RATE_HZ must be nonzero; an uncapped rate is a large value, not 0"
                .to_string(),
        );
    }

    // Reject a rate past the nanosecond pacer resolution here too, so the operator
    // gets a clean message rather than a mid-run typed denial. Above 1e9 Hz the
    // pacer cannot space dispatches below one nanosecond and would run uncapped.
    if config.arrival_rate_hz > MAX_RATE_HZ {
        return Err(format!(
            "CHIO_LOADGEN_RATE_HZ must not exceed {MAX_RATE_HZ}; dispatches cannot be spaced below one nanosecond"
        ));
    }

    // Reject a duration the monotonic clock cannot schedule before booting, so the
    // operator gets a clean message here instead of a mid-run typed denial.
    if Instant::now().checked_add(config.duration).is_none() {
        return Err(
            "CHIO_SUSTAINED_P99_SECONDS is too large to schedule on the monotonic clock"
                .to_string(),
        );
    }

    let harness = StackHarness::boot(&config).map_err(|error| error.to_string())?;
    let report = run_sustained(&harness, &config).map_err(|error| error.to_string())?;

    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize LoadReport: {error}"))?;
    println!("{json}");

    enforce_budget(&report, &config).map_err(|error| error.to_string())
}

/// Create a unique per-process work directory for the durable receipt store.
/// Uses `std::env::temp_dir` plus the pid and a wall-clock nonce so concurrent
/// runs on the same host cannot collide.
fn create_workdir() -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let dir = std::env::temp_dir().join(format!("chio-loadgen-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("failed to create work dir {}: {error}", dir.display()))?;
    Ok(dir)
}

/// Read an env knob, returning `default` when unset. A present-but-unparseable
/// or non-unicode value denies with a typed message rather than silently
/// falling back, so a malformed gate knob cannot pass a run unnoticed.
fn parse_env<T>(key: &str, default: T) -> Result<T, String>
where
    T: FromStr,
    T::Err: Display,
{
    match std::env::var(key) {
        Ok(raw) => raw
            .trim()
            .parse::<T>()
            .map_err(|error| format!("{key} is not a valid value: {error}")),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(format!("{key} is not valid unicode")),
    }
}
