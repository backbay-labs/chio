//! Chio deterministic-replay gate: binary entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use chio_replay_gate::gate::{self, ReplayGateError};

enum Parsed {
    Help,
    Version,
    Run {
        input: Option<PathBuf>,
        json: bool,
        expect_root: Option<String>,
        bless: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code_to_exit(code),
        Err(err) => {
            eprintln!("chio-replay-gate: error: {err}");
            code_to_exit(err.exit_code())
        }
    }
}

fn run() -> Result<i32, ReplayGateError> {
    let parsed = parse_args(std::env::args().skip(1)).map_err(ReplayGateError::InvalidInput)?;
    match parsed {
        Parsed::Help => {
            println!("{}", help_text());
            Ok(gate::EXIT_CLEAN)
        }
        Parsed::Version => {
            println!("chio-replay-gate {}", env!("CARGO_PKG_VERSION"));
            Ok(gate::EXIT_CLEAN)
        }
        Parsed::Run {
            input,
            json,
            expect_root,
            bless,
        } => {
            let report = if bless {
                if expect_root.is_some() {
                    return Err(ReplayGateError::InvalidInput(
                        "--expect-root is not valid with --bless".to_string(),
                    ));
                }
                gate::bless(input.as_deref())?
            } else {
                let input = input.ok_or_else(|| {
                    ReplayGateError::InvalidInput("missing <LOG_OR_FIXTURE>".to_string())
                })?;
                gate::validate_goldens(&input, expect_root.as_deref())?
            };

            if json {
                println!("{}", report.to_json_value());
            } else {
                println!("{}", report.to_text());
            }
            Ok(report.exit_code())
        }
    }
}

fn parse_args<I>(args: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = String>,
{
    let mut input: Option<PathBuf> = None;
    let mut json = false;
    let mut bless = false;
    let mut expect_root: Option<String> = None;
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--json" => json = true,
            "--bless" => bless = true,
            "--expect-root" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--expect-root requires a value".to_string())?;
                expect_root = Some(value);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg}")),
            _ => {
                if input.is_some() {
                    return Err(format!("unexpected extra positional argument {arg}"));
                }
                input = Some(PathBuf::from(arg));
            }
        }
    }

    Ok(Parsed::Run {
        input,
        json,
        expect_root,
        bless,
    })
}

fn help_text() -> &'static str {
    "chio-replay-gate <LOG_OR_FIXTURE> [--json] [--expect-root <HEX>] [--bless]

Validate deterministic replay goldens for the tests/replay corpus.

ARGS:
  <LOG_OR_FIXTURE>        Goldens root/scenario, or fixture manifest/root with --bless.

OPTIONS:
      --json              Emit chio.replay.report/v1 JSON.
      --expect-root <HEX> Assert the scenario root or aggregate root.
      --bless             Regenerate goldens through the CHIO_BLESS gate.
  -h, --help              Print help.
  -V, --version           Print version.

Exit codes:
  0   clean match
  10  byte or root drift
  30  parse or fixture-shape error
  1   CLI or bless-gate error"
}

fn code_to_exit(code: i32) -> ExitCode {
    match u8::try_from(code) {
        Ok(code) => ExitCode::from(code),
        Err(_) => ExitCode::from(1),
    }
}
