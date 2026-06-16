use std::{env, ffi::OsString, path::PathBuf, process::ExitCode};

use chio_proof_room::{
    parse_listen_addr, serve_proof_room, verify_proof_room_quickstart, ProofRoomServeConfig,
};

#[tokio::main]
async fn main() -> ExitCode {
    match parse_config(env::args_os().skip(1)) {
        Ok(ProofRoomCommand::Help) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(ProofRoomCommand::Serve(config)) => match serve_proof_room(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        Ok(ProofRoomCommand::VerifyOnly {
            bundle,
            doctor_report,
        }) => match verify_proof_room_quickstart(&bundle, doctor_report.as_deref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

enum ProofRoomCommand {
    Help,
    Serve(ProofRoomServeConfig),
    VerifyOnly {
        bundle: PathBuf,
        doctor_report: Option<PathBuf>,
    },
}

fn parse_config<I>(args: I) -> Result<ProofRoomCommand, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut bundle = None;
    let mut ui_dir = env::var_os("CHIO_PROOF_ROOM_UI_DIR").map(PathBuf::from);
    let mut fixture_root = env::var_os("CHIO_PROOF_FIXTURE_ROOT").map(PathBuf::from);
    let mut listen = "0.0.0.0:7391".to_string();
    let mut doctor_report = None;
    let mut verify_only = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.to_string_lossy().as_ref() {
            "--bundle" => {
                bundle = Some(next_path_arg(&mut args, "--bundle")?);
            }
            "--ui-dir" => {
                ui_dir = Some(next_path_arg(&mut args, "--ui-dir")?);
            }
            "--fixture-root" => {
                fixture_root = Some(next_path_arg(&mut args, "--fixture-root")?);
            }
            "--listen" => {
                listen = next_string_arg(&mut args, "--listen")?;
            }
            "--doctor-report" => {
                doctor_report = Some(next_path_arg(&mut args, "--doctor-report")?);
            }
            "--verify-only" => {
                verify_only = true;
            }
            "--help" | "-h" => {
                return Ok(ProofRoomCommand::Help);
            }
            other => {
                return Err(format!("unknown argument: {other}\n{}", usage()));
            }
        }
    }

    let bundle = bundle.ok_or_else(|| format!("missing required --bundle\n{}", usage()))?;
    if verify_only {
        return Ok(ProofRoomCommand::VerifyOnly {
            bundle,
            doctor_report,
        });
    }

    let ui_dir = ui_dir.ok_or_else(|| format!("missing required --ui-dir\n{}", usage()))?;
    let listen = parse_listen_addr(&listen).map_err(|error| error.to_string())?;

    Ok(ProofRoomCommand::Serve(ProofRoomServeConfig {
        bundle,
        ui_dir,
        listen,
        doctor_report,
        fixture_root,
    }))
}

fn next_path_arg<I>(args: &mut I, flag: &str) -> Result<PathBuf, String>
where
    I: Iterator<Item = OsString>,
{
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} requires a path"))
}

fn next_string_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let value = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    value
        .into_string()
        .map_err(|_| format!("{flag} must be valid UTF-8"))
}

fn usage() -> &'static str {
    "usage: chio-proof-room --bundle <proof-room-bundle> --ui-dir <dashboard-dist> [--fixture-root <fixtures/proof-room>] [--listen <addr>] [--doctor-report <path>] [--verify-only]"
}
