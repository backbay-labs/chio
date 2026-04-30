//! M07.P6.T3: Lambda deployment-shape verdict-matrix driver entry point.
//!
//! Emits a JSON report on stdout per the verdict-matrix driver contract.
//! When neither `CHIO_VERDICT_MATRIX_SIDECAR_URL` nor `CHIO_SIDECAR_URL`
//! is set, every scenario is reported as `unsupported`; the local-invoke
//! shim against `sdks/lambda/chio-lambda-extension` is operator-tactical
//! and out of M07.P6.T3 scope.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::process::ExitCode;

use chio_verdict_matrix_driver_lambda::{
    resolve_scenario_root, run_driver, SIDECAR_ENV, SIDECAR_FALLBACK_ENV,
};

fn main() -> ExitCode {
    let scenario_root = match resolve_scenario_root() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    let sidecar_url = std::env::var(SIDECAR_ENV)
        .ok()
        .or_else(|| std::env::var(SIDECAR_FALLBACK_ENV).ok());
    let report = match run_driver(&scenario_root, sidecar_url.as_deref()) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("error: failed to serialize report: {err}");
            return ExitCode::from(2);
        }
    };
    println!("{json}");
    if report.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
