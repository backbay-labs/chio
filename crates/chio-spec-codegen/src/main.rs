//! Thin CLI wrapper around `chio_spec_codegen::codegen_rust`.
//!
//! Most callers should use `cargo xtask codegen rust` instead; this binary
//! exists so that the codegen pipeline can be invoked standalone (for
//! example, from a release-engineering script that does not want to depend on
//! the xtask harness).
//!
//! Usage:
//!
//! ```text
//! chio-spec-codegen <schemas-dir> <out-dir>
//! chio-spec-codegen --errors-only
//! ```
//!
//! The schemas directory is walked recursively for `*.schema.json` files; the
//! output directory is created if missing. `--errors-only` regenerates the
//! Chio error registry output from the default registry path.

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str =
    "usage: chio-spec-codegen <schemas-dir> <out-dir>\n       chio-spec-codegen --errors-only";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(schemas_dir) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    if schemas_dir == "--errors-only" {
        if args.next().is_some() {
            eprintln!("error: unexpected extra argument");
            return ExitCode::FAILURE;
        }
        let registry = PathBuf::from(chio_spec_codegen::ERROR_REGISTRY_INPUT);
        let out = PathBuf::from(chio_spec_codegen::ERRORS_GENERATED_DIR);
        return match chio_spec_codegen::codegen_error_codes(&registry, &out) {
            Ok(()) => {
                println!(
                    "wrote {} and {}",
                    out.join(chio_spec_codegen::ERROR_CODES_OUTPUT).display(),
                    out.join(chio_spec_codegen::MOD_FILE).display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("chio-spec-codegen: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let Some(out_dir) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("error: unexpected extra argument");
        return ExitCode::FAILURE;
    }

    let schemas = PathBuf::from(schemas_dir);
    let out = PathBuf::from(out_dir);
    match chio_spec_codegen::codegen_rust(&schemas, &out) {
        Ok(()) => {
            println!(
                "wrote {} and {} (header stamped, formatted via prettyplease)",
                out.join(chio_spec_codegen::CHIO_WIRE_V1_OUTPUT).display(),
                out.join(chio_spec_codegen::MOD_FILE).display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("chio-spec-codegen: {err}");
            ExitCode::FAILURE
        }
    }
}
