//! `chio-spec-validate` CLI.
//!
//! Usage:
//!
//! ```text
//! chio-spec-validate <schema.json> <document.json>
//! ```
//!
//! Exit code is 0 on success, 1 on any failure (I/O, parse, schema compile,
//! or schema violation). Diagnostics are written to stderr; on success a
//! single `OK` line is printed to stdout.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let schema = args.next();
    let document = args.next();
    let extra = args.next();
    let (schema, document) = match (schema, document, extra) {
        (Some(s), Some(d), None) => (PathBuf::from(s), PathBuf::from(d)),
        _ => {
            eprintln!("usage: chio-spec-validate <schema.json> <document.json>");
            return ExitCode::from(2);
        }
    };
    match chio_spec_validate::validate(&schema, &document) {
        Ok(()) => {
            println!("OK {} -> {}", document.display(), schema.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("chio-spec-validate: {err}");
            ExitCode::FAILURE
        }
    }
}
