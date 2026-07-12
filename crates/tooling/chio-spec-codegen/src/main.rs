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
//! chio-spec-codegen --statemachines [--check] [--repo-root <path>]
//! chio-spec-codegen --threat-model <input.json> --out <stubs-dir>
//! ```
//!
//! The schemas directory is walked recursively for `*.schema.json` files; the
//! output directory is created if missing. `--errors-only` regenerates the
//! Chio error registry output from the default registry path.
//! `--threat-model` emits one stub Rust test per threat ID.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: chio-spec-codegen <schemas-dir> <out-dir>\n\
                     \x20      chio-spec-codegen --errors-only\n\
                     \x20      chio-spec-codegen --statemachines [--check] [--repo-root <path>]\n\
                     \x20      chio-spec-codegen --threat-model <input.json> --out <stubs-dir>\n\
                     \x20      chio-spec-codegen --threat-model-doc [--repo-root <path>]";

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
        let repo_root = match workspace_root() {
            Ok(root) => root,
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        };
        let registry = repo_root.join(chio_spec_codegen::ERROR_REGISTRY_INPUT);
        let out = repo_root.join(chio_spec_codegen::ERRORS_GENERATED_DIR);
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

    if schemas_dir == "--statemachines" {
        let mut check = false;
        let mut repo_root = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--check" => check = true,
                "--repo-root" => {
                    let Some(path) = args.next() else {
                        eprintln!("error: --repo-root requires a path argument");
                        return ExitCode::FAILURE;
                    };
                    repo_root = Some(PathBuf::from(path));
                }
                other => {
                    eprintln!("error: unexpected argument {other}");
                    return ExitCode::FAILURE;
                }
            }
        }
        let repo_root = match repo_root.map_or_else(workspace_root, Ok) {
            Ok(root) => root,
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        };
        let input = repo_root.join(chio_spec_codegen::STATEMACHINES_INPUT);
        let result = if check {
            chio_spec_codegen::check_statemachine_outputs(&input, &repo_root)
        } else {
            chio_spec_codegen::codegen_statemachines(&input, &repo_root)
        };
        return match result {
            Ok(outputs) => {
                println!("processed {} state-machine outputs", outputs.len());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("chio-spec-codegen: {err}");
                ExitCode::FAILURE
            }
        };
    }

    if schemas_dir == "--threat-model-doc" {
        // chio-spec-codegen --threat-model-doc [--repo-root <path>]
        let repo_root: PathBuf = match args.next().as_deref() {
            None => match std::env::current_dir() {
                Ok(d) => d,
                Err(err) => {
                    eprintln!("error: cannot resolve current directory: {err}");
                    return ExitCode::FAILURE;
                }
            },
            Some("--repo-root") => match args.next() {
                Some(p) => PathBuf::from(p),
                None => {
                    eprintln!("error: --repo-root requires a path argument");
                    return ExitCode::FAILURE;
                }
            },
            Some(other) => {
                eprintln!("error: unexpected argument {other}");
                return ExitCode::FAILURE;
            }
        };
        if args.next().is_some() {
            eprintln!("error: unexpected extra argument");
            return ExitCode::FAILURE;
        }
        return match chio_spec_codegen::codegen_threat_coverage_doc_default(&repo_root) {
            Ok(out) => {
                println!("wrote {}", out.display());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("chio-spec-codegen: {err}");
                ExitCode::FAILURE
            }
        };
    }

    if schemas_dir == "--threat-model" {
        // chio-spec-codegen --threat-model <input.json> --out <stubs-dir>
        let Some(input) = args.next() else {
            eprintln!("error: --threat-model requires an input path");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        };
        let Some(out_flag) = args.next() else {
            eprintln!("error: --threat-model requires --out <stubs-dir>");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        };
        if out_flag != "--out" {
            eprintln!("error: expected --out, got {out_flag}");
            return ExitCode::FAILURE;
        }
        let Some(out_dir) = args.next() else {
            eprintln!("error: --out requires a directory argument");
            return ExitCode::FAILURE;
        };
        if args.next().is_some() {
            eprintln!("error: unexpected extra argument");
            return ExitCode::FAILURE;
        }

        let input_path = PathBuf::from(&input);
        let out_path = PathBuf::from(&out_dir);

        // Best-effort: validate against the v1 schema if a sibling
        // `chio-threat-model.schema.json` is present. Fail closed if
        // the validator rejects.
        let schema_path = input_path
            .parent()
            .map(|p| p.join("chio-threat-model.schema.json"))
            .unwrap_or_else(|| PathBuf::from(chio_spec_codegen::THREAT_MODEL_SCHEMA));
        if schema_path.exists() {
            if let Err(err) =
                chio_spec_codegen::validate_threat_model_against_schema(&schema_path, &input_path)
            {
                eprintln!("chio-spec-codegen: {err}");
                return ExitCode::FAILURE;
            }
        }

        return match chio_spec_codegen::codegen_threat_model(&input_path, &out_path) {
            Ok(written) => {
                println!(
                    "wrote {} threat-stub file(s) under {}",
                    written.len(),
                    out_path.display()
                );
                for (id, path) in written {
                    println!("  {id} -> {}", path.display());
                }
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

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "cannot derive workspace root from CARGO_MANIFEST_DIR={}",
                manifest_dir.display()
            )
        })
}
