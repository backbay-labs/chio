//! Workspace task runner.
//!
//! Argument parsing is `clap`-derived (see `cli.rs`); run `cargo xtask --help`
//! for the full tree. The flat leaf spellings are aliases for the noun-group
//! leaves:
//!
//! ```text
//! cargo xtask validate-scenarios
//! cargo xtask freeze-vectors [--check]
//! cargo xtask eval-receipt-regen [--check]
//! cargo xtask codegen <rust|ts|go|python> [--check]
//! cargo xtask codegen --lang <rust|ts|go|python> [--check]
//! cargo xtask errors regen [--check]
//! cargo xtask snippets regen [--check]
//! cargo xtask check crate-paths
//! ```
//!
//! `validate-scenarios` walks `tests/conformance/scenarios/**/*.json`, looks
//! up each scenario's declared `$schema` URI (resolved primarily through an
//! index of `$id` values discovered under `spec/schemas/**`, with a
//! fallback to the `https://chio-protocol.dev/schemas/` strip-prefix
//! mapping), and validates the scenario via `chio-spec-validate`.
//! Scenarios without a `$schema` field are skipped (so a conformance
//! descriptor that declares no schema still loads). Scenarios that DO declare a
//! `$schema` URI but fail to resolve are treated as a hard failure rather
//! than a SKIP, so a typo in the URI cannot silently bypass validation.
//! Prints a per-scenario `PASS|FAIL|SKIP` line and exits non-zero on any
//! FAIL. If the scenarios directory or schema root is missing, or no JSON
//! scenarios are present, validation fails closed.
//!
//! `freeze-vectors` walks `tests/bindings/vectors/**/*.json`, computes a
//! sha256 digest per file, and writes
//! `tests/bindings/vectors/MANIFEST.sha256` with one
//! `<sha256>  <relative-path>` line per file (sorted by path, lower-case hex,
//! two-space separator, trailing newline). The format mirrors
//! `shasum -a 256` so the manifest can be verified with that tool. With
//! `--check` it compares the computed manifest against the on-disk file and
//! exits non-zero on drift; CI uses this mode to catch unfrozen vectors.
//!
//! `codegen rust` (alias: `codegen --lang rust`) regenerates the
//! schema-derived Rust types under `crates/core/chio-core-types/src/_generated/`
//! by invoking `chio_spec_codegen::codegen_rust`. With `--check` it renders
//! the codegen to memory and exits non-zero if the bytes disagree with the
//! on-disk file (used by the spec-drift CI lane).
//!
//! `codegen --lang go` is a thinner shim than the Rust target because Go
//! follows a checked-in regen pattern (see `xtask/codegen-tools.lock.toml`
//! `[go]`). The xtask shells out to
//! `bash sdks/go/chio-go-http/scripts/regen-types.sh`, which bundles the
//! schemas into a single OpenAPI 3.0 document and feeds them to
//! `oapi-codegen v2.4.1`, writing to `sdks/go/chio-go-http/types.go`. With
//! `--check` the xtask additionally runs `git diff --exit-code` against the
//! generated file so the spec-drift CI lane catches drift between the
//! committed bytes and a fresh regeneration.
//!
//! `codegen --lang ts [--check]` regenerates the schema-derived TypeScript
//! types under `sdks/typescript/packages/conformance/src/_generated/index.ts`
//! by shelling out to a pinned `json-schema-to-typescript@15.0.4` install
//! at `sdks/typescript/scripts/node_modules/.bin/json2ts`. Each schema's
//! output is wrapped in a `namespace` keyed by its `<group>/<name>` path so
//! the cross-schema `Operation` / `ToolGrant` collisions (capability/grant
//! vs capability/token) do not surface at the module top level. The
//! `--check` mode renders the output to memory and exits non-zero on byte
//! drift, mirroring the Rust target. The schema-set sha256 is stamped into
//! the file header so a downstream auditor can confirm the regeneration
//! input.
//!
//! `codegen --lang python [--check]` regenerates the Pydantic v2 bindings
//! under `sdks/python/chio-sdk-python/src/chio_sdk/_generated/` by shelling
//! out to `datamodel-code-generator` (pinned in
//! `xtask/codegen-tools.lock.toml`). The xtask invokes the tool via
//! `uv tool run --from "datamodel-code-generator==<pin>" datamodel-codegen`
//! so the toolchain is hermetic and never enters Cargo. With `--check` it
//! renders to a temp dir and exits non-zero on byte drift.
//!
//! `errors regen [--check]` regenerates the Chio error registry Rust output
//! from `spec/errors/registry.yaml`. With `--check`, it renders to a temp
//! directory and compares the generated files against the checked-in copies.

use std::process::ExitCode;

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::Path;

use clap::{CommandFactory, Parser};

use cli::Cli;

mod cli;
mod codegen;
mod crate_paths;
mod dispatch;
mod error;
mod eval_receipt_regen;
mod fixtures;
mod launch_acceptance;
mod qualify;
mod scenarios;
mod snippets_subcommand;
mod support;
mod vectors;

pub(crate) use codegen::{errors_regen, run_codegen};
#[cfg(test)]
pub(crate) use codegen::{normalize_ts_chunk, pascal_case, ts_header, ts_namespace_name};
pub(crate) use dispatch::dispatch;
pub(crate) use error::XtaskError;
pub(crate) use scenarios::validate_scenarios;
#[cfg(test)]
pub(crate) use scenarios::{
    build_schema_index, collect_scenario_files, resolve_schema_path, SchemaIndex,
    SCHEMA_URI_PREFIX,
};
#[cfg(test)]
pub(crate) use support::TempDir;
pub(crate) use support::{copy_dir_recursive, display_path, workspace_root};
pub(crate) use vectors::freeze_vectors;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        // Bare `cargo xtask` prints the help tree and exits 0. An unknown
        // subcommand still fails at the clap layer (non-zero), so this path only
        // covers the no-argument case.
        None => {
            let _ = Cli::command().print_long_help();
            println!();
            Ok(())
        }
        Some(command) => dispatch(command),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_snippets(args: Vec<String>) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    snippets_subcommand::run(args, &workspace_root)
}

#[cfg(test)]
mod tests;
