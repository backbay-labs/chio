//! Workspace task runner.
//!
//! Subcommands so far:
//!
//! ```text
//! cargo xtask trajectory regen-manifest
//! cargo xtask trajectory regen-manifest --check
//! cargo xtask validate-scenarios
//! cargo xtask freeze-vectors
//! cargo xtask freeze-vectors --check
//! ```
//!
//! `trajectory regen-manifest` walks `.planning/trajectory/tickets/M*/P*.yml`,
//! concatenates the per-phase ticket arrays, sorts by id, and writes the
//! result to `.planning/trajectory/tickets/manifest.yml` with the canonical
//! header. With `--check` it exits non-zero on drift instead of writing.
//!
//! `validate-scenarios` walks `tests/conformance/scenarios/**/*.json`, looks
//! up each scenario's declared `$schema` URI (resolved primarily through an
//! index of `$id` values discovered under `spec/schemas/**`, with a
//! fallback to the legacy `https://chio-protocol.dev/schemas/` strip-prefix
//! mapping), and validates the scenario via `chio-spec-validate`.
//! Scenarios without a `$schema` field are skipped (so that legacy
//! conformance descriptors continue to load). Scenarios that DO declare a
//! `$schema` URI but fail to resolve are treated as a hard failure rather
//! than a SKIP, so a typo in the URI cannot silently bypass validation.
//! Prints a per-scenario `PASS|FAIL|SKIP` line and exits non-zero on any
//! FAIL. If the scenarios directory is missing or contains no JSON files,
//! it prints `no scenarios found` and exits 0.
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
//! schema-derived Rust types under `crates/chio-core-types/src/_generated/`
//! by invoking `chio_spec_codegen::codegen_rust`. With `--check` it renders
//! the codegen to memory and exits non-zero if the bytes disagree with the
//! on-disk file (used by the spec-drift CI lane).
//!
//! `codegen --lang go` is a thinner shim than the Rust target because Go
//! follows a checked-in regen pattern (Wave 1 decision, see
//! `xtask/codegen-tools.lock.toml` `[go]`). The xtask shells out to
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

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::de::Error as _;
use serde_yml::Value;
use sha2::{Digest, Sha256};

const MANIFEST_HEADER: &str = "\
# GENERATED from per-phase files under .planning/trajectory/tickets/M{nn}/P{n}.yml
# Do not hand-edit. Regenerate with `cargo xtask trajectory regen-manifest`.
# CI validates manifest.yml against schema.json on every PR.
#
# The per-phase files under tickets/M{nn}/P{n}.yml are the source of truth.
# This manifest is a flat, id-sorted concatenation. Empty manifest is the
# Wave-0 seed state until the Wave 1a phase tickets are authored.
";

#[derive(Debug)]
enum XtaskError {
    Usage(String),
    Io(String, std::io::Error),
    Yaml(String, serde_yml::Error),
    Json(String, serde_json::Error),
    Drift(String),
    Validation(String),
    Codegen(chio_spec_codegen::CodegenError),
    Process(String),
    ToolMissing(String),
    ToolFailed(String),
}

impl fmt::Display for XtaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "usage: {msg}"),
            Self::Io(path, err) => write!(f, "io error on {path}: {err}"),
            Self::Yaml(path, err) => write!(f, "yaml error in {path}: {err}"),
            Self::Json(path, err) => write!(f, "json error in {path}: {err}"),
            Self::Drift(detail) => write!(f, "manifest drift: {detail}"),
            Self::Validation(detail) => write!(f, "scenario validation failed: {detail}"),
            Self::Codegen(err) => write!(f, "codegen failed: {err}"),
            Self::Process(msg) => write!(f, "subprocess error: {msg}"),
            Self::ToolMissing(detail) => write!(f, "codegen tool missing: {detail}"),
            Self::ToolFailed(detail) => write!(f, "codegen tool failed: {detail}"),
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "trajectory" => run_trajectory(args.collect()),
        "validate-scenarios" => validate_scenarios(args.collect()),
        "freeze-vectors" => freeze_vectors(args.collect()),
        "codegen" => run_codegen(args.collect()),
        "" | "help" | "--help" | "-h" => {
            print_help();
            return ExitCode::SUCCESS;
        }
        other => Err(XtaskError::Usage(format!("unknown subcommand: {other}"))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("xtask subcommands:");
    println!("  trajectory regen-manifest [--check]");
    println!("  validate-scenarios");
    println!("  freeze-vectors [--check]");
    println!("  codegen rust [--check]");
    println!("  codegen --lang rust [--check]");
    println!("  codegen --lang go [--check]");
    println!("  codegen ts [--check]");
    println!("  codegen --lang ts [--check]");
    println!("  codegen python [--check]");
    println!("  codegen --lang python [--check]");
}

fn run_trajectory(args: Vec<String>) -> Result<(), XtaskError> {
    let mut iter = args.into_iter();
    let sub = iter
        .next()
        .ok_or_else(|| XtaskError::Usage("trajectory <subcommand>".into()))?;
    match sub.as_str() {
        "regen-manifest" => regen_manifest(iter.collect()),
        other => Err(XtaskError::Usage(format!(
            "unknown trajectory subcommand: {other}"
        ))),
    }
}

fn regen_manifest(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "regen-manifest: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let tickets_dir = workspace_root.join(".planning/trajectory/tickets");
    let manifest_path = tickets_dir.join("manifest.yml");

    let mut tickets: Vec<Value> = Vec::new();
    let phase_files = collect_phase_files(&tickets_dir)?;
    for path in &phase_files {
        let raw =
            fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        if raw.trim().is_empty() {
            continue;
        }
        let parsed: Value =
            serde_yml::from_str(&raw).map_err(|err| XtaskError::Yaml(display_path(path), err))?;
        match parsed {
            Value::Sequence(seq) => tickets.extend(seq),
            Value::Null => continue,
            _ => {
                return Err(XtaskError::Yaml(
                    display_path(path),
                    serde_yml::Error::custom(format!(
                        "{}: expected a YAML sequence at the top level",
                        display_path(path)
                    )),
                ));
            }
        }
    }

    tickets.sort_by_key(ticket_id);

    let body = if tickets.is_empty() {
        "[]\n".to_string()
    } else {
        serde_yml::to_string(&Value::Sequence(tickets))
            .map_err(|err| XtaskError::Yaml(display_path(&manifest_path), err))?
    };
    let new_content = format!("{MANIFEST_HEADER}\n{body}");

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        if existing != new_content {
            return Err(XtaskError::Drift(format!(
                "manifest.yml is stale; rerun `cargo xtask trajectory regen-manifest` ({} phase files inspected)",
                phase_files.len()
            )));
        }
        println!(
            "manifest.yml in sync with {} phase files",
            phase_files.len()
        );
    } else {
        fs::write(&manifest_path, new_content)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        println!(
            "wrote {} ({} phase files; {} ticket entries)",
            display_path(&manifest_path),
            phase_files.len(),
            // Recompute count for the message.
            count_top_level_sequence_entries(&manifest_path).unwrap_or(0)
        );
    }
    Ok(())
}

fn collect_phase_files(tickets_dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out: Vec<PathBuf> = Vec::new();
    let entries = match fs::read_dir(tickets_dir) {
        Ok(it) => it,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(err) => return Err(XtaskError::Io(display_path(tickets_dir), err)),
    };
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(tickets_dir), err))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if !is_milestone_dir(name) || !path.is_dir() {
            continue;
        }
        let phase_entries =
            fs::read_dir(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let mut phase_files: Vec<PathBuf> = Vec::new();
        for phase_entry in phase_entries {
            let phase_entry =
                phase_entry.map_err(|err| XtaskError::Io(display_path(&path), err))?;
            let phase_path = phase_entry.path();
            let Some(phase_name) = phase_path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if is_phase_file(phase_name) {
                phase_files.push(phase_path);
            }
        }
        phase_files.sort();
        out.extend(phase_files);
    }
    out.sort();
    Ok(out)
}

fn is_milestone_dir(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 3 && bytes[0] == b'M' && bytes[1].is_ascii_digit() && bytes[2].is_ascii_digit()
}

fn is_phase_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".yml") else {
        return false;
    };
    if !stem.starts_with('P') {
        return false;
    }
    let rest = &stem[1..];
    if rest.is_empty() {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn ticket_id(value: &Value) -> String {
    match value {
        Value::Mapping(map) => map
            .get(Value::String("id".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn count_top_level_sequence_entries(path: &Path) -> Result<usize, XtaskError> {
    let raw = fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    let value: Value =
        serde_yml::from_str(&raw).map_err(|err| XtaskError::Yaml(display_path(path), err))?;
    match value {
        Value::Sequence(seq) => Ok(seq.len()),
        Value::Null => Ok(0),
        _ => Ok(0),
    }
}

const SCHEMA_URI_PREFIX: &str = "https://chio-protocol.dev/schemas/";

fn validate_scenarios(args: Vec<String>) -> Result<(), XtaskError> {
    if let Some(arg) = args.into_iter().next() {
        return Err(XtaskError::Usage(format!(
            "validate-scenarios: unexpected argument: {arg}"
        )));
    }

    let workspace_root = workspace_root()?;
    let scenarios_dir = workspace_root.join("tests/conformance/scenarios");
    let schemas_root = workspace_root.join("spec/schemas");

    let scenarios = collect_scenario_files(&scenarios_dir)?;
    if scenarios.is_empty() {
        println!("no scenarios found under {}", display_path(&scenarios_dir));
        return Ok(());
    }

    // Build a `$id` URI -> schema-path index by scanning every
    // *.schema.json under spec/schemas/. Each schema declares its canonical
    // identifier in `$id`; scenarios authored against a schema reference
    // that exact value (which does NOT match the on-disk path one-to-one,
    // see for example
    // `chio-wire/v1/capability/token/v1` vs the file
    // `chio-wire/v1/capability/token.schema.json`). We resolve the URI via
    // this index and fall back to the legacy strip-prefix path mapping for
    // hosts that pre-date `$id` adoption.
    let schema_index = build_schema_index(&schemas_root)?;

    let mut failures: Vec<String> = Vec::new();
    let mut pass_count: usize = 0;
    let mut skip_count: usize = 0;
    for scenario in &scenarios {
        let raw = fs::read_to_string(scenario)
            .map_err(|err| XtaskError::Io(display_path(scenario), err))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|err| XtaskError::Json(display_path(scenario), err))?;
        let schema_uri = value
            .as_object()
            .and_then(|obj| obj.get("$schema"))
            .and_then(|v| v.as_str());
        let Some(uri) = schema_uri else {
            println!("SKIP {} (no $schema field)", display_path(scenario));
            skip_count += 1;
            continue;
        };
        let schema_path = match resolve_schema_path(uri, &schema_index, &schemas_root) {
            Some(path) => path,
            None => {
                // Unrecognized `$schema` URIs were previously SKIPped, which
                // meant a typo could silently bypass validation. Treat them
                // as a hard failure: a scenario that opted into schema
                // validation must point at a real schema.
                println!(
                    "FAIL {}: unrecognized $schema URI: {}",
                    display_path(scenario),
                    uri
                );
                failures.push(display_path(scenario));
                continue;
            }
        };
        match chio_spec_validate::validate(&schema_path, scenario) {
            Ok(()) => {
                println!("PASS {}", display_path(scenario));
                pass_count += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", display_path(scenario));
                failures.push(display_path(scenario));
            }
        }
    }

    println!(
        "validate-scenarios: {} pass, {} fail, {} skip ({} scenarios inspected)",
        pass_count,
        failures.len(),
        skip_count,
        scenarios.len()
    );

    if failures.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Validation(format!(
            "{} scenarios failed: {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

/// Mapping from a schema's canonical `$id` URI (and a few normalized
/// variants) to the absolute path of the schema file on disk. Built once
/// per `validate-scenarios` invocation by walking `spec/schemas/`.
type SchemaIndex = std::collections::BTreeMap<String, PathBuf>;

fn build_schema_index(schemas_root: &Path) -> Result<SchemaIndex, XtaskError> {
    let mut index: SchemaIndex = SchemaIndex::new();
    if !schemas_root.exists() {
        return Ok(index);
    }
    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_json(schemas_root, &mut schema_files)?;
    for path in schema_files {
        let raw =
            fs::read_to_string(&path).map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|err| XtaskError::Json(display_path(&path), err))?;
        if let Some(id) = value.get("$id").and_then(|v| v.as_str()) {
            index.insert(id.to_string(), path.clone());
            // Some scenario authors paste the URI with or without a
            // trailing slash; treat both as the same schema.
            if let Some(trimmed) = id.strip_suffix('/') {
                index.insert(trimmed.to_string(), path.clone());
            } else {
                index.insert(format!("{id}/"), path.clone());
            }
        }
    }
    Ok(index)
}

/// Resolve a `$schema` URI to a schema path using (in order):
///   1. an exact match in the `$id` index built from `spec/schemas/`,
///   2. the legacy strip-prefix mapping (`<prefix><rel>` ->
///      `<schemas_root>/<rel>` plus `.schema.json`), retained for
///      backwards compatibility with scenarios that pre-date `$id` adoption.
///
/// Returns `None` when neither path resolves to a file on disk; callers
/// then surface a hard failure rather than silently skipping the scenario.
fn resolve_schema_path(
    uri: &str,
    schema_index: &SchemaIndex,
    schemas_root: &Path,
) -> Option<PathBuf> {
    if let Some(path) = schema_index.get(uri) {
        return Some(path.clone());
    }
    let trimmed_uri = uri.trim_end_matches('/');
    if let Some(path) = schema_index.get(trimmed_uri) {
        return Some(path.clone());
    }
    let rel = uri.strip_prefix(SCHEMA_URI_PREFIX)?;
    let direct = schemas_root.join(rel);
    if direct.is_file() {
        return Some(direct);
    }
    let with_suffix = schemas_root.join(format!("{}.schema.json", rel.trim_end_matches('/')));
    if with_suffix.is_file() {
        return Some(with_suffix);
    }
    None
}

fn collect_scenario_files(scenarios_dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out: Vec<PathBuf> = Vec::new();
    if !scenarios_dir.exists() {
        return Ok(out);
    }
    walk_json(scenarios_dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext.eq_ignore_ascii_case("json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

const VECTORS_DIR: &str = "tests/bindings/vectors";
const VECTORS_MANIFEST: &str = "tests/bindings/vectors/MANIFEST.sha256";

fn freeze_vectors(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "freeze-vectors: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let vectors_dir = workspace_root.join(VECTORS_DIR);
    let manifest_path = workspace_root.join(VECTORS_MANIFEST);

    let mut json_files: Vec<PathBuf> = Vec::new();
    if vectors_dir.exists() {
        walk_json(&vectors_dir, &mut json_files)?;
    }
    json_files.sort();

    // Build (relative-path, sha256-hex) pairs sorted by relative path.
    let mut entries: Vec<(String, String)> = Vec::with_capacity(json_files.len());
    for path in &json_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "freeze-vectors: vector file {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hex = digest_to_hex(&digest);
        entries.push((rel_str, hex));
    }
    // Sort lexicographically by relative path; tuples compare by `.0` first.
    entries.sort();

    // Format mirrors `shasum -a 256`: "<hex>  <path>\n" per file (including
    // a trailing newline after the last entry).
    let mut new_content = String::with_capacity(entries.len() * 96);
    for (rel_str, hex) in &entries {
        new_content.push_str(hex);
        new_content.push_str("  ");
        new_content.push_str(rel_str);
        new_content.push('\n');
    }

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        if existing != new_content {
            let drift = describe_manifest_drift(&existing, &new_content);
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask freeze-vectors` ({} vector files inspected)\n{}",
                display_path(&manifest_path),
                entries.len(),
                drift
            )));
        }
        println!(
            "{} in sync with {} vector files",
            display_path(&manifest_path),
            entries.len()
        );
    } else {
        fs::write(&manifest_path, &new_content)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        println!(
            "wrote {} ({} vector files)",
            display_path(&manifest_path),
            entries.len()
        );
    }
    Ok(())
}

/// Relative path (from workspace root) of the chio-wire/v1 schema directory.
const CHIO_WIRE_V1_SCHEMAS: &str = "spec/schemas/chio-wire/v1";
/// Relative path (from workspace root) of the generated Rust output dir.
const CHIO_WIRE_V1_RUST_OUT: &str = "crates/chio-core-types/src/_generated";

fn run_codegen(args: Vec<String>) -> Result<(), XtaskError> {
    // Accepted forms:
    //   cargo xtask codegen rust [--check]
    //   cargo xtask codegen --lang rust [--check]
    let mut lang: Option<String> = None;
    let mut check_only = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => check_only = true,
            "--lang" => match iter.next() {
                Some(value) => lang = Some(value),
                None => {
                    return Err(XtaskError::Usage(
                        "codegen: --lang requires an argument (e.g. --lang rust)".into(),
                    ));
                }
            },
            "rust" | "python" | "ts" | "go" => {
                if lang.is_none() {
                    lang = Some(arg);
                } else {
                    return Err(XtaskError::Usage(format!(
                        "codegen: language already specified; unexpected argument: {arg}"
                    )));
                }
            }
            other => {
                return Err(XtaskError::Usage(format!(
                    "codegen: unknown argument: {other}"
                )));
            }
        }
    }

    let lang = lang.ok_or_else(|| {
        XtaskError::Usage("codegen: language is required (rust|python|ts|go)".into())
    })?;

    match lang.as_str() {
        "rust" => codegen_rust(check_only),
        "ts" => codegen_ts(check_only),
        "go" => codegen_go(check_only),
        "python" => codegen_python(check_only),
        other => Err(XtaskError::Usage(format!(
            "codegen: unknown language: {other} (expected rust|python|ts|go)"
        ))),
    }
}

fn codegen_rust(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let out_dir = workspace_root.join(CHIO_WIRE_V1_RUST_OUT);

    if check_only {
        // Render BOTH the consolidated chio_wire_v1.rs and the placeholder
        // mod.rs into a temporary staging directory and compare every file
        // byte-for-byte with the on-disk copy. The previous implementation
        // only checked chio_wire_v1.rs, so a stale or missing mod.rs slipped
        // past the spec-drift CI lane.
        let staging = TempDir::new("chio-codegen-rust-check").map_err(|err| {
            XtaskError::Io("<temp staging dir for codegen rust --check>".into(), err)
        })?;
        chio_spec_codegen::codegen_rust(&schemas_dir, staging.path())
            .map_err(XtaskError::Codegen)?;

        let mut differences: Vec<String> = Vec::new();
        let mut total_bytes: u64 = 0;
        for filename in [
            chio_spec_codegen::CHIO_WIRE_V1_OUTPUT,
            chio_spec_codegen::MOD_FILE,
        ] {
            let staged = staging.path().join(filename);
            let on_disk = out_dir.join(filename);
            let staged_bytes =
                fs::read(&staged).map_err(|err| XtaskError::Io(display_path(&staged), err))?;
            if !on_disk.exists() {
                differences.push(format!(
                    "{} is missing on disk (computed {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len()
                ));
                continue;
            }
            let on_disk_bytes =
                fs::read(&on_disk).map_err(|err| XtaskError::Io(display_path(&on_disk), err))?;
            total_bytes += on_disk_bytes.len() as u64;
            if staged_bytes != on_disk_bytes {
                differences.push(format!(
                    "{} is stale (computed {} bytes, on-disk {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len(),
                    on_disk_bytes.len()
                ));
            }
        }
        if !differences.is_empty() {
            return Err(XtaskError::Drift(format!(
                "rerun `cargo xtask codegen rust`:\n  - {}",
                differences.join("\n  - ")
            )));
        }
        println!(
            "codegen rust: {} and {} in sync ({} bytes total)",
            display_path(&out_dir.join(chio_spec_codegen::CHIO_WIRE_V1_OUTPUT)),
            display_path(&out_dir.join(chio_spec_codegen::MOD_FILE)),
            total_bytes
        );
        return Ok(());
    }

    chio_spec_codegen::codegen_rust(&schemas_dir, &out_dir).map_err(XtaskError::Codegen)?;
    let out_path = out_dir.join(chio_spec_codegen::CHIO_WIRE_V1_OUTPUT);
    let mod_path = out_dir.join(chio_spec_codegen::MOD_FILE);
    let bytes = fs::metadata(&out_path).map(|m| m.len()).unwrap_or_default();
    println!(
        "codegen rust: wrote {} ({} bytes) and refreshed {}",
        display_path(&out_path),
        bytes,
        display_path(&mod_path)
    );
    Ok(())
}

/// Relative path (from workspace root) of the chio-go-http regen script.
const CHIO_GO_REGEN_SCRIPT: &str = "sdks/go/chio-go-http/scripts/regen-types.sh";
/// Relative path (from workspace root) of the generated Go file. Used by the
/// `--check` mode to scope `git diff --exit-code` precisely.
const CHIO_GO_OUTPUT_FILE: &str = "sdks/go/chio-go-http/types.go";

/// Wire `cargo xtask codegen --lang go [--check]`. The Go target is a thin
/// shim around `sdks/go/chio-go-http/scripts/regen-types.sh` because Go
/// follows the checked-in regen pattern (Wave 1 decision in
/// `xtask/codegen-tools.lock.toml [go]`): the regenerated bytes are
/// committed and a CI lane diffs them, rather than rebuilding live every
/// run like the Rust pipeline.
///
/// The shim does two things:
/// 1. Resolve the workspace root (so `bash regen-types.sh` runs from a
///    well-defined cwd regardless of where the user invoked cargo).
/// 2. With `--check`, additionally invoke `git diff --exit-code` on the
///    generated file so a stale committed copy fails the build instead of
///    silently re-rendering.
///
/// The script handles its own toolchain checks (go, python3, git on PATH);
/// the xtask does not duplicate them.
fn codegen_go(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let script_path = workspace_root.join(CHIO_GO_REGEN_SCRIPT);
    let output_path = workspace_root.join(CHIO_GO_OUTPUT_FILE);

    if !script_path.exists() {
        return Err(XtaskError::Usage(format!(
            "codegen go: regen script not found at {}",
            display_path(&script_path)
        )));
    }

    if check_only {
        // `--check` MUST NOT mutate the on-disk types.go. Snapshot the
        // committed bytes, run the regen, compare in-memory, and restore
        // the original bytes regardless of outcome. Any drift yields a
        // hard error rather than a silent rewrite.
        let original = if output_path.exists() {
            Some(
                fs::read(&output_path)
                    .map_err(|err| XtaskError::Io(display_path(&output_path), err))?,
            )
        } else {
            None
        };

        let run_result = run_go_regen_script(&script_path, &workspace_root);
        let regen_bytes = if run_result.is_ok() && output_path.exists() {
            fs::read(&output_path).map_err(|err| XtaskError::Io(display_path(&output_path), err))?
        } else {
            Vec::new()
        };

        // Restore the original committed bytes (or remove the file if it
        // did not exist before the regen) so callers see no on-disk side
        // effects from `--check`.
        match &original {
            Some(bytes) => {
                fs::write(&output_path, bytes)
                    .map_err(|err| XtaskError::Io(display_path(&output_path), err))?;
            }
            None => {
                if output_path.exists() {
                    fs::remove_file(&output_path)
                        .map_err(|err| XtaskError::Io(display_path(&output_path), err))?;
                }
            }
        }

        run_result?;

        match &original {
            Some(bytes) if bytes == &regen_bytes => {
                println!(
                    "codegen go: {} in sync with committed bytes",
                    display_path(&output_path)
                );
                Ok(())
            }
            Some(bytes) => Err(XtaskError::Drift(format!(
                "{} drifted from committed bytes (committed {} bytes, regenerated {} bytes); rerun `cargo xtask codegen --lang go` and commit the result",
                display_path(&output_path),
                bytes.len(),
                regen_bytes.len()
            ))),
            None => Err(XtaskError::Drift(format!(
                "{} is missing on disk; rerun `cargo xtask codegen --lang go` and commit the result",
                display_path(&output_path)
            ))),
        }
    } else {
        run_go_regen_script(&script_path, &workspace_root)?;
        let bytes = fs::metadata(&output_path)
            .map(|m| m.len())
            .unwrap_or_default();
        println!(
            "codegen go: wrote {} ({} bytes) via {}",
            display_path(&output_path),
            bytes,
            display_path(&script_path)
        );
        Ok(())
    }
}

/// Invoke the Go regen script with the workspace root as CWD. Surfaces a
/// dedicated `Process` error for shell-level failures instead of wrapping
/// them in the Rust-specific `Codegen(Typify(...))` variant, which made
/// shell errors look like a typify panic in CI logs.
fn run_go_regen_script(script_path: &Path, workspace_root: &Path) -> Result<(), XtaskError> {
    let status = std::process::Command::new("bash")
        .arg(script_path)
        .current_dir(workspace_root)
        .status()
        .map_err(|err| XtaskError::Io(display_path(script_path), err))?;
    if !status.success() {
        return Err(XtaskError::Process(format!(
            "{} exited with code {}",
            display_path(script_path),
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Relative path (from workspace root) of the directory that hosts the
/// pinned json-schema-to-typescript install. The xtask invokes
/// `<scripts>/node_modules/.bin/json2ts` directly so the dispatcher does not
/// depend on `npx` resolution; the caller is responsible for running
/// `npm ci` (or equivalent) inside the scripts dir before invoking codegen.
const TS_CODEGEN_SCRIPTS_DIR: &str = "sdks/typescript/scripts";
/// Relative path (from workspace root) of the generated TS output file.
const CHIO_WIRE_V1_TS_OUT: &str = "sdks/typescript/packages/conformance/src/_generated/index.ts";
/// Pinned json-schema-to-typescript version stamped into the file header so
/// auditors can confirm the generator without opening the lockfile. Must
/// match the [typescript] block in `xtask/codegen-tools.lock.toml`.
const TS_CODEGEN_TOOL_VERSION: &str = "json-schema-to-typescript 15.0.4";

fn codegen_ts(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let out_path = workspace_root.join(CHIO_WIRE_V1_TS_OUT);
    let scripts_dir = workspace_root.join(TS_CODEGEN_SCRIPTS_DIR);

    if !schemas_dir.exists() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: schemas directory missing: {}",
            display_path(&schemas_dir)
        )));
    }
    let json2ts = scripts_dir.join("node_modules/.bin/json2ts");
    if !json2ts.exists() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: json2ts not installed at {}; run `npm ci` in {} first \
             (toolchain pin: {} per xtask/codegen-tools.lock.toml)",
            display_path(&json2ts),
            display_path(&scripts_dir),
            TS_CODEGEN_TOOL_VERSION
        )));
    }

    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_json(&schemas_dir, &mut schema_files)?;
    schema_files.sort();
    if schema_files.is_empty() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: no *.schema.json files under {}",
            display_path(&schemas_dir)
        )));
    }

    // Compute a deterministic schema-set sha256: hash each schema's relative
    // path plus its bytes plus a NUL separator, in lex order. This is the
    // "schema git SHA" surfaced in the file header. Using content rather
    // than `git rev-parse` keeps `--check` byte-stable on dirty trees and on
    // shallow CI clones where the repository SHA may not be available.
    let mut schema_hasher = Sha256::new();
    for path in &schema_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen ts: schema {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        schema_hasher.update(rel_str.as_bytes());
        schema_hasher.update([0u8]);
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        schema_hasher.update(&bytes);
        schema_hasher.update([0u8]);
    }
    let schema_sha = digest_to_hex(&schema_hasher.finalize());

    // Render each schema in isolation, then wrap each emitted file in a
    // namespace keyed by its `<group>/<name>` path so the cross-schema name
    // collisions (e.g., `Operation` between capability/grant and
    // capability/token) do not surface at the module top level.
    let mut body = String::with_capacity(64 * 1024);
    body.push_str(&ts_header(&schema_sha));
    for path in &schema_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen ts: schema {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let ns_name = ts_namespace_name(path).ok_or_else(|| {
            XtaskError::Usage(format!(
                "codegen ts: cannot derive namespace name from {}",
                display_path(path)
            ))
        })?;
        let raw_ts = run_json2ts(&json2ts, path)?;
        let normalized = normalize_ts_chunk(&raw_ts);
        body.push_str(
            "// -----------------------------------------------------------------------------\n",
        );
        body.push_str(&format!("// Source: {rel_str}\n"));
        body.push_str(&format!("export namespace {ns_name} {{\n"));
        for line in normalized.lines() {
            if line.is_empty() {
                body.push('\n');
            } else {
                body.push_str("  ");
                body.push_str(line);
                body.push('\n');
            }
        }
        body.push_str("}\n\n");
    }
    // Trim the trailing extra newline so the file ends with exactly one '\n'.
    while body.ends_with("\n\n") {
        body.pop();
    }

    if check_only {
        if !out_path.exists() {
            return Err(XtaskError::Drift(format!(
                "{} is missing; rerun `cargo xtask codegen --lang ts`",
                display_path(&out_path)
            )));
        }
        let existing = fs::read_to_string(&out_path)
            .map_err(|err| XtaskError::Io(display_path(&out_path), err))?;
        if existing != body {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask codegen --lang ts` (computed {} bytes, on-disk {} bytes)",
                display_path(&out_path),
                body.len(),
                existing.len()
            )));
        }
        println!(
            "codegen ts: {} in sync ({} bytes, {} schemas, schema-sha {})",
            display_path(&out_path),
            existing.len(),
            schema_files.len(),
            &schema_sha[..16]
        );
        return Ok(());
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    fs::write(&out_path, body.as_bytes())
        .map_err(|err| XtaskError::Io(display_path(&out_path), err))?;
    println!(
        "codegen ts: wrote {} ({} bytes, {} schemas, schema-sha {})",
        display_path(&out_path),
        body.len(),
        schema_files.len(),
        &schema_sha[..16]
    );
    Ok(())
}

/// Render the canonical header for the generated TypeScript file. The
/// phrasing mirrors `chio_spec_codegen::GENERATED_HEADER` so an auditor
/// scanning either tree sees the same shape.
fn ts_header(schema_sha: &str) -> String {
    let mut header = String::new();
    header.push_str("// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.\n");
    header.push_str("//\n");
    header.push_str("// Source:     spec/schemas/chio-wire/v1/**/*.schema.json\n");
    header.push_str(&format!(
        "// Tool:       {TS_CODEGEN_TOOL_VERSION} (see xtask/codegen-tools.lock.toml)\n"
    ));
    header.push_str("// Pin file:   sdks/typescript/scripts/package.json\n");
    header.push_str(&format!("// Schema SHA: {schema_sha}\n"));
    header.push_str("//\n");
    header.push_str("// The schema-sha above is sha256 of `<rel-path>\\0<bytes>\\0` for every\n");
    header.push_str("// schema in lex order. It changes whenever any schema under\n");
    header.push_str("// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane\n");
    header.push_str("// asserts byte-equality of this entire file via `--check` mode.\n");
    header.push('\n');
    header.push_str("/* eslint-disable */\n");
    header.push('\n');
    header
}

/// Derive a TypeScript namespace name from a schema path under
/// `spec/schemas/chio-wire/v1/`. The schema at
/// `chio-wire/v1/capability/grant.schema.json` becomes `Capability_Grant`;
/// `trust-control/lease.schema.json` becomes `TrustControl_Lease`. The
/// underscore separator keeps the group prefix readable while remaining a
/// valid TypeScript identifier.
fn ts_namespace_name(schema_path: &Path) -> Option<String> {
    let stem = schema_path
        .file_name()
        .and_then(OsStr::to_str)?
        .strip_suffix(".schema.json")?;
    let group = schema_path
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)?;
    let group_pascal = pascal_case(group);
    let stem_pascal = pascal_case(stem);
    if group_pascal.is_empty() || stem_pascal.is_empty() {
        return None;
    }
    Some(format!("{group_pascal}_{stem_pascal}"))
}

/// Convert a kebab/snake-cased identifier to PascalCase. Non-alphanumeric
/// characters split words; the first char of each word is upper-cased.
fn pascal_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut upper_next = true;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if upper_next {
                for u in ch.to_uppercase() {
                    out.push(u);
                }
                upper_next = false;
            } else {
                out.push(ch);
            }
        } else {
            upper_next = true;
        }
    }
    out
}

/// Run `json2ts` against a single schema file and return the captured
/// stdout. Errors include the schema path so deviations surface clearly.
fn run_json2ts(json2ts: &Path, schema: &Path) -> Result<String, XtaskError> {
    let output = Command::new(json2ts)
        .arg("-i")
        .arg(schema)
        .arg("--no-bannerComment")
        .arg("--unreachableDefinitions=false")
        .arg("--strictIndexSignatures=false")
        .arg("--additionalProperties=false")
        .output()
        .map_err(|err| {
            XtaskError::Process(format!(
                "failed to spawn {} for schema {}: {err}",
                display_path(json2ts),
                display_path(schema)
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(XtaskError::Process(format!(
            "json2ts exited {} for schema {}: {}",
            output.status,
            display_path(schema),
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        XtaskError::Process(format!(
            "json2ts produced non-UTF8 output for {}: {err}",
            display_path(schema)
        ))
    })?;
    Ok(stdout)
}

/// Normalize a json2ts emission so it composes inside a namespace block.
/// The current pipeline strips per-chunk banner comments via
/// `--no-bannerComment`, so this function only collapses the trailing
/// blank-line padding that `prettier` (the json2ts formatter) appends.
fn normalize_ts_chunk(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    trimmed.to_string()
}

/// Walk `dir` recursively, collecting every `*.schema.json` file. Mirrors
/// the schema discovery in `chio_spec_codegen::walk_schema_files` so the
/// Rust and TS targets see an identical input set.
fn walk_schema_json(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_schema_json(&path, out)?;
        } else if file_type.is_file() {
            if let Some(name) = path.file_name().and_then(OsStr::to_str) {
                if name.ends_with(".schema.json") {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

fn digest_to_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Lower-case hex, two chars per byte, matches `shasum -a 256` output.
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

fn describe_manifest_drift(existing: &str, computed: &str) -> String {
    let existing_lines: Vec<&str> = existing.lines().collect();
    let computed_lines: Vec<&str> = computed.lines().collect();
    let mut diff = String::new();
    let mut shown = 0usize;
    let limit = 8usize;
    let max_len = existing_lines.len().max(computed_lines.len());
    for idx in 0..max_len {
        let lhs = existing_lines.get(idx).copied().unwrap_or("");
        let rhs = computed_lines.get(idx).copied().unwrap_or("");
        if lhs != rhs {
            if shown < limit {
                diff.push_str(&format!("  - on-disk: {lhs}\n"));
                diff.push_str(&format!("  + computed: {rhs}\n"));
            }
            shown += 1;
        }
    }
    if shown == 0 {
        // Bytes differ but no per-line difference (e.g. trailing newline).
        format!(
            "  on-disk bytes ({}) != computed bytes ({})",
            existing.len(),
            computed.len()
        )
    } else if shown > limit {
        format!("{diff}  ... ({} more differing lines)", shown - limit)
    } else {
        diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pascal_case_handles_kebab_and_snake() {
        assert_eq!(pascal_case("trust-control"), "TrustControl");
        assert_eq!(pascal_case("tool_call_request"), "ToolCallRequest");
        assert_eq!(pascal_case("agent"), "Agent");
        assert_eq!(pascal_case("inclusion-proof"), "InclusionProof");
    }

    #[test]
    fn pascal_case_passes_through_pascal_input() {
        // Already-PascalCase input is preserved (no separators to split on).
        assert_eq!(pascal_case("Capability"), "Capability");
    }

    #[test]
    fn ts_namespace_name_derives_group_and_stem() {
        let p = Path::new("spec/schemas/chio-wire/v1/capability/grant.schema.json");
        assert_eq!(ts_namespace_name(p).as_deref(), Some("Capability_Grant"));
        let p = Path::new("spec/schemas/chio-wire/v1/trust-control/lease.schema.json");
        assert_eq!(ts_namespace_name(p).as_deref(), Some("TrustControl_Lease"));
        let p = Path::new("spec/schemas/chio-wire/v1/jsonrpc/request.schema.json");
        assert_eq!(ts_namespace_name(p).as_deref(), Some("Jsonrpc_Request"));
    }

    #[test]
    fn ts_namespace_name_rejects_non_schema_paths() {
        assert!(ts_namespace_name(Path::new("/tmp/foo.txt")).is_none());
    }

    #[test]
    fn ts_header_includes_pin_and_sha() {
        let header = ts_header("deadbeef");
        assert!(header.contains("DO NOT EDIT"));
        assert!(header.contains("cargo xtask codegen --lang ts"));
        assert!(header.contains("json-schema-to-typescript 15.0.4"));
        assert!(header.contains("Schema SHA: deadbeef"));
        assert!(header.contains("/* eslint-disable */"));
    }

    #[test]
    fn normalize_ts_chunk_strips_trailing_newlines() {
        assert_eq!(normalize_ts_chunk("hello\n\n\n"), "hello");
        assert_eq!(normalize_ts_chunk("multi\nline\n"), "multi\nline");
    }
}

fn workspace_root() -> Result<PathBuf, XtaskError> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut here = PathBuf::from(manifest_dir);
    if !here.pop() {
        return Err(XtaskError::Usage(format!(
            "could not derive workspace root from CARGO_MANIFEST_DIR={manifest_dir}"
        )));
    }
    Ok(here)
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

/// Pinned tool spec for the Python codegen target. Reflected in
/// `[python]` in `xtask/codegen-tools.lock.toml`. Bumping this is a
/// spec-affecting change and must regenerate every `_generated/*.py` byte.
const PYTHON_CODEGEN_TOOL_PIN: &str = "datamodel-code-generator==0.34.0";

/// Relative path (from workspace root) of the generated Python output dir.
const CHIO_WIRE_V1_PYTHON_OUT: &str = "sdks/python/chio-sdk-python/src/chio_sdk/_generated";

/// Filename of the per-package `__init__.py` re-export written under each
/// generated subpackage. The xtask does not author these; datamodel-codegen
/// emits them as part of its directory-mode output.
const PYTHON_INIT_FILE: &str = "__init__.py";

fn codegen_python(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let final_out_dir = workspace_root.join(CHIO_WIRE_V1_PYTHON_OUT);

    if !schemas_dir.exists() {
        return Err(XtaskError::Codegen(
            chio_spec_codegen::CodegenError::SchemasDirMissing(schemas_dir.clone()),
        ));
    }

    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_json(&schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let schema_digest = hash_schema_set(&workspace_root, &schema_files)?;

    let staging = TempDir::new("chio-codegen-py")
        .map_err(|err| XtaskError::Io("<temp staging dir for codegen python>".to_string(), err))?;

    let clean_input = staging.path().join("input");
    mirror_schema_tree(&schemas_dir, &clean_input, &schema_files)?;

    let staging_out = staging.path().join("output");
    fs::create_dir_all(&staging_out)
        .map_err(|err| XtaskError::Io(display_path(&staging_out), err))?;

    let header_path = staging.path().join("file-header.txt");
    fs::write(&header_path, build_python_file_header(&schema_digest))
        .map_err(|err| XtaskError::Io(display_path(&header_path), err))?;

    invoke_datamodel_codegen(&clean_input, &staging_out, &header_path)?;
    harden_python_generated_models(&staging_out)?;

    // Walk the freshly-generated tree and rewrite each subpackage's
    // `__init__.py` to re-export its top-level model classes. The
    // top-level `__init__.py` then star-imports every subpackage. Together
    // these provide the documented `from chio_sdk._generated import
    // CapabilityToken` import path; without this step datamodel-codegen's
    // empty subpackage stubs cause that import to raise `ImportError`.
    let subpackage_exports = rewrite_python_subpackage_inits(&staging_out, &schema_digest)?;

    let top_init = staging_out.join(PYTHON_INIT_FILE);
    fs::write(
        &top_init,
        build_python_top_init(&schema_digest, &subpackage_exports),
    )
    .map_err(|err| XtaskError::Io(display_path(&top_init), err))?;

    if check_only {
        let drift = diff_python_trees(&staging_out, &final_out_dir)?;
        if let Some(detail) = drift {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask codegen python` ({} schema files inspected)\n{}",
                display_path(&final_out_dir),
                schema_files.len(),
                detail
            )));
        }
        println!(
            "codegen python: {} in sync ({} schema files, {} python files)",
            display_path(&final_out_dir),
            schema_files.len(),
            count_python_files(&staging_out)?
        );
        return Ok(());
    }

    if final_out_dir.exists() {
        fs::remove_dir_all(&final_out_dir)
            .map_err(|err| XtaskError::Io(display_path(&final_out_dir), err))?;
    }
    if let Some(parent) = final_out_dir.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    copy_dir_recursive(&staging_out, &final_out_dir)?;
    let py_count = count_python_files(&final_out_dir)?;
    println!(
        "codegen python: wrote {} ({} python files; {} schema files; sha256={})",
        display_path(&final_out_dir),
        py_count,
        schema_files.len(),
        schema_digest
    );
    Ok(())
}

fn build_python_file_header(schema_digest: &str) -> String {
    format!(
        "# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.\n\
         #\n\
         # Source: spec/schemas/chio-wire/v1/**/*.schema.json\n\
         # Tool:   {PYTHON_CODEGEN_TOOL_PIN} (see xtask/codegen-tools.lock.toml)\n\
         # Schema sha256: {schema_digest}\n\
         #\n\
         # Manual edits will be overwritten by the next regeneration; the\n\
         # spec-drift CI lane enforces this header on every file\n\
         # under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.\n"
    )
}

fn harden_python_generated_models(root_dir: &Path) -> Result<(), XtaskError> {
    harden_python_jsonrpc_response(&root_dir.join("jsonrpc").join("response_schema.py"))?;
    harden_python_provenance_verdict_link(
        &root_dir.join("provenance").join("verdict_link_schema.py"),
    )?;
    Ok(())
}

fn harden_python_jsonrpc_response(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, constr",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, constr, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    error: Error | None = Field(\n        None,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n\nclass ChioJsonRpc20Response2(BaseModel):",
        "    error: Error | None = Field(\n        None,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _success_excludes_error(self) -> \"ChioJsonRpc20Response1\":\n        if \"error\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC success response must not include error\")\n        return self\n\n\nclass ChioJsonRpc20Response2(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    error: Error = Field(\n        ...,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n\nclass ChioJsonRpc20Response(RootModel[ChioJsonRpc20Response1 | ChioJsonRpc20Response2]):",
        "    error: Error = Field(\n        ...,\n        description=\"Error payload. Present only on failure. Mutually exclusive with `result`.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _error_excludes_result(self) -> \"ChioJsonRpc20Response2\":\n        if \"result\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC error response must not include result\")\n        return self\n\n\nclass ChioJsonRpc20Response(RootModel[ChioJsonRpc20Response1 | ChioJsonRpc20Response2]):",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn harden_python_provenance_verdict_link(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink2(BaseModel):",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _allow_excludes_rejection_fields(self) -> \"ChioProvenanceVerdictLink1\":\n        if \"reason\" in self.model_fields_set or \"guard\" in self.model_fields_set:\n            raise ValueError(\"allow verdict must not include reason or guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink2(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink4(BaseModel):",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _cancel_excludes_guard(self) -> \"ChioProvenanceVerdictLink3\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"cancel verdict must not include guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink4(BaseModel):",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n\nclass ChioProvenanceVerdictLink(",
        "    evidenceClass: EvidenceClass | None = Field(\n        None,\n        description=\"Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.\",\n    )\n\n    @model_validator(mode=\"after\")\n    def _incomplete_excludes_guard(self) -> \"ChioProvenanceVerdictLink4\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"incomplete verdict must not include guard\")\n        return self\n\n\nclass ChioProvenanceVerdictLink(",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn replace_python_codegen_snippet(
    path: &Path,
    body: &mut String,
    needle: &str,
    replacement: &str,
) -> Result<(), XtaskError> {
    if !body.contains(needle) {
        return Err(XtaskError::ToolFailed(format!(
            "codegen python hardening pattern missing in {}",
            display_path(path)
        )));
    }
    *body = body.replacen(needle, replacement, 1);
    Ok(())
}

/// Per-subpackage re-export plan built by [`rewrite_python_subpackage_inits`].
///
/// Each entry is `(subpackage_dir_name, [class_name, ...])` sorted by
/// `subpackage_dir_name`. Class names are sorted within each subpackage so
/// the output is byte-stable across regenerations on different filesystems.
type PythonSubpackageExports = Vec<(String, Vec<String>)>;

fn build_python_top_init(schema_digest: &str, subpackages: &PythonSubpackageExports) -> String {
    let header = build_python_file_header(schema_digest);

    // Build the deterministic re-export block. Each line is
    // `from .<subpkg> import <Class1>, <Class2>` plus an `__all__` listing
    // every re-exported name and the SCHEMA_SHA256 constant.
    let mut imports = String::new();
    let mut all_names: Vec<String> = vec!["SCHEMA_SHA256".to_string()];
    for (subpkg, classes) in subpackages {
        let mut import_classes = classes.clone();
        if subpkg == "agent" {
            import_classes.retain(|name| name != "CapabilityToken");
        }
        if import_classes.is_empty() {
            continue;
        }
        imports.push_str(&format!(
            "from .{subpkg} import {names}\n",
            names = import_classes.join(", ")
        ));
        all_names.extend(import_classes.iter().cloned());
    }
    if subpackages.iter().any(|(subpkg, classes)| {
        subpkg == "capability" && classes.iter().any(|name| name == "ChioCapabilitytoken")
    }) {
        imports.push_str("\nCapabilityToken = ChioCapabilitytoken\n");
        all_names.push("CapabilityToken".to_string());
    }
    all_names.sort();
    all_names.dedup();

    let mut all_block = String::from("__all__ = [\n");
    for name in &all_names {
        all_block.push_str(&format!("    \"{name}\",\n"));
    }
    all_block.push_str("]\n");

    format!(
        "{header}\n\
         \"\"\"Generated Pydantic v2 models for the Chio wire protocol (chio-wire/v1).\n\
         \n\
         Re-exports every subpackage so callers can write\n\
         ``from chio_sdk._generated import CapabilityToken`` for the canonical\n\
         capability token shape without knowing the per-subpackage layout. The\n\
         SCHEMA_SHA256 constant pins the schema set this build was generated from;\n\
         the spec-drift CI lane reads it to detect tampering.\n\
         \"\"\"\n\
         \n\
         from __future__ import annotations\n\
         \n\
         #: SHA-256 of the lexicographically sorted concatenation of every\n\
         #: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was\n\
         #: fed into datamodel-code-generator at build time.\n\
         SCHEMA_SHA256 = \"{schema_digest}\"\n\
         \n\
         {imports}\n\
         {all_block}"
    )
}

/// Walk every subpackage directory under `root_dir`, scan each `*.py` module
/// (other than `__init__.py`) for top-level `class Name(...):` declarations,
/// rewrite the subpackage's `__init__.py` to re-export those classes, and
/// return the (sorted) plan so the top-level `__init__.py` can re-export
/// each subpackage in turn.
fn rewrite_python_subpackage_inits(
    root_dir: &Path,
    schema_digest: &str,
) -> Result<PythonSubpackageExports, XtaskError> {
    let header = build_python_file_header(schema_digest);
    let mut subpackages: PythonSubpackageExports = Vec::new();
    let entries =
        fs::read_dir(root_dir).map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        }
    }
    subdirs.sort();

    for subdir in subdirs {
        let Some(name) = subdir.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if name.starts_with('_') {
            continue;
        }
        let mut module_classes: Vec<(String, Vec<String>)> = Vec::new();
        let module_entries =
            fs::read_dir(&subdir).map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
        let mut modules: Vec<PathBuf> = Vec::new();
        for me in module_entries {
            let me = me.map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
            let p = me.path();
            if !p.is_file() {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(OsStr::to_str) else {
                continue;
            };
            if p.extension().and_then(OsStr::to_str) != Some("py") {
                continue;
            }
            if stem == "__init__" {
                continue;
            }
            modules.push(p);
        }
        modules.sort();

        let mut all_classes: Vec<String> = Vec::new();
        for module in &modules {
            let stem = module
                .file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            let body = fs::read_to_string(module)
                .map_err(|err| XtaskError::Io(display_path(module), err))?;
            let classes = extract_top_level_python_classes(&body);
            if !classes.is_empty() {
                all_classes.extend(classes.iter().cloned());
                module_classes.push((stem, classes));
            }
        }
        all_classes.sort();
        all_classes.dedup();

        // Rewrite the subpackage __init__.py with explicit imports per
        // module and a deterministic __all__. The header is preserved so
        // the spec-drift CI lane's per-file header check still
        // passes.
        let init_path = subdir.join(PYTHON_INIT_FILE);
        let mut body = header.clone();
        body.push('\n');
        body.push_str("from __future__ import annotations\n\n");
        for (module_stem, classes) in &module_classes {
            body.push_str(&format!(
                "from .{module_stem} import {names}\n",
                names = classes.join(", ")
            ));
        }
        body.push('\n');
        body.push_str("__all__ = [\n");
        for name in &all_classes {
            body.push_str(&format!("    \"{name}\",\n"));
        }
        body.push_str("]\n");
        fs::write(&init_path, body).map_err(|err| XtaskError::Io(display_path(&init_path), err))?;

        subpackages.push((name.to_string(), all_classes));
    }
    Ok(subpackages)
}

/// Extract top-level `class Name(...):` declarations from a Python module
/// source. Datamodel-codegen output uses 4-space indentation and never
/// nests classes at the module top level beyond a single colon-suffix
/// declaration line, so a string-prefix scan is sufficient (and avoids
/// adding a Python-AST dependency to xtask).
fn extract_top_level_python_classes(body: &str) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    for line in body.lines() {
        // Must begin in column zero (top-level), with `class ` then the
        // identifier, optionally followed by a parenthesized base list
        // and a trailing colon.
        let Some(rest) = line.strip_prefix("class ") else {
            continue;
        };
        let mut name = String::new();
        for ch in rest.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name.push(ch);
            } else {
                break;
            }
        }
        if name.is_empty() {
            continue;
        }
        // Skip private classes (datamodel-codegen does not emit any, but be
        // defensive against future changes).
        if name.starts_with('_') {
            continue;
        }
        classes.push(name);
    }
    classes.sort();
    classes.dedup();
    classes
}

fn mirror_schema_tree(
    src_root: &Path,
    dst_root: &Path,
    schema_files: &[PathBuf],
) -> Result<(), XtaskError> {
    fs::create_dir_all(dst_root).map_err(|err| XtaskError::Io(display_path(dst_root), err))?;
    for path in schema_files {
        let rel = path.strip_prefix(src_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen python: schema file {} is not under {}",
                display_path(path),
                display_path(src_root)
            ))
        })?;
        let dest = dst_root.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
        }
        fs::copy(path, &dest).map_err(|err| XtaskError::Io(display_path(&dest), err))?;
    }
    Ok(())
}

fn invoke_datamodel_codegen(
    input_dir: &Path,
    output_dir: &Path,
    header_path: &Path,
) -> Result<(), XtaskError> {
    let mut cmd = Command::new("uv");
    cmd.arg("tool")
        .arg("run")
        .arg("--from")
        .arg(PYTHON_CODEGEN_TOOL_PIN)
        .arg("datamodel-codegen")
        .arg("--input")
        .arg(input_dir)
        .arg("--input-file-type")
        .arg("jsonschema")
        .arg("--output")
        .arg(output_dir)
        .arg("--output-model-type")
        .arg("pydantic_v2.BaseModel")
        .arg("--target-python-version")
        .arg("3.11")
        .arg("--use-double-quotes")
        .arg("--use-standard-collections")
        .arg("--use-union-operator")
        .arg("--use-schema-description")
        .arg("--disable-timestamp")
        .arg("--custom-file-header-path")
        .arg(header_path);

    let output = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            XtaskError::ToolMissing(format!(
                "`uv` not found on PATH; install via https://docs.astral.sh/uv/ then rerun (underlying error: {err})"
            ))
        } else {
            XtaskError::Io("uv tool run datamodel-codegen".to_string(), err)
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(XtaskError::ToolFailed(format!(
            "datamodel-codegen exited {}\nstdout: {}\nstderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    Ok(())
}

fn hash_schema_set(workspace_root: &Path, schema_files: &[PathBuf]) -> Result<String, XtaskError> {
    let mut hasher = Sha256::new();
    for path in schema_files {
        let rel = path.strip_prefix(workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen python: schema file {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        hasher.update(rel_str.as_bytes());
        hasher.update(b"\n");
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        hasher.update(&bytes);
        hasher.update(b"\n");
    }
    Ok(digest_to_hex(&hasher.finalize()))
}

fn count_python_files(dir: &Path) -> Result<usize, XtaskError> {
    let mut count = 0usize;
    walk_python_files(dir, &mut count)?;
    Ok(count)
}

fn walk_python_files(dir: &Path, count: &mut usize) -> Result<(), XtaskError> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_python_files(&path, count)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "py" {
                    *count += 1;
                }
            }
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), XtaskError> {
    fs::create_dir_all(dst).map_err(|err| XtaskError::Io(display_path(dst), err))?;
    let entries = fs::read_dir(src).map_err(|err| XtaskError::Io(display_path(src), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(src), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let Some(name) = path.file_name() else {
            continue;
        };
        if name == "__pycache__" {
            continue;
        }
        let target = dst.join(name);
        if file_type.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            fs::copy(&path, &target).map_err(|err| XtaskError::Io(display_path(&target), err))?;
        }
    }
    Ok(())
}

fn diff_python_trees(expected: &Path, actual: &Path) -> Result<Option<String>, XtaskError> {
    if !actual.exists() {
        return Ok(Some(format!(
            "  on-disk dir {} is missing entirely",
            display_path(actual)
        )));
    }
    let mut expected_files: Vec<PathBuf> = Vec::new();
    let mut actual_files: Vec<PathBuf> = Vec::new();
    collect_relative_files(expected, expected, &mut expected_files)?;
    collect_relative_files(actual, actual, &mut actual_files)?;
    expected_files.sort();
    actual_files.sort();

    let mut diff_lines: Vec<String> = Vec::new();
    let limit = 12usize;
    let mut differing = 0usize;

    let exp_set: std::collections::BTreeSet<_> = expected_files.iter().cloned().collect();
    let act_set: std::collections::BTreeSet<_> = actual_files.iter().cloned().collect();
    for missing in exp_set.difference(&act_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!("  + missing on disk: {}", missing.display()));
        }
    }
    for extra in act_set.difference(&exp_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!(
                "  - present on disk but not regenerated: {}",
                extra.display()
            ));
        }
    }
    for rel in exp_set.intersection(&act_set) {
        let exp_bytes = fs::read(expected.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&expected.join(rel)), err))?;
        let act_bytes = fs::read(actual.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&actual.join(rel)), err))?;
        if exp_bytes != act_bytes {
            differing += 1;
            if diff_lines.len() < limit {
                diff_lines.push(format!(
                    "  ! bytes differ: {} (expected {} bytes, on-disk {} bytes)",
                    rel.display(),
                    exp_bytes.len(),
                    act_bytes.len()
                ));
            }
        }
    }

    if differing == 0 {
        return Ok(None);
    }
    let mut summary = diff_lines.join("\n");
    if differing > limit {
        summary.push_str(&format!(
            "\n  ... ({} more differing entries)",
            differing - limit
        ));
    }
    Ok(Some(summary))
}

fn collect_relative_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name == "__pycache__" {
            continue;
        }
        if file_type.is_dir() {
            collect_relative_files(root, &path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let mut base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        base.push(format!("{prefix}-{pid}-{nanos}"));
        fs::create_dir_all(&base)?;
        Ok(Self { path: base })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
