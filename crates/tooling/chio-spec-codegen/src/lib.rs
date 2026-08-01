//! Schema-to-Rust codegen for the Chio wire protocol.
//!
//! This crate is the Rust half of the four-language codegen pipeline gated by
//! `cargo xtask codegen` (see `xtask/codegen-tools.lock.toml` for the pinned
//! tool set per language). It walks
//! `spec/schemas/chio-wire/v1/**/*.schema.json`, parses each file as a
//! `schemars::schema::RootSchema`, registers every schema with a single
//! `typify::TypeSpace`, and emits one Rust source file per top-level schema
//! group (`agent/`, `capability/`, `error/`, ...). Each emitted file carries
//! the canonical `// DO NOT EDIT` header so downstream tooling and humans can
//! tell at a glance that the file is a regeneration target.
//!
//! # Output layout
//!
//! For an input tree like
//!
//! ```text
//! spec/schemas/chio-wire/v1/
//!   agent/heartbeat.schema.json
//!   agent/list_capabilities.schema.json
//!   jsonrpc/request.schema.json
//!   ...
//! ```
//!
//! the generator produces:
//!
//! ```text
//! crates/chio-core-types/src/_generated/
//!   chio_wire_v1.rs   (one module per unreferenced root schema)
//!   mod.rs            (header-only module marker; not pulled into lib.rs yet)
//! ```
//!
//! The single-file emission keeps downstream consumers pointing at one
//! well-known file.
//!
//! # Header policy
//!
//! Every regenerated file begins with [`GENERATED_HEADER`]. The companion
//! `crates/chio-core-types/tests/_generated_check.rs` integration test scans
//! every `*.rs` file under `_generated/` and fails the build if any file is
//! missing the header.
//!
//! # Determinism
//!
//! Schema files are sorted lexicographically before being added to the
//! `TypeSpace`, and the resulting token stream is fed through `prettyplease`
//! so the byte output is reproducible across machines. The xtask
//! `codegen --check` mode compares the freshly regenerated output against the
//! on-disk file and exits non-zero on drift.
//!
//! # House rules
//!
//! - No `unwrap()` / `expect()` in non-test code (workspace clippy denies).
//! - All errors are surfaced as [`CodegenError`]; the crate never panics on
//!   malformed input.
//! - Absolute URI `$ref`s fail closed before typify generation; Rust codegen
//!   only accepts internal fragments and local schema-tree references.
//! - No em dashes (U+2014); use `-` or parentheses.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use typify::{TypeSpace, TypeSpaceSettings};

mod errors_pass;
pub mod threat_coverage_doc;
pub mod threat_model;

pub use errors_pass::{
    codegen_error_codes, render_error_codes, ERRORS_GENERATED_DIR, ERROR_CODES_OUTPUT,
    ERROR_REGISTRY_INPUT,
};
pub use threat_coverage_doc::{
    codegen_threat_coverage_doc, codegen_threat_coverage_doc_default, render_threat_coverage_doc,
    ThreatCoverageInputs, ADVERSARIAL_MANIFEST, ESCAPE_HARNESS_DIR, THREAT_COVERAGE_DOC,
    THREAT_STUBS_DIR,
};
pub use threat_model::{
    codegen_threat_model, load_threat_model, render_threat_stub, render_threats_mod,
    validate_threat_model_against_schema, ThreatEntry, ThreatModelDoc, THREAT_MODEL_INPUT,
    THREAT_MODEL_SCHEMA, THREAT_STUBS_OUTPUT,
};

/// Canonical header stamped onto every regenerated Rust source file.
///
/// The phrasing is matched exactly by
/// `crates/chio-core-types/tests/_generated_check.rs`. Keep this string in
/// sync with that test and with `xtask::codegen` if either is updated.
pub const GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/chio-core-types/src/_generated/`.
";

/// File name for the consolidated chio-wire/v1 Rust output.
pub const CHIO_WIRE_V1_OUTPUT: &str = "chio_wire_v1.rs";

/// File name for the header-only module marker under `_generated/`.
pub const MOD_FILE: &str = "mod.rs";

/// Errors raised by the codegen pipeline.
#[derive(Debug)]
pub enum CodegenError {
    /// Failed to read or write a file.
    Io(PathBuf, io::Error),
    /// A schema file did not parse as JSON.
    Json(PathBuf, serde_json::Error),
    /// A schema file parsed as JSON but not as a `schemars::RootSchema`.
    SchemaShape(PathBuf, serde_json::Error),
    /// `typify::TypeSpace::add_root_schema` rejected the schema.
    Typify(PathBuf, String),
    /// A local JSON Schema reference could not be resolved for typify.
    SchemaRef(PathBuf, String),
    /// The token stream emitted by typify did not parse as a `syn::File`.
    SynParse(syn::Error),
    /// `rustfmt` could not format generated Rust source.
    Rustfmt(PathBuf, String),
    /// The error registry YAML could not be loaded or validated.
    Registry(PathBuf, String),
    /// The schemas directory did not exist on disk.
    SchemasDirMissing(PathBuf),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "io error on {}: {err}", path.display()),
            Self::Json(path, err) => write!(f, "json parse error in {}: {err}", path.display()),
            Self::SchemaShape(path, err) => {
                write!(f, "schema shape error in {}: {err}", path.display())
            }
            Self::Typify(path, msg) => {
                write!(f, "typify rejected schema {}: {msg}", path.display())
            }
            Self::SchemaRef(path, msg) => {
                write!(f, "schema reference error in {}: {msg}", path.display())
            }
            Self::SynParse(err) => write!(f, "generated tokens did not parse: {err}"),
            Self::Rustfmt(path, msg) => {
                write!(f, "rustfmt failed for {}: {msg}", path.display())
            }
            Self::Registry(path, msg) => {
                write!(
                    f,
                    "error registry load failed for {}: {msg}",
                    path.display()
                )
            }
            Self::SchemasDirMissing(path) => {
                write!(f, "schemas directory does not exist: {}", path.display())
            }
        }
    }
}

impl std::error::Error for CodegenError {}

/// Result alias for the public API.
pub type Result<T> = core::result::Result<T, CodegenError>;

/// Generate Rust types from every schema under `schemas_dir` and write them
/// to `out_dir`.
///
/// This is the single entry point used by both the `chio-spec-codegen` binary
/// and `cargo xtask codegen rust`. The pipeline is:
///
/// 1. Walk `schemas_dir` recursively, collecting every `*.schema.json` file
///    in lexicographic order.
/// 2. Parse each file as `schemars::schema::RootSchema` and register it with
///    a shared `typify::TypeSpace`.
/// 3. Render the `TypeSpace` to a `proc_macro2::TokenStream`, parse it as a
///    `syn::File`, and pretty-print via `prettyplease`.
/// 4. Prepend [`GENERATED_HEADER`] and write to
///    `out_dir/CHIO_WIRE_V1_OUTPUT`.
/// 5. Refresh the header-only `out_dir/MOD_FILE` with [`GENERATED_HEADER`] so
///    the integration test's header check stays green.
///
/// The function creates `out_dir` (and parents) if it does not already exist.
pub fn codegen_rust(schemas_dir: &Path, out_dir: &Path) -> Result<()> {
    if !schemas_dir.exists() {
        return Err(CodegenError::SchemasDirMissing(schemas_dir.to_path_buf()));
    }

    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_files(schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let referenced_schema_roots = collect_local_schema_ref_roots(&schema_files, schemas_dir)?;

    let pretty = render_schema_modules(&schema_files, schemas_dir, &referenced_schema_roots)?;

    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);

    let out_path = out_dir.join(CHIO_WIRE_V1_OUTPUT);
    let formatted = rustfmt_generated(&out_path, &body)?;
    write_if_changed(&out_path, formatted.as_bytes())?;

    // Refresh mod.rs so the header check passes on a fresh clone.
    // mod.rs intentionally does not re-export `chio_wire_v1`; the generated
    // bindings stay quarantined until the public API surface is settled.
    let mod_body = format!(
        "{GENERATED_HEADER}\n\
         //! Header-only module marker for the chio-wire/v1 generated types.\n\
         //!\n\
         //! This file intentionally declares no submodules. Generated wire\n\
         //! bindings remain quarantined until the public API and no_std story\n\
         //! are explicitly settled. The header is required by\n\
         //! `crates/chio-core-types/tests/_generated_check.rs`.\n"
    );
    let mod_path = out_dir.join(MOD_FILE);
    write_if_changed(&mod_path, mod_body.as_bytes())?;

    Ok(())
}

/// Render the chio-wire/v1 codegen to an in-memory string without touching
/// the filesystem. Used by the xtask `--check` mode to detect drift.
pub fn render_chio_wire_v1(schemas_dir: &Path) -> Result<String> {
    if !schemas_dir.exists() {
        return Err(CodegenError::SchemasDirMissing(schemas_dir.to_path_buf()));
    }
    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_files(schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let referenced_schema_roots = collect_local_schema_ref_roots(&schema_files, schemas_dir)?;

    let pretty = render_schema_modules(&schema_files, schemas_dir, &referenced_schema_roots)?;
    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);
    rustfmt_generated(Path::new(CHIO_WIRE_V1_OUTPUT), &body)
}

pub(crate) fn rustfmt_generated(path: &Path, source: &str) -> Result<String> {
    let mut child = Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2021"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt"), err))?;

    let Some(mut stdin) = child.stdin.take() else {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            "stdin unavailable".to_string(),
        ));
    };
    stdin
        .write_all(source.as_bytes())
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt stdin"), err))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt"), err))?;
    if !output.status.success() {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| CodegenError::Rustfmt(path.to_path_buf(), err.to_string()))
}

fn render_schema_modules(
    schema_files: &[PathBuf],
    schemas_dir: &Path,
    referenced_schema_roots: &BTreeSet<PathBuf>,
) -> Result<String> {
    let settings = TypeSpaceSettings::default();
    let mut source = String::new();

    for path in schema_files {
        if should_skip_referenced_root(path, referenced_schema_roots)? {
            continue;
        }
        let value = load_schema_value(path, schemas_dir)?;
        let schema: schemars::schema::RootSchema = serde_json::from_value(value)
            .map_err(|err| CodegenError::SchemaShape(path.clone(), err))?;
        let mut type_space = TypeSpace::new(&settings);
        type_space
            .add_root_schema(schema)
            .map_err(|err| CodegenError::Typify(path.clone(), err.to_string()))?;
        let tokens = type_space.to_stream();
        let file: syn::File = syn::parse2(tokens).map_err(CodegenError::SynParse)?;
        let module_name = schema_module_name(path, schemas_dir)?;
        source.push_str("pub mod ");
        source.push_str(&module_name);
        source.push_str(" {\n");
        source.push_str(&prettyplease::unparse(&file));
        source.push_str("}\n");
    }

    let file = syn::parse_file(&source).map_err(CodegenError::SynParse)?;
    Ok(prettyplease::unparse(&file))
}

fn schema_module_name(path: &Path, schemas_dir: &Path) -> Result<String> {
    let relative = path.strip_prefix(schemas_dir).map_err(|_| {
        CodegenError::SchemaRef(
            path.to_path_buf(),
            format!("schema is outside {}", schemas_dir.display()),
        )
    })?;
    let relative = relative.to_string_lossy();
    let stem = relative
        .strip_suffix(".schema.json")
        .unwrap_or(relative.as_ref());
    Ok(stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect())
}

fn walk_schema_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
        if file_type.is_symlink() {
            return Err(CodegenError::SchemaRef(
                path,
                "refusing symlink in schema tree".to_string(),
            ));
        }
        if file_type.is_dir() {
            walk_schema_files(&path, out)?;
        } else if file_type.is_file() && is_schema_json(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_schema_json(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name.ends_with(".schema.json")
}

fn load_schema_value(path: &Path, schemas_dir: &Path) -> Result<serde_json::Value> {
    let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|err| CodegenError::Json(path.to_path_buf(), err))?;
    let mut extra_defs = serde_json::Map::new();
    inline_local_schema_refs(&mut value, path, schemas_dir, &mut extra_defs)?;
    merge_extra_defs_into_root(&mut value, extra_defs, path)?;
    strip_typify_unsupported_conditionals(&mut value);
    Ok(value)
}

fn collect_local_schema_ref_roots(
    schema_files: &[PathBuf],
    schemas_dir: &Path,
) -> Result<BTreeSet<PathBuf>> {
    let mut referenced_roots = BTreeSet::new();

    for path in schema_files {
        let raw =
            fs::read_to_string(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|err| CodegenError::Json(path.to_path_buf(), err))?;
        collect_local_schema_ref_roots_from_value(
            &value,
            path,
            schemas_dir,
            &mut referenced_roots,
        )?;
    }

    Ok(referenced_roots)
}

fn collect_local_schema_ref_roots_from_value(
    value: &serde_json::Value,
    base_path: &Path,
    schemas_dir: &Path,
    referenced_roots: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                if let Some((target_path, fragment)) =
                    resolve_local_schema_ref(reference, base_path, schemas_dir)?
                {
                    let targets_root = match fragment.as_deref() {
                        None | Some("") => true,
                        Some(_) => false,
                    };
                    if targets_root {
                        referenced_roots.insert(target_path);
                    }
                }
            }
            for item in map.values() {
                collect_local_schema_ref_roots_from_value(
                    item,
                    base_path,
                    schemas_dir,
                    referenced_roots,
                )?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_local_schema_ref_roots_from_value(
                    item,
                    base_path,
                    schemas_dir,
                    referenced_roots,
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn should_skip_referenced_root(
    path: &Path,
    referenced_schema_roots: &BTreeSet<PathBuf>,
) -> Result<bool> {
    let path = fs::canonicalize(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    Ok(referenced_schema_roots.contains(&path))
}

fn inline_local_schema_refs(
    value: &mut serde_json::Value,
    base_path: &Path,
    schemas_dir: &Path,
    extra_defs: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                if let Some((target_path, fragment)) =
                    resolve_local_schema_ref(reference, base_path, schemas_dir)?
                {
                    let target = load_schema_value(&target_path, schemas_dir)?;
                    merge_referenced_defs(&target, extra_defs, base_path, reference)?;
                    let mut resolved = resolve_json_pointer(&target, fragment.as_deref())
                        .map_err(|msg| {
                            CodegenError::SchemaRef(
                                base_path.to_path_buf(),
                                format!("{reference}: {msg}"),
                            )
                        })?
                        .clone();
                    strip_inlined_resource_keywords(&mut resolved);
                    *value = resolved;
                    return Ok(());
                }
            }
            for item in map.values_mut() {
                inline_local_schema_refs(item, base_path, schemas_dir, extra_defs)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                inline_local_schema_refs(item, base_path, schemas_dir, extra_defs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_local_schema_ref(
    reference: &str,
    base_path: &Path,
    schemas_dir: &Path,
) -> Result<Option<(PathBuf, Option<String>)>> {
    let (path_part, fragment) = reference
        .split_once('#')
        .map_or((reference, None), |(path, fragment)| {
            (path, Some(fragment.to_string()))
        });

    if path_part.is_empty() {
        return Ok(None);
    }
    if has_uri_scheme(path_part) {
        return Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} uses an external schema reference"),
        ));
    }

    let base_dir = base_path.parent().ok_or_else(|| {
        CodegenError::SchemaRef(
            base_path.to_path_buf(),
            "schema path has no parent directory".to_string(),
        )
    })?;
    let target_path = base_dir.join(path_part);
    let target_path =
        fs::canonicalize(&target_path).map_err(|err| CodegenError::Io(target_path.clone(), err))?;
    let schemas_dir =
        fs::canonicalize(schemas_dir).map_err(|err| CodegenError::Io(schemas_dir.into(), err))?;

    if !target_path.starts_with(&schemas_dir) {
        return Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} resolves outside {}", schemas_dir.display()),
        ));
    }

    Ok(Some((target_path, fragment)))
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.')
}

fn merge_referenced_defs(
    target: &serde_json::Value,
    extra_defs: &mut serde_json::Map<String, serde_json::Value>,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    let Some(defs) = target
        .as_object()
        .and_then(|object| object.get("$defs"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for (key, value) in defs {
        merge_schema_def(extra_defs, key, value.clone(), base_path, reference)?;
    }

    Ok(())
}

fn merge_extra_defs_into_root(
    root: &mut serde_json::Value,
    extra_defs: serde_json::Map<String, serde_json::Value>,
    path: &Path,
) -> Result<()> {
    if extra_defs.is_empty() {
        return Ok(());
    }

    let Some(root_object) = root.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "cannot merge referenced definitions into a non-object schema".to_string(),
        ));
    };

    let defs = root_object
        .entry("$defs".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(defs_object) = defs.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "root $defs is not an object".to_string(),
        ));
    };

    for (key, value) in extra_defs {
        merge_schema_def(defs_object, &key, value, path, "$defs")?;
    }

    Ok(())
}

fn merge_schema_def(
    defs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    match defs.get(key) {
        Some(existing) if existing == &value => Ok(()),
        Some(_) => Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} collides with existing $defs/{key}"),
        )),
        None => {
            defs.insert(key.to_string(), value);
            Ok(())
        }
    }
}

fn resolve_json_pointer<'a>(
    value: &'a serde_json::Value,
    fragment: Option<&str>,
) -> core::result::Result<&'a serde_json::Value, String> {
    let Some(fragment) = fragment else {
        return Ok(value);
    };
    if fragment.is_empty() {
        return Ok(value);
    }
    if !fragment.starts_with('/') {
        return Err(format!("unsupported fragment #{fragment}"));
    }

    let mut current = value;
    for token in fragment.trim_start_matches('/').split('/') {
        let token = token.replace("~1", "/").replace("~0", "~");
        current = match current {
            serde_json::Value::Object(map) => map
                .get(&token)
                .ok_or_else(|| format!("missing object key {token}"))?,
            serde_json::Value::Array(items) => {
                let index = token
                    .parse::<usize>()
                    .map_err(|_| format!("array index {token} is not numeric"))?;
                items
                    .get(index)
                    .ok_or_else(|| format!("array index {index} is out of bounds"))?
            }
            _ => {
                return Err(format!(
                    "cannot descend through non-container token {token}"
                ))
            }
        };
    }

    Ok(current)
}

fn strip_inlined_resource_keywords(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        map.remove("$schema");
        map.remove("$id");
        map.remove("$defs");
    }
}

fn strip_typify_unsupported_conditionals(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let remove_all_of = map
                .get("allOf")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item.as_object()
                            .is_some_and(|object| object.contains_key("if"))
                    })
                });
            if remove_all_of {
                map.remove("allOf");
            }
            for item in map.values_mut() {
                strip_typify_unsupported_conditionals(item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_typify_unsupported_conditionals(item);
            }
        }
        _ => {}
    }
}

pub(crate) fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    fs::write(path, bytes).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| CodegenError::Io(PathBuf::from(prefix), std::io::Error::other(err)))?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("{prefix}-{nanos}")))
    }

    #[test]
    fn header_is_non_empty() {
        assert!(GENERATED_HEADER.starts_with("// DO NOT EDIT"));
        assert!(GENERATED_HEADER.contains("typify =0.4.3"));
    }

    #[test]
    fn is_schema_json_recognises_canonical_extension() {
        assert!(is_schema_json(Path::new("foo/bar.schema.json")));
        assert!(!is_schema_json(Path::new("foo/bar.json")));
        assert!(!is_schema_json(Path::new("foo/bar.schema.yaml")));
    }

    #[test]
    fn missing_schemas_dir_is_error() {
        let nonexistent = Path::new("/tmp/chio-spec-codegen-does-not-exist-xyz");
        match render_chio_wire_v1(nonexistent) {
            Err(CodegenError::SchemasDirMissing(_)) => {}
            Err(other) => panic!("expected SchemasDirMissing, got {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn walk_schema_files_rejects_symlinked_schema_file() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-schemas")?;
        let outside = unique_temp_dir("chio-spec-codegen-outside")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        fs::create_dir_all(&outside).map_err(|err| CodegenError::Io(outside.clone(), err))?;
        fs::write(outside.join("escape.schema.json"), "{}")
            .map_err(|err| CodegenError::Io(outside.join("escape.schema.json"), err))?;
        let link_path = dir.join("escape.schema.json");
        std::os::unix::fs::symlink(outside.join("escape.schema.json"), &link_path)
            .map_err(|err| CodegenError::Io(link_path.clone(), err))?;

        let mut files = Vec::new();
        let result = walk_schema_files(&dir, &mut files);

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("escape.schema.json"));
                assert!(message.contains("symlink"));
            }
            Err(error) => panic!("expected SchemaRef symlink error, got {error}"),
            Ok(paths) => panic!("symlinked schema should fail closed: {paths:?}"),
        }
        Ok(())
    }

    #[test]
    fn render_chio_wire_v1_rejects_external_schema_ref() -> Result<()> {
        let dir = unique_temp_dir("chio-spec-codegen-external-ref")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let schema_path = dir.join("external_ref.schema.json");
        fs::write(
            &schema_path,
            br#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/test/v1/external-ref.schema.json",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "remote": {
      "$ref": "https://example.invalid/not-local.schema.json"
    }
  }
}"#,
        )
        .map_err(|err| CodegenError::Io(schema_path.clone(), err))?;

        let result = render_chio_wire_v1(&dir);
        let _ = fs::remove_dir_all(&dir);
        match result {
            Err(CodegenError::SchemaRef(path, message)) => {
                assert!(path.ends_with("external_ref.schema.json"));
                assert!(
                    message.contains("external schema reference"),
                    "unexpected message: {message}"
                );
            }
            Err(error) => panic!("expected SchemaRef external-ref error, got {error}"),
            Ok(rendered) => panic!("external schema ref should fail closed: {rendered}"),
        }
        Ok(())
    }

    #[test]
    fn tool_call_response_receipt_keeps_record_type(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| std::io::Error::other("missing workspace"))?;
        let schemas_dir = workspace_root.join("spec/schemas/chio-wire/v1");

        let rendered = render_chio_wire_v1(&schemas_dir)?;

        assert!(
            rendered.contains("pub receipt: ChioReceiptRecord,"),
            "tool_call_response.receipt must use the typed receipt record"
        );
        assert!(
            !rendered.contains("External schema reference erased for Rust typify codegen"),
            "local cross-file refs must not be erased before typify"
        );
        assert_eq!(
            rendered.matches("pub struct ChioReceiptRecord {\n").count(),
            1,
            "the referenced receipt root schema must be emitted once"
        );
        assert_eq!(
            rustfmt_generated(Path::new(CHIO_WIRE_V1_OUTPUT), &rendered)?,
            rendered,
            "wire bindings must already match rustfmt output"
        );
        Ok(())
    }
}
