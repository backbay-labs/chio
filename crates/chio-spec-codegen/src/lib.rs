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
//!   chio_wire_v1.rs   (all types, formatted via prettyplease)
//!   mod.rs            (placeholder; not pulled into lib.rs yet)
//! ```
//!
//! The single-file emission keeps downstream consumers pointing at one
//! well-known file. The file can be split into per-group modules once the
//! `no_std + alloc` story for the generated types is settled.
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
//! - No em dashes (U+2014); use `-` or parentheses.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use typify::{TypeSpace, TypeSpaceSettings};

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

/// File name for the placeholder module entry under `_generated/`.
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
    /// The token stream emitted by typify did not parse as a `syn::File`.
    SynParse(syn::Error),
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
            Self::SynParse(err) => write!(f, "generated tokens did not parse: {err}"),
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
/// 5. Refresh the placeholder `out_dir/MOD_FILE` with [`GENERATED_HEADER`] so
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

    let settings = TypeSpaceSettings::default();
    let mut type_space = TypeSpace::new(&settings);

    for path in &schema_files {
        let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.clone(), err))?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|err| CodegenError::Json(path.clone(), err))?;
        let schema: schemars::schema::RootSchema = serde_json::from_value(value)
            .map_err(|err| CodegenError::SchemaShape(path.clone(), err))?;
        type_space
            .add_root_schema(schema)
            .map_err(|err| CodegenError::Typify(path.clone(), err.to_string()))?;
    }

    let tokens = type_space.to_stream();
    let file: syn::File = syn::parse2(tokens).map_err(CodegenError::SynParse)?;
    let pretty = prettyplease::unparse(&file);

    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);

    let out_path = out_dir.join(CHIO_WIRE_V1_OUTPUT);
    write_if_changed(&out_path, body.as_bytes())?;

    // Refresh the placeholder mod.rs so the header check passes even when
    // `_generated/` is otherwise empty (e.g. on a fresh clone). The mod.rs
    // intentionally does NOT pull in `chio_wire_v1` yet; downstream tickets
    // will gate it behind a feature flag once the no_std story is settled.
    let mod_body = format!(
        "{GENERATED_HEADER}\n\
         //! Placeholder module for the chio-wire/v1 generated types.\n\
         //!\n\
         //! This file is intentionally empty; the header is required by\n\
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

    let settings = TypeSpaceSettings::default();
    let mut type_space = TypeSpace::new(&settings);
    for path in &schema_files {
        let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.clone(), err))?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|err| CodegenError::Json(path.clone(), err))?;
        let schema: schemars::schema::RootSchema = serde_json::from_value(value)
            .map_err(|err| CodegenError::SchemaShape(path.clone(), err))?;
        type_space
            .add_root_schema(schema)
            .map_err(|err| CodegenError::Typify(path.clone(), err.to_string()))?;
    }
    let tokens = type_space.to_stream();
    let file: syn::File = syn::parse2(tokens).map_err(CodegenError::SynParse)?;
    let pretty = prettyplease::unparse(&file);
    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);
    Ok(body)
}

fn walk_schema_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
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

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
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
}
