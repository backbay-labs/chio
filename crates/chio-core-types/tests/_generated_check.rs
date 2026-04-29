//! Integration test that enforces the regenerate-only policy on every file
//! under `crates/chio-core-types/src/_generated/`.
//!
//! For each `*.rs` file under `_generated/` (recursively), we check:
//!
//! 1. The file begins with the canonical `// DO NOT EDIT` header banner. The
//!    banner is byte-for-byte identical with `chio_spec_codegen::GENERATED_HEADER`
//!    so a divergence between the codegen and the on-disk file fails CI.
//! 2. The file is reachable from the codegen pipeline (i.e. its contents do
//!    not contain a `// HAND EDIT` opt-out marker, which we forbid).
//!
//! Run via `cargo test -p chio-core-types --test _generated_check`.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Full canonical header that must begin every regenerated Rust file under
/// `_generated/`. This is the byte-for-byte source of truth: any change to
/// the header in `chio_spec_codegen::GENERATED_HEADER` must be mirrored here
/// (and vice versa). Asserting the full string rather than a single-line
/// prefix prevents stale tool-pin/source metadata from slipping through CI.
const CANONICAL_HEADER: &str = chio_spec_codegen::GENERATED_HEADER;

/// Marker that some past contributor might use to opt out of the
/// regeneration policy. We forbid it: every file under `_generated/` must be
/// produced by the codegen, period.
const FORBIDDEN_OPT_OUT: &str = "// HAND EDIT";

#[test]
fn every_generated_file_has_canonical_header() {
    let generated_dir = generated_dir();
    let files = collect_rust_files(&generated_dir);
    assert!(
        !files.is_empty(),
        "expected at least the placeholder mod.rs under {}",
        generated_dir.display()
    );
    let mut failures: Vec<String> = Vec::new();
    for path in &files {
        let Ok(body) = fs::read_to_string(path) else {
            failures.push(format!("could not read {}", path.display()));
            continue;
        };
        // Enforce the full canonical header byte-for-byte. The previous
        // check tested only the first line, so a stale `Tool:` pin or
        // out-of-date `Source:` path could pass. The header is short and
        // checked into `chio_spec_codegen`; equality is the stated invariant.
        if !body.starts_with(CANONICAL_HEADER) {
            failures.push(format!(
                "{} does not begin with the byte-for-byte canonical header (chio_spec_codegen::GENERATED_HEADER)",
                path.display()
            ));
        }
        if body.contains(FORBIDDEN_OPT_OUT) {
            failures.push(format!(
                "{} contains a forbidden `// HAND EDIT` opt-out marker",
                path.display()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "regenerate-only policy violated:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn placeholder_mod_rs_exists() {
    let mod_rs = generated_dir().join("mod.rs");
    assert!(
        mod_rs.exists(),
        "placeholder {} is missing; rerun `cargo xtask codegen rust`",
        mod_rs.display()
    );
}

fn generated_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at `crates/chio-core-types`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("_generated")
}

fn collect_rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_rust_files(&path));
        } else if path.extension().and_then(OsStr::to_str) == Some("rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}
