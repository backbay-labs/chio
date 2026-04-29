//! Vector domain to schema coverage test.
//!
//! Asserts that every vector domain shipped under `tests/bindings/vectors/<domain>/v1.json`
//! is represented in a hardcoded mapping table that pairs the domain with either
//! a wire-schema family file under `spec/schemas/chio-wire/v1/...` or `None` when
//! the domain is purely an in-memory algorithmic concern (canonical-JSON
//! encoding, manifest construction, hashing, signing) without a wire schema of
//! its own.
//!
//! The test is intentionally narrow: it does NOT validate every case against
//! every schema (that is the job of vectors_oracle.rs and downstream per-schema
//! conformance tests). It only checks that the domain-to-schema MAPPING is
//! complete: no orphan vector subtree is missing from the table, no table entry
//! references a missing vector file, and any referenced schema actually exists
//! and parses as JSON.
//!
//! Fail-closed: an unrecognized vector subtree, a missing file, or invalid JSON
//! trips a build break so new domains cannot land without an explicit decision
//! about their wire-schema pairing.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Repository root, computed from the crate manifest dir.
///
/// The crate lives at `<repo>/crates/chio-conformance`, so two `parent()` hops
/// land on the repo root that holds `tests/bindings/vectors/` and `spec/`.
fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(crates_dir) = manifest_dir.parent() else {
        panic!(
            "CARGO_MANIFEST_DIR has no parent: {}",
            manifest_dir.display()
        );
    };
    let Some(root) = crates_dir.parent() else {
        panic!("crates dir has no parent: {}", crates_dir.display());
    };
    root.to_path_buf()
}

fn vectors_root() -> PathBuf {
    repo_root().join("tests/bindings/vectors")
}

fn schemas_root() -> PathBuf {
    repo_root().join("spec/schemas")
}

/// Non-panicking JSON validator used inside the per-domain loop in
/// `every_mapping_entry_resolves_to_existing_files`. The loop accumulates
/// failures across every domain so the operator gets a single batched report.
/// Returns a human-readable error string on failure.
fn try_load_json(path: &Path) -> Result<Value, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

/// The hardcoded domain-to-schema mapping.
///
/// `None` means the domain is a pure algorithmic / in-memory contract with no
/// wire-schema family of its own; the canonical-JSON form, manifest-tree
/// construction, hashing, and signing tests are validated against the Rust
/// implementation directly via `vectors_oracle.rs`. `Some(path)` ties the
/// domain to a representative wire schema under `spec/schemas/`; the test only
/// asserts that the schema file exists and is valid JSON, leaving per-case
/// validation to other suites.
const DOMAIN_SCHEMA_MAP: &[(&str, Option<&str>)] = &[
    ("canonical", None),
    ("manifest", None),
    ("hashing", None),
    ("signing", None),
    ("receipt", Some("chio-wire/v1/receipt/record.schema.json")),
    (
        "capability",
        Some("chio-wire/v1/capability/token.schema.json"),
    ),
];

#[test]
fn every_vector_domain_has_a_schema_mapping_entry() {
    let vectors_dir = vectors_root();
    let entries = match fs::read_dir(&vectors_dir) {
        Ok(entries) => entries,
        Err(error) => panic!(
            "failed to read vectors directory {}: {error}",
            vectors_dir.display()
        ),
    };

    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("failed to enumerate {}: {error}", vectors_dir.display()),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => panic!("failed to stat {}: {error}", entry.path().display()),
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            panic!("non-UTF8 directory name under {}", vectors_dir.display());
        };
        on_disk.insert(name);
    }

    let mapped: BTreeSet<String> = DOMAIN_SCHEMA_MAP
        .iter()
        .map(|(domain, _)| (*domain).to_string())
        .collect();

    let orphan_subtrees: Vec<&String> = on_disk.difference(&mapped).collect();
    assert!(
        orphan_subtrees.is_empty(),
        "vector subtree(s) without a schema-mapping entry: {orphan_subtrees:?}; \
         add an entry to DOMAIN_SCHEMA_MAP in vectors_schema_pair.rs"
    );

    let missing_subtrees: Vec<&String> = mapped.difference(&on_disk).collect();
    assert!(
        missing_subtrees.is_empty(),
        "DOMAIN_SCHEMA_MAP entries without a corresponding vector subtree: \
         {missing_subtrees:?}; either land the vectors or remove the mapping"
    );
}

#[test]
fn every_mapping_entry_resolves_to_existing_files() {
    let vectors_dir = vectors_root();
    let schemas_dir = schemas_root();

    let mut failures: Vec<String> = Vec::new();
    for (domain, schema_rel) in DOMAIN_SCHEMA_MAP {
        let vector_path = vectors_dir.join(domain).join("v1.json");
        if !vector_path.is_file() {
            failures.push(format!(
                "domain `{domain}`: missing vector file {}",
                vector_path.display()
            ));
            continue;
        }
        // Validate the vector file parses as JSON before declaring success.
        // Use the non-panicking variant so a malformed vector file in one
        // domain does not short-circuit the loop and hide failures in
        // subsequent domains.
        if let Err(err) = try_load_json(&vector_path) {
            failures.push(format!("domain `{domain}` vector: {err}"));
            continue;
        }

        match schema_rel {
            None => {}
            Some(rel) => {
                let schema_path = schemas_dir.join(rel);
                if !schema_path.is_file() {
                    failures.push(format!(
                        "domain `{domain}`: missing schema file {}",
                        schema_path.display()
                    ));
                    continue;
                }
                if let Err(err) = try_load_json(&schema_path) {
                    failures.push(format!("domain `{domain}` schema: {err}"));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "schema-pair coverage failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
