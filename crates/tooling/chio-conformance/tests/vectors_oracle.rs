//! Cross-language vector oracle.
//!
//! Walks the canonical-JSON corpus under `tests/bindings/vectors/<subtree>/v1.json`
//! and validates that the in-tree Rust canonicalizer (the source of truth for the
//! wire format) reproduces the recorded `canonical_json` byte-for-byte from the
//! supplied `input_json`.
//!
//! The fail-closed contract: any drift between the encoder and the corpus is a
//! build break. Re-canonicalizing the input must produce exactly the recorded
//! `canonical_json` (string equality, byte equality), and re-canonicalizing the
//! `canonical_json` itself must be a fixed point.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use chio_core::canonicalize;
use serde_json::Value;

/// Repository root, computed from the crate manifest dir.
///
/// The crate lives at `<repo>/crates/chio-conformance`, so two `parent()` hops
/// land on the repo root that holds `tests/bindings/vectors/`.
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

fn load_json(path: &Path) -> Value {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => value,
        Err(error) => panic!("failed to parse {} as JSON: {error}", path.display()),
    }
}

fn cases_array(fixture: &Value, path: &Path) -> Vec<Value> {
    let Some(cases) = fixture.get("cases").and_then(Value::as_array) else {
        panic!(
            "fixture {} is missing a top-level `cases` array",
            path.display()
        );
    };
    cases.clone()
}

fn case_field<'a>(case: &'a Value, field: &str, case_id: &str, path: &Path) -> &'a str {
    let Some(text) = case.get(field).and_then(Value::as_str) else {
        panic!(
            "case `{case_id}` in {} is missing string field `{field}`",
            path.display()
        );
    };
    text
}

fn case_id<'a>(case: &'a Value, path: &Path) -> &'a str {
    let Some(id) = case.get("id").and_then(Value::as_str) else {
        panic!("a case in {} is missing string field `id`", path.display());
    };
    id
}

/// Parametric oracle: for every case in the canonical corpus, re-canonicalize
/// `input_json` and assert it matches the recorded `canonical_json` byte-for-byte.
/// Also assert idempotency: canonicalizing the recorded `canonical_json` is a
/// fixed point.
#[test]
fn canonical_corpus_round_trips_through_rust_encoder() {
    let path = vectors_root().join("canonical/v1.json");
    let fixture = load_json(&path);
    let cases = cases_array(&fixture, &path);

    assert!(
        cases.len() >= 20,
        "canonical corpus must hold at least 20 cases; found {} in {}",
        cases.len(),
        path.display()
    );

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let id = case_id(case, &path);
        let input_text = case_field(case, "input_json", id, &path);
        let expected_text = case_field(case, "canonical_json", id, &path);

        let parsed_input = match serde_json::from_str::<Value>(input_text) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!(
                    "case `{id}`: input_json failed to parse as JSON: {error}"
                ));
                continue;
            }
        };
        let actual_text = match canonicalize(&parsed_input) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!(
                    "case `{id}`: canonicalize(input_json) returned error: {error}"
                ));
                continue;
            }
        };
        if actual_text != expected_text {
            failures.push(format!(
                "case `{id}`: canonical drift\n  expected: {expected_text}\n  actual:   {actual_text}"
            ));
            continue;
        }
        if actual_text.as_bytes() != expected_text.as_bytes() {
            failures.push(format!(
                "case `{id}`: byte-equality check failed even though strings matched"
            ));
            continue;
        }

        // Idempotency: re-canonicalizing the canonical form is a fixed point.
        let parsed_canonical = match serde_json::from_str::<Value>(expected_text) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!(
                    "case `{id}`: canonical_json failed to re-parse as JSON: {error}"
                ));
                continue;
            }
        };
        let reencoded = match canonicalize(&parsed_canonical) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!(
                    "case `{id}`: canonicalize(canonical_json) returned error: {error}"
                ));
                continue;
            }
        };
        if reencoded != expected_text {
            failures.push(format!(
                "case `{id}`: not a canonical fixed point\n  canonical: {expected_text}\n  reencoded: {reencoded}"
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "canonical vector oracle failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Sanity check: every case carries the four required fields and a unique id.
/// Catches authoring mistakes in the corpus before the oracle complains.
#[test]
fn canonical_corpus_case_shape_is_well_formed() {
    let path = vectors_root().join("canonical/v1.json");
    let fixture = load_json(&path);
    let cases = cases_array(&fixture, &path);

    let mut seen_ids: Vec<String> = Vec::new();
    for case in &cases {
        let id = case_id(case, &path);
        assert!(
            !seen_ids.iter().any(|existing| existing == id),
            "duplicate case id `{id}` in {}",
            path.display()
        );
        seen_ids.push(id.to_string());

        for field in ["id", "description", "input_json", "canonical_json"] {
            assert!(
                case.get(field).and_then(Value::as_str).is_some(),
                "case `{id}` in {} is missing string field `{field}`",
                path.display()
            );
        }
    }
}
