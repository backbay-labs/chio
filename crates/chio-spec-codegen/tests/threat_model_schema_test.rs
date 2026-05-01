//! Validate `spec/security/chio-threat-model.v1.json` against
//! `spec/security/chio-threat-model.schema.json`.
//!
//! Owner: M05.P5.T1.
//!
//! The schema asserts the four top-level keys (`schema`, `updatedAt`,
//! `boundary`, `threats`), the `boundary.surfaces` and `boundary.assets`
//! enums, and the per-threat object shape (`id`, `name`, `surfaces`,
//! `mitigations`, `residualRisk`, optional `coveredBy` and
//! `coverage_state`). The optional `coverage_state` field carries the
//! enum `{covered, partial, pending}`. `partial` is reserved for IDs
//! whose backing test exists but whose attack surface is only partially
//! defended; the milestone audit doc for the partial owner documents
//! the residual gap. The threat-model-coverage CI gate (M05.P5.T4)
//! treats `partial` as PASS but the generated
//! `docs/security/threat-coverage.md` report flags it under a separate
//! Partial heading.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

fn load_json(path: &PathBuf) -> serde_json::Value {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("parse {} as JSON: {err}", path.display()))
}

#[test]
fn schema_validates_threat_model_v1() {
    let root = repo_root();
    let schema_path = root.join("spec/security/chio-threat-model.schema.json");
    let instance_path = root.join("spec/security/chio-threat-model.v1.json");

    let schema_value = load_json(&schema_path);
    let instance_value = load_json(&instance_path);

    let validator = jsonschema::validator_for(&schema_value)
        .expect("compile chio-threat-model.schema.json");

    let errors: Vec<String> = validator
        .iter_errors(&instance_value)
        .map(|err| format!("{} at {}", err, err.instance_path()))
        .collect();

    assert!(
        errors.is_empty(),
        "chio-threat-model.v1.json failed schema validation:\n  {}",
        errors.join("\n  ")
    );
}

#[test]
fn schema_rejects_threat_missing_required_field() {
    // Negative case: a threat object missing residualRisk must be
    // rejected. Confirms the schema is load-bearing rather than
    // permissive.
    let root = repo_root();
    let schema_path = root.join("spec/security/chio-threat-model.schema.json");
    let schema_value = load_json(&schema_path);
    let validator = jsonschema::validator_for(&schema_value)
        .expect("compile chio-threat-model.schema.json");

    let bad = serde_json::json!({
        "schema": "chio.threat-model.v1",
        "updatedAt": "2026-04-30",
        "boundary": {
            "focus": "agent-kernel-tool trust boundary",
            "surfaces": ["native_chio"],
            "assets": ["capability_tokens"]
        },
        "threats": [
            {
                "id": "missing_residual_risk",
                "name": "Missing residual risk",
                "surfaces": ["native_chio"],
                "mitigations": [
                    {"status": "existing", "control": "x"}
                ]
            }
        ]
    });

    assert!(
        !validator.is_valid(&bad),
        "schema must reject threats without residualRisk"
    );
}

#[test]
fn schema_rejects_invalid_coverage_state() {
    let root = repo_root();
    let schema_path = root.join("spec/security/chio-threat-model.schema.json");
    let schema_value = load_json(&schema_path);
    let validator = jsonschema::validator_for(&schema_value)
        .expect("compile chio-threat-model.schema.json");

    let bad = serde_json::json!({
        "schema": "chio.threat-model.v1",
        "updatedAt": "2026-04-30",
        "boundary": {
            "focus": "x",
            "surfaces": ["native_chio"],
            "assets": ["capability_tokens"]
        },
        "threats": [
            {
                "id": "invalid_coverage",
                "name": "Invalid coverage state",
                "surfaces": ["native_chio"],
                "mitigations": [
                    {"status": "existing", "control": "x"}
                ],
                "residualRisk": "x",
                "coverage_state": "green"
            }
        ]
    });

    assert!(
        !validator.is_valid(&bad),
        "schema must reject coverage_state values outside {{covered, partial, pending}}"
    );
}

#[test]
fn schema_rejects_invalid_boundary_surface() {
    let root = repo_root();
    let schema_path = root.join("spec/security/chio-threat-model.schema.json");
    let schema_value = load_json(&schema_path);
    let validator = jsonschema::validator_for(&schema_value)
        .expect("compile chio-threat-model.schema.json");

    let bad = serde_json::json!({
        "schema": "chio.threat-model.v1",
        "updatedAt": "2026-04-30",
        "boundary": {
            "focus": "x",
            "surfaces": ["not_a_real_surface"],
            "assets": ["capability_tokens"]
        },
        "threats": []
    });

    assert!(
        !validator.is_valid(&bad),
        "schema must reject boundary.surfaces values outside the documented enum"
    );
}
