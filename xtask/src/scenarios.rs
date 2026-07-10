use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::support::{display_path, walk_json, walk_schema_json, workspace_root};
use crate::XtaskError;

pub(crate) const SCHEMA_URI_PREFIX: &str = "https://chio-protocol.dev/schemas/";

pub(crate) fn validate_scenarios(args: Vec<String>) -> Result<(), XtaskError> {
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
        return Err(XtaskError::Validation(format!(
            "no scenarios found under {}",
            display_path(&scenarios_dir)
        )));
    }

    // Build a `$id` URI -> schema-path index by scanning every
    // *.schema.json under spec/schemas/. Each schema declares its canonical
    // identifier in `$id`; scenarios reference that exact value, which does
    // NOT match the on-disk path one-to-one (for example
    // `chio-wire/v1/capability/token/v1` vs the file
    // `chio-wire/v1/capability/token.schema.json`). A URI resolves via this
    // index first and falls back to the strip-prefix path mapping otherwise.
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
                // Fail closed on an unrecognized `$schema` URI: a scenario
                // that opted into schema validation must point at a real
                // schema, so a typo cannot silently bypass validation.
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
pub(crate) type SchemaIndex = BTreeMap<String, PathBuf>;

pub(crate) fn build_schema_index(schemas_root: &Path) -> Result<SchemaIndex, XtaskError> {
    let mut index: SchemaIndex = SchemaIndex::new();
    if !schemas_root.exists() {
        return Err(XtaskError::Validation(format!(
            "schema root is missing: {}",
            display_path(schemas_root)
        )));
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
///   2. the strip-prefix mapping (`<prefix><rel>` ->
///      `<schemas_root>/<rel>` plus `.schema.json`).
///
/// Returns `None` when neither path resolves to a file on disk; callers
/// then surface a hard failure rather than silently skipping the scenario.
pub(crate) fn resolve_schema_path(
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
    if schema_path_is_file_under_root(&direct, schemas_root) {
        return Some(direct);
    }
    let with_suffix = schemas_root.join(format!("{}.schema.json", rel.trim_end_matches('/')));
    if schema_path_is_file_under_root(&with_suffix, schemas_root) {
        return Some(with_suffix);
    }
    None
}

fn schema_path_is_file_under_root(path: &Path, schemas_root: &Path) -> bool {
    let Ok(root) = schemas_root.canonicalize() else {
        return false;
    };
    let Ok(candidate) = path.canonicalize() else {
        return false;
    };
    candidate.is_file() && candidate.starts_with(root)
}

pub(crate) fn collect_scenario_files(scenarios_dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    let mut out: Vec<PathBuf> = Vec::new();
    if !scenarios_dir.exists() {
        return Err(XtaskError::Validation(format!(
            "scenarios directory is missing: {}",
            display_path(scenarios_dir)
        )));
    }
    walk_json(scenarios_dir, &mut out)?;
    out.sort();
    Ok(out)
}
