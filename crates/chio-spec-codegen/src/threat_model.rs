//! Threat-model codegen pipeline.
//!
//! Owner: M05.P5.T2.
//!
//! Reads `spec/security/chio-threat-model.v1.json`, validates it against
//! `spec/security/chio-threat-model.schema.json`, and emits one stub
//! Rust test file per threat ID into the configured output directory
//! (typically `crates/chio-conformance/tests/threats/`). Each emitted
//! file is a minimal compiling test that calls `unimplemented!()` until
//! M05.P5.T3 fills the body in.
//!
//! The threat-model-coverage CI gate (M05.P5.T4) inspects the output
//! tree and fails the build if any threat ID lacks a populated test
//! body. The gate treats `unimplemented!()` as not-yet-covered.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{write_if_changed, CodegenError, GENERATED_HEADER};

/// Default location of the v1 threat-model JSON.
pub const THREAT_MODEL_INPUT: &str = "spec/security/chio-threat-model.v1.json";

/// Default location of the v1 threat-model JSON Schema.
pub const THREAT_MODEL_SCHEMA: &str = "spec/security/chio-threat-model.schema.json";

/// Default codegen output directory for threat-stub tests.
pub const THREAT_STUBS_OUTPUT: &str = "crates/chio-conformance/tests/threats";

/// Threat-model document parsed from the v1 JSON. Only the fields the
/// codegen pipeline cares about are deserialised; the rest are ignored
/// via `serde(default)` / `Value` so the parser does not break when new
/// optional fields land.
#[derive(Debug, Deserialize)]
pub struct ThreatModelDoc {
    /// Top-level schema discriminator (`chio.threat-model.v1`).
    pub schema: String,
    /// All threats with at minimum the fields the codegen pipeline reads.
    pub threats: Vec<ThreatEntry>,
}

/// A single entry from the `threats` array.
#[derive(Debug, Deserialize)]
pub struct ThreatEntry {
    /// Stable identifier (snake_case). Used as the codegen file stem.
    pub id: String,
    /// Human-readable name; copied into the generated module doc comment.
    pub name: String,
    /// List of surfaces the threat applies to; used in the generated doc
    /// comment so the test author knows which corpus or escape class to
    /// cite.
    pub surfaces: Vec<String>,
}

/// Validate the threat-model JSON against the v1 schema.
///
/// Returns `Ok(())` when the instance validates, and `Err` with a
/// concatenated description of every schema violation otherwise.
pub fn validate_threat_model_against_schema(
    schema_path: &Path,
    instance_path: &Path,
) -> Result<(), CodegenError> {
    let schema_raw = fs::read_to_string(schema_path)
        .map_err(|err| CodegenError::Io(schema_path.to_path_buf(), err))?;
    let schema_value: serde_json::Value = serde_json::from_str(&schema_raw)
        .map_err(|err| CodegenError::Json(schema_path.to_path_buf(), err))?;

    let instance_raw = fs::read_to_string(instance_path)
        .map_err(|err| CodegenError::Io(instance_path.to_path_buf(), err))?;
    let instance_value: serde_json::Value = serde_json::from_str(&instance_raw)
        .map_err(|err| CodegenError::Json(instance_path.to_path_buf(), err))?;

    let validator = jsonschema::validator_for(&schema_value)
        .map_err(|err| CodegenError::Registry(schema_path.to_path_buf(), err.to_string()))?;

    let errors: Vec<String> = validator
        .iter_errors(&instance_value)
        .map(|err| format!("{} at {}", err, err.instance_path()))
        .collect();

    if !errors.is_empty() {
        return Err(CodegenError::Registry(
            instance_path.to_path_buf(),
            format!(
                "threat-model JSON failed schema validation: {}",
                errors.join("; ")
            ),
        ));
    }
    Ok(())
}

/// Parse the threat-model JSON document at `path`.
pub fn load_threat_model(path: &Path) -> Result<ThreatModelDoc, CodegenError> {
    let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    let doc: ThreatModelDoc =
        serde_json::from_str(&raw).map_err(|err| CodegenError::Json(path.to_path_buf(), err))?;
    if doc.schema != "chio.threat-model.v1" {
        return Err(CodegenError::Registry(
            path.to_path_buf(),
            format!("unexpected schema discriminator: {}", doc.schema),
        ));
    }
    Ok(doc)
}

/// Render the stub source for a single threat ID. Public so callers can
/// preview the codegen output without writing to disk.
pub fn render_threat_stub(entry: &ThreatEntry) -> String {
    let surfaces = entry.surfaces.join(", ");
    format!(
        "{header}\n\
//! Stub test for threat ID `{id}` ({name}).\n\
//!\n\
//! Surfaces: {surfaces}.\n\
//!\n\
//! Owner: M05.P5.T2 (codegen) and M05.P5.T3 (test bodies for the\n\
//! six initial threat IDs). Until M05.P5.T3 lands a real test body\n\
//! the stub fails closed via `unimplemented!()` so the\n\
//! threat-model-coverage CI gate (M05.P5.T4) flags this threat ID\n\
//! as not-yet-covered.\n\
//!\n\
//! When you fill in the body, replace the `unimplemented!()` call\n\
//! with assertions that the relevant adversarial vector or escape\n\
//! class denies in the expected way and cite the threat ID in the\n\
//! comment header above the assertion.\n\
\n\
#[test]\n\
fn threat_{id}_is_covered() {{\n\
    // covers: {id}\n\
    unimplemented!(\"M05.P5.T3 must populate the test body for threat \\\"{id}\\\"\");\n\
}}\n",
        header = GENERATED_HEADER,
        id = entry.id,
        name = entry.name,
        surfaces = surfaces,
    )
}

/// Render the `mod.rs` aggregator that pulls in every per-threat stub
/// when the test crate references the directory. The aggregator is
/// optional today (each `*.rs` under `tests/threats/` is its own
/// integration test), but emitting it keeps the directory
/// self-documenting.
pub fn render_threats_mod(entries: &[ThreatEntry]) -> String {
    let mut body = String::with_capacity(GENERATED_HEADER.len() + 256);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str("//! Aggregator for the threat-model codegen stubs.\n");
    body.push_str("//!\n//! Owner: M05.P5.T2. The chio-conformance test crate does NOT\n");
    body.push_str("//! pull this module into its `lib.rs`; each per-threat `.rs` file\n");
    body.push_str("//! under this directory is its own integration test. The module\n");
    body.push_str("//! aggregator is emitted for documentation purposes only.\n\n");
    for entry in entries {
        body.push_str(&format!("// covers: {}\n", entry.id));
    }
    body
}

/// Generate one stub test file per threat ID under `out_dir` and
/// return the list of (id, file_path) pairs that were written.
///
/// `out_dir` is created if missing. Existing files whose body matches
/// the freshly rendered output are not rewritten (deterministic
/// `write_if_changed`). Files whose body diverges - because M05.P5.T3
/// or a later ticket has filled the body in - are NOT overwritten;
/// instead the codegen pass leaves them in place. The threat-model
/// coverage gate (M05.P5.T4) uses the presence of `unimplemented!()`
/// to decide whether the threat is covered.
pub fn codegen_threat_model(
    threat_model_path: &Path,
    out_dir: &Path,
) -> Result<Vec<(String, PathBuf)>, CodegenError> {
    let doc = load_threat_model(threat_model_path)?;

    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let mut written: Vec<(String, PathBuf)> = Vec::with_capacity(doc.threats.len());

    for entry in &doc.threats {
        if !is_valid_id(&entry.id) {
            return Err(CodegenError::Registry(
                threat_model_path.to_path_buf(),
                format!("threat id {:?} is not snake_case", entry.id),
            ));
        }
        let file_path = out_dir.join(format!("{}.rs", entry.id));
        let body = render_threat_stub(entry);

        // If the file already exists and has been hand-edited (i.e. no
        // longer contains `unimplemented!`), DO NOT clobber the test
        // body. Codegen is intentionally one-shot in that direction.
        if let Ok(existing) = fs::read_to_string(&file_path) {
            let has_stub_marker = existing.contains("unimplemented!");
            if !has_stub_marker {
                written.push((entry.id.clone(), file_path));
                continue;
            }
        }

        write_if_changed(&file_path, body.as_bytes())?;
        written.push((entry.id.clone(), file_path));
    }

    // Refresh the mod aggregator (always overwrite; it is pure index).
    let mod_path = out_dir.join(crate::MOD_FILE);
    write_if_changed(&mod_path, render_threats_mod(&doc.threats).as_bytes())?;

    Ok(written)
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .next()
            .map(|c| c.is_ascii_lowercase())
            .unwrap_or(false)
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ThreatEntry {
        ThreatEntry {
            id: "capability_token_theft".to_string(),
            name: "Capability token theft".to_string(),
            surfaces: vec!["trust_control".to_string(), "native_chio".to_string()],
        }
    }

    #[test]
    fn render_stub_contains_threat_id_and_unimplemented() {
        let body = render_threat_stub(&fixture());
        assert!(body.contains("// covers: capability_token_theft"));
        assert!(body.contains("unimplemented!"));
        assert!(body.contains("DO NOT EDIT"));
    }

    #[test]
    fn is_valid_id_accepts_snake_case() {
        assert!(is_valid_id("capability_token_theft"));
        assert!(is_valid_id("a"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("CapabilityTokenTheft"));
        assert!(!is_valid_id("9starts_with_digit"));
        assert!(!is_valid_id("dashes-not-allowed"));
    }
}
