//! Threat-model codegen pipeline.
//!
//! Reads `spec/security/chio-threat-model.v1.json`, validates it against
//! `spec/security/chio-threat-model.schema.json`, and emits one Rust test
//! inventory file per threat ID into the configured output directory
//! (typically `crates/tooling/chio-conformance/tests/threats/`).
//!
//! The threat-model coverage CI gate inspects the output tree and fails the
//! build if any threat ID lacks a populated regression body.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{write_if_changed, CodegenError, GENERATED_HEADER};

/// Default location of the v1 threat-model JSON.
pub const THREAT_MODEL_INPUT: &str = "spec/security/chio-threat-model.v1.json";

/// Default location of the v1 threat-model JSON Schema.
pub const THREAT_MODEL_SCHEMA: &str = "spec/security/chio-threat-model.schema.json";

/// Default codegen output directory for threat-stub tests.
pub const THREAT_STUBS_OUTPUT: &str = "crates/tooling/chio-conformance/tests/threats";

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
///
/// `entry.name` and each entry of `entry.surfaces` are interpolated into
/// generated Rust doc comments. Any ASCII control character (including
/// `\n`, `\r`, and the comment-closing `*/` sequence) in those fields is
/// replaced with a single space via [`sanitize_doc_comment`] so the
/// freely-typed text cannot break out of the comment into top-level Rust
/// code. The threat `id` is already constrained to snake_case by
/// [`is_valid_id`].
pub fn render_threat_stub(entry: &ThreatEntry) -> String {
    let safe_name = sanitize_doc_comment(&entry.name);
    let safe_surfaces = entry
        .surfaces
        .iter()
        .map(|s| sanitize_doc_comment(s))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{header}\n\
//! Stub test for threat ID `{id}` ({name}).\n\
//!\n\
//! Surfaces: {surfaces}.\n\
//!\n\
//! Until a real test body lands, the stub fails closed via\n\
//! `unimplemented!()` so the threat-model-coverage CI gate flags this\n\
//! threat ID as not-yet-covered.\n\
//!\n\
//! When you fill in the body, replace the `unimplemented!()` call\n\
//! with assertions that the relevant adversarial vector or escape\n\
//! class denies in the expected way and cite the threat ID in the\n\
//! comment header above the assertion.\n\
\n\
#[test]\n\
fn threat_{id}_is_covered() {{\n\
    // covers: {id}\n\
    unimplemented!(\"populate the test body for threat \\\"{id}\\\"\");\n\
}}\n",
        header = GENERATED_HEADER,
        id = entry.id,
        name = safe_name,
        surfaces = safe_surfaces,
    )
}

/// Strip newlines, ASCII control characters, and the block-comment
/// terminator `*/` from a free-form string before it is interpolated
/// into a generated Rust doc comment. Replaces each offending character
/// run with a single space so a malicious threat-model entry cannot
/// inject top-level code by ending the doc comment early.
fn sanitize_doc_comment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_was_space = false;
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        let unsafe_char = ch.is_control() || ch == '\u{2028}' || ch == '\u{2029}';
        let unsafe_pair = ch == '*' && chars.peek() == Some(&'/');
        if unsafe_char || unsafe_pair {
            if unsafe_pair {
                // Consume the '/'.
                chars.next();
            }
            if !prev_was_space {
                out.push(' ');
                prev_was_space = true;
            }
            continue;
        }
        out.push(ch);
        prev_was_space = false;
    }
    out
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
    body.push_str("//!\n//! The chio-conformance test crate does NOT\n");
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
/// `write_if_changed`). Files whose body diverges - because a real test
/// body has been filled in - are NOT overwritten; instead the codegen
/// pass leaves them in place. The threat-model coverage gate uses the
/// presence of `unimplemented!()`
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
        // longer contains a live `unimplemented!` call), DO NOT clobber the test
        // body. Codegen is intentionally one-shot in that direction.
        if let Ok(existing) = fs::read_to_string(&file_path) {
            let has_stub_marker = contains_live_unimplemented_marker(&existing);
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

fn contains_live_unimplemented_marker(source: &str) -> bool {
    source
        .lines()
        .map(str::trim_start)
        .any(|line| !line.starts_with("//") && line.contains("unimplemented!("))
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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

    #[test]
    fn render_stub_strips_doc_comment_escape_in_name() {
        // A threat-model entry with a newline (or `*/`) in its `name` must
        // NOT be able to break out of the generated doc comment and inject
        // top-level Rust into the stub.
        let evil = ThreatEntry {
            id: "evil_threat".to_string(),
            name: "evil\n#[panic_handler] fn p(_: &core::panic::PanicInfo) -> ! { loop {} } //"
                .to_string(),
            surfaces: vec!["native_chio".to_string()],
        };
        let body = render_threat_stub(&evil);
        // The injected attribute and item must not appear verbatim; the
        // newline before `#[panic_handler]` must have been collapsed.
        assert!(
            !body.contains("\n#[panic_handler]"),
            "doc-comment escape via newline must be neutralised: {body}"
        );
        // The stub must still parse as a valid Rust file.
        let _file: syn::File =
            syn::parse_str(&body).expect("sanitised stub must parse as Rust source");
    }

    #[test]
    fn render_stub_strips_block_comment_terminator_in_surfaces() {
        let evil = ThreatEntry {
            id: "evil_threat".to_string(),
            name: "Evil".to_string(),
            // `*/` would close a hypothetical block comment; collapse to space.
            surfaces: vec!["native_chio*/ #[no_mangle]".to_string()],
        };
        let body = render_threat_stub(&evil);
        // The fixed `GENERATED_HEADER` legitimately contains `**/*.schema.json`,
        // so check the post-header section only.
        let after_header = body
            .strip_prefix(GENERATED_HEADER)
            .expect("body must start with the canonical header");
        assert!(
            !after_header.contains("*/"),
            "block-comment terminator must be neutralised: {after_header}"
        );
        let _file: syn::File =
            syn::parse_str(&body).expect("sanitised stub must parse as Rust source");
    }

    #[test]
    fn sanitize_doc_comment_collapses_runs_of_unsafe_chars() {
        assert_eq!(sanitize_doc_comment("hello"), "hello");
        assert_eq!(sanitize_doc_comment("hello\nworld"), "hello world");
        assert_eq!(sanitize_doc_comment("hello\r\n\tworld"), "hello world");
        assert_eq!(sanitize_doc_comment("a*/b"), "a b");
        assert_eq!(sanitize_doc_comment("\nfoo\n"), " foo ");
    }

    #[test]
    fn live_unimplemented_marker_ignores_comments() {
        let filled = r#"
//! Replace the `unimplemented!()` call when editing.

#[test]
fn covered() {
    assert!(true);
}
"#;
        assert!(!contains_live_unimplemented_marker(filled));

        let stub = r#"
#[test]
fn pending() {
    unimplemented!("fill me");
}
"#;
        assert!(contains_live_unimplemented_marker(stub));
    }
}
