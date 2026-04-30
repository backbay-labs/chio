//! `chio.yaml` diagnostics.
//!
//! Mirrors the `chio doctor` chio.yaml probe (M01.P3.T6) so the
//! editor surface and the doctor surface agree on what counts as a
//! valid `chio.yaml`. Errors carry `urn:chio:error:cli:doctor-chio-yaml-invalid`
//! with a line/column anchor derived from the parser location.
//!
//! P4.T6 will extend this provider with deeper schema validation
//! against the wire-types under `spec/schemas/chio-wire/v1/` once the
//! manifest / guard-DSL providers ship; the chio.yaml top-level shape
//! is intentionally narrow (required keys, scalar shape) and stays
//! here.

use serde_yml::Value;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};

use super::diagnostic_with_urn;

/// Required top-level keys in `chio.yaml`. Keep in sync with
/// `crates/chio-cli/src/doctor/chio_yaml.rs::REQUIRED_KEYS`.
pub const REQUIRED_KEYS: &[&str] = &["version", "policy"];

/// URN code emitted for every chio.yaml diagnostic. Matches the doctor
/// probe so editor + CLI surface the same registry code.
pub const URN_CHIO_YAML_INVALID: &str = "urn:chio:error:cli:doctor-chio-yaml-invalid";

/// Validate a chio.yaml document and return any diagnostics.
#[must_use]
pub fn validate(text: &str) -> Vec<Diagnostic> {
    if text.trim().is_empty() {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_CHIO_YAML_INVALID,
            "chio.yaml is empty; expected a top-level mapping with `version` and `policy`.",
        )];
    }

    let doc: Value = match serde_yml::from_str(text) {
        Ok(v) => v,
        Err(err) => {
            let (line, column) = err
                .location()
                .map(|loc| (loc.line() as u32, loc.column() as u32))
                .unwrap_or((1, 1));
            return vec![diagnostic_with_urn(
                line,
                column,
                DiagnosticSeverity::ERROR,
                URN_CHIO_YAML_INVALID,
                format!("chio.yaml parse error: {err}"),
            )];
        }
    };

    let mapping = match doc.as_mapping() {
        Some(m) => m,
        None => {
            return vec![diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_CHIO_YAML_INVALID,
                "chio.yaml top-level value must be a mapping.",
            )];
        }
    };

    let mut diagnostics = Vec::new();
    for required in REQUIRED_KEYS {
        let present = mapping
            .iter()
            .any(|(k, _)| k.as_str().is_some_and(|s| s == *required));
        if !present {
            diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_CHIO_YAML_INVALID,
                format!("chio.yaml is missing required key `{required}`."),
            ));
        }
    }

    diagnostics
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::NumberOrString;

    fn first_code(diags: &[Diagnostic]) -> &str {
        match diags.first().and_then(|d| d.code.as_ref()).expect("code") {
            NumberOrString::String(s) => s.as_str(),
            NumberOrString::Number(_) => panic!("expected string code"),
        }
    }

    #[test]
    fn empty_document_emits_invalid_diagnostic() {
        let diags = validate("");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_CHIO_YAML_INVALID);
    }

    #[test]
    fn parse_error_carries_location() {
        let diags = validate("version: 1\n  bad: indent\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_CHIO_YAML_INVALID);
        // Parser reports a 1-based line; we translate to 0-based.
        assert!(diags[0].range.start.line >= 1);
    }

    #[test]
    fn missing_required_keys_each_get_their_own_diagnostic() {
        let diags = validate("name: demo\n");
        assert_eq!(diags.len(), REQUIRED_KEYS.len());
        for d in &diags {
            assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
            match d.code.as_ref().expect("code") {
                NumberOrString::String(s) => assert_eq!(s, URN_CHIO_YAML_INVALID),
                NumberOrString::Number(_) => panic!(),
            }
        }
    }

    #[test]
    fn complete_document_emits_no_diagnostics() {
        let diags = validate("version: 1\npolicy: ./policy.yaml\n");
        assert!(diags.is_empty());
    }

    #[test]
    fn non_mapping_top_level_is_invalid() {
        let diags = validate("- a\n- b\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_CHIO_YAML_INVALID);
    }
}
