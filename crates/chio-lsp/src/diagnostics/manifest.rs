//! Manifest schema diagnostics.
//!
//! Validates `*.chio-manifest.yaml` documents. The manifest carries a
//! list of `tools:` and an optional `capabilities:` section. Each
//! diagnostic carries `urn:chio:error:manifest:schema-invalid` so the
//! editor + the registry stay in lockstep.

use serde_yml::Value;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};

use super::diagnostic_with_urn;

/// URN code emitted for schema-invalid manifest documents.
pub const URN_MANIFEST_SCHEMA_INVALID: &str = "urn:chio:error:manifest:schema-invalid";

/// URN code emitted when a tool entry references a guard that is not
/// declared in the document's `guards:` allowlist (when present).
pub const URN_MANIFEST_TOOL_NOT_REGISTERED: &str = "urn:chio:error:manifest:tool-not-registered";

/// Required keys for tool entries.
pub const TOOL_REQUIRED_KEYS: &[&str] = &["id"];

#[must_use]
pub fn validate(text: &str) -> Vec<Diagnostic> {
    if text.trim().is_empty() {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_MANIFEST_SCHEMA_INVALID,
            "manifest is empty; expected a top-level mapping with `tools:`.",
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
                URN_MANIFEST_SCHEMA_INVALID,
                format!("manifest parse error: {err}"),
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
                URN_MANIFEST_SCHEMA_INVALID,
                "manifest top-level value must be a mapping.",
            )];
        }
    };

    let mut diagnostics = Vec::new();

    let tools_value = mapping
        .iter()
        .find(|(k, _)| k.as_str().is_some_and(|s| s == "tools"));
    let tools = match tools_value {
        Some((_, v)) => v,
        None => {
            diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_MANIFEST_SCHEMA_INVALID,
                "manifest is missing required key `tools`.",
            ));
            return diagnostics;
        }
    };

    let Some(tool_seq) = tools.as_sequence() else {
        diagnostics.push(diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_MANIFEST_SCHEMA_INVALID,
            "`tools` must be a sequence.",
        ));
        return diagnostics;
    };

    for (idx, tool) in tool_seq.iter().enumerate() {
        let Some(tool_map) = tool.as_mapping() else {
            diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_MANIFEST_SCHEMA_INVALID,
                format!("tool[{idx}] must be a mapping."),
            ));
            continue;
        };
        for required in TOOL_REQUIRED_KEYS {
            let present = tool_map
                .iter()
                .any(|(k, _)| k.as_str().is_some_and(|s| s == *required));
            if !present {
                diagnostics.push(diagnostic_with_urn(
                    1,
                    1,
                    DiagnosticSeverity::ERROR,
                    URN_MANIFEST_TOOL_NOT_REGISTERED,
                    format!("tool[{idx}] is missing required key `{required}`."),
                ));
            }
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
    fn empty_manifest_is_invalid() {
        let diags = validate("");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_MANIFEST_SCHEMA_INVALID);
    }

    #[test]
    fn missing_tools_key_is_invalid() {
        let diags = validate("name: demo\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_MANIFEST_SCHEMA_INVALID);
    }

    #[test]
    fn tool_without_id_is_unregistered() {
        let diags = validate("tools:\n  - name: nope\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_MANIFEST_TOOL_NOT_REGISTERED);
    }

    #[test]
    fn well_formed_manifest_is_clean() {
        let diags = validate("tools:\n  - id: search\n  - id: fetch\n");
        assert!(diags.is_empty());
    }
}
