//! Guard DSL diagnostics.
//!
//! Validates `*.chio-guard.yaml` documents. The DSL describes a guard
//! pipeline as a list of stages. The check is deliberately narrow: the
//! document must be a mapping with `guards:` keying a sequence; each
//! stage must carry an `id:` (the `urn:chio:guard:*` reference) and an
//! optional `policy:` key. Diagnostics carry
//! `urn:chio:error:guard:denied`.

use serde_yml::Value;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};

use super::diagnostic_with_urn;

/// URN code emitted for malformed guard DSL documents.
pub const URN_GUARD_DENIED: &str = "urn:chio:error:guard:denied";

#[must_use]
pub fn validate(text: &str) -> Vec<Diagnostic> {
    if text.trim().is_empty() {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_GUARD_DENIED,
            "guard DSL document is empty; expected a mapping with `guards:`.",
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
                URN_GUARD_DENIED,
                format!("guard DSL parse error: {err}"),
            )];
        }
    };

    let Some(mapping) = doc.as_mapping() else {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_GUARD_DENIED,
            "guard DSL top-level value must be a mapping.",
        )];
    };

    let guards_value = mapping
        .iter()
        .find(|(k, _)| k.as_str().is_some_and(|s| s == "guards"));
    let Some((_, guards)) = guards_value else {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_GUARD_DENIED,
            "guard DSL is missing required key `guards`.",
        )];
    };

    let Some(seq) = guards.as_sequence() else {
        return vec![diagnostic_with_urn(
            1,
            1,
            DiagnosticSeverity::ERROR,
            URN_GUARD_DENIED,
            "`guards` must be a sequence of stage entries.",
        )];
    };

    let mut diagnostics = Vec::new();
    for (idx, stage) in seq.iter().enumerate() {
        let stage_map = match stage.as_mapping() {
            Some(m) => m,
            None => {
                diagnostics.push(diagnostic_with_urn(
                    1,
                    1,
                    DiagnosticSeverity::ERROR,
                    URN_GUARD_DENIED,
                    format!("guards[{idx}] must be a mapping."),
                ));
                continue;
            }
        };
        let id_entry = stage_map
            .iter()
            .find(|(k, _)| k.as_str().is_some_and(|s| s == "id"));
        let Some((_, id_value)) = id_entry else {
            diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_GUARD_DENIED,
                format!("guards[{idx}] is missing required key `id`."),
            ));
            continue;
        };
        match id_value.as_str() {
            Some(id) if id.starts_with("urn:chio:guard:") => {}
            Some(id) => diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_GUARD_DENIED,
                format!("guards[{idx}] id `{id}` must be a urn:chio:guard:* identifier."),
            )),
            None => diagnostics.push(diagnostic_with_urn(
                1,
                1,
                DiagnosticSeverity::ERROR,
                URN_GUARD_DENIED,
                format!("guards[{idx}] id must be a string."),
            )),
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
    fn missing_guards_key_is_denied() {
        let diags = validate("name: demo\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_GUARD_DENIED);
    }

    #[test]
    fn stage_without_id_is_denied() {
        let diags = validate("guards:\n  - policy: relaxed\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_GUARD_DENIED);
    }

    #[test]
    fn stage_with_non_urn_id_is_denied() {
        let diags = validate("guards:\n  - id: input-redactor\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(first_code(&diags), URN_GUARD_DENIED);
    }

    #[test]
    fn well_formed_guard_dsl_is_clean() {
        let diags = validate(
            "guards:\n  - id: urn:chio:guard:input-redactor\n  - id: urn:chio:guard:rate-limiter\n",
        );
        assert!(diags.is_empty());
    }
}
