//! Guard DSL diagnostics integration test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_lsp::diagnostics::guard_dsl::{validate, URN_GUARD_DENIED};
use tower_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

fn first_code(diags: &[tower_lsp::lsp_types::Diagnostic]) -> &str {
    match diags.first().and_then(|d| d.code.as_ref()).expect("code") {
        NumberOrString::String(s) => s.as_str(),
        NumberOrString::Number(_) => panic!("expected string code"),
    }
}

#[test]
fn missing_guards_key_is_denied() {
    let diags = validate("name: demo\n");
    assert!(!diags.is_empty());
    assert_eq!(first_code(&diags), URN_GUARD_DENIED);
    assert_eq!(diags[0].severity, Some(DiagnosticSeverity::ERROR));
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
fn well_formed_guard_dsl_emits_no_diagnostics() {
    let diags = validate(
        "guards:\n  - id: urn:chio:guard:input-redactor\n  - id: urn:chio:guard:rate-limiter\n",
    );
    assert!(diags.is_empty());
}
