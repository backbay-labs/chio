//! P4.T6 manifest diagnostics integration test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_lsp::diagnostics::manifest::{
    validate, URN_MANIFEST_SCHEMA_INVALID, URN_MANIFEST_TOOL_NOT_REGISTERED,
};
use tower_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

fn first_code(diags: &[tower_lsp::lsp_types::Diagnostic]) -> &str {
    match diags.first().and_then(|d| d.code.as_ref()).expect("code") {
        NumberOrString::String(s) => s.as_str(),
        NumberOrString::Number(_) => panic!("expected string code"),
    }
}

#[test]
fn missing_tools_key_is_schema_invalid() {
    let diags = validate("name: demo\n");
    assert!(!diags.is_empty());
    assert_eq!(first_code(&diags), URN_MANIFEST_SCHEMA_INVALID);
    assert_eq!(diags[0].severity, Some(DiagnosticSeverity::ERROR));
}

#[test]
fn tool_without_id_is_unregistered() {
    let diags = validate("tools:\n  - name: nope\n");
    assert!(!diags.is_empty());
    assert_eq!(first_code(&diags), URN_MANIFEST_TOOL_NOT_REGISTERED);
}

#[test]
fn well_formed_manifest_emits_no_diagnostics() {
    let diags = validate("tools:\n  - id: search\n  - id: fetch\n");
    assert!(diags.is_empty());
}
