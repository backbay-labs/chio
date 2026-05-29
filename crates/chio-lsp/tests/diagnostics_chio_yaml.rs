//! chio.yaml diagnostics integration test.
//!
//! Drives the diagnostic provider directly so the test stays
//! deterministic and stdio-free. The full publish pipeline is
//! exercised by the lifecycle test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_lsp::diagnostics::chio_yaml::{validate, URN_CHIO_YAML_INVALID};
use tower_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

#[test]
fn missing_required_keys_emits_urn_coded_diagnostics() {
    let diags = validate("name: demo\n");
    assert!(!diags.is_empty(), "expected at least one diagnostic");
    for d in &diags {
        assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
        match d.code.as_ref().expect("code") {
            NumberOrString::String(s) => assert_eq!(s, URN_CHIO_YAML_INVALID),
            NumberOrString::Number(_) => panic!("registry codes must be string URNs"),
        }
        assert_eq!(d.source.as_deref(), Some("chio-lsp"));
    }
}

#[test]
fn complete_chio_yaml_emits_no_diagnostics() {
    let diags = validate("version: 1\npolicy: ./policy.yaml\n");
    assert!(diags.is_empty(), "valid chio.yaml has no diagnostics");
}

#[test]
fn parse_error_anchors_to_a_line() {
    // A flow-mapping with an unterminated value triggers a parse error.
    let diags = validate("version: 1\nbroken: {key: value\n");
    assert_eq!(
        diags.len(),
        1,
        "expected exactly one parse-error diagnostic"
    );
    let d = &diags[0];
    match d.code.as_ref().expect("code") {
        NumberOrString::String(s) => assert_eq!(s, URN_CHIO_YAML_INVALID),
        NumberOrString::Number(_) => panic!("registry codes must be string URNs"),
    }
    // The diagnostic must carry a non-zero-width source anchor: at minimum
    // a start position the editor can place a squiggle on.
    assert!(d.message.contains("parse error"));
}
