//! P4.T4 hover provider integration test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_lsp::hover::hover;
use chio_lsp::DocumentLanguage;
use tower_lsp::lsp_types::{HoverContents, Position};

#[test]
fn hover_on_capability_scope_renders_catalog_help() {
    let line = "  - urn:chio:scope:tool.read";
    let column = "  - urn:chio:scope:tool".len() as u32;
    let h = hover(DocumentLanguage::ChioYaml, line, Position::new(0, column))
        .expect("hover present on scope URN");
    match h.contents {
        HoverContents::Markup(m) => {
            assert!(m.value.contains("urn:chio:scope:tool.read"));
            assert!(m.value.to_lowercase().contains("read"));
        }
        _ => panic!("expected markup"),
    }
}

#[test]
fn hover_on_guard_identifier_renders_catalog_help() {
    let line = "  - urn:chio:guard:input-redactor";
    let column = "  - urn:chio:guard:input".len() as u32;
    let h = hover(DocumentLanguage::ChioYaml, line, Position::new(0, column))
        .expect("hover present on guard URN");
    match h.contents {
        HoverContents::Markup(m) => assert!(m.value.contains("urn:chio:guard:input-redactor")),
        _ => panic!("expected markup"),
    }
}

#[test]
fn hover_on_error_code_renders_registry_help() {
    let line = "code: urn:chio:error:capability:expired";
    let column = "code: urn:chio:error:capability:exp".len() as u32;
    let h = hover(DocumentLanguage::ChioYaml, line, Position::new(0, column))
        .expect("hover present on error URN");
    match h.contents {
        HoverContents::Markup(m) => {
            assert!(m.value.contains("urn:chio:error:capability:expired"));
            // Help text from the registry should mention "capability".
            assert!(m.value.to_lowercase().contains("capability"));
        }
        _ => panic!("expected markup"),
    }
}

#[test]
fn hover_on_unknown_urn_returns_none() {
    let line = "  - urn:chio:unknown:thing";
    let h = hover(DocumentLanguage::ChioYaml, line, Position::new(0, 6));
    assert!(h.is_none());
}

#[test]
fn hover_off_urn_returns_none() {
    let h = hover(
        DocumentLanguage::ChioYaml,
        "version: 1",
        Position::new(0, 0),
    );
    assert!(h.is_none());
}
