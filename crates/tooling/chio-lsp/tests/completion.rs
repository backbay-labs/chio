//! Completion provider integration test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_lsp::completion::complete;
use chio_lsp::DocumentLanguage;
use tower_lsp::lsp_types::{CompletionItemKind, Position};

#[test]
fn top_level_chio_yaml_offers_policy_keys() {
    let items = complete(DocumentLanguage::ChioYaml, "", Position::new(0, 0));
    let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.contains(&"version"));
    assert!(labels.contains(&"policy"));
    assert!(labels.contains(&"capabilities"));
    assert!(labels.contains(&"guards"));
    for item in &items {
        assert_eq!(item.kind, Some(CompletionItemKind::PROPERTY));
    }
}

#[test]
fn under_scopes_section_offers_capability_scopes() {
    let text = "scopes:\n  - ";
    let items = complete(DocumentLanguage::ChioYaml, text, Position::new(1, 4));
    assert!(!items.is_empty());
    let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.iter().any(|l| l.starts_with("urn:chio:scope:")));
    for item in &items {
        assert_eq!(item.kind, Some(CompletionItemKind::ENUM_MEMBER));
    }
}

#[test]
fn under_guards_section_offers_guard_identifiers() {
    let text = "guards:\n  - ";
    let items = complete(DocumentLanguage::ChioYaml, text, Position::new(1, 4));
    assert!(!items.is_empty());
    let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.iter().any(|l| l.starts_with("urn:chio:guard:")));
}

#[test]
fn other_languages_yield_no_completions() {
    let items = complete(DocumentLanguage::Other, "", Position::new(0, 0));
    assert!(items.is_empty());
    let items = complete(
        DocumentLanguage::Manifest,
        "tools:\n  - ",
        Position::new(1, 4),
    );
    assert!(items.is_empty());
}
