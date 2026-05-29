//! Completion provider for chio-lsp.
//!
//! Offers three completion classes, each backed by a small static
//! catalog so completions are deterministic and registry-driven:
//!
//! - capability scopes (the `scopes` and `tools` keys),
//! - guard identifiers (the `guards` key, native and WASM),
//! - policy keys (top-level keys in `chio.yaml`).
//!
//! The catalog stays intentionally small; additional entries can be
//! contributed over time.

pub mod guards;
pub mod scopes;

use tower_lsp::lsp_types::{CompletionItem, Position};

use crate::document::DocumentLanguage;
use crate::position::utf16_to_byte_offset;

/// Compute completion items for a document at a position. The provider
/// inspects the line prefix and any preceding section header to pick a
/// class; if no class matches it returns an empty list rather than
/// guess.
#[must_use]
pub fn complete(language: DocumentLanguage, text: &str, position: Position) -> Vec<CompletionItem> {
    match language {
        DocumentLanguage::ChioYaml => complete_chio_yaml(text, position),
        DocumentLanguage::Manifest | DocumentLanguage::GuardDsl | DocumentLanguage::Other => {
            Vec::new()
        }
    }
}

fn complete_chio_yaml(text: &str, position: Position) -> Vec<CompletionItem> {
    let lines: Vec<&str> = text.split('\n').collect();
    let cursor_line_idx = (position.line as usize).min(lines.len().saturating_sub(1));
    let cursor_line = lines.get(cursor_line_idx).copied().unwrap_or("");
    // `position.character` is a UTF-16 code-unit count per the LSP
    // spec. Translate it to a byte offset before slicing so non-ASCII
    // text earlier on the line cannot land the index inside a UTF-8
    // boundary and panic the completion handler.
    let prefix_end = utf16_to_byte_offset(cursor_line, position.character);
    let prefix = &cursor_line[..prefix_end];

    let trimmed_prefix = prefix.trim_start();
    let in_list_or_indented =
        trimmed_prefix.starts_with('-') || (prefix.starts_with(' ') && trimmed_prefix.is_empty());

    if in_list_or_indented {
        if let Some(section) = nearest_top_level_section(&lines, cursor_line_idx) {
            return match section {
                "scopes" | "tools" | "capabilities" => scopes::items(),
                "guards" => guards::items(),
                _ => Vec::new(),
            };
        }
    }

    // Otherwise offer the top-level policy keys.
    policy_keys()
}

/// Walk upward from `cursor_line` looking for the nearest line that
/// looks like `key:` at column 0. The check stays cheap because the
/// YAML model is kept lightweight; a full AST is the eventual direction.
fn nearest_top_level_section<'a>(lines: &[&'a str], cursor_line: usize) -> Option<&'a str> {
    let mut idx = cursor_line;
    loop {
        let line = lines.get(idx).copied().unwrap_or("");
        if !line.starts_with([' ', '-', '\t']) && !line.is_empty() {
            if let Some((key, _)) = line.split_once(':') {
                return Some(key.trim());
            }
        }
        if idx == 0 {
            return None;
        }
        idx -= 1;
    }
}

/// Top-level keys recognised in `chio.yaml`. Mirrors the doctor
/// `REQUIRED_KEYS` plus the optional companion keys the registry
/// references.
#[must_use]
pub fn policy_keys() -> Vec<CompletionItem> {
    use tower_lsp::lsp_types::{CompletionItemKind, MarkupContent, MarkupKind};

    const KEYS: &[(&str, &str)] = &[
        ("version", "Schema version of this chio.yaml document."),
        ("policy", "Path to the policy file or inline policy block."),
        (
            "capabilities",
            "List of capabilities granted to this project.",
        ),
        (
            "guards",
            "List of guard identifiers active for this project.",
        ),
        ("manifest", "Path to the tool / capability manifest."),
    ];

    KEYS.iter()
        .map(|(label, help)| CompletionItem {
            label: (*label).to_string(),
            kind: Some(CompletionItemKind::PROPERTY),
            detail: Some("chio.yaml top-level key".to_string()),
            documentation: Some(tower_lsp::lsp_types::Documentation::MarkupContent(
                MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: (*help).to_string(),
                },
            )),
            insert_text: Some(format!("{label}: ")),
            ..CompletionItem::default()
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_chio_yaml_offers_top_level_keys() {
        let items = complete(DocumentLanguage::ChioYaml, "", Position::new(0, 0));
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"version"));
        assert!(labels.contains(&"policy"));
    }

    #[test]
    fn under_scopes_section_offers_capability_scopes() {
        let text = "scopes:\n  - ";
        let pos = Position::new(1, 4);
        let items = complete(DocumentLanguage::ChioYaml, text, pos);
        assert!(!items.is_empty());
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.starts_with("urn:chio:scope:")));
    }

    #[test]
    fn under_guards_section_offers_guard_identifiers() {
        let text = "guards:\n  - ";
        let pos = Position::new(1, 4);
        let items = complete(DocumentLanguage::ChioYaml, text, pos);
        assert!(!items.is_empty());
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.starts_with("urn:chio:guard:")));
    }

    #[test]
    fn other_languages_offer_no_completions() {
        let items = complete(DocumentLanguage::Other, "", Position::new(0, 0));
        assert!(items.is_empty());
    }

    #[test]
    fn non_ascii_prefix_does_not_panic_in_chio_yaml() {
        // LSP column 12 is past the 'é' accent in UTF-16 code units;
        // the helper must translate it to a UTF-8 byte boundary so
        // slicing does not panic on the multibyte character.
        let text = "policy: café\n  - ";
        let pos = Position::new(0, 12);
        // Should not panic, regardless of whether items come back.
        let _ = complete(DocumentLanguage::ChioYaml, text, pos);
    }
}
