//! Hover provider for chio-lsp.
//!
//! Renders registry-side help text on three identifier classes:
//!
//! - capability scopes (`urn:chio:scope:*`),
//! - guard identifiers (`urn:chio:guard:*`),
//! - error codes (`urn:chio:error:*`, sourced from `chio-errors`).
//!
//! For scope and guard URNs the hover text comes from the same static
//! catalogs the completion provider uses. For error codes it comes
//! from the generated registry slice in `chio_errors::ERROR_CODES`,
//! mirroring the audit doc's "registry-side `help`" contract.

use chio_errors::lookup_error_code;
use tower_lsp::lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position, Range};

use crate::completion::{guards as guard_catalog, scopes as scope_catalog};
use crate::document::DocumentLanguage;

/// Compute hover content at a position. Returns `None` if the cursor is
/// not on a recognised URN.
#[must_use]
pub fn hover(language: DocumentLanguage, text: &str, position: Position) -> Option<Hover> {
    if !matches!(
        language,
        DocumentLanguage::ChioYaml | DocumentLanguage::Manifest | DocumentLanguage::GuardDsl
    ) {
        return None;
    }

    let lines: Vec<&str> = text.split('\n').collect();
    let line = lines.get(position.line as usize).copied()?;
    let (start, end, urn) = extract_urn_at(line, position.character as usize)?;

    let help = lookup_help(&urn)?;

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format!("**{urn}**\n\n{help}"),
        }),
        range: Some(Range::new(
            Position::new(position.line, start as u32),
            Position::new(position.line, end as u32),
        )),
    })
}

fn extract_urn_at(line: &str, column: usize) -> Option<(usize, usize, String)> {
    // Find the URN spanning the column. URNs only contain
    // [A-Za-z0-9:_.-]; bound the slice by those characters.
    fn is_urn_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_')
    }
    let bytes = line.as_bytes();
    let len = bytes.len();
    if column > len {
        return None;
    }

    let mut start = column.min(len);
    while start > 0 && is_urn_char(bytes[start - 1] as char) {
        start -= 1;
    }
    let mut end = column.min(len);
    while end < len && is_urn_char(bytes[end] as char) {
        end += 1;
    }
    if start == end {
        return None;
    }
    let token = &line[start..end];
    if token.starts_with("urn:chio:") {
        Some((start, end, token.to_string()))
    } else {
        None
    }
}

fn lookup_help(urn: &str) -> Option<String> {
    if let Some(spec) = lookup_error_code(urn) {
        return Some(format!("{}\n\n{}", spec.summary, spec.help));
    }
    if let Some(item) = scope_catalog::items().into_iter().find(|i| i.label == urn) {
        return item.documentation.map(|d| match d {
            tower_lsp::lsp_types::Documentation::String(s) => s,
            tower_lsp::lsp_types::Documentation::MarkupContent(m) => m.value,
        });
    }
    if let Some(item) = guard_catalog::items().into_iter().find(|i| i.label == urn) {
        return item.documentation.map(|d| match d {
            tower_lsp::lsp_types::Documentation::String(s) => s,
            tower_lsp::lsp_types::Documentation::MarkupContent(m) => m.value,
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hover_on_scope_urn_returns_catalog_help() {
        let line = "  - urn:chio:scope:tool.read";
        let column = "  - urn:chio:scope:tool".len();
        let h = hover(
            DocumentLanguage::ChioYaml,
            line,
            Position::new(0, column as u32),
        )
        .expect("hover present");
        match h.contents {
            HoverContents::Markup(m) => assert!(m.value.contains("urn:chio:scope:tool.read")),
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
}
