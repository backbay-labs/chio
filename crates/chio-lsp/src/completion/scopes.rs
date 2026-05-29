//! Capability scope completions.
//!
//! The catalog is the seed set of `urn:chio:scope:*` identifiers
//! recognised by the kernel. It is extended as new scopes are
//! introduced.

use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, Documentation, MarkupContent, MarkupKind,
};

const SCOPES: &[(&str, &str)] = &[
    (
        "urn:chio:scope:tool.read",
        "Read-only tool invocations (introspection, listing).",
    ),
    (
        "urn:chio:scope:tool.write",
        "Tool invocations that mutate state or external resources.",
    ),
    (
        "urn:chio:scope:resource.read",
        "Read access to bound resource roots.",
    ),
    (
        "urn:chio:scope:resource.write",
        "Write access to bound resource roots.",
    ),
    (
        "urn:chio:scope:prompt.execute",
        "Execute pre-approved prompt templates.",
    ),
    (
        "urn:chio:scope:capability.delegate",
        "Delegate the capability to a sub-agent.",
    ),
];

/// Static list of capability scope completion items.
#[must_use]
pub fn items() -> Vec<CompletionItem> {
    SCOPES
        .iter()
        .map(|(label, help)| CompletionItem {
            label: (*label).to_string(),
            kind: Some(CompletionItemKind::ENUM_MEMBER),
            detail: Some("chio capability scope".to_string()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value: (*help).to_string(),
            })),
            insert_text: Some((*label).to_string()),
            ..CompletionItem::default()
        })
        .collect()
}
