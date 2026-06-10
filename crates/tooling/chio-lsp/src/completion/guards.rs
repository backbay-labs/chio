//! Guard identifier completions.
//!
//! The catalog covers the seed set of native, data, external, and
//! WASM guards.

use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, Documentation, MarkupContent, MarkupKind,
};

const GUARDS: &[(&str, &str)] = &[
    (
        "urn:chio:guard:input-redactor",
        "Redacts sensitive content in tool inputs before kernel dispatch.",
    ),
    (
        "urn:chio:guard:output-redactor",
        "Redacts sensitive content in tool outputs before they reach the agent.",
    ),
    (
        "urn:chio:guard:rate-limiter",
        "Caps tool invocations per session against the policy budget.",
    ),
    (
        "urn:chio:guard:wasm-sandbox",
        "Runs an external policy module under the chio-wasm-guards sandbox.",
    ),
    (
        "urn:chio:guard:resource-root",
        "Enforces resource-root containment on file and URI access.",
    ),
];

/// Static list of guard identifier completion items.
#[must_use]
pub fn items() -> Vec<CompletionItem> {
    GUARDS
        .iter()
        .map(|(label, help)| CompletionItem {
            label: (*label).to_string(),
            kind: Some(CompletionItemKind::ENUM_MEMBER),
            detail: Some("chio guard identifier".to_string()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value: (*help).to_string(),
            })),
            insert_text: Some((*label).to_string()),
            ..CompletionItem::default()
        })
        .collect()
}
