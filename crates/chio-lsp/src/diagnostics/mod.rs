//! Diagnostics for chio-lsp documents.
//!
//! Each subdocument language (chio.yaml, manifest, guard DSL) gets a
//! dedicated provider. Providers return a flat
//! `Vec<lsp_types::Diagnostic>` so the server can publish them as-is
//! through `textDocument/publishDiagnostics`.
//!
//! Diagnostics carry `urn:chio:error:*` codes via
//! `Diagnostic::code` (a `NumberOrString::String`) so editor extensions
//! can route by registry code.

pub mod chio_yaml;

use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, NumberOrString, Position, Range, Url};

use crate::document::DocumentLanguage;

/// Build an `lsp_types::Diagnostic` with a `urn:chio:error:*` code in
/// the `code` field. The location is given as a (line, column) pair
/// because the YAML parser surfaces 1-based locations; we convert here
/// to LSP 0-based positions and zero-width ranges so the editor can
/// place a squiggle on the offending token.
pub fn diagnostic_with_urn(
    line: u32,
    column: u32,
    severity: DiagnosticSeverity,
    code: &str,
    message: impl Into<String>,
) -> Diagnostic {
    let line = line.saturating_sub(1);
    let column = column.saturating_sub(1);
    let start = Position::new(line, column);
    Diagnostic {
        range: Range::new(start, start),
        severity: Some(severity),
        code: Some(NumberOrString::String(code.to_string())),
        code_description: None,
        source: Some("chio-lsp".to_string()),
        message: message.into(),
        related_information: None,
        tags: None,
        data: None,
    }
}

/// Top-level dispatch: route to the right provider for a document.
#[must_use]
pub fn validate(language: DocumentLanguage, _uri: &Url, text: &str) -> Vec<Diagnostic> {
    match language {
        DocumentLanguage::ChioYaml => chio_yaml::validate(text),
        // Manifest + guard DSL providers land in P4.T6.
        DocumentLanguage::Manifest | DocumentLanguage::GuardDsl | DocumentLanguage::Other => {
            Vec::new()
        }
    }
}
