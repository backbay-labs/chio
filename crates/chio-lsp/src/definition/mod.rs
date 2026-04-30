//! Go-to-definition provider for chio-lsp.
//!
//! Resolves capability (`urn:chio:scope:*`) and guard (`urn:chio:guard:*`)
//! references inside `chio.yaml` to their definition site. The
//! resolver picks the first match it finds, in priority order:
//!
//! 1. The on-disk manifest pointed at by the document's top-level
//!    `manifest:` key, if present and readable.
//! 2. The first occurrence of the same URN earlier in the current
//!    document (so a list reference resolves to its declaration site).
//!
//! If no definition is found, the provider returns `None` rather than
//! pretend.

pub mod resolver;

use tower_lsp::lsp_types::{Location, Position, Url};

use crate::document::DocumentLanguage;

/// Resolve the definition of the URN at `position` in `text`.
#[must_use]
pub fn definition(
    language: DocumentLanguage,
    uri: &Url,
    text: &str,
    position: Position,
) -> Option<Location> {
    if !matches!(
        language,
        DocumentLanguage::ChioYaml | DocumentLanguage::Manifest | DocumentLanguage::GuardDsl
    ) {
        return None;
    }
    let urn = resolver::extract_urn_at_position(text, position)?;
    if !urn.starts_with("urn:chio:scope:") && !urn.starts_with("urn:chio:guard:") {
        return None;
    }
    resolver::resolve(uri, text, &urn)
}
