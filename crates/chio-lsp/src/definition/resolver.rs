//! URN resolution helpers for the go-to-definition provider.

use std::path::PathBuf;

use tower_lsp::lsp_types::{Location, Position, Range, Url};

/// Extract the URN spanning `position` in `text`. Returns `None` if
/// the cursor is not on a `urn:chio:*` token.
#[must_use]
pub fn extract_urn_at_position(text: &str, position: Position) -> Option<String> {
    let line = text.split('\n').nth(position.line as usize)?;
    let column = (position.character as usize).min(line.len());
    let bytes = line.as_bytes();

    fn is_urn_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_')
    }

    let mut start = column;
    while start > 0 && is_urn_char(bytes[start - 1] as char) {
        start -= 1;
    }
    let mut end = column;
    while end < line.len() && is_urn_char(bytes[end] as char) {
        end += 1;
    }
    if start == end {
        return None;
    }
    let token = &line[start..end];
    if token.starts_with("urn:chio:") {
        Some(token.to_string())
    } else {
        None
    }
}

/// Resolve a URN to its definition. Tries the on-disk manifest first
/// (if reachable), then the first occurrence of the URN in `text`.
#[must_use]
pub fn resolve(uri: &Url, text: &str, urn: &str) -> Option<Location> {
    if let Some(manifest_path) = manifest_path_in(text) {
        if let Some(loc) = locate_in_file(uri, &manifest_path, urn) {
            return Some(loc);
        }
    }
    locate_in_text(uri, text, urn).map(|range| Location {
        uri: uri.clone(),
        range,
    })
}

/// Read the top-level `manifest:` key from a chio.yaml-shaped
/// document. Returns `None` if absent or if the value is not a scalar
/// string.
fn manifest_path_in(text: &str) -> Option<PathBuf> {
    for line in text.split('\n') {
        if !line.starts_with([' ', '-', '\t']) {
            if let Some((key, value)) = line.split_once(':') {
                if key.trim() == "manifest" {
                    let v = value.trim().trim_matches('"').trim_matches('\'');
                    if v.is_empty() {
                        return None;
                    }
                    return Some(PathBuf::from(v));
                }
            }
        }
    }
    None
}

/// Locate the first occurrence of `urn` in the file at `manifest_path`
/// resolved relative to the directory of the document URI.
fn locate_in_file(doc_uri: &Url, manifest_path: &PathBuf, urn: &str) -> Option<Location> {
    let doc_dir = doc_uri.to_file_path().ok()?.parent()?.to_path_buf();
    let resolved = if manifest_path.is_absolute() {
        manifest_path.clone()
    } else {
        doc_dir.join(manifest_path)
    };
    let body = std::fs::read_to_string(&resolved).ok()?;
    let range = locate_in_text(doc_uri, &body, urn)?;
    let target = Url::from_file_path(&resolved).ok()?;
    Some(Location { uri: target, range })
}

fn locate_in_text(_uri: &Url, text: &str, urn: &str) -> Option<Range> {
    for (idx, line) in text.split('\n').enumerate() {
        if let Some(col) = line.find(urn) {
            let start = Position::new(idx as u32, col as u32);
            let end = Position::new(idx as u32, (col + urn.len()) as u32);
            return Some(Range::new(start, end));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_urn_returns_full_token() {
        let text = "scopes:\n  - urn:chio:scope:tool.read\n";
        let pos = Position::new(1, 12);
        let urn = extract_urn_at_position(text, pos).expect("urn");
        assert_eq!(urn, "urn:chio:scope:tool.read");
    }

    #[test]
    fn locate_in_text_returns_first_match() {
        let text = "scopes:\n  - urn:chio:scope:tool.read\n  - urn:chio:scope:tool.read\n";
        let uri = Url::parse("file:///proj/chio.yaml").unwrap();
        let range = locate_in_text(&uri, text, "urn:chio:scope:tool.read").expect("range");
        assert_eq!(range.start.line, 1);
    }

    #[test]
    fn manifest_path_in_returns_relative_path() {
        let text = "version: 1\nmanifest: ./manifest.chio-manifest.yaml\n";
        let p = manifest_path_in(text).expect("manifest");
        assert_eq!(p, PathBuf::from("./manifest.chio-manifest.yaml"));
    }

    #[test]
    fn manifest_path_in_skips_indented_keys() {
        let text = "version: 1\nnested:\n  manifest: should-be-ignored\n";
        assert!(manifest_path_in(text).is_none());
    }
}
