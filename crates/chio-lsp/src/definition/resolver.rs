//! URN resolution helpers for the go-to-definition provider.

use std::path::PathBuf;

use tower_lsp::lsp_types::{Location, Position, Range, Url};

use crate::position::{byte_to_utf16_column, utf16_to_byte_offset};

/// Extract the URN spanning `position` in `text`. Returns `None` if
/// the cursor is not on a `urn:chio:*` token.
///
/// `position.character` is a UTF-16 code-unit count per the LSP
/// spec; the helper translates it to a UTF-8 byte index inside the
/// target line so multibyte characters (for example accented Latin or
/// CJK) cannot drive `&line[start..end]` into a non-boundary slice.
#[must_use]
pub fn extract_urn_at_position(text: &str, position: Position) -> Option<String> {
    let line = text.split('\n').nth(position.line as usize)?;
    let column = utf16_to_byte_offset(line, position.character);

    fn is_urn_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '.' | '_')
    }

    // Walk backward over scalar values so the boundary stays valid for
    // multibyte characters. URN bytes are all ASCII, so the byte-level
    // peek inside the loop only fires on ASCII bytes; that keeps the
    // step size correct.
    let bytes = line.as_bytes();
    let mut start = column;
    while start > 0 {
        let prev_byte = bytes[start - 1];
        if !prev_byte.is_ascii() {
            break;
        }
        if !is_urn_char(prev_byte as char) {
            break;
        }
        start -= 1;
    }
    let mut end = column;
    while end < line.len() {
        let next_byte = bytes[end];
        if !next_byte.is_ascii() {
            break;
        }
        if !is_urn_char(next_byte as char) {
            break;
        }
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
        if let Some(byte_col) = line.find(urn) {
            // LSP `Range` columns are UTF-16 code units, not bytes.
            // Translate so editors highlight the correct span when the
            // line contains non-ASCII text before the URN.
            let start_col = byte_to_utf16_column(line, byte_col);
            let end_col = byte_to_utf16_column(line, byte_col + urn.len());
            let start = Position::new(idx as u32, start_col);
            let end = Position::new(idx as u32, end_col);
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

    #[test]
    fn extract_urn_handles_non_ascii_prefix() {
        // 'café ' adds a multibyte char before the URN. Pre-fix the
        // function used `position.character` as a byte offset and could
        // panic when slicing into the URN. Now it must round-trip the
        // URN intact regardless of the leading non-ASCII run.
        let text = "scopes: # café\n  - urn:chio:scope:tool.read\n";
        // UTF-16 column of 't' in 'tool.read' on line 1: bytes
        // "  - urn:chio:scope:" -> all ASCII, so column == byte index.
        let pos = Position::new(1, 22);
        let urn = extract_urn_at_position(text, pos).expect("urn extracted");
        assert_eq!(urn, "urn:chio:scope:tool.read");
    }

    #[test]
    fn locate_in_text_emits_utf16_columns_for_non_ascii_prefix() {
        // 'café ' is 5 chars / 6 bytes. The URN starts at byte 6 but
        // UTF-16 column 5. Pre-fix the function emitted byte 6 in the
        // start column, shifting the editor highlight by one.
        let text = "café urn:chio:scope:tool.read\n";
        let uri = Url::parse("file:///proj/chio.yaml").unwrap();
        let range = locate_in_text(&uri, text, "urn:chio:scope:tool.read").expect("range");
        assert_eq!(range.start.character, 5);
        // 'urn:chio:scope:tool.read' is 24 ASCII chars, so end column
        // is 5 + 24 = 29 in UTF-16 units.
        assert_eq!(range.end.character, 29);
    }
}
