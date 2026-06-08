//! `cargo xtask check-crate-paths` - fail-closed guard against crate-path drift.
//!
//! Scans config files that embed literal `crates/chio-*` path references (CI path
//! filters, CODEOWNERS, mutation/kani/threat configs, formal manifests,
//! qualification matrices) and asserts every reference resolves to an existing
//! file or directory. A reference that no longer resolves is an error: after a
//! crate move such a reference would silently match nothing, and the gate or
//! required-reviewer rule it encodes would go dark while CI stayed green.

/// Extract every `crates/chio-*` path literal from `content`. Matching starts at
/// each `crates/chio-` occurrence and continues over path bytes, stopping at the
/// first character that cannot be part of a path reference (quote, whitespace,
/// `:`, comma). Trailing glob/symbol decoration is preserved here and stripped by
/// `normalize_for_resolution`.
pub fn extract_crate_paths(content: &str) -> Vec<String> {
    let bytes = content.as_bytes();
    let needle = b"crates/chio-";
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i;
            let mut j = i + needle.len();
            while j < bytes.len() && is_path_byte(bytes[j]) {
                j += 1;
            }
            if let Ok(text) = std::str::from_utf8(&bytes[start..j]) {
                out.push(text.to_string());
            }
            i = j.max(start + 1);
        } else {
            i += 1;
        }
    }
    out
}

fn is_path_byte(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'*'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_captures_paths_and_stops_at_delimiters() {
        let content = concat!(
            "paths:\n",
            "  - \"crates/chio-kernel/**\"\n",
            "x: crates/chio-anchor/src/authority.rs::Symbol\n"
        );
        let got = extract_crate_paths(content);
        assert!(got.contains(&"crates/chio-kernel/**".to_string()), "got: {got:?}");
        assert!(
            got.contains(&"crates/chio-anchor/src/authority.rs".to_string()),
            "stops before `::`; got: {got:?}"
        );
    }
}
