//! Conversions between LSP positions (UTF-16 code units) and byte
//! offsets inside a single line.
//!
//! `lsp_types::Position.character` is documented in the LSP
//! specification as a count of UTF-16 code units, not bytes and not
//! Unicode scalar values. The Chio LSP must translate that count into
//! a byte offset before slicing source text; otherwise a multibyte
//! character earlier on the line can land the slice index inside a
//! UTF-8 boundary and panic the request handler.
//!
//! The helpers here are deliberately scoped to the inputs the providers
//! actually pass them: a single `&str` line and an `lsp_types::Position`
//! whose `character` field is a UTF-16 code-unit count. They saturate
//! cleanly when the column overshoots the line so callers can keep
//! treating these as best-effort lookups instead of fallible operations.

/// Convert a UTF-16 column (the `Position.character` value) into the
/// byte offset of that column inside `line`. Saturates to `line.len()`
/// when the column points past the end.
///
/// The conversion walks scalar values via `char_indices` and
/// accumulates `char::len_utf16` so multi-byte characters (for example
/// non-ASCII Latin or CJK) advance the column count by the correct
/// number of UTF-16 code units. Lone surrogate halves cannot appear in
/// well-formed UTF-8 so this round-trips for every input the editor
/// can produce.
#[must_use]
pub fn utf16_to_byte_offset(line: &str, character: u32) -> usize {
    let target = character as usize;
    if target == 0 {
        return 0;
    }
    let mut utf16_units: usize = 0;
    for (byte_idx, ch) in line.char_indices() {
        if utf16_units >= target {
            return byte_idx;
        }
        utf16_units = utf16_units.saturating_add(ch.len_utf16());
    }
    line.len()
}

/// Convert a byte offset inside `line` into the UTF-16 column LSP
/// expects in `Position.character`. Saturates to the line's full UTF-16
/// length when `byte_offset` overshoots, which keeps the helper total
/// for the slicing patterns we have today.
#[must_use]
pub fn byte_to_utf16_column(line: &str, byte_offset: usize) -> u32 {
    let mut utf16_units: usize = 0;
    let mut consumed: usize = 0;
    for ch in line.chars() {
        if consumed >= byte_offset {
            break;
        }
        consumed = consumed.saturating_add(ch.len_utf8());
        utf16_units = utf16_units.saturating_add(ch.len_utf16());
    }
    u32::try_from(utf16_units).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trips_directly() {
        let line = "scopes: urn:chio:scope:tool.read";
        assert_eq!(utf16_to_byte_offset(line, 0), 0);
        assert_eq!(utf16_to_byte_offset(line, 8), 8);
        assert_eq!(utf16_to_byte_offset(line, line.len() as u32), line.len());
        assert_eq!(byte_to_utf16_column(line, 8), 8);
    }

    #[test]
    fn non_ascii_prefix_advances_byte_index_correctly() {
        // "café " (last char is the ASCII space) -> the 'é' is 2 bytes
        // / 1 UTF-16 code unit, so column 5 (after the space) maps to
        // byte 6.
        let line = "café x";
        assert_eq!(utf16_to_byte_offset(line, 5), 6);
        assert_eq!(byte_to_utf16_column(line, 6), 5);
    }

    #[test]
    fn surrogate_pair_counts_two_utf16_units() {
        // U+1F600 grinning face is 4 bytes in UTF-8 / 2 UTF-16 units.
        let line = "x\u{1F600}y";
        // Column 0 -> byte 0, column 1 -> byte 1 (after 'x'), column 3
        // -> byte 5 (after the emoji), column 4 -> byte 6 (after 'y').
        assert_eq!(utf16_to_byte_offset(line, 0), 0);
        assert_eq!(utf16_to_byte_offset(line, 1), 1);
        assert_eq!(utf16_to_byte_offset(line, 3), 5);
        assert_eq!(utf16_to_byte_offset(line, 4), 6);
        assert_eq!(byte_to_utf16_column(line, 5), 3);
    }

    #[test]
    fn column_past_end_saturates_to_line_length() {
        let line = "abc";
        assert_eq!(utf16_to_byte_offset(line, 99), line.len());
        assert_eq!(byte_to_utf16_column(line, 99), 3);
    }

    #[test]
    fn boundary_only_lands_on_char_starts() {
        // Slicing into café at the byte index returned by
        // utf16_to_byte_offset must never split a char boundary.
        let line = "café";
        for col in 0..=4 {
            let idx = utf16_to_byte_offset(line, col);
            // line.is_char_boundary catches mid-multibyte indices.
            assert!(
                line.is_char_boundary(idx),
                "byte idx {idx} for col {col} is not a char boundary in {line:?}"
            );
        }
    }
}
