//! Text canonicalization utilities shared across content-safety guards.
//!
//! These functions normalize free-form text before running regex-based signal
//! detection.  Canonicalization is deliberately conservative: the output is a
//! lowercase ASCII-biased form that preserves the general shape of the input
//! but strips common obfuscation techniques (zero-width splicing, homoglyph
//! substitution, punctuation runs, case flipping).
//!
//! This module is shared infrastructure for the
//! [`crate::prompt_injection::PromptInjectionGuard`] and the forthcoming
//! jailbreak guard.  It has no external dependencies beyond the standard
//! library and is safe to use in fail-closed guard paths.

/// The canonical-form representation of an input string.
///
/// The returned `String` has:
///
/// - all ASCII letters lowercased;
/// - common Unicode homoglyphs of Latin letters folded to their ASCII
///   counterparts (e.g. Cyrillic `а` -> `a`, full-width digits -> ASCII);
/// - zero-width and Unicode formatting characters removed;
/// - runs of two or more separator-class punctuation characters collapsed
///   to a single space.
///
/// This is NOT a security-grade Unicode normaliser.  It is a best-effort
/// heuristic that defeats the most common copy-paste prompt injection
/// tricks seen in the wild.  Callers still need to bound the input length
/// (`max_scan_bytes`) and fail-closed on internal errors.
pub fn canonicalize(input: &str) -> String {
    // First pass: strip zero-width / format characters, fold homoglyphs,
    // lowercase ASCII letters in one sweep.
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_zero_width(ch) {
            continue;
        }
        let mapped = fold_homoglyph(ch);
        // Lowercase only for ASCII letters; leave folded ASCII as-is.
        if mapped.is_ascii_uppercase() {
            out.push(mapped.to_ascii_lowercase());
        } else {
            out.push(mapped);
        }
    }

    // Second pass: collapse whitespace runs and separator-punctuation runs
    // to a single space, and trim the result.
    collapse_runs(&out)
}

/// Return true if `ch` is a zero-width or Unicode formatting character
/// commonly used to obfuscate prompt content.
///
/// The set is a subset of the Unicode "formatting / joining" category plus a
/// handful of BOM/LRM/RLM codepoints; it is not exhaustive but covers the
/// characters that appear in observed injection payloads.
pub fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZWNJ
            | '\u{200D}' // ZWJ
            | '\u{200E}' // LRM
            | '\u{200F}' // RLM
            | '\u{202A}'..='\u{202E}' // LRE/RLE/PDF/LRO/RLO
            | '\u{2060}' // WORD JOINER
            | '\u{2061}'..='\u{2064}' // invisible function/plus/separator
            | '\u{FEFF}' // BOM / zero-width no-break space
            | '\u{180E}' // Mongolian vowel separator
            | '\u{034F}' // combining grapheme joiner
            | '\u{061C}' // arabic letter mark
    )
}

/// Fold a single character to its ASCII analogue when it is a commonly-used
/// homoglyph.  Returns the original character when no fold is known.
///
/// The table is intentionally small: we prioritise characters that actually
/// appear in observed prompt-injection payloads (Cyrillic letters that look
/// like Latin, full-width digits and letters, Greek alpha/omicron, etc.).
/// Expanding the table later is purely additive.
fn fold_homoglyph(ch: char) -> char {
    match ch {
        // Cyrillic -> Latin look-alikes.
        'А' => 'A',
        'а' => 'a',
        'В' => 'B',
        'С' => 'C',
        'с' => 'c',
        'Е' => 'E',
        'е' => 'e',
        'Н' => 'H',
        'К' => 'K',
        'М' => 'M',
        'О' => 'O',
        'о' => 'o',
        'Р' => 'P',
        'р' => 'p',
        'Т' => 'T',
        'Х' => 'X',
        'х' => 'x',
        'У' => 'Y',
        'у' => 'y',
        'і' => 'i',
        'І' => 'I',
        // Greek -> Latin look-alikes.
        'Α' => 'A',
        'α' => 'a',
        'Β' => 'B',
        'Ε' => 'E',
        'ε' => 'e',
        'Η' => 'H',
        'Ι' => 'I',
        'ι' => 'i',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'ο' => 'o',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        // Full-width ASCII -> ASCII.
        '\u{FF01}'..='\u{FF5E}' => {
            // Full-width punctuation and Latin block maps directly via offset.
            // SAFETY: the subtraction stays inside the BMP; every codepoint
            // in the range has a valid ASCII analogue at offset 0xFEE0.
            let raw = ch as u32 - 0xFEE0;
            char::from_u32(raw).unwrap_or(ch)
        }
        // Full-width digits 0-9 handled by the FF01-FF5E range above.
        _ => ch,
    }
}

/// Collapse runs of whitespace and separator punctuation into a single space,
/// then trim leading/trailing whitespace.  This prevents attackers from
/// evading regex matchers by splicing extra punctuation into key phrases.
fn collapse_runs(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_was_break = false;
    for ch in input.chars() {
        let is_break = ch.is_whitespace() || is_separator_punct(ch);
        if is_break {
            if !prev_was_break && !out.is_empty() {
                out.push(' ');
            }
            prev_was_break = true;
        } else {
            out.push(ch);
            prev_was_break = false;
        }
    }
    let trimmed = out.trim_end().to_string();
    trimmed
}

/// ASCII-centric separator punctuation run detector.  We collapse runs of
/// these so "ignore---all---previous" normalises cleanly.  We do NOT collapse
/// single punctuation characters: only runs of two or more are affected by
/// `collapse_runs`.
///
/// Note: `:` and `/` are intentionally excluded so URL-shaped substrings
/// (`https://`) survive canonicalization and remain matchable by the
/// exfiltration-framing signal.
fn is_separator_punct(ch: char) -> bool {
    matches!(
        ch,
        '-' | '_' | '~' | '=' | '*' | '+' | '.' | ',' | ';' | '|' | '\\'
    )
}

/// Truncate `input` to at most `max_bytes` bytes while preserving UTF-8
/// boundaries.  Returns the truncated slice and a `bool` indicating whether
/// truncation happened.  Guards use this to bound scan cost without splitting
/// multi-byte characters.
pub fn truncate_at_char_boundary(input: &str, max_bytes: usize) -> (&str, bool) {
    if input.len() <= max_bytes {
        return (input, false);
    }
    // Walk backwards from max_bytes to the nearest char boundary.
    let mut end = max_bytes.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (&input[..end], true)
}

/// Ratio of non-alphanumeric (punctuation / symbol) characters to
/// non-whitespace characters.  Used by the statistical jailbreak layer to
/// flag inputs whose visible content is dominated by symbols (a common
/// adversarial-suffix shape).  Returns `0.0` for empty or all-whitespace
/// input.
pub fn punctuation_ratio(s: &str) -> f32 {
    let mut punct = 0usize;
    let mut total = 0usize;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        total += 1;
        if !c.is_alphanumeric() {
            punct += 1;
        }
    }
    if total == 0 {
        0.0
    } else {
        punct as f32 / total as f32
    }
}

/// Return true if `s` contains a run of `min_run` or more consecutive
/// non-alphanumeric, non-whitespace characters.  Adversarial suffixes in the
/// wild typically appear as long unbroken punctuation / symbol sequences.
pub fn long_run_of_symbols(s: &str, min_run: usize) -> bool {
    if min_run == 0 {
        return true;
    }
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_alphanumeric() || c.is_whitespace() {
            run = 0;
            continue;
        }
        run += 1;
        if run >= min_run {
            return true;
        }
    }
    false
}

/// Shannon entropy (bits/char) over non-whitespace ASCII bytes of `s`.
/// Returns `0.0` when the ASCII-non-whitespace subset is empty.  This is a
/// cheap proxy for character diversity: payloads dominated by a handful of
/// symbols have low entropy; uniform-random adversarial suffixes have high
/// entropy.  Non-ASCII characters are ignored (they are already accounted
/// for by canonicalization folding).
pub fn shannon_entropy_ascii_nonws(s: &str) -> f32 {
    let mut counts = [0u32; 128];
    let mut total = 0u32;
    for b in s.bytes() {
        if b >= 128 || b.is_ascii_whitespace() {
            continue;
        }
        counts[b as usize] = counts[b as usize].saturating_add(1);
        total = total.saturating_add(1);
    }
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / total_f;
        entropy -= p * p.log2();
    }
    entropy as f32
}

/// Number of zero-width / Unicode formatting codepoints in `s` (using the
/// [`is_zero_width`] predicate).  Useful for a statistical "obfuscation"
/// signal that fires even when canonicalization has already stripped the
/// characters: callers count on the original pre-canonicalization string.
pub fn zero_width_count(s: &str) -> usize {
    s.chars().filter(|c| is_zero_width(*c)).count()
}

/// Ratio of distinct character shingles (sliding n-grams) to total shingles
/// for `s` after canonicalization.  Lower values indicate heavy repetition
/// (a hallmark of token-spam / adversarial-suffix attacks).  Returns `1.0`
/// when `s` has fewer than `n` chars or is empty (nothing to compare).
///
/// `n` is clamped to `[1, 16]`; callers typically pick `n = 3` for
/// character trigrams, which balance sensitivity against random noise.
pub fn shingle_uniqueness(s: &str, n: usize) -> f32 {
    let n = n.clamp(1, 16);
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < n {
        return 1.0;
    }
    let total = chars.len() - n + 1;
    if total == 0 {
        return 1.0;
    }
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(total);
    for window in chars.windows(n) {
        let key: String = window.iter().collect();
        seen.insert(key);
    }
    (seen.len() as f32) / (total as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_lowercases_ascii() {
        assert_eq!(canonicalize("IGNORE ALL"), "ignore all");
    }

    #[test]
    fn canonicalize_strips_zero_width() {
        let sneaky = "ig\u{200B}no\u{200C}re all";
        assert_eq!(canonicalize(sneaky), "ignore all");
    }

    #[test]
    fn canonicalize_folds_homoglyphs() {
        // Cyrillic U+0440 (er) -> ASCII "p"; lowercase and fold together.
        let disguised = "igno\u{0440}e";
        assert_eq!(canonicalize(disguised), "ignope");
        // Full-width ASCII folds via the 0xFEE0 offset.
        assert_eq!(canonicalize("ＩＧＮＯＲＥ"), "ignore");
    }

    #[test]
    fn canonicalize_collapses_separators() {
        assert_eq!(
            canonicalize("ignore---all___previous"),
            "ignore all previous"
        );
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        let input = "héllo"; // é is two bytes
        let (out, truncated) = truncate_at_char_boundary(input, 2);
        assert!(truncated);
        assert_eq!(out, "h");
    }

    #[test]
    fn truncate_short_input_unchanged() {
        let (out, truncated) = truncate_at_char_boundary("hi", 100);
        assert!(!truncated);
        assert_eq!(out, "hi");
    }

    #[test]
    fn punctuation_ratio_basic() {
        assert_eq!(punctuation_ratio(""), 0.0);
        assert_eq!(punctuation_ratio("   \n\t"), 0.0);
        // All alphanum -> 0.0.
        assert_eq!(punctuation_ratio("abc123"), 0.0);
        // All punctuation -> 1.0.
        assert_eq!(punctuation_ratio("!!!@@@"), 1.0);
        // Half and half (non-whitespace): 3/6 = 0.5.
        assert!((punctuation_ratio("ab;c;!") - 0.5).abs() < 1e-6);
    }

    #[test]
    fn long_run_of_symbols_detects_runs() {
        assert!(!long_run_of_symbols("hello world", 12));
        assert!(long_run_of_symbols("hello !!!!!!!!!!!! world", 12));
        assert!(!long_run_of_symbols("hello !!! world", 12));
        // min_run 0 is trivially true even for empty input.
        assert!(long_run_of_symbols("", 0));
    }

    #[test]
    fn shannon_entropy_ascii_nonws_bounds() {
        // All-one-character -> 0 entropy.
        assert!(shannon_entropy_ascii_nonws("aaaaaa") < 1e-6);
        // Two equiprobable characters -> 1 bit.
        let e = shannon_entropy_ascii_nonws("abababab");
        assert!((e - 1.0).abs() < 0.1);
        // Empty input -> 0.
        assert_eq!(shannon_entropy_ascii_nonws(""), 0.0);
    }

    #[test]
    fn zero_width_count_matches_inserts() {
        let s = "a\u{200B}b\u{200C}c\u{FEFF}d";
        assert_eq!(zero_width_count(s), 3);
        assert_eq!(zero_width_count("plain"), 0);
    }

    #[test]
    fn shingle_uniqueness_detects_repetition() {
        // Unique input: every trigram distinct.
        let u = shingle_uniqueness("abcdefg", 3);
        assert!((u - 1.0).abs() < 1e-6);
        // Repeated trigrams: "aaa" repeats.
        let r = shingle_uniqueness("aaaaaaaaa", 3);
        assert!(r < 0.2, "expected low uniqueness, got {r}");
        // Too-short input returns 1.0.
        assert_eq!(shingle_uniqueness("ab", 3), 1.0);
    }
}
