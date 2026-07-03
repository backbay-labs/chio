use sha2::{Digest, Sha256};

pub(super) fn preview_redacted(s: &str) -> String {
    let len = s.chars().count();
    if len <= 4 {
        return "*".repeat(len);
    }
    let prefix: String = s.chars().take(2).collect();
    let suffix_chars: Vec<char> = s.chars().rev().take(2).collect();
    let suffix: String = suffix_chars.into_iter().rev().collect();
    format!("{prefix}***{suffix}")
}

pub(super) fn truncate_to_char_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (&text[..end], end < text.len())
}

pub(super) fn fingerprint(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
