#[must_use]
pub fn sha256_hex_bytes(input: &[u8]) -> String {
    chio_core::sha256_hex(input)
}

#[must_use]
pub fn sha256_hex_utf8(input: &str) -> String {
    sha256_hex_bytes(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex_bytes, sha256_hex_utf8};

    #[test]
    fn sha256_helpers_match_known_value() {
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(sha256_hex_utf8("hello"), expected);
        assert_eq!(sha256_hex_bytes(b"hello"), expected);
    }
}
