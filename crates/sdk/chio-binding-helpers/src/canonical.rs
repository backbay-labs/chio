use serde_json::Value;

use crate::Result;

/// Parse a raw JSON string and return its RFC 8785 canonical form.
pub fn canonicalize_json_str(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input)?;
    Ok(chio_core::canonicalize(&value)?)
}

#[cfg(test)]
mod tests {
    use super::canonicalize_json_str;

    #[test]
    fn canonicalize_json_string_input() -> crate::Result<()> {
        let canonical = canonicalize_json_str(r#"{"z":1,"a":2}"#)?;
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
        Ok(())
    }
}
