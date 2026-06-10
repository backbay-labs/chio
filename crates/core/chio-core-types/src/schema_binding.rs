use alloc::format;

use crate::error::{Error, Result};

pub(crate) fn ensure_schema_matches(actual: &str, expected: &str, artifact: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }

    Err(Error::CanonicalJson(format!(
        "unsupported {artifact} schema: {actual}"
    )))
}
