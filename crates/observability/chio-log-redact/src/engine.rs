use std::fmt;

use chio_data_guards_redactors_default::{
    redact_payload, validate_default_redactor_compiles, RedactClass, RedactError,
};

pub(crate) const REDACTION_FAILED_PLACEHOLDER: &str = "[REDACTION-FAILED]";

/// Failure modes for strict log redaction setup.
#[derive(Debug, thiserror::Error)]
pub enum LogRedactError {
    #[error("default redactor patterns failed to compile: {0}")]
    DefaultRedactorInvalid(String),
    #[error("log redaction failed: {0}")]
    RedactionFailed(String),
}

impl From<RedactError> for LogRedactError {
    fn from(error: RedactError) -> Self {
        Self::RedactionFailed(error.to_string())
    }
}

/// Validated redaction policy for text, display, and tracing log surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRedactor {
    classes: RedactClass,
}

impl LogRedactor {
    /// Build a redactor with the default production class set.
    pub fn new() -> Result<Self, LogRedactError> {
        Self::with_classes(RedactClass::default_full())
    }

    /// Build a redactor with caller-selected classes after validating the
    /// built-in default redactor patterns.
    pub fn with_classes(classes: RedactClass) -> Result<Self, LogRedactError> {
        validate_default_redactor_compiles()
            .map_err(|failures| LogRedactError::DefaultRedactorInvalid(failures.join(", ")))?;
        Ok(Self { classes })
    }

    /// Return the redaction classes captured by this policy handle.
    #[must_use]
    pub fn classes(&self) -> RedactClass {
        self.classes
    }

    /// Redact a UTF-8 string under this policy.
    pub fn redact_text(&self, value: &str) -> Result<String, LogRedactError> {
        redact_text_with_classes(value, self.classes)
    }

    /// Redact a displayable value under this policy.
    pub fn redact_display(
        &self,
        value: impl fmt::Display,
    ) -> Result<RedactedValue, LogRedactError> {
        Ok(RedactedValue {
            redacted: self.redact_text(&value.to_string())?,
        })
    }

    /// Redact a displayable value under this policy, replacing redaction
    /// failures with the fail-closed placeholder instead of the original value.
    #[must_use]
    pub fn redact_display_or_placeholder(&self, value: impl fmt::Display) -> RedactedValue {
        RedactedValue {
            redacted: self.redact_str_or_placeholder(&value.to_string()),
        }
    }

    pub(crate) fn redact_str_or_placeholder(&self, value: &str) -> String {
        self.redact_text(value)
            .unwrap_or_else(|_| REDACTION_FAILED_PLACEHOLDER.to_string())
    }
}

/// Redact a UTF-8 string with the default production redactor classes.
pub fn redact_text(value: &str) -> Result<String, LogRedactError> {
    redact_text_with_classes(value, RedactClass::default_full())
}

/// Redact a UTF-8 string with caller-selected classes.
pub fn redact_text_with_classes(
    value: &str,
    classes: RedactClass,
) -> Result<String, LogRedactError> {
    let redacted = redact_payload(value.as_bytes(), classes)?;
    String::from_utf8(redacted.bytes).map_err(|error| {
        LogRedactError::RedactionFailed(format!("redacted output was not utf-8: {error}"))
    })
}

/// Display wrapper that never falls back to the original value on failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedValue {
    redacted: String,
}

impl RedactedValue {
    #[must_use]
    pub fn new(value: impl fmt::Display) -> Self {
        Self::with_classes(value, RedactClass::default_full())
    }

    #[must_use]
    pub fn with_classes(value: impl fmt::Display, classes: RedactClass) -> Self {
        let original = value.to_string();
        let redacted = redact_text_with_classes(&original, classes)
            .unwrap_or_else(|_| REDACTION_FAILED_PLACEHOLDER.to_string());
        Self { redacted }
    }

    #[must_use]
    pub fn with_redactor(value: impl fmt::Display, redactor: &LogRedactor) -> Self {
        redactor.redact_display_or_placeholder(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.redacted
    }
}

impl fmt::Display for RedactedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted)
    }
}
