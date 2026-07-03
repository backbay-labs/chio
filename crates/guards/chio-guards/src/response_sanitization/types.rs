use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Category of a sensitive data finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveCategory {
    Secret,
    Pii,
    Internal,
    Custom(String),
}

/// Redaction strategy applied to a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategy {
    /// Replace the match with a constant mask (`****`).
    Mask,
    /// Replace the match with a stable fingerprint (sha256 prefix).
    Fingerprint,
    /// Drop the match entirely (replace with empty text; at the JSON-field
    /// level the whole field is replaced with `null`).
    Drop,
    /// Replace the match with an opaque token id and record the mapping.
    Tokenize,
    /// Keep a small prefix/suffix, redact the middle.
    Partial,
    /// Replace with a typed label (`[REDACTED:email]`).
    TypeLabel,
    /// Do not redact.
    Keep,
}

/// Byte span in the sanitized text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A single sensitive-data finding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensitiveDataFinding {
    pub id: String,
    pub category: SensitiveCategory,
    pub data_type: String,
    pub confidence: f32,
    pub span: Span,
    pub preview: String,
    pub detector: String,
    pub recommended_action: RedactionStrategy,
}

/// Record of a redaction that was actually applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Redaction {
    pub finding_id: String,
    pub strategy: RedactionStrategy,
    pub original_span: Span,
    pub replacement: String,
}

/// Processing statistics for a single sanitization run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessingStats {
    pub input_length: usize,
    pub output_length: usize,
    pub findings_count: usize,
    pub redactions_count: usize,
}

/// Result of sanitizing a single string.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationResult {
    pub sanitized: String,
    pub was_redacted: bool,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub stats: ProcessingStats,
}

/// Category enable/disable toggles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryConfig {
    pub secrets: bool,
    pub pii: bool,
    pub internal: bool,
}

impl Default for CategoryConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            internal: true,
        }
    }
}

/// High-entropy token detector configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropyConfig {
    pub enabled: bool,
    pub threshold: f64,
    pub min_token_len: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 4.5,
            min_token_len: 16,
        }
    }
}

/// Allowlist configuration (false-positive reduction).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowlistConfig {
    pub exact: Vec<String>,
    pub patterns: Vec<String>,
}

/// Denylist configuration (forced redaction).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DenylistConfig {
    pub exact: Vec<String>,
    pub patterns: Vec<String>,
}

/// Output sanitizer configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputSanitizerConfig {
    pub categories: CategoryConfig,
    pub redaction_strategies: HashMap<SensitiveCategory, RedactionStrategy>,
    pub entropy: EntropyConfig,
    pub allowlist: AllowlistConfig,
    pub denylist: DenylistConfig,
    pub max_input_bytes: usize,
    pub include_findings: bool,
}

impl Default for OutputSanitizerConfig {
    fn default() -> Self {
        let mut redaction_strategies = HashMap::new();
        redaction_strategies.insert(SensitiveCategory::Secret, RedactionStrategy::Mask);
        redaction_strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Partial);
        redaction_strategies.insert(SensitiveCategory::Internal, RedactionStrategy::TypeLabel);
        Self {
            categories: CategoryConfig::default(),
            redaction_strategies,
            entropy: EntropyConfig::default(),
            allowlist: AllowlistConfig::default(),
            denylist: DenylistConfig::default(),
            max_input_bytes: 1_000_000,
            include_findings: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutputSanitizerConfigError {
    #[error("invalid {list_name} regex `{pattern}`: {source}")]
    InvalidPattern {
        list_name: &'static str,
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Output of `OutputSanitizer::sanitize_value`.
#[derive(Debug, Clone)]
pub struct SanitizedValue {
    pub value: serde_json::Value,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub was_redacted: bool,
}
