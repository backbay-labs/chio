//! Response sanitization guard -- scans tool results for secrets, PII/PHI,
//! and other sensitive data, then redacts them before the agent sees them.
//!
//! This module exposes two layered APIs:
//!
//! - A simple, backwards-compatible [`ResponseSanitizationGuard`] that uses a
//!   small fixed pattern set and Block/Redact binary actions.
//! - A full-featured [`OutputSanitizer`] with secret detectors (AWS, GitHub,
//!   Slack, GCP service-account JSON, passwords, PEM private keys, JWTs,
//!   OAuth bearer tokens),
//!   credit-card numbers with Luhn validation, US SSNs, Shannon-entropy
//!   high-entropy token detection, configurable allowlist/denylist,
//!   deterministic overlap resolution (longest-match-wins with strategy
//!   ranking), and four redaction strategies: `Mask`, `Fingerprint`, `Drop`,
//!   `Tokenize`, plus `Partial`, `TypeLabel`, and `Keep`.
//!
//! The guard fails closed: if pattern compilation fails or an internal error
//! occurs, the response is blocked.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chio_kernel::{Guard, GuardContext, KernelError, Verdict};

// ===========================================================================
// Backwards-compatible simple API.
// ===========================================================================

/// Classification level for a detected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivityLevel {
    /// Low sensitivity -- may produce false positives (e.g., phone numbers).
    Low,
    /// Medium sensitivity -- likely PII (e.g., email addresses).
    Medium,
    /// High sensitivity -- definite PII/PHI (e.g., SSN, medical record numbers).
    High,
}

/// A named pattern that matches sensitive data.
#[derive(Debug, Clone)]
pub struct SensitivePattern {
    /// Human-readable name for the pattern.
    pub name: String,
    /// The compiled regex.
    regex: Regex,
    /// Classification level.
    pub level: SensitivityLevel,
    /// Replacement string for redaction.
    pub redaction: String,
}

/// Action to take when sensitive data is detected by the simple guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationAction {
    /// Block the response entirely.
    Block,
    /// Redact the matching patterns and allow the response.
    Redact,
}

fn default_patterns() -> Vec<SensitivePattern> {
    // (regex, name, level, redaction) for each built-in PII/PHI detector.
    let specs: [(&str, &str, SensitivityLevel, &str); 7] = [
        (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "SSN",
            SensitivityLevel::High,
            "[SSN REDACTED]",
        ),
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "email",
            SensitivityLevel::Medium,
            "[EMAIL REDACTED]",
        ),
        (
            r"\b(?:\(\d{3}\)\s*|\d{3}[-.])\d{3}[-.]?\d{4}\b",
            "phone",
            SensitivityLevel::Low,
            "[PHONE REDACTED]",
        ),
        (
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "credit-card",
            SensitivityLevel::High,
            "[CARD REDACTED]",
        ),
        (
            r"\b(?:\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})\b",
            "date-of-birth",
            SensitivityLevel::Low,
            "[DATE REDACTED]",
        ),
        (
            r"\bMRN[:\s#]*\d{6,12}\b",
            "MRN",
            SensitivityLevel::High,
            "[MRN REDACTED]",
        ),
        (
            r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b",
            "ICD-10",
            SensitivityLevel::Medium,
            "[ICD REDACTED]",
        ),
    ];

    let mut patterns = Vec::with_capacity(specs.len());
    for (pattern, name, level, redaction) in specs {
        match compile_required_pattern(pattern) {
            Ok(regex) => patterns.push(SensitivePattern {
                name: name.to_string(),
                regex,
                level,
                redaction: redaction.to_string(),
            }),
            Err(_) => {
                // Fail closed: a built-in constant pattern failed to compile.
                // Shipping the reduced set would let that PII/PHI category
                // through, so redact every response instead (the simple-guard
                // analogue of the OutputSanitizer fail-closed path). The
                // catch-all is itself a constant, so its fallback is
                // unreachable in practice.
                if let Ok(catch_all) = compile_required_pattern(r"[\s\S]+") {
                    return vec![SensitivePattern {
                        name: "redaction_unavailable_fail_closed".to_string(),
                        regex: catch_all,
                        level: SensitivityLevel::High,
                        redaction: "[REDACTED]".to_string(),
                    }];
                }
                return patterns;
            }
        }
    }
    patterns
}

/// Guard that scans responses for PII/PHI patterns and redacts or blocks them.
pub struct ResponseSanitizationGuard {
    patterns: Vec<SensitivePattern>,
    min_level: SensitivityLevel,
    action: SanitizationAction,
}

impl ResponseSanitizationGuard {
    pub fn new(min_level: SensitivityLevel, action: SanitizationAction) -> Self {
        Self {
            patterns: default_patterns(),
            min_level,
            action,
        }
    }

    pub fn with_patterns(
        patterns: Vec<SensitivePattern>,
        min_level: SensitivityLevel,
        action: SanitizationAction,
    ) -> Self {
        Self {
            patterns,
            min_level,
            action,
        }
    }

    pub fn with_additional_patterns(
        additional_patterns: Vec<SensitivePattern>,
        min_level: SensitivityLevel,
        action: SanitizationAction,
    ) -> Self {
        let mut patterns = default_patterns();
        patterns.extend(additional_patterns);
        Self {
            patterns,
            min_level,
            action,
        }
    }

    pub fn scan(&self, text: &str) -> Vec<(String, String)> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            if level_ord(pattern.level) < level_ord(self.min_level) {
                continue;
            }
            for m in pattern.regex.find_iter(text) {
                findings.push((pattern.name.clone(), m.as_str().to_string()));
            }
        }
        findings
    }

    pub fn redact(&self, text: &str) -> (String, usize) {
        let mut result = text.to_string();
        let mut count = 0usize;
        for pattern in &self.patterns {
            if level_ord(pattern.level) < level_ord(self.min_level) {
                continue;
            }
            let match_count = pattern.regex.find_iter(&result).count();
            if match_count > 0 {
                result = pattern
                    .regex
                    .replace_all(&result, pattern.redaction.as_str())
                    .to_string();
                count = count.saturating_add(match_count);
            }
        }
        (result, count)
    }

    pub fn scan_response(&self, response: &serde_json::Value) -> ScanResult {
        let text = response.to_string();
        let findings = self.scan(&text);
        if findings.is_empty() {
            return ScanResult::Clean;
        }
        match self.action {
            SanitizationAction::Block => ScanResult::Blocked(findings),
            SanitizationAction::Redact => {
                let (redacted, count) = self.redact(&text);
                ScanResult::Redacted {
                    redacted_text: redacted,
                    redaction_count: count,
                    findings,
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ScanResult {
    Clean,
    Blocked(Vec<(String, String)>),
    Redacted {
        redacted_text: String,
        redaction_count: usize,
        findings: Vec<(String, String)>,
    },
}

fn level_ord(level: SensitivityLevel) -> u8 {
    match level {
        SensitivityLevel::Low => 0,
        SensitivityLevel::Medium => 1,
        SensitivityLevel::High => 2,
    }
}

impl Guard for ResponseSanitizationGuard {
    fn name(&self) -> &str {
        "response-sanitization"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let args_text = ctx.request.arguments.to_string();
        let findings = self.scan(&args_text);
        if findings.is_empty() {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::Deny)
        }
    }
}

/// Build a `SensitivePattern` from components. Returns None if the regex is invalid.
pub fn build_pattern(
    name: &str,
    regex_str: &str,
    level: SensitivityLevel,
    redaction: &str,
) -> Option<SensitivePattern> {
    Regex::new(regex_str).ok().map(|regex| SensitivePattern {
        name: name.to_string(),
        regex,
        level,
        redaction: redaction.to_string(),
    })
}

// ===========================================================================
// Full OutputSanitizer.
// ===========================================================================

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

// ---------------------------------------------------------------------------
// Compiled detector registry (lazy, built once per process).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CompiledPattern {
    id: &'static str,
    category: SensitiveCategory,
    data_type: &'static str,
    confidence: f32,
    recommended: RedactionStrategy,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,
}

/// Compile a built-in (compile-time-constant) redaction pattern.
///
/// These patterns are unit-tested constants, so a failure here is a build
/// regression, not a runtime input condition. We must NOT degrade to a
/// never-matching regex on failure: that silently disables an entire
/// redaction class and lets the matching content pass through unredacted,
/// which is fail-open. Instead we surface the error so the sanitizer refuses
/// to construct (see `OutputSanitizer::with_config`) and the runtime
/// detectors fail closed by redacting the whole input. This mirrors
/// `chio-log-redact`, which substitutes `[REDACTION-FAILED]` rather than ever
/// emitting the original value when redaction cannot run.
fn compile_required_pattern(pattern: &'static str) -> Result<Regex, regex::Error> {
    Regex::new(pattern).inspect_err(|err| {
        tracing::error!(error = %err, %pattern, "failed to compile hardcoded redaction regex");
    })
}

/// Pattern used by the high-entropy secret detector.
const HIGH_ENTROPY_TOKEN_PATTERN: &str = r"[A-Za-z0-9+/=_-]{16,}";

/// Fail-closed finding that drops the entire scanned input.
///
/// Used when a constant detector pattern cannot be compiled at runtime, a
/// state `OutputSanitizer::with_config` already refuses to construct. Rather
/// than let any content through unredacted, we redact everything: the
/// response-sanitization analogue of `chio-log-redact`'s `[REDACTION-FAILED]`
/// substitution. The strategy is `Drop` (not `Mask`) because `resolve_overlaps`
/// honors `Drop` unconditionally, so a per-category strategy override cannot
/// downgrade this fail-closed finding to `Keep`.
fn redact_all_finding(limited: &str) -> SensitiveDataFinding {
    SensitiveDataFinding {
        id: "redaction_unavailable_fail_closed".to_string(),
        category: SensitiveCategory::Secret,
        data_type: "redaction_unavailable".to_string(),
        confidence: 1.0,
        span: Span {
            start: 0,
            end: limited.len(),
        },
        preview: String::new(),
        detector: "fail_closed".to_string(),
        recommended_action: RedactionStrategy::Drop,
    }
}

/// Returns the built-in detector registry, or an error if any
/// compile-time-constant pattern fails to compile. Computed once per process.
fn compiled_patterns() -> Result<&'static [CompiledPattern], &'static str> {
    static PATS: OnceLock<Result<Vec<CompiledPattern>, String>> = OnceLock::new();
    match PATS.get_or_init(|| build_compiled_patterns().map_err(|err| err.to_string())) {
        Ok(patterns) => Ok(patterns.as_slice()),
        Err(message) => Err(message.as_str()),
    }
}

fn build_compiled_patterns() -> Result<Vec<CompiledPattern>, regex::Error> {
    Ok(vec![
        // ---- Secrets ----
        CompiledPattern {
            id: "secret_aws_access_key_id",
            category: SensitiveCategory::Secret,
            data_type: "aws_access_key_id",
            confidence: 0.99,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_aws_secret_access_key",
            category: SensitiveCategory::Secret,
            data_type: "aws_secret_access_key",
            confidence: 0.9,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}",
            )?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_github_token",
            category: SensitiveCategory::Secret,
            data_type: "github_token",
            confidence: 0.99,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_slack_token",
            category: SensitiveCategory::Secret,
            data_type: "slack_token",
            confidence: 0.99,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"\bxox[abopsr]-[A-Za-z0-9-]{10,}\b")?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_slack_webhook",
            category: SensitiveCategory::Secret,
            data_type: "slack_webhook",
            confidence: 0.95,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            )?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_gcp_service_account",
            category: SensitiveCategory::Secret,
            data_type: "gcp_service_account_json",
            confidence: 0.97,
            recommended: RedactionStrategy::Drop,
            regex: compile_required_pattern(r#""type"\s*:\s*"service_account""#)?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_pem_private_key",
            category: SensitiveCategory::Secret,
            data_type: "pem_private_key",
            confidence: 0.99,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            )?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_jwt",
            category: SensitiveCategory::Secret,
            data_type: "jwt",
            confidence: 0.85,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            )?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_oauth_bearer",
            category: SensitiveCategory::Secret,
            data_type: "oauth_bearer",
            confidence: 0.85,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"(?i)\b(?:authorization|auth)\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}",
            )?,
            validator: None,
        },
        CompiledPattern {
            id: "secret_password_assignment",
            category: SensitiveCategory::Secret,
            data_type: "password",
            confidence: 0.7,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(
                r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*\S{6,}",
            )?,
            validator: None,
        },
        // ---- PII ----
        CompiledPattern {
            id: "pii_ssn",
            category: SensitiveCategory::Pii,
            data_type: "ssn",
            confidence: 0.9,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"\b\d{3}-\d{2}-\d{4}\b")?,
            validator: Some(is_valid_ssn_fragments),
        },
        CompiledPattern {
            id: "pii_ssn_compact",
            category: SensitiveCategory::Pii,
            data_type: "ssn",
            confidence: 0.7,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"(?:^|[^0-9])(\d{9})(?:$|[^0-9])")?,
            validator: Some(is_valid_ssn_compact),
        },
        CompiledPattern {
            id: "pii_credit_card",
            category: SensitiveCategory::Pii,
            data_type: "credit_card",
            confidence: 0.9,
            recommended: RedactionStrategy::Mask,
            regex: compile_required_pattern(r"\b(?:\d[ -]*?){13,19}\b")?,
            validator: Some(is_luhn_valid_card_number),
        },
        CompiledPattern {
            id: "pii_email",
            category: SensitiveCategory::Pii,
            data_type: "email",
            confidence: 0.95,
            recommended: RedactionStrategy::Partial,
            regex: compile_required_pattern(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")?,
            validator: None,
        },
        // ---- Internal ----
        CompiledPattern {
            id: "internal_private_ip",
            category: SensitiveCategory::Internal,
            data_type: "internal_ip",
            confidence: 0.8,
            recommended: RedactionStrategy::TypeLabel,
            regex: compile_required_pattern(
                r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b",
            )?,
            validator: None,
        },
    ])
}

// ---------------------------------------------------------------------------
// Utility: Shannon entropy, Luhn, SSN validation, token previews.
// ---------------------------------------------------------------------------

fn shannon_entropy_ascii(token: &str) -> Option<f64> {
    if !token.is_ascii() {
        return None;
    }
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    Some(entropy)
}

fn is_candidate_secret_token(token: &str) -> bool {
    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

fn is_luhn_valid_card_number(text: &str) -> bool {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut v = u32::from(*d);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum = sum.saturating_add(v);
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn is_valid_ssn_fragments(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

fn is_valid_ssn_compact(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area: u32 = digits.get(0..3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let group: u32 = digits.get(3..5).and_then(|s| s.parse().ok()).unwrap_or(0);
    let serial: u32 = digits.get(5..9).and_then(|s| s.parse().ok()).unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

fn preview_redacted(s: &str) -> String {
    let len = s.chars().count();
    if len <= 4 {
        return "*".repeat(len);
    }
    let prefix: String = s.chars().take(2).collect();
    let suffix_chars: Vec<char> = s.chars().rev().take(2).collect();
    let suffix: String = suffix_chars.into_iter().rev().collect();
    format!("{prefix}***{suffix}")
}

fn truncate_to_char_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (&text[..end], end < text.len())
}

fn fingerprint(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Tokenize store: opaque-id -> original mapping.
// ---------------------------------------------------------------------------

/// Shared token vault used by the `Tokenize` redaction strategy.
#[derive(Debug, Default)]
pub struct TokenVault {
    inner: Mutex<TokenVaultInner>,
}

#[derive(Debug, Default)]
struct TokenVaultInner {
    counter: u64,
    map: HashMap<String, String>,
}

impl TokenVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, value: &str) -> String {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.counter = inner.counter.saturating_add(1);
        let fp = fingerprint(value);
        let id = format!("tok_{}_{}", inner.counter, fp);
        inner.map.insert(id.clone(), value.to_string());
        id
    }

    pub fn get(&self, token: &str) -> Option<String> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.map.get(token).cloned()
    }

    pub fn len(&self) -> usize {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// OutputSanitizer
// ---------------------------------------------------------------------------

/// Full-featured output sanitizer.
pub struct OutputSanitizer {
    config: OutputSanitizerConfig,
    allowlist_patterns: Vec<Regex>,
    denylist_patterns: Vec<(String, Regex)>,
    token_vault: Arc<TokenVault>,
}

impl std::fmt::Debug for OutputSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputSanitizer")
            .field("config", &self.config)
            .field("allowlist_patterns", &self.allowlist_patterns.len())
            .field("denylist_patterns", &self.denylist_patterns.len())
            .finish()
    }
}

impl Default for OutputSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for OutputSanitizer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            allowlist_patterns: self.allowlist_patterns.clone(),
            denylist_patterns: self.denylist_patterns.clone(),
            token_vault: self.token_vault.clone(),
        }
    }
}

impl OutputSanitizer {
    pub fn new() -> Self {
        match Self::with_config(OutputSanitizerConfig::default()) {
            Ok(sanitizer) => sanitizer,
            Err(error) => panic!("default output sanitizer config should be valid: {error}"),
        }
    }

    pub fn with_config(config: OutputSanitizerConfig) -> Result<Self, OutputSanitizerConfigError> {
        // Fail closed: refuse to construct a sanitizer whose constant detector
        // patterns do not compile. Otherwise a malformed built-in pattern would
        // silently disable an entire redaction class (fail-open). This mirrors
        // chio-log-redact validating the default redactor before use.
        build_compiled_patterns().map_err(|source| OutputSanitizerConfigError::InvalidPattern {
            list_name: "built-in",
            pattern: "<built-in>".to_string(),
            source,
        })?;
        compile_required_pattern(HIGH_ENTROPY_TOKEN_PATTERN).map_err(|source| {
            OutputSanitizerConfigError::InvalidPattern {
                list_name: "high-entropy-token",
                pattern: HIGH_ENTROPY_TOKEN_PATTERN.to_string(),
                source,
            }
        })?;
        let allowlist_patterns = config
            .allowlist
            .patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern).map_err(|source| OutputSanitizerConfigError::InvalidPattern {
                    list_name: "allowlist",
                    pattern: pattern.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let denylist_patterns = config
            .denylist
            .patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern)
                    .map(|re| {
                        let id = format!("denylist_{}", fingerprint(pattern));
                        (id, re)
                    })
                    .map_err(|source| OutputSanitizerConfigError::InvalidPattern {
                        list_name: "denylist",
                        pattern: pattern.clone(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            config,
            allowlist_patterns,
            denylist_patterns,
            token_vault: Arc::new(TokenVault::new()),
        })
    }

    pub fn token_vault(&self) -> Arc<TokenVault> {
        self.token_vault.clone()
    }

    pub fn config(&self) -> &OutputSanitizerConfig {
        &self.config
    }

    fn is_allowlisted(&self, s: &str) -> bool {
        if self.config.allowlist.exact.iter().any(|x| x == s) {
            return true;
        }
        self.allowlist_patterns.iter().any(|re| re.is_match(s))
    }

    /// Sanitize a raw text string.
    pub fn sanitize_text(&self, input: &str) -> SanitizationResult {
        let (limited, truncated) = truncate_to_char_boundary(input, self.config.max_input_bytes);

        let mut findings: Vec<SensitiveDataFinding> = Vec::new();

        // Denylist (forced redaction) -- exact strings first, then regexes.
        for needle in &self.config.denylist.exact {
            if needle.is_empty() {
                continue;
            }
            let mut start = 0usize;
            while let Some(pos) = limited[start..].find(needle.as_str()) {
                let s = start + pos;
                let e = s + needle.len();
                findings.push(SensitiveDataFinding {
                    id: format!("denylist_exact_{}", fingerprint(needle)),
                    category: SensitiveCategory::Secret,
                    data_type: "denylist".to_string(),
                    confidence: 1.0,
                    span: Span { start: s, end: e },
                    preview: preview_redacted(needle),
                    detector: "denylist".to_string(),
                    recommended_action: RedactionStrategy::Mask,
                });
                start = e;
            }
        }
        for (id, re) in &self.denylist_patterns {
            for m in re.find_iter(limited) {
                findings.push(SensitiveDataFinding {
                    id: id.clone(),
                    category: SensitiveCategory::Secret,
                    data_type: "denylist".to_string(),
                    confidence: 0.95,
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    preview: preview_redacted(m.as_str()),
                    detector: "denylist".to_string(),
                    recommended_action: RedactionStrategy::Mask,
                });
            }
        }

        // Built-in detectors. If the constant registry failed to compile we
        // fail closed by redacting the whole input rather than scanning with a
        // degraded (matching nothing) detector set.
        let builtin_patterns: &[CompiledPattern] = match compiled_patterns() {
            Ok(patterns) => patterns,
            Err(message) => {
                tracing::error!(
                    error = %message,
                    "built-in redaction patterns unavailable; redacting entire output"
                );
                findings.push(redact_all_finding(limited));
                &[]
            }
        };
        for p in builtin_patterns {
            let enabled = match p.category {
                SensitiveCategory::Secret => self.config.categories.secrets,
                SensitiveCategory::Pii => self.config.categories.pii,
                SensitiveCategory::Internal => self.config.categories.internal,
                SensitiveCategory::Custom(_) => true,
            };
            if !enabled {
                continue;
            }
            for m in p.regex.find_iter(limited) {
                let raw = m.as_str();
                if let Some(validator) = p.validator {
                    if !validator(raw) {
                        continue;
                    }
                }
                if self.is_allowlisted(raw) {
                    continue;
                }
                // For SSN compact, shrink the span to the 9-digit run.
                let (span_start, span_end) = if p.id == "pii_ssn_compact" {
                    let bytes = limited.as_bytes();
                    let mut s = m.start();
                    while s < m.end() && !bytes[s].is_ascii_digit() {
                        s += 1;
                    }
                    let mut e = m.end();
                    while e > s && !bytes[e - 1].is_ascii_digit() {
                        e -= 1;
                    }
                    (s, e)
                } else {
                    (m.start(), m.end())
                };
                if span_start >= span_end {
                    continue;
                }
                let slice = &limited[span_start..span_end];
                findings.push(SensitiveDataFinding {
                    id: p.id.to_string(),
                    category: p.category.clone(),
                    data_type: p.data_type.to_string(),
                    confidence: p.confidence,
                    span: Span {
                        start: span_start,
                        end: span_end,
                    },
                    preview: preview_redacted(slice),
                    detector: "pattern".to_string(),
                    recommended_action: p.recommended.clone(),
                });
            }
        }

        // High-entropy detector. If the token pattern cannot be compiled we
        // fail closed by redacting the whole input rather than skipping the
        // detector (which would let high-entropy secrets through).
        if self.config.categories.secrets && self.config.entropy.enabled {
            static TOKEN_RE: OnceLock<Option<Regex>> = OnceLock::new();
            let token_re =
                TOKEN_RE.get_or_init(|| compile_required_pattern(HIGH_ENTROPY_TOKEN_PATTERN).ok());
            match token_re {
                None => {
                    tracing::error!(
                        "high-entropy token pattern unavailable; redacting entire output"
                    );
                    findings.push(redact_all_finding(limited));
                }
                Some(token_re) => {
                    for m in token_re.find_iter(limited) {
                        let token = m.as_str();
                        if token.len() < self.config.entropy.min_token_len {
                            continue;
                        }
                        if self.is_allowlisted(token) {
                            continue;
                        }
                        if !is_candidate_secret_token(token) {
                            continue;
                        }
                        let ent = match shannon_entropy_ascii(token) {
                            Some(e) => e,
                            None => continue,
                        };
                        if ent < self.config.entropy.threshold {
                            continue;
                        }
                        findings.push(SensitiveDataFinding {
                            id: "secret_high_entropy_token".to_string(),
                            category: SensitiveCategory::Secret,
                            data_type: "high_entropy_token".to_string(),
                            confidence: 0.6,
                            span: Span {
                                start: m.start(),
                                end: m.end(),
                            },
                            preview: preview_redacted(token),
                            detector: "entropy".to_string(),
                            recommended_action: RedactionStrategy::Mask,
                        });
                    }
                }
            }
        }

        findings.sort_by(|a, b| {
            a.span
                .start
                .cmp(&b.span.start)
                .then_with(|| b.span.end.cmp(&a.span.end))
        });

        let merged = resolve_overlaps(&findings, &self.config.redaction_strategies);

        let mut sanitized = limited.to_string();
        let mut redactions: Vec<Redaction> = Vec::new();
        let mut applied_any = false;

        // Apply from last to first so byte offsets remain valid.
        let mut merged_desc = merged;
        merged_desc.sort_by(|a, b| b.0.start.cmp(&a.0.start).then(b.0.end.cmp(&a.0.end)));

        for (span, strategy, category, data_type, finding_id) in merged_desc {
            if span.end > sanitized.len() || span.start >= span.end {
                continue;
            }
            if !sanitized.is_char_boundary(span.start) || !sanitized.is_char_boundary(span.end) {
                continue;
            }
            let raw = &sanitized[span.start..span.end];
            let replacement = self.replacement_for(&strategy, &category, &data_type, raw);
            if replacement == raw {
                continue;
            }
            sanitized.replace_range(span.start..span.end, &replacement);
            applied_any = true;
            redactions.push(Redaction {
                finding_id,
                strategy,
                original_span: span,
                replacement,
            });
        }

        if truncated {
            sanitized.push_str("\n[TRUNCATED_UNSCANNED_OUTPUT]");
            applied_any = true;
        }

        let stats = ProcessingStats {
            input_length: input.len(),
            output_length: sanitized.len(),
            findings_count: findings.len(),
            redactions_count: redactions.len(),
        };

        let mut result = SanitizationResult {
            sanitized,
            was_redacted: applied_any,
            findings,
            redactions,
            stats,
        };
        if !self.config.include_findings {
            result.findings.clear();
        }
        result
    }

    fn replacement_for(
        &self,
        strategy: &RedactionStrategy,
        category: &SensitiveCategory,
        data_type: &str,
        raw: &str,
    ) -> String {
        match strategy {
            RedactionStrategy::Keep => raw.to_string(),
            RedactionStrategy::Mask => "****".to_string(),
            RedactionStrategy::Fingerprint => format!("[FP:{}]", fingerprint(raw)),
            RedactionStrategy::Drop => String::new(),
            RedactionStrategy::Tokenize => {
                let id = self.token_vault.insert(raw);
                format!("[TOKEN:{id}]")
            }
            RedactionStrategy::Partial => preview_redacted(raw),
            RedactionStrategy::TypeLabel => match category {
                SensitiveCategory::Secret | SensitiveCategory::Pii => {
                    format!("[REDACTED:{data_type}]")
                }
                SensitiveCategory::Internal => "[REDACTED:internal]".to_string(),
                SensitiveCategory::Custom(label) => format!("[REDACTED:{label}]"),
            },
        }
    }

    /// Sanitize a JSON value. Preserves structure: strings are sanitized in
    /// place, arrays and objects are recursed. Fields whose detected strategy
    /// is `Drop` and which consist entirely of the match become `null`.
    pub fn sanitize_value(&self, value: &serde_json::Value) -> SanitizedValue {
        let mut findings: Vec<SensitiveDataFinding> = Vec::new();
        let mut redactions: Vec<Redaction> = Vec::new();
        let mut was_redacted = false;
        let sanitized =
            self.sanitize_value_inner(value, &mut findings, &mut redactions, &mut was_redacted);
        SanitizedValue {
            value: sanitized,
            findings,
            redactions,
            was_redacted,
        }
    }

    fn sanitize_value_inner(
        &self,
        value: &serde_json::Value,
        findings: &mut Vec<SensitiveDataFinding>,
        redactions: &mut Vec<Redaction>,
        was_redacted: &mut bool,
    ) -> serde_json::Value {
        use serde_json::Value as V;
        match value {
            V::Null | V::Bool(_) | V::Number(_) => value.clone(),
            V::String(s) => {
                let r = self.sanitize_text(s);
                if r.was_redacted {
                    *was_redacted = true;
                    // If the entire string was detected and the chosen
                    // strategy was Drop, collapse the field to null so it
                    // disappears downstream.
                    if r.sanitized.is_empty()
                        && r.redactions.len() == 1
                        && matches!(r.redactions[0].strategy, RedactionStrategy::Drop)
                    {
                        findings.extend(r.findings);
                        redactions.extend(r.redactions);
                        return V::Null;
                    }
                }
                findings.extend(r.findings);
                redactions.extend(r.redactions);
                V::String(r.sanitized)
            }
            V::Array(items) => {
                let new_items: Vec<serde_json::Value> = items
                    .iter()
                    .map(|v| self.sanitize_value_inner(v, findings, redactions, was_redacted))
                    .collect();
                V::Array(new_items)
            }
            V::Object(map) => {
                if let Some((finding, redaction)) = detect_service_account_object(map) {
                    *was_redacted = true;
                    findings.push(finding);
                    redactions.push(redaction);
                    return V::Null;
                }
                let mut new_map = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    let sv = self.sanitize_value_inner(v, findings, redactions, was_redacted);
                    new_map.insert(k.clone(), sv);
                }
                V::Object(new_map)
            }
        }
    }
}

/// Output of `OutputSanitizer::sanitize_value`.
#[derive(Debug, Clone)]
pub struct SanitizedValue {
    pub value: serde_json::Value,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub was_redacted: bool,
}

// ---------------------------------------------------------------------------
// Overlap resolution: longest-match-wins, with strategy-rank tiebreaker.
// ---------------------------------------------------------------------------

fn strategy_rank(s: &RedactionStrategy) -> u8 {
    match s {
        RedactionStrategy::Keep => 0,
        RedactionStrategy::Partial => 1,
        RedactionStrategy::TypeLabel => 2,
        RedactionStrategy::Fingerprint => 3,
        RedactionStrategy::Tokenize => 4,
        RedactionStrategy::Mask => 5,
        RedactionStrategy::Drop => 6,
    }
}

type ResolvedSpan = (Span, RedactionStrategy, SensitiveCategory, String, String);

fn resolve_overlaps(
    findings: &[SensitiveDataFinding],
    defaults: &HashMap<SensitiveCategory, RedactionStrategy>,
) -> Vec<ResolvedSpan> {
    let mut spans: Vec<ResolvedSpan> = Vec::with_capacity(findings.len());
    for f in findings {
        // Strategy selection:
        //   - If the detector recommended Keep, honor it.
        //   - If the detector asked for a "strong" action (Drop, Fingerprint,
        //     Tokenize), honor that (overriding category default).
        //   - Otherwise fall back to the config's per-category default, else
        //     the detector's recommendation.
        let strategy = match &f.recommended_action {
            RedactionStrategy::Keep => RedactionStrategy::Keep,
            RedactionStrategy::Drop
            | RedactionStrategy::Fingerprint
            | RedactionStrategy::Tokenize => f.recommended_action.clone(),
            _ => defaults
                .get(&f.category)
                .cloned()
                .unwrap_or_else(|| f.recommended_action.clone()),
        };
        spans.push((
            f.span,
            strategy,
            f.category.clone(),
            f.data_type.clone(),
            f.id.clone(),
        ));
    }

    spans.sort_by(|a, b| {
        a.0.start
            .cmp(&b.0.start)
            .then_with(|| b.0.end.cmp(&a.0.end))
    });

    let mut merged: Vec<ResolvedSpan> = Vec::new();
    for current in spans {
        if let Some(last) = merged.last_mut() {
            if current.0.start < last.0.end {
                let new_end = last.0.end.max(current.0.end);
                last.0.end = new_end;
                if strategy_rank(&current.1) > strategy_rank(&last.1) {
                    last.1 = current.1;
                    last.2 = current.2;
                    last.3 = current.3;
                    last.4 = current.4;
                }
                continue;
            }
        }
        merged.push(current);
    }
    merged
}

fn detect_service_account_object(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Option<(SensitiveDataFinding, Redaction)> {
    let value = map.get("type")?.as_str()?;
    if !value.eq_ignore_ascii_case("service_account") {
        return None;
    }

    let span = Span { start: 0, end: 0 };
    let finding = SensitiveDataFinding {
        id: "secret_gcp_service_account".to_string(),
        category: SensitiveCategory::Secret,
        data_type: "gcp_service_account_json".to_string(),
        confidence: 0.97,
        span,
        preview: preview_redacted(value),
        detector: "object".to_string(),
        recommended_action: RedactionStrategy::Drop,
    };
    let redaction = Redaction {
        finding_id: finding.id.clone(),
        strategy: RedactionStrategy::Drop,
        original_span: span,
        replacement: String::new(),
    };
    Some((finding, redaction))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_patterns_compile_to_full_set() {
        // Every built-in constant pattern must compile; a regression that
        // breaks one must fail CI here rather than silently shrink the
        // detector set at runtime.
        assert_eq!(default_patterns().len(), 7);
    }

    // ---- Simple (backwards-compatible) API tests ----

    #[test]
    fn guard_name() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        assert_eq!(guard.name(), "response-sanitization");
    }

    #[test]
    fn detects_ssn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("My SSN is 123-45-6789");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|(name, _)| name == "SSN"));
    }

    #[test]
    fn detects_email() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("Contact john@example.com for info");
        assert!(findings.iter().any(|(name, _)| name == "email"));
    }

    #[test]
    fn detects_mrn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("Patient MRN: 123456789");
        assert!(findings.iter().any(|(name, _)| name == "MRN"));
    }

    #[test]
    fn no_findings_on_clean_text() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let findings = guard.scan("This is perfectly clean text with no PII.");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_minimum_sensitivity() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let findings = guard.scan("Contact john@example.com");
        assert!(!findings.iter().any(|(name, _)| name == "email"));
        let findings2 = guard.scan("SSN 123-45-6789");
        assert!(findings2.iter().any(|(name, _)| name == "SSN"));
    }

    #[test]
    fn redacts_ssn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
        let (redacted, count) = guard.redact("SSN is 123-45-6789 please");
        assert!(redacted.contains("[SSN REDACTED]"));
        assert!(!redacted.contains("123-45-6789"));
        assert!(count > 0);
    }

    #[test]
    fn redacts_email() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
        let (redacted, _) = guard.redact("Email: jane@example.com");
        assert!(redacted.contains("[EMAIL REDACTED]"));
        assert!(!redacted.contains("jane@example.com"));
    }

    #[test]
    fn scan_response_clean() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let response = serde_json::json!({"status": "ok", "data": "nothing sensitive"});
        let result = guard.scan_response(&response);
        assert!(matches!(result, ScanResult::Clean));
    }

    #[test]
    fn scan_response_blocked() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
        let result = guard.scan_response(&response);
        assert!(matches!(result, ScanResult::Blocked(_)));
    }

    #[test]
    fn scan_response_redacted() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Redact);
        let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
        let result = guard.scan_response(&response);
        match result {
            ScanResult::Redacted { redacted_text, .. } => {
                assert!(redacted_text.contains("[SSN REDACTED]"));
            }
            _ => panic!("expected Redacted result"),
        }
    }

    #[test]
    fn guard_evaluate_denies_args_with_pii() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv".to_string();

        let cap_body = chio_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = chio_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"content": "SSN is 123-45-6789"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn guard_evaluate_allows_clean_args() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv".to_string();

        let cap_body = chio_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = chio_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn custom_pattern() {
        let pattern = build_pattern(
            "custom-id",
            r"\bCUST-\d{8}\b",
            SensitivityLevel::High,
            "[CUST-ID REDACTED]",
        );
        assert!(pattern.is_some());

        let guard = ResponseSanitizationGuard::with_patterns(
            vec![pattern.unwrap()],
            SensitivityLevel::High,
            SanitizationAction::Block,
        );
        let findings = guard.scan("Customer CUST-12345678 record");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|(name, _)| name == "custom-id"));
    }

    // ---- OutputSanitizer unit tests ----

    #[test]
    fn luhn_rejects_random_16_digit_number() {
        assert!(!is_luhn_valid_card_number("1234567890123456"));
        // Known-valid test card (Visa).
        assert!(is_luhn_valid_card_number("4111 1111 1111 1111"));
        // One digit flipped: no longer valid.
        assert!(!is_luhn_valid_card_number("4111 1111 1111 1112"));
    }

    #[test]
    fn shannon_entropy_basic() {
        let e = shannon_entropy_ascii("aaaaaa").unwrap();
        assert!(e < 0.01);
        let e2 = shannon_entropy_ascii("abcdefghij0123456789").unwrap();
        assert!(e2 > 4.0);
    }

    #[test]
    fn ssn_fragments_validator_rejects_invalid_areas() {
        assert!(!is_valid_ssn_fragments("000-12-3456"));
        assert!(!is_valid_ssn_fragments("666-12-3456"));
        assert!(!is_valid_ssn_fragments("900-12-3456"));
        assert!(!is_valid_ssn_fragments("123-00-4567"));
        assert!(!is_valid_ssn_fragments("123-45-0000"));
        assert!(is_valid_ssn_fragments("123-45-6789"));
    }
}
