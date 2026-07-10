use std::sync::OnceLock;

use regex::Regex;

use super::types::{RedactionStrategy, SensitiveCategory, SensitiveDataFinding, Span};
use super::validators::{is_luhn_valid_card_number, is_valid_ssn_compact, is_valid_ssn_fragments};

// ---------------------------------------------------------------------------
// Compiled detector registry (lazy, built once per process).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(super) struct CompiledPattern {
    pub(super) id: &'static str,
    pub(super) category: SensitiveCategory,
    pub(super) data_type: &'static str,
    pub(super) confidence: f32,
    pub(super) recommended: RedactionStrategy,
    pub(super) regex: Regex,
    pub(super) validator: Option<fn(&str) -> bool>,
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
pub(super) fn compile_required_pattern(pattern: &'static str) -> Result<Regex, regex::Error> {
    Regex::new(pattern).inspect_err(|err| {
        tracing::error!(error = %err, %pattern, "failed to compile hardcoded redaction regex");
    })
}

/// Pattern used by the high-entropy secret detector.
pub(super) const HIGH_ENTROPY_TOKEN_PATTERN: &str = r"[A-Za-z0-9+/=_-]{16,}";

/// Fail-closed finding that drops the entire scanned input.
///
/// Used when a constant detector pattern cannot be compiled at runtime, a
/// state `OutputSanitizer::with_config` already refuses to construct. Rather
/// than let any content through unredacted, we redact everything: the
/// response-sanitization analogue of `chio-log-redact`'s `[REDACTION-FAILED]`
/// substitution. The strategy is `Drop` (not `Mask`) because `resolve_overlaps`
/// honors `Drop` unconditionally, so a per-category strategy override cannot
/// downgrade this fail-closed finding to `Keep`.
pub(super) fn redact_all_finding(limited: &str) -> SensitiveDataFinding {
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
pub(super) fn compiled_patterns() -> Result<&'static [CompiledPattern], &'static str> {
    static PATS: OnceLock<Result<Vec<CompiledPattern>, String>> = OnceLock::new();
    match PATS.get_or_init(|| build_compiled_patterns().map_err(|err| err.to_string())) {
        Ok(patterns) => Ok(patterns.as_slice()),
        Err(message) => Err(message.as_str()),
    }
}

pub(super) fn build_compiled_patterns() -> Result<Vec<CompiledPattern>, regex::Error> {
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
                r"\b(?:10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.[0-9]{1,3}){2})\b",
            )?,
            validator: None,
        },
    ])
}
