use regex::Regex;

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

use super::detectors::compile_required_pattern;

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

pub(super) fn default_patterns() -> Vec<SensitivePattern> {
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

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let args_text = ctx.request.arguments.to_string();
        let findings = self.scan(&args_text);
        if findings.is_empty() {
            Ok(GuardDecision::allow())
        } else {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        crate::revalidate_non_consuming_guard(self, ctx)
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
