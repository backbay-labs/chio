use std::sync::{Arc, OnceLock};

use regex::Regex;

use super::detectors::{
    build_compiled_patterns, compile_required_pattern, compiled_patterns, redact_all_finding,
    CompiledPattern, HIGH_ENTROPY_TOKEN_PATTERN,
};
use super::formatting::{fingerprint, preview_redacted, truncate_to_char_boundary};
use super::overlap::{detect_service_account_object, resolve_overlaps};
use super::types::{
    OutputSanitizerConfig, OutputSanitizerConfigError, ProcessingStats, Redaction,
    RedactionStrategy, SanitizationResult, SanitizedValue, SensitiveCategory, SensitiveDataFinding,
    Span,
};
use super::validators::{is_candidate_secret_token, shannon_entropy_ascii};
use super::vault::TokenVault;

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
    fn build_default_or_fail_closed() -> Self {
        Self::with_config(OutputSanitizerConfig::default()).unwrap_or_else(|_| Self {
            config: OutputSanitizerConfig::default(),
            allowlist_patterns: vec![],
            denylist_patterns: vec![],
            token_vault: Arc::new(TokenVault::default()),
        })
    }

    fn clone_with_fresh_vault(&self) -> Self {
        Self {
            config: self.config.clone(),
            allowlist_patterns: self.allowlist_patterns.clone(),
            denylist_patterns: self.denylist_patterns.clone(),
            token_vault: Arc::new(TokenVault::new()),
        }
    }

    pub fn new() -> Self {
        static DEFAULT: OnceLock<OutputSanitizer> = OnceLock::new();
        DEFAULT
            .get_or_init(Self::build_default_or_fail_closed)
            .clone_with_fresh_vault()
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
        if !self.config.include_findings {
            findings.clear();
        }
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
