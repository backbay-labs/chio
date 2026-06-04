//! ContentReviewGuard -- pre-invocation review of outbound content for
//! SaaS / communication / payment tool calls.
//!
//! The guard inspects
//! [`ToolAction::ExternalApiCall`] requests to services like Slack,
//! SendGrid, Twilio, and Stripe, applying:
//!
//! 1. **PII detection** on message bodies / email text.  Detected
//!    categories are surfaced through tracing evidence.
//! 2. **Tone / profanity** filter (configurable wordlist).
//! 3. **Monetary approval gating** -- payment calls whose amount meets
//!    or exceeds the grant's [`Constraint::RequireApprovalAbove`]
//!    threshold yield [`Verdict::PendingApproval`] so the HITL flow in
//!    [`chio_kernel::approval`] can collect a human signoff.
//!
//! Unknown / non-external-API actions pass through with [`Verdict::Allow`].
//!
//! Evidence is emitted via `tracing::warn!` with a structured
//! `detected_categories` field so downstream log pipelines can extract
//! the reasons.
//!
//! # Fail-closed semantics
//!
//! - [`ContentReviewConfig::per_service`] lookups fall back to
//!   [`ContentReviewConfig::default_rules`];
//! - invalid user-supplied regex patterns cause
//!   [`ContentReviewGuard::with_config`] to return
//!   [`ContentReviewError::InvalidPattern`];
//! - messages that trip both PII and profanity return a single `Deny`
//!   outcome but log both categories as evidence.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use chio_core::capability::Constraint;
use chio_kernel::{Guard, GuardContext, KernelError, Verdict};

use crate::action::{extract_action_checked, ToolAction};

/// Errors produced when building a [`ContentReviewGuard`].
#[derive(Debug, thiserror::Error)]
pub enum ContentReviewError {
    /// A user-supplied regex pattern failed to compile.
    #[error("invalid review pattern `{pattern}`: {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    /// A user-supplied regex pattern exceeded policy-load safety limits.
    #[error("{0}")]
    UnsafePattern(String),
}

/// Per-service review rules.  Missing fields fall back to defaults.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentReviewRules {
    /// Enable PII detection on the message body.  Default `true`.
    #[serde(default = "default_true")]
    pub detect_pii: bool,
    /// Enable the profanity filter.  Default `true`.
    #[serde(default = "default_true")]
    pub detect_profanity: bool,
    /// Case-insensitive words that trigger a Deny.
    #[serde(default)]
    pub banned_words: Vec<String>,
    /// Extra regex patterns whose match triggers a Deny.
    #[serde(default)]
    pub extra_patterns: Vec<String>,
    /// Maximum bytes of outbound text to scan.  Longer inputs are
    /// truncated at a UTF-8 boundary.
    #[serde(default = "default_max_scan_bytes")]
    pub max_scan_bytes: usize,
}

fn default_true() -> bool {
    true
}

fn default_max_scan_bytes() -> usize {
    64 * 1024
}

/// Full content-review configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentReviewConfig {
    /// Enable/disable the guard entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default rules applied when a service has no per-service entry.
    #[serde(default = "default_rules")]
    pub default_rules: ContentReviewRules,
    /// Per-service overrides keyed by the service name produced by
    /// [`crate::action::extract_action`] (e.g. `"slack"`, `"stripe"`).
    #[serde(default)]
    pub per_service: HashMap<String, ContentReviewRules>,
}

fn default_rules() -> ContentReviewRules {
    ContentReviewRules {
        detect_pii: true,
        detect_profanity: true,
        banned_words: Vec::new(),
        extra_patterns: Vec::new(),
        max_scan_bytes: default_max_scan_bytes(),
    }
}

impl Default for ContentReviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rules: default_rules(),
            per_service: HashMap::new(),
        }
    }
}

/// Compiled per-service rules (regex already built).
struct CompiledRules {
    detect_pii: bool,
    detect_profanity: bool,
    banned_words: HashSet<String>,
    extra_patterns: Vec<Regex>,
    max_scan_bytes: usize,
}

const MAX_EXTRA_PATTERNS: usize = 64;
const MAX_EXTRA_PATTERN_LEN: usize = 512;
const MAX_EXTRA_PATTERN_COMPLEXITY: usize = 96;
const EXTRA_PATTERN_REGEX_SIZE_LIMIT: usize = 1 << 20;
const EXTRA_PATTERN_DFA_SIZE_LIMIT: usize = 1 << 20;

impl CompiledRules {
    fn compile(rules: &ContentReviewRules) -> Result<Self, ContentReviewError> {
        if rules.extra_patterns.len() > MAX_EXTRA_PATTERNS {
            return Err(ContentReviewError::UnsafePattern(format!(
                "content_review.extra_patterns allows at most {MAX_EXTRA_PATTERNS} patterns"
            )));
        }
        let mut extra_patterns = Vec::with_capacity(rules.extra_patterns.len());
        for pat in &rules.extra_patterns {
            let trimmed = pat.trim();
            if trimmed.is_empty() {
                return Err(ContentReviewError::UnsafePattern(
                    "content_review.extra_patterns cannot contain empty patterns".to_string(),
                ));
            }
            if trimmed.len() > MAX_EXTRA_PATTERN_LEN {
                return Err(ContentReviewError::UnsafePattern(format!(
                    "content_review.extra_patterns entries must be at most {MAX_EXTRA_PATTERN_LEN} characters"
                )));
            }
            let complexity = review_pattern_complexity(trimmed);
            if complexity > MAX_EXTRA_PATTERN_COMPLEXITY {
                return Err(ContentReviewError::UnsafePattern(format!(
                    "content_review.extra_patterns entries must have complexity at most {MAX_EXTRA_PATTERN_COMPLEXITY}"
                )));
            }
            let re = RegexBuilder::new(trimmed)
                .size_limit(EXTRA_PATTERN_REGEX_SIZE_LIMIT)
                .dfa_size_limit(EXTRA_PATTERN_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| ContentReviewError::InvalidPattern {
                    pattern: trimmed.to_string(),
                    source: e,
                })?;
            extra_patterns.push(re);
        }
        let banned_words = rules
            .banned_words
            .iter()
            .map(|w| w.to_ascii_lowercase())
            .collect();
        Ok(Self {
            detect_pii: rules.detect_pii,
            detect_profanity: rules.detect_profanity,
            banned_words,
            extra_patterns,
            max_scan_bytes: rules.max_scan_bytes.max(1),
        })
    }
}

fn review_pattern_complexity(pattern: &str) -> usize {
    let mut score = 0usize;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' | '*' | '+' | '?' => score = score.saturating_add(4),
            '{' | '[' | '(' => score = score.saturating_add(2),
            _ => {}
        }
    }
    score
}

/// Guard that runs content review on outbound SaaS / payment / comms
/// calls.
pub struct ContentReviewGuard {
    enabled: bool,
    default_rules: CompiledRules,
    per_service: HashMap<String, CompiledRules>,
}

impl ContentReviewGuard {
    /// Build a guard with default configuration.
    pub fn new() -> Self {
        match Self::with_config(ContentReviewConfig::default()) {
            Ok(g) => g,
            Err(_) => Self {
                enabled: true,
                default_rules: CompiledRules {
                    detect_pii: true,
                    detect_profanity: true,
                    banned_words: HashSet::new(),
                    extra_patterns: Vec::new(),
                    max_scan_bytes: default_max_scan_bytes(),
                },
                per_service: HashMap::new(),
            },
        }
    }

    /// Build a guard with explicit configuration.  Returns
    /// [`ContentReviewError::InvalidPattern`] if any regex fails to
    /// compile.
    pub fn with_config(config: ContentReviewConfig) -> Result<Self, ContentReviewError> {
        let default_rules = CompiledRules::compile(&config.default_rules)?;
        let mut per_service = HashMap::with_capacity(config.per_service.len());
        for (service, rules) in &config.per_service {
            per_service.insert(service.clone(), CompiledRules::compile(rules)?);
        }
        Ok(Self {
            enabled: config.enabled,
            default_rules,
            per_service,
        })
    }

    /// Fetch compiled rules for a service, falling back to defaults.
    fn rules_for(&self, service: &str) -> &CompiledRules {
        self.per_service.get(service).unwrap_or(&self.default_rules)
    }
}

impl Default for ContentReviewGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for ContentReviewGuard {
    fn name(&self) -> &str {
        "content-review"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        if !self.enabled {
            return Ok(Verdict::Allow);
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(Verdict::Deny),
        };
        let (service, endpoint) = match action {
            ToolAction::ExternalApiCall { service, endpoint } => (service, endpoint),
            _ => return Ok(Verdict::Allow),
        };

        // 1. Monetary approval gating: check the matched grant for a
        //    RequireApprovalAbove constraint and compare to the amount
        //    surfaced in the request body / governed intent.
        if let Some(verdict) = evaluate_amount_threshold(ctx, &service)? {
            return Ok(verdict);
        }

        // 2. Extract outbound text from the common argument shapes.
        let text = extract_outbound_text(&ctx.request.arguments);
        let text = match text {
            Some(t) if !t.is_empty() => t,
            _ => return Ok(Verdict::Allow),
        };

        let rules = self.rules_for(&service);
        let truncated = truncate_utf8(&text, rules.max_scan_bytes);

        // 3. PII detection.
        let mut categories: Vec<&'static str> = Vec::new();
        if rules.detect_pii {
            for (category, re) in builtin_pii_patterns() {
                if re.is_match(truncated) {
                    categories.push(*category);
                }
            }
        }

        // 4. Profanity / banned word check.
        if rules.detect_profanity && contains_banned_word(truncated, &rules.banned_words) {
            categories.push("profanity");
        }

        // 5. Extra user regex patterns.
        for re in &rules.extra_patterns {
            if re.is_match(truncated) {
                categories.push("custom");
            }
        }

        if !categories.is_empty() {
            tracing::warn!(
                guard = "content-review",
                service = %service,
                endpoint = %endpoint,
                detected_categories = ?categories,
                "content-review denied outbound message"
            );
            return Ok(Verdict::Deny);
        }

        Ok(Verdict::Allow)
    }
}

/// Inspect the matched grant for a [`Constraint::RequireApprovalAbove`]
/// and compare the requested amount to its threshold.  When the call is
/// a payment-service call (`stripe`, `paypal`, ...) and the amount meets
/// the threshold, emit [`Verdict::PendingApproval`] so the kernel's
/// HITL surface can take over.
fn evaluate_amount_threshold(
    ctx: &GuardContext,
    service: &str,
) -> Result<Option<Verdict>, KernelError> {
    if !is_payment_service(service) {
        return Ok(None);
    }
    let Some(grant) = ctx
        .matched_grant_index
        .and_then(|idx| ctx.scope.grants.get(idx))
    else {
        return Ok(None);
    };

    let threshold = grant.constraints.iter().find_map(|c| match c {
        Constraint::RequireApprovalAbove { threshold_units } => Some(*threshold_units),
        _ => None,
    });
    let Some(threshold) = threshold else {
        return Ok(None);
    };

    let amount_units = extract_amount_units(ctx.request).or_else(|| {
        ctx.request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.max_amount.as_ref().map(|amt| amt.units))
    });
    let Some(units) = amount_units else {
        // Cannot compare; leave the decision to other guards.
        return Ok(None);
    };
    if units >= threshold {
        tracing::info!(
            guard = "content-review",
            service = %service,
            units,
            threshold,
            "content-review requires human approval for monetary threshold"
        );
        return Ok(Some(Verdict::PendingApproval));
    }
    Ok(None)
}

/// Return `true` for services where monetary threshold checks apply.
fn is_payment_service(service: &str) -> bool {
    matches!(
        service,
        "stripe" | "paypal" | "square" | "braintree" | "adyen" | "plaid"
    )
}

/// Extract an amount-in-units figure from common argument names used by
/// payment APIs.  Interprets plain numeric fields (`amount`,
/// `amount_units`) as the minor-unit integer.
fn extract_amount_units(request: &chio_kernel::ToolCallRequest) -> Option<u64> {
    let args = &request.arguments;
    for key in ["amount_units", "amountUnits", "amount"] {
        if let Some(v) = args.get(key) {
            if let Some(u) = v.as_u64() {
                return Some(u);
            }
            if let Some(f) = v.as_f64() {
                if f >= 0.0 && f.is_finite() {
                    return Some(f as u64);
                }
            }
        }
    }
    None
}

/// Extract the outbound text to review from the tool-call arguments.
fn extract_outbound_text(arguments: &Value) -> Option<String> {
    let mut chunks: Vec<String> = Vec::new();
    for key in [
        "text",
        "body",
        "message",
        "content",
        "subject",
        "html",
        "description",
        "summary",
        "note",
    ] {
        if let Some(v) = arguments.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                chunks.push(v.to_string());
            }
        }
    }
    // Slack-style blocks[].text.text.
    if let Some(arr) = arguments.get("blocks").and_then(|v| v.as_array()) {
        for block in arr {
            if let Some(text) = block
                .get("text")
                .and_then(|t| t.get("text"))
                .and_then(|t| t.as_str())
            {
                chunks.push(text.to_string());
            }
        }
    }
    if chunks.is_empty() {
        None
    } else {
        Some(chunks.join("\n"))
    }
}

fn truncate_utf8(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

fn contains_banned_word(text: &str, banned: &HashSet<String>) -> bool {
    if banned.is_empty() {
        return false;
    }
    let lowered = text.to_ascii_lowercase();
    for word in banned {
        if word.is_empty() {
            continue;
        }
        if lowered.contains(word) {
            return true;
        }
    }
    false
}

/// Compiled once per process.  Built-in PII detectors keyed by the
/// category tag surfaced in tracing evidence.
fn builtin_pii_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        let sources: &[(&'static str, &'static str)] = &[
            ("email", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
            ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
            ("phone_us", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
            ("credit_card", r"\b(?:\d[ -]*?){13,19}\b"),
            ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ];
        sources
            .iter()
            .filter_map(|(cat, src)| match Regex::new(src) {
                Ok(re) => Some((*cat, re)),
                Err(err) => {
                    tracing::error!(error = %err, source = %src, category = %cat, "content-review: pii regex failed");
                    None
                }
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_outbound_text_joins_chunks() {
        let args = serde_json::json!({
            "subject": "hi",
            "body": "hello",
            "blocks": [{"text": {"text": "b1"}}]
        });
        let text = extract_outbound_text(&args).unwrap();
        assert!(text.contains("hi"));
        assert!(text.contains("hello"));
        assert!(text.contains("b1"));
    }

    #[test]
    fn pii_patterns_detect_email() {
        let pats = builtin_pii_patterns();
        assert!(pats
            .iter()
            .any(|(cat, re)| *cat == "email" && re.is_match("user@example.com")));
    }

    #[test]
    fn truncate_utf8_honors_boundaries() {
        let s = "héllo";
        let out = truncate_utf8(s, 2);
        assert_eq!(out, "h");
    }
}
