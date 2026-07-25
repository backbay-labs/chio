//! Post-invocation hook pipeline -- inspects tool results before they reach
//! the agent.
//!
//! This module provides a pipeline of post-invocation hooks that run after
//! a tool has produced a response. Each hook can:
//!
//! - **Allow** the response to pass through unmodified
//! - **Block** the response entirely (replacing it with an error)
//! - **Redact** parts of the response before delivery
//! - **Escalate** the response for operator review
//!
//! Hooks run in registration order. A Block from any hook stops the pipeline.
//!
//! The ready-made [`SanitizerHook`] wraps the full [`OutputSanitizer`] and
//! automatically redacts secrets, PII, and high-entropy tokens from tool
//! results while preserving JSON structure. Sanitization evidence is emitted
//! alongside the pipeline verdict so the kernel can embed it in the receipt's
//! `GuardEvidence`.

use chio_core::receipt::metadata::GuardEvidence;
pub use chio_kernel::{
    PipelineOutcome, PostInvocationContext, PostInvocationHook, PostInvocationHookIdentity,
    PostInvocationPipeline, PostInvocationVerdict,
};
use serde::Serialize;
use serde_json::Value;

use crate::response_sanitization::{
    OutputSanitizer, OutputSanitizerConfig, OutputSanitizerConfigError, SanitizationResult,
    SensitiveDataFinding,
};

// ---------------------------------------------------------------------------
// SanitizerHook -- post-invocation hook wrapping the full OutputSanitizer.
// ---------------------------------------------------------------------------

/// Post-invocation hook that runs the [`OutputSanitizer`] over tool results.
///
/// Behavior:
/// - If no sensitive data is detected, returns `Allow`.
/// - Otherwise, returns `Redact(sanitized)` with a JSON value whose strings
///   have been sanitized in place (structure preserved).
/// - Emits [`GuardEvidence`] summarizing the findings so they flow into the
///   kernel's receipt. Raw secrets are never included; only previews, spans,
///   and detector ids.
pub struct SanitizerHook {
    sanitizer: OutputSanitizer,
    hook_name: String,
    evidence: std::sync::Mutex<Option<GuardEvidence>>,
}

impl SanitizerHook {
    /// Build a sanitizer hook with the default sanitizer configuration.
    pub fn new() -> Self {
        Self {
            sanitizer: OutputSanitizer::new(),
            hook_name: "output-sanitizer".to_string(),
            evidence: std::sync::Mutex::new(None),
        }
    }

    /// Build a sanitizer hook with a custom sanitizer configuration.
    pub fn with_config(config: OutputSanitizerConfig) -> Result<Self, OutputSanitizerConfigError> {
        Ok(Self {
            sanitizer: OutputSanitizer::with_config(config)?,
            hook_name: "output-sanitizer".to_string(),
            evidence: std::sync::Mutex::new(None),
        })
    }

    /// Build a sanitizer hook from a pre-constructed sanitizer.
    pub fn from_sanitizer(sanitizer: OutputSanitizer) -> Self {
        Self {
            sanitizer,
            hook_name: "output-sanitizer".to_string(),
            evidence: std::sync::Mutex::new(None),
        }
    }

    /// Override the hook name (useful for telemetry).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.hook_name = name.into();
        self
    }

    /// Access the underlying sanitizer (useful for tests / operator tooling).
    pub fn sanitizer(&self) -> &OutputSanitizer {
        &self.sanitizer
    }

    fn store_evidence(&self, ev: GuardEvidence) {
        let mut guard = match self.evidence.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(ev);
    }
}

impl Default for SanitizerHook {
    fn default() -> Self {
        Self::new()
    }
}

impl PostInvocationHook for SanitizerHook {
    fn name(&self) -> &str {
        &self.hook_name
    }

    fn inspect(&self, _ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        let sanitized = self.sanitizer.sanitize_value(response);
        if !sanitized.was_redacted {
            // Clear any stale evidence from a previous run.
            if let Ok(mut g) = self.evidence.lock() {
                *g = None;
            }
            return PostInvocationVerdict::Allow;
        }
        let details = summarize_findings(&sanitized.findings, &sanitized.redactions);
        self.store_evidence(GuardEvidence {
            guard_name: self.hook_name.clone(),
            verdict: true, // sanitized: still allowed but redacted
            details: Some(details),
        });
        PostInvocationVerdict::Redact(sanitized.value)
    }

    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        if self.sanitizer.uses_tokenization().map_err(str::to_owned)? {
            return Err(
                "output sanitizer tokenize redaction strategy is not deterministic".to_string(),
            );
        }
        #[derive(Serialize)]
        struct SanitizerIdentityConfig<'a> {
            hook_name: &'a str,
            sanitizer: &'a OutputSanitizerConfig,
        }

        PostInvocationHookIdentity::from_canonical_config(
            "chio.output-sanitizer",
            "1",
            "chio-guards.output-sanitizer.v1",
            &SanitizerIdentityConfig {
                hook_name: &self.hook_name,
                sanitizer: self.sanitizer.config(),
            },
        )
        .map(Some)
    }

    fn take_evidence(&self) -> Option<GuardEvidence> {
        let mut guard = match self.evidence.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.take()
    }
}

// Produce a stable, non-leaky summary of findings for receipt evidence.
fn summarize_findings(
    findings: &[SensitiveDataFinding],
    _redactions: &[crate::response_sanitization::Redaction],
) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in findings {
        *counts.entry(f.id.clone()).or_insert(0) += 1;
    }
    let parts: Vec<String> = counts
        .into_iter()
        .map(|(id, n)| format!("{id}:{n}"))
        .collect();
    format!(
        "sanitizer detected {} findings ({})",
        findings.len(),
        parts.join(",")
    )
}

/// Run the sanitizer over a JSON value and return the sanitized value plus a
/// [`SanitizationResult`] aggregating all findings/redactions. Useful for
/// tests and for callers that want the raw details without wiring a full
/// pipeline.
pub fn sanitize_json(sanitizer: &OutputSanitizer, value: &Value) -> (Value, SanitizationResult) {
    let sv = sanitizer.sanitize_value(value);
    let sanitized_text = sv.value.to_string();
    let stats = crate::response_sanitization::ProcessingStats {
        input_length: value.to_string().len(),
        output_length: sanitized_text.len(),
        findings_count: sv.findings.len(),
        redactions_count: sv.redactions.len(),
    };
    let result = SanitizationResult {
        sanitized: sanitized_text,
        was_redacted: sv.was_redacted,
        findings: sv.findings,
        redactions: sv.redactions,
        stats,
    };
    (sv.value, result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct AllowHook;
    impl PostInvocationHook for AllowHook {
        fn name(&self) -> &str {
            "allow-all"
        }
        fn inspect(
            &self,
            _ctx: &PostInvocationContext<'_>,
            _resp: &Value,
        ) -> PostInvocationVerdict {
            PostInvocationVerdict::Allow
        }
    }

    struct BlockHook(String);
    impl PostInvocationHook for BlockHook {
        fn name(&self) -> &str {
            "block-all"
        }
        fn inspect(
            &self,
            _ctx: &PostInvocationContext<'_>,
            _resp: &Value,
        ) -> PostInvocationVerdict {
            PostInvocationVerdict::Block(self.0.clone())
        }
    }

    struct RedactHook;
    impl PostInvocationHook for RedactHook {
        fn name(&self) -> &str {
            "redact-all"
        }
        fn inspect(
            &self,
            _ctx: &PostInvocationContext<'_>,
            _resp: &Value,
        ) -> PostInvocationVerdict {
            PostInvocationVerdict::Redact(serde_json::json!({"redacted": true}))
        }
    }

    struct EscalateHook(String);
    impl PostInvocationHook for EscalateHook {
        fn name(&self) -> &str {
            "escalate"
        }
        fn inspect(
            &self,
            _ctx: &PostInvocationContext<'_>,
            _resp: &Value,
        ) -> PostInvocationVerdict {
            PostInvocationVerdict::Escalate(self.0.clone())
        }
    }

    #[test]
    fn empty_pipeline_allows() {
        let pipeline = PostInvocationPipeline::new();
        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Allow));
        assert!(escalations.is_empty());
    }

    #[test]
    fn all_allow_passes() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(AllowHook));
        pipeline.add(Box::new(AllowHook));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Allow));
    }

    #[test]
    fn block_stops_pipeline() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(AllowHook));
        pipeline.add(Box::new(BlockHook("blocked".to_string())));
        pipeline.add(Box::new(AllowHook));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Block(_)));
    }

    #[test]
    fn redact_modifies_response() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(RedactHook));

        let response = serde_json::json!({"data": "sensitive"});
        let (verdict, _) = pipeline.evaluate("tool", &response);
        match verdict {
            PostInvocationVerdict::Redact(v) => {
                assert_eq!(v, serde_json::json!({"redacted": true}));
            }
            other => panic!("expected Redact, got {other:?}"),
        }
    }

    #[test]
    fn escalations_collected() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(EscalateHook("warning 1".to_string())));
        pipeline.add(Box::new(EscalateHook("warning 2".to_string())));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Escalate(_)));
        assert_eq!(escalations.len(), 2);
    }

    #[test]
    fn block_after_escalation_returns_block_with_escalations() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(EscalateHook("noticed something".to_string())));
        pipeline.add(Box::new(BlockHook("critical".to_string())));

        let response = serde_json::json!({"data": "hello"});
        let (verdict, escalations) = pipeline.evaluate("tool", &response);
        assert!(matches!(verdict, PostInvocationVerdict::Block(_)));
        assert_eq!(escalations.len(), 1);
    }

    #[test]
    fn len_and_is_empty() {
        let mut pipeline = PostInvocationPipeline::new();
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
        pipeline.add(Box::new(AllowHook));
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn sanitizer_hook_allows_clean_response() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(SanitizerHook::new()));

        let response = serde_json::json!({"ok": true, "message": "nothing to see"});
        let outcome = pipeline.evaluate_with_evidence("tool", &response);
        assert!(matches!(outcome.verdict, PostInvocationVerdict::Allow));
        assert!(outcome.evidence.is_empty());
    }

    #[test]
    fn sanitizer_hook_redacts_and_emits_evidence() {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(SanitizerHook::new()));

        let key = format!("ghp_{}", "a".repeat(36));
        let response = serde_json::json!({"token": key});
        let outcome = pipeline.evaluate_with_evidence("tool", &response);

        match &outcome.verdict {
            PostInvocationVerdict::Redact(v) => {
                let rendered = v.to_string();
                assert!(!rendered.contains(&key));
            }
            other => panic!("expected Redact, got {other:?}"),
        }
        assert_eq!(outcome.evidence.len(), 1);
        let ev = &outcome.evidence[0];
        assert_eq!(ev.guard_name, "output-sanitizer");
        assert!(ev.verdict, "verdict field marks successful redaction");
        let details = ev.details.as_deref().unwrap_or("");
        assert!(details.contains("secret_github_token"), "got {details}");
    }

    #[test]
    fn sanitizer_tokenization_has_no_durable_identity() {
        let mut config = OutputSanitizerConfig::default();
        config.redaction_strategies.insert(
            crate::response_sanitization::SensitiveCategory::Pii,
            crate::response_sanitization::RedactionStrategy::Tokenize,
        );
        let sanitizer = OutputSanitizer::with_config(config).expect("tokenizing sanitizer");
        let hook = SanitizerHook::from_sanitizer(sanitizer);

        let error = hook
            .durable_identity()
            .expect_err("counter-backed tokenization must not be durable");
        assert!(error.contains("tokenize redaction strategy is not deterministic"));
    }
}
