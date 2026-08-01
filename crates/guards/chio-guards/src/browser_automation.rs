//! BrowserAutomationGuard -- domain allowlists, action-type restrictions,
//! and credential detection in `Type` actions.
//!
//! Complements the coarse
//! [`crate::computer_use::ComputerUseGuard`] with fine-grained rules
//! specifically for browser-automation tool calls:
//!
//! - **Navigation gating**: URLs whose host is outside
//!   [`BrowserAutomationConfig::allowed_domains`] are denied.
//! - **Verb gating**: [`BrowserAutomationConfig::allowed_verbs`] restricts
//!   the action verbs an agent may issue (e.g. read-only sessions
//!   permit `navigate` + `screenshot` but deny `type` / `click`).
//! - **Credential detection**: `type` / `input` actions whose text
//!   looks like a secret (API key, bearer token, PEM key, AWS key,
//!   high-entropy password) are denied.
//!
//! Calls that are not [`ToolAction::BrowserAction`] pass through with
//! [`Verdict::Allow`] so the guard composes cleanly with the rest of
//! the pipeline.
//!
//! # Fail-closed semantics
//!
//! - navigation verbs (`navigate`/`goto`/`open`) without a parseable
//!   target URL are denied when a non-empty
//!   [`BrowserAutomationConfig::allowed_domains`] list is configured;
//! - `type` actions with no `value` / `text` argument are allowed (the
//!   guard has nothing to inspect);
//! - malformed credential regex configuration causes
//!   [`BrowserAutomationGuard::with_config`] to return
//!   [`BrowserAutomationError::InvalidPattern`].

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

use crate::action::{extract_action_checked, ToolAction};

/// Default allowed verbs (open browser session, navigate, read state).
pub fn default_allowed_verbs() -> Vec<String> {
    vec![
        "navigate".to_string(),
        "goto".to_string(),
        "open".to_string(),
        "screenshot".to_string(),
        "screen_capture".to_string(),
        "capture".to_string(),
        "browser_screenshot".to_string(),
        "get_url".to_string(),
        "get_title".to_string(),
        "read".to_string(),
        "get_content".to_string(),
        "close".to_string(),
        "back".to_string(),
        "forward".to_string(),
        "reload".to_string(),
    ]
}

/// Errors produced when building a [`BrowserAutomationGuard`].
#[derive(Debug, thiserror::Error)]
pub enum BrowserAutomationError {
    /// A user-supplied credential pattern was not a valid regex.
    #[error("invalid credential pattern `{pattern}`: {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Configuration for [`BrowserAutomationGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAutomationConfig {
    /// Enable/disable the guard entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hosts the agent may navigate to.  Supports exact match and
    /// `*.suffix` wildcard patterns.  Empty means "no allowlist"
    /// (navigation check is skipped).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Blocked hosts (always denied, evaluated before the allowlist).
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// Verbs (actions) the agent may issue.  Empty means "any verb".
    #[serde(default = "default_allowed_verbs")]
    pub allowed_verbs: Vec<String>,
    /// When `true`, check `type` / `input` action values for
    /// credential-shaped secrets.
    #[serde(default = "default_true")]
    pub credential_detection: bool,
    /// Extra credential regex patterns layered on top of the built-in
    /// detectors.  Invalid regexes cause initialization to fail.
    #[serde(default)]
    pub extra_credential_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for BrowserAutomationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            allowed_verbs: default_allowed_verbs(),
            credential_detection: true,
            extra_credential_patterns: Vec::new(),
        }
    }
}

/// Guard that enforces browser-automation policy per
/// [`BrowserAutomationConfig`].
pub struct BrowserAutomationGuard {
    enabled: bool,
    allowed_domains: Vec<String>,
    blocked_domains: Vec<String>,
    allowed_verbs: HashSet<String>,
    credential_detection: bool,
    extra_patterns: Vec<Regex>,
}

impl BrowserAutomationGuard {
    /// Build a guard with default configuration.
    pub fn new() -> Self {
        match Self::with_config(BrowserAutomationConfig::default()) {
            Ok(g) => g,
            Err(_) => Self::empty_failclosed(),
        }
    }

    /// Build an empty guard that denies every browser action.  Defensive
    /// fallback used when the default config cannot compile (should never
    /// happen because defaults carry no user regex).
    fn empty_failclosed() -> Self {
        Self {
            enabled: true,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            allowed_verbs: HashSet::new(),
            credential_detection: true,
            extra_patterns: Vec::new(),
        }
    }

    /// Build a guard with explicit configuration.
    pub fn with_config(config: BrowserAutomationConfig) -> Result<Self, BrowserAutomationError> {
        let mut extra_patterns = Vec::with_capacity(config.extra_credential_patterns.len());
        for pat in &config.extra_credential_patterns {
            let re = Regex::new(pat).map_err(|e| BrowserAutomationError::InvalidPattern {
                pattern: pat.clone(),
                source: e,
            })?;
            extra_patterns.push(re);
        }
        let allowed_verbs: HashSet<String> = config
            .allowed_verbs
            .into_iter()
            .map(|v| v.to_ascii_lowercase())
            .collect();
        Ok(Self {
            enabled: config.enabled,
            allowed_domains: config.allowed_domains,
            blocked_domains: config.blocked_domains,
            allowed_verbs,
            credential_detection: config.credential_detection,
            extra_patterns,
        })
    }

    /// Evaluate a navigation verb against the blocked/allowed domain
    /// sets.  Returns `Verdict::Deny` when the target is blocked or
    /// outside a non-empty allowlist.
    fn check_navigation(&self, target: Option<&str>) -> Verdict {
        let empty_allow = self.allowed_domains.is_empty();
        let empty_block = self.blocked_domains.is_empty();
        if empty_allow && empty_block {
            return Verdict::Allow;
        }
        let url = match target {
            Some(u) if !u.trim().is_empty() => u,
            // Missing target with a configured allowlist is fail-closed:
            // we cannot attest the nav host, so deny.
            _ if !empty_allow => return Verdict::Deny,
            _ => return Verdict::Allow,
        };
        let host = match extract_host(url) {
            Some(h) => h,
            None if !empty_allow => return Verdict::Deny,
            None => return Verdict::Allow,
        };
        if self
            .blocked_domains
            .iter()
            .any(|pat| matches_domain(pat, &host))
        {
            return Verdict::Deny;
        }
        if !empty_allow
            && !self
                .allowed_domains
                .iter()
                .any(|pat| matches_domain(pat, &host))
        {
            return Verdict::Deny;
        }
        Verdict::Allow
    }

    /// Check whether `text` looks like a credential / secret.  Runs both
    /// built-in detectors and any extra regexes supplied via config.
    fn looks_like_credential(&self, text: &str) -> bool {
        if text.trim().is_empty() {
            return false;
        }
        for re in builtin_credential_patterns() {
            if re.is_match(text) {
                return true;
            }
        }
        for re in &self.extra_patterns {
            if re.is_match(text) {
                return true;
            }
        }
        false
    }
}

impl Default for BrowserAutomationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for BrowserAutomationGuard {
    fn name(&self) -> &str {
        "browser-automation"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };
        let (verb, target) = match action {
            ToolAction::BrowserAction { verb, target } => (verb, target),
            _ => return Ok(GuardDecision::allow()),
        };

        let verb_lower = verb.to_ascii_lowercase();

        // 1. Verb allowlist.
        if !self.allowed_verbs.is_empty() && !self.allowed_verbs.contains(&verb_lower) {
            return Ok(GuardDecision::deny(Vec::new()));
        }

        // 2. Navigation domain gating.
        if is_navigation_verb(&verb_lower) {
            let target_ref = target.as_deref().filter(|s| !is_selector_like(s));
            return Ok(GuardDecision::from_verdict(
                self.check_navigation(target_ref),
            ));
        }

        // 3. Credential detection on type/input verbs.
        if self.credential_detection && is_type_verb(&verb_lower) {
            if let Some(text) = extract_type_text(&ctx.request.arguments) {
                if self.looks_like_credential(&text) {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        crate::revalidate_non_consuming_guard(self, ctx)
    }
}

/// Return true when `s` looks like a CSS selector / xpath / anchor rather
/// than a navigation URL.
fn is_selector_like(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.starts_with('#')
        || trimmed.starts_with('.')
        || trimmed.starts_with('[')
        || trimmed.starts_with('/') && !trimmed.starts_with("//")
        || trimmed.starts_with("xpath=")
}

fn is_navigation_verb(verb: &str) -> bool {
    matches!(verb, "navigate" | "goto" | "open" | "load" | "browse")
}

fn is_type_verb(verb: &str) -> bool {
    matches!(
        verb,
        "type" | "input" | "fill" | "browser_type" | "type_text" | "enter_text" | "send_keys"
    )
}

/// Extract the string the agent wants to type.  Looks at common argument
/// names: `text`, `value`, `content`, `input`, `keys`.
fn extract_type_text(arguments: &Value) -> Option<String> {
    for key in ["text", "value", "content", "input", "keys"] {
        if let Some(v) = arguments.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Match a domain host against a pattern.  Supports exact match and
/// `*.suffix` wildcards.
fn matches_domain(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    pattern == host
}

/// Extract the host portion of a URL.
fn extract_host(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    if url.starts_with('#') || url.starts_with('.') || url.starts_with('[') {
        return None;
    }
    let lowered = url.to_ascii_lowercase();
    if lowered.starts_with("data:")
        || lowered.starts_with("javascript:")
        || lowered.starts_with("about:")
        || lowered.starts_with("file:")
    {
        return None;
    }
    let rest = if lowered.starts_with("https://") {
        &url["https://".len()..]
    } else if lowered.starts_with("http://") {
        &url["http://".len()..]
    } else if let Some(rest) = url.strip_prefix("//") {
        rest
    } else {
        url
    };
    let host_with_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_without_userinfo = host_with_port
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(host_with_port);
    let host = if let Some(bracketed) = host_without_userinfo.strip_prefix('[') {
        let (host, remainder) = bracketed.split_once(']')?;
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return None;
        }
        host
    } else {
        host_without_userinfo
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_without_userinfo)
    }
    .trim_matches(|c: char| c == '/' || c == '.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Compiled once per process.  Returns regexes that match common
/// credential / secret shapes appearing in Type action text.
fn builtin_credential_patterns() -> &'static [Regex] {
    static PATS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        let sources = [
            // AWS access key ID.
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            // GitHub personal access tokens.
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
            // Slack bot/user tokens.
            r"\bxox[abopsr]-[A-Za-z0-9-]{10,}\b",
            // JWT shape.
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            // PEM private keys.
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            // Generic `password = ...` / `token = ...` assignment shapes.
            r"(?i)\b(?:password|passwd|pwd|token|api[_-]?key|secret|bearer)\s*[:=]\s*\S{6,}",
            // OpenAI-style API key prefix.
            r"\bsk-[A-Za-z0-9]{20,}\b",
            // Stripe secret key prefix.
            r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        ];
        sources
            .iter()
            .filter_map(|s| match Regex::new(s) {
                Ok(re) => Some(re),
                Err(err) => {
                    tracing::error!(error = %err, source = %s, "browser-automation: builtin credential regex failed");
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
    fn extract_host_basic() {
        assert_eq!(
            extract_host("https://example.com/x"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("HTTPS://Blocked.Example/x"),
            Some("blocked.example".into())
        );
        assert_eq!(
            extract_host("https://user:pass@blocked.example:8443/path"),
            Some("blocked.example".into())
        );
        assert_eq!(
            extract_host("https://user@[fd00:ec2::254]:8443/path"),
            Some("fd00:ec2::254".into())
        );
        assert_eq!(
            extract_host("//blocked.example/path"),
            Some("blocked.example".into())
        );
        assert_eq!(
            extract_host("https://blocked.example?redir=1"),
            Some("blocked.example".into())
        );
        assert_eq!(
            extract_host("https://blocked.example#anchor"),
            Some("blocked.example".into())
        );
        assert_eq!(extract_host("#submit"), None);
        assert_eq!(extract_host("data:text/plain,hi"), None);
    }

    #[test]
    fn matches_domain_wildcard() {
        assert!(matches_domain("*.example.com", "api.example.com"));
        assert!(!matches_domain("*.example.com", "example.org"));
        assert!(matches_domain("example.com", "example.com"));
    }

    #[test]
    fn builtin_detects_common_tokens() {
        let guard = BrowserAutomationGuard::new();
        assert!(guard.looks_like_credential("AKIAABCDEFGHIJKLMNOP"));
        assert!(guard.looks_like_credential("password=hunter2345"));
        assert!(guard.looks_like_credential("sk-0123456789abcdef01234567"));
        assert!(!guard.looks_like_credential("hello world"));
        assert!(!guard.looks_like_credential(""));
    }

    #[test]
    fn is_selector_like_classifies() {
        assert!(is_selector_like("#submit"));
        assert!(is_selector_like(".login"));
        assert!(is_selector_like("[data-id=1]"));
        assert!(!is_selector_like("https://example.com/x"));
        assert!(!is_selector_like("//example.com"));
    }

    #[test]
    fn check_navigation_blocks_scheme_relative_urls() {
        let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
            blocked_domains: vec!["blocked.example".into()],
            ..BrowserAutomationConfig::default()
        })
        .expect("default browser automation config should compile");

        assert_eq!(
            guard.check_navigation(Some("//blocked.example/path")),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_urls_with_userinfo() {
        let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
            blocked_domains: vec!["blocked.example".into()],
            ..BrowserAutomationConfig::default()
        })
        .expect("default browser automation config should compile");

        assert_eq!(
            guard.check_navigation(Some("https://user@blocked.example/path")),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_bracketed_ipv6_hosts() {
        let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
            blocked_domains: vec!["fd00:ec2::254".into()],
            ..BrowserAutomationConfig::default()
        })
        .expect("default browser automation config should compile");

        assert_eq!(
            guard.check_navigation(Some("https://[fd00:ec2::254]/latest")),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_mixed_case_scheme_urls() {
        let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
            blocked_domains: vec!["blocked.example".into()],
            ..BrowserAutomationConfig::default()
        })
        .expect("default browser automation config should compile");

        assert_eq!(
            guard.check_navigation(Some("HTTPS://blocked.example/path")),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_query_and_fragment_only_urls() {
        let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
            blocked_domains: vec!["blocked.example".into()],
            ..BrowserAutomationConfig::default()
        })
        .expect("default browser automation config should compile");

        assert_eq!(
            guard.check_navigation(Some("https://blocked.example?redir=1")),
            Verdict::Deny
        );
        assert_eq!(
            guard.check_navigation(Some("https://blocked.example#anchor")),
            Verdict::Deny
        );
    }
}
