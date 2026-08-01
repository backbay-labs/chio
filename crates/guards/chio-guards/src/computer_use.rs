//! ComputerUseGuard - coarse gate for Computer Use Agent (CUA) actions.
//!
//! Implements Chio's synchronous [`chio_kernel::Guard`] trait.
//!
//! The guard is a coarse-grained allowlist for CUA action types.  It
//! recognises three surfaces that arrive on the kernel:
//!
//! 1. **Remote-session and side-channel actions** - tool names or
//!    `action_type`/`custom_type` arguments that start with `remote.` or
//!    `input.` (e.g., `remote.clipboard`, `input.inject`).  The action-type
//!    string is matched against a configurable allowlist.
//! 2. **[`ToolAction::BrowserAction`]** - browser navigation verbs.  The
//!    guard denies navigation to configured blocked domains.
//! 3. **Screenshot actions** (subset of [`ToolAction::BrowserAction`] with
//!    a `screenshot`-family verb) - rate-limited via a token bucket so a
//!    runaway agent cannot drain the capture channel.
//!
//! Enforcement modes:
//!
//! | Mode         | Behavior                                              |
//! |--------------|-------------------------------------------------------|
//! | [`EnforcementMode::Observe`]     | Always allow; logs every decision |
//! | [`EnforcementMode::Guardrail`]   | Allow if in allowlist, warn otherwise (default) |
//! | [`EnforcementMode::FailClosed`]  | Allow if in allowlist, deny otherwise |
//!
//! Fail-closed semantics:
//!
//! - [`ToolAction::Unknown`] / non-CUA actions → [`Verdict::Allow`];
//! - invalid configuration → best-effort fallback to defaults at build
//!   time (never panics);
//! - token-bucket mutex poisoning → treated as no-tokens (deny).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

use crate::action::{extract_action_checked, ToolAction};
use crate::external::TokenBucket;

/// Default allowlist of CUA action-type strings.
///
/// Covers the common remote-session and input action taxonomy so existing
/// policies continue to work without translation.
pub fn default_allowed_action_types() -> Vec<String> {
    vec![
        "remote.session.connect".to_string(),
        "remote.session.disconnect".to_string(),
        "remote.session.reconnect".to_string(),
        "input.inject".to_string(),
        "remote.clipboard".to_string(),
        "remote.file_transfer".to_string(),
        "remote.audio".to_string(),
        "remote.drive_mapping".to_string(),
        "remote.printing".to_string(),
        "remote.session_share".to_string(),
    ]
}

/// Enforcement modes for [`ComputerUseGuard`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Always allow, regardless of allowlist membership.
    Observe,
    /// Allow if in allowlist; allow-with-warning otherwise.
    #[default]
    Guardrail,
    /// Allow if in allowlist; deny otherwise (fail-closed).
    FailClosed,
}

/// Configuration for [`ComputerUseGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerUseConfig {
    /// Enable/disable the guard.  When `false`, [`Guard::evaluate`] always
    /// returns `Allow`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allowed CUA action-type strings (for `remote.*` / `input.*` flows).
    #[serde(default = "default_allowed_action_types")]
    pub allowed_action_types: Vec<String>,
    /// Enforcement mode.
    #[serde(default)]
    pub mode: EnforcementMode,
    /// Domain patterns (exact host match or `*.suffix` wildcard) that are
    /// blocked for browser navigation.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// Optional allowlist of navigation hosts.  When non-empty, navigation
    /// to a host outside the allowlist is treated the same as a blocked
    /// domain in `FailClosed` mode, warned in `Guardrail`, ignored in
    /// `Observe`.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Maximum screenshots per second (token-bucket refill rate).  `None`
    /// disables rate limiting.
    #[serde(default)]
    pub screenshot_rate_per_second: Option<f64>,
    /// Token-bucket burst capacity for screenshot rate limiting.  Defaults
    /// to `5` when [`Self::screenshot_rate_per_second`] is set.
    #[serde(default)]
    pub screenshot_burst: Option<u32>,
}

fn default_true() -> bool {
    true
}

impl Default for ComputerUseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_action_types: default_allowed_action_types(),
            mode: EnforcementMode::Guardrail,
            blocked_domains: Vec::new(),
            allowed_domains: Vec::new(),
            screenshot_rate_per_second: None,
            screenshot_burst: None,
        }
    }
}

/// Coarse gate for CUA actions.
///
/// See [module docs](self) for the policy surface.
pub struct ComputerUseGuard {
    enabled: bool,
    mode: EnforcementMode,
    allowed_actions: HashSet<String>,
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
    screenshot_bucket: Option<TokenBucket>,
}

impl ComputerUseGuard {
    /// Build a guard with default configuration.
    pub fn new() -> Self {
        Self::with_config(ComputerUseConfig::default())
    }

    /// Build a guard with an explicit configuration.
    pub fn with_config(config: ComputerUseConfig) -> Self {
        let allowed_actions: HashSet<String> = config.allowed_action_types.into_iter().collect();
        let screenshot_bucket = match config.screenshot_rate_per_second {
            Some(rate) if rate > 0.0 && rate.is_finite() => {
                let burst = config.screenshot_burst.unwrap_or(5).max(1);
                Some(TokenBucket::new(rate, burst))
            }
            _ => None,
        };
        Self {
            enabled: config.enabled,
            mode: config.mode,
            allowed_actions,
            blocked_domains: config.blocked_domains,
            allowed_domains: config.allowed_domains,
            screenshot_bucket,
        }
    }

    /// Returns `true` if the verb indicates a screenshot/screen-capture
    /// browser action.
    fn is_screenshot_verb(verb: &str) -> bool {
        let v = verb.to_ascii_lowercase();
        matches!(
            v.as_str(),
            "screenshot"
                | "screen_capture"
                | "screen_shot"
                | "capture"
                | "capture_screen"
                | "browser_screenshot"
        )
    }

    /// Extract the CUA `action_type` string from a tool call, if any.
    ///
    /// Checks (in priority order):
    /// 1. `tool_name` itself if it starts with `remote.` or `input.`;
    /// 2. the `action_type` / `actionType` argument;
    /// 3. the `custom_type` / `customType` argument.
    fn extract_cua_action_type<'a>(
        tool_name: &'a str,
        arguments: &'a serde_json::Value,
    ) -> Option<String> {
        if tool_name.starts_with("remote.") || tool_name.starts_with("input.") {
            return Some(tool_name.to_string());
        }
        for key in ["action_type", "actionType", "custom_type", "customType"] {
            if let Some(value) = arguments.get(key).and_then(|v| v.as_str()) {
                if value.starts_with("remote.") || value.starts_with("input.") {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    /// Apply the configured enforcement mode to an allowlist decision.
    fn apply_mode(&self, in_allowlist: bool) -> Verdict {
        match (self.mode, in_allowlist) {
            (EnforcementMode::Observe, _) => Verdict::Allow,
            (EnforcementMode::Guardrail, _) => Verdict::Allow,
            (EnforcementMode::FailClosed, true) => Verdict::Allow,
            (EnforcementMode::FailClosed, false) => Verdict::Deny,
        }
    }

    /// Check browser navigation against the blocked/allowed domain sets.
    fn check_navigation(&self, target: &str) -> Verdict {
        // Only apply navigation gating when either list has content; the
        // module docs call this out as opt-in.
        if self.blocked_domains.is_empty() && self.allowed_domains.is_empty() {
            return Verdict::Allow;
        }
        let host = match extract_host(target) {
            Some(host) => host,
            None => {
                // Opaque navigation targets (selectors, data URIs) are
                // allowed here - finer checks belong to
                // `BrowserNavigationGuard`.
                return Verdict::Allow;
            }
        };
        let blocked = self
            .blocked_domains
            .iter()
            .any(|pat| matches_domain(pat, &host));
        if blocked {
            return match self.mode {
                EnforcementMode::Observe => Verdict::Allow,
                EnforcementMode::Guardrail | EnforcementMode::FailClosed => Verdict::Deny,
            };
        }
        if !self.allowed_domains.is_empty() {
            let allowed = self
                .allowed_domains
                .iter()
                .any(|pat| matches_domain(pat, &host));
            if !allowed {
                return match self.mode {
                    EnforcementMode::Observe | EnforcementMode::Guardrail => Verdict::Allow,
                    EnforcementMode::FailClosed => Verdict::Deny,
                };
            }
        }
        Verdict::Allow
    }
}

impl Default for ComputerUseGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for ComputerUseGuard {
    fn name(&self) -> &str {
        "computer-use"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        // 1. Direct CUA action-type dispatch (remote.*, input.*).
        if let Some(action_type) =
            Self::extract_cua_action_type(&ctx.request.tool_name, &ctx.request.arguments)
        {
            let in_allowlist = self.allowed_actions.contains(&action_type);
            return Ok(GuardDecision::from_verdict(self.apply_mode(in_allowlist)));
        }

        // 2. BrowserAction: navigation domain checks + screenshot rate limit.
        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };
        if let ToolAction::BrowserAction { verb, target } = &action {
            // Screenshot rate-limit.
            if Self::is_screenshot_verb(verb) {
                if let Some(bucket) = &self.screenshot_bucket {
                    if !bucket.try_acquire() {
                        return Ok(GuardDecision::from_verdict(match self.mode {
                            EnforcementMode::Observe => Verdict::Allow,
                            EnforcementMode::Guardrail | EnforcementMode::FailClosed => {
                                Verdict::Deny
                            }
                        }));
                    }
                }
                return Ok(GuardDecision::allow());
            }

            // Navigation domain check.
            if matches!(
                verb.to_ascii_lowercase().as_str(),
                "navigate" | "goto" | "open"
            ) {
                if let Some(url) = target {
                    return Ok(GuardDecision::from_verdict(self.check_navigation(url)));
                }
            }
        }

        // 3. Non-CUA actions pass through.
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext) -> Result<(), KernelError> {
        Ok(())
    }
}

/// Match a domain host against a pattern.  Supports exact match and
/// `*.suffix` wildcard patterns (same semantics as Chio's egress allowlist).
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

/// Extract the host portion of a URL.  Returns `None` for opaque targets
/// like CSS selectors, data URIs, or empty strings.
fn extract_host(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    // Reject obvious non-URL targets used by browser click/type actions.
    if url.starts_with('#') || url.starts_with('.') || url.starts_with('[') {
        return None;
    }
    // Reject data / javascript / about URIs - no network host.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_domain_exact_and_wildcard() {
        assert!(matches_domain("example.com", "example.com"));
        assert!(!matches_domain("example.com", "evil.com"));
        assert!(matches_domain("*.example.com", "api.example.com"));
        assert!(matches_domain("*.example.com", "example.com"));
        assert!(!matches_domain("*.example.com", "example.org"));
    }

    #[test]
    fn extract_host_handles_common_urls() {
        assert_eq!(
            extract_host("https://example.com/x"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("HTTPS://169.254.169.254/latest"),
            Some("169.254.169.254".into())
        );
        assert_eq!(
            extract_host("https://user:pass@example.com:8443/x"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("https://user@[fd00:ec2::254]:8443/x"),
            Some("fd00:ec2::254".into())
        );
        assert_eq!(
            extract_host("http://localhost:8080"),
            Some("localhost".into())
        );
        assert_eq!(
            extract_host("example.com:443/y"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_host("//169.254.169.254/latest"),
            Some("169.254.169.254".into())
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
    fn check_navigation_blocks_scheme_relative_urls() {
        let guard = ComputerUseGuard::with_config(ComputerUseConfig {
            mode: EnforcementMode::FailClosed,
            blocked_domains: vec!["169.254.169.254".into()],
            ..ComputerUseConfig::default()
        });

        assert_eq!(
            guard.check_navigation("//169.254.169.254/latest"),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_urls_with_userinfo() {
        let guard = ComputerUseGuard::with_config(ComputerUseConfig {
            mode: EnforcementMode::FailClosed,
            blocked_domains: vec!["blocked.example".into()],
            ..ComputerUseConfig::default()
        });

        assert_eq!(
            guard.check_navigation("https://user@blocked.example/path"),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_bracketed_ipv6_hosts() {
        let guard = ComputerUseGuard::with_config(ComputerUseConfig {
            mode: EnforcementMode::FailClosed,
            blocked_domains: vec!["fd00:ec2::254".into()],
            ..ComputerUseConfig::default()
        });

        assert_eq!(
            guard.check_navigation("https://[fd00:ec2::254]/latest"),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_query_and_fragment_only_urls() {
        let guard = ComputerUseGuard::with_config(ComputerUseConfig {
            mode: EnforcementMode::FailClosed,
            blocked_domains: vec!["blocked.example".into()],
            ..ComputerUseConfig::default()
        });

        assert_eq!(
            guard.check_navigation("https://blocked.example?redir=1"),
            Verdict::Deny
        );
        assert_eq!(
            guard.check_navigation("https://blocked.example#anchor"),
            Verdict::Deny
        );
    }

    #[test]
    fn check_navigation_blocks_mixed_case_scheme_urls() {
        let guard = ComputerUseGuard::with_config(ComputerUseConfig {
            mode: EnforcementMode::FailClosed,
            blocked_domains: vec!["169.254.169.254".into()],
            ..ComputerUseConfig::default()
        });

        assert_eq!(
            guard.check_navigation("HTTPS://169.254.169.254/latest"),
            Verdict::Deny
        );
    }

    #[test]
    fn is_screenshot_verb_matches_common_names() {
        assert!(ComputerUseGuard::is_screenshot_verb("screenshot"));
        assert!(ComputerUseGuard::is_screenshot_verb("capture_screen"));
        assert!(!ComputerUseGuard::is_screenshot_verb("click"));
    }

    #[test]
    fn extract_cua_action_type_reads_args() {
        let args = serde_json::json!({"action_type": "remote.clipboard"});
        assert_eq!(
            ComputerUseGuard::extract_cua_action_type("unknown", &args),
            Some("remote.clipboard".to_string())
        );
    }
}
