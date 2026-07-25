//! Patch integrity guard -- validates patch/diff safety.
//!
//! Checks for:
//! - Maximum additions/deletions thresholds
//! - Forbidden patterns in added lines (security disablement, backdoors, etc.)
//! - Optional addition/deletion imbalance checks

use regex::Regex;

use std::sync::OnceLock;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Errors produced when building a [`PatchIntegrityGuard`].
#[derive(Debug, thiserror::Error)]
pub enum PatchIntegrityConfigError {
    /// A forbidden pattern was not a valid regex.
    #[error("invalid patch integrity forbidden pattern `{pattern}`: {source}")]
    InvalidForbiddenPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Configuration for `PatchIntegrityGuard`.
#[derive(Clone)]
pub struct PatchIntegrityConfig {
    /// Enable/disable this guard.
    pub enabled: bool,
    /// Maximum lines added in a single patch.
    pub max_additions: usize,
    /// Maximum lines deleted in a single patch.
    pub max_deletions: usize,
    /// Patterns that are forbidden in added patch lines.
    pub forbidden_patterns: Vec<String>,
    /// Require patches to have balanced additions/deletions.
    pub require_balance: bool,
    /// Maximum imbalance ratio (additions / deletions).
    pub max_imbalance_ratio: f64,
}

fn default_forbidden_patterns() -> Vec<String> {
    vec![
        // Disable security features
        r"(?i)disable[ _\-]?(security|auth|ssl|tls)".to_string(),
        r"(?i)skip[ _\-]?(verify|validation|check)".to_string(),
        // Dangerous operations
        r"(?i)rm\s+-rf\s+/".to_string(),
        r"(?i)chmod\s+777".to_string(),
        r"(?i)eval\s*\(".to_string(),
        r"(?i)exec\s*\(".to_string(),
        // Backdoor indicators
        r"(?i)reverse[_\-]?shell".to_string(),
        r"(?i)bind[_\-]?shell".to_string(),
        r"base64[_\-]?decode.*exec".to_string(),
    ]
}

impl Default for PatchIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_additions: 1000,
            max_deletions: 500,
            forbidden_patterns: default_forbidden_patterns(),
            require_balance: false,
            max_imbalance_ratio: 10.0,
        }
    }
}

/// A forbidden pattern match found in a patch.
#[derive(Clone, Debug)]
pub struct ForbiddenMatch {
    pub line: String,
    pub pattern: String,
}

/// Analysis result for a patch.
#[derive(Clone, Debug)]
pub struct PatchAnalysis {
    pub additions: usize,
    pub deletions: usize,
    pub imbalance_ratio: f64,
    pub forbidden_matches: Vec<ForbiddenMatch>,
    pub exceeds_max_additions: bool,
    pub exceeds_max_deletions: bool,
    pub exceeds_imbalance: bool,
}

impl PatchAnalysis {
    /// Returns true when the patch passes all safety checks.
    pub fn is_safe(&self) -> bool {
        self.forbidden_matches.is_empty()
            && !self.exceeds_max_additions
            && !self.exceeds_max_deletions
            && !self.exceeds_imbalance
    }
}

/// Guard that validates the safety of applied patches/diffs.
#[derive(Clone)]
pub struct PatchIntegrityGuard {
    enabled: bool,
    config: PatchIntegrityConfig,
    forbidden_regexes: Vec<Regex>,
}

impl PatchIntegrityGuard {
    fn build_default_or_fail_closed() -> Self {
        Self::with_config(PatchIntegrityConfig::default()).unwrap_or_else(|_| Self {
            enabled: true,
            config: PatchIntegrityConfig::default(),
            forbidden_regexes: vec![],
        })
    }

    pub fn new() -> Self {
        static DEFAULT: OnceLock<PatchIntegrityGuard> = OnceLock::new();
        DEFAULT
            .get_or_init(Self::build_default_or_fail_closed)
            .clone()
    }

    pub fn with_config(config: PatchIntegrityConfig) -> Result<Self, PatchIntegrityConfigError> {
        let enabled = config.enabled;
        let forbidden_regexes = config
            .forbidden_patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern).map_err(|source| {
                    PatchIntegrityConfigError::InvalidForbiddenPattern {
                        pattern: pattern.clone(),
                        source,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            enabled,
            config,
            forbidden_regexes,
        })
    }

    /// Analyze a unified diff and return a `PatchAnalysis`.
    pub fn analyze(&self, diff: &str) -> PatchAnalysis {
        let mut additions = 0;
        let mut deletions = 0;
        let mut forbidden_matches = Vec::new();

        for line in diff.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                additions += 1;

                // Check added lines for forbidden patterns.
                for (idx, regex) in self.forbidden_regexes.iter().enumerate() {
                    if regex.is_match(line) {
                        forbidden_matches.push(ForbiddenMatch {
                            line: line.to_string(),
                            pattern: self.config.forbidden_patterns[idx].clone(),
                        });
                    }
                }
            } else if line.starts_with('-') && !line.starts_with("---") {
                deletions += 1;
            }
        }

        let imbalance_ratio = if deletions > 0 {
            additions as f64 / deletions as f64
        } else if additions > 0 {
            f64::INFINITY
        } else {
            1.0
        };

        PatchAnalysis {
            additions,
            deletions,
            imbalance_ratio,
            forbidden_matches,
            exceeds_max_additions: additions > self.config.max_additions,
            exceeds_max_deletions: deletions > self.config.max_deletions,
            exceeds_imbalance: self.config.require_balance
                && imbalance_ratio > self.config.max_imbalance_ratio,
        }
    }
}

impl Default for PatchIntegrityGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for PatchIntegrityGuard {
    fn name(&self) -> &str {
        "patch-integrity"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let diff = match &action {
            ToolAction::Patch(_, diff) => diff.as_str(),
            _ => return Ok(GuardDecision::allow()),
        };

        let analysis = self.analyze(diff);

        if analysis.is_safe() {
            Ok(GuardDecision::allow())
        } else {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::Guard;

    #[test]
    fn safe_patch_is_allowed() {
        let guard = PatchIntegrityGuard::new();

        let diff = "\
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,4 @@
 unchanged
+added line 1
+added line 2
-deleted line";

        let analysis = guard.analyze(diff);
        assert_eq!(analysis.additions, 2);
        assert_eq!(analysis.deletions, 1);
        assert!(analysis.is_safe());
    }

    #[test]
    fn forbidden_pattern_blocks() {
        let guard = PatchIntegrityGuard::new();

        let diff = "\
+disable_security = True
+disable security = True
+rm -rf /";

        let analysis = guard.analyze(diff);
        assert!(!analysis.forbidden_matches.is_empty());
        assert!(analysis
            .forbidden_matches
            .iter()
            .any(|m| m.line.contains("disable security")));
        assert!(!analysis.is_safe());
    }

    #[test]
    fn eval_blocks_patch_with_eval() {
        let guard = PatchIntegrityGuard::new();

        let diff = "+eval(user_input)";
        let analysis = guard.analyze(diff);
        assert!(!analysis.is_safe());
    }

    #[test]
    fn max_additions_exceeded() {
        let config = PatchIntegrityConfig {
            max_additions: 5,
            ..Default::default()
        };
        let guard = PatchIntegrityGuard::with_config(config).expect("valid patch integrity config");

        let diff = "+line1\n+line2\n+line3\n+line4\n+line5\n+line6";
        let analysis = guard.analyze(diff);
        assert!(analysis.exceeds_max_additions);
        assert!(!analysis.is_safe());
    }

    #[test]
    fn max_deletions_exceeded() {
        let config = PatchIntegrityConfig {
            max_deletions: 2,
            ..Default::default()
        };
        let guard = PatchIntegrityGuard::with_config(config).expect("valid patch integrity config");

        let diff = "-del1\n-del2\n-del3";
        let analysis = guard.analyze(diff);
        assert!(analysis.exceeds_max_deletions);
        assert!(!analysis.is_safe());
    }

    #[test]
    fn imbalance_check() {
        let config = PatchIntegrityConfig {
            require_balance: true,
            max_imbalance_ratio: 2.0,
            ..Default::default()
        };
        let guard = PatchIntegrityGuard::with_config(config).expect("valid patch integrity config");

        // 6 additions, 1 deletion = ratio 6.0, exceeds 2.0
        let diff = "+a\n+b\n+c\n+d\n+e\n+f\n-x";
        let analysis = guard.analyze(diff);
        assert!(analysis.exceeds_imbalance);
        assert!(!analysis.is_safe());
    }

    #[test]
    fn evaluate_allows_safe_patch() {
        let guard = PatchIntegrityGuard::new();

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "apply_patch".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "file.txt",
                "diff": "+added line\n-deleted line",
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }

    #[test]
    fn evaluate_blocks_unsafe_patch() {
        let guard = PatchIntegrityGuard::new();

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "apply_patch".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "file.py",
                "diff": "+eval(user_input)",
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);
    }

    #[test]
    fn disabled_guard_allows_everything() {
        let config = PatchIntegrityConfig {
            enabled: false,
            ..Default::default()
        };
        let guard = PatchIntegrityGuard::with_config(config).expect("valid patch integrity config");

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "apply_patch".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "file.py",
                "diff": "+eval(user_input)\n+reverse_shell()",
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
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

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }

    #[test]
    fn with_config_rejects_invalid_forbidden_regex() {
        let config = PatchIntegrityConfig {
            forbidden_patterns: vec!["[".to_string()],
            ..Default::default()
        };

        let error = match PatchIntegrityGuard::with_config(config) {
            Ok(_) => panic!("invalid forbidden regex should fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PatchIntegrityConfigError::InvalidForbiddenPattern { .. }
        ));
    }
}
