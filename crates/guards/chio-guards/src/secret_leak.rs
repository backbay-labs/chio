//! Secret leak guard -- detects potential secret exposure in file writes.
//!
//! Uses regex patterns to detect common API keys, tokens, passwords, and
//! private keys in file write content. This is a critical security guard.

use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Pattern definition for secret detection.
pub struct SecretPattern {
    /// Pattern name (e.g. "aws_access_key").
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
}

#[derive(Clone, Debug)]
pub struct CustomSecretPattern {
    pub name: String,
    pub pattern: String,
}

fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key",
            pattern: r"AKIA[0-9A-Z]{16}",
        },
        SecretPattern {
            name: "aws_secret_key",
            pattern: r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#,
        },
        SecretPattern {
            name: "github_token",
            pattern: r"gh[ps]_[A-Za-z0-9]{36}",
        },
        SecretPattern {
            name: "github_pat",
            pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        },
        SecretPattern {
            name: "openai_key",
            pattern: r"sk-[A-Za-z0-9]{48}",
        },
        SecretPattern {
            name: "openai_project_key",
            pattern: r"sk-proj-[A-Za-z0-9]{48,}",
        },
        SecretPattern {
            name: "anthropic_key",
            pattern: r"sk-ant-[A-Za-z0-9\-]{95}",
        },
        SecretPattern {
            name: "anthropic_api03_key",
            pattern: r"sk-ant-api03-[A-Za-z0-9_\-]{93}",
        },
        SecretPattern {
            name: "private_key",
            pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        },
        SecretPattern {
            name: "npm_token",
            pattern: r"npm_[A-Za-z0-9]{36}",
        },
        SecretPattern {
            name: "slack_token",
            pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        },
        SecretPattern {
            name: "stripe_secret_key",
            pattern: r"sk_live_[A-Za-z0-9]{24,}",
        },
        SecretPattern {
            name: "stripe_restricted_key",
            pattern: r"rk_live_[A-Za-z0-9]{24,}",
        },
        SecretPattern {
            name: "gcp_service_account",
            pattern: r#""type"\s*:\s*"service_account""#,
        },
        SecretPattern {
            name: "azure_key_vault_token",
            pattern: r#"(?i)azure[_\-]?(?:key[_\-]?vault|kv)[_\-]?(?:secret|token|key)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/=_\-]{32,}"#,
        },
        SecretPattern {
            name: "gitlab_pat",
            pattern: r#"glpat-[A-Za-z0-9_\-]{20,}"#,
        },
        SecretPattern {
            name: "generic_api_key",
            pattern: r#"(?i)(api[_\-]?key|apikey)[\x27"]?\s*[:=]\s*[\x27"]?[A-Za-z0-9]{32,}"#,
        },
        SecretPattern {
            name: "generic_secret",
            pattern: r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}"#,
        },
    ]
}

/// Compiled pattern for matching.
#[derive(Clone)]
struct CompiledPattern {
    name: String,
    regex: Regex,
}

/// A detected secret match.
#[derive(Clone, Debug)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
}

fn mask_value(s: &str) -> String {
    let len = s.chars().count();
    let first = 4usize;
    let last = 4usize;

    if s.is_empty() {
        return String::new();
    }

    if first + last >= len {
        return "*".repeat(len);
    }

    let first_chars: String = s.chars().take(first).collect();
    let last_chars: String = s
        .chars()
        .rev()
        .take(last)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!(
        "{}{}{}",
        first_chars,
        "*".repeat(len - first - last),
        last_chars
    )
}

/// Guard configuration.
pub struct SecretLeakConfig {
    /// Enable/disable this guard.
    pub enabled: bool,
    /// File path patterns to skip (e.g. test fixtures).
    pub skip_paths: Vec<String>,
    /// Additional operator-defined secret patterns.
    pub custom_patterns: Vec<CustomSecretPattern>,
}

impl Default for SecretLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            skip_paths: vec![
                "**/test/**".to_string(),
                "**/tests/**".to_string(),
                "**/*_test.*".to_string(),
                "**/*.test.*".to_string(),
            ],
            custom_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SecretLeakConfigError {
    #[error("invalid built-in secret pattern `{name}`: {source}")]
    InvalidBuiltInPattern {
        name: String,
        #[source]
        source: regex::Error,
    },
    #[error("invalid custom secret pattern `{name}`: {source}")]
    InvalidCustomPattern {
        name: String,
        #[source]
        source: regex::Error,
    },
}

/// Guard that detects potential secret exposure in file writes.
#[derive(Clone)]
pub struct SecretLeakGuard {
    enabled: bool,
    patterns: Vec<CompiledPattern>,
    skip_paths: Vec<glob::Pattern>,
}

impl SecretLeakGuard {
    fn build_default_or_fail_closed() -> Self {
        match Self::with_config(SecretLeakConfig::default()) {
            Ok(guard) => guard,
            Err(_) => Self::unavailable_fail_closed(),
        }
    }

    fn unavailable_fail_closed() -> Self {
        let patterns = Regex::new(r"[\s\S]+")
            .ok()
            .map(|regex| CompiledPattern {
                name: "secret_leak_config_unavailable_fail_closed".to_string(),
                regex,
            })
            .into_iter()
            .collect();
        Self {
            enabled: true,
            patterns,
            skip_paths: vec![],
        }
    }

    pub fn new() -> Self {
        static DEFAULT: OnceLock<SecretLeakGuard> = OnceLock::new();
        DEFAULT
            .get_or_init(Self::build_default_or_fail_closed)
            .clone()
    }

    pub fn with_config(config: SecretLeakConfig) -> Result<Self, SecretLeakConfigError> {
        let mut patterns: Vec<CompiledPattern> = default_patterns()
            .into_iter()
            .map(|pattern| {
                Regex::new(pattern.pattern)
                    .map(|regex| CompiledPattern {
                        name: pattern.name.to_string(),
                        regex,
                    })
                    .map_err(|source| SecretLeakConfigError::InvalidBuiltInPattern {
                        name: pattern.name.to_string(),
                        source,
                    })
            })
            .collect::<Result<_, _>>()?;
        patterns.extend(
            config
                .custom_patterns
                .iter()
                .map(|pattern| {
                    Regex::new(&pattern.pattern)
                        .map(|regex| CompiledPattern {
                            name: pattern.name.clone(),
                            regex,
                        })
                        .map_err(|source| SecretLeakConfigError::InvalidCustomPattern {
                            name: pattern.name.clone(),
                            source,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
        );

        let skip_paths = config
            .skip_paths
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Ok(Self {
            enabled: config.enabled,
            patterns,
            skip_paths,
        })
    }

    /// Scan content for secrets. Returns a list of matches.
    pub fn scan(&self, content: &[u8]) -> Vec<SecretMatch> {
        let content = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return vec![], // Skip binary content.
        };

        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                let matched = m.as_str();
                let redacted = mask_value(matched);

                matches.push(SecretMatch {
                    pattern_name: pattern.name.clone(),
                    offset: m.start(),
                    length: m.len(),
                    redacted,
                });
            }
        }
        matches
    }

    /// Check if a path should be skipped (e.g. test fixtures).
    pub fn should_skip_path(&self, path: &str) -> bool {
        for pattern in &self.skip_paths {
            if pattern.matches(path) {
                return true;
            }
        }
        false
    }
}

impl Default for SecretLeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        "secret-leak"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let (path, content) = match &action {
            ToolAction::FileWrite(p, c) => (p.as_str(), c.as_slice()),
            ToolAction::Patch(p, diff) => (p.as_str(), diff.as_bytes()),
            _ => return Ok(GuardDecision::allow()),
        };

        if self.should_skip_path(path) {
            return Ok(GuardDecision::allow());
        }

        let matches = self.scan(content);

        if matches.is_empty() {
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
    fn detects_aws_access_key() {
        let guard = SecretLeakGuard::new();
        let content = b"aws_key = AKIAIOSFODNN7EXAMPLE";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn detects_github_token() {
        let guard = SecretLeakGuard::new();
        let content = b"token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "github_token");
    }

    #[test]
    fn detects_private_key() {
        let guard = SecretLeakGuard::new();
        let content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "private_key");
    }

    #[test]
    fn detects_openai_project_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk-proj-{}", "a".repeat(48));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "openai_project_key"));
    }

    #[test]
    fn detects_anthropic_api03_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk-ant-api03-{}", "a".repeat(93));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "anthropic_api03_key"));
    }

    #[test]
    fn detects_stripe_secret_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk_live_{}", "a".repeat(24));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "stripe_secret_key"));
    }

    #[test]
    fn detects_gcp_service_account() {
        let guard = SecretLeakGuard::new();
        let content = br#"{"type": "service_account", "project_id": "test"}"#;
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "gcp_service_account"));
    }

    #[test]
    fn detects_gitlab_pat() {
        let guard = SecretLeakGuard::new();
        let content = format!("token = glpat-{}", "a".repeat(20));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_name == "gitlab_pat"));
    }

    #[test]
    fn no_false_positive_on_normal_code() {
        let guard = SecretLeakGuard::new();
        let content = b"This is just normal code\nfn main() { }";
        let matches = guard.scan(content);
        assert!(matches.is_empty());
    }

    #[test]
    fn redaction() {
        assert_eq!(mask_value("short"), "*****");
        assert_eq!(mask_value("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE");
    }

    #[test]
    fn skip_paths() {
        let guard = SecretLeakGuard::new();
        assert!(guard.should_skip_path("/app/tests/fixtures/sample.json"));
        assert!(guard.should_skip_path("/app/src/main_test.rs"));
        assert!(!guard.should_skip_path("/app/src/main.rs"));
    }

    #[test]
    fn evaluate_blocks_file_write_with_secret() {
        let guard = SecretLeakGuard::new();

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

        // File write containing an OpenAI key.
        let secret_content = format!("api_key = sk-{}", "x".repeat(48));
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/config.py",
                "content": secret_content,
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

        // Normal file write should be allowed.
        let request2 = chio_kernel::ToolCallRequest {
            request_id: "req-test-2".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/main.rs",
                "content": "fn main() { println!(\"Hello\"); }",
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

        let ctx2 = chio_kernel::GuardContext {
            request: &request2,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result2 = guard.evaluate(&ctx2).expect("evaluate should not error");
        assert_eq!(result2, Verdict::Allow);
    }

    #[test]
    fn evaluate_allows_write_to_test_path() {
        let guard = SecretLeakGuard::new();

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

        // Even though content contains a secret, test paths are skipped.
        let secret_content = format!("api_key = sk-{}", "x".repeat(48));
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/tests/fixtures/sample.json",
                "content": secret_content,
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
    fn with_config_rejects_invalid_custom_regex() {
        let result = SecretLeakGuard::with_config(SecretLeakConfig {
            enabled: true,
            skip_paths: Vec::new(),
            custom_patterns: vec![CustomSecretPattern {
                name: "broken".to_string(),
                pattern: "(".to_string(),
            }],
        });

        match result {
            Ok(_) => panic!("invalid custom regex should fail configuration"),
            Err(error) => {
                assert!(error.to_string().contains("broken"));
            }
        }
    }
}
