//! Egress allowlist guard -- controls network egress by domain.
//!
//! Controls outbound network egress by matching the target domain against a
//! configured allowlist using simple glob matching.

use std::sync::OnceLock;

use glob::Pattern;

use chio_kernel::{GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Errors produced when building an [`EgressAllowlistGuard`].
#[derive(Debug, thiserror::Error)]
pub enum EgressAllowlistConfigError {
    /// An allowlist pattern was not a valid glob.
    #[error("invalid egress allowlist pattern `{pattern}`: {source}")]
    InvalidAllowPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },
    /// A blocklist pattern was not a valid glob.
    #[error("invalid egress blocklist pattern `{pattern}`: {source}")]
    InvalidBlockPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },
}

fn default_allow_patterns() -> Vec<String> {
    vec![
        // Common AI/ML APIs
        "*.openai.com".to_string(),
        "*.anthropic.com".to_string(),
        "api.github.com".to_string(),
        // Package registries
        "*.npmjs.org".to_string(),
        "registry.npmjs.org".to_string(),
        "pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        "crates.io".to_string(),
        "static.crates.io".to_string(),
    ]
}

/// Guard that controls network egress via domain allowlist.
///
/// By default, only well-known AI API and package registry domains are
/// allowed. All other egress is denied (fail-closed).
#[derive(Clone)]
pub struct EgressAllowlistGuard {
    allow_patterns: Vec<Pattern>,
    block_patterns: Vec<Pattern>,
}

impl EgressAllowlistGuard {
    fn build_default_or_fail_closed() -> Self {
        Self::with_lists(default_allow_patterns(), vec![]).unwrap_or_else(|_| Self {
            allow_patterns: vec![],
            block_patterns: vec![],
        })
    }

    pub fn new() -> Self {
        static DEFAULT: OnceLock<EgressAllowlistGuard> = OnceLock::new();
        DEFAULT
            .get_or_init(Self::build_default_or_fail_closed)
            .clone()
    }

    pub fn with_lists(
        allow: Vec<String>,
        block: Vec<String>,
    ) -> Result<Self, EgressAllowlistConfigError> {
        let allow_patterns = allow
            .into_iter()
            .map(|pattern| {
                Pattern::new(&pattern).map_err(|source| {
                    EgressAllowlistConfigError::InvalidAllowPattern { pattern, source }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let block_patterns = block
            .into_iter()
            .map(|pattern| {
                Pattern::new(&pattern).map_err(|source| {
                    EgressAllowlistConfigError::InvalidBlockPattern { pattern, source }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            allow_patterns,
            block_patterns,
        })
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();

        // Block list takes precedence.
        for pattern in &self.block_patterns {
            if pattern.matches(&domain) {
                return false;
            }
        }

        // Check allow list.
        for pattern in &self.allow_patterns {
            if pattern.matches(&domain) {
                return true;
            }
        }

        // Default: deny (fail-closed).
        false
    }
}

impl Default for EgressAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for EgressAllowlistGuard {
    fn name(&self) -> &str {
        "egress-allowlist"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let host = match &action {
            ToolAction::NetworkEgress(h, _) => h.as_str(),
            _ => return Ok(GuardDecision::allow()),
        };

        if self.is_allowed(host) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_default_domains() {
        let guard = EgressAllowlistGuard::new();
        assert!(guard.is_allowed("api.openai.com"));
        assert!(guard.is_allowed("api.anthropic.com"));
        assert!(guard.is_allowed("api.github.com"));
        assert!(guard.is_allowed("registry.npmjs.org"));
    }

    #[test]
    fn blocks_unknown_domains() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("evil.com"));
        assert!(!guard.is_allowed("random-site.org"));
        assert!(!guard.is_allowed("malware.bad"));
    }

    #[test]
    fn block_list_takes_precedence() {
        let guard = EgressAllowlistGuard::with_lists(
            vec!["*.mycompany.com".to_string()],
            vec!["blocked.mycompany.com".to_string()],
        )
        .expect("valid egress patterns");
        assert!(guard.is_allowed("api.mycompany.com"));
        assert!(!guard.is_allowed("blocked.mycompany.com"));
        assert!(!guard.is_allowed("other.com"));
    }

    #[test]
    fn wildcard_subdomain_matching() {
        let guard = EgressAllowlistGuard::with_lists(vec!["*.example.com".to_string()], vec![])
            .expect("valid egress patterns");
        assert!(guard.is_allowed("api.example.com"));
        assert!(guard.is_allowed("www.example.com"));
        // Bare domain does not match *.example.com with glob
        assert!(!guard.is_allowed("example.com"));
    }

    #[test]
    fn rejects_invalid_block_pattern() {
        let error = match EgressAllowlistGuard::with_lists(
            vec!["*.example.com".to_string()],
            vec!["[".to_string()],
        ) {
            Ok(_) => panic!("invalid block pattern should fail"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("invalid egress blocklist pattern"));
    }
}
