//! Forbidden path guard -- blocks access to sensitive filesystem paths.
//!
//! Denies a request when the normalized target path matches a configured
//! forbidden glob pattern.

use chio_kernel::{GuardContext, KernelError, Verdict};
use glob::Pattern;

use crate::action::{extract_action, ToolAction};
use crate::path_normalization::{
    normalize_path_for_policy, normalize_path_for_policy_lexical_absolute,
    normalize_path_for_policy_with_fs,
};

fn default_forbidden_patterns() -> Vec<String> {
    let mut patterns = vec![
        // SSH keys
        "**/.ssh/**".to_string(),
        "**/id_rsa*".to_string(),
        "**/id_ed25519*".to_string(),
        "**/id_ecdsa*".to_string(),
        // AWS credentials
        "**/.aws/**".to_string(),
        // Environment files
        "**/.env".to_string(),
        "**/.env.*".to_string(),
        // Git credentials
        "**/.git-credentials".to_string(),
        "**/.gitconfig".to_string(),
        // GPG keys
        "**/.gnupg/**".to_string(),
        // Kubernetes
        "**/.kube/**".to_string(),
        // Docker
        "**/.docker/**".to_string(),
        // NPM tokens
        "**/.npmrc".to_string(),
        // Password stores
        "**/.password-store/**".to_string(),
        "**/pass/**".to_string(),
        // 1Password
        "**/.1password/**".to_string(),
        // System paths (Unix)
        "/etc/shadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
    ];

    // Windows paths -- on non-Windows these globs simply never match.
    patterns.extend([
        "**/AppData/Roaming/Microsoft/Credentials/**".to_string(),
        "**/AppData/Local/Microsoft/Credentials/**".to_string(),
        "**/AppData/Roaming/Microsoft/Vault/**".to_string(),
        "**/NTUSER.DAT".to_string(),
        "**/NTUSER.DAT.*".to_string(),
        "**/Windows/System32/config/SAM".to_string(),
        "**/Windows/System32/config/SECURITY".to_string(),
        "**/Windows/System32/config/SYSTEM".to_string(),
        "**/*.reg".to_string(),
        "**/AppData/Roaming/Microsoft/SystemCertificates/**".to_string(),
        "**/WindowsPowerShell/profile.ps1".to_string(),
        "**/PowerShell/profile.ps1".to_string(),
    ]);

    patterns
}

/// Guard that blocks access to sensitive filesystem paths.
pub struct ForbiddenPathGuard {
    patterns: Vec<Pattern>,
    exceptions: Vec<Pattern>,
}

/// Error returned when an operator-supplied forbidden-path glob fails to
/// compile. Surfaced at policy-load time so an invalid pattern rejects the
/// policy instead of being silently dropped (which would leave the path
/// reachable).
#[derive(Debug, thiserror::Error)]
pub enum ForbiddenPathConfigError {
    #[error("invalid forbidden-path pattern {pattern:?}: {source}")]
    InvalidPattern {
        pattern: String,
        source: glob::PatternError,
    },
    #[error("invalid forbidden-path exception {pattern:?}: {source}")]
    InvalidException {
        pattern: String,
        source: glob::PatternError,
    },
}

impl ForbiddenPathGuard {
    pub fn new() -> Self {
        // Default patterns are compile-time constants and always valid globs,
        // so this construction never drops one. Operator-supplied patterns go
        // through `with_patterns`, which rejects invalid globs rather than
        // silently dropping them.
        let patterns = default_forbidden_patterns()
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();
        Self {
            patterns,
            exceptions: Vec::new(),
        }
    }

    /// Build a guard from operator-supplied glob patterns, failing closed.
    ///
    /// Any pattern or exception that is not a valid glob is rejected so a typo
    /// in policy cannot silently disable a forbidden-path block.
    pub fn with_patterns(
        patterns: Vec<String>,
        exceptions: Vec<String>,
    ) -> Result<Self, ForbiddenPathConfigError> {
        let patterns = patterns
            .iter()
            .map(|p| {
                Pattern::new(p).map_err(|source| ForbiddenPathConfigError::InvalidPattern {
                    pattern: p.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let exceptions = exceptions
            .iter()
            .map(|p| {
                Pattern::new(p).map_err(|source| ForbiddenPathConfigError::InvalidException {
                    pattern: p.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            patterns,
            exceptions,
        })
    }

    pub fn is_forbidden(&self, path: &str) -> bool {
        let lexical_path = normalize_path_for_policy(path);
        let resolved_path = normalize_path_for_policy_with_fs(path);
        let lexical_abs_path = normalize_path_for_policy_lexical_absolute(path);
        let resolved_differs_from_lexical_target = lexical_abs_path
            .as_deref()
            .map(|abs| abs != resolved_path.as_str())
            .unwrap_or(resolved_path != lexical_path);

        // Check exceptions first
        for exception in &self.exceptions {
            let lexical_matches = exception.matches(&lexical_path)
                || lexical_abs_path
                    .as_deref()
                    .map(|abs| exception.matches(abs))
                    .unwrap_or(false);
            let resolved_matches = exception.matches(&resolved_path);
            let exception_matches = if resolved_differs_from_lexical_target {
                resolved_matches
            } else {
                resolved_matches || lexical_matches
            };

            if exception_matches {
                return false;
            }
        }

        // Check forbidden patterns
        for pattern in &self.patterns {
            if pattern.matches(&resolved_path) || pattern.matches(&lexical_path) {
                return true;
            }
        }

        false
    }
}

impl Default for ForbiddenPathGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for ForbiddenPathGuard {
    fn name(&self) -> &str {
        "forbidden-path"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let path = match &action {
            ToolAction::FileAccess(p) | ToolAction::FileWrite(p, _) | ToolAction::Patch(p, _) => {
                Some(p.as_str())
            }
            _ => None,
        };

        let Some(path) = path else {
            return Ok(Verdict::Allow);
        };

        if self.is_forbidden(path) {
            Ok(Verdict::Deny)
        } else {
            Ok(Verdict::Allow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ssh_keys() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden("/home/user/.ssh/id_rsa"));
        assert!(guard.is_forbidden("/home/user/.ssh/authorized_keys"));
    }

    #[test]
    fn blocks_etc_shadow() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden("/etc/shadow"));
    }

    #[test]
    fn blocks_aws_credentials() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden("/home/user/.aws/credentials"));
    }

    #[test]
    fn blocks_env_files() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden("/app/.env"));
        assert!(guard.is_forbidden("/app/.env.local"));
    }

    #[test]
    fn allows_normal_files() {
        let guard = ForbiddenPathGuard::new();
        assert!(!guard.is_forbidden("/home/user/project/src/main.rs"));
        assert!(!guard.is_forbidden("/home/user/project/README.md"));
        assert!(!guard.is_forbidden("/app/src/main.rs"));
    }

    #[test]
    fn exceptions_work() {
        let guard = ForbiddenPathGuard::with_patterns(
            vec!["**/.env".to_string()],
            vec!["**/project/.env".to_string()],
        )
        .expect("valid test patterns");
        assert!(guard.is_forbidden("/app/.env"));
        assert!(!guard.is_forbidden("/app/project/.env"));
    }

    #[test]
    fn invalid_pattern_fails_closed() {
        // A typo in an operator-supplied forbidden pattern must reject the
        // policy, not be silently dropped (which would leave the path open).
        let result = ForbiddenPathGuard::with_patterns(vec!["**/id_rsa[".to_string()], vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_exception_fails_closed() {
        let result = ForbiddenPathGuard::with_patterns(
            vec!["**/.env".to_string()],
            vec!["**/[".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn default_patterns_all_compile() {
        // new() builds defaults via filter_map(...ok()), which would silently
        // drop a malformed default. Guarantee none is malformed so the default
        // guard never loses a forbidden pattern.
        for pattern in default_forbidden_patterns() {
            assert!(
                Pattern::new(&pattern).is_ok(),
                "default forbidden pattern failed to compile: {pattern}"
            );
        }
    }

    #[test]
    fn windows_paths_normalized() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden(r"C:\Users\alice\.ssh\id_rsa"));
        assert!(guard.is_forbidden(r"C:\Users\bob\.aws\credentials"));
        assert!(!guard.is_forbidden(r"C:\Users\alice\Documents\report.docx"));
    }
}
