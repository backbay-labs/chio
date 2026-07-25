//! Path allowlist guard -- deny by default when enabled.
//!
//! If a path is NOT in the allowlist, the guard denies the request. Separate
//! allowlists for file access, file write, and patch operations. When
//! `patch_allow` is empty, it falls back to `file_write_allow`.

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{GuardContext, GuardDecision, KernelError};
use glob::Pattern;

use crate::action::{extract_action_checked, ToolAction};
use crate::path_normalization::{
    normalize_path_for_policy, normalize_path_for_policy_lexical_absolute,
    normalize_path_for_policy_with_fs,
};

/// Configuration for `PathAllowlistGuard`.
pub struct PathAllowlistConfig {
    /// Enable/disable this guard.
    pub enabled: bool,
    /// Allowed globs for file access operations.
    pub file_access_allow: Vec<String>,
    /// Allowed globs for file write operations.
    pub file_write_allow: Vec<String>,
    /// Allowed globs for patch operations (falls back to `file_write_allow` when empty).
    pub patch_allow: Vec<String>,
}

/// Guard that restricts filesystem access to explicitly allowed paths.
///
/// When enabled, any file access, write, or patch to a path not matching the
/// corresponding allowlist is denied. When disabled, the guard returns Allow
/// for all requests.
pub struct PathAllowlistGuard {
    enabled: bool,
    file_access_allow: Vec<Pattern>,
    file_write_allow: Vec<Pattern>,
    patch_allow: Vec<Pattern>,
}

impl PathAllowlistGuard {
    pub fn new() -> Self {
        // Disabled by default (allowlist-based guard must be explicitly configured).
        Self::with_config(PathAllowlistConfig {
            enabled: false,
            file_access_allow: Vec::new(),
            file_write_allow: Vec::new(),
            patch_allow: Vec::new(),
        })
    }

    pub fn with_config(config: PathAllowlistConfig) -> Self {
        let file_access_allow: Vec<Pattern> = config
            .file_access_allow
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();
        let file_write_allow: Vec<Pattern> = config
            .file_write_allow
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();
        let patch_allow = if config.patch_allow.is_empty() {
            file_write_allow.clone()
        } else {
            config
                .patch_allow
                .iter()
                .filter_map(|p| Pattern::new(p).ok())
                .collect()
        };

        Self {
            enabled: config.enabled,
            file_access_allow,
            file_write_allow,
            patch_allow,
        }
    }

    fn matches_any(patterns: &[Pattern], path: &str) -> bool {
        patterns.iter().any(|p| p.matches(path))
    }

    fn matches_allowlist(&self, patterns: &[Pattern], path: &str) -> bool {
        let lexical_path = normalize_path_for_policy(path);
        let resolved_path = normalize_path_for_policy_with_fs(path);
        let lexical_abs_path = normalize_path_for_policy_lexical_absolute(path);

        let resolved_differs_from_lexical_target = lexical_abs_path
            .as_deref()
            .map(|abs| abs != resolved_path.as_str())
            .unwrap_or(resolved_path != lexical_path);

        if resolved_differs_from_lexical_target {
            // When resolution changes the target (e.g. symlink traversal), require the
            // resolved path to match to prevent lexical-path allowlist bypasses.
            return Self::matches_any(patterns, &resolved_path);
        }

        Self::matches_any(patterns, &lexical_path)
            || Self::matches_any(patterns, &resolved_path)
            || lexical_abs_path
                .as_deref()
                .map(|abs| Self::matches_any(patterns, abs))
                .unwrap_or(false)
    }

    fn path_within_root(candidate: &str, root: &str) -> bool {
        if candidate == root {
            return true;
        }

        if root == "/" {
            return candidate.starts_with('/');
        }

        candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
    }

    fn matches_session_roots(&self, path: &str, session_roots: &[String]) -> bool {
        if session_roots.is_empty() {
            return false;
        }

        let lexical_path = normalize_path_for_policy(path);
        let resolved_path = normalize_path_for_policy_with_fs(path);
        let lexical_abs_path = normalize_path_for_policy_lexical_absolute(path);
        let resolved_differs_from_lexical_target = lexical_abs_path
            .as_deref()
            .map(|abs| abs != resolved_path.as_str())
            .unwrap_or(resolved_path != lexical_path);

        if resolved_differs_from_lexical_target {
            return session_roots
                .iter()
                .any(|root| Self::path_within_root(&resolved_path, root));
        }

        session_roots.iter().any(|root| {
            Self::path_within_root(&lexical_path, root)
                || Self::path_within_root(&resolved_path, root)
                || lexical_abs_path
                    .as_deref()
                    .map(|abs| Self::path_within_root(abs, root))
                    .unwrap_or(false)
        })
    }

    pub fn is_file_access_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.matches_allowlist(&self.file_access_allow, path)
    }

    pub fn is_file_write_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.matches_allowlist(&self.file_write_allow, path)
    }

    pub fn is_patch_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.matches_allowlist(&self.patch_allow, path)
    }
}

impl Default for PathAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for PathAllowlistGuard {
    fn name(&self) -> &str {
        "path-allowlist"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled && ctx.session_filesystem_roots.is_none() {
            return Ok(GuardDecision::allow());
        }
        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };
        let Some(path) = action.filesystem_path() else {
            return Ok(GuardDecision::allow());
        };

        if let Some(session_roots) = ctx.session_filesystem_roots {
            if !self.matches_session_roots(path, session_roots) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let allowed = match &action {
            ToolAction::FileAccess(path) => self.is_file_access_allowed(path),
            ToolAction::FileWrite(path, _) => self.is_file_write_allowed(path),
            ToolAction::Patch(path, _) => self.is_patch_allowed(path),
            // Fail closed: any path-bearing action this allowlist cannot
            // classify is denied, never silently allowed.
            _ => false,
        };

        if allowed {
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

    fn enabled_config(
        file_access: Vec<&str>,
        file_write: Vec<&str>,
        patch: Vec<&str>,
    ) -> PathAllowlistConfig {
        PathAllowlistConfig {
            enabled: true,
            file_access_allow: file_access.into_iter().map(String::from).collect(),
            file_write_allow: file_write.into_iter().map(String::from).collect(),
            patch_allow: patch.into_iter().map(String::from).collect(),
        }
    }

    fn make_guard_context<'a>(
        tool_name: &'a str,
        arguments: serde_json::Value,
        scope: &'a chio_core::capability::scope::ChioScope,
        agent_id: &'a String,
        server_id: &'a String,
        capability: chio_core::capability::token::CapabilityToken,
        session_roots: Option<&'a [String]>,
    ) -> chio_kernel::GuardContext<'a> {
        let request = Box::leak(Box::new(chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability,
            tool_name: tool_name.to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }));

        chio_kernel::GuardContext {
            request,
            scope,
            agent_id,
            server_id,
            session_filesystem_roots: session_roots,
            matched_grant_index: None,
        }
    }

    fn make_test_capability(
        kp: &chio_core::crypto::Keypair,
        scope: &chio_core::capability::scope::ChioScope,
    ) -> chio_core::capability::token::CapabilityToken {
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
        chio_core::capability::token::CapabilityToken::sign(cap_body, kp).expect("sign cap")
    }

    #[test]
    fn allows_paths_inside_scope() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec!["**/repo/**"],
            vec!["**/repo/**"],
            vec![],
        ));

        assert!(guard.is_file_access_allowed("/tmp/repo/src/main.rs"));
        assert!(guard.is_file_write_allowed("/tmp/repo/src/main.rs"));
        assert!(guard.is_patch_allowed("/tmp/repo/src/main.rs"));
    }

    #[test]
    fn denies_paths_outside_scope() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec!["**/repo/**"],
            vec!["**/repo/**"],
            vec![],
        ));

        assert!(!guard.is_file_access_allowed("/etc/passwd"));
        assert!(!guard.is_file_write_allowed("/etc/passwd"));
        assert!(!guard.is_patch_allowed("/etc/passwd"));
    }

    #[test]
    fn patch_allow_falls_back_to_file_write_allow() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec![],
            vec!["**/repo/**"],
            vec![], // empty patch_allow falls back to file_write_allow
        ));
        assert!(guard.is_patch_allowed("/tmp/repo/src/main.rs"));
        assert!(!guard.is_patch_allowed("/tmp/other/src/main.rs"));
    }

    #[test]
    fn explicit_patch_allow_does_not_fall_back() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec![],
            vec!["**/repo/**"],
            vec!["**/patches/**"],
        ));
        // Matches patch_allow, not file_write_allow.
        assert!(guard.is_patch_allowed("/tmp/patches/fix.diff"));
        // Does NOT match patch_allow even though it matches file_write_allow.
        assert!(!guard.is_patch_allowed("/tmp/repo/src/main.rs"));
    }

    #[test]
    fn disabled_guard_allows_everything() {
        let guard = PathAllowlistGuard::new(); // disabled by default
        assert!(guard.is_file_access_allowed("/etc/shadow"));
        assert!(guard.is_file_write_allowed("/etc/shadow"));
        assert!(guard.is_patch_allowed("/etc/shadow"));
    }

    #[test]
    fn disabled_guard_without_session_roots_allows_malformed_filesystem_actions() {
        let guard = PathAllowlistGuard::new();
        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();
        let cap = make_test_capability(&kp, &scope);
        let ctx = make_guard_context(
            "read_file",
            serde_json::json!({}),
            &scope,
            &agent_id,
            &server_id,
            cap,
            None,
        );

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }

    #[test]
    fn disabled_guard_with_session_roots_denies_malformed_filesystem_actions() {
        let guard = PathAllowlistGuard::new();
        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();
        let cap = make_test_capability(&kp, &scope);
        let session_roots = vec!["/workspace/project".to_string()];
        let ctx = make_guard_context(
            "read_file",
            serde_json::json!({}),
            &scope,
            &agent_id,
            &server_id,
            cap,
            Some(session_roots.as_slice()),
        );

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);
    }

    #[test]
    fn evaluate_denies_write_outside_allowlist() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec!["**/repo/**"],
            vec!["**/repo/**"],
            vec![],
        ));

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
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/etc/passwd", "content": "bad"}),
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
    fn evaluate_denies_acp_write_text_file_outside_allowlist() {
        let guard = PathAllowlistGuard::with_config(enabled_config(
            vec!["**/repo/**"],
            vec!["**/repo/**"],
            vec![],
        ));

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
            tool_name: "fs/write_text_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "sessionId": "sess-1",
                "path": "/etc/passwd",
                "content": "bad"
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

    #[cfg(unix)]
    #[test]
    fn symlink_escape_outside_allowlist_is_denied() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("chio-path-allowlist-{}", std::process::id()));
        let allowed_dir = root.join("allowed");
        let outside_dir = root.join("outside");
        std::fs::create_dir_all(&allowed_dir).expect("create allowed dir");
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");

        let target = outside_dir.join("secret.txt");
        std::fs::write(&target, "sensitive").expect("write target");
        let link = allowed_dir.join("link.txt");
        symlink(&target, &link).expect("create symlink");

        let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![format!("{}/allowed/**", root.display())],
            file_write_allow: vec![format!("{}/allowed/**", root.display())],
            patch_allow: vec![],
        });

        assert!(
            !guard.is_file_access_allowed(link.to_str().expect("utf-8 path")),
            "symlink target outside allowlist must be denied"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn session_roots_deny_out_of_root_access_even_when_allowlist_matches() {
        let guard = PathAllowlistGuard::with_config(enabled_config(vec!["**"], vec!["**"], vec![]));
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
        let session_roots = vec!["/workspace/project".to_string()];
        let ctx = make_guard_context(
            "filesystem",
            serde_json::json!({"path": "/etc/passwd"}),
            &scope,
            &agent_id,
            &server_id,
            cap,
            Some(session_roots.as_slice()),
        );

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);
    }

    #[test]
    fn session_roots_fail_closed_when_root_set_is_empty() {
        let guard = PathAllowlistGuard::new();
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
        let session_roots: Vec<String> = Vec::new();
        let ctx = make_guard_context(
            "filesystem",
            serde_json::json!({"path": "/workspace/project/src/lib.rs"}),
            &scope,
            &agent_id,
            &server_id,
            cap,
            Some(session_roots.as_slice()),
        );

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);
    }

    #[test]
    fn session_roots_allow_in_root_access_when_other_checks_pass() {
        let guard = PathAllowlistGuard::new();
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
        let session_roots = vec!["/workspace/project".to_string()];
        let ctx = make_guard_context(
            "filesystem",
            serde_json::json!({"path": "/workspace/project/src/lib.rs"}),
            &scope,
            &agent_id,
            &server_id,
            cap,
            Some(session_roots.as_slice()),
        );

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }
}
