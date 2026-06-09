//! Default policy assignment for OpenAPI operations.
//!
//! Safe HTTP methods (GET, HEAD, OPTIONS) receive session-scoped allow.
//! Side-effect methods (POST, PUT, PATCH, DELETE) are deny-by-default and
//! require an explicit capability grant.

use chio_http_core::HttpMethod;

use crate::extensions::ChioExtensions;

/// The policy decision for a given operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Session-scoped allow -- the operation is permitted by default within
    /// an active session.
    SessionAllow,
    /// Deny by default -- the operation requires an explicit capability grant.
    DenyByDefault,
}

/// Computes the default policy for an operation given its HTTP method and
/// any Chio extension overrides.
pub struct DefaultPolicy;

impl DefaultPolicy {
    /// Determine the policy decision for an HTTP method. Safe methods get
    /// session-scoped allow; side-effect methods get deny-by-default.
    #[must_use]
    pub fn for_method(method: HttpMethod) -> PolicyDecision {
        if method.is_safe() {
            PolicyDecision::SessionAllow
        } else {
            PolicyDecision::DenyByDefault
        }
    }

    /// Determine the policy decision, taking Chio extensions into account.
    ///
    /// If `x-chio-side-effects` is explicitly set, it overrides the method
    /// default: `true` forces deny-by-default, `false` forces session-allow.
    /// If `x-chio-approval-required` is `true`, the result is always
    /// deny-by-default regardless of other settings.
    #[must_use]
    pub fn for_method_with_extensions(
        method: HttpMethod,
        extensions: &ChioExtensions,
    ) -> PolicyDecision {
        // Approval-required always forces deny.
        if extensions.approval_required == Some(true) {
            return PolicyDecision::DenyByDefault;
        }

        // Explicit side-effects override takes priority over method default.
        if let Some(has_side_effects) = extensions.side_effects {
            return if has_side_effects {
                PolicyDecision::DenyByDefault
            } else {
                PolicyDecision::SessionAllow
            };
        }

        Self::for_method(method)
    }

    /// Whether the operation has side effects, considering both the HTTP method
    /// default and any Chio extension override.
    #[must_use]
    pub fn has_side_effects(method: HttpMethod, extensions: &ChioExtensions) -> bool {
        if let Some(explicit) = extensions.side_effects {
            return explicit;
        }
        method.requires_capability()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_methods_allow() {
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Get),
            PolicyDecision::SessionAllow
        );
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Head),
            PolicyDecision::SessionAllow
        );
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Options),
            PolicyDecision::SessionAllow
        );
    }

    #[test]
    fn unsafe_methods_deny() {
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Post),
            PolicyDecision::DenyByDefault
        );
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Put),
            PolicyDecision::DenyByDefault
        );
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Patch),
            PolicyDecision::DenyByDefault
        );
        assert_eq!(
            DefaultPolicy::for_method(HttpMethod::Delete),
            PolicyDecision::DenyByDefault
        );
    }

    #[test]
    fn extension_side_effects_override() {
        let mut ext = ChioExtensions {
            side_effects: Some(true),
            ..Default::default()
        };
        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Get, &ext),
            PolicyDecision::DenyByDefault
        );

        ext.side_effects = Some(false);
        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Post, &ext),
            PolicyDecision::SessionAllow
        );
    }

    #[test]
    fn approval_required_always_denies() {
        let ext = ChioExtensions {
            approval_required: Some(true),
            side_effects: Some(false),
            ..Default::default()
        };

        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Get, &ext),
            PolicyDecision::DenyByDefault
        );
    }

    #[test]
    fn has_side_effects_follows_method() {
        let ext = ChioExtensions::default();
        assert!(!DefaultPolicy::has_side_effects(HttpMethod::Get, &ext));
        assert!(DefaultPolicy::has_side_effects(HttpMethod::Post, &ext));
    }

    #[test]
    fn has_side_effects_respects_override() {
        let mut ext = ChioExtensions {
            side_effects: Some(true),
            ..Default::default()
        };
        assert!(DefaultPolicy::has_side_effects(HttpMethod::Get, &ext));

        ext.side_effects = Some(false);
        assert!(!DefaultPolicy::has_side_effects(HttpMethod::Delete, &ext));
    }
}
