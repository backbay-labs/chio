//! HTTP-layer verdict type, consistent with the existing Chio Decision enum
//! in chio-core-types but specialized for the HTTP substrate.
//!
//! The `Deny` variant carries optional structured context (tool identity,
//! required vs granted scope, guard name, a stable reason code, and a
//! next-steps hint) so the HTTP sidecar can tell an SDK exactly what scope
//! to request. All detail fields default to `None` on serde; the `details`
//! key is omitted from the wire when all fields are absent.

use serde::{Deserialize, Serialize};

/// Structured deny context attached to [`Verdict::Deny`].
///
/// Every field is optional. Callers that only know a reason and a guard
/// can continue to use [`Verdict::deny`]; callers with richer context
/// should prefer [`Verdict::deny_detailed`] or build a [`DenyDetails`]
/// directly and pass it to the struct variant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyDetails {
    /// Tool name that was denied, e.g. `"write_file"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Tool server that hosts the denied tool, e.g. `"filesystem"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,

    /// Short human-readable summary of the attempted action, suitable for
    /// inclusion in an error line. Example: `write_file(path=".env")`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_action: Option<String>,

    /// Scope the kernel says is required to perform the action, rendered
    /// as the SDK's canonical `ToolGrant(...)` string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,

    /// Scope the presented capability actually had, same rendering as
    /// `required_scope`. `None` when no capability was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_scope: Option<String>,

    /// Stable machine-readable code for this denial, e.g.
    /// `"scope.missing"`, `"guard.prompt_injection"`, `"tenant.mismatch"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,

    /// Receipt id that captures this denial, for audit correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,

    /// Next-steps sentence shown to the developer. Example: `"Request
    /// scope filesystem::write_file from the capability authority."`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,

    /// Link to the docs page that explains this deny code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

impl DenyDetails {
    /// True when every field is `None`. Used to keep the default-path
    /// serialized form compact (details key omitted when empty).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tool_name.is_none()
            && self.tool_server.is_none()
            && self.requested_action.is_none()
            && self.required_scope.is_none()
            && self.granted_scope.is_none()
            && self.reason_code.is_none()
            && self.receipt_id.is_none()
            && self.hint.is_none()
            && self.docs_url.is_none()
    }
}

/// The verdict for an HTTP request evaluation.
/// Consistent with `chio_core_types::Decision` but carries HTTP-specific context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Request is allowed. Proceed to upstream.
    Allow,

    /// Request is denied. Return a structured error response.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
        /// The guard or policy rule that triggered the denial.
        guard: String,
        /// Suggested HTTP status code for the error response (default 403).
        #[serde(default = "default_deny_status")]
        http_status: u16,
        /// Structured deny context: tool identity, required vs granted
        /// scope, a stable reason code, receipt id, and a next-steps
        /// hint. All fields are optional and default to `None`, so this
        /// field is transparent to wire clients that ignore deny details.
        ///
        /// Boxed to keep the [`Verdict`] enum compact on the hot allow
        /// path; the structured deny context is only populated on the
        /// (comparatively rare) deny path.
        #[serde(default, skip_serializing_if = "deny_details_is_empty")]
        details: Box<DenyDetails>,
    },

    /// Request evaluation was cancelled (e.g., timeout, circuit breaker).
    Cancel {
        /// Reason for cancellation.
        reason: String,
    },

    /// Request evaluation did not reach a terminal state.
    Incomplete {
        /// Reason for incomplete evaluation.
        reason: String,
    },
}

fn default_deny_status() -> u16 {
    403
}

fn deny_details_is_empty(details: &DenyDetails) -> bool {
    details.is_empty()
}

impl Verdict {
    /// Deny with a 403 status.
    #[must_use]
    pub fn deny(reason: impl Into<String>, guard: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status: 403,
            details: Box::new(DenyDetails::default()),
        }
    }

    /// Deny with a custom HTTP status code.
    #[must_use]
    pub fn deny_with_status(
        reason: impl Into<String>,
        guard: impl Into<String>,
        http_status: u16,
    ) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status,
            details: Box::new(DenyDetails::default()),
        }
    }

    /// Deny with a full structured context block.
    ///
    /// Prefer this constructor when the kernel already knows what scope
    /// was needed versus granted, which guard fired, and a hint for
    /// the developer. The HTTP status defaults to 403.
    #[must_use]
    pub fn deny_detailed(
        reason: impl Into<String>,
        guard: impl Into<String>,
        details: DenyDetails,
    ) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status: 403,
            details: Box::new(details),
        }
    }

    /// Attach (or overwrite) the structured deny context on an existing
    /// `Deny` verdict. No-op for non-`Deny` variants. Useful when the
    /// guard pipeline constructs a plain deny and a later enrichment
    /// stage populates the details.
    pub fn with_deny_details(mut self, new_details: DenyDetails) -> Self {
        if let Self::Deny { details, .. } = &mut self {
            **details = new_details;
        }
        self
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Convert to the core Decision type for receipt signing.
    #[must_use]
    pub fn to_decision(&self) -> chio_core_types::Decision {
        match self {
            Self::Allow => chio_core_types::Decision::Allow,
            Self::Deny { reason, guard, .. } => chio_core_types::Decision::Deny {
                reason: reason.clone(),
                guard: guard.clone(),
            },
            Self::Cancel { reason } => chio_core_types::Decision::Cancelled {
                reason: reason.clone(),
            },
            Self::Incomplete { reason } => chio_core_types::Decision::Incomplete {
                reason: reason.clone(),
            },
        }
    }
}

impl From<chio_core_types::Decision> for Verdict {
    fn from(decision: chio_core_types::Decision) -> Self {
        match decision {
            chio_core_types::Decision::Allow => Self::Allow,
            chio_core_types::Decision::Deny { reason, guard } => Self::Deny {
                reason,
                guard,
                http_status: 403,
                details: Box::new(DenyDetails::default()),
            },
            chio_core_types::Decision::Cancelled { reason } => Self::Cancel { reason },
            chio_core_types::Decision::Incomplete { reason } => Self::Incomplete { reason },
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn expect_deny(v: Verdict) -> (String, String, u16, DenyDetails) {
        match v {
            Verdict::Deny {
                reason,
                guard,
                http_status,
                details,
            } => (reason, guard, http_status, *details),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn verdict_deny_default_status() {
        let v = Verdict::deny("no capability", "CapabilityGuard");
        assert!(v.is_denied());
        assert!(!v.is_allowed());
        let (_, _, http_status, details) = expect_deny(v);
        assert_eq!(http_status, 403);
        assert!(details.is_empty());
    }

    #[test]
    fn verdict_to_decision_roundtrip() {
        let v = Verdict::deny("blocked", "TestGuard");
        let d = v.to_decision();
        let v2 = Verdict::from(d);
        assert!(v2.is_denied());
    }

    #[test]
    fn serde_roundtrip() {
        let v = Verdict::Allow;
        let json = serde_json::to_string(&v).expect("allow serializes");
        let back: Verdict = serde_json::from_str(&json).expect("allow deserializes");
        assert_eq!(back, v);
    }

    #[test]
    fn deny_serde_includes_status() {
        let v = Verdict::deny_with_status("rate limited", "RateGuard", 429);
        let json = serde_json::to_string(&v).expect("serializes");
        assert!(json.contains("429"));
        let back: Verdict = serde_json::from_str(&json).expect("deserializes");
        let (_, _, http_status, _) = expect_deny(back);
        assert_eq!(http_status, 429);
    }

    #[test]
    fn cancel_verdict_conversion() {
        let v = Verdict::Cancel {
            reason: "timed out".to_string(),
        };
        assert!(!v.is_allowed());
        assert!(!v.is_denied());
        let decision = v.to_decision();
        assert!(matches!(
            decision,
            chio_core_types::Decision::Cancelled { .. }
        ));
        let v2 = Verdict::from(decision);
        assert!(matches!(v2, Verdict::Cancel { reason } if reason == "timed out"));
    }

    #[test]
    fn incomplete_verdict_conversion() {
        let v = Verdict::Incomplete {
            reason: "partial evaluation".to_string(),
        };
        assert!(!v.is_allowed());
        assert!(!v.is_denied());
        let decision = v.to_decision();
        assert!(matches!(
            decision,
            chio_core_types::Decision::Incomplete { .. }
        ));
        let v2 = Verdict::from(decision);
        assert!(matches!(v2, Verdict::Incomplete { reason } if reason == "partial evaluation"));
    }

    #[test]
    fn cancel_serde_roundtrip() {
        let v = Verdict::Cancel {
            reason: "circuit breaker".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serializes");
        let back: Verdict = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, v);
    }

    #[test]
    fn incomplete_serde_roundtrip() {
        let v = Verdict::Incomplete {
            reason: "pending approval".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serializes");
        let back: Verdict = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, v);
    }

    #[test]
    fn deny_default_status_via_serde_default() {
        // When deserializing a Deny variant without the http_status field,
        // the default should be 403.
        let json = r#"{"verdict":"deny","reason":"blocked","guard":"TestGuard"}"#;
        let v: Verdict = serde_json::from_str(json).expect("deserializes");
        let (_, _, http_status, details) = expect_deny(v);
        assert_eq!(http_status, 403);
        // A payload with no details field deserializes into an empty
        // DenyDetails block (compact wire form, details omitted when empty).
        assert!(details.is_empty());
    }

    #[test]
    fn allow_roundtrip_through_decision() {
        let v = Verdict::Allow;
        let decision = v.to_decision();
        assert!(matches!(decision, chio_core_types::Decision::Allow));
        let v2 = Verdict::from(decision);
        assert!(v2.is_allowed());
    }

    #[test]
    fn deny_detailed_carries_structured_fields() {
        let details = DenyDetails {
            tool_name: Some("write_file".into()),
            tool_server: Some("filesystem".into()),
            requested_action: Some("write_file(path=.env)".into()),
            required_scope: Some("ToolGrant(server_id=filesystem, tool_name=write_file)".into()),
            granted_scope: Some("ToolGrant(server_id=filesystem, tool_name=read_file)".into()),
            reason_code: Some("scope.missing".into()),
            receipt_id: Some("chio-receipt-7f3a9b2c".into()),
            hint: Some("Request scope filesystem::write_file from the authority.".into()),
            docs_url: Some("https://docs.chio-protocol.dev/errors/Chio-DENIED".into()),
        };
        let v = Verdict::deny_detailed("scope check failed", "ScopeGuard", details);
        let (reason, guard, http_status, details) = expect_deny(v);
        assert_eq!(reason, "scope check failed");
        assert_eq!(guard, "ScopeGuard");
        assert_eq!(http_status, 403);
        assert_eq!(details.tool_name.as_deref(), Some("write_file"));
        assert_eq!(details.reason_code.as_deref(), Some("scope.missing"));
    }

    #[test]
    fn deny_details_empty_is_omitted_on_the_wire() {
        // The plain `deny(...)` path emits compact wire form: details key
        // is omitted when the DenyDetails block is entirely empty.
        let v = Verdict::deny("no capability", "CapabilityGuard");
        let json = serde_json::to_string(&v).expect("serializes");
        assert!(
            !json.contains("details"),
            "unexpected details in JSON: {json}"
        );
        assert!(json.contains("\"verdict\":\"deny\""));
        assert!(json.contains("\"reason\":\"no capability\""));
        assert!(json.contains("\"guard\":\"CapabilityGuard\""));
    }

    #[test]
    fn with_deny_details_attaches_context() {
        let details = DenyDetails {
            tool_name: Some("read_file".into()),
            reason_code: Some("scope.missing".into()),
            ..DenyDetails::default()
        };
        let v = Verdict::deny("missing scope", "ScopeGuard").with_deny_details(details);
        let (_, _, _, details) = expect_deny(v);
        assert_eq!(details.tool_name.as_deref(), Some("read_file"));
        assert_eq!(details.reason_code.as_deref(), Some("scope.missing"));
    }

    #[test]
    fn with_deny_details_is_noop_for_non_deny() {
        let v = Verdict::Allow.with_deny_details(DenyDetails {
            tool_name: Some("should_be_ignored".into()),
            ..DenyDetails::default()
        });
        assert!(v.is_allowed());
    }
}
