//! InputInjectionCapabilityGuard - fine-grained control over `input.inject`
//! actions.
//!
//! Implements Chio's synchronous [`chio_kernel::Guard`] trait.
//!
//! The guard applies to tool calls that represent an **input injection**
//! action on a remote / desktop session.  It claims two detection surfaces:
//!
//! 1. `tool_name == "input.inject"` (or an `action_type`/`custom_type`
//!    argument equal to `input.inject`);
//! 2. arbitrary tool names where the arguments explicitly carry an
//!    `input_type` / `inputType` field together with metadata consistent
//!    with an injection flow (e.g., `keyboard`, `mouse`, `touch`).
//!
//! Enforcement:
//!
//! - the `input_type` value must be in the configured allowlist (default
//!   `{keyboard, mouse, touch}`).  Missing `input_type` is denied
//!   (fail-closed);
//! - when `require_postcondition_probe = true`, the arguments must carry a
//!   non-empty `postcondition_probe_hash` / `postconditionProbeHash`
//!   string.  This binds every input injection to a later verification
//!   step (a screenshot hash, typically) so the agent cannot act blindly.
//!
//! Non-injection actions pass through with [`Verdict::Allow`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

/// Default allowlist of input types.
pub fn default_allowed_input_types() -> Vec<String> {
    vec![
        "keyboard".to_string(),
        "mouse".to_string(),
        "touch".to_string(),
    ]
}

/// Configuration for [`InputInjectionCapabilityGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputInjectionCapabilityConfig {
    /// Enable/disable the guard.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allowed input-type strings.
    #[serde(default = "default_allowed_input_types")]
    pub allowed_input_types: Vec<String>,
    /// When true, the arguments must carry a non-empty
    /// `postcondition_probe_hash` / `postconditionProbeHash` string.
    #[serde(default)]
    pub require_postcondition_probe: bool,
    /// When true, the guard runs in strict mode and denies actions that
    /// look like input injection but are missing `input_type` entirely.
    /// When false, such actions pass through with [`Verdict::Allow`]
    /// (useful for deployments where `input.inject` arrives through a
    /// different dispatch path).
    #[serde(default = "default_true")]
    pub strict: bool,
}

fn default_true() -> bool {
    true
}

impl Default for InputInjectionCapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_input_types: default_allowed_input_types(),
            require_postcondition_probe: false,
            strict: true,
        }
    }
}

/// Fine-grained gate for `input.inject` CUA actions.
pub struct InputInjectionCapabilityGuard {
    enabled: bool,
    allowed_types: HashSet<String>,
    require_postcondition_probe: bool,
    strict: bool,
}

impl InputInjectionCapabilityGuard {
    /// Build a guard with default configuration.
    pub fn new() -> Self {
        Self::with_config(InputInjectionCapabilityConfig::default())
    }

    /// Build a guard with an explicit configuration.
    pub fn with_config(config: InputInjectionCapabilityConfig) -> Self {
        Self {
            enabled: config.enabled,
            allowed_types: config.allowed_input_types.into_iter().collect(),
            require_postcondition_probe: config.require_postcondition_probe,
            strict: config.strict,
        }
    }

    /// Determine whether this tool call is an input-injection candidate.
    fn is_injection(tool_name: &str, arguments: &Value) -> bool {
        if tool_name == "input.inject" || tool_name == "input_inject" {
            return true;
        }
        for key in ["action_type", "actionType", "custom_type", "customType"] {
            if let Some(v) = arguments.get(key).and_then(|v| v.as_str()) {
                if v == "input.inject" {
                    return true;
                }
            }
        }
        // Fallback: explicit `input_type` field with a recognised value
        // indicates an injection flow even when dispatched by a generic
        // tool name.
        arguments
            .get("input_type")
            .or_else(|| arguments.get("inputType"))
            .and_then(|v| v.as_str())
            .is_some()
            && (tool_name == "keyboard"
                || tool_name == "mouse"
                || tool_name == "touch"
                || tool_name == "input")
    }

    /// Read `input_type` / `inputType` from arguments.
    fn input_type(arguments: &Value) -> Option<&str> {
        arguments
            .get("input_type")
            .or_else(|| arguments.get("inputType"))
            .and_then(|v| v.as_str())
    }

    /// Return `true` if a non-empty postcondition probe hash is present.
    fn has_postcondition_probe(arguments: &Value) -> bool {
        arguments
            .get("postcondition_probe_hash")
            .or_else(|| arguments.get("postconditionProbeHash"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    }
}

impl Default for InputInjectionCapabilityGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for InputInjectionCapabilityGuard {
    fn name(&self) -> &str {
        "input-injection-capability"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        if !Self::is_injection(&ctx.request.tool_name, &ctx.request.arguments) {
            return Ok(GuardDecision::allow());
        }

        // 1. Validate input_type.
        match Self::input_type(&ctx.request.arguments) {
            Some(it) => {
                if !self.allowed_types.contains(it) {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
            None => {
                // Missing input_type on an injection-flagged call.
                return Ok(GuardDecision::from_verdict(if self.strict {
                    Verdict::Deny
                } else {
                    Verdict::Allow
                }));
            }
        }

        // 2. Postcondition probe.
        if self.require_postcondition_probe
            && !Self::has_postcondition_probe(&ctx.request.arguments)
        {
            return Ok(GuardDecision::deny(Vec::new()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_explicit_input_inject_tool() {
        let args = serde_json::json!({"input_type": "keyboard"});
        assert!(InputInjectionCapabilityGuard::is_injection(
            "input.inject",
            &args
        ));
    }

    #[test]
    fn detects_action_type_argument() {
        let args = serde_json::json!({"action_type": "input.inject", "input_type": "mouse"});
        assert!(InputInjectionCapabilityGuard::is_injection(
            "generic", &args
        ));
    }

    #[test]
    fn ignores_unrelated_tools() {
        let args = serde_json::json!({"path": "/tmp/x"});
        assert!(!InputInjectionCapabilityGuard::is_injection(
            "read_file",
            &args
        ));
    }

    #[test]
    fn input_type_accepts_camel_case() {
        let args = serde_json::json!({"inputType": "keyboard"});
        assert_eq!(
            InputInjectionCapabilityGuard::input_type(&args),
            Some("keyboard")
        );
    }

    #[test]
    fn postcondition_probe_detected_both_cases() {
        let snake = serde_json::json!({"postcondition_probe_hash": "sha256:abc"});
        let camel = serde_json::json!({"postconditionProbeHash": "sha256:def"});
        assert!(InputInjectionCapabilityGuard::has_postcondition_probe(
            &snake
        ));
        assert!(InputInjectionCapabilityGuard::has_postcondition_probe(
            &camel
        ));
    }

    #[test]
    fn postcondition_probe_empty_string_is_missing() {
        let empty = serde_json::json!({"postcondition_probe_hash": ""});
        assert!(!InputInjectionCapabilityGuard::has_postcondition_probe(
            &empty
        ));
    }
}
