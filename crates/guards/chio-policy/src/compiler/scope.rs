use super::patterns::confirmation_overlap;
use super::CompileError;
use crate::models::{DefaultAction, HumanInLoopRule, HushSpec, ToolAccessRule};

use chio_core::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};

// ---------------------------------------------------------------------------
// Scope compilation
// ---------------------------------------------------------------------------

/// Build a default ChioScope from the policy's tool_access rules.
///
/// If tool_access has an allow list and can be faithfully represented as an
/// `ChioScope`, each entry becomes a wildcard ToolGrant with `Invoke`
/// permission. Policies that rely on negative matches or other semantics the
/// scope model cannot encode fail closed and emit no default grants.
pub(super) fn compile_scope(policy: &HushSpec) -> Result<ChioScope, CompileError> {
    let Some(rules) = &policy.rules else {
        return Ok(permissive_scope());
    };

    let Some(ta) = &rules.tool_access else {
        return Ok(permissive_scope());
    };

    if !ta.enabled {
        return Ok(permissive_scope());
    }

    let human_in_loop = rules.human_in_loop.as_ref();

    if ta.default == DefaultAction::Allow {
        if default_allow_has_unrepresentable_selective_confirmation(ta, human_in_loop) {
            return Ok(ChioScope::default());
        }
        if tool_access_can_safely_widen_to_wildcard(ta, human_in_loop) {
            return Ok(permissive_scope());
        }
        if tool_access_can_emit_constrained_wildcard(ta, human_in_loop) {
            return constrained_wildcard_scope(ta, human_in_loop);
        }
        return Ok(ChioScope::default());
    }

    if ta.allow.is_empty() && ta.default == DefaultAction::Block {
        // Block-by-default with no allowlist: empty scope
        return Ok(ChioScope::default());
    }

    if ta.require_workload_identity.is_some() || ta.prefer_workload_identity.is_some() {
        return Ok(ChioScope::default());
    }

    let mut allowed_tool_patterns = Vec::with_capacity(ta.allow.len());
    for tool_pattern in &ta.allow {
        if !confirmation_overlap(tool_pattern, &ta.block)? {
            allowed_tool_patterns.push(tool_pattern);
        }
    }
    if allowed_tool_patterns.is_empty() {
        return Ok(ChioScope::default());
    }

    // Each allowed tool pattern becomes a grant on a wildcard server
    let mut grants = Vec::with_capacity(allowed_tool_patterns.len());
    for tool_pattern in allowed_tool_patterns {
        grants.push(ToolGrant {
            server_id: "*".to_string(),
            tool_name: tool_pattern.clone(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(ta, tool_pattern, human_in_loop)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
    }

    Ok(ChioScope {
        grants,
        ..ChioScope::default()
    })
}

fn permissive_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn constrained_wildcard_scope(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> Result<ChioScope, CompileError> {
    Ok(ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(rule, "*", human_in_loop)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    })
}

fn tool_access_can_safely_widen_to_wildcard(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    rule.allow.is_empty()
        && rule.block.is_empty()
        && rule.require_confirmation.is_empty()
        && rule.max_args_size.is_none()
        && rule.require_runtime_assurance_tier.is_none()
        && rule.require_workload_identity.is_none()
        && rule.prefer_workload_identity.is_none()
        && !human_in_loop_requires_scope_constraints(human_in_loop)
}

fn default_allow_has_unrepresentable_selective_confirmation(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    confirmation_requires_selective_scope(&rule.require_confirmation)
        || human_in_loop.is_some_and(|rule| {
            rule.enabled && confirmation_requires_selective_scope(&rule.require_confirmation)
        })
}

fn human_in_loop_requires_scope_constraints(human_in_loop: Option<&HumanInLoopRule>) -> bool {
    human_in_loop.is_some_and(|rule| {
        rule.enabled
            && (confirmation_applies_to_all_tools(&rule.require_confirmation)
                || rule.approve_above.is_some())
    })
}

fn confirmation_applies_to_all_tools(patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| pattern == "*")
}

fn confirmation_requires_selective_scope(patterns: &[String]) -> bool {
    !patterns.is_empty() && !confirmation_applies_to_all_tools(patterns)
}

fn tool_access_can_emit_constrained_wildcard(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    rule.allow.is_empty()
        && rule.block.is_empty()
        && rule.require_workload_identity.is_none()
        && rule.prefer_workload_identity.is_none()
        && (rule.max_args_size.is_some()
            || rule.require_runtime_assurance_tier.is_some()
            || confirmation_applies_to_all_tools(&rule.require_confirmation)
            || human_in_loop_requires_scope_constraints(human_in_loop))
}

fn compile_tool_constraints(
    rule: &ToolAccessRule,
    tool_pattern: &str,
    human_in_loop: Option<&HumanInLoopRule>,
) -> Result<Vec<Constraint>, CompileError> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = rule.max_args_size {
        constraints.push(Constraint::MaxArgsSize(max_args_size));
    }

    // Determine approval threshold. require_confirmation forces threshold=0
    // when it matches the compiled grant. A wildcard grant can only carry
    // confirmation when the source pattern applies to all tools; selective
    // confirmations stay in the policy evaluator instead of being widened.
    let mut approval_threshold: Option<u64> = None;
    if confirmation_matches_compiled_grant(tool_pattern, &rule.require_confirmation)? {
        approval_threshold = Some(0);
    }
    if let Some(hil) = human_in_loop {
        if hil.enabled {
            if confirmation_matches_compiled_grant(tool_pattern, &hil.require_confirmation)? {
                approval_threshold = Some(0);
            } else if approval_threshold.is_none() {
                if let Some(threshold) = hil.approve_above {
                    approval_threshold = Some(threshold);
                }
            }
        }
    }
    if let Some(threshold_units) = approval_threshold {
        constraints.push(Constraint::RequireApprovalAbove { threshold_units });
    }

    if let Some(tier) = rule.require_runtime_assurance_tier {
        constraints.push(Constraint::MinimumRuntimeAssurance(tier));
    }
    Ok(constraints)
}

fn confirmation_matches_compiled_grant(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, CompileError> {
    if tool_pattern == "*" {
        return Ok(confirmation_applies_to_all_tools(confirmation_patterns));
    }
    confirmation_overlap(tool_pattern, confirmation_patterns)
}
