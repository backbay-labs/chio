use std::collections::HashMap;

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};

use super::guard_config::{GuardPolicyConfig, ToolAccessConfig, ToolAccessDefaultAction};
use super::types::PolicyError;

pub(super) fn synthesize_tool_access_scope(
    config: &GuardPolicyConfig,
) -> Result<Option<ChioScope>, PolicyError> {
    let Some(tool_access) = config.tool_access.as_ref() else {
        return Ok(None);
    };
    if !tool_access.enabled {
        return Ok(None);
    }

    if tool_access.allow.is_empty() && tool_access.default_action == ToolAccessDefaultAction::Block
    {
        return Ok(None);
    }

    if tool_access.allow.is_empty() && tool_access.default_action == ToolAccessDefaultAction::Allow
    {
        if !tool_access.require_confirmation.is_empty()
            && !tool_access
                .require_confirmation
                .iter()
                .any(|pattern| pattern == "*")
        {
            return Err(PolicyError::Invalid(
                "guards.tool_access.require_confirmation with default_action=allow requires either explicit allow entries or a wildcard '*' confirmation pattern".to_string(),
            ));
        }
        return Ok(Some(ChioScope {
            grants: vec![ToolGrant {
                server_id: "*".to_string(),
                tool_name: "*".to_string(),
                operations: vec![Operation::Invoke],
                constraints: compile_wildcard_tool_constraints(tool_access),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }));
    }

    for allow_pattern in &tool_access.allow {
        if tool_pattern_has_wildcard(allow_pattern)
            && confirmation_overlap(allow_pattern, &tool_access.require_confirmation)?
            && !tool_access
                .require_confirmation
                .iter()
                .any(|pattern| pattern == "*" || pattern == allow_pattern)
        {
            return Err(PolicyError::Invalid(format!(
                "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern '{allow_pattern}'; use an exact matching confirmation pattern or '*'"
            )));
        }
    }

    let mut grants = Vec::with_capacity(tool_access.allow.len());
    for tool_name in &tool_access.allow {
        grants.push(ToolGrant {
            server_id: "*".to_string(),
            tool_name: tool_name.clone(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(tool_access, tool_name)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
    }

    Ok(Some(ChioScope {
        grants,
        ..ChioScope::default()
    }))
}

fn compile_wildcard_tool_constraints(
    tool_access: &ToolAccessConfig,
) -> Vec<chio_core::capability::scope::Constraint> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = tool_access.max_args_size {
        constraints.push(chio_core::capability::scope::Constraint::MaxArgsSize(
            max_args_size,
        ));
    }
    if tool_access
        .require_confirmation
        .iter()
        .any(|pattern| pattern == "*")
    {
        constraints.push(
            chio_core::capability::scope::Constraint::RequireApprovalAbove { threshold_units: 0 },
        );
    }
    constraints
}

fn tool_pattern_has_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

pub(super) const MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES: usize = 512;
const MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES: usize = 16_384;

fn compile_tool_constraints(
    tool_access: &ToolAccessConfig,
    tool_pattern: &str,
) -> Result<Vec<chio_core::capability::scope::Constraint>, PolicyError> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = tool_access.max_args_size {
        constraints.push(chio_core::capability::scope::Constraint::MaxArgsSize(
            max_args_size,
        ));
    }
    if confirmation_overlap(tool_pattern, &tool_access.require_confirmation)? {
        constraints.push(
            chio_core::capability::scope::Constraint::RequireApprovalAbove { threshold_units: 0 },
        );
    }
    Ok(constraints)
}

fn confirmation_overlap(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, PolicyError> {
    for pattern in confirmation_patterns {
        if tool_patterns_overlap(tool_pattern, pattern)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn tool_patterns_overlap(left: &str, right: &str) -> Result<bool, PolicyError> {
    validate_tool_overlap_pattern_len(left, "left")?;
    validate_tool_overlap_pattern_len(right, "right")?;
    validate_tool_overlap_budget(left, right)?;
    if left == "*" || right == "*" {
        return Ok(true);
    }
    // Confirmation constraints are synthesized onto one grant, so a pair of
    // leading unbounded globs must fail closed instead of risking a gap.
    if left.starts_with('*') && right.starts_with('*') {
        return Ok(true);
    }
    let mut memo = HashMap::new();
    Ok(pattern_suffixes_overlap(
        left.as_bytes(),
        0,
        right.as_bytes(),
        0,
        &mut memo,
    ))
}

fn validate_tool_overlap_pattern_len(pattern: &str, side: &str) -> Result<(), PolicyError> {
    if pattern.len() > MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES {
        return Err(PolicyError::Invalid(format!(
            "guards.tool_access {side} glob pattern exceeds {MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_tool_overlap_budget(left: &str, right: &str) -> Result<(), PolicyError> {
    let state_count = (left.len() + 1).saturating_mul(right.len() + 1);
    if state_count > MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES {
        return Err(PolicyError::Invalid(format!(
            "guards.tool_access glob overlap exceeds {MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES} recursive states"
        )));
    }
    Ok(())
}

fn pattern_suffixes_overlap(
    left: &[u8],
    left_index: usize,
    right: &[u8],
    right_index: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(left_index, right_index)) {
        return *result;
    }
    let result = if left_index == left.len() {
        pattern_suffix_can_match_empty(right, right_index)
    } else if right_index == right.len() {
        pattern_suffix_can_match_empty(left, left_index)
    } else {
        match (left[left_index], right[right_index]) {
            (b'*', _) => {
                pattern_suffixes_overlap(left, left_index + 1, right, right_index, memo)
                    || pattern_suffixes_overlap(left, left_index, right, right_index + 1, memo)
            }
            (_, b'*') => {
                pattern_suffixes_overlap(left, left_index, right, right_index + 1, memo)
                    || pattern_suffixes_overlap(left, left_index + 1, right, right_index, memo)
            }
            (left_byte, right_byte) => {
                pattern_bytes_compatible(left_byte, right_byte)
                    && pattern_suffixes_overlap(left, left_index + 1, right, right_index + 1, memo)
            }
        }
    };
    memo.insert((left_index, right_index), result);
    result
}

fn pattern_suffix_can_match_empty(pattern: &[u8], index: usize) -> bool {
    pattern[index..].iter().all(|byte| *byte == b'*')
}

fn pattern_bytes_compatible(left: u8, right: u8) -> bool {
    left == right || left == b'?' || right == b'?'
}
