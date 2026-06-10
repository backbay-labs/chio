// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn required_capability(action_type: &str) -> Option<&'static str> {
    match action_type {
        "file_read" => Some("file_access"),
        "file_write" => Some("file_write"),
        "patch_apply" => Some("patch"),
        "shell_command" => Some("shell"),
        "tool_call" => Some("tool_call"),
        "egress" => Some("egress"),
        _ => None,
    }
}

fn trigger_name(trigger: &TransitionTrigger) -> &'static str {
    match trigger {
        TransitionTrigger::UserApproval => "user_approval",
        TransitionTrigger::UserDenial => "user_denial",
        TransitionTrigger::CriticalViolation => "critical_violation",
        TransitionTrigger::AnyViolation => "any_violation",
        TransitionTrigger::Timeout => "timeout",
        TransitionTrigger::BudgetExhausted => "budget_exhausted",
        TransitionTrigger::PatternMatch => "pattern_match",
    }
}

fn profile_rule_prefix(profile_id: &str, field: &str) -> String {
    format!("extensions.origins.profiles.{profile_id}.{field}")
}

fn decision_rank(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow => 1,
        Decision::Warn => 2,
        Decision::Deny => 3,
    }
}

fn more_restrictive_result(left: EvaluationResult, right: EvaluationResult) -> EvaluationResult {
    let left_rank = decision_rank(&left.decision);
    let right_rank = decision_rank(&right.decision);
    if right_rank > left_rank {
        return right;
    }
    if left_rank > right_rank {
        return left;
    }
    if right.matched_rule.is_some() {
        right
    } else {
        left
    }
}

fn allow_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Allow,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn warn_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Warn,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn deny_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Deny,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn find_first_match(target: &str, patterns: &[String]) -> Result<Option<usize>, String> {
    for (index, pattern) in patterns.iter().enumerate() {
        if glob_matches(pattern, target)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn find_first_match_or_deny(
    target: &str,
    patterns: &[String],
    field: &str,
    origin_profile_id: Option<String>,
    posture: Option<PostureResult>,
) -> Result<Option<usize>, Box<EvaluationResult>> {
    find_first_match(target, patterns).map_err(|error| {
        Box::new(deny_result(
            Some(field.to_string()),
            Some(format!("invalid policy glob pattern: {error}")),
            origin_profile_id,
            posture,
        ))
    })
}

pub fn glob_matches(pattern: &str, target: &str) -> Result<bool, String> {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    compile_generated_policy_regex(&regex, "policy glob pattern")
        .map(|compiled| compiled.is_match(target))
}

struct PatchStats {
    additions: usize,
    deletions: usize,
}

fn patch_stats(content: &str) -> PatchStats {
    let mut additions = 0usize;
    let mut deletions = 0usize;

    for line in content.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            additions += 1;
        } else if line.starts_with('-') {
            deletions += 1;
        }
    }

    PatchStats {
        additions,
        deletions,
    }
}

fn imbalance_ratio(additions: usize, deletions: usize) -> f64 {
    match (additions, deletions) {
        (0, 0) => 0.0,
        (0, _) => deletions as f64,
        (_, 0) => additions as f64,
        _ => {
            let larger = additions.max(deletions) as f64;
            let smaller = additions.min(deletions) as f64;
            larger / smaller
        }
    }
}
