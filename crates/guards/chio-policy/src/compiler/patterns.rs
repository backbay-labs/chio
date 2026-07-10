use super::CompileError;

pub(super) fn confirmation_overlap(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, CompileError> {
    for pattern in confirmation_patterns {
        if tool_patterns_overlap(tool_pattern, pattern)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn tool_patterns_overlap(left: &str, right: &str) -> Result<bool, CompileError> {
    if left == "*" || right == "*" {
        return Ok(true);
    }
    if !contains_wildcards(left) && !contains_wildcards(right) {
        return Ok(left == right);
    }
    if glob_matches(left, right)? || glob_matches(right, left)? {
        return Ok(true);
    }
    let left_prefix = literal_prefix(left);
    let right_prefix = literal_prefix(right);
    Ok(left_prefix.starts_with(&right_prefix) || right_prefix.starts_with(&left_prefix))
}

fn contains_wildcards(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn literal_prefix(pattern: &str) -> String {
    pattern
        .chars()
        .take_while(|ch| *ch != '*' && *ch != '?')
        .collect()
}

fn glob_matches(pattern: &str, target: &str) -> Result<bool, CompileError> {
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
    crate::regex_safety::compile_generated_policy_regex(&regex, "compiler glob pattern")
        .map(|compiled| compiled.is_match(target))
        .map_err(|error| CompileError::Invalid(format!("invalid policy glob pattern: {error}")))
}
