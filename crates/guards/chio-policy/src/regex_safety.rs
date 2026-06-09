use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, OnceLock};

use regex::{Regex, RegexBuilder};

const MAX_POLICY_REGEX_LEN: usize = 512;
const MAX_POLICY_REGEX_COMPLEXITY: usize = 96;
const POLICY_REGEX_SIZE_LIMIT: usize = 1 << 20;
const POLICY_REGEX_DFA_SIZE_LIMIT: usize = 1 << 20;
const POLICY_REGEX_CACHE_MAX_KEYS: usize = 4_096;

static POLICY_REGEX_CACHE: OnceLock<StdMutex<HashMap<String, Result<Regex, String>>>> =
    OnceLock::new();

pub(crate) fn compile_policy_regex(pattern: &str, field: &str) -> Result<Regex, String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if trimmed.len() > MAX_POLICY_REGEX_LEN {
        return Err(format!(
            "{field} must be at most {MAX_POLICY_REGEX_LEN} characters"
        ));
    }
    let complexity = policy_regex_complexity(trimmed);
    if complexity > MAX_POLICY_REGEX_COMPLEXITY {
        return Err(format!(
            "{field} must have complexity at most {MAX_POLICY_REGEX_COMPLEXITY}"
        ));
    }
    RegexBuilder::new(trimmed)
        .size_limit(POLICY_REGEX_SIZE_LIMIT)
        .dfa_size_limit(POLICY_REGEX_DFA_SIZE_LIMIT)
        .build()
        .map_err(|error| format!("{field} invalid regex pattern {trimmed:?}: {error}"))
}

pub(crate) fn compile_generated_policy_regex(pattern: &str, field: &str) -> Result<Regex, String> {
    if pattern.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    RegexBuilder::new(pattern)
        .size_limit(POLICY_REGEX_SIZE_LIMIT)
        .dfa_size_limit(POLICY_REGEX_DFA_SIZE_LIMIT)
        .build()
        .map_err(|error| format!("{field} invalid generated regex: {error}"))
}

pub(crate) fn policy_regex_is_match(
    pattern: &str,
    field: &str,
    haystack: &str,
) -> Result<bool, String> {
    let cache = POLICY_REGEX_CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
    let key = format!("{field}\0{pattern}");
    let compiled = {
        let mut guard = cache
            .lock()
            .map_err(|_| format!("{field} regex cache lock was poisoned"))?;
        if let Some(compiled) = guard.get(&key) {
            compiled.clone()
        } else {
            if guard.len() >= POLICY_REGEX_CACHE_MAX_KEYS {
                guard.clear();
            }
            let compiled = compile_policy_regex(pattern, field);
            guard.insert(key, compiled.clone());
            compiled
        }
    }?;
    Ok(compiled.is_match(haystack))
}

pub(crate) fn validate_policy_regex_count(
    count: usize,
    field: &str,
    max: usize,
) -> Result<(), String> {
    if count > max {
        return Err(format!("{field} allows at most {max} patterns"));
    }
    Ok(())
}

fn policy_regex_complexity(pattern: &str) -> usize {
    let mut score = 0usize;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' | '*' | '+' | '?' => score = score.saturating_add(4),
            '{' | '[' | '(' => score = score.saturating_add(2),
            _ => {}
        }
    }
    score
}
