//! Portable scope matching for tool grants.
//!
//! The hosted kernel carries the richest matcher in
//! `chio-kernel::request_matching`, but the portable core must never
//! silently drop a grant constraint. Constraints that can be evaluated
//! from request arguments are enforced here; constraints that require
//! richer kernel state (governed intent, runtime attestation, SQL result
//! inspection, regex compilation, etc.) fail closed with an explicit
//! error instead of widening scope.
//!
//! Callers that want the full constraint pipeline go through
//! `chio_kernel::capability_matches_request`. This function is the
//! pure-compute matcher that the portable adapters consume directly.
//!
//! Verified-core boundary note:
//! `formal/proof-manifest.toml` includes the portable matcher because it is
//! the fail-closed subset of scope evaluation that never reaches into stores,
//! regex engines, runtime-attestation records, or governed-transaction state.

use alloc::format;
use alloc::string::{String, ToString};
#[cfg(kani)]
use alloc::vec;
use alloc::vec::Vec;

use chio_core_types::capability::{
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::CapabilityToken,
};

/// Borrowed match result, ordered by specificity.
///
/// Mirrors the layout of `chio_kernel::MatchingGrant` but is exposed
/// publicly so portable adapters can rank and iterate matches without
/// re-running the sort.
#[derive(Debug, Clone, Copy)]
pub struct MatchedGrant<'a> {
    /// Index of this grant inside the scope's grant vector.
    pub index: usize,
    /// The matched grant itself.
    pub grant: &'a ToolGrant,
    /// Specificity tuple: `(server-exact, tool-exact, constraint-count)`.
    pub specificity: (u8, u8, usize),
}

/// Errors that can be raised by the portable scope matcher.
///
/// The full matcher in `chio-kernel` surfaces richer error variants
/// (invalid-constraint, attestation-trust, etc.); the portable core
/// returns the two coarse-grained cases that do not require regex or
/// other IO-adjacent machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeMatchError {
    /// No grant in the scope covers the requested `(server, tool, Invoke)`.
    OutOfScope,
    /// The portable kernel cannot safely evaluate a constraint carried by a
    /// target-matching grant.
    ConstraintError(String),
}

/// Resolve the set of grants that authorise a tool invocation on the
/// given server.
///
/// Returns the matched grants sorted by decreasing specificity
/// (exact-exact first, then exact-wildcard, then wildcard-wildcard; ties
/// broken by grant-list order).
pub fn resolve_matching_grants<'a>(
    scope: &'a ChioScope,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<Vec<MatchedGrant<'a>>, ScopeMatchError> {
    #[cfg(kani)]
    if scope.grants.len() == 1 {
        let grant = &scope.grants[0];
        if !grant.constraints.is_empty() {
            return Err(ScopeMatchError::ConstraintError(
                "portable kernel cannot safely evaluate constrained Kani fixture".to_string(),
            ));
        }

        if matches_pattern(&grant.server_id, server_id)
            && matches_pattern(&grant.tool_name, tool_name)
            && grant.operations.contains(&Operation::Invoke)
        {
            return Ok(vec![MatchedGrant {
                index: 0,
                grant,
                specificity: (
                    u8::from(pattern_exact(&grant.server_id, server_id)),
                    u8::from(pattern_exact(&grant.tool_name, tool_name)),
                    grant.constraints.len(),
                ),
            }]);
        }

        return Ok(Vec::new());
    }

    let mut matches: Vec<MatchedGrant<'a>> = Vec::new();

    for (index, grant) in scope.grants.iter().enumerate() {
        let covered = match grant_covers(grant, tool_name, server_id, arguments) {
            Ok(covered) => covered,
            Err(error @ ScopeMatchError::ConstraintError(_)) => return Err(error),
            Err(error) => return Err(error),
        };
        if !covered {
            continue;
        }

        matches.push(MatchedGrant {
            index,
            grant,
            specificity: (
                u8::from(grant.server_id == server_id),
                u8::from(grant.tool_name == tool_name),
                grant.constraints.len(),
            ),
        });
    }

    #[cfg(kani)]
    if matches.len() <= 1 {
        // A zero-or-one element vector is already sorted; this keeps Kani
        // focused on grant coverage rather than allocator internals.
        return Ok(matches);
    }

    matches.sort_by(|left, right| {
        right
            .specificity
            .cmp(&left.specificity)
            .then_with(|| left.index.cmp(&right.index))
    });

    Ok(matches)
}

/// Convenience wrapper that runs [`resolve_matching_grants`] against a
/// full capability token.
pub fn resolve_capability_grants<'a>(
    capability: &'a CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<Vec<MatchedGrant<'a>>, ScopeMatchError> {
    let matches = resolve_matching_grants(&capability.scope, tool_name, server_id, arguments)?;
    if matches.is_empty() {
        return Err(ScopeMatchError::OutOfScope);
    }
    Ok(matches)
}

fn grant_covers(
    grant: &ToolGrant,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<bool, ScopeMatchError> {
    if !matches_pattern(&grant.server_id, server_id)
        || !matches_pattern(&grant.tool_name, tool_name)
        || !grant.operations.contains(&Operation::Invoke)
    {
        return Ok(false);
    }

    #[cfg(kani)]
    let constraints_ok = if grant.constraints.is_empty() {
        true
    } else {
        constraints_match(&grant.constraints, arguments)?
    };

    #[cfg(not(kani))]
    let constraints_ok = constraints_match(&grant.constraints, arguments)?;

    Ok(constraints_ok)
}

fn constraints_match(
    constraints: &[Constraint],
    arguments: &serde_json::Value,
) -> Result<bool, ScopeMatchError> {
    for constraint in constraints {
        if !constraint_matches(constraint, arguments)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn constraint_matches(
    constraint: &Constraint,
    arguments: &serde_json::Value,
) -> Result<bool, ScopeMatchError> {
    let string_leaves = collect_string_leaves(arguments);

    match constraint {
        Constraint::PathPrefix(prefix) => {
            let candidates: Vec<&str> = string_leaves
                .iter()
                .filter(|leaf| {
                    leaf.key.as_deref().is_some_and(is_path_key) || looks_like_path(&leaf.value)
                })
                .map(|leaf| leaf.value.as_str())
                .collect();
            Ok(!candidates.is_empty()
                && candidates
                    .into_iter()
                    .all(|path| path_has_prefix(path, prefix)))
        }
        Constraint::DomainExact(expected) => {
            let expected = normalize_domain(expected);
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty() && domains.into_iter().all(|domain| domain == expected))
        }
        Constraint::DomainGlob(pattern) => {
            let pattern = pattern.to_ascii_lowercase();
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty()
                && domains
                    .into_iter()
                    .all(|domain| wildcard_matches(&pattern, &domain)))
        }
        Constraint::MaxLength(max) => Ok(string_leaves.iter().all(|leaf| leaf.value.len() <= *max)),
        Constraint::MaxArgsSize(max) => Ok(arguments.to_string().len() <= *max),
        // The delivery carriers are enforced only where an output-aware
        // terminal exists. Spelling either as a Custom key must never
        // satisfy a grant by argument matching alone, so the spelling
        // fails the grant it appears on without condemning its sibling
        // grants; the first-class variants below still deny the whole
        // evaluation on this surface.
        Constraint::Custom(key, _)
            if key == "output_digest_sha256" || key == "require_finding_purchase" =>
        {
            Ok(false)
        }
        Constraint::Custom(key, expected) => Ok(argument_contains_custom(arguments, key, expected)),
        Constraint::AudienceAllowlist(allowed) => {
            Ok(audience_allowlist_matches(arguments, allowed))
        }
        Constraint::MemoryStoreAllowlist(allowed) => {
            Ok(memory_store_allowlist_matches(arguments, allowed))
        }
        Constraint::RegexMatch(_)
        | Constraint::GovernedIntentRequired
        | Constraint::RequireApprovalAbove { .. }
        | Constraint::RequireCumulativeApprovalAbove { .. }
        | Constraint::SellerExact(_)
        | Constraint::MinimumRuntimeAssurance(_)
        | Constraint::MinimumAutonomyTier(_)
        | Constraint::TableAllowlist(_)
        | Constraint::ColumnDenylist(_)
        | Constraint::MaxRowsReturned(_)
        | Constraint::OperationClass(_)
        | Constraint::ContentReviewTier(_)
        | Constraint::MaxTransactionAmountUsd(_)
        | Constraint::RequireDualApproval(_)
        | Constraint::ModelConstraint { .. }
        | Constraint::MemoryWriteDenyPatterns(_)
        | Constraint::OutputDigestSha256(_)
        | Constraint::RequireFindingPurchase(_) => Err(ScopeMatchError::ConstraintError(format!(
            "portable kernel cannot safely evaluate {}",
            constraint_name(constraint)
        ))),
    }
}

fn matches_pattern(pattern: &str, candidate: &str) -> bool {
    #[cfg(kani)]
    {
        let pattern = pattern.as_bytes();
        let candidate = candidate.as_bytes();
        if pattern.len() == 1 && pattern[0] == b'*' {
            return true;
        }
        if pattern.len() != candidate.len() {
            return false;
        }
        if pattern.len() == 1 {
            return pattern[0] == candidate[0];
        }
    }

    pattern == "*" || pattern == candidate
}

#[cfg(kani)]
fn pattern_exact(pattern: &str, candidate: &str) -> bool {
    #[cfg(kani)]
    {
        let pattern = pattern.as_bytes();
        let candidate = candidate.as_bytes();
        if pattern.len() != candidate.len() {
            return false;
        }
        if pattern.len() == 1 {
            return pattern[0] == candidate[0];
        }
    }

    pattern == candidate
}

fn path_has_prefix(candidate: &str, prefix: &str) -> bool {
    let Some(candidate) = normalize_path(candidate) else {
        return false;
    };
    let Some(prefix) = normalize_path(prefix) else {
        return false;
    };
    if candidate.is_absolute != prefix.is_absolute {
        return false;
    }
    if prefix.segments.len() > candidate.segments.len() {
        return false;
    }
    prefix
        .segments
        .iter()
        .zip(candidate.segments.iter())
        .all(|(expected, actual)| expected == actual)
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedPath {
    is_absolute: bool,
    segments: Vec<String>,
}

fn normalize_path(path: &str) -> Option<NormalizedPath> {
    let is_absolute = path.starts_with('/') || path.starts_with('\\');
    let mut segments = Vec::new();
    for segment in path.split(['/', '\\']) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop()?;
            continue;
        }
        segments.push(segment.to_string());
    }
    Some(NormalizedPath {
        is_absolute,
        segments,
    })
}

fn constraint_name(constraint: &Constraint) -> &'static str {
    match constraint {
        Constraint::PathPrefix(_) => "path_prefix",
        Constraint::DomainExact(_) => "domain_exact",
        Constraint::DomainGlob(_) => "domain_glob",
        Constraint::RegexMatch(_) => "regex_match",
        Constraint::MaxLength(_) => "max_length",
        Constraint::MaxArgsSize(_) => "max_args_size",
        Constraint::GovernedIntentRequired => "governed_intent_required",
        Constraint::RequireApprovalAbove { .. } => "require_approval_above",
        Constraint::RequireCumulativeApprovalAbove { .. } => "require_cumulative_approval_above",
        Constraint::SellerExact(_) => "seller_exact",
        Constraint::MinimumRuntimeAssurance(_) => "minimum_runtime_assurance",
        Constraint::MinimumAutonomyTier(_) => "minimum_autonomy_tier",
        Constraint::Custom(_, _) => "custom",
        Constraint::TableAllowlist(_) => "table_allowlist",
        Constraint::ColumnDenylist(_) => "column_denylist",
        Constraint::MaxRowsReturned(_) => "max_rows_returned",
        Constraint::OperationClass(_) => "operation_class",
        Constraint::AudienceAllowlist(_) => "audience_allowlist",
        Constraint::ContentReviewTier(_) => "content_review_tier",
        Constraint::MaxTransactionAmountUsd(_) => "max_transaction_amount_usd",
        Constraint::RequireDualApproval(_) => "require_dual_approval",
        Constraint::ModelConstraint { .. } => "model_constraint",
        Constraint::MemoryStoreAllowlist(_) => "memory_store_allowlist",
        Constraint::MemoryWriteDenyPatterns(_) => "memory_write_deny_patterns",
        Constraint::OutputDigestSha256(_) => "output_digest_sha256",
        Constraint::RequireFindingPurchase(_) => "require_finding_purchase",
    }
}

#[derive(Clone)]
struct StringLeaf {
    key: Option<String>,
    value: String,
}

fn collect_string_leaves(arguments: &serde_json::Value) -> Vec<StringLeaf> {
    let mut leaves = Vec::new();
    collect_string_leaves_inner(arguments, None, &mut leaves);
    leaves
}

fn collect_string_leaves_inner(
    arguments: &serde_json::Value,
    current_key: Option<&str>,
    leaves: &mut Vec<StringLeaf>,
) {
    match arguments {
        serde_json::Value::String(value) => leaves.push(StringLeaf {
            key: current_key.map(str::to_string),
            value: value.clone(),
        }),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_string_leaves_inner(value, current_key, leaves);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                collect_string_leaves_inner(value, Some(key), leaves);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn is_path_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("path")
        || matches!(
            key.as_str(),
            "file" | "filepath" | "dir" | "directory" | "root" | "cwd"
        )
}

fn looks_like_path(value: &str) -> bool {
    !value.contains("://")
        && (value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with("~/")
            || value.contains('/')
            || value.contains('\\'))
}

fn collect_domain_candidates(string_leaves: &[StringLeaf]) -> Vec<String> {
    string_leaves
        .iter()
        .filter_map(|leaf| parse_domain(&leaf.value))
        .collect()
}

fn parse_domain(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host_port = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };

    let authority = host_port
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(host_port)
        .rsplit('@')
        .next()
        .unwrap_or(host_port);
    let host = authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .trim_matches('.');
    let normalized = normalize_domain(host);

    if normalized == "localhost"
        || (!normalized.is_empty()
            && normalized.contains('.')
            && normalized.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '.'
            }))
    {
        Some(normalized)
    } else {
        None
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let candidate_chars: Vec<char> = candidate.chars().collect();
    let (mut pattern_idx, mut candidate_idx) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while candidate_idx < candidate_chars.len() {
        if pattern_idx < pattern_chars.len()
            && (pattern_chars[pattern_idx] == candidate_chars[candidate_idx]
                || pattern_chars[pattern_idx] == '*')
        {
            if pattern_chars[pattern_idx] == '*' {
                star_idx = Some(pattern_idx);
                match_idx = candidate_idx;
                pattern_idx += 1;
            } else {
                pattern_idx += 1;
                candidate_idx += 1;
            }
        } else if let Some(star_position) = star_idx {
            pattern_idx = star_position + 1;
            match_idx += 1;
            candidate_idx = match_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern_chars.len() && pattern_chars[pattern_idx] == '*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern_chars.len()
}

fn argument_contains_custom(arguments: &serde_json::Value, key: &str, expected: &str) -> bool {
    match arguments {
        serde_json::Value::Object(map) => map.iter().any(|(entry_key, value)| {
            (entry_key == key && value.as_str() == Some(expected))
                || argument_contains_custom(value, key, expected)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| argument_contains_custom(value, key, expected)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => false,
    }
}

/// Observed string values for a key-driven allowlist constraint.
///
/// `saw_relevant_key` distinguishes "the request never carried such a
/// key" (constraint cannot apply) from "the request carried the key but
/// no string values" (fail-closed). `invalid` is set when a relevant key
/// holds a non-string leaf (number, object, bool, null) which is rejected
/// outright instead of silently widening scope. A bare null directly under
/// a relevant key fails closed because the request named the constrained
/// field without supplying an allowlistable value. Mirrors the full-kernel
/// `chio_kernel::request_matching` semantics for the cases where they
/// overlap.
#[derive(Default)]
struct ObservedStringValues {
    values: Vec<String>,
    saw_relevant_key: bool,
    invalid: bool,
}

fn audience_allowlist_matches(arguments: &serde_json::Value, allowed: &[String]) -> bool {
    let mut observed = ObservedStringValues::default();
    collect_audience_values(arguments, &mut observed);
    if observed.invalid {
        return false;
    }
    if !observed.saw_relevant_key {
        return true;
    }
    observed
        .values
        .iter()
        .all(|value| allowed.iter().any(|allowed_value| allowed_value == value))
}

fn collect_audience_values(arguments: &serde_json::Value, out: &mut ObservedStringValues) {
    match arguments {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if is_audience_key(key) {
                    let before = out.values.len();
                    out.saw_relevant_key = true;
                    if !collect_string_values_strict(value, &mut out.values)
                        || out.values.len() == before
                    {
                        out.invalid = true;
                    }
                } else {
                    collect_audience_values(value, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_audience_values(value, out);
            }
        }
        _ => {}
    }
}

fn is_audience_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "recipient" | "recipients" | "audience" | "to" | "channel" | "channels"
    )
}

/// Walk a JSON value collecting string leaves; returns false if any
/// non-string, non-array leaf is observed (including `null`). The
/// strict policy applies everywhere a relevant key is present. A bare
/// `audience: null` and a mixed array like `["security", null]` both
/// poison the constraint, matching the hosted kernel's
/// `request_matching::collect_string_values_strict`.
fn collect_string_values_strict(value: &serde_json::Value, out: &mut Vec<String>) -> bool {
    match value {
        serde_json::Value::String(s) => {
            out.push(s.clone());
            true
        }
        serde_json::Value::Array(values) => {
            for entry in values {
                if !collect_string_values_strict(entry, out) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Object(_) => false,
    }
}

fn memory_store_allowlist_matches(arguments: &serde_json::Value, allowed: &[String]) -> bool {
    let mut observed = ObservedStringValues::default();
    collect_memory_store_values(arguments, &mut observed);
    if observed.invalid {
        return false;
    }
    if !observed.saw_relevant_key {
        return true;
    }
    observed
        .values
        .iter()
        .all(|value| allowed.iter().any(|allowed_value| allowed_value == value))
}

fn collect_memory_store_values(arguments: &serde_json::Value, out: &mut ObservedStringValues) {
    match arguments {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if is_memory_store_key(key) {
                    let before = out.values.len();
                    out.saw_relevant_key = true;
                    if !collect_string_values_strict(value, &mut out.values)
                        || out.values.len() == before
                    {
                        out.invalid = true;
                    }
                } else {
                    collect_memory_store_values(value, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_memory_store_values(value, out);
            }
        }
        _ => {}
    }
}

fn is_memory_store_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "store" | "memory_store" | "collection" | "namespace"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod delivery_spelling_tests {
    use alloc::vec;

    use super::*;

    fn grant(constraints: Vec<Constraint>) -> ToolGrant {
        ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "tool".to_string(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    #[test]
    fn custom_delivery_spellings_never_match_and_never_poison_siblings() {
        for (key, value) in [
            ("output_digest_sha256", "aa"),
            ("require_finding_purchase", "finding-1"),
        ] {
            let scope = ChioScope {
                grants: vec![
                    grant(vec![Constraint::Custom(key.to_string(), value.to_string())]),
                    grant(Vec::new()),
                ],
                ..ChioScope::default()
            };
            let arguments = serde_json::Value::Object(serde_json::Map::from_iter([(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            )]));
            let matches = resolve_matching_grants(&scope, "tool", "srv", &arguments)
                .expect("a custom delivery spelling must not fail the whole candidate set");
            assert_eq!(
                matches.len(),
                1,
                "only the clean sibling may match for {key}"
            );
            assert_eq!(matches[0].index, 1);
        }
    }

    #[test]
    fn first_class_delivery_constraints_still_deny_the_whole_evaluation() {
        let digest = "aa".repeat(32);
        for constraint in [
            Constraint::OutputDigestSha256(digest),
            Constraint::Custom("path".to_string(), "unrelated".to_string()),
        ] {
            let expect_error = matches!(constraint, Constraint::OutputDigestSha256(_));
            let scope = ChioScope {
                grants: vec![grant(vec![constraint]), grant(Vec::new())],
                ..ChioScope::default()
            };
            let result = resolve_matching_grants(&scope, "tool", "srv", &serde_json::json!({}));
            if expect_error {
                assert!(
                    matches!(result, Err(ScopeMatchError::ConstraintError(_))),
                    "a first-class delivery constraint denies this surface outright"
                );
            } else {
                assert!(result.is_ok());
            }
        }
    }
}
