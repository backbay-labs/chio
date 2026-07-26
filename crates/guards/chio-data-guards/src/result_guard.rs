//! Post-invocation query result guard.
//!
//! The `QueryResultGuard` inspects the *response* of a database-shaped
//! tool call and reshapes it before it reaches the agent:
//!
//! 1. Truncate result rows to at most `Constraint::MaxRowsReturned` from
//!    the active scope.
//! 2. Redact columns called out by `Constraint::ColumnDenylist`.
//!    Denylisted entries may be either bare column names (`"email"`, any
//!    table) or `table.column` qualified names.
//! 3. Apply an optional PII pattern denylist supplied via the guard
//!    config (`redact_pii_patterns`) and replace matches with a
//!    deterministic redaction marker.
//!
//! # Integration surface
//!
//! `chio-guards` ships a [`PostInvocationHook`] trait and a
//! [`PostInvocationPipeline`] that threads pre-invocation guards' output
//! into a chain of response inspectors.  `chio-kernel` threads a
//! post-invocation context that includes the matched grant, and this
//! guard also exposes standalone transform helpers so callers can wire
//! it into bespoke pipelines or test harnesses. The guard exposes three
//! shapes:
//!
//! - [`QueryResultGuard::redact_result`] and
//!   [`QueryResultGuard::redact_result_for_request`] -- standalone
//!   transforms over a mutable [`serde_json::Value`] that callers
//!   (kernel integrations, test harnesses, pipeline wrappers) can wire
//!   in wherever post-invocation shaping is already happening.
//! - An implementation of [`PostInvocationHook`] for the guard struct so
//!   it plugs straight into
//!   `chio_guards::post_invocation::PostInvocationPipeline` and consumes
//!   the matched-grant context when the kernel provides it.
//! - An [`chio_kernel::Guard`] impl that never denies -- the guard is
//!   post-invocation, not pre-invocation; installing it pre-invocation
//!   is a no-op.  This keeps the guard installable via
//!   `GuardPipeline::add` without forcing callers to branch on two
//!   guard registries.
//!
//! # Fail-closed rules
//!
//! The post-invocation guard cannot deny a response the way pre-guards
//! deny a call -- the tool has already run -- but it is still
//! fail-closed in spirit:
//!
//! - Responses that do not look like a row list are returned to the
//!   caller with *every* value in the `data` field replaced by the
//!   redaction marker, rather than passing through unredacted.
//! - Unknown column structures inside a row are redacted to the marker.
//! - PII regex compilation errors reject guard construction so invalid
//!   policies fail closed before serving traffic.

use std::borrow::Cow;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use chio_core::capability::scope::{ChioScope, Constraint};
use chio_guards::post_invocation::{
    PostInvocationContext, PostInvocationHook, PostInvocationHookIdentity, PostInvocationVerdict,
};
use chio_kernel::{GuardContext, GuardDecision, KernelError};

/// Default redaction marker written in place of denied columns.
pub const DEFAULT_REDACTION_MARKER: &str = "[REDACTED]";
const MAX_REDACT_PII_PATTERNS: usize = 64;
const MAX_REDACT_PII_PATTERN_LEN: usize = 512;
const MAX_REDACT_PII_PATTERN_COMPLEXITY: usize = 96;
const REDACT_PII_REGEX_SIZE_LIMIT: usize = 1 << 20;
const REDACT_PII_DFA_SIZE_LIMIT: usize = 1 << 20;

/// Configuration for [`QueryResultGuard`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResultGuardConfig {
    /// Marker written in place of redacted column values.  Defaults to
    /// [`DEFAULT_REDACTION_MARKER`].
    #[serde(default = "default_redaction_marker")]
    pub redaction_marker: String,

    /// Regex patterns whose matches in any string value are replaced by
    /// the redaction marker.  Compiled case-insensitively.  Invalid
    /// patterns are logged and skipped (see fail-closed note in the
    /// module docs).
    #[serde(default)]
    pub redact_pii_patterns: Vec<String>,

    /// JSON keys the guard recognises as the list of rows on a tool
    /// response.  The first key that resolves to a JSON array wins.
    #[serde(default = "default_rows_keys")]
    pub rows_keys: Vec<String>,
}

fn default_redaction_marker() -> String {
    DEFAULT_REDACTION_MARKER.to_string()
}

fn default_rows_keys() -> Vec<String> {
    vec![
        "rows".into(),
        "results".into(),
        "records".into(),
        "data".into(),
    ]
}

impl Default for QueryResultGuardConfig {
    fn default() -> Self {
        Self {
            redaction_marker: default_redaction_marker(),
            redact_pii_patterns: Vec::new(),
            rows_keys: default_rows_keys(),
        }
    }
}

/// Post-invocation guard that enforces row and column constraints on
/// query tool responses.
#[derive(Debug)]
pub struct QueryResultGuard {
    config: QueryResultGuardConfig,
    pii_regex: Vec<(String, Regex)>,
}

impl QueryResultGuard {
    /// Construct a guard with the given configuration.
    ///
    /// Invalid or over-broad PII regex patterns reject guard construction so
    /// policy loading fails closed instead of silently widening output.
    pub fn new(config: QueryResultGuardConfig) -> Result<Self, String> {
        if config.redact_pii_patterns.len() > MAX_REDACT_PII_PATTERNS {
            return Err(format!(
                "query_result.redact_pii_patterns allows at most {MAX_REDACT_PII_PATTERNS} patterns"
            ));
        }
        let mut pii_regex = Vec::with_capacity(config.redact_pii_patterns.len());
        for pattern in &config.redact_pii_patterns {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(
                    "query_result.redact_pii_patterns cannot contain empty patterns".to_string(),
                );
            }
            if trimmed.len() > MAX_REDACT_PII_PATTERN_LEN {
                return Err(format!(
                    "query_result.redact_pii_patterns entries must be at most {MAX_REDACT_PII_PATTERN_LEN} characters"
                ));
            }
            let complexity = pii_pattern_complexity(trimmed);
            if complexity > MAX_REDACT_PII_PATTERN_COMPLEXITY {
                return Err(format!(
                    "query_result.redact_pii_patterns entries must have complexity at most {MAX_REDACT_PII_PATTERN_COMPLEXITY}"
                ));
            }
            let re = RegexBuilder::new(trimmed)
                .case_insensitive(true)
                .size_limit(REDACT_PII_REGEX_SIZE_LIMIT)
                .dfa_size_limit(REDACT_PII_DFA_SIZE_LIMIT)
                .build()
                .map_err(|error| {
                    format!("invalid query_result.redact_pii_patterns entry `{trimmed}`: {error}")
                })?;
            pii_regex.push((trimmed.to_string(), re));
        }
        Ok(Self { config, pii_regex })
    }

    /// Read-only access to the configuration.
    pub fn config(&self) -> &QueryResultGuardConfig {
        &self.config
    }

    /// Redact the response in place.
    ///
    /// This is the primary transform entrypoint: kernel integrations
    /// and the [`PostInvocationHook`] impl both delegate here.
    ///
    /// Behaviour:
    ///
    /// - If `scope` has any [`Constraint::MaxRowsReturned`], the rows
    ///   array is truncated to the minimum of those limits.
    /// - If `scope` has any [`Constraint::ColumnDenylist`], matching
    ///   columns (bare name or `table.column`) are replaced by the
    ///   redaction marker inside every row.
    /// - If the config has `redact_pii_patterns`, every matched substring
    ///   in every string value is replaced.
    /// - Constrained responses that do not expose rows under a
    ///   recognised shape are redacted fail-closed instead of passing
    ///   through unchanged.
    pub fn redact_result(&self, scope: &ChioScope, value: &mut Value) {
        self.redact_result_for_request(scope, None, value);
    }

    /// Redact the response in place using either the matched grant or
    /// the full scope when no grant index is available.
    pub fn redact_result_for_request(
        &self,
        scope: &ChioScope,
        matched_grant_index: Option<usize>,
        value: &mut Value,
    ) {
        let constraints = constraints_for_request(scope, matched_grant_index);
        let max_rows = min_max_rows(&constraints);
        let denied = column_denylist(&constraints);
        let requires_row_shape = max_rows.is_some() || !denied.is_empty();

        // Apply the row-level transforms first.
        if let Some(array) = locate_rows_array_mut(value, &self.config.rows_keys) {
            if let Some(limit) = max_rows {
                if array.len() > limit as usize {
                    array.truncate(limit as usize);
                }
            }
            if !denied.is_empty() {
                for row in array.iter_mut() {
                    redact_columns(row, &denied, &self.config.redaction_marker);
                }
            }
        } else if requires_row_shape {
            redact_unstructured_result(value, &self.config.redaction_marker);
        }

        // PII pass runs after structural shaping so denied columns are
        // already marker strings (and will not re-match PII patterns).
        if !self.pii_regex.is_empty() {
            redact_pii_in_place(value, &self.pii_regex, &self.config.redaction_marker);
        }
    }

    /// Non-mutating convenience wrapper used by [`PostInvocationHook`].
    fn redact_result_cloned_for_request(
        &self,
        scope: &ChioScope,
        matched_grant_index: Option<usize>,
        value: &Value,
    ) -> Value {
        let mut out = value.clone();
        self.redact_result_for_request(scope, matched_grant_index, &mut out);
        out
    }
}

fn pii_pattern_complexity(pattern: &str) -> usize {
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

/// Non-mutating convenience that bundles the scope.
impl QueryResultGuard {
    /// Build a [`PostInvocationHook`] adapter bound to an [`ChioScope`].
    ///
    /// Callers that already have a concrete scope can still construct a
    /// fresh adapter per request. When the kernel provides a scope via
    /// [`PostInvocationContext`], the hook prefers that context over the
    /// fallback scope stored here.
    pub fn as_hook(&self, scope: ChioScope) -> QueryResultHook<'_> {
        QueryResultHook { guard: self, scope }
    }

    /// Build an owned [`PostInvocationHook`] adapter for runtime
    /// pipelines that need a `'static` hook object.
    pub fn into_owned_hook(self, scope: ChioScope) -> OwnedQueryResultHook {
        OwnedQueryResultHook { guard: self, scope }
    }
}

/// `PostInvocationHook` adapter around a [`QueryResultGuard`] + scope.
pub struct QueryResultHook<'a> {
    guard: &'a QueryResultGuard,
    scope: ChioScope,
}

impl<'a> PostInvocationHook for QueryResultHook<'a> {
    fn name(&self) -> &str {
        "query-result"
    }

    fn inspect(&self, ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        let scope = ctx.scope.unwrap_or(&self.scope);
        let redacted =
            self.guard
                .redact_result_cloned_for_request(scope, ctx.matched_grant_index, response);
        if redacted == *response {
            PostInvocationVerdict::Allow
        } else {
            PostInvocationVerdict::Redact(redacted)
        }
    }

    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        query_result_hook_identity(&self.guard.config, &self.scope).map(Some)
    }
}

/// Owned `PostInvocationHook` adapter around a [`QueryResultGuard`] +
/// fallback scope.
pub struct OwnedQueryResultHook {
    guard: QueryResultGuard,
    scope: ChioScope,
}

impl PostInvocationHook for OwnedQueryResultHook {
    fn name(&self) -> &str {
        "query-result"
    }

    fn inspect(&self, ctx: &PostInvocationContext<'_>, response: &Value) -> PostInvocationVerdict {
        let scope = ctx.scope.unwrap_or(&self.scope);
        let redacted =
            self.guard
                .redact_result_cloned_for_request(scope, ctx.matched_grant_index, response);
        if redacted == *response {
            PostInvocationVerdict::Allow
        } else {
            PostInvocationVerdict::Redact(redacted)
        }
    }

    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        query_result_hook_identity(&self.guard.config, &self.scope).map(Some)
    }
}

fn query_result_hook_identity(
    config: &QueryResultGuardConfig,
    fallback_scope: &ChioScope,
) -> Result<PostInvocationHookIdentity, String> {
    PostInvocationHookIdentity::from_canonical_config(
        "chio.query-result-guard",
        "1",
        "chio-data-guards.query-result.v1",
        &(config, fallback_scope),
    )
}

impl chio_kernel::Guard for QueryResultGuard {
    fn name(&self) -> &str {
        "query-result"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        // Pre-invocation path is a no-op: the guard only operates on
        // responses.  Installing it pre-invocation is supported so
        // kernel integrations don't need to branch on two pipelines, but
        // it never denies.
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext) -> Result<(), KernelError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

fn constraints_for_request(
    scope: &ChioScope,
    matched_grant_index: Option<usize>,
) -> Vec<&Constraint> {
    if let Some(index) = matched_grant_index {
        if let Some(grant) = scope.grants.get(index) {
            return grant.constraints.iter().collect();
        }
        warn!(
            target: "chio.data-guards.result",
            matched_grant_index = index,
            grant_count = scope.grants.len(),
            "matched grant index missing from scope, falling back to full scope"
        );
    }

    scope
        .grants
        .iter()
        .flat_map(|grant| grant.constraints.iter())
        .collect()
}

fn min_max_rows(constraints: &[&Constraint]) -> Option<u64> {
    let mut min: Option<u64> = None;
    for constraint in constraints {
        if let Constraint::MaxRowsReturned(n) = constraint {
            min = Some(min.map_or(*n, |m| m.min(*n)));
        }
    }
    min
}

fn column_denylist(constraints: &[&Constraint]) -> Vec<String> {
    let mut out = Vec::new();
    for constraint in constraints {
        if let Constraint::ColumnDenylist(list) = constraint {
            for entry in list {
                out.push(entry.to_ascii_lowercase());
            }
        }
    }
    out
}

fn locate_rows_array_mut<'a>(
    value: &'a mut Value,
    rows_keys: &[String],
) -> Option<&'a mut Vec<Value>> {
    let is_value_envelope = value
        .as_object()
        .and_then(|object| object.get("kind"))
        .and_then(Value::as_str)
        == Some("value");
    let value = if is_value_envelope {
        value.get_mut("value")?
    } else {
        value
    };

    if value.is_array() {
        return value.as_array_mut();
    }

    let obj = value.as_object_mut()?;
    let rows_key = rows_keys
        .iter()
        .find(|key| obj.get(*key).map(Value::is_array).unwrap_or(false))?
        .clone();
    obj.get_mut(&rows_key).and_then(Value::as_array_mut)
}

fn redact_unstructured_result(value: &mut Value, marker: &str) {
    match value {
        Value::Object(map) => {
            for field in map.values_mut() {
                redact_nested_values(field, marker);
            }
        }
        _ => redact_nested_values(value, marker),
    }
}

fn redact_nested_values(value: &mut Value, marker: &str) {
    match value {
        Value::Array(items) => {
            for item in items {
                redact_nested_values(item, marker);
            }
        }
        Value::Object(map) => {
            for field in map.values_mut() {
                redact_nested_values(field, marker);
            }
        }
        _ => *value = Value::String(marker.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Row-level redaction
// ---------------------------------------------------------------------------

/// Replace denied columns inside a single row with the redaction marker.
///
/// We accept three row shapes:
///
/// - `{ "column": value, ... }` -- flat JSON object; keys match bare
///   column names, and `table.column` entries also match via suffix.
/// - `{ "table": { "column": value, ... } }` -- nested table shape; the
///   full `table.column` path is checked against the denylist.
/// - Anything else -- redacted whole to the marker for safety.
fn redact_columns(row: &mut Value, denied: &[String], marker: &str) {
    let Some(map) = row.as_object_mut() else {
        *row = Value::String(marker.to_string());
        return;
    };

    // Flat shape: redact keys that match bare names OR any suffix after
    // the last '.' in a denylist entry.
    let bare: Vec<Cow<'_, str>> = denied
        .iter()
        .map(|s| match s.rsplit_once('.') {
            Some((_, col)) => Cow::Borrowed(col),
            None => Cow::Borrowed(s.as_str()),
        })
        .collect();

    // Truly-bare entries (no `table.` qualifier) are the only ones that
    // apply table-agnostically under the nested `{table:{column:...}}`
    // shape. Using the flat-row `bare` list there would widen a
    // qualified denylist like ["users.email"] to also redact
    // `orders.email` in nested payloads, corrupting unrelated tables.
    let truly_bare: Vec<&str> = denied
        .iter()
        .filter(|s| !s.contains('.'))
        .map(|s| s.as_str())
        .collect();

    let keys: Vec<String> = map.keys().cloned().collect();
    for key in &keys {
        let lower = key.to_ascii_lowercase();

        // Bare-name or "*.column" denial.
        // Disambiguate `Cow::as_ref` to the `&str` impl explicitly: the
        // 2024 edition surfaces multiple `PartialEq<String>` impls
        // through `Cow`'s `Deref`, leaving the comparison ambiguous.
        let match_bare = bare
            .iter()
            .any(|b| AsRef::<str>::as_ref(b) == lower.as_str());
        if match_bare {
            if let Some(v) = map.get_mut(key) {
                *v = Value::String(marker.to_string());
            }
            continue;
        }

        // Nested table shape: "table" with a nested object whose columns
        // we need to scrub. Check exact `table.column` dotted entries
        // AND truly-bare entries (no `.` qualifier). A qualified entry
        // like `users.email` must NOT table-agnostically match
        // `orders.email` in nested rows.
        if let Some(Value::Object(inner)) = map.get_mut(key) {
            let inner_keys: Vec<String> = inner.keys().cloned().collect();
            for col in inner_keys {
                let col_lower = col.to_ascii_lowercase();
                let dotted = format!("{}.{}", lower, col_lower);
                let hit = denied.iter().any(|d| d == &dotted)
                    || truly_bare.iter().any(|b| *b == col_lower);
                if hit {
                    if let Some(v) = inner.get_mut(&col) {
                        *v = Value::String(marker.to_string());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PII redaction
// ---------------------------------------------------------------------------

fn redact_pii_in_place(value: &mut Value, patterns: &[(String, Regex)], marker: &str) {
    match value {
        Value::String(s) => {
            let mut out: Cow<'_, str> = Cow::Borrowed(s.as_str());
            for (_, re) in patterns {
                if re.is_match(out.as_ref()) {
                    out = Cow::Owned(re.replace_all(out.as_ref(), marker).into_owned());
                }
            }
            if !matches!(&out, Cow::Borrowed(_)) {
                *s = out.into_owned();
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_pii_in_place(item, patterns, marker);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_pii_in_place(v, patterns, marker);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};

    fn grant(constraints: Vec<Constraint>) -> ToolGrant {
        ToolGrant {
            server_id: "srv".into(),
            tool_name: "*".into(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn scope(constraints: Vec<Constraint>) -> ChioScope {
        ChioScope {
            grants: vec![grant(constraints)],
            ..Default::default()
        }
    }

    #[test]
    fn truncates_rows_to_max_rows_returned() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::MaxRowsReturned(2)]);
        let mut value = serde_json::json!({
            "rows": [
                {"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}
            ]
        });
        guard.redact_result(&scope, &mut value);
        let rows = value.get("rows").and_then(|v| v.as_array()).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn leaves_rows_untouched_when_no_max_rows() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![]);
        let mut value = serde_json::json!({"rows": [{"id": 1}, {"id": 2}]});
        guard.redact_result(&scope, &mut value);
        assert_eq!(value["rows"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn redacts_bare_column_name() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::ColumnDenylist(vec!["email".into()])]);
        let mut value = serde_json::json!({
            "rows": [
                {"id": 1, "email": "a@b.com"},
                {"id": 2, "email": "c@d.com"}
            ]
        });
        guard.redact_result(&scope, &mut value);
        for row in value["rows"].as_array().unwrap() {
            assert_eq!(row["email"], "[REDACTED]");
            assert_ne!(row["id"], "[REDACTED]");
        }
    }

    #[test]
    fn redacts_qualified_column_name_on_flat_row() {
        // "users.email" should still match a flat row with an "email"
        // column (last segment wins).
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::ColumnDenylist(vec!["users.email".into()])]);
        let mut value = serde_json::json!({
            "rows": [{"id": 1, "email": "a@b.com"}]
        });
        guard.redact_result(&scope, &mut value);
        assert_eq!(value["rows"][0]["email"], "[REDACTED]");
    }

    #[test]
    fn redacts_qualified_column_name_on_nested_row() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::ColumnDenylist(vec!["users.email".into()])]);
        let mut value = serde_json::json!({
            "rows": [
                {"users": {"id": 1, "email": "a@b.com"}},
                {"users": {"id": 2, "email": "c@d.com"}}
            ]
        });
        guard.redact_result(&scope, &mut value);
        for row in value["rows"].as_array().unwrap() {
            assert_eq!(row["users"]["email"], "[REDACTED]");
            assert_ne!(row["users"]["id"], "[REDACTED]");
        }
    }

    #[test]
    fn truncation_then_redaction_compose() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![
            Constraint::MaxRowsReturned(1),
            Constraint::ColumnDenylist(vec!["email".into()]),
        ]);
        let mut value = serde_json::json!({
            "rows": [
                {"id": 1, "email": "a@b.com"},
                {"id": 2, "email": "c@d.com"}
            ]
        });
        guard.redact_result(&scope, &mut value);
        let rows = value["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["email"], "[REDACTED]");
    }

    #[test]
    fn pii_patterns_redact_strings() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig {
            redact_pii_patterns: vec![r"\b\d{3}-\d{2}-\d{4}\b".into()],
            ..Default::default()
        })
        .unwrap();
        let scope = scope(vec![]);
        let mut value = serde_json::json!({
            "rows": [{"id": 1, "note": "SSN: 123-45-6789"}]
        });
        guard.redact_result(&scope, &mut value);
        let note = value["rows"][0]["note"].as_str().unwrap();
        assert!(note.contains("[REDACTED]"));
        assert!(!note.contains("123-45-6789"));
    }

    #[test]
    fn invalid_pii_pattern_rejects_guard_construction() {
        let error = QueryResultGuard::new(QueryResultGuardConfig {
            redact_pii_patterns: vec!["[".into()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.contains("invalid query_result.redact_pii_patterns entry"));
    }

    #[test]
    fn top_level_array_is_treated_as_rows() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::MaxRowsReturned(1)]);
        let mut value = serde_json::json!([1, 2, 3]);
        guard.redact_result(&scope, &mut value);
        assert_eq!(value, serde_json::json!([1]));
    }

    #[test]
    fn constrained_unknown_row_key_is_redacted_fail_closed() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::ColumnDenylist(vec!["email".into()])]);
        let mut value = serde_json::json!({
            "items": [
                {"id": 1, "email": "a@b.com"},
                {"id": 2, "email": "c@d.com"}
            ],
            "count": 2
        });
        guard.redact_result(&scope, &mut value);
        assert_eq!(
            value,
            serde_json::json!({
                "items": [
                    {"id": "[REDACTED]", "email": "[REDACTED]"},
                    {"id": "[REDACTED]", "email": "[REDACTED]"}
                ],
                "count": "[REDACTED]"
            })
        );
    }

    #[test]
    fn post_invocation_hook_returns_redact_when_modified() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::MaxRowsReturned(1)]);
        let hook = guard.as_hook(scope);
        let value = serde_json::json!({"rows": [{"id": 1}, {"id": 2}]});
        let context = PostInvocationContext::synthetic("sql");
        match hook.inspect(&context, &value) {
            PostInvocationVerdict::Redact(v) => {
                assert_eq!(v["rows"].as_array().unwrap().len(), 1);
            }
            other => panic!("expected Redact, got {other:?}"),
        }
    }

    #[test]
    fn post_invocation_hook_returns_allow_when_unchanged() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![]);
        let hook = guard.as_hook(scope);
        let value = serde_json::json!({"rows": [{"id": 1}]});
        let context = PostInvocationContext::synthetic("sql");
        match hook.inspect(&context, &value) {
            PostInvocationVerdict::Allow => {}
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn durable_identity_binds_effective_config_and_fallback_scope() {
        let base_scope = scope(vec![]);
        let base_guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let base = base_guard
            .as_hook(base_scope.clone())
            .durable_identity()
            .unwrap()
            .unwrap();

        let configured_guard = QueryResultGuard::new(QueryResultGuardConfig {
            redaction_marker: "[FILTERED]".to_string(),
            ..Default::default()
        })
        .unwrap();
        let configured = configured_guard
            .as_hook(base_scope)
            .durable_identity()
            .unwrap()
            .unwrap();
        let scoped = base_guard
            .as_hook(scope(vec![Constraint::MaxRowsReturned(1)]))
            .durable_identity()
            .unwrap()
            .unwrap();

        assert_ne!(base, configured);
        assert_ne!(base, scoped);
    }

    #[test]
    fn pre_invocation_guard_impl_allows_everything() {
        // The kernel Guard::evaluate path is a no-op for this guard.
        // We assert the default name is stable for observability.
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        assert_eq!(
            <QueryResultGuard as chio_kernel::Guard>::name(&guard),
            "query-result"
        );
    }

    #[test]
    fn strictest_max_rows_wins() {
        let g = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope_multi = ChioScope {
            grants: vec![
                grant(vec![Constraint::MaxRowsReturned(10)]),
                grant(vec![Constraint::MaxRowsReturned(3)]),
            ],
            ..Default::default()
        };
        let mut value = serde_json::json!({
            "rows": [
                {"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}
            ]
        });
        g.redact_result(&scope_multi, &mut value);
        assert_eq!(value["rows"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn matched_grant_constraints_override_other_grants() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope_multi = ChioScope {
            grants: vec![
                grant(vec![
                    Constraint::MaxRowsReturned(1),
                    Constraint::ColumnDenylist(vec!["email".into()]),
                ]),
                grant(vec![
                    Constraint::MaxRowsReturned(5),
                    Constraint::ColumnDenylist(vec!["ssn".into()]),
                ]),
            ],
            ..Default::default()
        };
        let mut value = serde_json::json!({
            "rows": [
                {"id": 1, "email": "a@b.com", "ssn": "123-45-6789"},
                {"id": 2, "email": "c@d.com", "ssn": "987-65-4321"}
            ]
        });

        guard.redact_result_for_request(&scope_multi, Some(1), &mut value);

        let rows = value["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["ssn"], "[REDACTED]");
        assert_eq!(rows[1]["ssn"], "[REDACTED]");
        assert_ne!(rows[0]["email"], "[REDACTED]");
        assert_ne!(rows[1]["email"], "[REDACTED]");
    }

    #[test]
    fn alternative_rows_key_respected() {
        let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
        let scope = scope(vec![Constraint::MaxRowsReturned(1)]);
        let mut value = serde_json::json!({
            "results": [{"id": 1}, {"id": 2}, {"id": 3}]
        });
        guard.redact_result(&scope, &mut value);
        assert_eq!(value["results"].as_array().unwrap().len(), 1);
    }
}
