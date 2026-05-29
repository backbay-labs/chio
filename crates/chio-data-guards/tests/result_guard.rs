//! Integration tests for `QueryResultGuard`.
//!
//! The guard is post-invocation-shaped; kernel integration is deferred
//! (see module docs in `result_guard.rs`).  These tests exercise two
//! integration surfaces:
//!
//! 1. The standalone `redact_result` transform that callers can wire
//!    anywhere they have a response value and an `ChioScope`.
//! 2. The `PostInvocationHook` adapter, which slots into the
//!    `chio_guards::post_invocation::PostInvocationPipeline` today.
//!
//! Acceptance criteria:
//!
//! - Post-invocation guard truncates results exceeding `MaxRowsReturned`.
//! - Columns in `ColumnDenylist` are redacted from results.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{ChioScope, Constraint, Operation, ToolGrant};
use chio_data_guards::{QueryResultGuard, QueryResultGuardConfig};
use chio_guards::post_invocation::{
    PostInvocationContext, PostInvocationHook, PostInvocationPipeline, PostInvocationVerdict,
};

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
fn truncates_results_exceeding_max_rows_returned() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![Constraint::MaxRowsReturned(10)]);
    let mut value = serde_json::json!({
        "rows": (0..50).map(|i| serde_json::json!({"id": i})).collect::<Vec<_>>()
    });
    guard.redact_result(&scope, &mut value);
    assert_eq!(value["rows"].as_array().unwrap().len(), 10);
}

#[test]
fn redacts_columns_in_column_denylist() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![Constraint::ColumnDenylist(vec![
        "email".into(),
        "users.ssn".into(),
    ])]);
    let mut value = serde_json::json!({
        "rows": [
            {"id": 1, "email": "a@b.com", "users": {"ssn": "123-45-6789", "name": "Alice"}},
            {"id": 2, "email": "c@d.com", "users": {"ssn": "987-65-4321", "name": "Bob"}}
        ]
    });
    guard.redact_result(&scope, &mut value);
    for row in value["rows"].as_array().unwrap() {
        assert_eq!(row["email"], "[REDACTED]");
        assert_eq!(row["users"]["ssn"], "[REDACTED]");
        // id and name stay untouched.
        assert_ne!(row["id"], "[REDACTED]");
        assert_ne!(row["users"]["name"], "[REDACTED]");
    }
}

#[test]
fn pipeline_integration_via_post_invocation_hook() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![
        Constraint::MaxRowsReturned(1),
        Constraint::ColumnDenylist(vec!["password".into()]),
    ]);

    // Wire the guard through the chio-guards pipeline.
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(OwnedHook {
        guard,
        scope: scope.clone(),
    }));

    let response = serde_json::json!({
        "rows": [
            {"id": 1, "password": "hunter2"},
            {"id": 2, "password": "correct horse battery staple"}
        ]
    });
    let (verdict, escalations) = pipeline.evaluate("sql", &response);
    assert!(escalations.is_empty());
    match verdict {
        PostInvocationVerdict::Redact(v) => {
            let rows = v["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["password"], "[REDACTED]");
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

#[test]
fn pipeline_allows_when_scope_has_no_constraints() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![]);
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(OwnedHook { guard, scope }));

    let response = serde_json::json!({"rows": [{"id": 1}]});
    let (verdict, _) = pipeline.evaluate("sql", &response);
    assert!(matches!(verdict, PostInvocationVerdict::Allow));
}

#[test]
fn pii_patterns_are_applied_in_pipeline() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig {
        redact_pii_patterns: vec![r"\b\d{3}-\d{2}-\d{4}\b".into()],
        ..Default::default()
    })
    .unwrap();
    let scope = scope(vec![]);
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(OwnedHook { guard, scope }));

    let response = serde_json::json!({
        "rows": [{"id": 1, "note": "SSN: 123-45-6789"}]
    });
    let (verdict, _) = pipeline.evaluate("sql", &response);
    match verdict {
        PostInvocationVerdict::Redact(v) => {
            let note = v["rows"][0]["note"].as_str().unwrap();
            assert!(note.contains("[REDACTED]"));
            assert!(!note.contains("123-45-6789"));
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

#[test]
fn pii_pattern_count_limit_fails_closed() {
    let error = QueryResultGuard::new(QueryResultGuardConfig {
        redact_pii_patterns: (0..65).map(|idx| format!("pattern-{idx}")).collect(),
        ..Default::default()
    })
    .expect_err("too many PII patterns should fail closed");
    assert!(error.contains("allows at most 64 patterns"));
}

#[test]
fn pii_pattern_length_limit_fails_closed() {
    let error = QueryResultGuard::new(QueryResultGuardConfig {
        redact_pii_patterns: vec!["a".repeat(513)],
        ..Default::default()
    })
    .expect_err("overlong PII pattern should fail closed");
    assert!(error.contains("must be at most 512 characters"));
}

#[test]
fn pii_pattern_complexity_limit_fails_closed() {
    let error = QueryResultGuard::new(QueryResultGuardConfig {
        redact_pii_patterns: vec!["(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+".into()],
        ..Default::default()
    })
    .expect_err("over-complex PII pattern should fail closed");
    assert!(error.contains("complexity at most"));
}

#[test]
fn constrained_unknown_row_shape_is_redacted_in_pipeline() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![Constraint::ColumnDenylist(vec!["email".into()])]);
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(OwnedHook { guard, scope }));

    let response = serde_json::json!({
        "items": [{"id": 1, "email": "a@b.com"}],
        "count": 1
    });
    let (verdict, _) = pipeline.evaluate("sql", &response);
    match verdict {
        PostInvocationVerdict::Redact(v) => {
            assert_eq!(
                v,
                serde_json::json!({
                    "items": [{"id": "[REDACTED]", "email": "[REDACTED]"}],
                    "count": "[REDACTED]"
                })
            );
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

#[test]
fn constrained_unknown_shape_redacts_all_top_level_fields() {
    let guard = QueryResultGuard::new(QueryResultGuardConfig::default()).unwrap();
    let scope = scope(vec![Constraint::ColumnDenylist(vec!["email".into()])]);
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(OwnedHook { guard, scope }));

    let response = serde_json::json!({
        "data": {"summary": "ok"},
        "items": [{"id": 1, "email": "a@b.com"}]
    });
    let (verdict, _) = pipeline.evaluate("sql", &response);
    match verdict {
        PostInvocationVerdict::Redact(v) => {
            assert_eq!(
                v,
                serde_json::json!({
                    "data": {"summary": "[REDACTED]"},
                    "items": [{"id": "[REDACTED]", "email": "[REDACTED]"}]
                })
            );
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

/// A helper hook that owns both the guard and the scope so it satisfies
/// the `PostInvocationHook: Send + Sync` bounds required by the
/// pipeline's `Box<dyn PostInvocationHook>`.
struct OwnedHook {
    guard: QueryResultGuard,
    scope: ChioScope,
}

impl PostInvocationHook for OwnedHook {
    fn name(&self) -> &str {
        "query-result"
    }

    fn inspect(
        &self,
        _ctx: &PostInvocationContext<'_>,
        response: &serde_json::Value,
    ) -> PostInvocationVerdict {
        let mut redacted = response.clone();
        self.guard.redact_result(&self.scope, &mut redacted);
        if redacted == *response {
            PostInvocationVerdict::Allow
        } else {
            PostInvocationVerdict::Redact(redacted)
        }
    }
}
