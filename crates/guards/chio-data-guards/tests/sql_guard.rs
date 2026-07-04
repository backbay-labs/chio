//! Integration tests for `SqlQueryGuard`.
//!
//! These tests drive the guard through the `chio_kernel::Guard` trait path,
//! exercising action extraction, verdict mapping, and pass-through for
//! non-`DatabaseQuery` actions.  The `analyze()` API is covered by the
//! module-level unit tests inside the crate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_data_guards::{SqlDialect, SqlGuardConfig, SqlOperation, SqlQueryGuard};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn make_request(
    tool: &str,
    args: serde_json::Value,
) -> (Keypair, ChioScope, String, String, ToolCallRequest) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-test".to_string();

    let cap_body = CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
    };
    let cap = CapabilityToken::sign(cap_body, &kp).expect("sign cap");

    let request = ToolCallRequest {
        request_id: "req-test".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    (kp, scope, agent_id, server_id, request)
}

fn evaluate(guard: &SqlQueryGuard, tool: &str, args: serde_json::Value) -> Verdict {
    let (_kp, scope, agent_id, server_id, request) = make_request(tool, args);
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    guard
        .evaluate(&ctx)
        .expect("evaluate should not error")
        .verdict
}

fn base_cfg() -> SqlGuardConfig {
    SqlGuardConfig {
        dialect: SqlDialect::Generic,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".to_string()],
        ..Default::default()
    }
}

#[test]
fn allows_select_id_from_orders() {
    let guard = SqlQueryGuard::new(base_cfg());
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id, name FROM orders"}),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_select_star_from_unlisted_users_table() {
    let guard = SqlQueryGuard::new(base_cfg());
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT * FROM users"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_drop_table_when_ddl_not_allowed() {
    let guard = SqlQueryGuard::new(base_cfg());
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "DROP TABLE orders"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_update_when_only_select_allowed() {
    let guard = SqlQueryGuard::new(base_cfg());
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "UPDATE orders SET foo = 1 WHERE id = 1"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_malformed_sql() {
    let guard = SqlQueryGuard::new(base_cfg());
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELEKT oops FRUM"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_when_config_is_empty() {
    let guard = SqlQueryGuard::new(SqlGuardConfig::default());
    let verdict = evaluate(&guard, "sql", serde_json::json!({"query": "SELECT 1"}));
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allow_all_still_denies_malformed_sql() {
    let guard = SqlQueryGuard::new(SqlGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "NOT SQL AT ALL ;;;;"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allow_all_permits_any_well_formed_query() {
    let guard = SqlQueryGuard::new(SqlGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id FROM arbitrary_table"}),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn passes_through_non_database_actions() {
    // A shell tool call should be allowed by the SQL guard (it does not apply).
    let guard = SqlQueryGuard::new(SqlGuardConfig::default());
    let verdict = evaluate(&guard, "bash", serde_json::json!({"command": "ls -la"}));
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn parses_postgres_dialect_when_configured() {
    let cfg = SqlGuardConfig {
        dialect: SqlDialect::Postgres,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".to_string()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "postgres",
        serde_json::json!({
            "query": "SELECT id FROM orders WHERE created_at > NOW() - INTERVAL '1 day'"
        }),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn parses_mysql_dialect_with_backticks() {
    let cfg = SqlGuardConfig {
        dialect: SqlDialect::MySql,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".to_string()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "mysql",
        serde_json::json!({"query": "SELECT `id` FROM `orders` WHERE `status` = 'open'"}),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn parses_sqlite_dialect() {
    let cfg = SqlGuardConfig {
        dialect: SqlDialect::Sqlite,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".to_string()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "sqlite",
        serde_json::json!({"query": "SELECT id FROM orders LIMIT 10"}),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn column_allowlist_end_to_end() {
    let mut map = HashMap::new();
    map.insert(
        "orders".to_string(),
        vec!["id".to_string(), "total".to_string()],
    );
    let cfg = SqlGuardConfig {
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".into()],
        column_allowlist: Some(map),
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);

    let allowed = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id, total FROM orders"}),
    );
    assert_eq!(allowed, Verdict::Allow);

    let denied = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id, email FROM orders"}),
    );
    assert_eq!(denied, Verdict::Deny);

    let star_denied = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT * FROM orders"}),
    );
    assert_eq!(star_denied, Verdict::Deny);
}

#[test]
fn denylisted_predicate_blocks_sql_injection_pattern() {
    let cfg = SqlGuardConfig {
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".into()],
        denylisted_predicates: vec![r"\bor\s+1\s*=\s*1\b".to_string()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id FROM orders WHERE id = 1 OR 1=1"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denylisted_predicate_count_limit_fails_closed() {
    let result = SqlQueryGuard::try_new(SqlGuardConfig {
        denylisted_predicates: (0..65).map(|idx| format!("pattern-{idx}")).collect(),
        ..base_cfg()
    });
    let Err(error) = result else {
        panic!("too many denylisted predicates should fail closed");
    };
    assert!(error.contains("allows at most 64 patterns"));
}

#[test]
fn denylisted_predicate_length_limit_fails_closed() {
    let result = SqlQueryGuard::try_new(SqlGuardConfig {
        denylisted_predicates: vec!["a".repeat(513)],
        ..base_cfg()
    });
    let Err(error) = result else {
        panic!("overlong denylisted predicate should fail closed");
    };
    assert!(error.contains("must be at most 512 characters"));
}

#[test]
fn denylisted_predicate_complexity_limit_fails_closed() {
    let result = SqlQueryGuard::try_new(SqlGuardConfig {
        denylisted_predicates: vec!["(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+".into()],
        ..base_cfg()
    });
    let Err(error) = result else {
        panic!("over-complex denylisted predicate should fail closed");
    };
    assert!(error.contains("complexity at most"));
}

#[test]
fn delete_without_where_denied_by_default() {
    let cfg = SqlGuardConfig {
        operation_allowlist: vec![SqlOperation::Delete],
        table_allowlist: vec!["orders".into()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "DELETE FROM orders"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn delete_with_where_allowed_when_configured() {
    let cfg = SqlGuardConfig {
        operation_allowlist: vec![SqlOperation::Delete],
        table_allowlist: vec!["orders".into()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "DELETE FROM orders WHERE id = 1"}),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn select_into_is_denied_by_read_only_policy() {
    let cfg = SqlGuardConfig {
        dialect: SqlDialect::MsSql,
        operation_allowlist: vec![SqlOperation::Select],
        table_allowlist: vec!["orders".into(), "archive".into()],
        ..Default::default()
    };
    let guard = SqlQueryGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "sql",
        serde_json::json!({"query": "SELECT id INTO archive FROM orders"}),
    );
    assert_eq!(verdict, Verdict::Deny);
}
