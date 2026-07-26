//! Integration tests for `VectorDbGuard`.
//!
//! Drives the guard through the `chio_kernel::Guard` trait with realistic
//! capability scopes, verifying that:
//!
//! - Query to a collection not in `CollectionAllowlist` is denied.
//! - Cross-namespace access is denied.
//! - Upsert is denied when the operation class is `ReadOnly`.
//! - `top_k=500` is denied when `MaxRowsReturned=50`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    scope::{ChioScope, Constraint, Operation, SqlOperationClass, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_data_guards::{VectorDbGuard, VectorFieldPaths, VectorGuardConfig};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn grant(constraints: Vec<Constraint>) -> ToolGrant {
    ToolGrant {
        server_id: "srv-vec".into(),
        tool_name: "*".into(),
        operations: vec![Operation::Invoke],
        constraints,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_request(
    tool: &str,
    args: serde_json::Value,
    scope: ChioScope,
) -> (ChioScope, String, String, ToolCallRequest) {
    let kp = Keypair::generate();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-vec".to_string();

    let cap_body = CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let cap = CapabilityToken::sign(cap_body, &kp).expect("sign cap");

    let req = ToolCallRequest {
        request_id: "req-vec".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    (scope, agent_id, server_id, req)
}

fn evaluate(
    guard: &VectorDbGuard,
    tool: &str,
    args: serde_json::Value,
    scope: ChioScope,
) -> Verdict {
    evaluate_with_matched_grant(guard, tool, args, scope, None)
}

fn evaluate_with_matched_grant(
    guard: &VectorDbGuard,
    tool: &str,
    args: serde_json::Value,
    scope: ChioScope,
    matched_grant_index: Option<usize>,
) -> Verdict {
    let (scope, agent_id, server_id, req) = make_request(tool, args, scope);
    let ctx = GuardContext {
        request: &req,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index,
    };
    guard
        .evaluate(&ctx)
        .expect("evaluate should not error")
        .verdict
}

fn cfg_docs_only() -> VectorGuardConfig {
    VectorGuardConfig {
        collection_allowlist: vec!["docs".into()],
        ..Default::default()
    }
}

#[test]
fn denies_query_to_collection_not_in_allowlist() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone",
        serde_json::json!({
            "collection": "secrets",
            "operation": "query",
            "top_k": 10
        }),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allows_query_to_collection_in_allowlist() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 10
        }),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_cross_namespace_access() {
    let cfg = VectorGuardConfig {
        collection_allowlist: vec!["docs".into()],
        namespace_allowlist: Some(vec!["tenant-a".into()]),
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg);
    let verdict = evaluate(
        &guard,
        "qdrant",
        serde_json::json!({
            "collection": "docs",
            "namespace": "tenant-b",
            "operation": "query",
            "top_k": 10
        }),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_upsert_under_readonly_grant() {
    let scope = ChioScope {
        grants: vec![grant(vec![Constraint::OperationClass(
            SqlOperationClass::ReadOnly,
        )])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "weaviate",
        serde_json::json!({
            "collection": "docs",
            "operation": "upsert",
            "top_k": 1
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allows_query_under_readonly_grant() {
    let scope = ChioScope {
        grants: vec![grant(vec![
            Constraint::OperationClass(SqlOperationClass::ReadOnly),
            Constraint::MaxRowsReturned(50),
        ])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "qdrant",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 10
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_top_k_500_when_max_rows_returned_50() {
    let scope = ChioScope {
        grants: vec![grant(vec![Constraint::MaxRowsReturned(50)])],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "chroma",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 500
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn passes_through_non_vector_database_actions() {
    // A request against a SQL-shaped database with no vendor marker in
    // the tool name or database id should pass the vector guard.
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "postgres",
        serde_json::json!({"query": "SELECT 1", "database": "postgres"}),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_parse_error_missing_collection() {
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "pinecone_query",
        // A memory-shaped call with no collection/index/class/store: the
        // guard should deny on parse error.
        serde_json::json!({"namespace": "anywhere"}),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn custom_nested_field_paths_are_enforced() {
    let guard = VectorDbGuard::new(VectorGuardConfig {
        collection_allowlist: vec!["docs".into()],
        namespace_allowlist: Some(vec!["tenant-a".into()]),
        field_paths: VectorFieldPaths {
            collection: vec!["payload.index".into()],
            namespace: vec!["payload.routing.namespace".into()],
            operation: vec!["payload.action".into()],
            top_k: vec!["payload.options.top_k".into()],
        },
        ..Default::default()
    });
    let scope = ChioScope {
        grants: vec![grant(vec![Constraint::MaxRowsReturned(50)])],
        ..Default::default()
    };
    let verdict = evaluate(
        &guard,
        "pinecone_query",
        serde_json::json!({
            "payload": {
                "index": "docs",
                "routing": {"namespace": "tenant-a"},
                "action": "query",
                "options": {"top_k": "10"}
            }
        }),
        scope,
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn allow_all_permits_any_vector_call() {
    let guard = VectorDbGuard::new(VectorGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "weaviate",
        serde_json::json!({
            "collection": "whatever",
            "operation": "upsert",
            "top_k": 50_000
        }),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn applies_operation_class_to_the_matched_grant_only() {
    let scope = ChioScope {
        grants: vec![
            grant(vec![Constraint::OperationClass(
                SqlOperationClass::ReadOnly,
            )]),
            grant(vec![Constraint::OperationClass(
                SqlOperationClass::ReadWrite,
            )]),
        ],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate_with_matched_grant(
        &guard,
        "weaviate",
        serde_json::json!({
            "collection": "docs",
            "operation": "upsert",
            "top_k": 1
        }),
        scope,
        Some(1),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn applies_max_rows_to_the_matched_grant_only() {
    let scope = ChioScope {
        grants: vec![
            grant(vec![Constraint::MaxRowsReturned(10)]),
            grant(vec![Constraint::MaxRowsReturned(500)]),
        ],
        ..Default::default()
    };
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate_with_matched_grant(
        &guard,
        "qdrant",
        serde_json::json!({
            "collection": "docs",
            "operation": "query",
            "top_k": 100
        }),
        scope,
        Some(1),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn allow_all_still_denies_malformed_vector_call() {
    let guard = VectorDbGuard::new(VectorGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "weaviate",
        serde_json::json!({
            "operation": "upsert",
            "top_k": 50_000
        }),
        ChioScope::default(),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn memory_read_action_routed_through_vector_guard() {
    // chio-guards maps `recall` into ToolAction::MemoryRead; the vector
    // guard must still be able to inspect it.
    let guard = VectorDbGuard::new(cfg_docs_only());
    let verdict = evaluate(
        &guard,
        "recall",
        // Must pick up "collection" and the tool name contains no vendor
        // marker, but the store field is "pinecone".
        serde_json::json!({
            "collection": "pinecone",
            "operation": "query",
            "top_k": 1
        }),
        ChioScope::default(),
    );
    // collection "pinecone" is not on the allowlist, so this is deny.
    assert_eq!(verdict, Verdict::Deny);
}
