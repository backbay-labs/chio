//! Integration tests for `WarehouseCostGuard`.
//!
//! Drives the guard through the `chio_kernel::Guard` trait and verifies
//! that:
//!
//! - Query estimating 50 GiB scan denied when `max_bytes_scanned = 1 GiB`.
//! - Query estimating $0.25 allowed when `max_cost_per_query_usd = 5.00`.
//! - The guard emits `CostDimension::WarehouseQuery` with actual bytes
//!   and cost on allow paths.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_data_guards::{
    DryRunEstimate, WarehouseCostFieldPaths, WarehouseCostGuard, WarehouseCostGuardConfig,
};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use chio_metering::CostDimension;

fn make_request(
    tool: &str,
    args: serde_json::Value,
) -> (ChioScope, String, String, ToolCallRequest) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-warehouse".to_string();

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

    let request = ToolCallRequest {
        request_id: "req-wh".to_string(),
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

    (scope, agent_id, server_id, request)
}

fn evaluate(guard: &WarehouseCostGuard, tool: &str, args: serde_json::Value) -> Verdict {
    let (scope, agent_id, server_id, request) = make_request(tool, args);
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

fn limits_1gb_5usd() -> WarehouseCostGuardConfig {
    WarehouseCostGuardConfig {
        max_bytes_scanned: Some(1024u64 * 1024 * 1024),
        max_cost_per_query_usd: Some("5.00".into()),
        ..Default::default()
    }
}

#[test]
fn denies_50gb_scan_when_limit_is_1gb() {
    let guard = WarehouseCostGuard::new(limits_1gb_5usd());
    let verdict = evaluate(
        &guard,
        "bigquery",
        serde_json::json!({
            "query": "SELECT * FROM huge",
            "dry_run": {
                "bytes_scanned": 50u64 * 1024 * 1024 * 1024,
                "estimated_cost_usd": "0.25"
            }
        }),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn allows_query_estimating_25_cents_under_5_usd_limit() {
    let guard = WarehouseCostGuard::new(limits_1gb_5usd());
    let verdict = evaluate(
        &guard,
        "snowflake",
        serde_json::json!({
            "query": "SELECT id FROM small",
            "dry_run": {
                "bytes_scanned": 1024,
                "estimated_cost_usd": "0.25"
            }
        }),
    );
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn denies_query_above_cost_limit() {
    let guard = WarehouseCostGuard::new(WarehouseCostGuardConfig {
        max_cost_per_query_usd: Some("5.00".into()),
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "snowflake",
        serde_json::json!({
            "query": "SELECT 1",
            "dry_run": {"bytes_scanned": 0, "estimated_cost_usd": "100.00"}
        }),
    );
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn denies_missing_dry_run_metadata() {
    let guard = WarehouseCostGuard::new(limits_1gb_5usd());
    let verdict = evaluate(&guard, "bigquery", serde_json::json!({"query": "SELECT 1"}));
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn passes_through_non_warehouse_tools() {
    let guard = WarehouseCostGuard::new(limits_1gb_5usd());
    let verdict = evaluate(&guard, "postgres", serde_json::json!({"query": "SELECT 1"}));
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn allow_all_still_denies_missing_dry_run_metadata() {
    let guard = WarehouseCostGuard::new(WarehouseCostGuardConfig {
        allow_all: true,
        ..Default::default()
    });
    let verdict = evaluate(&guard, "bigquery", serde_json::json!({"query": "SELECT 1"}));
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn record_cost_emits_warehouse_query_dimension() {
    let estimate = DryRunEstimate {
        bytes_scanned: 1024 * 1024,
        estimated_cost_usd: "0.01".into(),
    };
    match WarehouseCostGuard::record_cost(&estimate) {
        CostDimension::WarehouseQuery {
            bytes_scanned,
            estimated_cost_usd,
        } => {
            assert_eq!(bytes_scanned, 1024 * 1024);
            assert_eq!(estimated_cost_usd, "0.01");
        }
        other => panic!("expected WarehouseQuery, got {other:?}"),
    }
}

#[test]
fn custom_field_paths_picked_up() {
    let guard = WarehouseCostGuard::new(WarehouseCostGuardConfig {
        field_paths: WarehouseCostFieldPaths {
            bytes_scanned: "bq_stats.total_bytes".into(),
            estimated_cost_usd: "bq_stats.usd".into(),
        },
        max_bytes_scanned: Some(100_000),
        ..Default::default()
    });
    let verdict = evaluate(
        &guard,
        "bigquery",
        serde_json::json!({
            "query": "SELECT id FROM small",
            "bq_stats": {"total_bytes": 1024, "usd": "0.00"}
        }),
    );
    assert_eq!(verdict, Verdict::Allow);
}
