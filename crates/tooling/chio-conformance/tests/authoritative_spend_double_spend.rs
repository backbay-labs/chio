//! Double-spend regression: atomic hold serialization on the integrated path;
//! the advisory path is the visible-failure witness.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::runtime::{ToolCallRequest, Verdict};
use std::sync::Arc;
use std::thread;

mod support;
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

#[test]
fn concurrent_calls_over_half_budget_yield_exactly_one_allow() {
    // max_total_cost = 100; each call worst-case = 60 (> N/2). Only one can win.
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 60, "USD")));
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 60, 100, "USD");
    let cap_id = cap.id.clone();
    let kernel = Arc::new(kernel);

    let mut handles = Vec::new();
    for i in 0..2 {
        let kernel = Arc::clone(&kernel);
        let cap = cap.clone();
        let agent_hex = agent.public_key().to_hex();
        handles.push(thread::spawn(move || {
            let request = ToolCallRequest {
                request_id: format!("req-concurrent-{i}"),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_hex,
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            };
            kernel
                .evaluate_tool_call_blocking(&request)
                .unwrap()
                .verdict
        }));
    }
    let verdicts: Vec<Verdict> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let allows = verdicts
        .iter()
        .filter(|v| matches!(v, Verdict::Allow))
        .count();
    let denies = verdicts
        .iter()
        .filter(|v| matches!(v, Verdict::Deny))
        .count();
    assert_eq!(allows, 1, "exactly one Allow on the atomic integrated path");
    assert_eq!(denies, 1, "the other must be Denied");

    // Total committed cost never exceeds N.
    let usage = budget.get_usage(&cap_id, 0).unwrap().unwrap();
    assert!(usage.committed_cost_units().unwrap() <= 100);
}

#[test]
fn advisory_path_double_authorizes_and_is_a_visible_failure() {
    // Two advisory "authorizations" move no ledger; both fail the predicate, so
    // treating either as authorization is a machine-visible conformance failure.
    let signer = Keypair::generate();
    let advisory_a = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    let advisory_b = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    let nonce = support::fake_bound_nonce(
        &signer,
        "cap-x",
        "cost-srv",
        "compute",
        &advisory_a.action.parameter_hash,
    );
    assert!(is_authoritative_spend_receipt(&advisory_a, &[signer.public_key()], &nonce).is_err());
    assert!(is_authoritative_spend_receipt(&advisory_b, &[signer.public_key()], &nonce).is_err());
}
