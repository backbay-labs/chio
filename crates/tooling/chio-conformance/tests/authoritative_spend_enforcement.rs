//! Golden conformance gate for authoritative spend: the mediated path is authoritative,
//! the advisory path is not, and consuming an advisory receipt as authorization
//! is rejected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::runtime::ToolCallRequest;
use std::sync::Arc;

mod support;
use support::{
    advisory_receipt, issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer,
};

#[test]
fn mediated_receipt_is_authoritative_advisory_is_not() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");

    let request = ToolCallRequest {
        request_id: "req-golden".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({ "k": "v" }),
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
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let nonce = response
        .execution_nonce
        .as_ref()
        .expect("mediated allow mints a nonce");

    // Mediated path: authoritative.
    assert_eq!(
        is_authoritative_spend_receipt(&response.receipt, &[signer.public_key()], nonce.as_ref()),
        Ok(())
    );

    // Advisory path: an AdvisoryEvaluation receipt (built exactly like the
    // sidecar advisory handler) fails the predicate - the visible-failure witness.
    let advisory = advisory_receipt(&signer, &response.receipt);
    let result = is_authoritative_spend_receipt(&advisory, &[signer.public_key()], nonce.as_ref());
    assert!(
        result.is_err(),
        "advisory receipt must not be authoritative: {result:?}"
    );
}
