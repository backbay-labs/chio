//! Threat test for threat ID `cumulative_data_exfiltration`.
//!
//! Coverage strategy: seed the session journal with cumulative read/write
//! totals and assert `DataFlowGuard` denies once the configured total ceiling
//! has been reached.
//!
//! Revert-to-prove-it-fails recipe: flip the `max_bytes_total`
//! `Ok(Verdict::Deny)` branch in `crates/chio-guards/src/data_flow.rs`
//! to `Ok(Verdict::Allow)`. The deny-arm assertion below fails when
//! the production guard stops denying once the cumulative ceiling is
//! reached.

use std::sync::Arc;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{DataFlowConfig, DataFlowGuard};
use chio_http_session::{RecordParams, SessionJournal};
use chio_kernel::{Guard, GuardContext, GuardDecision, ToolCallRequest, Verdict};

fn request_fixture() -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let body = CapabilityTokenBody {
        id: "cap-data-flow".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let token = match CapabilityToken::sign(body, &kp) {
        Ok(token) => token,
        Err(error) => panic!("capability fixture must sign: {error}"),
    };
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-data-flow".to_string();
    let request = ToolCallRequest {
        request_id: "req-data-flow".to_string(),
        capability: token,
        tool_name: "export_records".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: serde_json::json!({}),
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
    (request, scope, agent_id, server_id)
}

fn guard_ctx<'a>(
    request: &'a ToolCallRequest,
    scope: &'a ChioScope,
    agent_id: &'a String,
    server_id: &'a String,
) -> GuardContext<'a> {
    GuardContext {
        request,
        scope,
        agent_id,
        server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    }
}

fn verdict(result: Result<GuardDecision, chio_kernel::KernelError>) -> Verdict {
    match result {
        Ok(decision) => decision.verdict,
        Err(error) => panic!("guard evaluation must not error: {error}"),
    }
}

#[test]
fn threat_cumulative_data_exfiltration_is_covered() {
    // covers: cumulative_data_exfiltration
    let journal = Arc::new(SessionJournal::new("sess-exfil".to_string()));
    if let Err(error) = journal.record(RecordParams {
        tool_name: "export_records".to_string(),
        server_id: "srv-data-flow".to_string(),
        agent_id: "agent-a".to_string(),
        bytes_read: 700,
        bytes_written: 500,
        delegation_depth: 0,
        allowed: true,
    }) {
        panic!("journal fixture must record: {error}");
    }

    let guard = DataFlowGuard::new(
        journal,
        DataFlowConfig {
            max_bytes_read: None,
            max_bytes_written: None,
            max_bytes_total: Some(1_000),
        },
    );
    let (request, scope, agent_id, server_id) = request_fixture();
    let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
    assert_eq!(verdict(guard.evaluate(&ctx)), Verdict::Deny);
}
