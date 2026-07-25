//! Threat test for threat ID `agent_velocity_abuse`.
//!
//! Coverage strategy: instantiate the in-tree `AgentVelocityGuard` with a
//! one-request per-agent ceiling and assert a repeated request for the same
//! agent denies while a different agent has an independent bucket.
//!
//! Revert-to-prove-it-fails recipe: flip the per-agent ceiling
//! `Ok(Verdict::Deny)` to `Ok(Verdict::Allow)` inside
//! `crates/chio-guards/src/agent_velocity.rs`. The deny-arm assertion
//! below fails when the production guard stops denying the second
//! request.

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{AgentVelocityConfig, AgentVelocityGuard};
use chio_kernel::{Guard, GuardContext, GuardDecision, ToolCallRequest, Verdict};

fn signed_cap(kp: &Keypair, cap_id: &str, scope: ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: cap_id.to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope,
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    match CapabilityToken::sign(body, kp) {
        Ok(token) => token,
        Err(error) => panic!("capability fixture must sign: {error}"),
    }
}

fn request_for(agent_id: &str, cap_id: &str) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let token = signed_cap(&kp, cap_id, scope.clone());
    let server_id = "srv-threat".to_string();
    let request = ToolCallRequest {
        request_id: format!("req-{agent_id}-{cap_id}"),
        capability: token,
        tool_name: "read_file".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.to_string(),
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
    (request, scope, agent_id.to_string(), server_id)
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
fn threat_agent_velocity_abuse_is_covered() {
    // covers: agent_velocity_abuse
    let guard = AgentVelocityGuard::new(AgentVelocityConfig {
        max_requests_per_agent: Some(1),
        max_requests_per_session: None,
        window_secs: 60,
        burst_factor: 1.0,
    });

    let (request, scope, agent, server) = request_for("agent-a", "cap-a");
    let ctx = guard_ctx(&request, &scope, &agent, &server);
    assert_eq!(verdict(guard.evaluate(&ctx)), Verdict::Allow);

    let (repeat_request, repeat_scope, repeat_agent, repeat_server) =
        request_for("agent-a", "cap-b");
    let repeat_ctx = guard_ctx(
        &repeat_request,
        &repeat_scope,
        &repeat_agent,
        &repeat_server,
    );
    assert_eq!(verdict(guard.evaluate(&repeat_ctx)), Verdict::Deny);

    let (other_request, other_scope, other_agent, other_server) = request_for("agent-b", "cap-c");
    let other_ctx = guard_ctx(&other_request, &other_scope, &other_agent, &other_server);
    assert_eq!(verdict(guard.evaluate(&other_ctx)), Verdict::Allow);
}
