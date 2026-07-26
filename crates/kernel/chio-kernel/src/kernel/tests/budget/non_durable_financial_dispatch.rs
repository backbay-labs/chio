use super::*;

#[test]
fn non_durable_monetary_kernel_denies_before_ambiguous_dispatch() {
    // A non-durable monetary kernel must reverse the provisional budget hold and
    // deny before dispatch. It therefore cannot reach RequestIncomplete or add
    // an unrecoverable retained-hold sample.
    let mut kernel = ChioKernel::new(make_monetary_config());
    assert!(kernel.durable_admission_runtime.is_none());
    kernel.register_tool_server(Box::new(IncompleteServer {
        id: "broken".to_string(),
    }));
    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("broken", "drop_stream", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let before = ambiguous_retained_hold_none_sample();
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-ambiguous-incomplete".to_string(),
            capability: cap,
            tool_name: "drop_stream".to_string(),
            server_id: "broken".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
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
        })
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("requires durable admission coverage")),
        "the denial must identify the missing financial durability boundary: {:?}",
        response.reason
    );

    let after = ambiguous_retained_hold_none_sample();
    assert_eq!(
        after, before,
        "pre-dispatch denial must not record an ambiguous retained hold"
    );
    let usage = kernel
        .budget_store
        .get_usage(&response.receipt.capability_id, 0)
        .unwrap()
        .expect("the reversible mutation history retains a zeroed usage projection");
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 0);
}
