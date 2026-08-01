use super::*;

pub(super) fn chio_swarm_runtime_request(
    args: serde_json::Value,
    bundle_hash: String,
    swarm_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let cap = capability("cap-live-1")?;
    Ok(ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: cap.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-live-1".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            purpose: "close governed vendor account".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioAdmission": {
                    "admissionId": "adm-live-1",
                    "bundleSha256": bundle_hash
                },
                "chioSwarm": swarm_context
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

pub(super) fn swarm_runtime_context(
    bundle: &SwarmAuthorityBundle,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::json!({
        "taskGraph": {
            "id": &bundle.task_graph.graph_id,
            "sha256": canonical_test_hash(&bundle.task_graph)?
        },
        "continuationToken": {
            "id": &bundle.continuation_tokens[0].token_id,
            "sha256": canonical_test_hash(&bundle.continuation_tokens[0])?
        },
        "routePlanReceipt": {
            "id": &bundle.route_plan_receipts[0].route_plan_id,
            "sha256": canonical_test_hash(&bundle.route_plan_receipts[0])?
        },
        "delegationWitness": {
            "id": &bundle.witness_chains[0].chain_id,
            "sha256": canonical_test_hash(&bundle.witness_chains[0])?
        },
        "joinReceipt": {
            "id": &bundle.join_receipts[0].join_id,
            "sha256": canonical_test_hash(&bundle.join_receipts[0])?
        },
        "revocationEpoch": {
            "id": &bundle.revocation_epoch.epoch_id,
            "sha256": canonical_test_hash(&bundle.revocation_epoch)?
        },
        "budgetPool": {
            "id": &bundle.budget_pool.pool_id,
            "sha256": canonical_test_hash(&bundle.budget_pool)?
        }
    }))
}
