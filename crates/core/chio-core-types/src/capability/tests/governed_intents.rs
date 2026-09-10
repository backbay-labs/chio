use super::*;

#[test]
fn governed_transaction_intent_binding_hash_changes_with_payload() {
    let base = GovernedTransactionIntent {
        id: "intent-1".to_string(),
        server_id: "srv-pay".to_string(),
        tool_name: "charge".to_string(),
        purpose: "pay supplier".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
        commerce: Some(GovernedCommerceContext {
            seller: "merchant.example".to_string(),
            shared_payment_token_id: "spt_123".to_string(),
            settlement_destination_ref: Some("acct:merchant-primary".to_string()),
        }),
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::AllowThenSettle,
            quote: MeteredBillingQuote {
                quote_id: "quote-1".to_string(),
                provider: "meter.chio".to_string(),
                billing_unit: "1k_tokens".to_string(),
                quoted_units: 12,
                quoted_cost: MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                },
                issued_at: 950,
                expires_at: Some(1300),
            },
            max_billed_units: Some(20),
            verified_outcome: None,
        }),
        runtime_attestation: Some(RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 900,
            expires_at: 1200,
            evidence_sha256: "attestation-digest".to_string(),
            runtime_identity: Some("spiffe://chio/runtime/123".to_string()),
            workload_identity: None,
            claims: None,
        }),
        call_chain: Some(GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        }),
        autonomy: Some(GovernedAutonomyContext {
            tier: GovernedAutonomyTier::Delegated,
            delegation_bond_id: Some("bond-1".to_string()),
        }),
        context: None,
        body: GovernedTransactionIntentBody::ToolInvocation,
    };
    let mut changed = base.clone();
    changed
        .call_chain
        .as_mut()
        .expect("call chain present")
        .parent_request_id = "req-parent-2".to_string();

    assert_ne!(
        base.binding_hash().unwrap(),
        changed.binding_hash().unwrap()
    );

    let mut changed_destination = base.clone();
    changed_destination
        .commerce
        .as_mut()
        .expect("commerce present")
        .settlement_destination_ref = Some("acct:merchant-substituted".to_string());
    assert_ne!(
        base.binding_hash().unwrap(),
        changed_destination.binding_hash().unwrap()
    );
}

#[test]
fn bound_tool_invocation_intent_hash_commits_canonical_parameters() {
    let arguments = serde_json::json!({"path": "/workspace/approved.txt", "content": "ok"});
    let parameters_hash = crate::hashing::sha256(&canonical_json_bytes(&arguments).unwrap());
    let mut wire = serde_json::json!({
        "id": "bound-intent-1",
        "server_id": "files",
        "tool_name": "write_file",
        "purpose": "write the reviewed file",
        "body": {
            "kind": "bound_tool_invocation",
            "value": {"capability_id": "cap-reviewed-1", "parameters_hash": parameters_hash}
        }
    });
    let intent: GovernedTransactionIntent = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        intent.body,
        GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: "cap-reviewed-1".to_string(),
            parameters_hash,
        }
    );
    assert_eq!(intent.governed_operation_expires_at(), None);
    assert_eq!(serde_json::to_value(&intent).unwrap(), wire);

    wire["body"]["value"]["capability_id"] = serde_json::json!("cap-reviewed-2");
    let changed_capability: GovernedTransactionIntent =
        serde_json::from_value(wire.clone()).unwrap();
    assert_ne!(
        intent.binding_hash().unwrap(),
        changed_capability.binding_hash().unwrap()
    );
    wire["body"]["value"]
        .as_object_mut()
        .unwrap()
        .remove("capability_id");
    assert!(serde_json::from_value::<GovernedTransactionIntent>(wire.clone()).is_err());
    wire["body"]["value"]["capability_id"] = serde_json::json!("cap-reviewed-1");

    wire["body"]["value"]["parameters_hash"] =
        serde_json::to_value(crate::hashing::sha256(b"different parameters")).unwrap();
    let changed: GovernedTransactionIntent = serde_json::from_value(wire.clone()).unwrap();
    assert_ne!(
        intent.binding_hash().unwrap(),
        changed.binding_hash().unwrap()
    );

    wire["body"]["value"]["parameters_hash"] = serde_json::json!("0x1234");
    assert!(serde_json::from_value::<GovernedTransactionIntent>(wire.clone()).is_err());

    wire.as_object_mut().unwrap().remove("body");
    let legacy: GovernedTransactionIntent = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(legacy.body, GovernedTransactionIntentBody::ToolInvocation);
    assert_eq!(serde_json::to_value(legacy).unwrap(), wire);
}
