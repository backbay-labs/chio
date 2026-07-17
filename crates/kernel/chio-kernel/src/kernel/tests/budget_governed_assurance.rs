#[test]
fn governed_monetary_denial_without_required_runtime_assurance_releases_budget() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Attested,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-deny";
    let intent = make_governed_intent(
        "intent-governed-assurance-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("runtime attestation tier")),
        "denial should explain the missing runtime attestation"
    );
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    let usage = kernel

        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_request_denies_unverified_attestation_when_runtime_assurance_is_required() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Attested,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-allow";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-allow",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().is_some_and(|reason| {
            reason.contains("runtime attestation tier 'Attested' required by grant")
                && reason.contains("did not cross a local verified trust boundary")
        }),
        "denial should explain that raw attestation did not satisfy the local verified boundary"
    );
}

#[test]
fn governed_monetary_allow_omits_unverified_runtime_assurance_metadata_when_optional() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-optional";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-optional",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed.get("runtime_assurance"),
        None,
        "optional raw attestation should not be emitted as verified runtime authority"
    );
}

#[test]
fn governed_request_denies_conflicting_workload_identity_binding() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-workload-identity-deny";
    let mut intent = make_governed_intent(
        "intent-governed-workload-identity-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.enterprise-verifier.json.v1".to_string(),
        verifier: "https://attest.chio.example".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: current_unix_timestamp().saturating_sub(1),
        expires_at: current_unix_timestamp() + 300,
        evidence_sha256: "digest-invalid-workload".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: Some(chio_core::capability::workload_identity::WorkloadIdentity {
            scheme: chio_core::capability::workload_identity::WorkloadIdentityScheme::Spiffe,
            credential_kind: chio_core::capability::workload_identity::WorkloadCredentialKind::X509Svid,
            uri: "spiffe://other/runtime/test".to_string(),
            trust_domain: "other".to_string(),
            path: "/runtime/test".to_string(),
        }),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": "sha384:digest-invalid-workload"
            }
        })),
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1002" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("workload identity is invalid")),
        "denial should explain the workload-identity binding failure"
    );
}

#[test]
fn governed_monetary_allow_rebinds_trusted_attestation_to_verified() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1003" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(governed["runtime_assurance"]["verifierFamily"], "azure_maa");
    assert_eq!(
        governed["runtime_assurance"]["verifier"],
        "https://maa.contoso.test"
    );
    assert_eq!(
        governed["runtime_assurance"]["workloadIdentity"]["trustDomain"],
        "chio"
    );
}

#[test]
fn governed_request_denies_untrusted_attestation_when_trust_policy_is_configured() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-untrusted";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-untrusted",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    let mut attestation = make_trusted_azure_runtime_attestation();
    attestation.verifier = "https://maa.untrusted.test".to_string();
    intent.runtime_attestation = Some(attestation);
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1004" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().is_some_and(|reason| {
            reason.contains("rejected by local verification boundary")
                && reason.contains("did not match any trusted verifier rule")
        }),
        "denial should explain the local verification-boundary mismatch"
    );
}

#[test]
fn governed_monetary_allow_rebinds_google_attestation_to_verified() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-google-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-google-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_google_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1005" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(
        governed["runtime_assurance"]["verifierFamily"],
        "google_attestation"
    );
}

#[test]
fn governed_monetary_allow_rebinds_nitro_attestation_to_verified() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-nitro-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-nitro-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_nitro_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1006" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(governed["runtime_assurance"]["verifierFamily"], "aws_nitro");
    assert_eq!(
        governed["runtime_assurance"]["verifier"],
        "https://nitro.aws.example"
    );
    assert_eq!(
        governed["runtime_assurance"]["evidenceSha256"],
        "digest-nitro-attestation"
    );
}

#[test]
fn governed_request_denies_delegated_autonomy_without_bond_attachment() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-autonomy-missing-bond";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-missing-bond",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-1",
        "req-parent-1",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        None,
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-1" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| { reason.contains("requires a delegation bond attachment") }));
}

#[test]
fn governed_request_denies_autonomous_tier_with_weak_runtime_assurance() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attested_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Autonomous,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-autonomy-weak-assurance";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-weak-assurance",
        "cost-srv",
        "compute",
        "execute autonomous bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-2",
        "req-parent-2",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Autonomous,
        Some("bond-required"),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-2" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("runtime attestation tier 'Attested'")
            && reason.contains("below required 'Verified'")
    }));
}

#[test]
fn governed_request_denies_delegated_autonomy_with_expired_bond() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let path = unique_receipt_db_path("kernel-bond-expired");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let bond = make_credit_bond(CreditBondFixture {
        signer: &kernel.config.keypair,
        cap: &cap,
        server: "cost-srv",
        tool: "compute",
        disposition: CreditBondDisposition::Hold,
        lifecycle_state: CreditBondLifecycleState::Active,
        expires_at: current_unix_timestamp().saturating_sub(1),
        runtime_assurance_met: true,
    });
    let bond_id = bond.body.bond_id.clone();
    store
        .record_credit_bond(&bond, CreditBondLifecycleState::Active)
        .unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();

    let request_id = "req-governed-autonomy-expired-bond";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-expired-bond",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-3",
        "req-parent-3",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        Some(&bond_id),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-3" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("is expired")));
}

#[test]
fn governed_request_allows_delegated_autonomy_with_active_bond_and_receipt_metadata() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let path = unique_receipt_db_path("kernel-bond-active");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let bond = make_credit_bond(CreditBondFixture {
        signer: &kernel.config.keypair,
        cap: &cap,
        server: "cost-srv",
        tool: "compute",
        disposition: CreditBondDisposition::Hold,
        lifecycle_state: CreditBondLifecycleState::Active,
        expires_at: current_unix_timestamp() + 300,
        runtime_assurance_met: true,
    });
    let bond_id = bond.body.bond_id.clone();
    store
        .record_credit_bond(&bond, CreditBondLifecycleState::Active)
        .unwrap();
    kernel.set_receipt_store(Box::new(store)).unwrap();

    let request_id = "req-governed-autonomy-allow";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-allow",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-4",
        "req-parent-4",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        Some(&bond_id),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-4" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["autonomy"]["tier"], "delegated");
    assert_eq!(governed["autonomy"]["delegationBondId"], bond_id);
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
}

#[test]
fn governed_monetary_denial_without_approval_releases_budget_and_records_intent() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent = make_governed_intent(
        "intent-governed-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-deny".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("approval token required")),
        "denial should explain the missing approval token"
    );

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert!(governed["approval"].is_null());

    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let usage = kernel

        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata() {
    let mut config = make_monetary_config();
    config.max_stream_total_bytes = 1;

    let mut kernel = make_kernel(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![serde_json::json!({ "chunk": "governed-stream-payload" })],
    }));

    let grant = make_governed_monetary_grant("stream", "stream_file", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-incomplete";
    let intent = make_governed_intent(
        "intent-governed-incomplete",
        "stream",
        "stream_file",
        "stream governed artifact",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "stream_file".to_string(),
            server_id: "stream".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "path": "/tmp/governed.txt" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("incomplete receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("incomplete receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["approval"]["approved"], true);

    let financial = metadata
        .get("financial")
        .expect("incomplete receipt should retain financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(900));

    let stream = match response
        .output
        .expect("partial stream output should be preserved")
    {
        ToolCallOutput::Stream(stream) => Some(stream),
        ToolCallOutput::Value(_) => None,
    }
    .expect("expected streamed partial output");
    assert!(
        stream.chunks.is_empty(),
        "truncated stream should drop chunks once byte limit is exceeded"
    );
}

#[test]
fn governed_x402_prepaid_flow_records_governed_authorization_and_receipt_metadata() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        200,
        serde_json::json!({
            "authorizationId": "x402_txn_governed",
            "settled": true,
            "metadata": {
                "network": "base",
                "merchant": "pay-per-api"
            }
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        X402PaymentAdapter::new(url)
            .with_bearer_token("bridge-token")
            .with_timeout(Duration::from_secs(2)),
    )).expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-x402";
    let intent = make_governed_intent(
        "intent-governed-x402",
        "cost-srv",
        "compute",
        "purchase premium API result",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "dataset-pro" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token.clone()),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "tool should run after x402 authorization succeeds"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.starts_with("POST /authorize HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer bridge-token"));
    assert!(request.contains("\"amountUnits\":100"));
    assert!(request.contains("\"reference\":\"req-governed-x402\""));
    assert!(request.contains("\"governed\":{"));
    assert!(request.contains("\"intentId\":\"intent-governed-x402\""));
    assert!(request.contains("\"approvalTokenId\":\"approval-req-governed-x402\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "x402_txn_governed");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "x402_txn_governed"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "x402"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["merchant"],
        "pay-per-api"
    );

    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["approval"]["token_id"], approval_token.id);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_x402_authorization_failure_denies_before_tool_execution() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        402,
        serde_json::json!({
            "error": "insufficient funds"
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2)),
    )).expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-x402-deny";
    let intent = make_governed_intent(
        "intent-governed-x402-deny",
        "cost-srv",
        "compute",
        "purchase premium API result",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "dataset-pro" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payment authorization failed")),
        "denial should explain the x402 authorization failure"
    );
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when x402 authorization fails"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.contains("\"intentId\":\"intent-governed-x402-deny\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);

    let usage = kernel

        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_acp_hold_flow_records_commerce_scope_and_payment_metadata() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        200,
        serde_json::json!({
            "authorizationId": "acp_hold_governed",
            "settled": false,
            "metadata": {
                "provider": "stripe",
                "seller": "merchant.example"
            }
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        AcpPaymentAdapter::new(url)
            .with_authorize_path("/commerce/authorize")
            .with_bearer_token("acp-token")
            .with_timeout(Duration::from_secs(2)),
    )).expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "commerce-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_acp_monetary_grant(
        "commerce-srv",
        "compute",
        "merchant.example",
        100,
        1000,
        "USD",
        50,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-acp";
    let intent = make_governed_acp_intent(GovernedAcpIntentFixture {
        id: "intent-governed-acp",
        server: "commerce-srv",
        tool: "compute",
        purpose: "purchase seller-bound result",
        seller: "merchant.example",
        shared_payment_token_id: "spt_live_governed",
        units: 100,
        currency: "USD",
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "commerce-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token.clone()),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "tool should run after ACP authorization succeeds"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer acp-token"));
    assert!(request.contains("\"commerce\":{"));
    assert!(request.contains("\"seller\":\"merchant.example\""));
    assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_governed\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "acp_hold_governed");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "acp_hold_governed"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "acp"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "shared_payment_token_hold"
    );

    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["commerce"]["seller"], "merchant.example");
    assert_eq!(
        governed["commerce"]["shared_payment_token_id"],
        "spt_live_governed"
    );
    assert_eq!(governed["approval"]["token_id"], approval_token.id);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_acp_seller_mismatch_denies_before_payment_or_tool_execution() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        AcpPaymentAdapter::new("http://127.0.0.1:1").with_timeout(Duration::from_millis(50)),
    )).expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "commerce-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_acp_monetary_grant(
        "commerce-srv",
        "compute",
        "merchant.example",
        100,
        1000,
        "USD",
        50,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-acp-seller-mismatch";
    let intent = make_governed_acp_intent(GovernedAcpIntentFixture {
        id: "intent-governed-acp-seller-mismatch",
        server: "commerce-srv",
        tool: "compute",
        purpose: "attempt purchase for wrong seller",
        seller: "wrong-merchant.example",
        shared_payment_token_id: "spt_live_wrong",
        units: 100,
        currency: "USD",
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "commerce-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("seller")),
        "denial should explain the seller-scope mismatch"
    );
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when the seller scope does not match"
    );

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["commerce"]["seller"], "wrong-merchant.example");

    let usage = kernel

        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}
