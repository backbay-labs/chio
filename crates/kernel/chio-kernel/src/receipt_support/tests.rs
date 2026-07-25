use super::*;
use crate::operator_report::GovernedTransactionDiagnostics;
use crate::*;
use chio_core::capability::{
    governance::{
        GovernedCallChainContext, GovernedCallChainEvidenceSource, GovernedProvenanceEvidenceClass,
        GovernedTransactionIntent, GovernedUpstreamCallChainProof,
        GovernedUpstreamCallChainProofBody,
    },
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
    trust_policy::{AttestationTrustPolicy, AttestationTrustRule},
};
use chio_core::crypto::sha256_hex;

fn test_capability() -> CapabilityToken {
    let keypair = Keypair::generate();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .expect("test capability should sign")
}

fn trusted_attestation_trust_policy() -> AttestationTrustPolicy {
    AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "azure-contoso".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(120),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: std::collections::BTreeMap::new(),
        }],
    }
}

fn raw_runtime_attestation() -> RuntimeAttestationEvidence {
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: sha256_hex(b"raw-runtime-attestation"),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: None,
    }
}

fn trusted_runtime_attestation() -> RuntimeAttestationEvidence {
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: sha256_hex(b"trusted-runtime-attestation"),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn trusted_nitro_attestation_trust_policy() -> AttestationTrustPolicy {
    AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "aws-nitro".to_string(),
            schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
            verifier: "https://nitro.aws.example".to_string(),
            effective_tier: RuntimeAssuranceTier::Verified,
            verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro),
            max_evidence_age_seconds: Some(120),
            allowed_attestation_types: Vec::new(),
            required_assertions: std::collections::BTreeMap::new(),
        }],
    }
}

fn trusted_nitro_runtime_attestation() -> RuntimeAttestationEvidence {
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
        verifier: "https://nitro.aws.example/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: sha256_hex(b"trusted-nitro-runtime-attestation"),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "awsNitro": {
                "moduleId": "nitro-enclave-1",
                "digest": "sha384:aws-measurement",
                "pcrs": { "0": "0123" }
            }
        })),
    }
}

#[test]
fn governed_request_metadata_preserves_asserted_call_chain_and_diagnostics() {
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-1".to_string(),
        parent_request_id: "req-parent-1".to_string(),
        parent_receipt_id: Some("rcpt-parent-1".to_string()),
        origin_subject: "origin-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
    };
    let request = ToolCallRequest {
        request_id: "req-current-1".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(call_chain.clone()),
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let metadata = governed_request_metadata(&request, None, 0)
        .expect("metadata should build")
        .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");
    let governed_call_chain = governed
        .call_chain
        .expect("asserted call-chain should remain visible on the signed receipt");
    assert_eq!(
        governed_call_chain.evidence_class,
        GovernedProvenanceEvidenceClass::Asserted
    );
    assert_eq!(
        metadata["governed_transaction_diagnostics"]["assertedCallChain"]["evidenceClass"],
        serde_json::json!("asserted")
    );
    assert_eq!(
        metadata["governed_transaction_diagnostics"]["assertedCallChain"]["chainId"],
        serde_json::json!("chain-1")
    );
    assert_eq!(
        metadata["governed_transaction_diagnostics"]["assertedCallChain"]["parentRequestId"],
        serde_json::json!("req-parent-1")
    );
    let diagnostics: GovernedTransactionDiagnostics =
        serde_json::from_value(metadata["governed_transaction_diagnostics"].clone())
            .expect("diagnostics should deserialize");
    let provenance = diagnostics
        .asserted_call_chain
        .expect("asserted call-chain should be preserved in diagnostics");
    assert_eq!(
        provenance.evidence_class,
        GovernedProvenanceEvidenceClass::Asserted
    );
    assert!(provenance.evidence_sources.is_empty());
    assert_eq!(provenance.into_inner(), call_chain);
}

#[test]
fn governed_request_metadata_marks_matching_local_call_chain_evidence_as_observed() {
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-2".to_string(),
        parent_request_id: "req-parent-2".to_string(),
        parent_receipt_id: Some("rcpt-parent-2".to_string()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let request = ToolCallRequest {
        request_id: "req-current-2".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-2" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-2".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(call_chain.clone()),
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let _scope =
        scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
            local_parent_request_id: Some("req-parent-2".to_string()),
            local_parent_receipt_id: Some("rcpt-parent-2".to_string()),
            capability_delegator_subject: Some("subject-delegator".to_string()),
            capability_origin_subject: Some("subject-origin".to_string()),
            upstream_proof: None,
            continuation_token_id: None,
            session_anchor_id: None,
        }));

    let metadata = governed_request_metadata(&request, None, 0)
        .expect("metadata should build")
        .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");
    let provenance = governed
        .call_chain
        .expect("call-chain provenance should be present");

    assert_eq!(
        provenance.evidence_class,
        GovernedProvenanceEvidenceClass::Observed
    );
    assert_eq!(
        provenance.evidence_sources,
        vec![
            GovernedCallChainEvidenceSource::SessionParentRequestLineage,
            GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
            GovernedCallChainEvidenceSource::CapabilityDelegatorSubject,
            GovernedCallChainEvidenceSource::CapabilityOriginSubject,
        ]
    );
    assert_eq!(provenance.into_inner(), call_chain);
    assert!(metadata.get("governed_transaction_diagnostics").is_none());
}

#[test]
fn governed_request_metadata_marks_validated_upstream_call_chain_proof_as_verified() {
    let signer = Keypair::generate();
    let subject = Keypair::generate();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-verified".to_string(),
        parent_request_id: "req-parent-verified".to_string(),
        parent_receipt_id: Some("rcpt-parent-verified".to_string()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let upstream_proof = GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: subject.public_key(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            delegator_subject: call_chain.delegator_subject.clone(),
            issued_at: 100,
            expires_at: 200,
        },
        &signer,
    )
    .expect("upstream proof should sign");
    let request = ToolCallRequest {
        request_id: "req-current-verified".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-verified" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-verified".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(call_chain.clone()),
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let _scope =
        scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
            local_parent_request_id: None,
            local_parent_receipt_id: None,
            capability_delegator_subject: None,
            capability_origin_subject: None,
            upstream_proof: Some(upstream_proof.clone()),
            continuation_token_id: Some("continuation-verified".to_string()),
            session_anchor_id: Some("anchor-verified".to_string()),
        }));

    let metadata = governed_request_metadata(&request, None, 0)
        .expect("metadata should build")
        .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");
    let provenance = governed
        .call_chain
        .expect("call-chain provenance should be present");

    assert_eq!(
        provenance.evidence_class,
        GovernedProvenanceEvidenceClass::Verified
    );
    assert_eq!(
        provenance.evidence_sources,
        vec![GovernedCallChainEvidenceSource::UpstreamDelegatorProof]
    );
    assert_eq!(provenance.upstream_proof, Some(upstream_proof));
    assert_eq!(
        provenance.continuation_token_id.as_deref(),
        Some("continuation-verified")
    );
    assert_eq!(
        provenance.session_anchor_id.as_deref(),
        Some("anchor-verified")
    );
    assert_eq!(provenance.into_inner(), call_chain);
    assert_eq!(
        metadata["governed_transaction_diagnostics"]["lineageReferences"]["sessionAnchorId"],
        serde_json::json!("anchor-verified")
    );
    assert!(metadata["governed_transaction_diagnostics"]["assertedCallChain"].is_null());
}

#[test]
fn governed_request_metadata_omits_unverified_runtime_assurance() {
    let request = ToolCallRequest {
        request_id: "req-current-3".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-3" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-3".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: Some(raw_runtime_attestation()),
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let metadata = governed_request_metadata(&request, None, 150)
        .expect("metadata should build")
        .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");

    assert!(
        governed.runtime_assurance.is_none(),
        "raw runtime attestation should not appear as verified receipt authority"
    );
}

#[test]
fn governed_request_metadata_uses_verified_runtime_assurance_boundary() {
    let request = ToolCallRequest {
        request_id: "req-current-4".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-4" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-4".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: Some(trusted_runtime_attestation()),
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let metadata =
        governed_request_metadata(&request, Some(&trusted_attestation_trust_policy()), 150)
            .expect("metadata should build")
            .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");
    let runtime_assurance = governed
        .runtime_assurance
        .expect("verified runtime assurance should be present");

    assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
    assert_eq!(
        runtime_assurance.verifier_family,
        Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
    );
    assert_eq!(runtime_assurance.verifier, "https://maa.contoso.test");
    assert_eq!(
        runtime_assurance
            .workload_identity
            .expect("verified workload identity should be present")
            .trust_domain,
        "chio"
    );
}

#[test]
fn governed_request_metadata_prefers_scoped_nitro_verified_record() {
    let attestation = trusted_nitro_runtime_attestation();
    let verified_runtime_attestation = verify_governed_runtime_attestation_record(
        &attestation,
        Some(&trusted_nitro_attestation_trust_policy()),
        150,
    )
    .expect("nitro attestation should verify at governed admission");
    let request = ToolCallRequest {
        request_id: "req-current-nitro".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-nitro" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-nitro".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: Some(attestation),
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let _scope =
        scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

    let metadata = governed_request_metadata(&request, None, 150)
        .expect("metadata should build")
        .expect("governed metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("receipt metadata should deserialize");
    let runtime_assurance = governed
        .runtime_assurance
        .expect("scoped verified runtime assurance should be present");

    assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
    assert_eq!(
        runtime_assurance.verifier_family,
        Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro)
    );
    assert_eq!(runtime_assurance.verifier, "https://nitro.aws.example");
    assert_eq!(
        runtime_assurance.evidence_sha256,
        sha256_hex(b"trusted-nitro-runtime-attestation")
    );
}

#[test]
fn governed_request_metadata_rejects_mismatched_scoped_runtime_attestation_record() {
    let attestation = trusted_nitro_runtime_attestation();
    let verified_runtime_attestation = verify_governed_runtime_attestation_record(
        &attestation,
        Some(&trusted_nitro_attestation_trust_policy()),
        150,
    )
    .expect("nitro attestation should verify at governed admission");
    let mut mismatched_attestation = attestation.clone();
    mismatched_attestation.evidence_sha256 = sha256_hex(b"mismatched-nitro-runtime-attestation");
    let request = ToolCallRequest {
        request_id: "req-current-nitro-mismatch".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-nitro-mismatch" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-nitro-mismatch".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: Some(mismatched_attestation),
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let _scope =
        scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

    let error = governed_request_metadata(&request, None, 150)
        .expect_err("mismatched scoped runtime attestation should fail closed");
    assert!(
            error.to_string().contains(
                "governed request runtime attestation does not match the scoped verified runtime attestation record"
            ),
            "expected mismatch error, got {error}"
        );
}

#[test]
fn request_receipt_metadata_omits_economic_authorization_without_verified_payee_binding() {
    let request = ToolCallRequest {
        request_id: "req-economic-1".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-economic-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-economic-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: Some(chio_core::capability::scope::MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            commerce: Some(chio_core::capability::governance::GovernedCommerceContext {
                seller: "seller-1".to_string(),
                shared_payment_token_id: "shared-token-1".to_string(),
                settlement_destination_ref: Some("acct:seller-1".to_string()),
            }),
            metered_billing: Some(chio_core::capability::governance::MeteredBillingContext {
                settlement_mode:
                    chio_core::capability::governance::MeteredSettlementMode::HoldCapture,
                quote: chio_core::capability::governance::MeteredBillingQuote {
                    quote_id: "quote-1".to_string(),
                    provider: "meterd".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 42,
                    quoted_cost: chio_core::capability::scope::MonetaryAmount {
                        units: 230,
                        currency: "USD".to_string(),
                    },
                    issued_at: 100,
                    expires_at: Some(200),
                },
                max_billed_units: Some(100),
                verified_outcome: None,
            }),
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let extra_metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 1,
            cost_charged: 230,
            currency: "USD".to_string(),
            budget_remaining: 770,
            budget_total: 1000,
            delegation_depth: 0,
            root_budget_holder: "issuer-1".to_string(),
            payment_reference: Some("payref-1".to_string()),
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(250),
        }
    });

    let metadata = request_receipt_metadata(&request, None, 150, Some(&extra_metadata))
        .expect("metadata should build")
        .expect("receipt metadata should exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("governed metadata should deserialize");
    assert!(governed.economic_authorization.is_none());
}

#[test]
fn request_receipt_metadata_treats_untyped_financial_extra_metadata_as_pass_through() {
    let request = ToolCallRequest {
        request_id: "req-economic-legacy-financial".to_string(),
        capability: test_capability(),
        tool_name: "charge".to_string(),
        server_id: "srv-pay".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "invoice_id": "inv-legacy-financial" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-legacy-financial".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let extra_metadata = serde_json::json!({
        "financial": {
            "legacy_payload": true,
            "vendor": "custom-financial-metadata"
        }
    });

    let metadata = request_receipt_metadata(&request, None, 150, Some(&extra_metadata))
        .expect("legacy financial metadata should not fail receipt metadata")
        .expect("governed metadata should still exist");
    let governed: GovernedTransactionReceiptMetadata =
        serde_json::from_value(metadata["governed_transaction"].clone())
            .expect("governed metadata should deserialize");

    assert!(governed.economic_authorization.is_none());
}
