use serde::{Deserialize, Serialize};

use super::{
    body::{chio_receipt_id, prepare_receipt_body_for_signing, ChioReceipt, ChioReceiptBody},
    checkpoint::{
        CheckpointPublicationIdentity, CheckpointPublicationIdentityKind,
        CheckpointPublicationTrustAnchorBinding, CheckpointTrustAnchorIdentity,
        CheckpointTrustAnchorIdentityKind,
    },
    crypto_floor::ReceiptCryptoFloor,
    decision::{Decision, ToolCallAction},
    economics::{
        EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
        EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
        EconomicBudgetReceiptMetadata, EconomicLiabilityReceiptMetadata,
        EconomicMerchantReceiptMetadata, EconomicMeteringReceiptMetadata,
        EconomicPayeeReceiptMetadata, EconomicPayerReceiptMetadata,
        EconomicPricingBasisReceiptMetadata, EconomicRailReceiptMetadata,
        EconomicSettlementReceiptMetadata, FinancialBudgetAuthorityReceiptMetadata,
        FinancialBudgetAuthorizeReceiptMetadata, FinancialBudgetHoldAuthorityMetadata,
        FinancialBudgetTerminalReceiptMetadata, FinancialReceiptMetadata, SettlementStatus,
    },
    governance::{
        GovernedApprovalReceiptMetadata, GovernedAutonomyReceiptMetadata,
        GovernedCommerceReceiptMetadata, GovernedTransactionReceiptMetadata,
        MeteredBillingReceiptMetadata, MeteredUsageEvidenceReceiptMetadata,
        RuntimeAssuranceReceiptMetadata,
    },
    kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    },
    lineage::{
        ChildRequestReceipt, ChildRequestReceiptBody, ReceiptLineageEndpoints,
        ReceiptLineageRelationKind, ReceiptLineageStatement, ReceiptLineageStatementBody,
        SignedExportEnvelope,
    },
    metadata::{ActorRef, GuardEvidence, ReceiptAttributionMetadata, ReceiptSemanticFields},
    signing::{
        bind_receipt_signing_nonce, BbsReceiptSignature, ChioReceiptSigningBody,
        ReceiptSigningHandle, CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1,
        CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1, CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM,
        CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA, CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
    },
};
use crate::capability::governance::{
    GovernedAutonomyTier, GovernedCallChainContext, GovernedCallChainEvidenceSource,
    GovernedCallChainProvenance, GovernedUpstreamCallChainProof,
    GovernedUpstreamCallChainProofBody, MeteredBillingQuote, MeteredSettlementMode,
};
use crate::capability::runtime_attestation::RuntimeAssuranceTier;
use crate::capability::scope::MonetaryAmount;
use crate::crypto::{sha256_hex, Keypair};
use crate::runtime_attestation::AttestationVerifierFamily;
use crate::session::{
    OperationKind, OperationTerminalState, RequestId, SessionAnchorReference, SessionId,
};

fn make_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({
        "path": "/app/src/main.rs"
    }))
    .unwrap()
}

fn make_receipt_body(kp: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-001".to_string(),
        timestamp: 1710000000,
        capability_id: "cap-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action: make_action(),
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "abc123def456".to_string(),
        evidence: vec![
            GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: None,
            },
            GuardEvidence {
                guard_name: "SecretLeakGuard".to_string(),
                verdict: true,
                details: Some("no secrets detected".to_string()),
            },
        ],
        metadata: Some(serde_json::json!({
            "sandbox": {
                "enforced": true
            }
        })),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    }
}

fn make_child_receipt_body(kp: &Keypair) -> ChildRequestReceiptBody {
    ChildRequestReceiptBody {
        id: "child-rcpt-001".to_string(),
        timestamp: 1710000001,
        session_id: SessionId::new("sess-001"),
        parent_request_id: RequestId::new("parent-001"),
        request_id: RequestId::new("child-001"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
        policy_hash: "abc123def456".to_string(),
        metadata: Some(serde_json::json!({
            "outcome": "result"
        })),
        kernel_key: kp.public_key(),
    }
}

fn bbs_signature_fixture() -> BbsReceiptSignature {
    BbsReceiptSignature {
        schema: CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA.to_string(),
        projection_version: CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string(),
        algorithm: CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM.to_string(),
        ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
        issuer_fingerprint: "issuer:chio:test-bbs".to_string(),
        issuer_public_key_hex: "11".repeat(96),
        message_count: CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1,
        signature_hex: "22".repeat(80),
    }
}

fn make_economic_authorization_receipt_metadata() -> EconomicAuthorizationReceiptMetadata {
    EconomicAuthorizationReceiptMetadata {
        version: EconomicAuthorizationReceiptMetadataVersion::V1,
        economic_mode: EconomicAuthorizationMode::MeteredHoldCapture,
        payer: EconomicPayerReceiptMetadata {
            party_id: "payer-001".to_string(),
            funding_source_ref: "wallet-001".to_string(),
            custody_provider: Some("custody.chio".to_string()),
            obligor_ref: Some("obligor-001".to_string()),
        },
        merchant: EconomicMerchantReceiptMetadata {
            merchant_id: "merchant-001".to_string(),
            merchant_of_record: Some("merchant-of-record-001".to_string()),
            order_ref: Some("order-001".to_string()),
        },
        payee: EconomicPayeeReceiptMetadata {
            beneficiary_id: "beneficiary-001".to_string(),
            settlement_destination_ref: "acct-settle-001".to_string(),
        },
        rail: EconomicRailReceiptMetadata {
            kind: "card".to_string(),
            asset: "USD".to_string(),
            network: Some("visa".to_string()),
            facilitator: Some("stripe".to_string()),
            contract_or_account_ref: Some("acct_1".to_string()),
        },
        amount_bounds: EconomicAmountBoundsReceiptMetadata {
            approved_max: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            hold_amount: Some(MonetaryAmount {
                units: 400,
                currency: "USD".to_string(),
            }),
            settlement_cap: MonetaryAmount {
                units: 450,
                currency: "USD".to_string(),
            },
        },
        pricing_basis: Some(EconomicPricingBasisReceiptMetadata {
            quote_hash: Some("quote-hash-001".to_string()),
            tariff_hash: Some("tariff-hash-001".to_string()),
            quote_expiry: Some(1_710_000_600),
        }),
        metering: Some(EconomicMeteringReceiptMetadata {
            provider: "meter.chio".to_string(),
            meter_profile_hash: "meter-profile-hash-001".to_string(),
            max_billable_units: Some(12),
            billing_unit: Some("1k_tokens".to_string()),
        }),
        liability_refs: Some(EconomicLiabilityReceiptMetadata {
            bond_id: Some("bond-001".to_string()),
            policy_id: Some("policy-001".to_string()),
            indemnity_ref: None,
            dispute_policy_ref: Some("dispute-policy-001".to_string()),
        }),
        budget: EconomicBudgetReceiptMetadata {
            grant_index: 3,
            cost_charged: 250,
            currency: "USD".to_string(),
            budget_remaining: 750,
            budget_total: 1000,
            delegation_depth: 2,
            root_budget_holder: "agent-root-001".to_string(),
            attempted_cost: None,
        },
        settlement: EconomicSettlementReceiptMetadata {
            settlement_status: SettlementStatus::Pending,
        },
    }
}

#[test]
fn receipt_sign_and_verify() {
    let kp = Keypair::generate();
    let body = make_receipt_body(&kp);
    let mut expected_body = body.clone();
    bind_receipt_signing_nonce(&mut expected_body);
    let expected_id = chio_receipt_id(&expected_body).unwrap();
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    assert_eq!(receipt.id, expected_id);
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_allowed());
    assert!(!receipt.is_denied());
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY))
            .and_then(serde_json::Value::as_str),
        Some("rcpt-001")
    );
}

#[test]
fn receipt_floor_rejects_ed25519_under_pq_required() {
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();

    let err = receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::PqRequired)
        .expect_err("ed25519 receipt must reject under pq_required");

    assert!(err.to_string().contains("crypto_floor=pq_required"));
    assert!(err.to_string().contains("ed25519"));
}

#[test]
fn receipt_floor_accepts_ed25519_under_allow_classical() {
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();

    assert!(receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowClassical)
        .unwrap());
}

#[cfg(feature = "pq")]
#[test]
fn receipt_floor_accepts_hybrid_under_pq_required() {
    use crate::crypto::{
        Ed25519Backend, HybridBackend, MlDsa65Backend, SigningAlgorithm, SigningBackend,
    };

    let kp = Keypair::generate();
    let seed = [7u8; 32];
    let pq = MlDsa65Backend::from_seed(&seed);
    let backend = HybridBackend::new(Box::new(Ed25519Backend::new(kp.clone())), pq).unwrap();
    let mut body = make_receipt_body(&kp);
    body.kernel_key = backend.public_key();
    let receipt = ChioReceipt::sign_with_backend(body, &backend).unwrap();

    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Hybrid);
    assert!(receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::PqRequired)
        .unwrap());
}

#[cfg(feature = "pq")]
#[test]
fn receipt_floor_rejects_hybrid_under_allow_classical() {
    use crate::crypto::{Ed25519Backend, HybridBackend, MlDsa65Backend, SigningBackend};

    let kp = Keypair::generate();
    let seed = [7u8; 32];
    let pq = MlDsa65Backend::from_seed(&seed);
    let backend = HybridBackend::new(Box::new(Ed25519Backend::new(kp.clone())), pq).unwrap();
    let mut body = make_receipt_body(&kp);
    body.kernel_key = backend.public_key();
    let receipt = ChioReceipt::sign_with_backend(body, &backend).unwrap();

    let err = receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowClassical)
        .expect_err("hybrid receipt must reject under allow_classical");

    assert!(err.to_string().contains("crypto_floor=allow_classical"));
    assert!(err.to_string().contains("hybrid"));
}

#[test]
fn receipt_id_is_authoritative_and_content_addressed() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.id = "caller-supplied-id-is-ignored".to_string();
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    assert_ne!(receipt.id, "caller-supplied-id-is-ignored");

    let mut tampered = receipt.clone();
    tampered.id = "not-the-content-address".to_string();
    assert!(!tampered.verify_signature().unwrap());
}

#[test]
fn receipt_signing_nonce_preserves_repeated_invocation_identity() {
    let kp = Keypair::generate();
    let mut first = make_receipt_body(&kp);
    let mut second = first.clone();
    first.id = "request-1".to_string();
    second.id = "request-2".to_string();

    let first_receipt = ChioReceipt::sign(first, &kp).unwrap();
    let second_receipt = ChioReceipt::sign(second, &kp).unwrap();

    assert_ne!(first_receipt.id, second_receipt.id);
    assert_eq!(
        first_receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY))
            .and_then(serde_json::Value::as_str),
        Some("request-1")
    );
    assert_eq!(
        second_receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY))
            .and_then(serde_json::Value::as_str),
        Some("request-2")
    );
    assert!(first_receipt.verify_signature().unwrap());
    assert!(second_receipt.verify_signature().unwrap());
}

#[test]
fn receipt_signature_binds_typed_id_and_body_wrapper() {
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();
    let body = receipt.body();
    let signing_body = ChioReceiptSigningBody::from(&body);

    assert_eq!(signing_body.id, receipt.id);
    assert_eq!(chio_receipt_id(&body).unwrap(), receipt.id);
    assert!(receipt
        .kernel_key
        .verify_canonical(&signing_body, &receipt.signature)
        .unwrap());
    assert!(!receipt
        .kernel_key
        .verify_canonical(&body, &receipt.signature)
        .unwrap());
}

#[test]
fn receipt_semantics_authorized_only_for_mediated_prevent_allow() {
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();

    let semantics = receipt.semantic_fields();

    assert_eq!(semantics.receipt_kind, ReceiptKind::MediatedDecision);
    assert_eq!(semantics.boundary_class, BoundaryClass::Prevent);
    assert_eq!(
        semantics.result_label(receipt.decision.as_ref()),
        "Authorized"
    );
    assert!(semantics.is_authorized(receipt.decision.as_ref()));
}

#[test]
fn receipt_semantics_are_signed_top_level_fields() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.actor_chain = vec![ActorRef {
        actor_id: "agent-001".to_string(),
        actor_kind: Some("agent".to_string()),
    }];
    let receipt = ChioReceipt::sign(body, &kp).unwrap();

    let json = serde_json::to_value(&receipt).unwrap();

    assert_eq!(json["receipt_kind"], "mediated_decision");
    assert_eq!(json["boundary_class"], "prevent");
    assert_eq!(json["tool_origin"], "caller_executed");
    assert_eq!(json["redaction_mode"], "none");
    assert_eq!(json["actor_chain"][0]["actor_id"], "agent-001");
    assert!(json
        .get("metadata")
        .and_then(|metadata| metadata.get("receipt_semantics"))
        .is_none());
}

#[test]
fn trace_and_advisory_semantics_cannot_authorize() {
    let trace = ReceiptSemanticFields {
        receipt_kind: ReceiptKind::TraceObservation,
        boundary_class: BoundaryClass::DetectOnly,
        observation_outcome: Some(ObservationOutcome::Observed),
        tool_origin: ToolOrigin::HostExecutedProviderReported,
        redaction_mode: RedactionMode::Summary,
        actor_chain: Vec::new(),
    };
    let advisory = ReceiptSemanticFields {
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::HostExecutedUnmediated,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: Vec::new(),
    };

    assert!(trace.validate_decision(Some(&Decision::Allow)).is_err());
    assert!(advisory
        .validate_decision(Some(&Decision::Deny {
            reason: "advisory finding".to_string(),
            guard: "AdvisoryGuard".to_string(),
        }))
        .is_err());
    assert!(!trace.is_authorized(Some(&Decision::Allow)));
    assert_eq!(trace.result_label(Some(&Decision::Allow)), "Observed");
    assert_eq!(advisory.result_label(Some(&Decision::Allow)), "Advisory");
}

#[test]
fn trace_receipt_omits_decision_field() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.decision = None;
    body.trust_level = TrustLevel::Verified;
    body.receipt_kind = ReceiptKind::TraceObservation;
    body.boundary_class = BoundaryClass::DetectOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.tool_origin = ToolOrigin::HostExecutedProviderReported;
    body.redaction_mode = RedactionMode::Summary;

    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    let json = serde_json::to_value(&receipt).unwrap();

    assert_eq!(json["receipt_kind"], "trace_observation");
    assert_eq!(json["boundary_class"], "detect_only");
    assert!(json.get("decision").is_none());
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn non_mediated_receipt_cannot_sign_any_decision() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.trust_level = TrustLevel::Verified;
    body.receipt_kind = ReceiptKind::TraceObservation;
    body.boundary_class = BoundaryClass::DetectOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.tool_origin = ToolOrigin::HostExecutedProviderReported;
    body.redaction_mode = RedactionMode::Summary;

    let err = ChioReceipt::sign(body, &kp).expect_err("trace decision must not sign");
    assert!(err.to_string().contains("trace_observation"));
}

#[test]
fn mediated_receipt_requires_decision() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.decision = None;

    let err = ChioReceipt::sign(body, &kp).expect_err("mediated receipt needs decision");
    assert!(err.to_string().contains("mediated_decision"));
}

#[test]
fn signed_export_envelope_roundtrip() {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct ExampleExport {
        schema: String,
        exported_at: u64,
    }

    let kp = Keypair::generate();
    let export = ExampleExport {
        schema: "chio.example-export.v1".to_string(),
        exported_at: 1_710_000_000,
    };
    let envelope = SignedExportEnvelope::sign(export.clone(), &kp).unwrap();
    assert_eq!(envelope.body, export);
    assert!(envelope.verify_signature().unwrap());
}

#[test]
fn receipt_deny_decision() {
    let kp = Keypair::generate();
    let body = ChioReceiptBody {
        decision: Some(Decision::Deny {
            reason: "path /etc/passwd is forbidden".to_string(),
            guard: "ForbiddenPathGuard".to_string(),
        }),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        ..make_receipt_body(&kp)
    };
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert!(!receipt.is_allowed());
}

#[test]
fn receipt_cancelled_decision() {
    let kp = Keypair::generate();
    let body = ChioReceiptBody {
        decision: Some(Decision::Cancelled {
            reason: "cancelled by user".to_string(),
        }),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        ..make_receipt_body(&kp)
    };
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_cancelled());
    assert!(!receipt.is_allowed());
    assert!(!receipt.is_denied());
}

#[test]
fn receipt_incomplete_decision() {
    let kp = Keypair::generate();
    let body = ChioReceiptBody {
        decision: Some(Decision::Incomplete {
            reason: "stream terminated before final frame".to_string(),
        }),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        ..make_receipt_body(&kp)
    };
    let receipt = ChioReceipt::sign(body, &kp).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_incomplete());
    assert!(!receipt.is_allowed());
    assert!(!receipt.is_denied());
}

#[test]
fn receipt_serde_roundtrip() {
    let kp = Keypair::generate();
    let body = make_receipt_body(&kp);
    let receipt = ChioReceipt::sign(body, &kp).unwrap();

    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let restored: ChioReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(receipt.id, restored.id);
    assert_eq!(receipt.capability_id, restored.capability_id);
    assert_eq!(receipt.tool_name, restored.tool_name);
    assert_eq!(receipt.content_hash, restored.content_hash);
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn receipt_round_trips_bbs_projection_metadata() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
    let bbs_signature = bbs_signature_fixture();

    let receipt = ChioReceipt::sign_with_bbs(body, &kp, bbs_signature.clone()).unwrap();
    assert_eq!(
        receipt.bbs_projection_version.as_deref(),
        Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1)
    );
    assert_eq!(
        receipt.body().bbs_projection_version.as_deref(),
        Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1)
    );
    assert_eq!(receipt.bbs_signature.as_ref(), Some(&bbs_signature));

    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let restored: ChioReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(
        restored.bbs_projection_version.as_deref(),
        Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1)
    );
    assert_eq!(
        restored.body().bbs_projection_version.as_deref(),
        Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1)
    );
    assert_eq!(restored.bbs_signature.as_ref(), Some(&bbs_signature));
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn sign_prepared_with_bbs_using_handle_rejects_render_a_sign_b() {
    // The older BBS prepared-signing entrypoint does not recompute content_hash.
    // A prepared body whose content_hash claims the hash of content B while the
    // handle is bound to content A MUST be refused before any signature is
    // produced.
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
    body.content_hash = sha256_hex(br#"{"signed":"B"}"#);
    let prepared = prepare_receipt_body_for_signing(body).unwrap();

    // Handle bound to content A, not the body's claimed hash of B.
    let handle = ReceiptSigningHandle::from_content_preimage(br#"{"shown":"A"}"#.to_vec());

    let result = ChioReceipt::sign_prepared_with_bbs_using_handle(
        prepared,
        &kp,
        bbs_signature_fixture(),
        handle,
    );
    assert!(
        result.is_err(),
        "render-A/sign-B must be refused at the prepared BBS signing boundary"
    );
}

#[test]
fn sign_prepared_with_bbs_using_handle_accepts_matching_content() {
    let kp = Keypair::generate();
    let content = br#"{"shown":"A"}"#;
    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
    body.content_hash = sha256_hex(content);
    let prepared = prepare_receipt_body_for_signing(body).unwrap();

    let handle = ReceiptSigningHandle::from_content_preimage(content.to_vec());

    let receipt = ChioReceipt::sign_prepared_with_bbs_using_handle(
        prepared,
        &kp,
        bbs_signature_fixture(),
        handle,
    )
    .unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.content_hash, sha256_hex(content));
}

#[test]
fn receipt_rejects_invalid_bbs_projection_bindings() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some("chio.bbs-projection.receipt.v999".to_string());
    let mut bbs_signature = bbs_signature_fixture();
    bbs_signature.projection_version = "chio.bbs-projection.receipt.v999".to_string();
    assert!(ChioReceipt::sign_with_bbs(body, &kp, bbs_signature).is_err());

    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
    let bbs_signature = bbs_signature_fixture();
    let mut receipt = ChioReceipt::sign_with_bbs(body, &kp, bbs_signature).unwrap();

    receipt.bbs_projection_version = None;
    assert!(!receipt.verify_signature().unwrap());

    receipt.bbs_projection_version = Some("chio.bbs-projection.receipt.v999".to_string());
    assert!(!receipt.verify_signature().unwrap());
}

#[test]
fn receipt_rejects_schema_invalid_bbs_signature_material() {
    let kp = Keypair::generate();
    let mut body = make_receipt_body(&kp);
    body.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());

    let mut wrong_ciphersuite = bbs_signature_fixture();
    wrong_ciphersuite.ciphersuite = "BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_".to_string();
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, wrong_ciphersuite).is_err());

    let mut short_public_key = bbs_signature_fixture();
    short_public_key.issuer_public_key_hex = "11".repeat(95);
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, short_public_key).is_err());

    let mut wrong_message_count = bbs_signature_fixture();
    wrong_message_count.message_count = CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1 + 1;
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, wrong_message_count).is_err());

    let mut whitespace_fingerprint = bbs_signature_fixture();
    whitespace_fingerprint.issuer_fingerprint = "issuer chio test-bbs".to_string();
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, whitespace_fingerprint).is_err());

    let mut empty_after_trim_fingerprint = bbs_signature_fixture();
    empty_after_trim_fingerprint.issuer_fingerprint = "   ".to_string();
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, empty_after_trim_fingerprint).is_err());

    let mut control_fingerprint = bbs_signature_fixture();
    control_fingerprint.issuer_fingerprint = "issuer:chio:\nkey".to_string();
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, control_fingerprint).is_err());

    let mut overlong_fingerprint = bbs_signature_fixture();
    overlong_fingerprint.issuer_fingerprint = "a".repeat(129);
    assert!(ChioReceipt::sign_with_bbs(body.clone(), &kp, overlong_fingerprint).is_err());

    let mut odd_length_signature = bbs_signature_fixture();
    odd_length_signature.signature_hex = "abc".to_string();
    assert!(ChioReceipt::sign_with_bbs(body, &kp, odd_length_signature).is_err());
}

#[test]
fn receipt_wrong_key_fails() {
    let kp = Keypair::generate();
    let other_kp = Keypair::generate();
    let body = make_receipt_body(&kp);
    let mut receipt = ChioReceipt::sign(body, &kp).unwrap();
    receipt.kernel_key = other_kp.public_key();
    // Tampering the embedded verifier key after signing should fail.
    assert!(!receipt.verify_signature().unwrap());
}

#[test]
fn tool_call_action_hash_verification() {
    let action = make_action();
    assert!(action.verify_hash().unwrap());
}

#[test]
fn tool_call_action_tampered_hash() {
    let mut action = make_action();
    action.parameter_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!action.verify_hash().unwrap());
}

#[test]
fn decision_serde_roundtrip() {
    let allow = Decision::Allow;
    let json = serde_json::to_string(&allow).unwrap();
    let restored: Decision = serde_json::from_str(&json).unwrap();
    assert_eq!(allow, restored);

    let deny = Decision::Deny {
        reason: "forbidden".to_string(),
        guard: "TestGuard".to_string(),
    };
    let json = serde_json::to_string(&deny).unwrap();
    let restored: Decision = serde_json::from_str(&json).unwrap();
    assert_eq!(deny, restored);

    let cancelled = Decision::Cancelled {
        reason: "cancelled by client".to_string(),
    };
    let json = serde_json::to_string(&cancelled).unwrap();
    let restored: Decision = serde_json::from_str(&json).unwrap();
    assert_eq!(cancelled, restored);

    let incomplete = Decision::Incomplete {
        reason: "stream ended early".to_string(),
    };
    let json = serde_json::to_string(&incomplete).unwrap();
    let restored: Decision = serde_json::from_str(&json).unwrap();
    assert_eq!(incomplete, restored);
}

#[test]
fn guard_evidence_serde_roundtrip() {
    let evidence = vec![
        GuardEvidence {
            guard_name: "Guard1".to_string(),
            verdict: true,
            details: None,
        },
        GuardEvidence {
            guard_name: "Guard2".to_string(),
            verdict: false,
            details: Some("blocked".to_string()),
        },
    ];

    let json = serde_json::to_string_pretty(&evidence).unwrap();
    let restored: Vec<GuardEvidence> = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence.len(), restored.len());
    assert_eq!(evidence[0].guard_name, restored[0].guard_name);
    assert_eq!(evidence[1].details, restored[1].details);
}

#[test]
fn child_receipt_sign_and_verify() {
    let kp = Keypair::generate();
    let body = make_child_receipt_body(&kp);
    let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.operation_kind, OperationKind::CreateMessage);
    assert_eq!(receipt.request_id, RequestId::new("child-001"));
}

#[test]
fn financial_receipt_metadata_serde_roundtrip() {
    let meta = FinancialReceiptMetadata {
        grant_index: 2,
        cost_charged: 150,
        currency: "USD".to_string(),
        budget_remaining: 850,
        budget_total: 1000,
        delegation_depth: 1,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: Some("ref-abc123".to_string()),
        settlement_status: SettlementStatus::Pending,
        cost_breakdown: Some(serde_json::json!({"compute": 100, "io": 50})),
        oracle_evidence: None,
        attempted_cost: None,
    };

    let json = serde_json::to_string(&meta).unwrap();
    let restored: FinancialReceiptMetadata = serde_json::from_str(&json).unwrap();

    assert_eq!(meta.grant_index, restored.grant_index);
    assert_eq!(meta.cost_charged, restored.cost_charged);
    assert_eq!(meta.currency, restored.currency);
    assert_eq!(meta.budget_remaining, restored.budget_remaining);
    assert_eq!(meta.budget_total, restored.budget_total);
    assert_eq!(meta.delegation_depth, restored.delegation_depth);
    assert_eq!(meta.root_budget_holder, restored.root_budget_holder);
    assert_eq!(meta.settlement_status, restored.settlement_status);
    assert_eq!(meta.payment_reference, restored.payment_reference);
    assert!(restored.attempted_cost.is_none());
}

#[test]
fn financial_receipt_metadata_under_financial_key() {
    let meta = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 200,
        currency: "USD".to_string(),
        budget_remaining: 800,
        budget_total: 1000,
        delegation_depth: 0,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Settled,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };

    let wrapped = serde_json::json!({"financial": meta});
    let extracted: FinancialReceiptMetadata =
        serde_json::from_value(wrapped["financial"].clone()).unwrap();
    assert_eq!(extracted.cost_charged, 200);
    assert_eq!(extracted.settlement_status, SettlementStatus::Settled);
}

#[test]
fn financial_receipt_metadata_attempted_cost_optional() {
    // With attempted_cost Some: field present in JSON
    let meta_with = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 0,
        currency: "USD".to_string(),
        budget_remaining: 0,
        budget_total: 1000,
        delegation_depth: 0,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::NotApplicable,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: Some(500),
    };
    let json_with = serde_json::to_string(&meta_with).unwrap();
    assert!(json_with.contains("attempted_cost"));

    // Without attempted_cost: field absent from JSON
    let meta_without = FinancialReceiptMetadata {
        attempted_cost: None,
        ..meta_with
    };
    let json_without = serde_json::to_string(&meta_without).unwrap();
    assert!(!json_without.contains("attempted_cost"));
}

#[test]
fn financial_budget_authority_metadata_serde_roundtrip() {
    let metadata = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: "budget-hold:req-1:cap-1:0".to_string(),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some("budget-hold:req-1:cap-1:0:authorize".to_string()),
            budget_commit_index: Some(41),
            exposure_units: 120,
            committed_cost_units_after: 120,
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: "reconciled".to_string(),
            event_id: Some("budget-hold:req-1:cap-1:0:reconcile".to_string()),
            budget_commit_index: Some(42),
            exposure_units: 120,
            realized_spend_units: 75,
            committed_cost_units_after: 75,
        }),
    };

    let json = serde_json::to_string(&metadata).unwrap();
    let restored: FinancialBudgetAuthorityReceiptMetadata = serde_json::from_str(&json).unwrap();

    assert_eq!(restored, metadata);
}

#[test]
fn checkpoint_publication_trust_anchor_binding_serde_and_validation() {
    let binding = CheckpointPublicationTrustAnchorBinding {
        publication_identity: CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::TransparencyService,
            "transparency.example/checkpoints/7",
        ),
        trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::Did,
            "did:chio:operator-root",
        ),
        trust_anchor_ref: "chio_checkpoint_witness_chain".to_string(),
        signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
        publication_profile_version: "phase4-preview.v1".to_string(),
    };

    let json = serde_json::to_string(&binding).unwrap();
    let restored: CheckpointPublicationTrustAnchorBinding = serde_json::from_str(&json).unwrap();

    restored.validate().unwrap();
    assert_eq!(restored, binding);
}

#[test]
fn checkpoint_publication_trust_anchor_binding_rejects_blank_fields() {
    let error = CheckpointPublicationTrustAnchorBinding {
        publication_identity: CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::TransparencyService,
            "",
        ),
        trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::Did,
            "did:chio:operator-root",
        ),
        trust_anchor_ref: " ".to_string(),
        signer_cert_ref: "did:web:chio.example#checkpoint-signer".to_string(),
        publication_profile_version: "phase4-preview.v1".to_string(),
    }
    .validate()
    .expect_err("blank trust anchor must be rejected");
    assert!(error.to_string().contains("publication_identity.identity"));
}

#[test]
fn chio_receipt_extracts_typed_financial_and_budget_authority_metadata() {
    let kp = Keypair::generate();
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 75,
        currency: "USD".to_string(),
        budget_remaining: 925,
        budget_total: 1000,
        delegation_depth: 1,
        root_budget_holder: "agent-root-001".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Settled,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };
    let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: "budget-hold:req-1:cap-1:0".to_string(),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some("budget-hold:req-1:cap-1:0:authorize".to_string()),
            budget_commit_index: Some(41),
            exposure_units: 120,
            committed_cost_units_after: 120,
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: "reconciled".to_string(),
            event_id: Some("budget-hold:req-1:cap-1:0:reconcile".to_string()),
            budget_commit_index: Some(42),
            exposure_units: 120,
            realized_spend_units: 75,
            committed_cost_units_after: 75,
        }),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            metadata: Some(serde_json::json!({
                "financial": financial.clone(),
                "budget_authority": budget_authority.clone(),
            })),
            ..make_receipt_body(&kp)
        },
        &kp,
    )
    .unwrap();

    let extracted_financial = receipt
        .financial_metadata()
        .expect("extract financial metadata");
    assert_eq!(extracted_financial.grant_index, financial.grant_index);
    assert_eq!(extracted_financial.cost_charged, financial.cost_charged);
    assert_eq!(extracted_financial.currency, financial.currency);
    assert_eq!(
        extracted_financial.budget_remaining,
        financial.budget_remaining
    );
    assert_eq!(extracted_financial.budget_total, financial.budget_total);
    assert_eq!(
        extracted_financial.root_budget_holder,
        financial.root_budget_holder
    );
    assert_eq!(
        receipt.financial_budget_authority_metadata(),
        Some(budget_authority)
    );
}

#[test]
fn settlement_status_serde_roundtrip() {
    let status = SettlementStatus::Failed;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"failed\"");
    let restored: SettlementStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, SettlementStatus::Failed);
}

#[test]
fn governed_transaction_receipt_metadata_serde_roundtrip() {
    let proof_signer = Keypair::generate();
    let proof_subject = Keypair::generate();
    let economic_authorization = make_economic_authorization_receipt_metadata();
    let metadata = GovernedTransactionReceiptMetadata {
        intent_id: "intent-1".to_string(),
        intent_hash: "intent-hash".to_string(),
        purpose: "pay supplier".to_string(),
        server_id: "payments".to_string(),
        tool_name: "charge".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        }),
        commerce: Some(GovernedCommerceReceiptMetadata {
            seller: "merchant.example".to_string(),
            shared_payment_token_id: "spt_123".to_string(),
        }),
        metered_billing: Some(MeteredBillingReceiptMetadata {
            settlement_mode: MeteredSettlementMode::AllowThenSettle,
            quote: MeteredBillingQuote {
                quote_id: "quote-1".to_string(),
                provider: "meter.chio".to_string(),
                billing_unit: "1k_tokens".to_string(),
                quoted_units: 10,
                quoted_cost: MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                },
                issued_at: 1000,
                expires_at: Some(1600),
            },
            max_billed_units: Some(12),
            usage_evidence: Some(MeteredUsageEvidenceReceiptMetadata {
                evidence_kind: "billing_export".to_string(),
                evidence_id: "usage-1".to_string(),
                observed_units: 9,
                evidence_sha256: Some("usage-digest".to_string()),
            }),
        }),
        approval: Some(GovernedApprovalReceiptMetadata {
            token_id: "approval-1".to_string(),
            approver_key: "approver-key".to_string(),
            approved: true,
        }),
        runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier_family: Some(AttestationVerifierFamily::AzureMaa),
            tier: RuntimeAssuranceTier::Attested,
            verifier: "verifier.chio".to_string(),
            evidence_sha256: "attestation-digest".to_string(),
            workload_identity: None,
        }),
        call_chain: Some(
            GovernedCallChainProvenance::observed(GovernedCallChainContext {
                chain_id: "chain-1".to_string(),
                parent_request_id: "req-parent-1".to_string(),
                parent_receipt_id: Some("rc-parent-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            })
            .with_upstream_proof(
                GovernedUpstreamCallChainProof::sign(
                    GovernedUpstreamCallChainProofBody {
                        signer: proof_signer.public_key(),
                        subject: proof_subject.public_key(),
                        chain_id: "chain-1".to_string(),
                        parent_request_id: "req-parent-1".to_string(),
                        parent_receipt_id: Some("rc-parent-1".to_string()),
                        origin_subject: "origin-subject".to_string(),
                        delegator_subject: "delegator-subject".to_string(),
                        issued_at: 1000,
                        expires_at: 1600,
                    },
                    &proof_signer,
                )
                .unwrap(),
            )
            .with_evidence_sources([
                GovernedCallChainEvidenceSource::SessionParentRequestLineage,
                GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
                GovernedCallChainEvidenceSource::UpstreamDelegatorProof,
            ]),
        ),
        autonomy: Some(GovernedAutonomyReceiptMetadata {
            tier: GovernedAutonomyTier::Delegated,
            delegation_bond_id: Some("bond-1".to_string()),
        }),
        economic_authorization: Some(economic_authorization.clone()),
    };

    let json = serde_json::to_string(&serde_json::json!({
        "governed_transaction": metadata.clone()
    }))
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let restored: GovernedTransactionReceiptMetadata =
        serde_json::from_value(value["governed_transaction"].clone()).unwrap();
    assert_eq!(restored, metadata);
}

#[test]
fn economic_authorization_receipt_metadata_serde_roundtrip() {
    let metadata = make_economic_authorization_receipt_metadata();
    let json = serde_json::to_value(&metadata).unwrap();
    let restored: EconomicAuthorizationReceiptMetadata = serde_json::from_value(json).unwrap();

    assert_eq!(restored, metadata);
    assert_eq!(
        restored.version,
        EconomicAuthorizationReceiptMetadataVersion::V1
    );
    assert_eq!(
        restored.settlement.settlement_status,
        SettlementStatus::Pending
    );
}

#[test]
fn receipt_lineage_statement_sign_and_verify() {
    let kp = Keypair::generate();
    let body = ReceiptLineageStatementBody::new(
        "statement-1",
        ReceiptLineageEndpoints::new(
            "receipt-parent-1",
            "receipt-child-1",
            RequestId::new("req-parent-1"),
            RequestId::new("req-child-1"),
            SessionAnchorReference::new("anchor-parent-1", "anchor-parent-hash-1"),
            SessionAnchorReference::new("anchor-child-1", "anchor-child-hash-1"),
        ),
        ReceiptLineageRelationKind::Continued,
        1_710_000_000,
        kp.public_key(),
    )
    .with_continuation_token_id("continuation-1");
    let statement = ReceiptLineageStatement::sign(body, &kp).unwrap();
    let encoded = serde_json::to_string(&statement).unwrap();
    let decoded: ReceiptLineageStatement = serde_json::from_str(&encoded).unwrap();

    assert!(decoded.verify_signature().unwrap());
    assert!(decoded.is_verified());
    assert_eq!(decoded.parent_receipt_id, "receipt-parent-1");
    assert_eq!(decoded.child_receipt_id, "receipt-child-1");
    assert_eq!(
        decoded.continuation_token_id.as_deref(),
        Some("continuation-1")
    );
}

#[test]
fn governed_transaction_receipt_metadata_helpers_split_asserted_and_verified_call_chain() {
    let asserted_context = GovernedCallChainContext {
        chain_id: "chain-1".to_string(),
        parent_request_id: "req-parent-1".to_string(),
        parent_receipt_id: Some("rc-parent-1".to_string()),
        origin_subject: "origin-asserted".to_string(),
        delegator_subject: "delegator-asserted".to_string(),
    };
    let verified_context = GovernedCallChainContext {
        chain_id: "chain-1".to_string(),
        parent_request_id: "req-parent-1".to_string(),
        parent_receipt_id: Some("rc-parent-1".to_string()),
        origin_subject: "origin-verified".to_string(),
        delegator_subject: "delegator-verified".to_string(),
    };
    let metadata = GovernedTransactionReceiptMetadata {
        intent_id: "intent-1".to_string(),
        intent_hash: "intent-hash".to_string(),
        purpose: "pay supplier".to_string(),
        server_id: "payments".to_string(),
        tool_name: "charge".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        approval: None,
        runtime_assurance: None,
        call_chain: Some(
            GovernedCallChainProvenance::verified(verified_context.clone())
                .with_asserted_context(asserted_context.clone()),
        ),
        autonomy: None,
        economic_authorization: None,
    };

    assert_eq!(metadata.asserted_call_chain(), Some(&asserted_context));
    assert_eq!(metadata.verified_call_chain(), Some(&verified_context));
}

#[test]
fn receipt_attribution_metadata_serde_roundtrip() {
    let metadata = ReceiptAttributionMetadata {
        subject_key: "subject-key".to_string(),
        issuer_key: "issuer-key".to_string(),
        delegation_depth: 2,
        grant_index: Some(1),
    };

    let json = serde_json::to_string(&metadata).unwrap();
    let restored: ReceiptAttributionMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, metadata);
}

#[test]
fn checkpoint_publication_and_trust_anchor_identities_roundtrip() {
    let publication_identity = CheckpointPublicationIdentity::new(
        CheckpointPublicationIdentityKind::TransparencyService,
        "transparency.example/checkpoints/7",
    );
    let trust_anchor_identity = CheckpointTrustAnchorIdentity::new(
        CheckpointTrustAnchorIdentityKind::Did,
        "did:chio:operator-root",
    );

    assert!(publication_identity.has_identity());
    assert!(trust_anchor_identity.has_identity());

    let encoded = serde_json::to_string(&serde_json::json!({
        "publication_identity": publication_identity.clone(),
        "trust_anchor_identity": trust_anchor_identity.clone(),
    }))
    .unwrap();
    let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    let restored_publication: CheckpointPublicationIdentity =
        serde_json::from_value(decoded["publication_identity"].clone()).unwrap();
    let restored_trust_anchor: CheckpointTrustAnchorIdentity =
        serde_json::from_value(decoded["trust_anchor_identity"].clone()).unwrap();

    assert_eq!(restored_publication, publication_identity);
    assert_eq!(restored_trust_anchor, trust_anchor_identity);
}

#[test]
fn child_receipt_serde_roundtrip() {
    let kp = Keypair::generate();
    let body = make_child_receipt_body(&kp);
    let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let restored: ChildRequestReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(receipt.id, restored.id);
    assert_eq!(receipt.parent_request_id, restored.parent_request_id);
    assert_eq!(receipt.outcome_hash, restored.outcome_hash);
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn ed25519_receipt_is_byte_identical_without_algorithm_field() {
    // Back-compat: a standard Ed25519 receipt must still serialize
    // without any `algorithm` envelope field. Persisted receipts from
    // earlier Chio releases decode cleanly (the `algorithm` field is
    // `#[serde(default)]`) and verify through the unchanged path.
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    assert!(
        value.get("algorithm").is_none(),
        "Ed25519 receipts must omit the `algorithm` envelope field"
    );
    // Simulate an old on-disk receipt by stripping any algorithm field we
    // might later add and ensure it still verifies.
    let wire = serde_json::to_string(&receipt).unwrap();
    let restored: ChioReceipt = serde_json::from_str(&wire).unwrap();
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn ed25519_receipt_without_algorithm_field_verifies() {
    // Generate an Ed25519 receipt, then assert that parsing its JSON (which
    // has no `algorithm` key) produces a receipt whose `algorithm` is
    // `None` and whose signature still verifies.
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(make_receipt_body(&kp), &kp).unwrap();
    let wire = serde_json::to_string(&receipt).unwrap();
    assert!(!wire.contains("\"algorithm\""));
    let restored: ChioReceipt = serde_json::from_str(&wire).unwrap();
    assert!(restored.algorithm.is_none());
    assert!(restored.verify_signature().unwrap());
}

#[cfg(feature = "fips")]
#[test]
fn receipt_signs_and_verifies_under_p256_backend() {
    use crate::crypto::{P256Backend, SigningAlgorithm, SigningBackend};
    let backend = P256Backend::generate().expect("p256 backend");
    let mut body = make_receipt_body(&Keypair::generate());
    body.kernel_key = backend.public_key();
    let receipt = ChioReceipt::sign_with_backend(body, &backend).unwrap();
    assert_eq!(receipt.algorithm, Some(SigningAlgorithm::P256));
    assert!(receipt.verify_signature().unwrap());
    // And through the wire.
    let wire = serde_json::to_string(&receipt).unwrap();
    assert!(wire.contains("\"p256:"));
    let restored: ChioReceipt = serde_json::from_str(&wire).unwrap();
    assert!(restored.verify_signature().unwrap());
}
