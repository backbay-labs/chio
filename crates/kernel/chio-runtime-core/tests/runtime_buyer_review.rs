use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::{
    bilateral_dsse::sign_chio_bilateral_dsse_envelope,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_dsse::TreatyBindingRef, bilateral_dsse::PAYLOAD_TYPE_IN_TOTO,
};
use chio_runtime_core::{
    bilateral_dsse_consistency_model as dsse_consistency_model, tool_args_sha256,
    verify_buyer_attestation_packet, verify_buyer_attestation_review_package_with_trust,
    verify_receipt_lineage_bundle, BilateralInvocation, BuyerAttestationPacket,
    BuyerAttestationReviewArtifactRef, BuyerAttestationReviewPackage, BuyerAttestationReviewReport,
    BuyerAttestationReviewSource, BuyerAttestationReviewTrustContext, ChioRuntimeError,
    CrossBoundaryAdmissionReport, CrossBoundaryEvidenceRef, CrossKernelContinuation,
    ReceiptLineageBundle, ReceiptLineageStatement, RuntimeEvidenceManifest,
    RuntimeEvidenceManifestEntry, RuntimeProofRegenerationInput, RuntimeProofRegenerationReport,
    RuntimeProofSourceRecord, RuntimeStepEvidence, RuntimeWorkflowRunReport,
    CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_BUYER_ATTESTATION_PACKET_SCHEMA,
    CHIO_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA, CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA,
    CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
    CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA, CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
    CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA, CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
};
use std::io;

#[test]
fn buyer_attestation_packet_preserves_verified_lineage_boundary_without_accepting_unresolved_dsse(
) -> Result<(), Box<dyn std::error::Error>> {
    let (packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;

    let unresolved =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    assert!(!unresolved.accepted);
    assert_eq!(
        unresolved.failure_code.as_deref(),
        Some("chio_buyer_packet_dsse_unresolved")
    );
    assert_eq!(unresolved.verification_state, "unresolved");

    let mut asserted = lineage.clone();
    asserted.evidence_class = "asserted".to_string();
    let denied =
        verify_buyer_attestation_packet(&packet, &asserted, &continuation, &admission, &bilateral)?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_lineage_not_verified")
    );
    assert_eq!(denied.verification_state, "rejected");

    let mut mismatched = packet.clone();
    mismatched.bilateral_invocation_sha256 = "b".repeat(64);
    let denied = verify_buyer_attestation_packet(
        &mismatched,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_hash_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_hash_only_packet_rejects_unresolved_dsse_hash() -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    packet.bilateral_dsse_sha256 = "f".repeat(64);

    let denied =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;

    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_dsse_unresolved")
    );
    assert_eq!(denied.verification_state, "unresolved");
    Ok(())
}

#[test]
fn buyer_hash_only_packet_rejects_claimed_admission_dsse_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let (packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;

    let denied =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;

    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_dsse_unresolved")
    );
    assert_eq!(denied.verification_state, "unresolved");
    Ok(())
}

#[test]
fn buyer_attestation_packet_binds_buyer_to_lineage_source() -> Result<(), Box<dyn std::error::Error>>
{
    let (packet, mut lineage, continuation, admission, bilateral) = buyer_fixture()?;

    let mut wrong_buyer = packet.clone();
    wrong_buyer.buyer_id = "kernel.attacker".to_string();
    let denied = verify_buyer_attestation_packet(
        &wrong_buyer,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
    )?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_identity_mismatch")
    );

    lineage.source_kernel_id = "kernel.attacker".to_string();
    let denied =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_packet_identity_mismatch")
    );
    Ok(())
}

fn insert_review_source<T: serde::Serialize>(
    sources: &mut Vec<BuyerAttestationReviewSource>,
    role: &str,
    artifact: &T,
) -> Result<BuyerAttestationReviewArtifactRef, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(artifact)?;
    let artifact_sha256 = chio_core_types::crypto::sha256_hex(&bytes);
    let artifact_ref = BuyerAttestationReviewArtifactRef {
        role: role.to_string(),
        relative_path: format!("{role}.json"),
        artifact_sha256,
        byte_count: bytes.len() as u64,
    };
    sources.push(BuyerAttestationReviewSource {
        role: artifact_ref.role.clone(),
        relative_path: artifact_ref.relative_path.clone(),
        bytes,
    });
    Ok(artifact_ref)
}

fn review_manifest_entry<T: serde::Serialize>(
    role: &str,
    path: &str,
    artifact: &T,
) -> Result<RuntimeEvidenceManifestEntry, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(artifact)?;
    Ok(RuntimeEvidenceManifestEntry {
        role: role.to_string(),
        path: path.to_string(),
        sha256: chio_core_types::crypto::sha256_hex(&bytes),
        byte_count: bytes.len() as u64,
    })
}

fn replace_review_source<T: serde::Serialize>(
    package: &mut BuyerAttestationReviewPackage,
    sources: &mut [BuyerAttestationReviewSource],
    role: &str,
    artifact: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(artifact)?;
    let source = sources
        .iter_mut()
        .find(|source| source.role == role)
        .ok_or_else(|| io::Error::other(format!("missing {role} source")))?;
    source.bytes = bytes.clone();
    let artifact_ref = package
        .artifacts
        .iter_mut()
        .find(|artifact_ref| artifact_ref.role == role)
        .ok_or_else(|| io::Error::other(format!("missing {role} artifact ref")))?;
    artifact_ref.artifact_sha256 = chio_core_types::crypto::sha256_hex(&bytes);
    artifact_ref.byte_count = bytes.len() as u64;
    Ok(())
}

type BuyerFixture = (
    BuyerAttestationPacket,
    ReceiptLineageStatement,
    CrossKernelContinuation,
    CrossBoundaryAdmissionReport,
    BilateralInvocation,
);

fn strict_dsse_fixture_receipt(
    capability_id: &str,
    signer_b: &Keypair,
    receipt_action: Option<ToolCallAction>,
) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    strict_dsse_fixture_receipt_with_id("rcpt-treaty-dsse", capability_id, signer_b, receipt_action)
}

fn strict_dsse_fixture_receipt_with_id(
    receipt_id: &str,
    capability_id: &str,
    signer: &Keypair,
    receipt_action: Option<ToolCallAction>,
) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_800_000_010,
            capability_id: capability_id.to_string(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: receipt_action.unwrap_or(ToolCallAction::from_parameters(serde_json::json!({
                "record": "vendor-ledger-7",
                "value": "closed"
            }))?),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:chio-runtime/buyer-review".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: "c".repeat(64),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        signer,
    )
    .map_err(Into::into)
}

fn buyer_fixture() -> Result<BuyerFixture, Box<dyn std::error::Error>> {
    let default_buyer_key = Keypair::from_seed(&[1; 32]);
    let default_vendor_key = Keypair::from_seed(&[2; 32]);
    let default_parent_receipt = strict_dsse_fixture_receipt_with_id(
        "rcpt-parent-local",
        "cap-live-1",
        &default_buyer_key,
        None,
    )?;
    let default_parent_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&default_parent_receipt)?,
    );
    let default_child_receipt =
        strict_dsse_fixture_receipt("cap-live-1", &default_vendor_key, None)?;
    let default_child_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&default_child_receipt)?,
    );
    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: default_parent_receipt_sha256.clone(),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    let mut lineage = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-1".to_string(),
        parent_receipt_sha256: default_parent_receipt_sha256,
        child_receipt_sha256: default_child_receipt_sha256,
        continuation_sha256,
        bilateral_invocation_sha256: String::new(),
        evidence_class: "verified".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
    };
    let mut admission = CrossBoundaryAdmissionReport {
        schema: CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        required_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "4".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: "4".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: String::new(),
                verified: true,
            },
        ],
        treaty_scope_sha256: "5".repeat(64),
        ladder_intersection_sha256: "6".repeat(64),
        expected_ladder_intersection_sha256: Some("6".repeat(64)),
        checks: vec!["chio_treaty.required_evidence_present".to_string()],
    };
    let mut bilateral = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-1".to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        continuation_sha256: lineage.continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: "cap-live-1".to_string(),
        request_sha256: tool_args_sha256(&serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        }))?,
        outcome_sha256: "c".repeat(64),
        local_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        remote_receipt_sha256: lineage.child_receipt_sha256.clone(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };
    let bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral)?;
    lineage.bilateral_invocation_sha256 = bilateral_invocation_sha256.clone();
    let lineage_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&lineage)?,
    );
    bilateral.lineage_statement_sha256 = lineage_hash.clone();
    for evidence in &mut admission.verified_evidence {
        if evidence.evidence_class == "receipt_lineage" {
            evidence.artifact_sha256 = lineage_hash.clone();
        } else if evidence.evidence_class == "bilateral_invocation" {
            evidence.artifact_sha256 = bilateral_invocation_sha256.clone();
        }
    }
    let admission_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&admission)?,
    );
    let packet = BuyerAttestationPacket {
        schema: CHIO_BUYER_ATTESTATION_PACKET_SCHEMA.to_string(),
        packet_id: "buyer-packet-1".to_string(),
        buyer_id: "kernel.buyer".to_string(),
        capability_id: bilateral.capability_id.clone(),
        treaty_scope_sha256: admission.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: admission.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: admission_hash,
        continuation_sha256: lineage.continuation_sha256.clone(),
        receipt_lineage_statement_sha256: lineage_hash,
        bilateral_invocation_sha256,
        bilateral_dsse_sha256: "4".repeat(64),
        workflow_receipt_sha256: "8".repeat(64),
        proof_package_sha256: "9".repeat(64),
        verifier_report_sha256: "a".repeat(64),
        budget_refs: vec!["budget.reserve:local-demo".to_string()],
        settlement_claimed: false,
    };
    Ok((packet, lineage, continuation, admission, bilateral))
}

fn rebind_buyer_review_core(
    packet: &mut BuyerAttestationPacket,
    lineage: &mut ReceiptLineageStatement,
    admission: &mut CrossBoundaryAdmissionReport,
    bilateral: &mut BilateralInvocation,
) -> Result<(), Box<dyn std::error::Error>> {
    bilateral.continuation_sha256 = lineage.continuation_sha256.clone();
    bilateral.ladder_intersection_sha256 = admission.ladder_intersection_sha256.clone();
    bilateral.action_class_id = admission.action_class_id.clone();
    bilateral.consistency_model = admission.consistency_model.clone();
    bilateral.local_receipt_sha256 = lineage.parent_receipt_sha256.clone();
    bilateral.remote_receipt_sha256 = lineage.child_receipt_sha256.clone();
    let bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(bilateral)?;
    lineage.bilateral_invocation_sha256 = bilateral_invocation_sha256.clone();
    let lineage_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(lineage)?,
    );
    bilateral.lineage_statement_sha256 = lineage_hash.clone();
    for evidence in &mut admission.verified_evidence {
        if evidence.evidence_class == "receipt_lineage" {
            evidence.artifact_sha256 = lineage_hash.clone();
        } else if evidence.evidence_class == "bilateral_invocation" {
            evidence.artifact_sha256 = bilateral_invocation_sha256.clone();
        }
    }
    let admission_hash = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(admission)?,
    );
    packet.capability_id = bilateral.capability_id.clone();
    packet.treaty_scope_sha256 = admission.treaty_scope_sha256.clone();
    packet.ladder_intersection_sha256 = admission.ladder_intersection_sha256.clone();
    packet.cross_boundary_admission_report_sha256 = admission_hash;
    packet.continuation_sha256 = lineage.continuation_sha256.clone();
    packet.receipt_lineage_statement_sha256 = lineage_hash;
    packet.bilateral_invocation_sha256 = bilateral_invocation_sha256;
    Ok(())
}

struct StrictDsseFixture {
    envelope: chio_federation::bilateral_dsse::DsseEnvelope,
    local_receipt: ChioReceipt,
    receipt: ChioReceipt,
    signer_a_public_key: chio_core_types::crypto::PublicKey,
    signer_b_public_key: chio_core_types::crypto::PublicKey,
}

struct StrictDsseFixtureInput<'a> {
    packet: &'a BuyerAttestationPacket,
    lineage_bundle: &'a ReceiptLineageBundle,
    admission: &'a CrossBoundaryAdmissionReport,
    bilateral: &'a BilateralInvocation,
    signer_kernel_ids: Option<(&'a str, &'a str)>,
    lease_id: &'a str,
    lease_scope_digest: Option<&'a str>,
    governance_receipt_id: &'a str,
    governance_digest: Option<&'a str>,
    consistency_anchor: Option<&'a str>,
    receipt_action: Option<ToolCallAction>,
    policy_evaluation_summary: Option<PolicyEvaluationSummary>,
}

struct StrictDsseFixtureKeypairs {
    signer_a: Keypair,
    signer_b: Keypair,
}

fn strict_dsse_fixture_with_keys(
    packet: &BuyerAttestationPacket,
    lineage_bundle: &ReceiptLineageBundle,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<StrictDsseFixture, Box<dyn std::error::Error>> {
    strict_dsse_fixture_with_kernel_ids(packet, lineage_bundle, admission, bilateral, None)
}

fn strict_dsse_fixture_with_kernel_ids(
    packet: &BuyerAttestationPacket,
    lineage_bundle: &ReceiptLineageBundle,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
    signer_kernel_ids: Option<(&str, &str)>,
) -> Result<StrictDsseFixture, Box<dyn std::error::Error>> {
    strict_dsse_fixture_with_keypairs(
        StrictDsseFixtureInput {
            packet,
            lineage_bundle,
            admission,
            bilateral,
            signer_kernel_ids,
            lease_id: "lease-live-1",
            lease_scope_digest: None,
            governance_receipt_id: "gov-receipt-1",
            governance_digest: None,
            consistency_anchor: Some("anchor-live"),
            receipt_action: None,
            policy_evaluation_summary: None,
        },
        StrictDsseFixtureKeypairs {
            signer_a: Keypair::from_seed(&[1; 32]),
            signer_b: Keypair::from_seed(&[2; 32]),
        },
    )
}

fn strict_dsse_fixture_with_keypairs(
    input: StrictDsseFixtureInput<'_>,
    keypairs: StrictDsseFixtureKeypairs,
) -> Result<StrictDsseFixture, Box<dyn std::error::Error>> {
    let StrictDsseFixtureInput {
        packet,
        lineage_bundle,
        admission,
        bilateral,
        signer_kernel_ids,
        lease_id,
        lease_scope_digest,
        governance_receipt_id,
        governance_digest,
        consistency_anchor,
        receipt_action,
        policy_evaluation_summary,
    } = input;
    let StrictDsseFixtureKeypairs { signer_a, signer_b } = keypairs;
    let (signer_a_kernel_id, signer_b_kernel_id) = signer_kernel_ids.unwrap_or((
        bilateral.signer_kernel_ids[0].as_str(),
        bilateral.signer_kernel_ids[1].as_str(),
    ));
    let lease_scope_digest = lease_scope_digest
        .unwrap_or("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let governance_receipt =
        proof_package_governance_receipt_for_test(bilateral, governance_receipt_id);
    let computed_governance_digest = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&governance_receipt)?,
    );
    let governance_digest = governance_digest.unwrap_or(&computed_governance_digest);
    let local_receipt = strict_dsse_fixture_receipt_with_id(
        "rcpt-parent-local",
        &packet.capability_id,
        &signer_a,
        None,
    )?;
    let receipt = strict_dsse_fixture_receipt(&packet.capability_id, &signer_b, receipt_action)?;
    let policy_evaluation_summary =
        policy_evaluation_summary.unwrap_or_else(|| PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-buyer".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-vendor".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        });
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &signer_a,
        &signer_b,
        signer_a_kernel_id,
        signer_b_kernel_id,
        &receipt.tool_name,
        1_800_000_010_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: lease_id.to_string(),
                issuer: bilateral.signer_kernel_ids[0].clone(),
                expires_at_unix_ms: 1_800_003_600_000,
                scope_digest: Some(HashRecord {
                    alg: "sha256".to_string(),
                    value: lease_scope_digest.to_string(),
                }),
            }),
            policy_evaluation_summary: Some(policy_evaluation_summary),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: governance_receipt_id.to_string(),
                kernel_id: bilateral.signer_kernel_ids[1].clone(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: governance_digest.to_string(),
                },
            }),
            consistency_anchor: consistency_anchor.map(str::to_string),
            consistency_model: Some(dsse_consistency_model(&admission.consistency_model)?.into()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: admission.treaty_id.clone(),
                treaty_scope_sha256: packet.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
                admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
                continuation_sha256: packet.continuation_sha256.clone(),
                lineage_bundle_sha256: chio_core_types::crypto::sha256_hex(
                    &chio_core_types::crypto::canonical_json_bytes(lineage_bundle)?,
                ),
                action_class_id: admission.action_class_id.clone(),
                consistency_model: dsse_consistency_model(&admission.consistency_model)?.into(),
                request_sha256: bilateral.request_sha256.clone(),
                outcome_sha256: bilateral.outcome_sha256.clone(),
                local_receipt_sha256: bilateral.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral.remote_receipt_sha256.clone(),
                lease_refs: vec![lease_id.to_string()],
                governance_refs: vec![governance_receipt_id.to_string()],
                signer_kernel_ids: bilateral.signer_kernel_ids.clone(),
            }),
        },
    )?;
    Ok(StrictDsseFixture {
        envelope,
        local_receipt,
        receipt,
        signer_a_public_key: signer_a.public_key(),
        signer_b_public_key: signer_b.public_key(),
    })
}

fn proof_package_governance_receipt_for_test(
    bilateral: &BilateralInvocation,
    governance_receipt_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "body": {
            "schema": "chio.governance-receipt.v1",
            "receiptId": governance_receipt_id,
            "authorizingKernel": bilateral.signer_kernel_ids[1],
            "caseKind": "destructive_authorization",
            "authorizedLeaseId": "lease-live-1",
            "workflowId": "workflow-live-1",
            "stepSha256": "e".repeat(64),
            "issuedAtUnixMs": 1_800_000_000_000_i64,
            "expiresAtUnixMs": 1_800_003_600_000_i64
        },
        "signerKey": "ab",
        "signature": "cd"
    })
}

fn strict_dsse_with_policy_disagreement(
    dsse: &StrictDsseFixture,
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = dsse.envelope.decode_statement()?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture DSSE missing policy summary"))?;
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            statement.canonical_bytes()?,
        ),
        signatures: dsse.envelope.signatures.clone(),
    })
}

fn proof_package_with_peer_keys(
    bilateral: &BilateralInvocation,
    dsse: &StrictDsseFixture,
) -> serde_json::Value {
    let workflow_receipt = serde_json::json!({
        "schema": "chio.workflow-receipt.v1",
        "workflowId": "workflow-live-1",
        "workflowStepSha256": "e".repeat(64)
    });
    serde_json::json!({
        "schema": "chio.attest.proof-package.v1",
        "proofPackageId": "proof-from-live-run",
        "workflowId": "workflow-live-1",
        "generatedAtUnixMs": 1_800_000_010_000_i64,
        "workflowReceipt": workflow_receipt,
        "toolReceipts": [
            dsse.local_receipt,
            dsse.receipt
        ],
        "bilateralEnvelopes": [dsse.envelope],
        "capabilityLeases": [
            {
                "leaseId": "lease-live-1",
                "issuer": bilateral.signer_kernel_ids[0],
                "expiresAtUnixMs": 1_800_003_600_000_i64,
                "scopeDigest": "f".repeat(64)
            }
        ],
        "leaseScopeBindings": [
            {
                "leaseId": "lease-live-1",
                "capabilityId": bilateral.capability_id,
                "actionClassId": bilateral.action_class_id
            }
        ],
        "governanceReceipts": [
            proof_package_governance_receipt_for_test(bilateral, "gov-receipt-1")
        ],
        "workflowIntersection": {
            "treatyId": bilateral.treaty_id,
            "ladderIntersectionSha256": bilateral.ladder_intersection_sha256
        },
        "selectiveDisclosureProof": {
            "schema": "chio.attest.selective-disclosure-proof.v1",
            "claimsHidden": false
        },
        "claims": {
            "hiddenRangePredicates": false,
            "settlementClaimed": false
        },
        "vendorKeys": [
            {
                "kernelId": bilateral.signer_kernel_ids[0],
                "publicKey": dsse.signer_a_public_key.to_hex()
            },
            {
                "kernelId": bilateral.signer_kernel_ids[1],
                "publicKey": dsse.signer_b_public_key.to_hex()
            }
        ],
        "peerLadderBindings": [
            {
                "kernelId": bilateral.signer_kernel_ids[0],
                "publicKey": dsse.signer_a_public_key.to_hex(),
                "ladderManifestRef": {
                    "manifestId": "ladder-buyer-live",
                    "issuedAtUnixMs": 1_800_000_000_000_i64,
                    "expiresAtUnixMs": 1_800_003_600_000_i64
                }
            },
            {
                "kernelId": bilateral.signer_kernel_ids[1],
                "publicKey": dsse.signer_b_public_key.to_hex(),
                "ladderManifestRef": {
                    "manifestId": "ladder-vendor-live",
                    "issuedAtUnixMs": 1_800_000_000_000_i64,
                    "expiresAtUnixMs": 1_800_003_600_000_i64
                }
            }
        ]
    })
}

type ReviewSourceBytes = Vec<BuyerAttestationReviewSource>;
type ReviewPackageSources = (
    BuyerAttestationReviewPackage,
    ReviewSourceBytes,
    serde_json::Value,
);

struct BuyerReviewStrictDsseSources<'a> {
    packet: &'a mut BuyerAttestationPacket,
    lineage: &'a ReceiptLineageStatement,
    continuation: &'a CrossKernelContinuation,
    admission: &'a CrossBoundaryAdmissionReport,
    bilateral: &'a BilateralInvocation,
    lineage_bundle: &'a ReceiptLineageBundle,
    bilateral_dsse_envelope: &'a serde_json::Value,
    proof_package: &'a serde_json::Value,
}

struct BuyerReviewVerifierArtifacts<'a> {
    verifier_trust_bundle: &'a serde_json::Value,
    verification_context: &'a serde_json::Value,
    verifier_report: &'a serde_json::Value,
}

fn buyer_review_sources_with_strict_dsse(
    sources: BuyerReviewStrictDsseSources<'_>,
) -> Result<ReviewPackageSources, Box<dyn std::error::Error>> {
    buyer_review_sources_with_strict_dsse_and_verifier(sources, None)
}

fn buyer_review_sources_with_strict_dsse_and_verifier(
    sources: BuyerReviewStrictDsseSources<'_>,
    verifier_artifacts: Option<BuyerReviewVerifierArtifacts<'_>>,
) -> Result<ReviewPackageSources, Box<dyn std::error::Error>> {
    let BuyerReviewStrictDsseSources {
        packet,
        lineage,
        continuation,
        admission,
        bilateral,
        lineage_bundle,
        bilateral_dsse_envelope,
        proof_package,
    } = sources;
    let workflow_receipt = proof_package
        .get("workflowReceipt")
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "schema": "chio.workflow-receipt.v1",
                "workflowId": "workflow-live-1",
                "workflowStepSha256": "e".repeat(64)
            })
        });
    let workflow_step =
        first_workflow_step_for_receipt(proof_package, &bilateral.remote_receipt_sha256).or_else(
            || {
                proof_package
                    .get("workflowReceipt")
                    .and_then(|receipt| receipt.get("steps"))
                    .and_then(serde_json::Value::as_array)
                    .and_then(|steps| steps.first())
            },
        );
    let workflow_step_sha256 = workflow_step
        .map(chio_core_types::crypto::canonical_json_bytes)
        .transpose()?
        .map(|bytes| chio_core_types::crypto::sha256_hex(&bytes))
        .unwrap_or_else(|| "e".repeat(64));
    let step_index = workflow_step
        .and_then(|step| step.get("step_index"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let tool_receipt_id = workflow_step
        .and_then(|step| step.get("tool_receipt_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("rcpt-treaty-dsse")
        .to_string();
    let consistency_anchor = workflow_step
        .and_then(|step| step.get("consistency_anchor"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("anchor-live")
        .to_string();
    packet.workflow_receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&workflow_receipt)?,
    );
    packet.proof_package_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(proof_package)?,
    );
    let (verifier_trust_bundle, verification_context, verifier_report) =
        if let Some(artifacts) = verifier_artifacts {
            (
                artifacts.verifier_trust_bundle.clone(),
                artifacts.verification_context.clone(),
                artifacts.verifier_report.clone(),
            )
        } else {
            let verifier_trust_bundle = serde_json::json!({
                "schema": "chio.federation.verifier-trust-bundle.v1",
                "peers": proof_package
                    .get("peerLadderBindings")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([]))
            });
            let verifier_trust_bundle_sha256 = chio_core_types::crypto::sha256_hex(
                &chio_core_types::crypto::canonical_json_bytes(&verifier_trust_bundle)?,
            );
            let verifier_report = serde_json::json!({
                "schema": "chio.attest.verifier-report.v1",
                "accepted": true,
                "trustBundleSha256": verifier_trust_bundle_sha256,
                "failure": null
            });
            (
                verifier_trust_bundle,
                default_verification_context(),
                verifier_report,
            )
        };
    let verifier_trust_bundle_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&verifier_trust_bundle)?,
    );
    packet.verifier_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&verifier_report)?,
    );
    let bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(bilateral_dsse_envelope)?,
    );
    let review_generated_at_unix_ms = serde_json::from_value::<
        chio_federation::bilateral_dsse::DsseEnvelope,
    >(bilateral_dsse_envelope.clone())
    .ok()
    .and_then(|envelope| {
        envelope
            .decode_statement()
            .ok()
            .map(|(statement, _)| statement.predicate.timestamp_unix_ms)
    })
    .unwrap_or_else(|| {
        verification_context
            .get("issuedAtUnixMs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1_800_000_000_000)
            .saturating_add(10_000)
    });
    packet.bilateral_dsse_sha256 = bilateral_dsse_sha256.clone();
    let lease_id = proof_package_lease_id_for_step(proof_package, step_index)
        .or_else(|| first_proof_array_field(proof_package, "capabilityLeases", "leaseId"))
        .unwrap_or_else(|| "lease-live-1".to_string());
    let governance_receipt_id = workflow_step
        .and_then(|step| step.get("governance_receipt_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| first_proof_array_field(proof_package, "governanceReceipts", "receiptId"))
        .unwrap_or_else(|| "gov-receipt-1".to_string());
    let source_record = RuntimeProofSourceRecord {
        step_index,
        admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
        tool_receipt_sha256: bilateral.remote_receipt_sha256.clone(),
        bilateral_dsse_sha256: bilateral_dsse_sha256.clone(),
        workflow_step_sha256,
    };
    let proof_regeneration_report = RuntimeProofRegenerationReport {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: "run-live-1".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: review_generated_at_unix_ms,
        proof_package_sha256: Some(packet.proof_package_sha256.clone()),
        verifier_report_sha256: Some(packet.verifier_report_sha256.clone()),
        workflow_receipt_sha256: Some(packet.workflow_receipt_sha256.clone()),
        source_records: vec![source_record.clone()],
        checks: vec!["runtime_proof.regenerated".to_string()],
    };
    let proof_regeneration_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&proof_regeneration_report)?,
    );
    let runtime_run_report = RuntimeWorkflowRunReport {
        schema: CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: "run-live-1".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: review_generated_at_unix_ms,
        admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
        evidence_paths: vec![
            "bilateral-dsse-envelope.json".to_string(),
            "proof-regeneration-report.json".to_string(),
        ],
        step_evidence: vec![RuntimeStepEvidence {
            schema: CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
            step_index,
            admission_id: admission.treaty_id.clone(),
            admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
            tool_receipt_id,
            tool_receipt_sha256: bilateral.remote_receipt_sha256.clone(),
            output_sha256: bilateral.outcome_sha256.clone(),
            bilateral_dsse_sha256,
            workflow_step_sha256: source_record.workflow_step_sha256.clone(),
            parent_receipt_sha256: Some(bilateral.local_receipt_sha256.clone()),
            consistency_anchor,
            destructive: true,
            lease_id: Some(lease_id),
            governance_receipt_id: Some(governance_receipt_id),
        }],
        proof_regeneration_report_sha256: Some(proof_regeneration_report_sha256.clone()),
    };
    let runtime_run_report_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&runtime_run_report)?,
    );
    let runtime_evidence_manifest = RuntimeEvidenceManifest {
        schema: CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: "run-live-1".to_string(),
        generated_at_unix_ms: review_generated_at_unix_ms,
        workflow_run_report_sha256: runtime_run_report_sha256.clone(),
        proof_regeneration_report_sha256: proof_regeneration_report_sha256.clone(),
        entries: vec![
            review_manifest_entry(
                "bilateral_dsse_envelope",
                "bilateral_dsse_envelope.json",
                bilateral_dsse_envelope,
            )?,
            review_manifest_entry(
                "workflow_receipt",
                "workflow_receipt.json",
                &workflow_receipt,
            )?,
            review_manifest_entry("proof_package", "proof_package.json", proof_package)?,
            review_manifest_entry("verifier_report", "verifier_report.json", &verifier_report)?,
            review_manifest_entry(
                "proof_regeneration_report",
                "proof_regeneration_report.json",
                &proof_regeneration_report,
            )?,
            review_manifest_entry(
                "runtime_run_report",
                "runtime_run_report.json",
                &runtime_run_report,
            )?,
        ],
    };
    let runtime_evidence_manifest_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&runtime_evidence_manifest)?,
    );
    let proof_regeneration_input = RuntimeProofRegenerationInput {
        schema: CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA.to_string(),
        run_id: "run-live-1".to_string(),
        evidence_manifest_sha256: runtime_evidence_manifest_sha256,
        workflow_run_report_sha256: runtime_run_report_sha256,
        admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
        trust_bundle_sha256: verifier_trust_bundle_sha256,
        verification_context_sha256: chio_core_types::crypto::sha256_hex(
            &chio_core_types::crypto::canonical_json_bytes(&verification_context)?,
        ),
        source_records: vec![source_record],
    };
    let mut sources = Vec::new();
    let artifacts = vec![
        insert_review_source(&mut sources, "buyer_attestation_packet", packet)?,
        insert_review_source(&mut sources, "receipt_lineage_statement", lineage)?,
        insert_review_source(&mut sources, "receipt_lineage_bundle", lineage_bundle)?,
        insert_review_source(&mut sources, "cross_kernel_continuation", continuation)?,
        insert_review_source(&mut sources, "cross_boundary_admission_report", admission)?,
        insert_review_source(&mut sources, "bilateral_invocation", bilateral)?,
        insert_review_source(
            &mut sources,
            "bilateral_dsse_envelope",
            bilateral_dsse_envelope,
        )?,
        insert_review_source(&mut sources, "workflow_receipt", &workflow_receipt)?,
        insert_review_source(&mut sources, "proof_package", proof_package)?,
        insert_review_source(&mut sources, "verifier_report", &verifier_report)?,
        insert_review_source(
            &mut sources,
            "proof_regeneration_report",
            &proof_regeneration_report,
        )?,
        insert_review_source(&mut sources, "runtime_run_report", &runtime_run_report)?,
        insert_review_source(
            &mut sources,
            "runtime_evidence_manifest",
            &runtime_evidence_manifest,
        )?,
        insert_review_source(
            &mut sources,
            "proof_regeneration_input",
            &proof_regeneration_input,
        )?,
    ];
    let package = BuyerAttestationReviewPackage {
        schema: CHIO_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: "review-package-1".to_string(),
        packet_id: packet.packet_id.clone(),
        buyer_id: packet.buyer_id.clone(),
        generated_at_unix_ms: review_generated_at_unix_ms,
        artifacts,
    };
    Ok((package, sources, verifier_trust_bundle))
}

fn verify_review_for_test(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    verifier_trust_bundle: &serde_json::Value,
) -> Result<BuyerAttestationReviewReport, ChioRuntimeError> {
    let verification_context = default_verification_context();
    verify_review_for_test_with_context(
        package,
        sources,
        verifier_trust_bundle,
        &verification_context,
    )
}

fn verify_review_for_test_with_context(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    verifier_trust_bundle: &serde_json::Value,
    verification_context: &serde_json::Value,
) -> Result<BuyerAttestationReviewReport, ChioRuntimeError> {
    verify_buyer_attestation_review_package_with_trust(
        package,
        sources,
        &BuyerAttestationReviewTrustContext {
            verifier_trust_bundle,
            verification_context,
        },
    )
}

fn default_verification_context() -> serde_json::Value {
    serde_json::json!({
        "schema": "chio.federation.verification-context.v1",
        "audience": "buyer-auditor-offline-verifier",
        "challenge": "refund-workflow-001-audit",
        "proofPurpose": "buyer-auditor-workflow-disclosure",
        "issuedAtUnixMs": 1_800_000_000_000_i64,
        "expiresAtUnixMs": 1_800_003_600_000_i64
    })
}

fn first_proof_array_field(
    proof_package: &serde_json::Value,
    array_field: &str,
    field: &str,
) -> Option<String> {
    proof_package
        .get(array_field)
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.first())
        .and_then(|value| {
            value
                .get(field)
                .or_else(|| value.get("body").and_then(|body| body.get(field)))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string)
}

fn first_workflow_step_for_receipt<'a>(
    proof_package: &'a serde_json::Value,
    receipt_sha256: &str,
) -> Option<&'a serde_json::Value> {
    let receipt_id = proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .and_then(|receipts| {
            receipts.iter().find_map(|receipt| {
                let hash = chio_core_types::crypto::canonical_json_bytes(receipt)
                    .ok()
                    .map(|bytes| chio_core_types::crypto::sha256_hex(&bytes))?;
                if hash != receipt_sha256 {
                    return None;
                }
                receipt
                    .get("id")
                    .or_else(|| receipt.get("receiptId"))
                    .and_then(serde_json::Value::as_str)
            })
        })?;
    proof_package
        .get("workflowReceipt")
        .and_then(|receipt| receipt.get("steps"))
        .and_then(serde_json::Value::as_array)
        .and_then(|steps| {
            steps.iter().find(|step| {
                step.get("tool_receipt_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(receipt_id)
            })
        })
}

fn proof_package_lease_id_for_step(
    proof_package: &serde_json::Value,
    step_index: u64,
) -> Option<String> {
    proof_package
        .get("leaseScopeBindings")
        .and_then(serde_json::Value::as_array)
        .and_then(|bindings| {
            bindings.iter().find_map(|binding| {
                (binding.get("stepIndex").and_then(serde_json::Value::as_u64) == Some(step_index))
                    .then(|| binding.get("leaseId").and_then(serde_json::Value::as_str))
                    .flatten()
            })
        })
        .map(str::to_string)
}

#[test]
fn buyer_review_package_hydrates_required_artifacts_by_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, mut lineage, mut continuation, mut admission, mut bilateral) =
        buyer_fixture()?;
    let base_package = chio_attest_loopback::fresh_proof_package()?;
    let initial_proof_package: serde_json::Value =
        serde_json::from_str(&chio_attest_loopback::package_json(&base_package)?)?;
    let verification_context_typed = chio_attest_loopback::verification_context();
    let verification_context: serde_json::Value = serde_json::from_str(
        &chio_attest_loopback::verification_context_json(&verification_context_typed)?,
    )?;
    let proof_step_index = 2usize;
    let receipt = &initial_proof_package["toolReceipts"][proof_step_index];
    let receipt_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(receipt)?,
    );
    let lease_id = initial_proof_package["capabilityLeases"][proof_step_index]["body"]["leaseId"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture lease is missing leaseId"))?
        .to_string();
    let lease_issuer = initial_proof_package["capabilityLeases"][proof_step_index]["body"]
        ["issuer"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture lease is missing issuer"))?
        .to_string();
    let lease_expires_at_unix_ms = initial_proof_package["capabilityLeases"][proof_step_index]
        ["body"]["expiresAtUnixMs"]
        .as_u64()
        .ok_or_else(|| io::Error::other("fixture lease is missing expiresAtUnixMs"))?;
    let lease_scope_digest = initial_proof_package["capabilityLeases"][proof_step_index]["body"]
        ["scopeDigest"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture lease is missing scopeDigest"))?
        .to_string();
    let governance_receipt_id = initial_proof_package["governanceReceipts"][0]["body"]["receiptId"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture governance receipt is missing receiptId"))?
        .to_string();
    let governance_kernel_id = initial_proof_package["governanceReceipts"][0]["body"]
        .get("authorizingKernel")
        .or_else(|| initial_proof_package["governanceReceipts"][0]["body"].get("kernelId"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::other("fixture governance receipt is missing kernel id"))?
        .to_string();
    let governance_digest =
        chio_core_types::crypto::sha256_hex(&chio_core_types::crypto::canonical_json_bytes(
            &initial_proof_package["governanceReceipts"][0],
        )?);
    let consistency_anchor = initial_proof_package["workflowReceipt"]["steps"][proof_step_index]
        ["consistency_anchor"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture step is missing consistency_anchor"))?
        .to_string();
    let local_receipt_sha256 = initial_proof_package["workflowReceipt"]["steps"][proof_step_index]
        ["parent_receipt_sha256"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture step is missing parent_receipt_sha256"))?
        .to_string();
    let buyer_kernel_id = "did:chio:buyer-kernel";
    let (vendor_kernel_id, vendor_server_id, vendor_tool_name) =
        chio_attest_loopback::runtime_vendor_binding(proof_step_index)?;
    packet.buyer_id = buyer_kernel_id.to_string();
    continuation.source_kernel_id = buyer_kernel_id.to_string();
    continuation.target_kernel_id = vendor_kernel_id.to_string();
    continuation.parent_receipt_sha256 = local_receipt_sha256.clone();
    continuation.capability_id = lease_id.clone();
    continuation.action_class_id = vendor_tool_name.to_string();
    continuation.audience_tool = format!("{vendor_server_id}.{vendor_tool_name}");
    lineage.source_kernel_id = buyer_kernel_id.to_string();
    lineage.target_kernel_id = vendor_kernel_id.to_string();
    lineage.parent_receipt_sha256 = local_receipt_sha256;
    lineage.child_receipt_sha256 = receipt_sha256.clone();
    lineage.continuation_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&continuation)?,
    );
    admission.action_class_id = vendor_tool_name.to_string();
    bilateral.signer_kernel_ids = vec![buyer_kernel_id.to_string(), vendor_kernel_id.to_string()];
    bilateral.capability_id = lease_id.clone();
    bilateral.request_sha256 = receipt["action"]["parameter_hash"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture receipt is missing action parameter_hash"))?
        .to_string();
    bilateral.outcome_sha256 = receipt["content_hash"]
        .as_str()
        .ok_or_else(|| io::Error::other("fixture receipt is missing content_hash"))?
        .to_string();
    rebind_buyer_review_core(&mut packet, &mut lineage, &mut admission, &mut bilateral)?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let receipt_typed = base_package.tool_receipts[proof_step_index].clone();
    let buyer_key = Keypair::from_seed(&[11; 32]);
    let vendor_key = chio_attest_loopback::runtime_vendor_keypair(proof_step_index)?;
    let dsse_timestamp_unix_ms = verification_context
        .get("issuedAtUnixMs")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| io::Error::other("verification context missing issue time"))?
        .saturating_add(10_000);
    let bilateral_dsse = sign_chio_bilateral_dsse_envelope(
        &receipt_typed,
        &buyer_key,
        &vendor_key,
        buyer_kernel_id,
        vendor_kernel_id,
        &receipt_typed.tool_name,
        dsse_timestamp_unix_ms,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: lease_id.clone(),
                issuer: lease_issuer,
                expires_at_unix_ms: lease_expires_at_unix_ms,
                scope_digest: Some(HashRecord {
                    alg: "sha256".to_string(),
                    value: lease_scope_digest,
                }),
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-buyer".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-vendor".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: None,
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: governance_receipt_id.clone(),
                kernel_id: governance_kernel_id,
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: governance_digest,
                },
            }),
            consistency_anchor: Some(consistency_anchor),
            consistency_model: Some(dsse_consistency_model(&admission.consistency_model)?.into()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: admission.treaty_id.clone(),
                treaty_scope_sha256: packet.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
                admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
                continuation_sha256: packet.continuation_sha256.clone(),
                lineage_bundle_sha256: chio_core_types::crypto::sha256_hex(
                    &chio_core_types::crypto::canonical_json_bytes(&lineage_bundle)?,
                ),
                action_class_id: admission.action_class_id.clone(),
                consistency_model: dsse_consistency_model(&admission.consistency_model)?.into(),
                request_sha256: bilateral.request_sha256.clone(),
                outcome_sha256: bilateral.outcome_sha256.clone(),
                local_receipt_sha256: bilateral.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral.remote_receipt_sha256.clone(),
                lease_refs: vec![lease_id],
                governance_refs: vec![governance_receipt_id],
                signer_kernel_ids: bilateral.signer_kernel_ids.clone(),
            }),
        },
    )?;
    let bilateral_dsse_envelope = serde_json::to_value(&bilateral_dsse)?;
    let bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&bilateral_dsse_envelope)?,
    );
    let mut runtime_artifacts: Vec<_> = base_package
        .tool_receipts
        .iter()
        .cloned()
        .zip(base_package.bilateral_envelopes.iter().cloned())
        .zip(base_package.workflow_receipt.steps.iter().cloned())
        .map(|((tool_receipt, bilateral_envelope), workflow_step)| {
            chio_attest_loopback::RuntimeProofArtifact {
                tool_receipt,
                bilateral_envelope,
                workflow_step,
            }
        })
        .collect();
    runtime_artifacts[proof_step_index].bilateral_envelope = bilateral_dsse;
    runtime_artifacts[proof_step_index]
        .workflow_step
        .bilateral_dsse_sha256 = Some(bilateral_dsse_sha256);
    let typed_package =
        chio_attest_loopback::proof_package_from_runtime_artifacts(runtime_artifacts)?;
    let verifier_trust_bundle_document =
        chio_attest_loopback::verifier_trust_bundle_document_for_package(&typed_package)?;
    let proof_package: serde_json::Value =
        serde_json::from_str(&chio_attest_loopback::package_json(&typed_package)?)?;
    let verifier_trust_bundle: serde_json::Value = serde_json::from_str(
        &chio_attest_loopback::verifier_trust_bundle_json(&verifier_trust_bundle_document)?,
    )?;
    let typed_trust_bundle = chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_from_json(
        &serde_json::to_string(&verifier_trust_bundle)?,
    )?;
    let verifier_report =
        serde_json::to_value(chio_attest_buyer_core::report::verify_package_report(
            &typed_package,
            &typed_trust_bundle,
            &verification_context_typed,
        ))?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse_and_verifier(
            BuyerReviewStrictDsseSources {
                packet: &mut packet,
                lineage: &lineage,
                continuation: &continuation,
                admission: &admission,
                bilateral: &bilateral,
                lineage_bundle: &lineage_bundle,
                bilateral_dsse_envelope: &bilateral_dsse_envelope,
                proof_package: &proof_package,
            },
            Some(BuyerReviewVerifierArtifacts {
                verifier_trust_bundle: &verifier_trust_bundle,
                verification_context: &verification_context,
                verifier_report: &verifier_report,
            }),
        )?;

    let report = verify_review_for_test_with_context(
        &package,
        &sources,
        &verifier_trust_bundle,
        &verification_context,
    )?;
    assert!(report.accepted, "{report:#?}");
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "chio_buyer_review.proof_verifier_accepted"));

    let mut timestamp_drift_package = package.clone();
    timestamp_drift_package.generated_at_unix_ms = timestamp_drift_package
        .generated_at_unix_ms
        .saturating_sub(1);
    let denied = verify_review_for_test_with_context(
        &timestamp_drift_package,
        &sources,
        &verifier_trust_bundle,
        &verification_context,
    )?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_review_package_manifest_timestamp_mismatch")
    );

    let mut tampered_sources = sources.clone();
    let verifier_source = tampered_sources
        .iter_mut()
        .find(|source| source.role == "verifier_report")
        .ok_or_else(|| io::Error::other("missing verifier_report source"))?;
    verifier_source.bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "chio.attest.verifier-report.v1",
        "accepted": false
    }))?;
    let denied = verify_review_for_test(&package, &tampered_sources, &verifier_trust_bundle)?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_buyer_review_artifact_hash_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_minimal_proof_package() -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = serde_json::json!({
        "schema": "chio.attest.proof-package.v1"
    });
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_incomplete")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_missing_hydrated_parent_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["toolReceipts"]
        .as_array_mut()
        .ok_or_else(|| io::Error::other("fixture proof package missing tool receipts"))?
        .remove(0);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_signed_receipt_with_unbound_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["toolReceipts"][0]["unsignedShadow"] = serde_json::json!("not-signed");
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_claimed_governance_digest_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["governanceReceipts"][0]["digest"] = serde_json::json!("0".repeat(64));
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_lineage_bundle_without_packet_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let mut alternate_lineage = lineage.clone();
    alternate_lineage.statement_id = "lineage-alternate".to_string();
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: alternate_lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: alternate_lineage.child_receipt_sha256.clone(),
        statements: vec![alternate_lineage],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_lineage_bundle_incomplete")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_report_without_matching_dsse_step(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let mut runtime_report: RuntimeWorkflowRunReport = serde_json::from_slice(
        &sources
            .iter()
            .find(|source| source.role == "runtime_run_report")
            .ok_or_else(|| io::Error::other("missing runtime_run_report source"))?
            .bytes,
    )?;
    runtime_report.step_evidence[0].bilateral_dsse_sha256 = "f".repeat(64);
    replace_review_source(
        &mut package,
        &mut sources,
        "runtime_run_report",
        &runtime_report,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_proof_input_trust_hash_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let source = sources
        .iter()
        .find(|source| source.role == "proof_regeneration_input")
        .ok_or_else(|| io::Error::other("missing proof regeneration input"))?;
    let mut input: RuntimeProofRegenerationInput = serde_json::from_slice(&source.bytes)?;
    input.trust_bundle_sha256 = "0".repeat(64);
    replace_review_source(
        &mut package,
        &mut sources,
        "proof_regeneration_input",
        &input,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_manifest_artifact_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let source = sources
        .iter()
        .find(|source| source.role == "runtime_evidence_manifest")
        .ok_or_else(|| io::Error::other("missing runtime evidence manifest"))?;
    let mut manifest: RuntimeEvidenceManifest = serde_json::from_slice(&source.bytes)?;
    let proof_entry = manifest
        .entries
        .iter_mut()
        .find(|entry| entry.role == "proof_package")
        .ok_or_else(|| io::Error::other("missing proof package manifest entry"))?;
    proof_entry.byte_count = proof_entry.byte_count.saturating_add(1);
    replace_review_source(
        &mut package,
        &mut sources,
        "runtime_evidence_manifest",
        &manifest,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_missing_strict_dsse_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    package
        .artifacts
        .retain(|artifact| artifact.role != "bilateral_dsse_envelope");
    sources.retain(|source| source.role != "bilateral_dsse_envelope");

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_missing_artifact_role")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_non_strict_dsse_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let compatibility_dsse = serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": "not-a-strict-chio-payload",
        "signatures": []
    });
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["bilateralEnvelopes"] = serde_json::json!([compatibility_dsse]);
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &proof_package["bilateralEnvelopes"][0],
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_non_strict_dsse")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[0].sig = dsse.envelope.signatures[1].sig.clone();
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_strict_dsse_signer_kernel_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut attacker_bilateral = bilateral.clone();
    attacker_bilateral.signer_kernel_ids[0] = "kernel.attacker".to_string();
    let dsse =
        strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &attacker_bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_binding_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_duplicate_strict_dsse_signature_keyids(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[1].keyid = dsse.envelope.signatures[0].keyid.clone();
    packet.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&dsse.envelope)?,
    );
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_same_key_strict_dsse_trust_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let Some(bindings) = proof_package
        .get_mut("peerLadderBindings")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Err(Box::new(io::Error::other(
            "proof package did not contain peer ladder bindings",
        )));
    };
    bindings[1]["publicKey"] = serde_json::json!(dsse.signer_a_public_key.to_hex());
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_strict_dsse_policy_verdict_disagreement(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope = strict_dsse_with_policy_disagreement(&dsse)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    packet.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&dsse.envelope)?,
    );
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_binding_mismatch")
    );
    Ok(())
}

#[test]
fn receipt_lineage_bundle_rejects_asserted_required_edge() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, mut lineage, _, _, _) = buyer_fixture()?;
    lineage.schema = CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string();
    let accepted = verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    })?;
    assert!(accepted);

    lineage.evidence_class = "asserted".to_string();
    let err = match verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-2".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    }) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "asserted lineage bundle unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_lineage_bundle_unverified_edge");
    Ok(())
}
