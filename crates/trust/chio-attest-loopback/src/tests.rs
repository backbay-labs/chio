#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
fn resign_bilateral_envelope_unanimous_deny(
    envelope: &mut DsseEnvelope,
    buyer_key: &Keypair,
    vendor_key: &Keypair,
) -> Result<(), ChioPackageError> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use chio_core_types::crypto::{Ed25519Backend, SigningBackend};
    use chio_federation::bilateral_dsse::{pae, PAYLOAD_TYPE_IN_TOTO};

    let (mut statement, _) = envelope
        .decode_statement()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| {
            ChioPackageError::Federation(
                "bilateral envelope missing policy_evaluation_summary".to_string(),
            )
        })?;
    summary.server_a_verdict.verdict = "deny".to_string();
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    let statement_bytes = statement
        .canonical_bytes()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    envelope.payload = BASE64_STANDARD.encode(&statement_bytes);
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
    let sig_a = Ed25519Backend::new(buyer_key.clone())
        .sign_bytes(&pae_bytes)
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    let sig_b = Ed25519Backend::new(vendor_key.clone())
        .sign_bytes(&pae_bytes)
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    envelope.signatures[0].sig = BASE64_STANDARD.encode(sig_a.to_bytes());
    envelope.signatures[1].sig = BASE64_STANDARD.encode(sig_b.to_bytes());
    Ok(())
}

fn refresh_workflow_step_parent_chain(steps: &mut [StepRecord]) -> Result<(), ChioPackageError> {
    let mut previous: Option<String> = None;
    for step in steps.iter_mut() {
        step.parent_receipt_sha256 = previous.clone();
        previous = Some(canonical_sha256(step)?);
    }
    Ok(())
}

use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::signing::ReceiptSigningHandle;
use chio_selective_disclosure::{
    derive_selective_disclosure_proof_from_receipt, sign_chio_receipt_with_bbs,
    BBS_CIPHERSUITE_SHA256, PROJECTION_VERSION_RECEIPT_V1,
};

fn rebuild_verifier_material(
    package: &mut ChioProofPackage,
    context: &ChioVerificationContext,
) -> ChioVerifierTrustBundle {
    let document =
        refresh_verifier_material_for_package(package, context).expect("trust bundle rebuilds");
    ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses")
}

fn runtime_artifacts_from_package(
    package: &ChioProofPackage,
) -> Result<Vec<RuntimeProofArtifact>, String> {
    let receipt_count = package.tool_receipts.len();
    let envelope_count = package.bilateral_envelopes.len();
    let step_count = package.workflow_receipt.steps.len();
    if receipt_count != envelope_count || receipt_count != step_count {
        return Err(format!(
            "runtime artifact fixture length mismatch: receipts={receipt_count}, envelopes={envelope_count}, steps={step_count}"
        ));
    }
    Ok(package
        .tool_receipts
        .iter()
        .cloned()
        .zip(package.bilateral_envelopes.iter().cloned())
        .zip(package.workflow_receipt.steps.iter().cloned())
        .map(
            |((tool_receipt, bilateral_envelope), workflow_step)| RuntimeProofArtifact {
                tool_receipt,
                bilateral_envelope,
                workflow_step,
            },
        )
        .collect())
}

fn refresh_runtime_parent_chain(artifacts: &mut [RuntimeProofArtifact]) {
    let mut parent = None;
    for artifact in artifacts {
        artifact.workflow_step.parent_receipt_sha256 = parent;
        parent = Some(canonical_sha256(&artifact.workflow_step).expect("step hashes"));
    }
}

#[test]
fn runtime_vendor_helper_reports_unknown_step() {
    let error = runtime_vendor(VENDORS.len()).expect_err("unknown step must fail");
    assert!(error.to_string().contains("unknown runtime vendor step 3"));
}

#[test]
fn fresh_proof_package_binds_disclosure_subject_to_workflow() {
    let package = fresh_proof_package().expect("fresh package builds");
    let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .expect("workflow projection derives");

    assert_eq!(
        package.selective_disclosure_proof.subject_sha256_hex,
        projection.subject_sha256_hex
    );
}

fn receipt_v1_runtime_package() -> (
    ChioProofPackage,
    ChioVerifierTrustBundle,
    ChioVerificationContext,
) {
    let context = verification_context();
    let bbs_keypair =
        generate_bbs_keypair(BBS_KEY_MATERIAL, BBS_KEY_INFO).expect("fixture BBS keypair derives");
    let mut receipts = Vec::new();
    for (index, vendor) in VENDORS.iter().enumerate() {
        let vendor_key = Keypair::from_seed(&vendor.seed);
        let body = receipt_body(vendor, &vendor_key).expect("receipt body builds");
        let receipt = if index == 0 {
            // WYSIWYS handle bound to the exact preimage the body's
            // content_hash is defined over (sha256_hex(vendor.output_label)).
            let handle = ReceiptSigningHandle::from_content_preimage(vendor.output_label.to_vec());
            sign_chio_receipt_with_bbs(body, &vendor_key, &bbs_keypair, handle)
                .expect("receipt signs with BBS")
        } else {
            ChioReceipt::sign(body, &vendor_key).expect("receipt signs")
        };
        receipts.push(receipt);
    }
    let mut package =
        proof_package_from_runtime_receipts(receipts).expect("runtime package builds");
    package.selective_disclosure_proof = derive_selective_disclosure_proof_from_receipt(
        &package.tool_receipts[0],
        &bbs_keypair,
        &DisclosureSet(vec![1, 5, 11]),
        &context
            .expected_bbs_proof_nonce()
            .expect("context nonce derives"),
    )
    .expect("receipt-bound proof derives");

    let mut trust_bundle_document =
        verifier_trust_bundle_document_for_package(&package).expect("trust bundle builds");
    trust_bundle_document.disclosure_policy = Some(ChioDisclosurePolicy {
        projection_version: PROJECTION_VERSION_RECEIPT_V1.to_string(),
        ciphersuite: BBS_CIPHERSUITE_SHA256.to_string(),
        message_count: 14,
        required_disclosed_indices: vec![1, 5, 11],
        required_disclosed_fields: vec![
            "capability_id".to_string(),
            "id".to_string(),
            "tool_name".to_string(),
        ],
    });
    let trust_bundle = ChioVerifierTrustBundle::from_document(trust_bundle_document)
        .expect("receipt v1 trust bundle parses");

    (package, trust_bundle, context)
}

#[test]
fn receipt_v1_disclosure_verifies_when_runtime_receipt_carries_embedded_bbs() {
    let (package, trust_bundle, context) = receipt_v1_runtime_package();

    let report =
        verify_package(&package, &trust_bundle, &context).expect("receipt v1 package verifies");
    assert!(report.accepted);
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "bbs.selective_disclosure"));
}

#[test]
fn receipt_v1_disclosure_rejects_tampered_embedded_bbs_material() {
    let (mut package, trust_bundle, context) = receipt_v1_runtime_package();
    package.tool_receipts[0]
        .bbs_signature
        .as_mut()
        .expect("receipt carries BBS material")
        .signature_hex = "00".repeat(112);

    let error = verify_package(&package, &trust_bundle, &context)
        .expect_err("tampered receipt-bound BBS material must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("federation verification failed"),
        "{message}"
    );
    assert!(
        message.contains("resolved receipt signature is invalid"),
        "{message}"
    );
}

#[test]
fn runtime_artifacts_from_package_rejects_fixture_length_mismatch() {
    let mut package = fresh_proof_package().expect("fresh package builds");
    package.bilateral_envelopes.pop();

    let error = runtime_artifacts_from_package(&package)
        .expect_err("mismatched runtime artifacts were silently truncated");

    assert!(error.contains("runtime artifact fixture length mismatch"));
    assert!(error.contains("receipts=3"));
    assert!(error.contains("envelopes=2"));
    assert!(error.contains("steps=3"));
}

#[test]
fn fresh_package_verifies() {
    let package = fresh_proof_package().expect("fresh package builds");
    let trust_bundle = verifier_trust_bundle().expect("verifier trust bundle builds");
    let context = verification_context();
    let report = verify_package(&package, &trust_bundle, &context).expect("fresh package verifies");
    assert!(report.accepted);
    assert!(report
        .checks
        .iter()
        .any(|check| check.code == "workflow.intersection"));
}

#[test]
fn authority_issuance_request_hashes_signed_receipt_body_for_governance(
) -> Result<(), ChioPackageError> {
    let package = fresh_proof_package()?;
    let request = authority_issuance_request()?;
    let destructive_step = request
        .steps
        .iter()
        .find(|step| step.destructive)
        .ok_or_else(|| ChioPackageError::Inconsistent("destructive step missing".into()))?;
    let governance_receipt = package
        .governance_receipts
        .first()
        .ok_or_else(|| ChioPackageError::Inconsistent("governance receipt missing".into()))?;

    assert_eq!(
        destructive_step.step_sha256.as_deref(),
        Some(governance_receipt.body.step_sha256.as_str())
    );
    Ok(())
}

#[test]
fn authority_issuance_request_for_package_uses_package_receipt_hashes(
) -> Result<(), ChioPackageError> {
    let package = fixture_proof_package()?;
    let request = authority_issuance_request_for_package(&package)?;

    for request_step in &request.steps {
        let workflow_step = package
            .workflow_receipt
            .steps
            .iter()
            .find(|step| step.step_index == request_step.step_index)
            .ok_or_else(|| ChioPackageError::Inconsistent("workflow step missing".into()))?;
        let tool_receipt_id = workflow_step
            .tool_receipt_id
            .as_ref()
            .ok_or_else(|| ChioPackageError::Inconsistent("tool receipt id missing".into()))?;
        let receipt = package
            .tool_receipts
            .iter()
            .find(|receipt| &receipt.id == tool_receipt_id)
            .ok_or_else(|| ChioPackageError::Inconsistent("tool receipt missing".into()))?;

        assert_eq!(request_step.tool_args_hash, receipt.action.parameter_hash);
        if request_step.destructive {
            let governance_receipt_id =
                workflow_step
                    .governance_receipt_id
                    .as_ref()
                    .ok_or_else(|| {
                        ChioPackageError::Inconsistent("governance receipt id missing".into())
                    })?;
            let governance_receipt = package
                .governance_receipts
                .iter()
                .find(|receipt| &receipt.body.receipt_id == governance_receipt_id)
                .ok_or_else(|| {
                    ChioPackageError::Inconsistent("governance receipt missing".into())
                })?;
            let step_sha256 = canonical_sha256(&receipt.body())?;

            assert_eq!(
                request_step.step_sha256.as_deref(),
                Some(step_sha256.as_str())
            );
            assert_eq!(governance_receipt.body.step_sha256, step_sha256);
        }
    }
    Ok(())
}

#[test]
fn authority_profile_pins_fixture_runtime_policy_signer() -> Result<(), ChioPackageError> {
    let fixture_runtime_policy_key = Keypair::from_seed(&[42; 32]);
    let profile = authority_profile_document()?;

    assert_eq!(
        profile.runtime_policy_issuer_public_keys,
        vec![fixture_runtime_policy_key.public_key()]
    );
    Ok(())
}

#[test]
fn runtime_artifact_package_uses_supplied_envelopes_and_steps() {
    let baseline = fresh_proof_package().expect("fresh package builds");
    let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
    artifacts[0].bilateral_envelope.signatures.reverse();
    let supplied_envelope_hash =
        canonical_sha256(&artifacts[0].bilateral_envelope).expect("envelope hashes");
    artifacts[0].workflow_step.bilateral_dsse_sha256 = Some(supplied_envelope_hash.clone());
    artifacts[0].workflow_step.duration_ms = 77;
    refresh_runtime_parent_chain(&mut artifacts);
    let supplied_steps = canonical_string(
        &artifacts
            .iter()
            .map(|artifact| &artifact.workflow_step)
            .collect::<Vec<_>>(),
    )
    .expect("steps canonicalize");
    let supplied_signature_order = artifacts[0].bilateral_envelope.signatures.clone();

    let package = proof_package_from_runtime_artifacts(artifacts).expect("package builds");

    assert_eq!(
        package.bilateral_envelopes[0].signatures,
        supplied_signature_order
    );
    assert_eq!(package.workflow_receipt.steps[0].duration_ms, 77);
    assert_eq!(
        package.workflow_receipt.steps[0]
            .bilateral_dsse_sha256
            .as_deref(),
        Some(supplied_envelope_hash.as_str())
    );
    let packaged_steps =
        canonical_string(&package.workflow_receipt.steps.iter().collect::<Vec<_>>())
            .expect("steps canonicalize");
    assert_eq!(packaged_steps, supplied_steps);

    let trust_bundle_document =
        verifier_trust_bundle_document_for_package(&package).expect("trust bundle builds");
    let trust_bundle = ChioVerifierTrustBundle::from_document(trust_bundle_document).unwrap();
    let context = verification_context();
    let report = verify_package(&package, &trust_bundle, &context)
        .expect("runtime artifact package verifies");
    assert!(report.accepted);
}

#[test]
fn runtime_artifact_package_rejects_step_dsse_hash_mismatch() {
    let baseline = fresh_proof_package().expect("fresh package builds");
    let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
    artifacts[0].workflow_step.bilateral_dsse_sha256 = Some("0".repeat(64));

    let error = proof_package_from_runtime_artifacts(artifacts).unwrap_err();

    assert!(error.to_string().contains("DSSE hash"));
}

#[test]
fn runtime_artifact_package_rejects_step_consistency_anchor_mismatch() {
    let baseline = fresh_proof_package().expect("fresh package builds");
    let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
    artifacts[0].workflow_step.consistency_anchor =
        Some("chio:consistency:wf-chio-refund-001:wrong".to_string());
    refresh_runtime_parent_chain(&mut artifacts);

    let error = proof_package_from_runtime_artifacts(artifacts).unwrap_err();

    assert!(error.to_string().contains("consistency anchor"));
}

#[test]
fn runtime_receipt_package_rejects_cross_workflow_action_payload() -> Result<(), ChioPackageError> {
    let baseline = fresh_proof_package()?;
    let mut receipts = baseline.tool_receipts;
    let mut body = receipts[0].body();
    body.action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": "wf-other",
        "caseRef": CASE_REF,
        "tool": VENDORS[0].tool_name,
    }))
    .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    receipts[0] = ChioReceipt::sign(body, &Keypair::from_seed(&VENDOR_A_SEED))
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;

    let Err(error) = proof_package_from_runtime_receipts(receipts) else {
        return Err(ChioPackageError::Inconsistent(
            "cross-workflow receipt was accepted".to_string(),
        ));
    };

    assert!(error.to_string().contains("workflow"));
    Ok(())
}

#[test]
fn missing_ladder_ref_fails_closed() {
    let mut package = fresh_proof_package().unwrap();
    package
        .workflow_intersection
        .pairwise_intersection_refs
        .retain(|peer| peer.peer_kernel_id != "did:chio:vendor-a");
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("pairwise ref") || error.to_string().contains("hash"));
}

#[test]
fn package_peer_pin_not_present_in_trust_bundle_fails_closed() {
    let package = fresh_proof_package().unwrap();
    let mut document = verifier_trust_bundle_document().unwrap();
    document
        .peers
        .retain(|binding| binding.kernel_id != "did:chio:vendor-a");
    let trust_bundle = ChioVerifierTrustBundle::from_document(document).unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("did:chio:vendor-a"));
    assert!(error.to_string().contains("trusted"));
}

#[test]
fn workflow_intersection_hash_mismatch_fails_closed() {
    let package = fresh_proof_package().unwrap();
    let mut document = verifier_trust_bundle_document().unwrap();
    document.workflow_intersections[0].sha256 = "f".repeat(64);
    let trust_bundle = ChioVerifierTrustBundle::from_document(document).unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("workflow intersection"));
}

#[test]
fn stale_lease_fails_closed() {
    let mut package = fresh_proof_package().unwrap();
    package.capability_leases[0].body.expires_at_unix_ms = GENERATED_AT_UNIX_MS;
    package.lease_scope_bindings[0].expires_at_unix_ms = GENERATED_AT_UNIX_MS;
    package.capability_leases[0].body.scope_digest = package.lease_scope_bindings[0]
        .scope_digest()
        .expect("scope digest rebuilds");
    package.capability_leases[0] = SignedExportEnvelope::sign(
        package.capability_leases[0].body.clone(),
        &Keypair::from_seed(&BUYER_SEED),
    )
    .expect("lease re-signs");
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("expired") || error.to_string().contains("signature"));
}

#[test]
fn mismatched_governance_receipt_fails_closed() {
    let mut package = fresh_proof_package().unwrap();
    package.governance_receipts[0].body.workflow_id = "wf-other".to_string();
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("signature") || error.to_string().contains("workflow"));
}

#[test]
fn tampered_step_parent_hash_fails_closed() {
    let mut package = fresh_proof_package().unwrap();
    package.workflow_receipt.steps[1].parent_receipt_sha256 = Some("0".repeat(64));
    resign_workflow_receipt(&mut package).expect("workflow resigns");
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(
        error.to_string().contains("parent hash")
            || error.to_string().contains("workflow intersection")
    );
}

#[test]
fn bad_vendor_signature_fails_closed() {
    let mut package = fresh_proof_package().unwrap();
    package.workflow_receipt.vendor_signatures[0].signature =
        Keypair::from_seed(&[99; 32]).sign(b"not the workflow body");
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("vendor signature"));
}

#[test]
fn unsupported_claims_fail_closed() {
    let mut package = fresh_proof_package().unwrap();
    package.claims.zkvm = true;
    let trust_bundle = verifier_trust_bundle().unwrap();
    let context = verification_context();
    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("zkVM"));
}

#[test]
fn committed_fixtures_verify() {
    let package =
        proof_package_from_json(include_str!("../fixtures/buyer-auditor-proof-package.json"))
            .expect("package fixture parses");
    let trust_bundle =
        verifier_trust_bundle_from_json(include_str!("../fixtures/verifier-trust-bundle.json"))
            .expect("verifier trust bundle fixture parses");
    let context =
        verification_context_from_json(include_str!("../fixtures/verification-context.json"))
            .expect("verification context fixture parses");
    let report =
        verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");
    let committed_report =
        verifier_report_from_json(include_str!("../fixtures/verifier-report.json"))
            .expect("report fixture parses");
    assert_eq!(report, committed_report);
}

#[test]
fn step_tool_receipt_mismatch_fails_closed() {
    let mut package = fresh_proof_package().expect("fresh package builds");
    package.workflow_receipt.steps[0].tool_receipt_id =
        package.workflow_receipt.steps[1].tool_receipt_id.clone();
    resign_workflow_receipt(&mut package).expect("workflow resigns");
    let context = verification_context();
    let trust_bundle = rebuild_verifier_material(&mut package, &context);

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("tool receipt"));
}

#[test]
fn step_output_hash_mismatch_fails_closed() {
    let mut package = fresh_proof_package().expect("fresh package builds");
    package.workflow_receipt.steps[0].output_hash = Some("0".repeat(64));
    resign_workflow_receipt(&mut package).expect("workflow resigns");
    let context = verification_context();
    let trust_bundle = rebuild_verifier_material(&mut package, &context);

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("output hash"));
}

#[test]
fn step_consistency_anchor_mismatch_fails_closed() {
    let mut package = fresh_proof_package().expect("fresh package builds");
    package.workflow_receipt.steps[0].consistency_anchor =
        Some("chio:consistency:wf-chio-refund-001:wrong".to_string());
    resign_workflow_receipt(&mut package).expect("workflow resigns");
    let context = verification_context();
    let trust_bundle = rebuild_verifier_material(&mut package, &context);

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    assert!(error.to_string().contains("consistency anchor"));
}

#[test]
fn bilateral_envelope_deny_verdict_fails_package_verification() {
    let mut package = fresh_proof_package().expect("fresh package builds");
    let buyer_key = Keypair::from_seed(&BUYER_SEED);
    let vendor_key = Keypair::from_seed(&VENDOR_A_SEED);
    resign_bilateral_envelope_unanimous_deny(
        &mut package.bilateral_envelopes[0],
        &buyer_key,
        &vendor_key,
    )
    .expect("deny bilateral envelope resigns");
    package.workflow_receipt.steps[0].bilateral_dsse_sha256 =
        Some(canonical_sha256(&package.bilateral_envelopes[0]).expect("envelope hash computes"));
    refresh_workflow_step_parent_chain(&mut package.workflow_receipt.steps)
        .expect("step parent chain refreshes");
    resign_workflow_receipt(&mut package).expect("workflow resigns");
    let context = verification_context();
    let trust_bundle = rebuild_verifier_material(&mut package, &context);

    let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("bilateral envelope policy verdict"),
        "expected admission gate failure, got: {message}"
    );
    assert!(
        message.contains("deny"),
        "expected deny verdict, got: {message}"
    );
}
