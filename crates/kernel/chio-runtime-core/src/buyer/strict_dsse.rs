use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::PublicKey;

use crate::buyer::proof_package::{
    proof_package_capability_lease_ref, proof_package_governance_receipt_ref,
    proof_package_receipt_subject,
};
use crate::hash::canonical_sha256;
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, CrossBoundaryAdmissionReport,
    ReceiptLineageBundle, RuntimeStepEvidence,
};

pub(super) struct BuyerReviewStrictDsseContext<'a> {
    pub(super) packet: &'a BuyerAttestationPacket,
    pub(super) lineage_bundle: &'a ReceiptLineageBundle,
    pub(super) admission: &'a CrossBoundaryAdmissionReport,
    pub(super) bilateral: &'a BilateralInvocation,
    pub(super) proof_package: &'a serde_json::Value,
    pub(super) runtime_step: &'a RuntimeStepEvidence,
    pub(super) signer_public_keys: &'a BTreeMap<String, PublicKey>,
    pub(super) generated_at_unix_ms: u64,
}

pub(super) fn verify_buyer_review_strict_dsse(
    envelope: &chio_federation::bilateral_dsse::DsseEnvelope,
    context: &BuyerReviewStrictDsseContext<'_>,
) -> Result<(), &'static str> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return Err("chio_buyer_review_non_strict_dsse");
    };
    if statement.predicate_type
        != chio_federation::bilateral_dsse::PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
    {
        return Err("chio_buyer_review_non_strict_dsse");
    }
    if statement.predicate.timestamp_unix_ms != context.generated_at_unix_ms {
        return Err("chio_buyer_review_runtime_timestamp_mismatch");
    }
    let lineage_bundle_sha256 = match canonical_sha256(context.lineage_bundle) {
        Ok(hash) => hash,
        Err(_) => return Err("chio_buyer_review_lineage_hash_mismatch"),
    };
    let consistency_model =
        crate::bilateral_dsse_consistency_model(&context.admission.consistency_model)
            .map_err(|_| "chio_buyer_review_strict_dsse_binding_mismatch")?;
    let expected_treaty_binding = chio_federation::bilateral_dsse::TreatyBindingRef {
        treaty_id: context.admission.treaty_id.clone(),
        treaty_scope_sha256: context.packet.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: context.packet.ladder_intersection_sha256.clone(),
        admission_report_sha256: context
            .packet
            .cross_boundary_admission_report_sha256
            .clone(),
        continuation_sha256: context.packet.continuation_sha256.clone(),
        lineage_bundle_sha256,
        action_class_id: context.admission.action_class_id.clone(),
        consistency_model: consistency_model.to_string(),
        request_sha256: context.bilateral.request_sha256.clone(),
        outcome_sha256: context.bilateral.outcome_sha256.clone(),
        local_receipt_sha256: context.bilateral.local_receipt_sha256.clone(),
        remote_receipt_sha256: context.bilateral.remote_receipt_sha256.clone(),
        lease_refs: vec![context
            .runtime_step
            .lease_id
            .clone()
            .ok_or("chio_buyer_review_runtime_report_mismatch")?],
        governance_refs: vec![context
            .runtime_step
            .governance_receipt_id
            .clone()
            .ok_or("chio_buyer_review_runtime_report_mismatch")?],
        signer_kernel_ids: context.bilateral.signer_kernel_ids.clone(),
    };
    let (expected_subject_name, expected_subject_sha256) = proof_package_receipt_subject(
        context.proof_package,
        &context.runtime_step.tool_receipt_sha256,
    )?;
    let lease_id = context
        .runtime_step
        .lease_id
        .as_deref()
        .ok_or("chio_buyer_review_runtime_report_mismatch")?;
    let expected_capability_lease_ref =
        proof_package_capability_lease_ref(context.proof_package, lease_id)?;
    let governance_receipt_id = context
        .runtime_step
        .governance_receipt_id
        .as_deref()
        .ok_or("chio_buyer_review_runtime_report_mismatch")?;
    let expected_governance_receipt_ref =
        proof_package_governance_receipt_ref(context.proof_package, governance_receipt_id)?;
    let review = chio_federation::bilateral_verifier::TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: &context.runtime_step.consistency_anchor,
        signer_public_keys: context.signer_public_keys,
    };
    chio_federation::bilateral_verifier::verify_treaty_bound_chio_bilateral_invocation(
        envelope, &review,
    )
    .map(|_| ())
    .map_err(|error| buyer_review_strict_dsse_error_code(&error))
}

pub(super) fn buyer_review_signer_public_keys_from_trust_bundle(
    verifier_trust_bundle: &serde_json::Value,
    verifier_report: &serde_json::Value,
    proof_package: &serde_json::Value,
    signer_kernel_ids: &[String],
) -> Result<Option<BTreeMap<String, PublicKey>>, &'static str> {
    let trust_bundle_sha256 = canonical_sha256(verifier_trust_bundle)
        .map_err(|_| "chio_buyer_review_strict_dsse_signer_mismatch")?;
    if verifier_report
        .get("trustBundleSha256")
        .and_then(serde_json::Value::as_str)
        != Some(trust_bundle_sha256.as_str())
    {
        return Err("chio_buyer_review_strict_dsse_signer_mismatch");
    }
    let Some(trusted_peers) = verifier_trust_bundle
        .get("peers")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let Some(proof_bindings) = proof_package
        .get("peerLadderBindings")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let expected_signers: BTreeSet<&str> = signer_kernel_ids.iter().map(String::as_str).collect();
    let mut signer_public_keys = BTreeMap::new();
    for binding in trusted_peers {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chio_buyer_review_strict_dsse_signer_mismatch");
        };
        let public_key = PublicKey::from_hex(public_key_hex)
            .map_err(|_| "chio_buyer_review_strict_dsse_signature_invalid")?;
        if signer_public_keys
            .insert(kernel_id.to_string(), public_key)
            .is_some()
        {
            return Err("chio_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    for binding in proof_bindings {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chio_buyer_review_strict_dsse_signer_mismatch");
        };
        let Some(trusted_key) = signer_public_keys.get(kernel_id) else {
            return Err("chio_buyer_review_strict_dsse_signer_mismatch");
        };
        if trusted_key.to_hex() != public_key_hex {
            return Err("chio_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    if signer_public_keys.is_empty() {
        return Ok(None);
    }
    if signer_kernel_ids
        .iter()
        .any(|kernel_id| !signer_public_keys.contains_key(kernel_id))
    {
        return Err("chio_buyer_review_strict_dsse_signer_mismatch");
    }
    Ok(Some(signer_public_keys))
}

fn buyer_review_strict_dsse_error_code(
    error: &chio_federation::bilateral_verifier::VerifierError,
) -> &'static str {
    match error {
        chio_federation::bilateral_verifier::VerifierError::PredicateTypeUnrecognised(_)
        | chio_federation::bilateral_verifier::VerifierError::StatementMalformed(_)
        | chio_federation::bilateral_verifier::VerifierError::StatementSchemaInvalid(_) => {
            "chio_buyer_review_non_strict_dsse"
        }
        chio_federation::bilateral_verifier::VerifierError::PredicateSchemaInvalid(message) => {
            if message.contains("missing treaty_binding_ref") {
                "chio_buyer_review_missing_treaty_dsse_binding"
            } else if message.contains("signer_kernel_ids") || message.contains("signer kernels") {
                "chio_buyer_review_strict_dsse_signer_mismatch"
            } else {
                "chio_buyer_review_strict_dsse_binding_mismatch"
            }
        }
        chio_federation::bilateral_verifier::VerifierError::PeerUnpinnedOrKeyidMismatch(_) => {
            "chio_buyer_review_strict_dsse_signer_mismatch"
        }
        chio_federation::bilateral_verifier::VerifierError::SignatureServerAInvalid(_)
        | chio_federation::bilateral_verifier::VerifierError::SignatureServerBInvalid(_) => {
            "chio_buyer_review_strict_dsse_signature_invalid"
        }
        chio_federation::bilateral_verifier::VerifierError::DsseMalformed(message) => {
            if message.contains("duplicate signature")
                || message.contains("signature keyid")
                || message.contains("signer keys")
                || message.contains("independent Org")
                || message.contains("expected exactly 2 signatures")
            {
                "chio_buyer_review_strict_dsse_signature_invalid"
            } else {
                "chio_buyer_review_non_strict_dsse"
            }
        }
        _ => "chio_buyer_review_strict_dsse_binding_mismatch",
    }
}
