use std::collections::BTreeSet;

use chio_core_types::receipt::body::ChioReceipt;

use crate::hash::canonical_sha256;
use crate::treaty::{validate_receipt_lineage_bundle, validate_receipt_lineage_statement};
use crate::types::{
    BilateralInvocation, BuyerAttestationPacket, ReceiptLineageBundle, ReceiptLineageStatement,
};
use crate::validation::rejected;
use crate::{bilateral_invocation_binding_sha256, ChioRuntimeError};

pub(super) fn verify_buyer_review_lineage_binding(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    lineage_bundle: &ReceiptLineageBundle,
    bilateral: &BilateralInvocation,
) -> Result<(), &'static str> {
    let lineage_sha256 =
        canonical_sha256(lineage).map_err(|_| "chio_buyer_review_packet_hash_mismatch")?;
    if lineage_sha256 != packet.receipt_lineage_statement_sha256 {
        return Err("chio_buyer_review_packet_hash_mismatch");
    }
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)
        .map_err(|_| "chio_treaty_bilateral_mismatch")?;
    if bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
    {
        return Err("chio_treaty_bilateral_mismatch");
    }
    let mut bundle_contains_packet_statement = false;
    for statement in &lineage_bundle.statements {
        let statement_sha256 =
            canonical_sha256(statement).map_err(|_| "chio_lineage_bundle_incomplete")?;
        if statement_sha256 == packet.receipt_lineage_statement_sha256 {
            bundle_contains_packet_statement = true;
            break;
        }
    }
    if !bundle_contains_packet_statement {
        return Err("chio_lineage_bundle_incomplete");
    }
    if lineage_bundle.root_receipt_sha256 != bilateral.local_receipt_sha256
        || lineage_bundle.leaf_receipt_sha256 != bilateral.remote_receipt_sha256
    {
        return Err("chio_treaty_bilateral_mismatch");
    }
    Ok(())
}

pub(super) fn verify_buyer_review_proof_package(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    workflow_sha256: &str,
    bilateral_dsse_sha256: &str,
) -> Result<(), &'static str> {
    if proof_package
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some("chio.attest.proof-package.v1")
    {
        return Err("chio_buyer_review_proof_package_incomplete");
    }
    for field in [
        "toolReceipts",
        "bilateralEnvelopes",
        "capabilityLeases",
        "leaseScopeBindings",
        "peerLadderBindings",
        "vendorKeys",
    ] {
        let Some(values) = proof_package
            .get(field)
            .and_then(serde_json::Value::as_array)
        else {
            return Err("chio_buyer_review_proof_package_incomplete");
        };
        if values.is_empty() {
            return Err("chio_buyer_review_proof_package_incomplete");
        }
    }
    if !proof_package
        .get("selectiveDisclosureProof")
        .is_some_and(serde_json::Value::is_object)
        || !proof_package
            .get("workflowIntersection")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("chio_buyer_review_proof_package_incomplete");
    }
    let Some(embedded_workflow_receipt) = proof_package.get("workflowReceipt") else {
        return Err("chio_buyer_review_proof_package_incomplete");
    };
    if embedded_workflow_receipt != workflow_receipt {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    let embedded_workflow_sha256 = canonical_sha256(embedded_workflow_receipt)
        .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
    if embedded_workflow_sha256 != workflow_sha256 {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    if proof_package.get("treatyBilateralEnvelopes").is_some() {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    let bilateral_envelopes = proof_package
        .get("bilateralEnvelopes")
        .and_then(serde_json::Value::as_array)
        .ok_or("chio_buyer_review_proof_package_incomplete")?;
    let mut contains_hydrated_envelope = false;
    for envelope in bilateral_envelopes {
        let envelope_sha256 =
            canonical_sha256(envelope).map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
        if envelope_sha256 == bilateral_dsse_sha256 {
            contains_hydrated_envelope = true;
            break;
        }
    }
    if !contains_hydrated_envelope {
        return Err("chio_buyer_review_proof_package_mismatch");
    }
    Ok(())
}

pub(super) fn verify_buyer_review_existing_verifier(
    verifier_report: &serde_json::Value,
    context: &BuyerReviewExistingVerifierContext<'_>,
) -> Result<(), &'static str> {
    if verifier_report
        .get("packageSha256")
        .and_then(serde_json::Value::as_str)
        != Some(context.proof_sha256)
        || verifier_report
            .get("trustBundleSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.trust_bundle_sha256)
        || verifier_report
            .get("contextSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.verification_context_sha256)
        || verifier_report
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err("chio_buyer_review_verifier_report_rejected");
    }
    let proof_package_json = serde_json::to_string(context.proof_package)
        .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let verifier_trust_bundle_json = serde_json::to_string(context.verifier_trust_bundle)
        .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let verification_context_json = serde_json::to_string(context.verification_context)
        .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let typed_package =
        chio_attest_buyer_core::proof_package::proof_package_from_json(&proof_package_json)
            .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let typed_trust_bundle = chio_attest_buyer_core::trust_bundle::verifier_trust_bundle_from_json(
        &verifier_trust_bundle_json,
    )
    .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let typed_context =
        chio_attest_buyer_core::context::verification_context_from_json(&verification_context_json)
            .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    let expected_report = chio_attest_buyer_core::report::verify_package_report(
        &typed_package,
        &typed_trust_bundle,
        &typed_context,
    );
    if !expected_report.accepted {
        return Err("chio_buyer_review_verifier_report_rejected");
    }
    if expected_report.package_sha256 != context.proof_sha256
        || expected_report.trust_bundle_sha256.as_deref() != Some(context.trust_bundle_sha256)
        || expected_report.context_sha256.as_deref() != Some(context.verification_context_sha256)
    {
        return Err("chio_buyer_review_verifier_report_rejected");
    }
    let expected_sha256 = canonical_sha256(&expected_report)
        .map_err(|_| "chio_buyer_review_verifier_report_rejected")?;
    if expected_sha256 != context.verifier_sha256 {
        return Err("chio_buyer_review_verifier_report_rejected");
    }
    Ok(())
}

pub(super) struct BuyerReviewExistingVerifierContext<'a> {
    pub(super) proof_package: &'a serde_json::Value,
    pub(super) verifier_trust_bundle: &'a serde_json::Value,
    pub(super) verification_context: &'a serde_json::Value,
    pub(super) proof_sha256: &'a str,
    pub(super) trust_bundle_sha256: &'a str,
    pub(super) verification_context_sha256: &'a str,
    pub(super) verifier_sha256: &'a str,
}

fn receipt_wire_value_matches_parsed_receipt(
    wire_value: &serde_json::Value,
    receipt: &ChioReceipt,
) -> Result<bool, &'static str> {
    let typed_value =
        serde_json::to_value(receipt).map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
    let mut normalized_wire_value = wire_value.clone();
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "trust_level",
        |value| value.as_str() == Some("mediated"),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "algorithm",
        |value| value.as_str() == Some("ed25519") || value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "evidence",
        |value| value.as_array().is_some_and(Vec::is_empty),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "metadata",
        |value| value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "tenant_id",
        |value| value.is_null(),
    );
    Ok(normalized_wire_value == typed_value)
}

fn remove_default_receipt_wire_field<F>(
    wire_value: &mut serde_json::Value,
    typed_value: &serde_json::Value,
    field: &str,
    is_default: F,
) where
    F: Fn(&serde_json::Value) -> bool,
{
    if typed_value.get(field).is_some() {
        return;
    }
    let Some(wire_object) = wire_value.as_object_mut() else {
        return;
    };
    if wire_object.get(field).is_some_and(is_default) {
        wire_object.remove(field);
    }
}

pub(super) fn proof_package_contains_signed_receipt(
    proof_package: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chio_buyer_review_proof_package_incomplete")?
        .iter()
        .map(|value| {
            let actual_sha256 =
                canonical_sha256(value).map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
            if actual_sha256 != expected_sha256 {
                return Ok(false);
            }
            let receipt: ChioReceipt = serde_json::from_value(value.clone())
                .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
            if !receipt_wire_value_matches_parsed_receipt(value, &receipt)? {
                return Err("chio_buyer_review_proof_package_mismatch");
            }
            let signature_valid = receipt
                .verify_signature()
                .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
            if !signature_valid {
                return Err("chio_buyer_review_proof_package_mismatch");
            }
            Ok(true)
        })
        .try_fold(false, |found, current| {
            current.map(|current| found || current)
        })
}

pub(super) fn proof_package_array_contains_field(
    proof_package: &serde_json::Value,
    array_field: &str,
    field: &str,
    expected: &str,
) -> bool {
    proof_package
        .get(array_field)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .get(field)
                    .or_else(|| value.get("body").and_then(|body| body.get(field)))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actual| actual == expected)
            })
        })
}

pub(super) fn workflow_receipt_contains_step_hash(
    workflow_receipt: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    Ok(workflow_step_by_hash(workflow_receipt, expected_sha256)?.is_some())
}

pub(super) fn workflow_step_by_hash<'a>(
    workflow_receipt: &'a serde_json::Value,
    expected_sha256: &str,
) -> Result<Option<&'a serde_json::Value>, &'static str> {
    let Some(steps) = workflow_receipt
        .get("steps")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(workflow_receipt
            .get("workflowStepSha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|hash| hash == expected_sha256)
            .then_some(workflow_receipt));
    };
    for step in steps {
        let hash =
            canonical_sha256(step).map_err(|_| "chio_buyer_review_runtime_report_mismatch")?;
        if hash == expected_sha256 {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

pub(super) fn proof_package_contains_parent_lineage_anchor(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    child_workflow_step_sha256: &str,
    parent_sha256: &str,
) -> Result<bool, &'static str> {
    if proof_package_contains_signed_receipt(proof_package, parent_sha256)? {
        return Ok(true);
    }
    let Some(child_step) = workflow_step_by_hash(workflow_receipt, child_workflow_step_sha256)?
    else {
        return Ok(false);
    };
    if child_step
        .get("parent_receipt_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(parent_sha256)
    {
        return Ok(false);
    }
    workflow_receipt_contains_step_hash(workflow_receipt, parent_sha256)
}

pub(super) fn proof_package_receipt_subject(
    proof_package: &serde_json::Value,
    receipt_sha256: &str,
) -> Result<(String, String), &'static str> {
    let receipts = proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chio_buyer_review_proof_package_incomplete")?;
    for receipt_value in receipts {
        let Ok(actual_sha256) = canonical_sha256(receipt_value) else {
            return Err("chio_buyer_review_proof_package_mismatch");
        };
        if actual_sha256 != receipt_sha256 {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_value(receipt_value.clone())
            .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
        if !receipt_wire_value_matches_parsed_receipt(receipt_value, &receipt)? {
            return Err("chio_buyer_review_proof_package_mismatch");
        }
        let signature_valid = receipt
            .verify_signature()
            .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
        if !signature_valid {
            return Err("chio_buyer_review_proof_package_mismatch");
        }
        let subject_sha256 = canonical_sha256(&receipt.body())
            .map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
        return Ok((
            chio_federation::bilateral_dsse::receipt_subject_name(&receipt.id),
            subject_sha256,
        ));
    }
    Err("chio_buyer_review_proof_package_mismatch")
}

pub(super) fn proof_package_capability_lease_ref(
    proof_package: &serde_json::Value,
    lease_id: &str,
) -> Result<chio_federation::bilateral_dsse::CapabilityLeaseRef, &'static str> {
    let leases = proof_package
        .get("capabilityLeases")
        .and_then(serde_json::Value::as_array)
        .ok_or("chio_buyer_review_proof_package_incomplete")?;
    for lease in leases {
        let body = lease.get("body").unwrap_or(lease);
        if body.get("leaseId").and_then(serde_json::Value::as_str) != Some(lease_id) {
            continue;
        }
        let issuer = body
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .ok_or("chio_buyer_review_proof_package_mismatch")?;
        let expires_at_unix_ms = body
            .get("expiresAtUnixMs")
            .and_then(serde_json::Value::as_u64)
            .ok_or("chio_buyer_review_proof_package_mismatch")?;
        let scope_digest = body
            .get("scopeDigest")
            .and_then(serde_json::Value::as_str)
            .ok_or("chio_buyer_review_proof_package_mismatch")?;
        return Ok(chio_federation::bilateral_dsse::CapabilityLeaseRef {
            lease_id: lease_id.to_string(),
            issuer: issuer.to_string(),
            expires_at_unix_ms,
            scope_digest: Some(chio_federation::bilateral_dsse::HashRecord {
                alg: "sha256".to_string(),
                value: scope_digest.to_string(),
            }),
        });
    }
    Err("chio_buyer_review_proof_package_mismatch")
}

pub(super) fn proof_package_governance_receipt_ref(
    proof_package: &serde_json::Value,
    receipt_id: &str,
) -> Result<chio_federation::bilateral_dsse::GovernanceReceiptRef, &'static str> {
    let receipts = proof_package
        .get("governanceReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chio_buyer_review_proof_package_incomplete")?;
    for receipt in receipts {
        let body = receipt.get("body").unwrap_or(receipt);
        if body.get("receiptId").and_then(serde_json::Value::as_str) != Some(receipt_id) {
            continue;
        }
        let kernel_id = body
            .get("authorizingKernel")
            .or_else(|| body.get("kernelId"))
            .and_then(serde_json::Value::as_str)
            .ok_or("chio_buyer_review_proof_package_mismatch")?;
        let digest =
            canonical_sha256(receipt).map_err(|_| "chio_buyer_review_proof_package_mismatch")?;
        if receipt
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|claimed| claimed != digest)
        {
            return Err("chio_buyer_review_proof_package_mismatch");
        }
        return Ok(chio_federation::bilateral_dsse::GovernanceReceiptRef {
            receipt_id: receipt_id.to_string(),
            kernel_id: kernel_id.to_string(),
            digest: chio_federation::bilateral_dsse::HashRecord {
                alg: "sha256".to_string(),
                value: digest,
            },
        });
    }
    Err("chio_buyer_review_proof_package_mismatch")
}

pub fn verify_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<bool, ChioRuntimeError> {
    validate_receipt_lineage_bundle(bundle)?;
    if bundle.statements.is_empty() {
        return rejected(
            "chio_lineage_bundle_incomplete",
            "receipt lineage bundle must contain at least one statement",
        );
    }
    let mut seen_statement_ids = BTreeSet::new();
    let mut seen_receipts = BTreeSet::new();
    let mut current = bundle.root_receipt_sha256.clone();
    seen_receipts.insert(current.clone());
    for statement in &bundle.statements {
        validate_receipt_lineage_statement(statement)?;
        if statement.evidence_class != "verified" {
            return rejected(
                "chio_lineage_bundle_unverified_edge",
                "receipt lineage bundle requires verified lineage edges",
            );
        }
        if !seen_statement_ids.insert(statement.statement_id.clone()) {
            return rejected(
                "chio_lineage_bundle_cycle",
                "receipt lineage bundle contains duplicate statement id",
            );
        }
        if statement.parent_receipt_sha256 != current {
            return rejected(
                "chio_lineage_bundle_incomplete",
                "receipt lineage bundle has a parent-child gap",
            );
        }
        if !seen_receipts.insert(statement.child_receipt_sha256.clone()) {
            return rejected(
                "chio_lineage_bundle_cycle",
                "receipt lineage bundle reuses a child receipt",
            );
        }
        current = statement.child_receipt_sha256.clone();
    }
    if current != bundle.leaf_receipt_sha256 {
        return rejected(
            "chio_lineage_bundle_incomplete",
            "receipt lineage bundle does not reach the declared leaf receipt",
        );
    }
    Ok(true)
}
