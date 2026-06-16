use std::{collections::BTreeSet, path::Path};

use chio_core_types::{PublicKey, Signature};

use super::{
    verify_manifest_ref, ProofRoomArtifactRef, ProofRoomReceiptCoverage, CHIO_RECEIPT_SCHEMA,
    PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA, REQUIRED_RECEIPT_COVERAGE_CATEGORIES,
};

pub(crate) fn verify(
    bundle_root: &Path,
    coverage: &[ProofRoomReceiptCoverage],
    artifacts: &[ProofRoomArtifactRef],
    require_full_matrix: bool,
) -> Result<(), String> {
    if coverage.is_empty() {
        return if require_full_matrix {
            Err("proof-room.receipt-coverage.missing".to_string())
        } else {
            Ok(())
        };
    }

    let mut categories = BTreeSet::new();
    for entry in coverage {
        if !categories.insert(entry.category.as_str()) {
            return Err(format!(
                "proof-room.receipt-coverage.duplicate: {}",
                entry.category
            ));
        }
        if !REQUIRED_RECEIPT_COVERAGE_CATEGORIES.contains(&entry.category.as_str()) {
            return Err(format!(
                "proof-room.receipt-coverage.category-unsupported: {}",
                entry.category
            ));
        }
        match entry.status.as_str() {
            "covered" => verify_covered_category(bundle_root, entry, artifacts)?,
            "excluded" => verify_excluded_category(entry)?,
            _ => {
                return Err(format!(
                    "proof-room.receipt-coverage.status-unsupported: {}",
                    entry.category
                ));
            }
        }
    }

    if require_full_matrix {
        for required_category in REQUIRED_RECEIPT_COVERAGE_CATEGORIES {
            if !categories.contains(required_category) {
                return Err(format!(
                    "proof-room.receipt-coverage.category-missing: {required_category}"
                ));
            }
        }
    }
    Ok(())
}

fn verify_covered_category(
    bundle_root: &Path,
    entry: &ProofRoomReceiptCoverage,
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let artifact_path = entry.artifact_path.as_deref().ok_or_else(|| {
        format!(
            "proof-room.receipt-coverage.artifact-missing: {}",
            entry.category
        )
    })?;
    let declared_status = entry.terminal_status.as_deref().ok_or_else(|| {
        format!(
            "proof-room.receipt-coverage.terminal-status-missing: {}",
            entry.category
        )
    })?;
    if !terminal_status_matches_category(&entry.category, declared_status) {
        return Err(format!(
            "proof-room.receipt-coverage.status-mismatch: {}",
            entry.category
        ));
    }
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.path == artifact_path)
        .ok_or_else(|| {
            format!(
                "proof-room.receipt-coverage.artifact-unregistered: {} -> {artifact_path}",
                entry.category
            )
        })?;
    if !is_receipt_coverage_schema(&artifact.schema) {
        return Err(format!(
            "proof-room.schema-mismatch: receipt_coverage expected {PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA}"
        ));
    }
    let receipt = verify_manifest_ref(bundle_root, artifact, "receipt_coverage", None)?;
    let value: serde_json::Value = serde_json::from_slice(&receipt.bytes).map_err(|error| {
        format!(
            "proof-room.receipt-coverage.invalid-json: {}: {error}",
            entry.category
        )
    })?;
    let actual_status = value
        .get("terminal_status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "proof-room.receipt-coverage.terminal-status-missing: {}",
                entry.category
            )
        })?;
    if actual_status != declared_status
        || !terminal_status_matches_category(&entry.category, actual_status)
    {
        return Err(format!(
            "proof-room.receipt-coverage.status-mismatch: {}",
            entry.category
        ));
    }
    let receipt_id = required_receipt_field(&value, "receipt_id", &entry.category)?;
    let _policy_digest = required_receipt_field(&value, "policy_digest", &entry.category)?;
    let _signature = required_receipt_field(&value, "signature", &entry.category)?;
    let _kernel_key = required_receipt_field(&value, "kernel_key", &entry.category)?;
    verify_receipt_signature(&entry.category, receipt_id, &value)?;
    Ok(())
}

fn is_receipt_coverage_schema(schema: &str) -> bool {
    schema == PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA || schema == CHIO_RECEIPT_SCHEMA
}

fn required_receipt_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
    category: &str,
) -> Result<&'a str, String> {
    let field_value = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.receipt-coverage.{field}-missing: {category}"))?;
    if field_value.is_empty() {
        return Err(format!(
            "proof-room.receipt-coverage.{field}-missing: {category}"
        ));
    }
    Ok(field_value)
}

fn verify_receipt_signature(
    category: &str,
    receipt_id: &str,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    let signature = required_receipt_field(receipt, "signature", category)?;
    let kernel_key = required_receipt_field(receipt, "kernel_key", category)?;
    let public_key = PublicKey::from_hex(kernel_key).map_err(|error| {
        format!("proof-room.receipt-coverage.signature-invalid: {category}: {error}")
    })?;
    let signature = Signature::from_hex(signature).map_err(|error| {
        format!("proof-room.receipt-coverage.signature-invalid: {category}: {error}")
    })?;
    let mut signed_body = receipt.clone();
    let Some(signed_body_object) = signed_body.as_object_mut() else {
        return Err(format!(
            "proof-room.receipt-coverage.invalid-json: {category}"
        ));
    };
    signed_body_object.remove("signature");
    let verified = public_key
        .verify_canonical(&signed_body, &signature)
        .map_err(|error| {
            format!("proof-room.receipt-coverage.signature-invalid: {category}: {error}")
        })?;
    if verified {
        return Ok(());
    }
    Err(format!(
        "proof-room.receipt-coverage.signature-invalid: {category}: {receipt_id}"
    ))
}

fn verify_excluded_category(entry: &ProofRoomReceiptCoverage) -> Result<(), String> {
    let Some(reason) = entry.exclusion_reason.as_deref() else {
        return Err(format!(
            "proof-room.receipt-coverage.exclusion-reason-missing: {}",
            entry.category
        ));
    };
    if reason.is_empty() {
        return Err(format!(
            "proof-room.receipt-coverage.exclusion-reason-missing: {}",
            entry.category
        ));
    }
    if entry.artifact_path.is_some() || entry.terminal_status.is_some() {
        return Err(format!(
            "proof-room.receipt-coverage.exclusion-has-artifact: {}",
            entry.category
        ));
    }
    Ok(())
}

fn terminal_status_matches_category(category: &str, status: &str) -> bool {
    match category {
        "runtime_terminal_allow" => status.starts_with("allowed_"),
        "runtime_terminal_denial" => status.starts_with("denied_"),
        "runtime_terminal_failure" => status.starts_with("failed_"),
        _ => false,
    }
}
