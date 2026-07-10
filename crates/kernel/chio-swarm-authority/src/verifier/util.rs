use std::collections::BTreeSet;

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::error::SwarmAuthorityError;
use crate::types::{
    SwarmContinuationToken, SwarmJoinReceipt, SwarmRevocationEpoch, SwarmRoutePlanReceipt,
    SwarmTaskGraph, SwarmTerminalGraphReceipt,
};

pub(super) fn require_same_graph(
    actual: &str,
    expected: &str,
    label: &str,
) -> Result<(), SwarmAuthorityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(rejected(format!("swarm {label} graph id mismatch")))
    }
}

pub(super) fn require_non_empty(value: &str, label: &str) -> Result<(), SwarmAuthorityError> {
    if value.is_empty() {
        Err(rejected(format!("{label} must not be empty")))
    } else {
        Ok(())
    }
}

pub(super) fn require_sha256(value: &str, label: &str) -> Result<(), SwarmAuthorityError> {
    if is_sha256_hex(value) {
        Ok(())
    } else {
        Err(rejected(format!(
            "{label} must be a lowercase sha256 digest"
        )))
    }
}

pub(super) fn require_unique_strings(
    values: &[String],
    label: &str,
) -> Result<(), SwarmAuthorityError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label)?;
        if !seen.insert(value.as_str()) {
            return Err(rejected(format!("duplicate {label}: {value}")));
        }
    }
    Ok(())
}

pub(super) fn sorted_strings(values: &[String]) -> Vec<&str> {
    let mut sorted = values.iter().map(String::as_str).collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted
}

pub(super) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, SwarmAuthorityError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub(super) fn task_graph_signature_body(
    graph: &SwarmTaskGraph,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(graph).map_err(|error| {
        rejected(format!(
            "swarm task graph signature body invalid: {}: {error}",
            graph.graph_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm task graph signature body invalid: {}",
            graph.graph_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn continuation_token_signature_body(
    token: &SwarmContinuationToken,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(token).map_err(|error| {
        rejected(format!(
            "swarm continuation signature body invalid: {}: {error}",
            token.token_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm continuation signature body invalid: {}",
            token.token_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn join_receipt_signature_body(
    receipt: &SwarmJoinReceipt,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(receipt).map_err(|error| {
        rejected(format!(
            "swarm join receipt signature body invalid: {}: {error}",
            receipt.join_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm join receipt signature body invalid: {}",
            receipt.join_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn route_plan_signature_body(
    receipt: &SwarmRoutePlanReceipt,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(receipt).map_err(|error| {
        rejected(format!(
            "swarm route-plan signature body invalid: {}: {error}",
            receipt.route_plan_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm route-plan signature body invalid: {}",
            receipt.route_plan_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn revocation_epoch_signature_body(
    epoch: &SwarmRevocationEpoch,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(epoch).map_err(|error| {
        rejected(format!(
            "swarm revocation epoch signature body invalid: {}: {error}",
            epoch.epoch_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm revocation epoch signature body invalid: {}",
            epoch.epoch_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn terminal_graph_receipt_signature_body(
    receipt: &SwarmTerminalGraphReceipt,
) -> Result<serde_json::Value, SwarmAuthorityError> {
    let mut body = serde_json::to_value(receipt).map_err(|error| {
        rejected(format!(
            "swarm terminal receipt signature body invalid: {}: {error}",
            receipt.receipt_id
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        rejected(format!(
            "swarm terminal receipt signature body invalid: {}",
            receipt.receipt_id
        ))
    })?;
    object.remove("signature");
    Ok(body)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(super) fn rejected(message: impl Into<String>) -> SwarmAuthorityError {
    SwarmAuthorityError::Rejected(message.into())
}
