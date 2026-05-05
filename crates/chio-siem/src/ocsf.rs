//! OCSF (Open Cybersecurity Schema Framework) mapping for Chio receipts.
//!
//! This module transforms an [`ChioReceipt`] into a JSON object conforming to
//! the OCSF 1.3.0 Authorization event class (category 3 / class_uid 3002).
//!
//! Reference: <https://schema.ocsf.io/1.3.0/classes/authorization>
//!
//! ## Mapping summary
//!
//! | ChioReceipt field                | OCSF field                          |
//! |---------------------------------|-------------------------------------|
//! | `id`                            | `metadata.uid`                      |
//! | `timestamp` (unix seconds)      | `time` (unix milliseconds)          |
//! | `tool_server`                   | `dst_endpoint.name`                 |
//! | `tool_name`                     | `api.operation`                     |
//! | `action.parameters`             | `api.request.data`                  |
//! | `action.parameter_hash`         | `unmapped.action.parameter_hash`    |
//! | `decision` (verdict)            | `activity_id` / `activity_name` / `status_id` / `status` / `severity_id` / `severity` |
//! | `decision.reason` (Deny)        | `status_detail`                     |
//! | `decision.guard` (Deny)         | `unmapped.chio.guard`                |
//! | `policy_hash`                   | `policy.uid`                        |
//! | `content_hash`                  | `unmapped.chio.content_hash`         |
//! | `capability_id`                 | `observables[*]`, `unmapped.chio.capability_id` |
//! | `evidence[]`                    | `enrichments[*]` (one per guard)    |
//! | `trust_level`                   | `enrichments[0].data.trust_level` and top-level `unmapped.chio.trust_level` |
//! | `metadata.tenant_id` (if any)   | `unmapped.chio.tenant_id`            |
//! | full canonical JSON             | `raw_data`                          |
//!
//! ## Fail-closed behaviour
//!
//! Serialization failures are translated into an Unknown / Unknown event
//! that still carries `class_uid = 3002` so downstream consumers can reason
//! about the failure. Mapping never panics.

use chio_core::receipt::{ChioReceipt, Decision, GuardEvidence, TrustLevel};
use serde_json::{json, Map, Value};

use crate::redaction::redact_for_operator_log;

/// OCSF schema version targeted by this mapper.
pub const OCSF_SCHEMA_VERSION: &str = "1.3.0";

/// OCSF Authorization event class identifier.
pub const OCSF_CLASS_UID: u32 = 3002;

/// OCSF Authorization class name.
pub const OCSF_CLASS_NAME: &str = "Authorization";

/// OCSF IAM category identifier (parent of class 3002).
pub const OCSF_CATEGORY_UID: u32 = 3;

/// OCSF IAM category name.
pub const OCSF_CATEGORY_NAME: &str = "Identity & Access Management";

/// Product name surfaced in OCSF metadata.
pub const OCSF_PRODUCT_NAME: &str = "Chio";

/// Product vendor surfaced in OCSF metadata.
pub const OCSF_PRODUCT_VENDOR: &str = "Backbay Industries";

/// Convert an [`ChioReceipt`] into an OCSF 1.3.0 Authorization event.
///
/// The returned value is always a JSON object with `class_uid = 3002`. If any
/// component of the mapping fails (for example, `serde_json` cannot serialize
/// the receipt into `raw_data`) the function still returns a best-effort event
/// with `status_id = 0` (Unknown) and an `unmapped` block describing the
/// failure. It never panics.
#[must_use]
pub fn receipt_to_ocsf(receipt: &ChioReceipt) -> Value {
    let (activity_id, activity_name) = activity_for(&receipt.decision);
    let (status_id, status_name) = status_for(&receipt.decision);
    let (severity_id, severity_name) = severity_for(&receipt.decision);
    let type_uid = OCSF_CLASS_UID * 100 + activity_id;

    let mut event = Map::new();
    event.insert("category_uid".into(), json!(OCSF_CATEGORY_UID));
    event.insert("category_name".into(), json!(OCSF_CATEGORY_NAME));
    event.insert("class_uid".into(), json!(OCSF_CLASS_UID));
    event.insert("class_name".into(), json!(OCSF_CLASS_NAME));
    event.insert("type_uid".into(), json!(type_uid));
    event.insert(
        "type_name".into(),
        json!(format!("{OCSF_CLASS_NAME}: {activity_name}")),
    );
    event.insert("activity_id".into(), json!(activity_id));
    event.insert("activity_name".into(), json!(activity_name));
    event.insert("status_id".into(), json!(status_id));
    event.insert("status".into(), json!(status_name));
    event.insert("severity_id".into(), json!(severity_id));
    event.insert("severity".into(), json!(severity_name));

    // OCSF time is epoch milliseconds. Receipt timestamps are unix seconds.
    let time_ms = (receipt.timestamp as u128).saturating_mul(1_000);
    event.insert("time".into(), json!(time_ms as u64));

    if let Decision::Deny { reason, .. } = &receipt.decision {
        event.insert("status_detail".into(), json!(reason));
    }

    event.insert(
        "metadata".into(),
        json!({
            "version": OCSF_SCHEMA_VERSION,
            "uid": receipt.id,
            "product": {
                "name": OCSF_PRODUCT_NAME,
                "vendor_name": OCSF_PRODUCT_VENDOR,
            },
        }),
    );

    event.insert(
        "api".into(),
        json!({
            "operation": receipt.tool_name,
            "service": {
                "name": receipt.tool_server,
            },
            "request": {
                "uid": receipt.id,
                "data": receipt.action.parameters,
            },
        }),
    );

    event.insert(
        "dst_endpoint".into(),
        json!({
            "name": receipt.tool_server,
            "svc_name": receipt.tool_server,
        }),
    );

    event.insert(
        "actor".into(),
        json!({
            "invoked_by": "chio-agent",
            "authorizations": [
                {
                    "policy": {
                        "uid": receipt.policy_hash,
                    },
                    "decision": activity_name,
                }
            ],
        }),
    );

    event.insert(
        "policy".into(),
        json!({
            "uid": receipt.policy_hash,
            "name": "chio-policy",
        }),
    );

    event.insert("observables".into(), build_observables(receipt));
    event.insert("enrichments".into(), build_enrichments(receipt));
    event.insert("unmapped".into(), build_unmapped(receipt));

    match serde_json::to_string(receipt) {
        Ok(raw) => {
            event.insert("raw_data".into(), Value::String(raw));
        }
        Err(err) => {
            tracing::warn!(
                receipt_id = %receipt.id,
                error = %redact_for_operator_log(&err),
                "failed to serialize ChioReceipt to raw_data; emitting Unknown status",
            );
            event.insert("status_id".into(), json!(0));
            event.insert("status".into(), json!("Unknown"));
            if let Some(unmapped) = event.get_mut("unmapped") {
                if let Some(obj) = unmapped.as_object_mut() {
                    obj.insert("raw_data_error".into(), Value::String(format!("{err}")));
                }
            }
        }
    }

    Value::Object(event)
}

fn activity_for(decision: &Decision) -> (u32, &'static str) {
    match decision {
        // OCSF Authorization activity_id enum:
        //   0 Unknown, 1 Grant, 2 Revoke, 99 Other.
        // Chio Allow maps to Grant; Deny maps to a refused grant, which OCSF
        // represents with activity Grant + status Failure (not Revoke, which
        // is a prior grant being rescinded). Cancelled and Incomplete are
        // neither Grant nor Revoke; they surface as Other.
        Decision::Allow => (1, "Grant"),
        Decision::Deny { .. } => (1, "Grant"),
        Decision::Cancelled { .. } => (99, "Other"),
        Decision::Incomplete { .. } => (99, "Other"),
    }
}

fn status_for(decision: &Decision) -> (u32, &'static str) {
    match decision {
        // OCSF status_id enum: 0 Unknown, 1 Success, 2 Failure, 99 Other.
        Decision::Allow => (1, "Success"),
        Decision::Deny { .. } => (2, "Failure"),
        Decision::Cancelled { .. } => (2, "Failure"),
        Decision::Incomplete { .. } => (99, "Other"),
    }
}

fn severity_for(decision: &Decision) -> (u32, &'static str) {
    match decision {
        // OCSF severity_id enum:
        //   0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
        //   5 Critical, 6 Fatal, 99 Other.
        Decision::Allow => (1, "Informational"),
        Decision::Deny { .. } => (4, "High"),
        Decision::Cancelled { .. } => (2, "Low"),
        Decision::Incomplete { .. } => (3, "Medium"),
    }
}

fn build_observables(receipt: &ChioReceipt) -> Value {
    // OCSF observable type_id enum (selected values): 1 Hostname, 6 Endpoint,
    // 10 Resource UID, 20 Endpoint Name, 99 Other. We use:
    //   10 Resource UID  -- for receipt/capability identifiers
    //   20 Endpoint Name -- for tool server endpoints
    //   99 Other         -- for catch-all references (e.g. tool_name)
    let mut observables = vec![
        json!({
            "name": "chio.receipt.id",
            "type": "Resource UID",
            "type_id": 10,
            "value": receipt.id,
        }),
        json!({
            "name": "chio.capability.id",
            "type": "Resource UID",
            "type_id": 10,
            "value": receipt.capability_id,
        }),
        json!({
            "name": "chio.tool.server",
            "type": "Endpoint Name",
            "type_id": 20,
            "value": receipt.tool_server,
        }),
        json!({
            "name": "chio.tool.name",
            "type": "Other",
            "type_id": 99,
            "value": receipt.tool_name,
        }),
        json!({
            "name": "chio.policy.hash",
            "type": "Resource UID",
            "type_id": 10,
            "value": receipt.policy_hash,
        }),
        json!({
            "name": "chio.content.hash",
            "type": "Resource UID",
            "type_id": 10,
            "value": receipt.content_hash,
        }),
    ];

    if let Decision::Deny { guard, .. } = &receipt.decision {
        observables.push(json!({
            "name": "chio.guard",
            "type": "Other",
            "type_id": 99,
            "value": guard,
        }));
    }

    Value::Array(observables)
}

fn build_enrichments(receipt: &ChioReceipt) -> Value {
    let mut enrichments = Vec::new();

    enrichments.push(json!({
        "name": "chio.trust_level",
        "type": "string",
        "value": trust_level_str(receipt.trust_level),
        "data": {
            "trust_level": trust_level_str(receipt.trust_level),
        },
    }));

    for (index, evidence) in receipt.evidence.iter().enumerate() {
        enrichments.push(guard_evidence_enrichment(index, evidence));
    }

    if let Some(meta) = &receipt.metadata {
        if let Some(tenant) = meta.get("tenant_id").and_then(|v| v.as_str()) {
            enrichments.push(json!({
                "name": "chio.tenant_id",
                "type": "string",
                "value": tenant,
                "data": { "tenant_id": tenant },
            }));
        }
    }

    Value::Array(enrichments)
}

fn guard_evidence_enrichment(index: usize, evidence: &GuardEvidence) -> Value {
    let mut data = Map::new();
    data.insert("guard_name".into(), json!(evidence.guard_name));
    data.insert("verdict".into(), json!(evidence.verdict));
    if let Some(details) = &evidence.details {
        data.insert("details".into(), json!(details));
    }
    json!({
        "name": format!("chio.guard.evidence.{index}"),
        "type": "dict",
        "value": evidence.guard_name,
        "data": Value::Object(data),
    })
}

fn build_unmapped(receipt: &ChioReceipt) -> Value {
    // The OCSF `unmapped` attribute holds a key/value object for fields that
    // are meaningful to the producer but are not represented in the class.
    let mut chio_map = Map::new();
    chio_map.insert("receipt.id".into(), json!(receipt.id));
    chio_map.insert("capability.id".into(), json!(receipt.capability_id));
    chio_map.insert("tool.server".into(), json!(receipt.tool_server));
    chio_map.insert("tool.name".into(), json!(receipt.tool_name));
    chio_map.insert("content.hash".into(), json!(receipt.content_hash));
    chio_map.insert("policy.hash".into(), json!(receipt.policy_hash));
    chio_map.insert(
        "action.parameter_hash".into(),
        json!(receipt.action.parameter_hash),
    );
    chio_map.insert(
        "trust_level".into(),
        json!(trust_level_str(receipt.trust_level)),
    );

    match &receipt.decision {
        Decision::Allow => {
            chio_map.insert("decision.verdict".into(), json!("allow"));
        }
        Decision::Deny { reason, guard } => {
            chio_map.insert("decision.verdict".into(), json!("deny"));
            chio_map.insert("decision.reason".into(), json!(reason));
            chio_map.insert("decision.guard".into(), json!(guard));
        }
        Decision::Cancelled { reason } => {
            chio_map.insert("decision.verdict".into(), json!("cancelled"));
            chio_map.insert("decision.reason".into(), json!(reason));
        }
        Decision::Incomplete { reason } => {
            chio_map.insert("decision.verdict".into(), json!("incomplete"));
            chio_map.insert("decision.reason".into(), json!(reason));
        }
    }

    if let Some(meta) = &receipt.metadata {
        if let Some(tenant) = meta.get("tenant_id").and_then(|v| v.as_str()) {
            chio_map.insert("tenant_id".into(), json!(tenant));
        }
    }

    let mut root = Map::new();
    root.insert("chio".into(), Value::Object(chio_map));
    Value::Object(root)
}

fn trust_level_str(level: TrustLevel) -> &'static str {
    level.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};

    fn test_receipt(id: &str, decision: Decision) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = match ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        })) {
            Ok(action) => action,
            Err(error) => panic!("hash receipt parameters: {error}"),
        };
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_712_345_678,
            capability_id: "cap-abc".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            decision,
            content_hash: "content-xyz".to_string(),
            policy_hash: "policy-xyz".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kp.public_key(),
        };
        #[allow(clippy::unwrap_used)]
        ChioReceipt::sign(body, &kp).unwrap()
    }

    #[test]
    fn allow_maps_to_class_3002_and_informational() {
        let ev = receipt_to_ocsf(&test_receipt("r-1", Decision::Allow));
        assert_eq!(ev["class_uid"], 3002);
        assert_eq!(ev["category_uid"], 3);
        assert_eq!(ev["activity_id"], 1);
        assert_eq!(ev["status_id"], 1);
        assert_eq!(ev["severity_id"], 1);
        assert_eq!(ev["type_uid"], 300_201);
    }
}
