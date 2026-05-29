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
//! | `tenant_id` (if any)            | `unmapped.chio.tenant_id`            |
//! | full canonical JSON             | `raw_data`                          |
//!
//! ## Fail-closed behaviour
//!
//! Serialization failures are translated into an Unknown / Unknown event
//! that still carries `class_uid = 3002` so downstream consumers can reason
//! about the failure. Mapping never panics.

use chio_core::chio_receipt_id;
use chio_core::receipt::{ChioReceipt, Decision, GuardEvidence, ReceiptSemanticFields, TrustLevel};
use serde_json::{json, Map, Value};

use crate::event::SiemEvent;
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
pub const OCSF_PRODUCT_VENDOR: &str = "Backbay Labs";

/// Convert an [`ChioReceipt`] into an OCSF 1.3.0 Authorization event.
///
/// The returned value is always a JSON object with `class_uid = 3002`. If any
/// component of the mapping fails (for example, `serde_json` cannot serialize
/// the receipt into `raw_data`) the function still returns a best-effort event
/// with `status_id = 0` (Unknown) and an `unmapped` block describing the
/// failure. It never panics.
#[must_use]
pub fn receipt_to_ocsf(receipt: &ChioReceipt) -> Value {
    let semantics = receipt.semantic_fields();
    let authority = OcsfAuthority::from_receipt(receipt, &semantics);
    receipt_to_ocsf_with_authority(receipt, &semantics, authority)
}

/// Convert an already-authorized [`SiemEvent`] into OCSF.
///
/// This preserves signer trust and verification state from the SIEM manager
/// instead of recomputing authorization from the embedded receipt alone.
#[must_use]
pub fn siem_event_to_ocsf(event: &SiemEvent) -> Value {
    let receipt = &event.receipt;
    let semantics = receipt.semantic_fields();
    let authority = OcsfAuthority::from_event(event);
    receipt_to_ocsf_with_authority(receipt, &semantics, authority)
}

fn receipt_to_ocsf_with_authority(
    receipt: &ChioReceipt,
    semantics: &ReceiptSemanticFields,
    authority: OcsfAuthority,
) -> Value {
    let authorized = authority.authorized;
    let (activity_id, activity_name) = activity_for(receipt, semantics, authorized);
    let (status_id, status_name) = status_for(receipt, semantics, authorized);
    let (severity_id, severity_name) = severity_for(receipt, semantics, authorized);
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

    if let Some(Decision::Deny { reason, .. }) = &receipt.decision {
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
                    "decision": result_label_for_export(receipt, semantics, authorized),
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
    event.insert("enrichments".into(), build_enrichments(receipt, authorized));
    event.insert("unmapped".into(), build_unmapped(receipt, authority));

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

#[derive(Clone, Copy)]
struct OcsfAuthority {
    authoritative: bool,
    signature_valid: bool,
    receipt_id_valid: bool,
    parameter_hash_valid: bool,
    signer_trusted: bool,
    authorized: bool,
}

impl OcsfAuthority {
    fn from_receipt(receipt: &ChioReceipt, semantics: &ReceiptSemanticFields) -> Self {
        let receipt_id_valid = chio_receipt_id(&receipt.body())
            .map(|id| id == receipt.id)
            .unwrap_or(false);
        let signature_valid = receipt.verify_signature().unwrap_or(false);
        let parameter_hash_valid = receipt.action.verify_hash().unwrap_or(false);
        let authoritative = receipt_id_valid && signature_valid && parameter_hash_valid;
        let signer_trusted = false;
        let authorized =
            authoritative && signer_trusted && semantics.is_authorized(receipt.decision.as_ref());

        Self {
            authoritative,
            signature_valid,
            receipt_id_valid,
            parameter_hash_valid,
            signer_trusted,
            authorized,
        }
    }

    fn from_event(event: &SiemEvent) -> Self {
        Self {
            authoritative: event.authoritative,
            signature_valid: event.signature_valid,
            receipt_id_valid: event.receipt_id_valid,
            parameter_hash_valid: event.parameter_hash_valid,
            signer_trusted: event.signer_trusted,
            authorized: event.authorized,
        }
    }
}

fn result_label_for_export(
    receipt: &ChioReceipt,
    semantics: &ReceiptSemanticFields,
    authorized: bool,
) -> &'static str {
    if authorized {
        return "Authorized";
    }
    if matches!(&receipt.decision, Some(Decision::Allow))
        && semantics.is_authorized(receipt.decision.as_ref())
    {
        return "Unverified";
    }
    semantics.result_label(receipt.decision.as_ref())
}

fn activity_for(
    receipt: &ChioReceipt,
    _semantics: &ReceiptSemanticFields,
    authorized: bool,
) -> (u32, &'static str) {
    if matches!(&receipt.decision, Some(Decision::Allow)) && !authorized {
        return (99, "Other");
    }
    match &receipt.decision {
        // OCSF Authorization activity_id enum:
        //   0 Unknown, 1 Grant, 2 Revoke, 99 Other.
        // Chio Allow maps to Grant; Deny maps to a refused grant, which OCSF
        // represents with activity Grant + status Failure (not Revoke, which
        // is a prior grant being rescinded). Cancelled and Incomplete are
        // neither Grant nor Revoke; they surface as Other.
        Some(Decision::Allow) => (1, "Grant"),
        Some(Decision::Deny { .. }) => (1, "Grant"),
        Some(Decision::Cancelled { .. }) => (99, "Other"),
        Some(Decision::Incomplete { .. }) => (99, "Other"),
        None => (99, "Other"),
    }
}

fn status_for(
    receipt: &ChioReceipt,
    _semantics: &ReceiptSemanticFields,
    authorized: bool,
) -> (u32, &'static str) {
    if matches!(&receipt.decision, Some(Decision::Allow)) && !authorized {
        return (99, "Other");
    }
    match &receipt.decision {
        // OCSF status_id enum: 0 Unknown, 1 Success, 2 Failure, 99 Other.
        Some(Decision::Allow) => (1, "Success"),
        Some(Decision::Deny { .. }) => (2, "Failure"),
        Some(Decision::Cancelled { .. }) => (2, "Failure"),
        Some(Decision::Incomplete { .. }) => (99, "Other"),
        None => (99, "Other"),
    }
}

fn severity_for(
    receipt: &ChioReceipt,
    _semantics: &ReceiptSemanticFields,
    authorized: bool,
) -> (u32, &'static str) {
    if matches!(&receipt.decision, Some(Decision::Allow)) && !authorized {
        return (1, "Informational");
    }
    match &receipt.decision {
        // OCSF severity_id enum:
        //   0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
        //   5 Critical, 6 Fatal, 99 Other.
        Some(Decision::Allow) => (1, "Informational"),
        Some(Decision::Deny { .. }) => (4, "High"),
        Some(Decision::Cancelled { .. }) => (2, "Low"),
        Some(Decision::Incomplete { .. }) => (3, "Medium"),
        None => (1, "Informational"),
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

    if let Some(Decision::Deny { guard, .. }) = &receipt.decision {
        observables.push(json!({
            "name": "chio.guard",
            "type": "Other",
            "type_id": 99,
            "value": guard,
        }));
    }

    Value::Array(observables)
}

fn build_enrichments(receipt: &ChioReceipt, authorized: bool) -> Value {
    let mut enrichments = Vec::new();
    let semantics = receipt.semantic_fields();

    enrichments.push(json!({
        "name": "chio.trust_level",
        "type": "string",
        "value": trust_level_str(receipt.trust_level),
        "data": {
            "trust_level": trust_level_str(receipt.trust_level),
        },
    }));

    enrichments.push(json!({
        "name": "chio.receipt_semantics",
        "type": "dict",
        "value": semantics.receipt_kind.as_str(),
        "data": {
            "receipt_kind": semantics.receipt_kind.as_str(),
            "boundary_class": semantics.boundary_class.as_str(),
            "result": result_label_for_export(receipt, &semantics, authorized),
        },
    }));

    for (index, evidence) in receipt.evidence.iter().enumerate() {
        enrichments.push(guard_evidence_enrichment(index, evidence));
    }

    if let Some(tenant) = receipt.tenant_id.as_deref() {
        enrichments.push(json!({
            "name": "chio.tenant_id",
            "type": "string",
            "value": tenant,
            "data": { "tenant_id": tenant },
        }));
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

fn build_unmapped(receipt: &ChioReceipt, authority: OcsfAuthority) -> Value {
    // The OCSF `unmapped` attribute holds a key/value object for fields that
    // are meaningful to the producer but are not represented in the class.
    let semantics = receipt.semantic_fields();
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
    chio_map.insert(
        "receipt_kind".into(),
        json!(semantics.receipt_kind.as_str()),
    );
    chio_map.insert(
        "boundary_class".into(),
        json!(semantics.boundary_class.as_str()),
    );
    chio_map.insert(
        "result".into(),
        json!(result_label_for_export(
            receipt,
            &semantics,
            authority.authorized
        )),
    );
    chio_map.insert("authorized".into(), json!(authority.authorized));
    chio_map.insert("authoritative".into(), json!(authority.authoritative));
    chio_map.insert("signature_valid".into(), json!(authority.signature_valid));
    chio_map.insert("receipt_id_valid".into(), json!(authority.receipt_id_valid));
    chio_map.insert(
        "parameter_hash_valid".into(),
        json!(authority.parameter_hash_valid),
    );
    chio_map.insert("signer_trusted".into(), json!(authority.signer_trusted));

    match &receipt.decision {
        Some(Decision::Allow) if authority.authorized => {
            chio_map.insert("decision.verdict".into(), json!("allow"));
        }
        Some(Decision::Allow) => {
            chio_map.insert(
                "decision.verdict".into(),
                json!(semantics.receipt_kind.as_str()),
            );
        }
        Some(Decision::Deny { reason, guard }) => {
            chio_map.insert("decision.verdict".into(), json!("deny"));
            chio_map.insert("decision.reason".into(), json!(reason));
            chio_map.insert("decision.guard".into(), json!(guard));
        }
        Some(Decision::Cancelled { reason }) => {
            chio_map.insert("decision.verdict".into(), json!("cancelled"));
            chio_map.insert("decision.reason".into(), json!(reason));
        }
        Some(Decision::Incomplete { reason }) => {
            chio_map.insert("decision.verdict".into(), json!("incomplete"));
            chio_map.insert("decision.reason".into(), json!(reason));
        }
        None => {
            chio_map.insert(
                "decision.verdict".into(),
                json!(semantics.receipt_kind.as_str()),
            );
        }
    }

    if let Some(tenant) = receipt.tenant_id.as_deref() {
        chio_map.insert("tenant_id".into(), json!(tenant));
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
    use chio_core::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ReceiptSemanticFields, ToolCallAction, TrustLevel,
    };
    use chio_test_support::prelude::*;

    fn test_receipt(id: &str, decision: Decision) -> ChioReceipt {
        test_receipt_with_semantics(id, decision, None, TrustLevel::Mediated)
    }

    fn test_receipt_with_semantics(
        id: &str,
        decision: Decision,
        semantics: Option<ReceiptSemanticFields>,
        trust_level: TrustLevel,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let action = match ToolCallAction::from_parameters(serde_json::json!({
            "path": "/etc/passwd"
        })) {
            Ok(action) => action,
            Err(error) => panic!("hash receipt parameters: {error}"),
        };
        let semantics = semantics.unwrap_or_else(ReceiptSemanticFields::mediated_prevent);
        let decision = if semantics.receipt_kind == chio_core::ReceiptKind::MediatedDecision {
            Some(decision)
        } else {
            None
        };
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_712_345_678,
            capability_id: "cap-abc".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            decision,
            receipt_kind: semantics.receipt_kind,
            boundary_class: semantics.boundary_class,
            observation_outcome: semantics.observation_outcome,
            tool_origin: semantics.tool_origin,
            redaction_mode: semantics.redaction_mode,
            actor_chain: semantics.actor_chain,
            content_hash: "content-xyz".to_string(),
            policy_hash: "policy-xyz".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level,
            tenant_id: None,
            kernel_key: kp.public_key(),
        };
        #[allow(clippy::unwrap_used)]
        ChioReceipt::sign(body, &kp).test_unwrap()
    }

    #[test]
    fn raw_receipt_allow_without_trusted_signer_is_unverified() {
        let ev = receipt_to_ocsf(&test_receipt("r-1", Decision::Allow));
        assert_eq!(ev["class_uid"], 3002);
        assert_eq!(ev["category_uid"], 3);
        assert_ne!(ev["activity_name"], "Grant");
        assert_ne!(ev["status"], "Success");
        assert_eq!(ev["unmapped"]["chio"]["signer_trusted"], false);
        assert_eq!(ev["unmapped"]["chio"]["authorized"], false);
    }

    #[test]
    fn trace_observation_allow_never_maps_to_authorization_grant() {
        let receipt = test_receipt_with_semantics(
            "trace-1",
            Decision::Allow,
            Some(ReceiptSemanticFields::trace_detect_only()),
            TrustLevel::Verified,
        );
        let ev = receipt_to_ocsf(&receipt);

        assert_ne!(ev["activity_name"], "Grant");
        assert_ne!(ev["status"], "Success");
        assert_eq!(ev["unmapped"]["chio"]["receipt_kind"], "trace_observation");
        assert_eq!(ev["unmapped"]["chio"]["boundary_class"], "detect_only");
        assert_eq!(ev["unmapped"]["chio"]["authorized"], false);
    }
}
