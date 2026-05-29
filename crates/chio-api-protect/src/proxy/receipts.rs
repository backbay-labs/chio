use super::*;

pub(crate) fn decision_label(decision: &Option<Decision>) -> String {
    match decision {
        Some(Decision::Allow) => "allow".to_string(),
        Some(Decision::Deny { .. }) => "deny".to_string(),
        Some(Decision::Cancelled { .. }) => "cancelled".to_string(),
        Some(Decision::Incomplete { .. }) => "incomplete".to_string(),
        None => "none".to_string(),
    }
}

pub(crate) fn manual_receipt_policy_hash(label: &str) -> String {
    chio_core_types::sha256_hex(label.as_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_manual_receipt(
    state: &Arc<ProxyState>,
    request_id: String,
    route_pattern: String,
    method: HttpMethod,
    caller_identity_hash: String,
    session_id: Option<String>,
    verdict: Verdict,
    response_status: u16,
    timestamp: u64,
    content_hash: String,
    capability_id: Option<String>,
    metadata: Option<serde_json::Value>,
    policy_label: &str,
) -> Result<HttpReceipt, ProtectError> {
    HttpReceipt::sign(
        HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id,
            route_pattern,
            method,
            caller_identity_hash,
            session_id,
            verdict,
            receipt_kind: chio_core_types::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status,
            timestamp,
            content_hash,
            policy_hash: manual_receipt_policy_hash(policy_label),
            trust_level: chio_core_types::TrustLevel::Mediated,
            capability_id,
            metadata,
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    )
    .map_err(|error| ProtectError::ReceiptSign(error.to_string()))
}
