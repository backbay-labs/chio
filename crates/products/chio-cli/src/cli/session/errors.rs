use super::*;

pub(crate) fn control_request_id(session_id: &SessionId, suffix: &str) -> RequestId {
    RequestId::new(format!("{session_id}::{suffix}"))
}

/// Build an error receipt when the kernel fails internally.
pub(crate) fn make_error_receipt(
    _kernel: &mut ChioKernel,
    request: &KernelToolCallRequest,
) -> Result<chio_core::receipt::body::ChioReceipt, chio_core::error::Error> {
    let action = chio_core::receipt::decision::ToolCallAction::from_parameters(request.arguments.clone());
    let action = match action {
        Ok(a) => a,
        Err(_) => chio_core::receipt::decision::ToolCallAction::from_parameters(serde_json::json!({}))
            .unwrap_or_else(|_| {
                chio_core::receipt::decision::ToolCallAction {
                    parameter_hash: "error".to_string(),
                    parameters: serde_json::json!({}),
                }
        }),
    };

    // Kernel failures still need a signed deny receipt for audit continuity.
    let kp = Keypair::generate();
    let body = chio_core::receipt::body::ChioReceiptBody {
        id: format!("rcpt-error-{}", request.request_id),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        capability_id: request.capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        action,
        decision: Some(chio_core::receipt::decision::Decision::Deny {
            reason: "internal kernel error".to_string(),
            guard: "kernel".to_string(),
        }),
        receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
        boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
        redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: chio_core::sha256_hex(b"null"),
        policy_hash: "error".to_string(),
        evidence: vec![],
        metadata: None,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    };

    chio_core::receipt::body::ChioReceipt::sign(body, &kp)
}
