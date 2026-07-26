use chio_core::receipt::{
    body::ChioReceiptBody,
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};

/// Expected decision inputs for the production receipt-coupling gate.
pub struct ReceiptCouplingExpectation<'a> {
    pub capability_id: &'a str,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub action: &'a ToolCallAction,
    pub decision: &'a Decision,
    pub content_hash: &'a str,
    pub policy_hash: &'a str,
    pub trust_level: TrustLevel,
}

/// Compare an assembled receipt body with the decision inputs it must attest.
#[must_use]
pub fn receipt_body_fields_coupled(
    body: &ChioReceiptBody,
    expected: &ReceiptCouplingExpectation<'_>,
) -> bool {
    let capability_matches = body.capability_id == expected.capability_id;
    let request_matches = body.tool_server == expected.server_id
        && body.tool_name == expected.tool_name
        && body.action.parameters == expected.action.parameters
        && body.action.parameter_hash == expected.action.parameter_hash
        && body.content_hash == expected.content_hash;
    let verdict_matches = body.decision.as_ref() == Some(expected.decision);
    let policy_hash_matches = body.policy_hash == expected.policy_hash;
    let evidence_class_matches = body.receipt_kind == ReceiptKind::MediatedDecision
        && body.boundary_class == BoundaryClass::Prevent
        && body.observation_outcome.is_none()
        && body.tool_origin == ToolOrigin::CallerExecuted
        && body.redaction_mode == RedactionMode::None
        && body.actor_chain.is_empty()
        && body.trust_level == expected.trust_level;

    chio_kernel_core::receipt_fields_coupled(
        capability_matches,
        request_matches,
        verdict_matches,
        policy_hash_matches,
        evidence_class_matches,
    )
}
