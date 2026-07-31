use chio_core::capability::scope::{Constraint, ToolGrant};
use chio_kernel_core::CapabilityError;

use crate::event::{AgUiEvent, EventClassification};

pub(super) fn capability_error_message(error: &CapabilityError) -> &'static str {
    match error {
        CapabilityError::UntrustedIssuer => "issuer is not trusted",
        CapabilityError::InvalidSignature => "signature did not verify",
        CapabilityError::NotYetValid => "token is not yet valid",
        CapabilityError::Expired => "token has expired",
        CapabilityError::CryptoFloorRejected(_) => "capability crypto floor rejected",
        CapabilityError::AttenuationViolation(_) => "capability rejected by chain binding",
        CapabilityError::BudgetSplitRejected(_) => "capability rejected by sibling-sum budget",
        CapabilityError::Internal(_) => "internal verification error",
    }
}

pub(super) fn restricted_tool_name(classification: &EventClassification) -> &'static str {
    match classification {
        EventClassification::Display => "display",
        EventClassification::Mutate => "mutate",
        EventClassification::Navigate => "navigate",
        EventClassification::Create => "create",
        EventClassification::Destroy => "destroy",
        EventClassification::Submit => "submit",
        EventClassification::Alert => "alert",
    }
}

pub(super) fn event_scope_arguments(event: &AgUiEvent) -> serde_json::Value {
    let mut args = serde_json::json!({
        "event_id": event.event_id,
        "agent_id": event.agent_id,
        "event_classification": restricted_tool_name(&event.classification),
        "payload": event.payload,
    });

    if let serde_json::Value::Object(ref mut map) = args {
        if let Some(session_id) = &event.session_id {
            map.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.clone()),
            );
        }
        if let Some(target) = &event.target {
            map.insert(
                "target_component_type".to_string(),
                serde_json::Value::String(target.component_type.clone()),
            );
            if let Some(component_id) = &target.component_id {
                map.insert(
                    "target_component_id".to_string(),
                    serde_json::Value::String(component_id.clone()),
                );
            }
        }
    }

    args
}

pub(super) fn grant_binds_event(grant: &ToolGrant, event: &AgUiEvent) -> bool {
    if !custom_constraint_matches_if_present(grant, "event_id", &event.event_id) {
        return false;
    }

    if !trusted_custom_constraint_matches(grant, "session_id", event.session_id.as_deref()) {
        return false;
    }

    let target_component_type = event
        .target
        .as_ref()
        .map(|target| target.component_type.as_str());
    if !trusted_custom_constraint_matches(grant, "target_component_type", target_component_type) {
        return false;
    }

    let target_component_id = event
        .target
        .as_ref()
        .and_then(|target| target.component_id.as_deref());
    if !trusted_custom_constraint_matches(grant, "target_component_id", target_component_id) {
        return false;
    }

    true
}

fn trusted_custom_constraint_matches(
    grant: &ToolGrant,
    key: &str,
    trusted_value: Option<&str>,
) -> bool {
    let mut saw_constraint = false;

    for constraint in &grant.constraints {
        if let Constraint::Custom(candidate_key, candidate_value) = constraint {
            if candidate_key == key {
                saw_constraint = true;
                if trusted_value != Some(candidate_value.as_str()) {
                    return false;
                }
            }
        }
    }

    if trusted_value.is_some() {
        saw_constraint
    } else {
        !saw_constraint
    }
}

fn custom_constraint_matches_if_present(grant: &ToolGrant, key: &str, expected: &str) -> bool {
    // Exhaustive on purpose: the proxy evaluates only the Custom bindings it
    // understands and treats the rest of the vocabulary as satisfied, so a
    // future variant must be classified here explicitly rather than falling
    // into a wildcard that would silently satisfy it.
    grant.constraints.iter().all(|constraint| match constraint {
        Constraint::Custom(candidate_key, candidate_value) if candidate_key == key => {
            candidate_value == expected
        }
        Constraint::Custom(_, _) => true,
        // Delivery carriers require the output-aware durable terminal; the
        // proxy has no such terminal, so a grant carrying one never binds
        // an event.
        Constraint::OutputDigestSha256(_) | Constraint::RequireFindingPurchase(_) => false,
        Constraint::PathPrefix(_)
        | Constraint::DomainExact(_)
        | Constraint::DomainGlob(_)
        | Constraint::RegexMatch(_)
        | Constraint::MaxLength(_)
        | Constraint::MaxArgsSize(_)
        | Constraint::GovernedIntentRequired
        | Constraint::RequireApprovalAbove { .. }
        | Constraint::RequireCumulativeApprovalAbove { .. }
        | Constraint::SellerExact(_)
        | Constraint::MinimumRuntimeAssurance(_)
        | Constraint::MinimumAutonomyTier(_)
        | Constraint::TableAllowlist(_)
        | Constraint::ColumnDenylist(_)
        | Constraint::MaxRowsReturned(_)
        | Constraint::OperationClass(_)
        | Constraint::AudienceAllowlist(_)
        | Constraint::ContentReviewTier(_)
        | Constraint::MaxTransactionAmountUsd(_)
        | Constraint::RequireDualApproval(_)
        | Constraint::ModelConstraint { .. }
        | Constraint::MemoryStoreAllowlist(_)
        | Constraint::MemoryWriteDenyPatterns(_) => true,
    })
}
