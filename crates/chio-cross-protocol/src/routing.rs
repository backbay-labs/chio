use std::collections::BTreeMap;

use chio_core::capability::GovernedTransactionIntent;
use chio_core::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::discovery::{parse_discovery_protocol, DiscoveryProtocol, TargetProtocolRegistry};
use crate::error::BridgeError;
use crate::execution::TargetExecutionHop;

/// Route evidence emitted by the shared fabric for an authoritative bridged
/// execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossProtocolRouteEvidence {
    pub selected_protocols: Vec<DiscoveryProtocol>,
    pub terminal_protocol: DiscoveryProtocol,
    pub multi_hop: bool,
}

/// Availability state for one route family at planning time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteAvailabilityStatus {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RouteAvailabilityStatus {
    #[must_use]
    pub fn available() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
        }
    }
}

/// Candidate route considered by the shared control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCandidateEvidence {
    pub route_id: String,
    pub target_protocol: DiscoveryProtocol,
    pub selected_protocols: Vec<DiscoveryProtocol>,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_reason: Option<String>,
}

/// Planner decision for a route candidate set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteSelectionDecision {
    Select,
    Attenuate,
    Deny,
}

/// Signed route-selection evidence emitted by the shared control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteSelectionEvidence {
    pub route_selection_id: String,
    pub decision: RouteSelectionDecision,
    pub source_protocol: DiscoveryProtocol,
    pub requested_target_protocol: DiscoveryProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_target_protocol: Option<DiscoveryProtocol>,
    pub selected_protocols: Vec<DiscoveryProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_id: Option<String>,
    pub candidates: Vec<RouteCandidateEvidence>,
}

/// Concrete planning result used by the shared orchestrator.
#[derive(Debug, Clone)]
pub struct RoutePlanningOutcome {
    pub selected_target_protocol: Option<DiscoveryProtocol>,
    pub evidence: RouteSelectionEvidence,
}

/// Plan a control-plane route selection for an authoritative call.
pub fn plan_authoritative_route(
    request_id: &str,
    source_protocol: DiscoveryProtocol,
    requested_target_protocol: DiscoveryProtocol,
    governed_intent: Option<&GovernedTransactionIntent>,
    registry: &TargetProtocolRegistry<'_>,
    availability: &BTreeMap<DiscoveryProtocol, RouteAvailabilityStatus>,
) -> Result<RoutePlanningOutcome, BridgeError> {
    let hints = route_planning_hints(governed_intent)?;
    let mut targets = vec![requested_target_protocol];
    if let Some(preferred) = hints.preferred_target_protocol {
        if !targets.contains(&preferred) {
            targets.push(preferred);
        }
    }
    if hints.disallow_projected_protocols
        && requested_target_protocol != DiscoveryProtocol::Native
        && !targets.contains(&DiscoveryProtocol::Native)
    {
        targets.push(DiscoveryProtocol::Native);
    }
    if hints.allow_native_fallback && !targets.contains(&DiscoveryProtocol::Native) {
        targets.push(DiscoveryProtocol::Native);
    }

    let candidates = targets
        .into_iter()
        .map(|target_protocol| {
            build_route_candidate(source_protocol, target_protocol, registry, availability)
        })
        .collect::<Vec<_>>();

    let available_candidate = |protocol: DiscoveryProtocol| -> Option<&RouteCandidateEvidence> {
        candidates
            .iter()
            .find(|candidate| candidate.target_protocol == protocol && candidate.available)
    };

    let decision = if hints.disallow_projected_protocols
        && requested_target_protocol != DiscoveryProtocol::Native
    {
        if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Attenuate,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("governed intent disallowed projected protocols; selected native route"),
                governed_intent,
                &candidates,
            )?
        } else {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Deny,
                source_protocol,
                requested_target_protocol,
                candidates.first(),
                Some("governed intent disallowed projected protocols and no native route was available"),
                governed_intent,
                &candidates,
            )?
        }
    } else if let Some(preferred) = hints.preferred_target_protocol {
        if let Some(candidate) = available_candidate(preferred) {
            planned_outcome(
                request_id,
                if preferred == requested_target_protocol {
                    RouteSelectionDecision::Select
                } else {
                    RouteSelectionDecision::Attenuate
                },
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                if preferred == requested_target_protocol {
                    None
                } else {
                    Some("control-plane policy preferred an alternate target protocol")
                },
                governed_intent,
                &candidates,
            )?
        } else if let Some(candidate) = available_candidate(requested_target_protocol) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Select,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("preferred target protocol unavailable; retained requested route"),
                governed_intent,
                &candidates,
            )?
        } else if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Attenuate,
                source_protocol,
                requested_target_protocol,
                Some(candidate),
                Some("preferred target protocol unavailable; attenuated to native fallback"),
                governed_intent,
                &candidates,
            )?
        } else {
            planned_outcome(
                request_id,
                RouteSelectionDecision::Deny,
                source_protocol,
                requested_target_protocol,
                candidates.first(),
                Some("no candidate route satisfied the preferred target protocol policy"),
                governed_intent,
                &candidates,
            )?
        }
    } else if let Some(candidate) = available_candidate(requested_target_protocol) {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Select,
            source_protocol,
            requested_target_protocol,
            Some(candidate),
            None,
            governed_intent,
            &candidates,
        )?
    } else if let Some(candidate) = available_candidate(DiscoveryProtocol::Native) {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Attenuate,
            source_protocol,
            requested_target_protocol,
            Some(candidate),
            Some("requested target protocol unavailable; attenuated to native fallback"),
            governed_intent,
            &candidates,
        )?
    } else {
        planned_outcome(
            request_id,
            RouteSelectionDecision::Deny,
            source_protocol,
            requested_target_protocol,
            candidates.first(),
            Some("no candidate route was available at planning time"),
            governed_intent,
            &candidates,
        )?
    };

    Ok(decision)
}

/// Build receipt metadata wrapper for signed route-selection evidence.
pub fn route_selection_metadata(evidence: &RouteSelectionEvidence) -> Result<Value, BridgeError> {
    Ok(json!({
        "route_selection": serde_json::to_value(evidence)
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
    }))
}

#[derive(Debug, Default)]
struct RoutePlanningHints {
    preferred_target_protocol: Option<DiscoveryProtocol>,
    allow_native_fallback: bool,
    disallow_projected_protocols: bool,
}

fn route_planning_hints(
    governed_intent: Option<&GovernedTransactionIntent>,
) -> Result<RoutePlanningHints, BridgeError> {
    let Some(context) = governed_intent.and_then(|intent| intent.context.as_ref()) else {
        return Ok(RoutePlanningHints::default());
    };
    let Some(control_plane) = context
        .get("chioControlPlane")
        .or_else(|| context.get("chio_control_plane"))
    else {
        return Ok(RoutePlanningHints::default());
    };
    let Some(object) = control_plane.as_object() else {
        return Err(BridgeError::InvalidRequest(
            "governed intent arcControlPlane context must be an object".to_string(),
        ));
    };

    let preferred_target_protocol = object
        .get("preferredTargetProtocol")
        .or_else(|| object.get("preferred_target_protocol"))
        .and_then(Value::as_str)
        .map(parse_discovery_protocol)
        .transpose()
        .map_err(BridgeError::InvalidRequest)?;

    Ok(RoutePlanningHints {
        preferred_target_protocol,
        allow_native_fallback: object
            .get("allowNativeFallback")
            .or_else(|| object.get("allow_native_fallback"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        disallow_projected_protocols: object
            .get("disallowProjectedProtocols")
            .or_else(|| object.get("disallow_projected_protocols"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn build_route_candidate(
    source_protocol: DiscoveryProtocol,
    target_protocol: DiscoveryProtocol,
    registry: &TargetProtocolRegistry<'_>,
    availability: &BTreeMap<DiscoveryProtocol, RouteAvailabilityStatus>,
) -> RouteCandidateEvidence {
    let availability = if registry.supports_target_protocol(target_protocol) {
        availability
            .get(&target_protocol)
            .cloned()
            .unwrap_or_else(RouteAvailabilityStatus::available)
    } else {
        RouteAvailabilityStatus::unavailable(format!(
            "target protocol `{target_protocol}` is not registered"
        ))
    };

    RouteCandidateEvidence {
        route_id: format!("{}-route", target_protocol.as_str()),
        target_protocol,
        selected_protocols: planned_protocols_for_target(source_protocol, target_protocol),
        available: availability.available,
        availability_reason: availability.reason,
    }
}

fn planned_protocols_for_target(
    source_protocol: DiscoveryProtocol,
    target_protocol: DiscoveryProtocol,
) -> Vec<DiscoveryProtocol> {
    match target_protocol {
        DiscoveryProtocol::Native => vec![source_protocol, DiscoveryProtocol::Native],
        DiscoveryProtocol::Mcp | DiscoveryProtocol::OpenAi => {
            vec![source_protocol, target_protocol, DiscoveryProtocol::Native]
        }
        _ => vec![source_protocol, target_protocol],
    }
}

#[allow(clippy::too_many_arguments)]
fn planned_outcome(
    request_id: &str,
    decision: RouteSelectionDecision,
    source_protocol: DiscoveryProtocol,
    requested_target_protocol: DiscoveryProtocol,
    selected_candidate: Option<&RouteCandidateEvidence>,
    reason: Option<&str>,
    governed_intent: Option<&GovernedTransactionIntent>,
    candidates: &[RouteCandidateEvidence],
) -> Result<RoutePlanningOutcome, BridgeError> {
    let selected_route_id = if decision == RouteSelectionDecision::Deny {
        None
    } else {
        selected_candidate.map(|candidate| candidate.route_id.clone())
    };
    let selected_target_protocol = if decision == RouteSelectionDecision::Deny {
        None
    } else {
        selected_candidate.map(|candidate| candidate.target_protocol)
    };
    let selected_protocols = selected_candidate
        .map(|candidate| candidate.selected_protocols.clone())
        .unwrap_or_else(|| {
            candidates
                .first()
                .map(|candidate| candidate.selected_protocols.clone())
                .unwrap_or_else(|| vec![source_protocol, requested_target_protocol])
        });
    let route_selection_id = sha256_hex(
        &canonical_json_bytes(&json!({
            "requestId": request_id,
            "sourceProtocol": source_protocol,
            "requestedTargetProtocol": requested_target_protocol,
            "selectedRouteId": selected_route_id,
            "selectedTargetProtocol": selected_target_protocol,
            "selectedProtocols": selected_protocols,
            "decision": decision,
            "governedIntentId": governed_intent.map(|intent| intent.id.clone()),
        }))
        .map_err(|error| BridgeError::Canonical(error.to_string()))?,
    );

    Ok(RoutePlanningOutcome {
        selected_target_protocol,
        evidence: RouteSelectionEvidence {
            route_selection_id,
            decision,
            source_protocol,
            requested_target_protocol,
            selected_route_id,
            selected_target_protocol,
            selected_protocols,
            reason: reason.map(str::to_string),
            governed_intent_id: governed_intent.map(|intent| intent.id.clone()),
            candidates: candidates.to_vec(),
        },
    })
}

pub(crate) fn route_hops_from_planning(
    evidence: &RouteSelectionEvidence,
    kernel_request_id: &str,
    receipt_id: &str,
) -> Vec<TargetExecutionHop> {
    let target_protocols = evidence
        .selected_protocols
        .iter()
        .copied()
        .skip(1)
        .collect::<Vec<_>>();
    let last_index = target_protocols.len().saturating_sub(1);

    target_protocols
        .into_iter()
        .enumerate()
        .map(|(index, protocol)| TargetExecutionHop {
            protocol,
            request_id: if index == 0 && protocol != DiscoveryProtocol::Native {
                format!("{}:{}", kernel_request_id, protocol.as_str())
            } else {
                kernel_request_id.to_string()
            },
            receipt_id: (index == last_index).then(|| receipt_id.to_string()),
        })
        .collect()
}

pub(crate) fn build_route_evidence(
    source_protocol: DiscoveryProtocol,
    route_hops: &[TargetExecutionHop],
) -> Result<CrossProtocolRouteEvidence, BridgeError> {
    let Some(last_hop) = route_hops.last() else {
        return Err(BridgeError::InvalidRequest(
            "target executor must return at least one target-side hop".to_string(),
        ));
    };

    Ok(CrossProtocolRouteEvidence {
        selected_protocols: std::iter::once(source_protocol)
            .chain(route_hops.iter().map(|hop| hop.protocol))
            .collect(),
        terminal_protocol: last_hop.protocol,
        multi_hop: route_hops.len() > 1,
    })
}
