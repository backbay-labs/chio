use chio_core_types::PublicKey;
use chio_swarm_authority::{
    verify_swarm_authority_bundle, SwarmAuthorityBundle, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmJoinReceipt, SwarmRoutePlanReceipt,
};
use serde::Serialize;

use super::swarm_ref::{SwarmAuthorityReference, SwarmEvidenceReference};
use crate::*;

pub(super) fn verify_swarm_authority_reference_from_store<S>(
    store: &S,
    reference: &SwarmAuthorityReference,
    trusted_witness_keys: &[PublicKey],
    route_metadata: Option<&serde_json::Value>,
    now_unix_ms: u64,
) -> Result<VerifiedSwarmAuthorityReference, ChioRuntimeError>
where
    S: RuntimeAdmissionStore,
{
    let Some(mut bundle) = store.swarm_authority_bundle(&reference.task_graph.evidence_id)? else {
        return rejected(
            "missing_chio_swarm_authority_bundle",
            "swarm-bound request referenced authority evidence that is not in the verifier-owned store",
        );
    };
    bundle.now_unix_ms = now_unix_ms;
    verify_swarm_reference_hashes(&bundle, reference)?;
    let route_plan = find_route_plan(&bundle, &reference.route_plan_receipt.evidence_id)?;
    verify_route_metadata_matches(route_metadata, route_plan)?;
    verify_swarm_authority_bundle(&bundle, trusted_witness_keys).map_err(|error| {
        ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: error.runtime_detail(),
        }
    })?;
    let continuation = find_continuation(&bundle, &reference.continuation_token.evidence_id)?;
    if continuation.route_plan_receipt_id != reference.route_plan_receipt.evidence_id {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "swarm continuation route plan does not match referenced route plan evidence",
        );
    }
    Ok(VerifiedSwarmAuthorityReference {
        continuation_id_to_consume: match continuation.mode {
            SwarmContinuationMode::SingleUse => Some(continuation.token_id.clone()),
            SwarmContinuationMode::Resumable => None,
        },
    })
}

pub(super) struct VerifiedSwarmAuthorityReference {
    pub(super) continuation_id_to_consume: Option<String>,
}

fn verify_swarm_reference_hashes(
    bundle: &SwarmAuthorityBundle,
    reference: &SwarmAuthorityReference,
) -> Result<(), ChioRuntimeError> {
    verify_ref_matches(
        &reference.task_graph,
        &bundle.task_graph.graph_id,
        &bundle.task_graph,
    )?;
    verify_ref_matches(
        &reference.continuation_token,
        &find_continuation(bundle, &reference.continuation_token.evidence_id)?.token_id,
        find_continuation(bundle, &reference.continuation_token.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.route_plan_receipt,
        &find_route_plan(bundle, &reference.route_plan_receipt.evidence_id)?.route_plan_id,
        find_route_plan(bundle, &reference.route_plan_receipt.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.delegation_witness,
        &find_witness_chain(bundle, &reference.delegation_witness.evidence_id)?.chain_id,
        find_witness_chain(bundle, &reference.delegation_witness.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.join_receipt,
        &find_join_receipt(bundle, &reference.join_receipt.evidence_id)?.join_id,
        find_join_receipt(bundle, &reference.join_receipt.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.revocation_epoch,
        &bundle.revocation_epoch.epoch_id,
        &bundle.revocation_epoch,
    )?;
    verify_ref_matches(
        &reference.budget_pool,
        &bundle.budget_pool.pool_id,
        &bundle.budget_pool,
    )?;
    Ok(())
}

fn verify_route_metadata_matches(
    route_metadata: Option<&serde_json::Value>,
    route_plan: &SwarmRoutePlanReceipt,
) -> Result<(), ChioRuntimeError> {
    let Some(metadata) = route_metadata else {
        return Err(ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata missing for route plan {}",
                route_plan.route_plan_id
            ),
        });
    };
    let Some(route) = metadata
        .get("route")
        .or_else(|| metadata.get("route_selection"))
        .or_else(|| metadata.get("routeSelection"))
    else {
        return Err(ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata missing routed entry for route plan {}",
                route_plan.route_plan_id
            ),
        });
    };
    let bridge = route_metadata_string(
        route,
        &[
            "bridge",
            "bridgeId",
            "targetProtocol",
            "selectedTargetProtocol",
        ],
    )
    .ok_or_else(|| ChioRuntimeError::Rejected {
        code: "chio_swarm_authority_rejected",
        detail: format!(
            "swarm route metadata missing bridge for route plan {}",
            route_plan.route_plan_id
        ),
    })?;
    if bridge != route_plan.bridge_id {
        return Err(ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata bridge mismatch: expected {}, got {}",
                route_plan.bridge_id, bridge
            ),
        });
    }
    let protocol_target = route_metadata_string(route, &["protocolTarget", "protocol_target"])
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata missing protocol target for route plan {}",
                route_plan.route_plan_id
            ),
        })?;
    if protocol_target != route_plan.protocol_target {
        return Err(ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata target mismatch: expected {}, got {}",
                route_plan.protocol_target, protocol_target
            ),
        });
    }
    let selected_route = route_metadata_string(
        route,
        &[
            "selectedRoute",
            "selected_route",
            "selectedRouteId",
            "selected_route_id",
        ],
    )
    .ok_or_else(|| ChioRuntimeError::Rejected {
        code: "chio_swarm_authority_rejected",
        detail: format!(
            "swarm route metadata missing selected route for route plan {}",
            route_plan.route_plan_id
        ),
    })?;
    if selected_route != route_plan.selected_route {
        return Err(ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: format!(
                "swarm route metadata selected route mismatch: expected {}, got {}",
                route_plan.selected_route, selected_route
            ),
        });
    }
    Ok(())
}

fn route_metadata_string<'a>(route: &'a serde_json::Value, fields: &[&str]) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|field| route.get(*field).and_then(serde_json::Value::as_str))
}

fn verify_ref_matches<T>(
    reference: &SwarmEvidenceReference,
    stored_id: &str,
    stored_artifact: &T,
) -> Result<(), ChioRuntimeError>
where
    T: Serialize,
{
    if reference.evidence_id != stored_id
        || reference.artifact_sha256 != canonical_sha256(stored_artifact)?
    {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "swarm-bound request evidence hash does not match verifier-owned authority evidence",
        );
    }
    Ok(())
}

fn find_continuation<'a>(
    bundle: &'a SwarmAuthorityBundle,
    token_id: &str,
) -> Result<&'a SwarmContinuationToken, ChioRuntimeError> {
    find_by_id(&bundle.continuation_tokens, token_id, |token| {
        &token.token_id
    })
}

fn find_route_plan<'a>(
    bundle: &'a SwarmAuthorityBundle,
    route_plan_id: &str,
) -> Result<&'a SwarmRoutePlanReceipt, ChioRuntimeError> {
    find_by_id(&bundle.route_plan_receipts, route_plan_id, |route| {
        &route.route_plan_id
    })
}

fn find_witness_chain<'a>(
    bundle: &'a SwarmAuthorityBundle,
    chain_id: &str,
) -> Result<&'a SwarmDelegationWitnessChain, ChioRuntimeError> {
    find_by_id(&bundle.witness_chains, chain_id, |chain| &chain.chain_id)
}

fn find_join_receipt<'a>(
    bundle: &'a SwarmAuthorityBundle,
    join_id: &str,
) -> Result<&'a SwarmJoinReceipt, ChioRuntimeError> {
    find_by_id(&bundle.join_receipts, join_id, |receipt| &receipt.join_id)
}

fn find_by_id<'a, T>(
    items: &'a [T],
    expected_id: &str,
    id: impl Fn(&'a T) -> &'a str,
) -> Result<&'a T, ChioRuntimeError> {
    items
        .iter()
        .find(|item| id(item) == expected_id)
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_ref_mismatch",
            detail: "swarm-bound request referenced authority evidence that is absent from the stored bundle"
                .to_string(),
        })
}
