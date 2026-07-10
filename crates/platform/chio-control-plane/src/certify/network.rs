use std::path::Path;

use crate::enterprise_federation::CertificationDiscoveryNetwork;
use crate::CliError;

use super::commands::certification_resolution_label;
use super::helpers::{
    load_signed_certification_check, require_certification_discovery_path, unix_now,
};
use super::schema::{
    CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1, CERTIFICATION_PUBLIC_SEARCH_SCHEMA,
    CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA,
};
use super::types::{
    CertificationConsumptionPeerDecision, CertificationConsumptionRequest,
    CertificationConsumptionResponse, CertificationDiscoveryError,
    CertificationDiscoveryPeerResult, CertificationDiscoveryResponse, CertificationDisputeState,
    CertificationMarketplaceSearchQuery, CertificationMarketplaceTransparencyQuery,
    CertificationNetworkPublishPeerResult, CertificationNetworkPublishRequest,
    CertificationNetworkPublishResponse, CertificationPublicSearchResponse,
    CertificationResolutionState, CertificationTransparencyResponse, CertificationVerdict,
    SignedCertificationCheck,
};
use super::validators::validate_public_certification_metadata;
use super::verify::{certification_artifact_id, verify_signed_certification_check};

pub fn discover_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    tool_server_id: &str,
) -> CertificationDiscoveryResponse {
    let mut peers = Vec::new();
    let mut reachable_count = 0;
    let mut active_count = 0;
    let mut revoked_count = 0;
    let mut superseded_count = 0;
    let mut not_found_count = 0;

    for operator in network.validated_operators() {
        match crate::trust_control::service_runtime::public_registry::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => {
                    reachable_count += 1;
                    match crate::trust_control::service_runtime::public_registry::resolve_public_certification(
                        &operator.registry_url,
                        tool_server_id,
                    ) {
                        Ok(resolution) => {
                            match resolution.state {
                                CertificationResolutionState::Active => active_count += 1,
                                CertificationResolutionState::Revoked => revoked_count += 1,
                                CertificationResolutionState::Superseded => superseded_count += 1,
                                CertificationResolutionState::NotFound => not_found_count += 1,
                            }
                            peers.push(CertificationDiscoveryPeerResult {
                                operator_id: operator.operator_id.clone(),
                                operator_name: operator.operator_name.clone(),
                                registry_url: operator.registry_url.clone(),
                                reachable: true,
                                metadata: Some(metadata),
                                metadata_valid: true,
                                error: None,
                                resolution: Some(resolution),
                            });
                        }
                        Err(error) => peers.push(CertificationDiscoveryPeerResult {
                            operator_id: operator.operator_id.clone(),
                            operator_name: operator.operator_name.clone(),
                            registry_url: operator.registry_url.clone(),
                            reachable: true,
                            metadata: Some(metadata),
                            metadata_valid: true,
                            error: Some(error.to_string()),
                            resolution: None,
                        }),
                    }
                }
                Err(error) => peers.push(CertificationDiscoveryPeerResult {
                    operator_id: operator.operator_id.clone(),
                    operator_name: operator.operator_name.clone(),
                    registry_url: operator.registry_url.clone(),
                    reachable: true,
                    metadata: Some(metadata),
                    metadata_valid: false,
                    error: Some(error.to_string()),
                    resolution: None,
                }),
            },
            Err(error) => peers.push(CertificationDiscoveryPeerResult {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                reachable: false,
                metadata: None,
                metadata_valid: false,
                error: Some(error.to_string()),
                resolution: None,
            }),
        }
    }

    CertificationDiscoveryResponse {
        tool_server_id: tool_server_id.to_string(),
        peer_count: peers.len(),
        reachable_count,
        active_count,
        revoked_count,
        superseded_count,
        not_found_count,
        peers,
    }
}

fn selected_network_operators<'a>(
    network: &'a CertificationDiscoveryNetwork,
    operator_ids: &[String],
) -> Result<Vec<&'a crate::enterprise_federation::CertificationDiscoveryOperator>, CliError> {
    if operator_ids.is_empty() {
        return Ok(network.validated_operators().collect());
    }
    let mut operators = Vec::new();
    for operator_id in operator_ids {
        let operator = network.validated_operator(operator_id).ok_or_else(|| {
            CliError::attest_error(format!(
                "certification discovery operator `{operator_id}` was not found or is invalid"
            ))
        })?;
        operators.push(operator);
    }
    Ok(operators)
}

fn parse_operator_ids_csv(operator_ids: Option<&str>) -> Vec<String> {
    operator_ids
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn search_public_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    query: &CertificationMarketplaceSearchQuery,
) -> CertificationPublicSearchResponse {
    let mut results = Vec::new();
    let mut errors = Vec::new();
    let mut reachable_count = 0;
    let operator_ids = parse_operator_ids_csv(query.operator_ids.as_deref());
    let operators = match selected_network_operators(network, &operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationPublicSearchResponse {
                schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
                generated_at: unix_now(),
                peer_count: 0,
                reachable_count: 0,
                count: 0,
                results: Vec::new(),
                errors: vec![CertificationDiscoveryError {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: error.to_string(),
                }],
            };
        }
    };
    let peer_count = operators.len();
    for operator in operators {
        match crate::trust_control::service_runtime::public_registry::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => match crate::trust_control::service_runtime::public_registry::search_public_certifications(
                    &operator.registry_url,
                    &query.filters,
                ) {
                    Ok(response) => {
                        reachable_count += 1;
                        results.extend(response.results);
                    }
                    Err(error) => errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    }),
                },
                Err(error) => {
                    reachable_count += 1;
                    errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    });
                }
            },
            Err(error) => errors.push(CertificationDiscoveryError {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                error: error.to_string(),
            }),
        }
    }
    results.sort_by(|left, right| {
        left.publisher
            .publisher_id
            .cmp(&right.publisher.publisher_id)
            .then(left.entry.tool_server_id.cmp(&right.entry.tool_server_id))
            .then(right.entry.published_at.cmp(&left.entry.published_at))
            .then(left.entry.artifact_id.cmp(&right.entry.artifact_id))
    });
    CertificationPublicSearchResponse {
        schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
        generated_at: unix_now(),
        peer_count,
        reachable_count,
        count: results.len(),
        results,
        errors,
    }
}

pub fn transparency_public_certifications_across_network(
    network: &CertificationDiscoveryNetwork,
    query: &CertificationMarketplaceTransparencyQuery,
) -> CertificationTransparencyResponse {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut reachable_count = 0;
    let operator_ids = parse_operator_ids_csv(query.operator_ids.as_deref());
    let operators = match selected_network_operators(network, &operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationTransparencyResponse {
                schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
                generated_at: unix_now(),
                peer_count: 0,
                reachable_count: 0,
                count: 0,
                events: Vec::new(),
                errors: vec![CertificationDiscoveryError {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: error.to_string(),
                }],
            };
        }
    };
    let peer_count = operators.len();
    for operator in operators {
        match crate::trust_control::service_runtime::public_registry::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => match crate::trust_control::service_runtime::public_registry::resolve_public_certification_transparency(
                    &operator.registry_url,
                    &query.filters,
                ) {
                    Ok(response) => {
                        reachable_count += 1;
                        events.extend(response.events);
                    }
                    Err(error) => errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    }),
                },
                Err(error) => {
                    reachable_count += 1;
                    errors.push(CertificationDiscoveryError {
                        operator_id: operator.operator_id.clone(),
                        operator_name: operator.operator_name.clone(),
                        registry_url: operator.registry_url.clone(),
                        error: error.to_string(),
                    });
                }
            },
            Err(error) => errors.push(CertificationDiscoveryError {
                operator_id: operator.operator_id.clone(),
                operator_name: operator.operator_name.clone(),
                registry_url: operator.registry_url.clone(),
                error: error.to_string(),
            }),
        }
    }
    events.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then(
                left.publisher
                    .publisher_id
                    .cmp(&right.publisher.publisher_id),
            )
            .then(left.artifact_id.cmp(&right.artifact_id))
    });
    CertificationTransparencyResponse {
        schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
        generated_at: unix_now(),
        peer_count,
        reachable_count,
        count: events.len(),
        events,
        errors,
    }
}

pub fn consume_public_certification_across_network(
    network: &CertificationDiscoveryNetwork,
    request: &CertificationConsumptionRequest,
) -> CertificationConsumptionResponse {
    let mut decisions = Vec::new();
    let mut admitted_artifact_ids = Vec::new();
    let operators = match selected_network_operators(network, &request.operator_ids) {
        Ok(operators) => operators,
        Err(error) => {
            return CertificationConsumptionResponse {
                policy_profile: CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1.to_string(),
                tool_server_id: request.tool_server_id.clone(),
                admitted_count: 0,
                rejected_count: 1,
                admitted_artifact_ids: Vec::new(),
                decisions: vec![CertificationConsumptionPeerDecision {
                    operator_id: "selection".to_string(),
                    operator_name: None,
                    registry_url: String::new(),
                    accepted: false,
                    metadata_valid: false,
                    reasons: vec![error.to_string()],
                    resolution: None,
                }],
            };
        }
    };
    for operator in operators {
        let mut decision = CertificationConsumptionPeerDecision {
            operator_id: operator.operator_id.clone(),
            operator_name: operator.operator_name.clone(),
            registry_url: operator.registry_url.clone(),
            accepted: false,
            metadata_valid: false,
            reasons: Vec::new(),
            resolution: None,
        };
        match crate::trust_control::service_runtime::public_registry::resolve_public_certification_metadata(&operator.registry_url) {
            Ok(metadata) => match validate_public_certification_metadata(
                &metadata,
                Some(&operator.registry_url),
                unix_now(),
            ) {
                Ok(()) => {
                    decision.metadata_valid = true;
                    match crate::trust_control::service_runtime::public_registry::resolve_public_certification(
                        &operator.registry_url,
                        &request.tool_server_id,
                    ) {
                        Ok(resolution) => {
                            decision.resolution = Some(resolution.clone());
                            let mut accepted = true;
                            if resolution.state != CertificationResolutionState::Active {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "current listing state is {}",
                                    match resolution.state {
                                        CertificationResolutionState::Active => "active",
                                        CertificationResolutionState::Superseded => "superseded",
                                        CertificationResolutionState::Revoked => "revoked",
                                        CertificationResolutionState::NotFound => "not-found",
                                    }
                                ));
                            }
                            let Some(current) = resolution.current else {
                                decision.reasons.push(
                                    "no current certification artifact is available".to_string(),
                                );
                                decisions.push(decision);
                                continue;
                            };
                            if current.verdict != CertificationVerdict::Pass {
                                accepted = false;
                                decision
                                    .reasons
                                    .push("current certification verdict is not pass".to_string());
                            }
                            if let Some(dispute) = current.dispute.as_ref() {
                                if matches!(
                                    dispute.state,
                                    CertificationDisputeState::Open
                                        | CertificationDisputeState::UnderReview
                                ) {
                                    accepted = false;
                                    decision.reasons.push(format!(
                                        "current certification is disputed ({})",
                                        dispute.state.label()
                                    ));
                                }
                            }
                            if !request.allowed_criteria_profiles.is_empty()
                                && !request.allowed_criteria_profiles.iter().any(|profile| {
                                    profile == &current.artifact.body.criteria_profile
                                })
                            {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "criteria profile `{}` is not allowed by consumption policy",
                                    current.artifact.body.criteria_profile
                                ));
                            }
                            if !request.allowed_evidence_profiles.is_empty()
                                && !request.allowed_evidence_profiles.iter().any(|profile| {
                                    profile == &current.artifact.body.evidence.evidence_profile
                                })
                            {
                                accepted = false;
                                decision.reasons.push(format!(
                                    "evidence profile `{}` is not allowed by consumption policy",
                                    current.artifact.body.evidence.evidence_profile
                                ));
                            }
                            if accepted {
                                admitted_artifact_ids.push(current.artifact_id.clone());
                                decision.accepted = true;
                            }
                        }
                        Err(error) => decision.reasons.push(error.to_string()),
                    }
                }
                Err(error) => decision.reasons.push(error.to_string()),
            },
            Err(error) => decision.reasons.push(error.to_string()),
        }
        decisions.push(decision);
    }
    let admitted_count = decisions
        .iter()
        .filter(|decision| decision.accepted)
        .count();
    let rejected_count = decisions.len().saturating_sub(admitted_count);
    CertificationConsumptionResponse {
        policy_profile: CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1.to_string(),
        tool_server_id: request.tool_server_id.clone(),
        admitted_count,
        rejected_count,
        admitted_artifact_ids,
        decisions,
    }
}

pub fn publish_certification_across_network(
    network: &CertificationDiscoveryNetwork,
    artifact: &SignedCertificationCheck,
    operator_ids: &[String],
) -> Result<CertificationNetworkPublishResponse, CliError> {
    verify_signed_certification_check(artifact)?;
    let artifact_id = certification_artifact_id(artifact)?;
    let mut operators = Vec::new();
    if operator_ids.is_empty() {
        operators.extend(network.validated_operators().cloned());
    } else {
        for operator_id in operator_ids {
            let operator = network.validated_operator(operator_id).ok_or_else(|| {
                CliError::attest_error(format!(
                    "certification discovery operator `{operator_id}` was not found or is invalid"
                ))
            })?;
            operators.push(operator.clone());
        }
    }

    let mut results = Vec::new();
    let mut success_count = 0;
    for operator in operators {
        let mut result = CertificationNetworkPublishPeerResult {
            operator_id: operator.operator_id.clone(),
            operator_name: operator.operator_name.clone(),
            registry_url: operator.registry_url.clone(),
            published: false,
            error: None,
            entry: None,
        };

        if !operator.allow_publish {
            result.error = Some("operator is not configured for publish fan-out".to_string());
            results.push(result);
            continue;
        }
        let Some(token) = operator.control_token.as_deref() else {
            result.error = Some("operator is missing control_token".to_string());
            results.push(result);
            continue;
        };

        match crate::trust_control::service_runtime::client::build_client(
            &operator.registry_url,
            token,
        )
        .and_then(|client| client.publish_certification(artifact))
        {
            Ok(entry) => {
                success_count += 1;
                result.published = true;
                result.entry = Some(entry);
            }
            Err(error) => result.error = Some(error.to_string()),
        }
        results.push(result);
    }

    Ok(CertificationNetworkPublishResponse {
        artifact_id,
        tool_server_id: artifact.body.target.tool_server_id.clone(),
        peer_count: results.len(),
        success_count,
        results,
    })
}

pub fn cmd_certify_registry_discover(
    tool_server_id: &str,
    discovery_path: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .discover_certification(tool_server_id)?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        discover_certifications_across_network(&network, tool_server_id)
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("tool_server_id: {}", response.tool_server_id);
        println!("peer_count:     {}", response.peer_count);
        println!("reachable:      {}", response.reachable_count);
        println!("active:         {}", response.active_count);
        println!("revoked:        {}", response.revoked_count);
        println!("superseded:     {}", response.superseded_count);
        println!("not_found:      {}", response.not_found_count);
        for peer in response.peers {
            match peer.resolution {
                Some(resolution) => println!(
                    "- {} state={} registry={}",
                    peer.operator_id,
                    certification_resolution_label(resolution.state),
                    peer.registry_url
                ),
                None => println!(
                    "- {} error={} registry={}",
                    peer.operator_id,
                    peer.error.unwrap_or_else(|| "unknown".to_string()),
                    peer.registry_url
                ),
            }
        }
    }
    Ok(())
}

pub fn cmd_certify_registry_publish_network(
    input: &Path,
    discovery_path: Option<&Path>,
    operator_ids: &[String],
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let artifact = load_signed_certification_check(input)?;
    let response = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .publish_certification_network(&CertificationNetworkPublishRequest {
                artifact,
                operator_ids: operator_ids.to_vec(),
            })?
    } else {
        let path = require_certification_discovery_path(discovery_path)?;
        let network = CertificationDiscoveryNetwork::load(path)?;
        publish_certification_across_network(&network, &artifact, operator_ids)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("artifact_id:   {}", response.artifact_id);
        println!("tool_server:   {}", response.tool_server_id);
        println!("peer_count:    {}", response.peer_count);
        println!("success_count: {}", response.success_count);
        for result in response.results {
            if result.published {
                println!(
                    "- {} published registry={}",
                    result.operator_id, result.registry_url
                );
            } else {
                println!(
                    "- {} error={} registry={}",
                    result.operator_id,
                    result.error.unwrap_or_else(|| "unknown".to_string()),
                    result.registry_url
                );
            }
        }
    }
    Ok(())
}
