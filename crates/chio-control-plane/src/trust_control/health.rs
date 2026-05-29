use super::*;

pub(super) fn install_health_routes(
    router: Router<TrustServiceState>,
) -> Router<TrustServiceState> {
    router.route(HEALTH_PATH, get(handle_health))
}

async fn handle_health(State(state): State<TrustServiceState>) -> Response {
    let consensus = cluster_consensus_view(&state);
    let leader_url = consensus.as_ref().and_then(|view| view.leader_url.clone());
    let self_url = consensus
        .as_ref()
        .map(|view| view.self_url.clone())
        .or_else(|| cluster_self_url(&state));
    Json(json!({
        "ok": true,
        "leaderUrl": leader_url.clone(),
        "selfUrl": self_url.clone(),
        "clustered": state.cluster.is_some(),
        "authority": trust_authority_health_snapshot(&state.config),
        "stores": trust_store_health_snapshot(&state.config),
        "federation": trust_federation_health_snapshot(&state),
        "cluster": trust_cluster_health_snapshot(&state, consensus, leader_url, self_url),
    }))
    .into_response()
}

fn trust_authority_health_snapshot(config: &TrustServiceConfig) -> Value {
    let backend_hint = if config.authority_db_path.is_some() {
        Some("sqlite")
    } else if config.authority_seed_path.is_some() {
        Some("seed_file")
    } else {
        None
    };
    match load_authority_status(config) {
        Ok(status) => json!({
            "configured": status.configured,
            "available": true,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedKeyCount": status.trusted_public_keys.len(),
        }),
        Err(_) => json!({
            "configured": backend_hint.is_some(),
            "available": false,
            "backend": backend_hint,
            "publicKey": Value::Null,
            "generation": Value::Null,
            "rotatedAt": Value::Null,
            "appliesToFutureSessionsOnly": true,
            "trustedKeyCount": 0,
        }),
    }
}

fn trust_store_health_snapshot(config: &TrustServiceConfig) -> Value {
    json!({
        "receiptsConfigured": config.receipt_db_path.is_some(),
        "revocationsConfigured": config.revocation_db_path.is_some(),
        "budgetsConfigured": config.budget_db_path.is_some(),
        "verifierChallengesConfigured": config.verifier_challenge_db_path.is_some(),
    })
}

fn trust_federation_health_snapshot(state: &TrustServiceState) -> Value {
    let loaded_enterprise_provider_summary = state
        .enterprise_provider_registry()
        .map(|registry| {
            let enabled_count = registry
                .providers
                .values()
                .filter(|record| record.enabled)
                .count();
            let validated_count = registry
                .providers
                .values()
                .filter(|record| record.is_validated_enabled())
                .count();
            let invalid_count = registry
                .providers
                .values()
                .filter(|record| !record.validation_errors.is_empty())
                .count();
            (
                registry.providers.len(),
                enabled_count,
                validated_count,
                invalid_count,
            )
        })
        .unwrap_or((0, 0, 0, 0));

    let enterprise_provider_summary =
        if let Some(path) = state.config.enterprise_providers_file.as_deref() {
            match EnterpriseProviderRegistry::load(path) {
                Ok(registry) => {
                    let enabled_count = registry
                        .providers
                        .values()
                        .filter(|record| record.enabled)
                        .count();
                    let validated_count = registry
                        .providers
                        .values()
                        .filter(|record| record.is_validated_enabled())
                        .count();
                    let invalid_count = registry
                        .providers
                        .values()
                        .filter(|record| !record.validation_errors.is_empty())
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.providers.len(),
                        "enabledCount": enabled_count,
                        "validatedCount": validated_count,
                        "invalidCount": invalid_count,
                        "loadedCount": loaded_enterprise_provider_summary.0,
                        "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "enabledCount": 0,
                    "validatedCount": 0,
                    "invalidCount": 0,
                    "loadedCount": loaded_enterprise_provider_summary.0,
                    "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "enabledCount": 0,
                "validatedCount": 0,
                "invalidCount": 0,
                "loadedCount": 0,
                "loadedValidatedCount": 0,
            })
        };

    let loaded_verifier_policy_summary = state
        .verifier_policy_registry()
        .map(|registry| {
            let now = unix_timestamp_now();
            let active_count = registry
                .policies
                .values()
                .filter(|document| {
                    ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                })
                .count();
            (registry.policies.len(), active_count)
        })
        .unwrap_or((0, 0));

    let verifier_policy_summary = if let Some(path) = state.config.verifier_policies_file.as_deref()
    {
        match VerifierPolicyRegistry::load(path) {
            Ok(registry) => {
                let now = unix_timestamp_now();
                let active_count = registry
                    .policies
                    .values()
                    .filter(|document| {
                        ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                    })
                    .count();
                json!({
                    "configured": true,
                    "available": true,
                    "count": registry.policies.len(),
                    "activeCount": active_count,
                    "loadedCount": loaded_verifier_policy_summary.0,
                    "loadedActiveCount": loaded_verifier_policy_summary.1,
                })
            }
            Err(_) => json!({
                "configured": true,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "loadedCount": loaded_verifier_policy_summary.0,
                "loadedActiveCount": loaded_verifier_policy_summary.1,
            }),
        }
    } else {
        json!({
            "configured": false,
            "available": false,
            "count": 0,
            "activeCount": 0,
            "loadedCount": 0,
            "loadedActiveCount": 0,
        })
    };

    let federation_policy_summary =
        if let Some(path) = state.config.federation_policies_file.as_deref() {
            match FederationAdmissionPolicyRegistry::load(path) {
                Ok(registry) => {
                    let reputation_gated_count = registry
                        .policies
                        .values()
                        .filter(|record| record.minimum_reputation_score.is_some())
                        .count();
                    let proof_of_work_count = registry
                        .policies
                        .values()
                        .filter(|record| record.anti_sybil.proof_of_work_bits.is_some())
                        .count();
                    let rate_limited_count = registry
                        .policies
                        .values()
                        .filter(|record| record.anti_sybil.rate_limit.is_some())
                        .count();
                    let bond_backed_only_count = registry
                        .policies
                        .values()
                        .filter(|record| record.anti_sybil.bond_backed_only)
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.policies.len(),
                        "reputationGatedCount": reputation_gated_count,
                        "proofOfWorkCount": proof_of_work_count,
                        "rateLimitedCount": rate_limited_count,
                        "bondBackedOnlyCount": bond_backed_only_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "reputationGatedCount": 0,
                    "proofOfWorkCount": 0,
                    "rateLimitedCount": 0,
                    "bondBackedOnlyCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "reputationGatedCount": 0,
                "proofOfWorkCount": 0,
                "rateLimitedCount": 0,
                "bondBackedOnlyCount": 0,
            })
        };

    let scim_lifecycle_summary = if let Some(path) = state.config.scim_lifecycle_file.as_deref() {
        match ScimLifecycleRegistry::load(path) {
            Ok(registry) => {
                let active_count = registry
                    .users
                    .values()
                    .filter(|record| record.active())
                    .count();
                let inactive_count = registry.users.len().saturating_sub(active_count);
                let tracked_capability_count = registry
                    .users
                    .values()
                    .map(|record| record.tracked_capability_ids.len())
                    .sum::<usize>();
                json!({
                    "configured": true,
                    "available": true,
                    "count": registry.users.len(),
                    "activeCount": active_count,
                    "inactiveCount": inactive_count,
                    "trackedCapabilityCount": tracked_capability_count,
                })
            }
            Err(_) => json!({
                "configured": true,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "inactiveCount": 0,
                "trackedCapabilityCount": 0,
            }),
        }
    } else {
        json!({
            "configured": false,
            "available": false,
            "count": 0,
            "activeCount": 0,
            "inactiveCount": 0,
            "trackedCapabilityCount": 0,
        })
    };

    let certification_summary =
        if let Some(path) = state.config.certification_registry_file.as_deref() {
            match CertificationRegistry::load(path) {
                Ok(registry) => {
                    let active_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Active)
                        .count();
                    let superseded_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Superseded)
                        .count();
                    let revoked_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.artifacts.len(),
                        "activeCount": active_count,
                        "supersededCount": superseded_count,
                        "revokedCount": revoked_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "activeCount": 0,
                    "supersededCount": 0,
                    "revokedCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "supersededCount": 0,
                "revokedCount": 0,
            })
        };

    let certification_discovery_summary =
        if let Some(path) = state.config.certification_discovery_file.as_deref() {
            match CertificationDiscoveryNetwork::load(path) {
                Ok(network) => {
                    let validated_count = network
                        .operators
                        .values()
                        .filter(|operator| operator.validation_errors.is_empty())
                        .count();
                    let publish_enabled_count = network
                        .operators
                        .values()
                        .filter(|operator| {
                            operator.validation_errors.is_empty() && operator.allow_publish
                        })
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": network.operators.len(),
                        "validatedCount": validated_count,
                        "publishEnabledCount": publish_enabled_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "validatedCount": 0,
                    "publishEnabledCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "validatedCount": 0,
                "publishEnabledCount": 0,
            })
        };

    json!({
        "enterpriseProviders": enterprise_provider_summary,
        "openAdmissionPolicies": federation_policy_summary,
        "scimLifecycle": scim_lifecycle_summary,
        "verifierPolicies": verifier_policy_summary,
        "certifications": certification_summary,
        "certificationDiscovery": certification_discovery_summary,
        "issuancePolicyConfigured": state.config.issuance_policy.is_some(),
        "runtimeAssurancePolicyConfigured": state.config.runtime_assurance_policy.is_some(),
    })
}

fn trust_cluster_health_snapshot(
    state: &TrustServiceState,
    consensus: Option<ClusterConsensusView>,
    leader_url: Option<String>,
    self_url: Option<String>,
) -> Value {
    let Some(cluster) = state.cluster.as_ref() else {
        return json!({
            "peerCount": 0,
            "healthyPeers": 0,
            "unhealthyPeers": 0,
            "unknownPeers": 0,
            "partitionedPeers": 0,
            "lastErrorCount": 0,
            "leaderUrl": leader_url,
            "selfUrl": self_url,
            "hasQuorum": false,
            "quorumSize": 1,
            "reachableNodes": 1,
            "electionTerm": 0,
            "role": "standalone",
        });
    };

    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.clone(),
        Err(poisoned) => poisoned.into_inner().peers.clone(),
    };

    let mut healthy = 0usize;
    let mut unhealthy = 0usize;
    let mut unknown = 0usize;
    let mut partitioned = 0usize;
    let mut last_error_count = 0usize;
    for peer in peers.values() {
        match peer.health {
            PeerHealth::Healthy => healthy += 1,
            PeerHealth::Unhealthy => unhealthy += 1,
            PeerHealth::Unknown => unknown += 1,
        }
        if peer.partitioned {
            partitioned += 1;
        }
        if peer.last_error.is_some() {
            last_error_count += 1;
        }
    }
    let consensus = consensus.unwrap_or(ClusterConsensusView {
        self_url: self_url.clone().unwrap_or_default(),
        leader_url: leader_url.clone(),
        role: "candidate",
        has_quorum: false,
        quorum_size: peers.len().div_ceil(2) + 1,
        reachable_nodes: 1,
        election_term: 0,
    });

    json!({
        "peerCount": peers.len(),
        "healthyPeers": healthy,
        "unhealthyPeers": unhealthy,
        "unknownPeers": unknown,
        "partitionedPeers": partitioned,
        "lastErrorCount": last_error_count,
        "leaderUrl": consensus.leader_url,
        "selfUrl": consensus.self_url,
        "hasQuorum": consensus.has_quorum,
        "quorumSize": consensus.quorum_size,
        "reachableNodes": consensus.reachable_nodes,
        "electionTerm": consensus.election_term,
        "role": consensus.role,
    })
}
