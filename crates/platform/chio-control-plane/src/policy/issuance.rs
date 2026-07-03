use chio_core::capability::trust_policy::{AttestationTrustPolicy, AttestationTrustRule};
use chio_reputation::{
    ReputationConfig as LocalReputationConfig, ReputationWeights as LocalReputationWeights,
};

use super::types::{
    PolicyError, ReputationIssuancePolicy, ReputationTierPolicy, RuntimeAssuranceIssuancePolicy,
    RuntimeAssuranceTierPolicy, TierScopeCeiling,
};
use super::util::parse_operations;

pub(super) fn materialize_reputation_issuance_policy(
    spec: &chio_policy::HushSpec,
) -> Result<Option<ReputationIssuancePolicy>, PolicyError> {
    let Some(reputation) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.reputation.as_ref())
    else {
        return Ok(None);
    };

    let mut scoring = LocalReputationConfig::default();
    let mut probationary_receipt_count = 1_000;
    let mut probationary_min_days = 30;
    let mut probationary_score_ceiling = 0.60;

    if let Some(config) = &reputation.scoring {
        if let Some(weights) = &config.weights {
            scoring.weights = LocalReputationWeights {
                boundary_pressure: weights
                    .boundary_pressure
                    .unwrap_or(scoring.weights.boundary_pressure),
                resource_stewardship: weights
                    .resource_stewardship
                    .unwrap_or(scoring.weights.resource_stewardship),
                least_privilege: weights
                    .least_privilege
                    .unwrap_or(scoring.weights.least_privilege),
                history_depth: weights
                    .history_depth
                    .unwrap_or(scoring.weights.history_depth),
                tool_diversity: weights
                    .tool_diversity
                    .unwrap_or(scoring.weights.tool_diversity),
                delegation_hygiene: weights
                    .delegation_hygiene
                    .unwrap_or(scoring.weights.delegation_hygiene),
                reliability: weights.reliability.unwrap_or(scoring.weights.reliability),
                incident_correlation: weights
                    .incident_correlation
                    .unwrap_or(scoring.weights.incident_correlation),
            };
        }
        scoring.temporal_decay_half_life_days = config
            .temporal_decay_half_life_days
            .unwrap_or(scoring.temporal_decay_half_life_days);
        probationary_receipt_count = config
            .probationary_receipt_count
            .unwrap_or(probationary_receipt_count);
        probationary_min_days = config
            .probationary_min_days
            .unwrap_or(probationary_min_days);
        probationary_score_ceiling = config
            .probationary_score_ceiling
            .unwrap_or(probationary_score_ceiling);
        scoring.history_receipt_target = probationary_receipt_count;
        scoring.history_day_target = probationary_min_days;
    }

    let mut tiers = reputation
        .tiers
        .iter()
        .map(|(name, tier)| {
            Ok(ReputationTierPolicy {
                name: name.clone(),
                score_range: tier.score_range,
                max_scope: TierScopeCeiling {
                    operations: parse_operations(&tier.max_scope.operations)?,
                    max_invocations: tier.max_scope.max_invocations,
                    max_cost_per_invocation: tier.max_scope.max_cost_per_invocation.clone(),
                    max_total_cost: tier.max_scope.max_total_cost.clone(),
                    max_delegation_depth: tier.max_scope.max_delegation_depth,
                    ttl_seconds: tier.max_scope.ttl_seconds,
                    constraints_required: tier.max_scope.constraints_required.unwrap_or(false),
                },
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    tiers.sort_by(|left, right| {
        left.score_range[0]
            .partial_cmp(&right.score_range[0])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left.score_range[1]
                    .partial_cmp(&right.score_range[1])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(Some(ReputationIssuancePolicy {
        scoring,
        probationary_receipt_count,
        probationary_min_days,
        probationary_score_ceiling,
        tiers,
    }))
}

pub(super) fn materialize_runtime_assurance_policy(
    spec: &chio_policy::HushSpec,
) -> Result<Option<RuntimeAssuranceIssuancePolicy>, PolicyError> {
    let Some(runtime_assurance) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.runtime_assurance.as_ref())
    else {
        return Ok(None);
    };

    let mut tiers = runtime_assurance
        .tiers
        .iter()
        .map(|(name, tier)| {
            Ok(RuntimeAssuranceTierPolicy {
                name: name.clone(),
                minimum_attestation_tier: tier.minimum_attestation_tier,
                max_scope: TierScopeCeiling {
                    operations: parse_operations(&tier.max_scope.operations)?,
                    max_invocations: tier.max_scope.max_invocations,
                    max_cost_per_invocation: tier.max_scope.max_cost_per_invocation.clone(),
                    max_total_cost: tier.max_scope.max_total_cost.clone(),
                    max_delegation_depth: tier.max_scope.max_delegation_depth,
                    ttl_seconds: tier.max_scope.ttl_seconds,
                    constraints_required: tier.max_scope.constraints_required.unwrap_or(false),
                },
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    tiers.sort_by(|left, right| {
        left.minimum_attestation_tier
            .cmp(&right.minimum_attestation_tier)
            .then_with(|| left.name.cmp(&right.name))
    });

    let attestation_trust_policy = if runtime_assurance.trusted_verifiers.is_empty() {
        None
    } else {
        Some(AttestationTrustPolicy {
            rules: runtime_assurance
                .trusted_verifiers
                .iter()
                .map(|(name, rule)| AttestationTrustRule {
                    name: name.clone(),
                    schema: rule.schema.clone(),
                    verifier: rule.verifier.clone(),
                    effective_tier: rule.effective_tier,
                    verifier_family: rule.verifier_family,
                    max_evidence_age_seconds: rule.max_evidence_age_seconds,
                    allowed_attestation_types: rule.allowed_attestation_types.clone(),
                    required_assertions: rule.required_assertions.clone(),
                })
                .collect(),
        })
    };

    Ok(Some(RuntimeAssuranceIssuancePolicy {
        tiers,
        attestation_trust_policy,
    }))
}
