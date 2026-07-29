use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::capability::{
    runtime_attestation::RuntimeAssuranceTier,
    scope::{ChioScope, Constraint, Operation, PromptGrant, ResourceGrant, ToolGrant},
};
use chio_kernel::KernelError;

use crate::policy::{
    ReputationTierPolicy, RuntimeAssuranceIssuancePolicy, RuntimeAssuranceTierPolicy,
    TierScopeCeiling,
};

pub(in crate::issuance) fn enforce_tier_scope(
    scope: &ChioScope,
    ttl_seconds: u64,
    tier: &ReputationTierPolicy,
) -> Result<(), KernelError> {
    enforce_scope_ceiling(scope, ttl_seconds, &tier.name, &tier.max_scope)
}

fn enforce_scope_ceiling(
    scope: &ChioScope,
    ttl_seconds: u64,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    if ttl_seconds > max_scope.ttl_seconds {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested ttl_seconds {ttl_seconds} exceeds policy tier '{}' ceiling {}",
            ceiling_name, max_scope.ttl_seconds
        )));
    }

    for grant in &scope.grants {
        enforce_tool_grant(grant, ceiling_name, max_scope)?;
    }
    for grant in &scope.resource_grants {
        enforce_resource_grant(grant, ceiling_name, max_scope)?;
    }
    for grant in &scope.prompt_grants {
        enforce_prompt_grant(grant, ceiling_name, max_scope)?;
    }

    Ok(())
}

pub(in crate::issuance) fn enforce_runtime_assurance_policy(
    scope: &ChioScope,
    ttl_seconds: u64,
    policy: &RuntimeAssuranceIssuancePolicy,
    runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
) -> Result<ChioScope, KernelError> {
    let actual_tier = runtime_attestation
        .map(VerifiedRuntimeAttestationRecord::effective_tier)
        .unwrap_or(RuntimeAssuranceTier::None);
    let tier = resolve_runtime_assurance_tier(policy, actual_tier).ok_or_else(|| {
        KernelError::CapabilityIssuanceDenied(format!(
            "runtime assurance tier '{actual_tier:?}' does not satisfy any configured assurance tier"
        ))
    })?;

    enforce_scope_ceiling(scope, ttl_seconds, &tier.name, &tier.max_scope)?;

    let mut constrained = scope.clone();
    if tier.minimum_attestation_tier > RuntimeAssuranceTier::None {
        for grant in &mut constrained.grants {
            if grant_is_economically_sensitive(grant)
                && !grant
                    .constraints
                    .contains(&Constraint::MinimumRuntimeAssurance(
                        tier.minimum_attestation_tier,
                    ))
            {
                grant.constraints.push(Constraint::MinimumRuntimeAssurance(
                    tier.minimum_attestation_tier,
                ));
            }
        }
    }

    Ok(constrained)
}

fn resolve_runtime_assurance_tier(
    policy: &RuntimeAssuranceIssuancePolicy,
    actual_tier: RuntimeAssuranceTier,
) -> Option<&RuntimeAssuranceTierPolicy> {
    policy
        .tiers
        .iter()
        .rfind(|tier| actual_tier >= tier.minimum_attestation_tier)
}

fn grant_is_economically_sensitive(grant: &ToolGrant) -> bool {
    grant.max_cost_per_invocation.is_some()
        || grant.max_total_cost.is_some()
        || grant.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                Constraint::GovernedIntentRequired
                    | Constraint::RequireApprovalAbove { .. }
                    | Constraint::SellerExact(_)
                    | Constraint::MinimumAutonomyTier(_)
                    | Constraint::OutputDigestSha256(_)
                    | Constraint::RequireFindingPurchase(_)
            )
        })
}

fn enforce_tool_grant(
    grant: &ToolGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    if max_scope.constraints_required && grant.constraints.is_empty() {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "policy tier '{}' requires constrained tool grants",
            ceiling_name
        )));
    }

    if max_scope.max_delegation_depth == Some(0) && grant.operations.contains(&Operation::Delegate)
    {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "policy tier '{}' does not allow delegated capability issuance",
            ceiling_name
        )));
    }

    let ceiling = ToolGrant {
        server_id: grant.server_id.clone(),
        tool_name: grant.tool_name.clone(),
        operations: max_scope.operations.clone(),
        constraints: if max_scope.constraints_required {
            required_constraints(grant)
        } else {
            Vec::new()
        },
        max_invocations: max_scope.max_invocations,
        max_cost_per_invocation: max_scope.max_cost_per_invocation.clone(),
        max_total_cost: max_scope.max_total_cost.clone(),
        dpop_required: None,
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested tool grant '{}'/'{}' exceeds policy tier '{}' scope ceiling",
            grant.server_id, grant.tool_name, ceiling_name
        )))
    }
}

fn enforce_resource_grant(
    grant: &ResourceGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    let ceiling = ResourceGrant {
        uri_pattern: grant.uri_pattern.clone(),
        operations: max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested resource grant '{}' exceeds policy tier '{}' scope ceiling",
            grant.uri_pattern, ceiling_name
        )))
    }
}

fn enforce_prompt_grant(
    grant: &PromptGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    let ceiling = PromptGrant {
        prompt_name: grant.prompt_name.clone(),
        operations: max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested prompt grant '{}' exceeds policy tier '{}' scope ceiling",
            grant.prompt_name, ceiling_name
        )))
    }
}

fn required_constraints(grant: &ToolGrant) -> Vec<Constraint> {
    grant.constraints.clone()
}
