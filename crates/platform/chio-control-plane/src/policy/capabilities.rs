use std::collections::BTreeMap;

use chio_core::capability::scope::{ChioScope, PromptGrant, ResourceGrant, ToolGrant};

use super::capability_config::CapabilityPolicyConfig;
use super::tool_access::synthesize_tool_access_scope;
use super::types::{ChioPolicy, DefaultCapability, PolicyError};
use super::util::parse_operations;

/// Convert policy tool grant configs into one or more capabilities grouped by TTL.
pub fn build_runtime_default_capabilities(
    policy: &ChioPolicy,
) -> Result<Vec<DefaultCapability>, PolicyError> {
    let mut grants_by_ttl =
        build_default_capability_map(&policy.capabilities, policy.kernel.max_capability_ttl)?;

    let has_explicit_tool_caps = policy
        .capabilities
        .default
        .as_ref()
        .is_some_and(|default| !default.tools.is_empty());
    if !has_explicit_tool_caps {
        if let Some(scope) = synthesize_tool_access_scope(&policy.guards)? {
            grants_by_ttl
                .entry(policy.kernel.max_capability_ttl)
                .or_default()
                .grants
                .extend(scope.grants);
        }
    }

    Ok(default_capability_map_into_vec(grants_by_ttl))
}

/// Convert policy tool grant configs into one or more capabilities grouped by TTL.
pub fn build_default_capabilities(
    config: &CapabilityPolicyConfig,
    max_capability_ttl: u64,
) -> Result<Vec<DefaultCapability>, PolicyError> {
    Ok(default_capability_map_into_vec(
        build_default_capability_map(config, max_capability_ttl)?,
    ))
}

fn build_default_capability_map(
    config: &CapabilityPolicyConfig,
    max_capability_ttl: u64,
) -> Result<BTreeMap<u64, ChioScope>, PolicyError> {
    let default = match &config.default {
        Some(default) => default,
        None => return Ok(BTreeMap::new()),
    };

    let mut grants_by_ttl: BTreeMap<u64, ChioScope> = BTreeMap::new();

    for grant_config in &default.tools {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .grants
            .push(ToolGrant {
                server_id: grant_config.server.clone(),
                tool_name: grant_config.tool.clone(),
                operations,
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            });
    }

    for grant_config in &default.resources {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .resource_grants
            .push(ResourceGrant {
                uri_pattern: grant_config.uri.clone(),
                operations,
            });
    }

    for grant_config in &default.prompts {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .prompt_grants
            .push(PromptGrant {
                prompt_name: grant_config.prompt.clone(),
                operations,
            });
    }

    Ok(grants_by_ttl)
}

fn default_capability_map_into_vec(
    grants_by_ttl: BTreeMap<u64, ChioScope>,
) -> Vec<DefaultCapability> {
    grants_by_ttl
        .into_iter()
        .filter(|(_, scope)| {
            !scope.grants.is_empty()
                || !scope.resource_grants.is_empty()
                || !scope.prompt_grants.is_empty()
        })
        .map(|(ttl, scope)| DefaultCapability { scope, ttl })
        .collect()
}

pub(super) fn build_default_capabilities_from_scope(
    scope: &ChioScope,
    ttl: u64,
) -> Vec<DefaultCapability> {
    if scope.grants.is_empty() && scope.resource_grants.is_empty() && scope.prompt_grants.is_empty()
    {
        Vec::new()
    } else {
        vec![DefaultCapability {
            scope: scope.clone(),
            ttl,
        }]
    }
}
