use std::sync::Arc;
use std::time::Duration;

use chio_core::capability::scope::ChioScope;
use chio_data_guards::{QueryResultGuard, SqlQueryGuard, VectorDbGuard, WarehouseCostGuard};
use chio_external_guards::{
    external::{BackoffStrategy, CircuitBreakerConfig, RetryConfig},
    AsyncGuardAdapter, AzureCategory, AzureContentSafetyConfig, AzureContentSafetyGuard,
    SafeBrowsingConfig, SafeBrowsingGuard, ScopedAsyncGuard,
};
use chio_guards::{
    ContentReviewGuard, EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline,
    InternalNetworkGuard, McpToolGuard, PatchIntegrityGuard, PathAllowlistGuard,
    PostInvocationPipeline, SanitizerHook, SecretLeakGuard, ShellCommandGuard,
};

use super::guard_config::{
    default_forbidden_path_patterns, AzureContentSafetyPolicyConfig, ExternalAdapterPolicyConfig,
    GuardPolicyConfig, SafeBrowsingPolicyConfig, ToolAccessDefaultAction,
};
use super::types::PolicyError;

/// Build a `GuardPipeline` from a policy's guard configuration.
pub fn build_guard_pipeline(config: &GuardPolicyConfig) -> Result<GuardPipeline, PolicyError> {
    let mut pipeline = GuardPipeline::new();

    if let Some(fp) = &config.forbidden_path {
        if fp.enabled {
            if fp.patterns.is_none()
                && fp.additional_patterns.is_empty()
                && fp.exceptions.is_empty()
            {
                pipeline.add(Box::new(ForbiddenPathGuard::new()));
            } else {
                let mut patterns = fp
                    .patterns
                    .clone()
                    .unwrap_or_else(default_forbidden_path_patterns);
                patterns.extend(fp.additional_patterns.clone());
                pipeline.add(Box::new(
                    ForbiddenPathGuard::with_patterns(patterns, fp.exceptions.clone())
                        .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(pa) = &config.path_allowlist {
        if pa.enabled {
            pipeline.add(Box::new(PathAllowlistGuard::with_config(
                chio_guards::path_allowlist::PathAllowlistConfig {
                    enabled: true,
                    file_access_allow: pa.read.clone(),
                    file_write_allow: pa.write.clone(),
                    patch_allow: pa.patch.clone(),
                },
            )));
        }
    }

    if let Some(sc) = &config.shell_command {
        if sc.enabled {
            if sc.forbidden_patterns.is_empty() {
                pipeline.add(Box::new(ShellCommandGuard::new()));
            } else {
                pipeline.add(Box::new(
                    ShellCommandGuard::try_with_patterns(sc.forbidden_patterns.clone(), true)
                        .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(eg) = &config.egress_allowlist {
        if eg.enabled {
            if eg.allowed_domains.is_empty() && eg.blocked_domains.is_empty() {
                pipeline.add(Box::new(EgressAllowlistGuard::new()));
            } else {
                pipeline.add(Box::new(
                    EgressAllowlistGuard::with_lists(
                        eg.allowed_domains.clone(),
                        eg.blocked_domains.clone(),
                    )
                    .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(internal_network) = &config.internal_network {
        if internal_network.enabled {
            pipeline.add(Box::new(InternalNetworkGuard::with_config(
                internal_network.extra_blocked_hosts.clone(),
                internal_network.dns_rebinding_detection,
            )));
        }
    }

    if let Some(tool_access) = &config.tool_access {
        if tool_access.enabled {
            let default_action = match tool_access.default_action {
                ToolAccessDefaultAction::Allow => chio_guards::mcp_tool::McpDefaultAction::Allow,
                ToolAccessDefaultAction::Block => chio_guards::mcp_tool::McpDefaultAction::Block,
            };
            pipeline.add(Box::new(McpToolGuard::with_config(
                chio_guards::mcp_tool::McpToolConfig {
                    enabled: true,
                    allow: tool_access.allow.clone(),
                    block: tool_access.block.clone(),
                    default_action,
                    max_args_size: tool_access.max_args_size,
                },
            )));
        }
    }

    if let Some(secret_patterns) = &config.secret_patterns {
        if secret_patterns.enabled {
            let guard = SecretLeakGuard::with_config(chio_guards::secret_leak::SecretLeakConfig {
                enabled: true,
                skip_paths: secret_patterns.skip_paths.clone(),
                custom_patterns: Vec::new(),
            })
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            pipeline.add(Box::new(guard));
        }
    }

    if let Some(patch_integrity) = &config.patch_integrity {
        if patch_integrity.enabled {
            pipeline.add(Box::new(
                PatchIntegrityGuard::with_config(
                    chio_guards::patch_integrity::PatchIntegrityConfig {
                        enabled: true,
                        max_additions: patch_integrity.max_additions,
                        max_deletions: patch_integrity.max_deletions,
                        forbidden_patterns: patch_integrity.forbidden_patterns.clone(),
                        require_balance: patch_integrity.require_balance,
                        max_imbalance_ratio: patch_integrity.max_imbalance_ratio,
                    },
                )
                .map_err(|error| PolicyError::Invalid(error.to_string()))?,
            ));
        }
    }

    if let Some(sql_query) = &config.sql_query {
        pipeline.add(Box::new(
            SqlQueryGuard::try_new(sql_query.clone()).map_err(PolicyError::Invalid)?,
        ));
    }

    if let Some(vector_db) = &config.vector_db {
        pipeline.add(Box::new(VectorDbGuard::new(vector_db.clone())));
    }

    if let Some(warehouse_cost) = &config.warehouse_cost {
        pipeline.add(Box::new(WarehouseCostGuard::new(warehouse_cost.clone())));
    }

    if let Some(content_review) = &config.content_review {
        pipeline.add(Box::new(
            ContentReviewGuard::with_config(content_review.clone())
                .map_err(|error| PolicyError::Invalid(error.to_string()))?,
        ));
    }

    if let Some(cloud_guardrails) = &config.cloud_guardrails {
        if let Some(azure) = &cloud_guardrails.azure_content_safety {
            if azure.enabled {
                pipeline.add(Box::new(build_azure_content_safety_guard(azure)?));
            }
        }
    }

    if let Some(threat_intel) = &config.threat_intel {
        if let Some(safe_browsing) = &threat_intel.safe_browsing {
            if safe_browsing.enabled {
                pipeline.add(Box::new(build_safe_browsing_guard(safe_browsing)?));
            }
        }
    }

    Ok(pipeline)
}

fn build_azure_content_safety_guard(
    config: &AzureContentSafetyPolicyConfig,
) -> Result<ScopedAsyncGuard<AzureContentSafetyGuard>, PolicyError> {
    validate_required_secret(
        "cloud_guardrails.azure_content_safety.api_key",
        &config.api_key,
    )?;
    validate_https_url(
        "cloud_guardrails.azure_content_safety.endpoint",
        &config.endpoint,
    )?;

    let mut guard_config =
        AzureContentSafetyConfig::new(config.api_key.clone(), config.endpoint.clone());
    if let Some(api_version) = &config.api_version {
        if api_version.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.api_version cannot be empty".to_string(),
            ));
        }
        guard_config.api_version = api_version.clone();
    }
    if let Some(timeout_seconds) = config.timeout_seconds {
        if timeout_seconds == 0 {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.timeout_seconds must be greater than 0"
                    .to_string(),
            ));
        }
        guard_config.timeout = Duration::from_secs(timeout_seconds);
    }
    if let Some(severity_threshold) = config.severity_threshold {
        if severity_threshold > 7 {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.severity_threshold must be between 0 and 7"
                    .to_string(),
            ));
        }
        guard_config.severity_threshold = severity_threshold;
    }
    if !config.categories.is_empty() {
        guard_config.categories = config
            .categories
            .iter()
            .map(|category| parse_azure_category(category))
            .collect::<Result<Vec<_>, _>>()?;
    }

    let guard = AzureContentSafetyGuard::new(guard_config)
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
    let adapter = configure_async_guard_adapter(
        AsyncGuardAdapter::builder(Arc::new(guard)),
        &config.adapter,
        "cloud_guardrails.azure_content_safety.adapter",
    )?;
    Ok(ScopedAsyncGuard::new(adapter, config.tool_patterns.clone()))
}

pub(super) const SAFE_BROWSING_DEFAULT_BASE_URL: &str = "https://safebrowsing.googleapis.com/v4";

fn build_safe_browsing_guard(
    config: &SafeBrowsingPolicyConfig,
) -> Result<ScopedAsyncGuard<SafeBrowsingGuard>, PolicyError> {
    validate_required_secret("threat_intel.safe_browsing.api_key", &config.api_key)?;
    let mut guard_config = SafeBrowsingConfig::new(config.api_key.clone());
    let base_url = if let Some(base_url) = config.base_url.as_deref() {
        validate_https_url("threat_intel.safe_browsing.base_url", base_url)?;
        base_url.to_string()
    } else {
        chio_external_guards::validate_external_guard_url_without_dns(
            "threat_intel.safe_browsing.base_url",
            SAFE_BROWSING_DEFAULT_BASE_URL,
        )
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        SAFE_BROWSING_DEFAULT_BASE_URL.to_string()
    };
    guard_config.base_url = Some(base_url);
    if let Some(client_id) = &config.client_id {
        if client_id.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.client_id cannot be empty".to_string(),
            ));
        }
        guard_config.client_id = client_id.clone();
    }
    if let Some(client_version) = &config.client_version {
        if client_version.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.client_version cannot be empty".to_string(),
            ));
        }
        guard_config.client_version = client_version.clone();
    }
    if !config.threat_types.is_empty() {
        if config
            .threat_types
            .iter()
            .any(|threat_type| threat_type.trim().is_empty())
        {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.threat_types cannot contain empty values".to_string(),
            ));
        }
        guard_config.threat_types = config.threat_types.clone();
    }
    if let Some(timeout_seconds) = config.timeout_seconds {
        if timeout_seconds == 0 {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.timeout_seconds must be greater than 0".to_string(),
            ));
        }
        guard_config.timeout = Duration::from_secs(timeout_seconds);
    }

    let guard = SafeBrowsingGuard::new(guard_config)
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
    let adapter = configure_async_guard_adapter(
        AsyncGuardAdapter::builder(Arc::new(guard)),
        &config.adapter,
        "threat_intel.safe_browsing.adapter",
    )?;
    Ok(ScopedAsyncGuard::new(adapter, config.tool_patterns.clone()))
}

fn configure_async_guard_adapter<E>(
    builder: chio_external_guards::AsyncGuardAdapterBuilder<E>,
    config: &ExternalAdapterPolicyConfig,
    field_prefix: &str,
) -> Result<AsyncGuardAdapter<E>, PolicyError>
where
    E: chio_external_guards::ExternalGuard,
{
    if !config.rate_per_second.is_finite() || config.rate_per_second <= 0.0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.rate_per_second must be greater than 0"
        )));
    }
    if config.rate_burst == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.rate_burst must be greater than 0"
        )));
    }
    if config.cache_ttl_seconds == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.cache_ttl_seconds must be greater than 0"
        )));
    }
    if config.circuit_failure_threshold == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.circuit_failure_threshold must be greater than 0"
        )));
    }

    let circuit = CircuitBreakerConfig {
        failure_threshold: config.circuit_failure_threshold,
        ..CircuitBreakerConfig::default()
    };

    let retry = RetryConfig {
        max_retries: config.retry_max_retries,
        strategy: BackoffStrategy::Exponential,
        ..RetryConfig::default()
    };

    Ok(builder
        .circuit(circuit)
        .retry(retry)
        .cache_ttl(Duration::from_secs(config.cache_ttl_seconds))
        .rate_limit(config.rate_per_second, config.rate_burst)
        .build())
}

fn validate_required_secret(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.trim().is_empty() {
        return Err(PolicyError::Invalid(format!("{field} cannot be empty")));
    }
    Ok(())
}

pub(super) fn validate_https_url(field: &str, value: &str) -> Result<(), PolicyError> {
    chio_external_guards::validate_external_guard_url(field, value)
        .map_err(|error| PolicyError::Invalid(error.to_string()))
}

fn parse_azure_category(category: &str) -> Result<AzureCategory, PolicyError> {
    match category.trim().to_ascii_lowercase().as_str() {
        "hate" => Ok(AzureCategory::Hate),
        "self_harm" | "selfharm" => Ok(AzureCategory::SelfHarm),
        "sexual" => Ok(AzureCategory::Sexual),
        "violence" => Ok(AzureCategory::Violence),
        _ => Err(PolicyError::Invalid(format!(
            "unsupported azure content safety category: {category}"
        ))),
    }
}

/// Build a `PostInvocationPipeline` from a policy's guard configuration.
pub fn build_post_invocation_pipeline(
    config: &GuardPolicyConfig,
) -> Result<PostInvocationPipeline, PolicyError> {
    let mut pipeline = PostInvocationPipeline::new();

    if let Some(query_result) = &config.query_result {
        let guard = QueryResultGuard::new(query_result.clone()).map_err(PolicyError::Invalid)?;
        pipeline.add(Box::new(guard.into_owned_hook(ChioScope::default())));
    }

    if let Some(secret_patterns) = &config.secret_patterns {
        if secret_patterns.enabled {
            pipeline.add(Box::new(SanitizerHook::new()));
        }
    }

    Ok(pipeline)
}
