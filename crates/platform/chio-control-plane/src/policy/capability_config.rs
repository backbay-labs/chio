use serde::{Deserialize, Serialize};

/// Configuration for initial capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicyConfig {
    /// Default capabilities issued to every agent at session start.
    #[serde(default)]
    pub default: Option<DefaultCapabilityConfig>,
}

/// Default capability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultCapabilityConfig {
    /// Tool grants to include in the default capability.
    #[serde(default)]
    pub tools: Vec<ToolGrantConfig>,

    /// Resource grants to include in the default capability.
    #[serde(default)]
    pub resources: Vec<ResourceGrantConfig>,

    /// Prompt grants to include in the default capability.
    #[serde(default)]
    pub prompts: Vec<PromptGrantConfig>,
}

/// A tool grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrantConfig {
    /// Server pattern (e.g. "*" for any, or "my-server").
    pub server: String,
    /// Tool pattern (e.g. "*" for any, or "read_file").
    pub tool: String,
    /// Operations to grant.
    #[serde(default = "default_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

/// A resource grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrantConfig {
    /// Resource URI pattern (for example `repo://docs/*`).
    pub uri: String,
    /// Operations to grant.
    #[serde(default = "default_resource_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

/// A prompt grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptGrantConfig {
    /// Prompt name pattern.
    pub prompt: String,
    /// Operations to grant.
    #[serde(default = "default_prompt_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

fn default_operations() -> Vec<String> {
    vec!["invoke".to_string()]
}

fn default_grant_ttl() -> u64 {
    300
}

fn default_resource_operations() -> Vec<String> {
    vec!["read".to_string()]
}

fn default_prompt_operations() -> Vec<String> {
    vec!["get".to_string()]
}
