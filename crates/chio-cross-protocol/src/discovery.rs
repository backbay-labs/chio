use std::collections::BTreeMap;
use std::fmt;

use chio_manifest::ToolDefinition;
use serde::{Deserialize, Serialize};

use crate::execution::TargetProtocolExecutor;
use crate::validation::schema_string_extension;

/// Shared target-protocol registry and default binding policy for
/// claim-eligible routes.
pub struct TargetProtocolRegistry<'a> {
    default_target_protocol: DiscoveryProtocol,
    executors: BTreeMap<DiscoveryProtocol, &'a dyn TargetProtocolExecutor>,
}

/// Protocol families Chio can bridge across.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProtocol {
    Native,
    Http,
    Mcp,
    A2a,
    Acp,
    OpenAi,
}

impl DiscoveryProtocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Http => "http",
            Self::Mcp => "mcp",
            Self::A2a => "a2a",
            Self::Acp => "acp",
            Self::OpenAi => "open_ai",
        }
    }
}

impl fmt::Display for DiscoveryProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'a> TargetProtocolRegistry<'a> {
    #[must_use]
    pub fn new(default_target_protocol: DiscoveryProtocol) -> Self {
        Self {
            default_target_protocol,
            executors: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_executor(mut self, executor: &'a dyn TargetProtocolExecutor) -> Self {
        self.executors.insert(executor.target_protocol(), executor);
        self
    }

    #[must_use]
    pub fn default_target_protocol(&self) -> DiscoveryProtocol {
        self.default_target_protocol
    }

    pub fn resolve_target_protocol(
        &self,
        tool: &ToolDefinition,
    ) -> Result<DiscoveryProtocol, String> {
        let target = match schema_string_extension(&tool.input_schema, "x-chio-target-protocol")? {
            Some(value) => Some(value),
            None => match tool.output_schema.as_ref() {
                Some(schema) => schema_string_extension(schema, "x-chio-target-protocol")?,
                None => None,
            },
        };

        match target {
            Some(value) => parse_discovery_protocol(&value),
            None => Ok(self.default_target_protocol),
        }
    }

    #[must_use]
    pub fn supports_target_protocol(&self, protocol: DiscoveryProtocol) -> bool {
        protocol == DiscoveryProtocol::Native || self.executors.contains_key(&protocol)
    }

    pub(crate) fn executor_for_target(
        &self,
        protocol: DiscoveryProtocol,
    ) -> Option<&'a dyn TargetProtocolExecutor> {
        self.executors.get(&protocol).copied()
    }
}

/// Resolve the authoritative target protocol advertised for a tool.
///
/// `x-chio-target-protocol` follows the same schema-extension pattern as the
/// other `x-chio-*` bridge hints. When omitted, Chio defaults to `native`.
pub fn target_protocol_for_tool(tool: &ToolDefinition) -> Result<DiscoveryProtocol, String> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native).resolve_target_protocol(tool)
}

/// Resolve the authoritative target protocol using an explicit registry policy
/// rather than silent `Native` fallback.
pub fn target_protocol_for_tool_with_registry(
    tool: &ToolDefinition,
    registry: &TargetProtocolRegistry<'_>,
) -> Result<DiscoveryProtocol, String> {
    registry.resolve_target_protocol(tool)
}

/// Parse a protocol-family name used in bridge metadata.
pub fn parse_discovery_protocol(value: &str) -> Result<DiscoveryProtocol, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "native" => Ok(DiscoveryProtocol::Native),
        "http" => Ok(DiscoveryProtocol::Http),
        "mcp" => Ok(DiscoveryProtocol::Mcp),
        "a2a" => Ok(DiscoveryProtocol::A2a),
        "acp" => Ok(DiscoveryProtocol::Acp),
        "open_ai" | "openai" => Ok(DiscoveryProtocol::OpenAi),
        _ => Err(format!(
            "unsupported x-chio-target-protocol value `{value}`; expected one of native, http, mcp, a2a, acp, open_ai"
        )),
    }
}
