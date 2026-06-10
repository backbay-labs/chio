use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioCategory {
    McpCore,
    McpExperimental,
    ChioExtension,
    Infra,
}

impl ScenarioCategory {
    pub fn heading(self) -> &'static str {
        match self {
            Self::McpCore => "MCP Core",
            Self::McpExperimental => "MCP Experimental",
            Self::ChioExtension => "Chio Extensions",
            Self::Infra => "Infrastructure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Stdio,
    StreamableHttp,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::StreamableHttp => "streamable-http",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    ClientToChioServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    WrappedStdio,
    NativeStdio,
    RemoteHttp,
}

impl DeploymentMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::WrappedStdio => "wrapped-stdio",
            Self::NativeStdio => "native-stdio",
            Self::RemoteHttp => "remote-http",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredCapabilities {
    #[serde(default)]
    pub server: Vec<String>,
    #[serde(default)]
    pub client: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioDescriptor {
    pub id: String,
    pub title: String,
    pub area: String,
    pub category: ScenarioCategory,
    pub spec_versions: Vec<String>,
    #[serde(default)]
    pub transport: Vec<Transport>,
    #[serde(default)]
    pub peer_roles: Vec<PeerRole>,
    #[serde(default)]
    pub deployment_modes: Vec<DeploymentMode>,
    #[serde(default)]
    pub required_capabilities: RequiredCapabilities,
    #[serde(default)]
    pub tags: Vec<String>,
    pub expected: ResultStatus,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultStatus {
    Pass,
    Fail,
    Unsupported,
    Skipped,
    Xfail,
}

impl ResultStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unsupported => "unsupported",
            Self::Skipped => "skipped",
            Self::Xfail => "xfail",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResult {
    pub name: String,
    pub status: AssertionOutcome,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub peer: String,
    pub peer_role: PeerRole,
    pub deployment_mode: DeploymentMode,
    pub transport: Transport,
    pub spec_version: String,
    pub category: ScenarioCategory,
    pub status: ResultStatus,
    pub duration_ms: u64,
    #[serde(default)]
    pub assertions: Vec<AssertionResult>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default)]
    pub failure_kind: Option<String>,
    #[serde(default)]
    pub failure_message: Option<String>,
    #[serde(default)]
    pub expected_failure: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompatibilityReport {
    pub scenarios: Vec<ScenarioDescriptor>,
    pub results: Vec<ScenarioResult>,
}
