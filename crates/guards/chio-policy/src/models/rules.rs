use super::enums::{ComputerUseMode, DefaultAction, Severity};
use super::{
    default_1000, default_500, default_allow, default_block, default_burst_factor,
    default_guardrail, default_imbalance_ratio, default_true, default_velocity_window_secs,
};
use chio_core::capability::{
    runtime_attestation::RuntimeAssuranceTier,
    workload_identity::{WorkloadCredentialKind, WorkloadIdentityScheme},
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Rule-block names represented by [`Rules`]. Keep this list in lockstep with
/// the fields on `Rules` so validators and evaluators share the same inventory.
pub const RULE_BLOCK_NAMES: [&str; 14] = [
    "forbidden_paths",
    "path_allowlist",
    "egress",
    "secret_patterns",
    "patch_integrity",
    "shell_commands",
    "tool_access",
    "computer_use",
    "remote_desktop_channels",
    "input_injection",
    "browser_automation",
    "code_execution",
    "velocity",
    "human_in_loop",
];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_paths: Option<ForbiddenPathsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_allowlist: Option<PathAllowlistRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_patterns: Option<SecretPatternsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_integrity: Option<PatchIntegrityRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<ShellCommandsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_desktop_channels: Option<RemoteDesktopChannelsRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_injection: Option<InputInjectionRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_automation: Option<BrowserAutomationRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_execution: Option<CodeExecutionRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub velocity: Option<VelocityRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_in_loop: Option<HumanInLoopRule>,
}

impl Rules {
    pub(crate) fn has_configured_blocks(&self) -> bool {
        self.forbidden_paths.is_some()
            || self.path_allowlist.is_some()
            || self.egress.is_some()
            || self.secret_patterns.is_some()
            || self.patch_integrity.is_some()
            || self.shell_commands.is_some()
            || self.tool_access.is_some()
            || self.computer_use.is_some()
            || self.remote_desktop_channels.is_some()
            || self.input_injection.is_some()
            || self.browser_automation.is_some()
            || self.code_execution.is_some()
            || self.velocity.is_some()
            || self.human_in_loop.is_some()
    }

    pub(crate) fn clear_block(&mut self, block_name: &str) -> bool {
        match block_name {
            "forbidden_paths" => self.forbidden_paths = None,
            "path_allowlist" => self.path_allowlist = None,
            "egress" => self.egress = None,
            "secret_patterns" => self.secret_patterns = None,
            "patch_integrity" => self.patch_integrity = None,
            "shell_commands" => self.shell_commands = None,
            "tool_access" => self.tool_access = None,
            "computer_use" => self.computer_use = None,
            "remote_desktop_channels" => self.remote_desktop_channels = None,
            "input_injection" => self.input_injection = None,
            "browser_automation" => self.browser_automation = None,
            "code_execution" => self.code_execution = None,
            "velocity" => self.velocity = None,
            "human_in_loop" => self.human_in_loop = None,
            _ => return false,
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPathsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub exceptions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAllowlistRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub patch: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default = "default_block")]
    pub default: DefaultAction,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPatternsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<SecretPattern>,
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchIntegrityRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_1000")]
    pub max_additions: usize,
    #[serde(default = "default_500")]
    pub max_deletions: usize,
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    #[serde(default)]
    pub require_balance: bool,
    #[serde(default = "default_imbalance_ratio")]
    pub max_imbalance_ratio: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCommandsRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAccessRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    #[serde(default = "default_allow")]
    pub default: DefaultAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_workload_identity: Option<WorkloadIdentityMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_workload_identity: Option<WorkloadIdentityMatch>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<WorkloadIdentityScheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub credential_kinds: Vec<WorkloadCredentialKind>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerUseRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_guardrail")]
    pub mode: ComputerUseMode,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopChannelsRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub clipboard: bool,
    #[serde(default)]
    pub file_transfer: bool,
    #[serde(default = "default_true")]
    pub audio: bool,
    #[serde(default)]
    pub drive_mapping: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputInjectionRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_types: Vec<String>,
    #[serde(default)]
    pub require_postcondition_probe: bool,
}

/// Browser-automation restrictions. Compiles to
/// [`chio_guards::BrowserAutomationGuard`]: domain allowlist /
/// blocklist, verb allowlist, credential detection in `type` actions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAutomationRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub allowed_verbs: Vec<String>,
    #[serde(default = "default_true")]
    pub credential_detection: bool,
    #[serde(default)]
    pub extra_credential_patterns: Vec<String>,
}

/// Sandboxed-interpreter restrictions. Compiles to
/// [`chio_guards::CodeExecutionGuard`]: language allowlist, dangerous
/// module denylist, network gating, execution-time bounds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeExecutionRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub language_allowlist: Vec<String>,
    #[serde(default)]
    pub module_denylist: Vec<String>,
    #[serde(default)]
    pub network_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_execution_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scan_bytes: Option<usize>,
}

/// Token-bucket rate and spend limiting, compiled to `VelocityGuard` +
/// `AgentVelocityGuard`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VelocityRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations_per_window: Option<u32>,
    /// Integer minor units (e.g. cents) matching `ToolGrant::max_cost_per_invocation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_spend_per_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_agent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_session: Option<u32>,
    #[serde(default = "default_velocity_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_burst_factor")]
    pub burst_factor: f64,
}

/// Human-in-the-loop approval gating. Compiles to
/// `Constraint::RequireApprovalAbove { threshold_units }` on tool grants.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanInLoopRule {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tool-name globs that always need approval (compiles to threshold = 0).
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    /// Integer minor units; compiles to
    /// `Constraint::RequireApprovalAbove { threshold_units }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_above: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_above_currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub on_timeout: HumanInLoopTimeoutAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HumanInLoopTimeoutAction {
    #[default]
    Deny,
    Defer,
}
