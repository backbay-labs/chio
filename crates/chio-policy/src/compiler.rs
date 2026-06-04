//! HushSpec-to-Chio compiler.
//!
//! This is the key bridge between HushSpec policies and Chio's guard pipeline.
//! It translates HushSpec rule blocks into configured Chio guards and builds
//! a default capability scope from the policy's tool_access rules.
//!
//! # Guard coverage
//!
//! The compiler materializes 12 distinct guard types from a HushSpec
//! document. The first seven are driven directly by the `rules` section; the
//! remaining five are driven either by the `extensions.detection`
//! sub-section or by auxiliary semantics layered on top of existing rule
//! blocks (SSRF protection on egress, per-agent velocity from origin
//! budgets).
//!
//! | # | Guard | Triggered by |
//! |---|----------------------------|----------------------------------------|
//! | 1 | `ForbiddenPathGuard`       | `rules.forbidden_paths` |
//! | 2 | `ShellCommandGuard`        | `rules.shell_commands` |
//! | 3 | `EgressAllowlistGuard`     | `rules.egress` |
//! | 4 | `McpToolGuard`             | `rules.tool_access` |
//! | 5 | `SecretLeakGuard`          | `rules.secret_patterns` |
//! | 6 | `PatchIntegrityGuard`      | `rules.patch_integrity` |
//! | 7 | `PathAllowlistGuard`       | `rules.path_allowlist` |
//! | 8 | `PromptInjectionGuard`     | `extensions.detection.prompt_injection`|
//! | 9 | `JailbreakGuard`           | `extensions.detection.jailbreak` |
//! |10 | `SpiderSenseGuard`         | `extensions.detection.threat_intel` |
//! |11 | `InternalNetworkGuard`     | `rules.egress` (SSRF companion) |
//! |12 | `AgentVelocityGuard`       | `extensions.origins.profiles[].budgets` |

use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{
    ComputerUseMode, ComputerUseRule, DefaultAction, DetectionLevel, HumanInLoopRule, HushSpec,
    InputInjectionRule, JailbreakDetection, PromptInjectionDetection, RemoteDesktopChannelsRule,
    SecretPatternsRule, ThreatIntelDetection, ToolAccessRule, VelocityRule,
};

use chio_core::capability::{ChioScope, Constraint, Operation, ToolGrant};
use chio_guards::{
    agent_velocity::AgentVelocityConfig,
    computer_use::{ComputerUseConfig, EnforcementMode},
    input_injection::InputInjectionCapabilityConfig,
    jailbreak::{DetectorConfig as JailbreakDetectorConfig, JailbreakGuardConfig},
    post_invocation::SanitizerHook,
    prompt_injection::PromptInjectionConfig,
    remote_desktop::RemoteDesktopSideChannelConfig,
    response_sanitization::OutputSanitizerConfig,
    secret_leak::CustomSecretPattern,
    velocity::VelocityConfig,
    AgentVelocityGuard, ComputerUseGuard, EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline,
    InputInjectionCapabilityGuard, InternalNetworkGuard, JailbreakGuard, McpToolGuard,
    PatchIntegrityGuard, PathAllowlistGuard, PatternDb, PostInvocationPipeline,
    PromptInjectionGuard, RemoteDesktopSideChannelGuard, SecretLeakGuard, ShellCommandGuard,
    SpiderSenseConfig, SpiderSenseGuard, VelocityGuard,
};

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// The result of compiling a HushSpec policy into Chio primitives.
pub struct CompiledPolicy {
    /// A guard pipeline configured from the policy's rule blocks.
    pub guards: GuardPipeline,
    /// A post-invocation pipeline configured from the policy's rule blocks.
    pub post_invocation: PostInvocationPipeline,
    /// A default capability scope derived from the policy's tool_access rules.
    pub default_scope: ChioScope,
    /// Ordered list of guard names emitted by compilation.
    ///
    /// The compiler is required to emit a
    /// `Vec<Box<dyn Guard>>` containing all 12 guard types; because
    /// [`GuardPipeline`] does not publicly expose its contained guards,
    /// this sidecar records the `Guard::name()` of each guard added to the
    /// pipeline in insertion order. Deduplicated, this is the set of
    /// concrete guard types that compiled successfully.
    pub guard_names: Vec<String>,
}

/// Compile a HushSpec policy into a Chio guard pipeline and default scope.
///
/// This maps HushSpec rule blocks and detection-extension blocks to Chio
/// guard configurations. See the module-level documentation for the full
/// mapping table. Missing sections compile to an empty pipeline; no error
/// is raised for policies that simply do not exercise every guard type.
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_source(policy, None)
}

/// Compile a HushSpec policy with an optional source path used to resolve
/// relative auxiliary assets referenced by the policy.
pub fn compile_policy_with_source(
    policy: &HushSpec,
    source_path: Option<&Path>,
) -> Result<CompiledPolicy, CompileError> {
    ensure_compilable_policy(policy)?;

    let mut builder = PipelineBuilder::new();
    let mut post_invocation = PostInvocationPipeline::new();
    let source_dir = source_path.and_then(|path| path.parent());
    compile_rule_guards(policy, &mut builder, &mut post_invocation)?;
    compile_detection_guards(policy, &mut builder, source_dir)?;
    compile_budget_guards(policy, &mut builder)?;
    let default_scope = compile_scope(policy)?;
    let (guards, guard_names) = builder.finish();
    Ok(CompiledPolicy {
        guards,
        post_invocation,
        default_scope,
        guard_names,
    })
}

fn ensure_compilable_policy(policy: &HushSpec) -> Result<(), CompileError> {
    let validation = crate::validate::validate(policy);
    if validation.is_valid() {
        return Ok(());
    }

    let messages = validation
        .errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Err(CompileError::Invalid(format!(
        "HushSpec validation failed: {messages}"
    )))
}

// ---------------------------------------------------------------------------
// Pipeline builder
// ---------------------------------------------------------------------------

/// Helper that keeps the [`GuardPipeline`] and the parallel `guard_names`
/// list in lockstep so callers cannot forget to record a guard's name when
/// they add it.
struct PipelineBuilder {
    pipeline: GuardPipeline,
    names: Vec<String>,
}

impl PipelineBuilder {
    fn new() -> Self {
        Self {
            pipeline: GuardPipeline::new(),
            names: Vec::new(),
        }
    }

    fn add<G: chio_kernel::Guard + 'static>(&mut self, guard: G) {
        self.names.push(guard.name().to_string());
        self.pipeline.add(Box::new(guard));
    }

    fn finish(self) -> (GuardPipeline, Vec<String>) {
        (self.pipeline, self.names)
    }
}

// ---------------------------------------------------------------------------
// Rule-driven guards (1-7 + InternalNetworkGuard)
// ---------------------------------------------------------------------------

fn compile_rule_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
    post_invocation: &mut PostInvocationPipeline,
) -> Result<(), CompileError> {
    let Some(rules) = &policy.rules else {
        return Ok(());
    };

    // 1. forbidden_paths -> ForbiddenPathGuard
    if let Some(fp) = &rules.forbidden_paths {
        if fp.enabled {
            if fp.patterns.is_empty() {
                builder.add(ForbiddenPathGuard::new());
            } else {
                builder.add(
                    ForbiddenPathGuard::with_patterns(fp.patterns.clone(), fp.exceptions.clone())
                        .map_err(|error| CompileError::Invalid(error.to_string()))?,
                );
            }
        }
    }

    // 1b. velocity -> VelocityGuard + AgentVelocityGuard
    //
    // Inserted between ForbiddenPathGuard and ShellCommandGuard so that
    // rate-limit denials are observed before any shell semantics fire.
    if let Some(v) = &rules.velocity {
        if v.enabled {
            let (velocity_cfg, agent_cfg) = compile_velocity_rule(v);
            if let Some(cfg) = velocity_cfg {
                builder.add(VelocityGuard::new(cfg));
            }
            if let Some(cfg) = agent_cfg {
                builder.add(AgentVelocityGuard::new(cfg));
            }
        }
    }

    // 2. shell_commands -> ShellCommandGuard
    if let Some(sc) = &rules.shell_commands {
        if sc.enabled {
            if sc.forbidden_patterns.is_empty() {
                builder.add(ShellCommandGuard::new());
            } else {
                builder.add(ShellCommandGuard::with_patterns(
                    sc.forbidden_patterns.clone(),
                    true,
                ));
            }
        }
    }

    // 3. egress -> EgressAllowlistGuard
    // 10. egress -> InternalNetworkGuard (SSRF companion)
    //
    // When the policy opts into egress control we also add an internal-
    // network guard that blocks RFC1918 / cloud-metadata endpoints. This
    // provides a layered defense: the allowlist catches unknown domains and
    // the internal-network guard catches raw IPs.
    if let Some(eg) = &rules.egress {
        if eg.enabled {
            if eg.allow.is_empty() && eg.block.is_empty() {
                builder.add(EgressAllowlistGuard::new());
            } else {
                builder.add(
                    EgressAllowlistGuard::with_lists(eg.allow.clone(), eg.block.clone())
                        .map_err(|error| CompileError::Invalid(error.to_string()))?,
                );
            }
            builder.add(InternalNetworkGuard::new());
        }
    }

    // 4. tool_access -> McpToolGuard
    if let Some(ta) = &rules.tool_access {
        if ta.enabled {
            let mcp_default = match ta.default {
                DefaultAction::Allow => chio_guards::mcp_tool::McpDefaultAction::Allow,
                DefaultAction::Block => chio_guards::mcp_tool::McpDefaultAction::Block,
            };
            let config = chio_guards::mcp_tool::McpToolConfig {
                enabled: true,
                allow: ta.allow.clone(),
                block: ta.block.clone(),
                default_action: mcp_default,
                max_args_size: ta.max_args_size,
            };
            builder.add(McpToolGuard::with_config(config));
        }
    }

    // 5. secret_patterns -> SecretLeakGuard
    //
    // SecretLeakGuard handles the write path (detect secrets in outbound
    // file writes) while the post-invocation SanitizerHook handles the read
    // path (redact secrets in tool results before the agent sees them).
    if let Some(sp) = &rules.secret_patterns {
        if sp.enabled {
            let config = chio_guards::secret_leak::SecretLeakConfig {
                enabled: true,
                skip_paths: sp.skip_paths.clone(),
                custom_patterns: compile_custom_secret_patterns(sp),
            };
            builder.add(
                SecretLeakGuard::with_config(config)
                    .map_err(|error| CompileError::Invalid(error.to_string()))?,
            );
            post_invocation.add(Box::new(
                SanitizerHook::with_config(compile_output_sanitizer_config(sp))
                    .map_err(|error| CompileError::Invalid(error.to_string()))?,
            ));
        }
    }

    // 6. patch_integrity -> PatchIntegrityGuard
    if let Some(pi) = &rules.patch_integrity {
        if pi.enabled {
            let config = chio_guards::patch_integrity::PatchIntegrityConfig {
                enabled: true,
                max_additions: pi.max_additions,
                max_deletions: pi.max_deletions,
                forbidden_patterns: pi.forbidden_patterns.clone(),
                require_balance: pi.require_balance,
                max_imbalance_ratio: pi.max_imbalance_ratio,
            };
            builder.add(
                PatchIntegrityGuard::with_config(config)
                    .map_err(|error| CompileError::Invalid(error.to_string()))?,
            );
        }
    }

    // 7. path_allowlist -> PathAllowlistGuard
    if let Some(pa) = &rules.path_allowlist {
        if pa.enabled {
            let config = chio_guards::path_allowlist::PathAllowlistConfig {
                enabled: true,
                file_access_allow: pa.read.clone(),
                file_write_allow: pa.write.clone(),
                patch_allow: pa.patch.clone(),
            };
            builder.add(PathAllowlistGuard::with_config(config));
        }
    }

    // 8. computer_use -> ComputerUseGuard
    if let Some(cu) = &rules.computer_use {
        if cu.enabled {
            builder.add(ComputerUseGuard::with_config(compile_computer_use_rule(cu)));
        }
    }

    // 9. remote_desktop_channels -> RemoteDesktopSideChannelGuard
    if let Some(rd) = &rules.remote_desktop_channels {
        if rd.enabled {
            builder.add(RemoteDesktopSideChannelGuard::with_config(
                compile_remote_desktop_rule(rd),
            ));
        }
    }

    // 10. input_injection -> InputInjectionCapabilityGuard
    if let Some(ii) = &rules.input_injection {
        if ii.enabled {
            builder.add(InputInjectionCapabilityGuard::with_config(
                compile_input_injection_rule(ii),
            ));
        }
    }

    // 11. browser_automation -> BrowserAutomationGuard
    if let Some(ba) = &rules.browser_automation {
        if ba.enabled {
            let config = compile_browser_automation_rule(ba);
            builder.add(
                chio_guards::BrowserAutomationGuard::with_config(config)
                    .map_err(|error| CompileError::Invalid(error.to_string()))?,
            );
        }
    }

    // 12. code_execution -> CodeExecutionGuard
    if let Some(ce) = &rules.code_execution {
        if ce.enabled {
            let config = compile_code_execution_rule(ce);
            builder.add(
                chio_guards::CodeExecutionGuard::with_config(config)
                    .map_err(|error| CompileError::Invalid(error.to_string()))?,
            );
        }
    }

    Ok(())
}

fn compile_computer_use_rule(rule: &ComputerUseRule) -> ComputerUseConfig {
    let mode = match rule.mode {
        ComputerUseMode::Observe => EnforcementMode::Observe,
        ComputerUseMode::Guardrail => EnforcementMode::Guardrail,
        ComputerUseMode::FailClosed => EnforcementMode::FailClosed,
    };
    ComputerUseConfig {
        enabled: true,
        allowed_action_types: rule.allowed_actions.clone(),
        mode,
        ..ComputerUseConfig::default()
    }
}

fn compile_remote_desktop_rule(rule: &RemoteDesktopChannelsRule) -> RemoteDesktopSideChannelConfig {
    // HushSpec `remote_desktop_channels` carries per-channel toggles for
    // clipboard / file_transfer / audio / drive_mapping. It does not
    // currently model session_share, printing, or transfer size, so we
    // leave those at the guard's defaults (enabled / no limit).
    RemoteDesktopSideChannelConfig {
        enabled: true,
        clipboard_enabled: rule.clipboard,
        file_transfer_enabled: rule.file_transfer,
        audio_enabled: rule.audio,
        drive_mapping_enabled: rule.drive_mapping,
        ..RemoteDesktopSideChannelConfig::default()
    }
}

fn compile_input_injection_rule(rule: &InputInjectionRule) -> InputInjectionCapabilityConfig {
    InputInjectionCapabilityConfig {
        enabled: true,
        allowed_input_types: rule.allowed_types.clone(),
        require_postcondition_probe: rule.require_postcondition_probe,
        ..InputInjectionCapabilityConfig::default()
    }
}

fn compile_browser_automation_rule(
    rule: &crate::models::BrowserAutomationRule,
) -> chio_guards::BrowserAutomationConfig {
    chio_guards::BrowserAutomationConfig {
        enabled: true,
        allowed_domains: rule.allowed_domains.clone(),
        blocked_domains: rule.blocked_domains.clone(),
        allowed_verbs: rule.allowed_verbs.clone(),
        credential_detection: rule.credential_detection,
        extra_credential_patterns: rule.extra_credential_patterns.clone(),
    }
}

fn compile_code_execution_rule(
    rule: &crate::models::CodeExecutionRule,
) -> chio_guards::CodeExecutionConfig {
    let mut config = chio_guards::CodeExecutionConfig {
        enabled: true,
        language_allowlist: rule.language_allowlist.clone(),
        module_denylist: rule.module_denylist.clone(),
        network_access: rule.network_access,
        max_execution_time_ms: rule.max_execution_time_ms,
        ..chio_guards::CodeExecutionConfig::default()
    };
    if let Some(bytes) = rule.max_scan_bytes {
        config.max_scan_bytes = bytes;
    }
    config
}

// ---------------------------------------------------------------------------
// Detection-extension guards (8, 9, 10)
// ---------------------------------------------------------------------------

fn compile_detection_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
    source_dir: Option<&Path>,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(detection) = &extensions.detection else {
        return Ok(());
    };

    // 8. detection.prompt_injection -> PromptInjectionGuard
    if let Some(pi) = &detection.prompt_injection {
        if pi.enabled.unwrap_or(true) {
            builder.add(PromptInjectionGuard::with_config(
                prompt_injection_config_from(pi),
            ));
        }
    }

    // 9. detection.jailbreak -> JailbreakGuard
    if let Some(jb) = &detection.jailbreak {
        if jb.enabled.unwrap_or(true) {
            builder.add(JailbreakGuard::with_config(jailbreak_config_from(jb)?));
        }
    }

    // 10. detection.threat_intel -> SpiderSenseGuard
    if let Some(threat_intel) = &detection.threat_intel {
        if threat_intel.enabled.unwrap_or(true) {
            builder.add(threat_intel_guard_from(threat_intel, source_dir)?);
        }
    }

    Ok(())
}

fn prompt_injection_config_from(pi: &PromptInjectionDetection) -> PromptInjectionConfig {
    let mut config = PromptInjectionConfig::default();
    if let Some(block_at) = pi.block_at_or_above {
        config.score_threshold = prompt_level_to_score_threshold(block_at);
    }
    if let Some(max_scan_bytes) = pi.max_scan_bytes {
        // Clamp to at least one byte so the guard is well-formed; zero would
        // short-circuit the scanner to a no-op and silently allow everything.
        config.max_scan_bytes = max_scan_bytes.max(1);
    }
    config
}

/// Convert a HushSpec `DetectionLevel` into a PromptInjectionGuard score
/// threshold in `[0.0, 1.0]`. Higher levels require stronger signals before
/// the guard denies.
fn prompt_level_to_score_threshold(level: DetectionLevel) -> f32 {
    match level {
        DetectionLevel::Safe => 0.1,
        DetectionLevel::Suspicious => 0.4,
        DetectionLevel::High => 0.8,
        DetectionLevel::Critical => 1.0,
    }
}

fn jailbreak_config_from(jb: &JailbreakDetection) -> Result<JailbreakGuardConfig, CompileError> {
    let mut config = JailbreakGuardConfig::default();
    let mut detector = JailbreakDetectorConfig::default();

    if let Some(block) = jb.block_threshold {
        // HushSpec expresses thresholds as integer percentages (0-100 in
        // practice). Map that onto the `[0.0, 1.0]` jailbreak-guard space,
        // capping at 1.0 so out-of-range values fail closed rather than
        // produce an unreachable threshold.
        let capped = u32::try_from(block).unwrap_or(0).min(100);
        config.threshold = (capped as f32) / 100.0;
    }

    // `warn_threshold` has no dedicated field on Chio's `JailbreakGuardConfig`;
    // the guard emits advisory signals based on detector-level statistical
    // thresholds. We accept the HushSpec value for schema compatibility but
    // do not wire it in here -- if the warn value would exceed the configured
    // block threshold we conservatively ignore it rather than fail closed,
    // clamping partial overlays on merge.
    let _ = jb.warn_threshold;

    if let Some(max_bytes) = jb.max_input_bytes {
        detector.max_scan_bytes = max_bytes;
    }

    config.detector = detector;
    Ok(config)
}

fn threat_intel_guard_from(
    threat_intel: &ThreatIntelDetection,
    source_dir: Option<&Path>,
) -> Result<SpiderSenseGuard, CompileError> {
    let pattern_db_path = threat_intel.pattern_db.as_deref().ok_or_else(|| {
        CompileError::Invalid(
            "detection.threat_intel.pattern_db is required when enabled".to_string(),
        )
    })?;

    let resolved_pattern_db_path = resolve_policy_asset_path(pattern_db_path, source_dir);

    let pattern_db_json = fs::read_to_string(&resolved_pattern_db_path).map_err(|error| {
        CompileError::Invalid(format!(
            "failed to read detection.threat_intel.pattern_db '{pattern_db_path}' (resolved to '{}'): {error}",
            resolved_pattern_db_path.display()
        ))
    })?;
    let pattern_db = PatternDb::from_json(&pattern_db_json).map_err(|error| {
        CompileError::Invalid(format!(
            "invalid detection.threat_intel.pattern_db '{pattern_db_path}' (resolved to '{}'): {error}",
            resolved_pattern_db_path.display()
        ))
    })?;

    let mut config = SpiderSenseConfig::default();
    if let Some(similarity_threshold) = threat_intel.similarity_threshold {
        config.similarity_threshold = similarity_threshold;
    }
    if let Some(top_k) = threat_intel.top_k {
        config.top_k = top_k;
    }

    SpiderSenseGuard::new(pattern_db, config).map_err(|error| {
        CompileError::Invalid(format!(
            "invalid detection.threat_intel configuration: {error}"
        ))
    })
}

fn resolve_policy_asset_path(path: &str, source_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }

    match source_dir {
        Some(dir) => dir.join(candidate),
        None => candidate,
    }
}

// ---------------------------------------------------------------------------
// Budget-driven guards (12)
// ---------------------------------------------------------------------------

fn compile_budget_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(origins) = &extensions.origins else {
        return Ok(());
    };

    // 12. origin budgets -> AgentVelocityGuard
    //
    // Take the most restrictive `tool_calls` budget across all profiles and
    // use it as the per-agent request ceiling within a 60-second window.
    // This is a coarse mapping -- richer modelling would require a per-
    // origin guard factory -- but it provides a single policy-driven way to
    // exercise the guard type from a HushSpec document.
    let mut tightest_tool_calls: Option<u32> = None;
    for profile in &origins.profiles {
        let Some(budgets) = &profile.budgets else {
            continue;
        };
        if let Some(tool_calls) = budgets.tool_calls {
            let as_u32 = u32::try_from(tool_calls).unwrap_or(u32::MAX);
            tightest_tool_calls = Some(match tightest_tool_calls {
                Some(current) => current.min(as_u32),
                None => as_u32,
            });
        }
    }

    if let Some(limit) = tightest_tool_calls {
        let config = AgentVelocityConfig {
            max_requests_per_agent: Some(limit),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        };
        builder.add(AgentVelocityGuard::new(config));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scope compilation
// ---------------------------------------------------------------------------

/// Build a default ChioScope from the policy's tool_access rules.
///
/// If tool_access has an allow list and can be faithfully represented as an
/// `ChioScope`, each entry becomes a wildcard ToolGrant with `Invoke`
/// permission. Policies that rely on negative matches or other semantics the
/// scope model cannot encode fail closed and emit no default grants.
fn compile_scope(policy: &HushSpec) -> Result<ChioScope, CompileError> {
    let Some(rules) = &policy.rules else {
        return Ok(permissive_scope());
    };

    let Some(ta) = &rules.tool_access else {
        return Ok(permissive_scope());
    };

    if !ta.enabled {
        return Ok(permissive_scope());
    }

    let human_in_loop = rules.human_in_loop.as_ref();

    if ta.default == DefaultAction::Allow {
        if default_allow_has_unrepresentable_selective_confirmation(ta, human_in_loop) {
            return Ok(ChioScope::default());
        }
        if tool_access_can_safely_widen_to_wildcard(ta, human_in_loop) {
            return Ok(permissive_scope());
        }
        if tool_access_can_emit_constrained_wildcard(ta, human_in_loop) {
            return constrained_wildcard_scope(ta, human_in_loop);
        }
        return Ok(ChioScope::default());
    }

    if ta.allow.is_empty() && ta.default == DefaultAction::Block {
        // Block-by-default with no allowlist: empty scope
        return Ok(ChioScope::default());
    }

    if ta.require_workload_identity.is_some() || ta.prefer_workload_identity.is_some() {
        return Ok(ChioScope::default());
    }

    let mut allowed_tool_patterns = Vec::with_capacity(ta.allow.len());
    for tool_pattern in &ta.allow {
        if !confirmation_overlap(tool_pattern, &ta.block)? {
            allowed_tool_patterns.push(tool_pattern);
        }
    }
    if allowed_tool_patterns.is_empty() {
        return Ok(ChioScope::default());
    }

    // Each allowed tool pattern becomes a grant on a wildcard server
    let mut grants = Vec::with_capacity(allowed_tool_patterns.len());
    for tool_pattern in allowed_tool_patterns {
        grants.push(ToolGrant {
            server_id: "*".to_string(),
            tool_name: tool_pattern.clone(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(ta, tool_pattern, human_in_loop)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
    }

    Ok(ChioScope {
        grants,
        ..ChioScope::default()
    })
}

fn permissive_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn constrained_wildcard_scope(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> Result<ChioScope, CompileError> {
    Ok(ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(rule, "*", human_in_loop)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    })
}

fn compile_custom_secret_patterns(rule: &SecretPatternsRule) -> Vec<CustomSecretPattern> {
    rule.patterns
        .iter()
        .map(|pattern| CustomSecretPattern {
            name: pattern.name.clone(),
            pattern: pattern.pattern.clone(),
        })
        .collect()
}

fn compile_output_sanitizer_config(rule: &SecretPatternsRule) -> OutputSanitizerConfig {
    let mut config = OutputSanitizerConfig::default();
    config.denylist.patterns = rule
        .patterns
        .iter()
        .map(|pattern| pattern.pattern.clone())
        .collect();
    config
}

fn tool_access_can_safely_widen_to_wildcard(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    rule.allow.is_empty()
        && rule.block.is_empty()
        && rule.require_confirmation.is_empty()
        && rule.max_args_size.is_none()
        && rule.require_runtime_assurance_tier.is_none()
        && rule.require_workload_identity.is_none()
        && rule.prefer_workload_identity.is_none()
        && !human_in_loop_requires_scope_constraints(human_in_loop)
}

fn default_allow_has_unrepresentable_selective_confirmation(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    confirmation_requires_selective_scope(&rule.require_confirmation)
        || human_in_loop.is_some_and(|rule| {
            rule.enabled && confirmation_requires_selective_scope(&rule.require_confirmation)
        })
}

fn human_in_loop_requires_scope_constraints(human_in_loop: Option<&HumanInLoopRule>) -> bool {
    human_in_loop.is_some_and(|rule| {
        rule.enabled
            && (confirmation_applies_to_all_tools(&rule.require_confirmation)
                || rule.approve_above.is_some())
    })
}

fn confirmation_applies_to_all_tools(patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| pattern == "*")
}

fn confirmation_requires_selective_scope(patterns: &[String]) -> bool {
    !patterns.is_empty() && !confirmation_applies_to_all_tools(patterns)
}

fn tool_access_can_emit_constrained_wildcard(
    rule: &ToolAccessRule,
    human_in_loop: Option<&HumanInLoopRule>,
) -> bool {
    rule.allow.is_empty()
        && rule.block.is_empty()
        && rule.require_workload_identity.is_none()
        && rule.prefer_workload_identity.is_none()
        && (rule.max_args_size.is_some()
            || rule.require_runtime_assurance_tier.is_some()
            || confirmation_applies_to_all_tools(&rule.require_confirmation)
            || human_in_loop_requires_scope_constraints(human_in_loop))
}

fn compile_tool_constraints(
    rule: &ToolAccessRule,
    tool_pattern: &str,
    human_in_loop: Option<&HumanInLoopRule>,
) -> Result<Vec<Constraint>, CompileError> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = rule.max_args_size {
        constraints.push(Constraint::MaxArgsSize(max_args_size));
    }

    // Determine approval threshold. require_confirmation forces threshold=0
    // when it matches the compiled grant. A wildcard grant can only carry
    // confirmation when the source pattern applies to all tools; selective
    // confirmations stay in the policy evaluator instead of being widened.
    let mut approval_threshold: Option<u64> = None;
    if confirmation_matches_compiled_grant(tool_pattern, &rule.require_confirmation)? {
        approval_threshold = Some(0);
    }
    if let Some(hil) = human_in_loop {
        if hil.enabled {
            if confirmation_matches_compiled_grant(tool_pattern, &hil.require_confirmation)? {
                approval_threshold = Some(0);
            } else if approval_threshold.is_none() {
                if let Some(threshold) = hil.approve_above {
                    approval_threshold = Some(threshold);
                }
            }
        }
    }
    if let Some(threshold_units) = approval_threshold {
        constraints.push(Constraint::RequireApprovalAbove { threshold_units });
    }

    if let Some(tier) = rule.require_runtime_assurance_tier {
        constraints.push(Constraint::MinimumRuntimeAssurance(tier));
    }
    Ok(constraints)
}

fn confirmation_matches_compiled_grant(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, CompileError> {
    if tool_pattern == "*" {
        return Ok(confirmation_applies_to_all_tools(confirmation_patterns));
    }
    confirmation_overlap(tool_pattern, confirmation_patterns)
}

/// Translate a `VelocityRule` into optional `VelocityConfig` +
/// `AgentVelocityConfig`. If no invocation / spend / agent / session limit
/// is set, returns `(None, None)` - i.e. the guard is effectively a no-op
/// and no guard is pushed onto the pipeline.
fn compile_velocity_rule(
    rule: &VelocityRule,
) -> (Option<VelocityConfig>, Option<AgentVelocityConfig>) {
    let window_secs = rule.window_secs.max(1);
    let burst_factor = if rule.burst_factor.is_finite() && rule.burst_factor > 0.0 {
        rule.burst_factor
    } else {
        1.0
    };

    let velocity_cfg =
        if rule.max_invocations_per_window.is_some() || rule.max_spend_per_window.is_some() {
            Some(VelocityConfig {
                max_invocations_per_window: rule.max_invocations_per_window,
                max_spend_per_window: rule.max_spend_per_window,
                window_secs,
                burst_factor,
            })
        } else {
            None
        };

    let agent_cfg =
        if rule.max_requests_per_agent.is_some() || rule.max_requests_per_session.is_some() {
            Some(AgentVelocityConfig {
                max_requests_per_agent: rule.max_requests_per_agent,
                max_requests_per_session: rule.max_requests_per_session,
                window_secs,
                burst_factor,
            })
        } else {
            None
        };

    (velocity_cfg, agent_cfg)
}

fn confirmation_overlap(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, CompileError> {
    for pattern in confirmation_patterns {
        if tool_patterns_overlap(tool_pattern, pattern)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn tool_patterns_overlap(left: &str, right: &str) -> Result<bool, CompileError> {
    if left == "*" || right == "*" {
        return Ok(true);
    }
    if !contains_wildcards(left) && !contains_wildcards(right) {
        return Ok(left == right);
    }
    if glob_matches(left, right)? || glob_matches(right, left)? {
        return Ok(true);
    }
    let left_prefix = literal_prefix(left);
    let right_prefix = literal_prefix(right);
    Ok(left_prefix.starts_with(&right_prefix) || right_prefix.starts_with(&left_prefix))
}

fn contains_wildcards(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn literal_prefix(pattern: &str) -> String {
    pattern
        .chars()
        .take_while(|ch| *ch != '*' && *ch != '?')
        .collect()
}

fn glob_matches(pattern: &str, target: &str) -> Result<bool, CompileError> {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    crate::regex_safety::compile_generated_policy_regex(&regex, "compiler glob pattern")
        .map(|compiled| compiled.is_match(target))
        .map_err(|error| CompileError::Invalid(format!("invalid policy glob pattern: {error}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::RuntimeAssuranceTier;
    use std::path::PathBuf;

    fn sample_threat_intel_pattern_db() -> &'static str {
        r#"
[
  {
    "id": "known-prompt-injection",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "Known malicious prompt embedding",
    "embedding": [1.0, 0.0, 0.0]
  }
]
"#
    }

    fn write_temp_threat_intel_pattern_db() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "chio-policy-threat-intel-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, sample_threat_intel_pattern_db()).unwrap();
        path
    }

    #[test]
    fn compile_empty_policy() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
name: empty
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 0);
        assert!(compiled.guard_names.is_empty());
        assert_eq!(compiled.default_scope.grants.len(), 1);
        assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
    }

    #[test]
    fn compile_rejects_validation_errors_before_materializing_policy() {
        let spec = HushSpec::parse(
            r#"
hushspec: "9.9.9"
rules:
  tool_access:
    enabled: true
    allow: [read_file]
    default: block
    max_args_size: 0
"#,
        )
        .unwrap();

        let error = match compile_policy(&spec) {
            Ok(_) => panic!("invalid policy should fail compilation"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("HushSpec validation failed"),
            "unexpected error: {error}"
        );
        assert!(
            message.contains("unsupported hushspec version"),
            "unexpected error: {error}"
        );
        assert!(
            message.contains("rules.tool_access.max_args_size must be >= 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn compile_forbidden_paths_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.env"
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 1);
        assert_eq!(compiled.guard_names, vec!["forbidden-path".to_string()]);
    }

    #[test]
    fn compile_egress_adds_internal_network_companion() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["*.github.com"]
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 2);
        assert_eq!(
            compiled.guard_names,
            vec![
                "egress-allowlist".to_string(),
                "internal-network".to_string()
            ]
        );
    }

    #[test]
    fn compile_egress_rejects_invalid_globs() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["["]
"#,
        )
        .unwrap();

        let error = match compile_policy(&spec) {
            Ok(_) => panic!("invalid egress patterns should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid egress allowlist pattern"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn compile_computer_use_preserves_empty_allowed_actions() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []
"#,
        )
        .unwrap();
        let rule = spec.rules.as_ref().unwrap().computer_use.as_ref().unwrap();
        let config = compile_computer_use_rule(rule);
        assert!(config.allowed_action_types.is_empty());
        assert_eq!(config.mode, EnforcementMode::FailClosed);
    }

    #[test]
    fn compile_input_injection_preserves_empty_allowed_types() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  input_injection:
    enabled: true
    allowed_types: []
"#,
        )
        .unwrap();
        let rule = spec
            .rules
            .as_ref()
            .unwrap()
            .input_injection
            .as_ref()
            .unwrap();
        let config = compile_input_injection_rule(rule);
        assert!(config.allowed_input_types.is_empty());
    }

    #[test]
    fn compile_browser_automation_preserves_empty_allowed_verbs() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    allowed_verbs: []
"#,
        )
        .unwrap();
        let rule = spec
            .rules
            .as_ref()
            .unwrap()
            .browser_automation
            .as_ref()
            .unwrap();
        let config = compile_browser_automation_rule(rule);
        assert!(config.allowed_verbs.is_empty());
    }

    #[test]
    fn compile_code_execution_preserves_empty_module_denylist() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    module_denylist: []
"#,
        )
        .unwrap();
        let rule = spec
            .rules
            .as_ref()
            .unwrap()
            .code_execution
            .as_ref()
            .unwrap();
        let config = compile_code_execution_rule(rule);
        assert!(config.module_denylist.is_empty());
    }

    #[test]
    fn compile_patch_integrity_rejects_invalid_regex() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  patch_integrity:
    enabled: true
    forbidden_patterns: ["["]
"#,
        )
        .unwrap();

        let error = match compile_policy(&spec) {
            Ok(_) => panic!("invalid patch integrity regex should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("rules.patch_integrity.forbidden_patterns[0]"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn compile_secret_patterns_use_post_invocation_sanitizer_only() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 1);
        assert_eq!(compiled.post_invocation.len(), 1);
        assert_eq!(compiled.guard_names, vec!["secret-leak".to_string()]);
        let outcome = compiled.post_invocation.evaluate_with_evidence(
            "read_file",
            &serde_json::json!({
                "access_key": "AKIA1234567890ABCDEF"
            }),
        );
        assert!(matches!(
            outcome.verdict,
            chio_kernel::PostInvocationVerdict::Redact(_)
        ));
    }

    #[test]
    fn compile_secret_patterns_preserves_custom_denylist_patterns() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: internal-token
        pattern: "INTERNAL-[0-9]{4}"
        severity: critical
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));
        let rule = spec
            .rules
            .as_ref()
            .unwrap_or_else(|| unreachable!("test policy should contain rules"))
            .secret_patterns
            .as_ref()
            .unwrap_or_else(|| unreachable!("test policy should contain secret patterns"));

        let config = compile_output_sanitizer_config(rule);

        assert_eq!(config.denylist.patterns, vec!["INTERNAL-[0-9]{4}"]);
    }

    #[test]
    fn compile_detection_prompt_injection_adds_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
      max_scan_bytes: 100000
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["prompt-injection".to_string()]);
    }

    #[test]
    fn compile_detection_jailbreak_adds_guard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 30
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["jailbreak".to_string()]);
    }

    #[test]
    fn compile_detection_threat_intel_adds_guard() {
        let pattern_db = write_temp_threat_intel_pattern_db();
        let spec = HushSpec::parse(&format!(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
"#,
            pattern_db.display()
        ))
        .unwrap();

        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["spider-sense".to_string()]);

        let _ = std::fs::remove_file(pattern_db);
    }

    #[test]
    fn compile_detection_threat_intel_resolves_relative_pattern_db_against_source() {
        let policy_dir = std::env::temp_dir().join(format!(
            "chio-policy-threat-intel-dir-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&policy_dir).unwrap();
        let pattern_db = policy_dir.join("pattern-db.json");
        std::fs::write(&pattern_db, sample_threat_intel_pattern_db()).unwrap();
        let policy_path = policy_dir.join("policy.yaml");
        std::fs::write(&policy_path, "hushspec: \"0.1.0\"\n").unwrap();

        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
      similarity_threshold: 0.8
      top_k: 1
"#,
        )
        .unwrap();

        let compiled = compile_policy_with_source(&spec, Some(&policy_path)).unwrap();
        assert_eq!(compiled.guard_names, vec!["spider-sense".to_string()]);

        let _ = std::fs::remove_file(pattern_db);
        let _ = std::fs::remove_file(policy_path);
        let _ = std::fs::remove_dir(policy_dir);
    }

    #[test]
    fn compile_origin_budget_adds_agent_velocity() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 120
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guard_names, vec!["agent-velocity".to_string()]);
    }

    #[test]
    fn compile_all_12_guard_types() {
        let pattern_db = write_temp_threat_intel_pattern_db();
        let spec = HushSpec::parse(&format!(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**"]
  path_allowlist:
    enabled: true
    read: ["/app/**"]
  shell_commands:
    enabled: true
    forbidden_patterns: ["rm -rf /"]
  egress:
    enabled: true
    allow: ["*.example.com"]
    default: block
  tool_access:
    enabled: true
    allow: [read_file]
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{{16}}"
        severity: critical
  patch_integrity:
    enabled: true
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 70
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 1000
"#,
            pattern_db.display()
        ))
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        let expected: std::collections::HashSet<&str> = [
            "forbidden-path",
            "shell-command",
            "egress-allowlist",
            "internal-network",
            "mcp-tool",
            "secret-leak",
            "patch-integrity",
            "path-allowlist",
            "prompt-injection",
            "jailbreak",
            "spider-sense",
            "agent-velocity",
        ]
        .into_iter()
        .collect();

        let actual: std::collections::HashSet<&str> =
            compiled.guard_names.iter().map(String::as_str).collect();

        assert_eq!(
            actual, expected,
            "all 12 guard types should compile; got {actual:?}"
        );
        assert_eq!(compiled.guards.len(), 12);

        let _ = std::fs::remove_file(pattern_db);
    }

    #[test]
    fn compile_disabled_guards_excluded() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: false
  shell_commands:
    enabled: false
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.guards.len(), 0);
    }

    #[test]
    fn compile_tool_access_scope() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file, write_file, shell_exec]
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.default_scope.grants.len(), 3);
        assert_eq!(compiled.default_scope.grants[0].tool_name, "read_file");
        assert_eq!(compiled.default_scope.grants[1].tool_name, "write_file");
        assert_eq!(compiled.default_scope.grants[2].tool_name, "shell_exec");
    }

    #[test]
    fn compile_tool_access_scope_omits_only_allow_entries_overlapping_block() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file, shell_exec]
    block: [shell_exec]
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.default_scope.grants.len(), 1);
        assert_eq!(compiled.default_scope.grants[0].tool_name, "read_file");
    }

    #[test]
    fn compile_tool_access_scope_preserves_representable_security_constraints() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [write_file]
    require_confirmation: [write_*]
    max_args_size: 2048
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert_eq!(compiled.default_scope.grants.len(), 1);
        assert_eq!(
            compiled.default_scope.grants[0].constraints,
            vec![
                Constraint::MaxArgsSize(2048),
                Constraint::RequireApprovalAbove { threshold_units: 0 }
            ]
        );
    }

    #[test]
    fn compile_tool_access_default_allow_selective_confirmation_fails_closed() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_confirmation: [git_push]
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert!(compiled.default_scope.grants.is_empty());
    }

    #[test]
    fn compile_tool_access_default_allow_global_confirmation_emits_constrained_wildcard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_confirmation: ["*"]
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert_eq!(compiled.default_scope.grants.len(), 1);
        let grant = &compiled.default_scope.grants[0];
        assert_eq!(grant.server_id, "*");
        assert_eq!(grant.tool_name, "*");
        assert_eq!(
            grant.constraints,
            vec![Constraint::RequireApprovalAbove { threshold_units: 0 }]
        );
    }

    #[test]
    fn compile_tool_access_default_allow_max_args_size_emits_constrained_wildcard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    max_args_size: 2048
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert_eq!(compiled.default_scope.grants.len(), 1);
        let grant = &compiled.default_scope.grants[0];
        assert_eq!(grant.server_id, "*");
        assert_eq!(grant.tool_name, "*");
        assert_eq!(grant.constraints, vec![Constraint::MaxArgsSize(2048)]);
    }

    #[test]
    fn compile_tool_access_default_allow_max_args_size_with_selective_confirmation_fails_closed() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    max_args_size: 2048
    require_confirmation: [git_push]
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert!(compiled.default_scope.grants.is_empty());
    }

    #[test]
    fn compile_tool_access_default_allow_runtime_assurance_emits_constrained_wildcard() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_runtime_assurance_tier: attested
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert_eq!(compiled.default_scope.grants.len(), 1);
        let grant = &compiled.default_scope.grants[0];
        assert_eq!(grant.server_id, "*");
        assert_eq!(grant.tool_name, "*");
        assert_eq!(
            grant.constraints,
            vec![Constraint::MinimumRuntimeAssurance(
                RuntimeAssuranceTier::Attested
            )]
        );
    }

    #[test]
    fn compile_tool_access_default_allow_runtime_assurance_preference_stays_warning_only() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    prefer_runtime_assurance_tier: attested
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert_eq!(compiled.default_scope.grants.len(), 1);
        let grant = &compiled.default_scope.grants[0];
        assert_eq!(grant.server_id, "*");
        assert_eq!(grant.tool_name, "*");
        assert!(grant.constraints.is_empty());
    }

    #[test]
    fn compile_tool_access_allow_runtime_assurance_preference_does_not_harden_grant() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [payments.charge]
    prefer_runtime_assurance_tier: attested
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();

        assert_eq!(compiled.default_scope.grants.len(), 1);
        let grant = &compiled.default_scope.grants[0];
        assert_eq!(grant.server_id, "*");
        assert_eq!(grant.tool_name, "payments.charge");
        assert!(grant.constraints.is_empty());
    }

    #[test]
    fn exact_confirmation_patterns_do_not_overlap_different_tools() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [payments.charge]
    default: block
  human_in_loop:
    enabled: true
    require_confirmation: [payments.refund]
    approve_above: 15000
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));
        let compiled = compile_policy(&spec)
            .unwrap_or_else(|error| unreachable!("compile should pass: {error}"));

        assert_eq!(compiled.default_scope.grants.len(), 1);
        assert_eq!(
            compiled.default_scope.grants[0].constraints,
            vec![Constraint::RequireApprovalAbove {
                threshold_units: 15000
            }]
        );
    }

    #[test]
    fn compile_tool_access_rejects_oversized_confirmation_globs() {
        let oversized_glob = "*".repeat(600_000);
        let spec = HushSpec::parse(&format!(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file]
    require_confirmation: ["{oversized_glob}"]
    default: block
"#
        ))
        .unwrap();

        let error = match compile_policy(&spec) {
            Ok(_) => panic!("expected oversized glob to fail compilation"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CompileError::Invalid(ref message) if message.contains("invalid policy glob pattern")),
            "unexpected compile error: {error:?}"
        );
    }

    #[test]
    fn compile_tool_access_default_allow_with_security_overrides_fails_closed() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    block: [shell_exec]
    require_confirmation: [git_push]
    max_args_size: 2048
    default: allow
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert!(compiled.default_scope.grants.is_empty());
    }

    #[test]
    fn compile_block_default_empty_allow_produces_empty_scope() {
        let spec = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
"#,
        )
        .unwrap();
        let compiled = compile_policy(&spec).unwrap();
        assert!(compiled.default_scope.grants.is_empty());
    }

    #[test]
    fn prompt_level_ordering() {
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::Safe)
                < prompt_level_to_score_threshold(DetectionLevel::Suspicious)
        );
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::Suspicious)
                < prompt_level_to_score_threshold(DetectionLevel::High)
        );
        assert!(
            prompt_level_to_score_threshold(DetectionLevel::High)
                <= prompt_level_to_score_threshold(DetectionLevel::Critical)
        );
    }

    #[test]
    fn jailbreak_block_threshold_maps_to_zero_one() {
        let jb = JailbreakDetection {
            enabled: Some(true),
            block_threshold: Some(70),
            warn_threshold: Some(30),
            max_input_bytes: Some(100_000),
        };
        let cfg = jailbreak_config_from(&jb).unwrap();
        assert!((cfg.threshold - 0.70).abs() < f32::EPSILON);
        assert_eq!(cfg.detector.max_scan_bytes, 100_000);
    }

    #[test]
    fn jailbreak_oversize_threshold_clamped() {
        let jb = JailbreakDetection {
            enabled: Some(true),
            block_threshold: Some(200),
            warn_threshold: None,
            max_input_bytes: None,
        };
        let cfg = jailbreak_config_from(&jb).unwrap();
        assert!(cfg.threshold <= 1.0 + f32::EPSILON);
    }
}
