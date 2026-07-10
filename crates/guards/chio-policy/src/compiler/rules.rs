use super::{CompileError, PipelineBuilder};
use crate::models::{
    ComputerUseMode, ComputerUseRule, DefaultAction, HushSpec, InputInjectionRule,
    RemoteDesktopChannelsRule, SecretPatternsRule, VelocityRule,
};

use chio_guards::{
    agent_velocity::AgentVelocityConfig,
    computer_use::{ComputerUseConfig, EnforcementMode},
    input_injection::InputInjectionCapabilityConfig,
    post_invocation::SanitizerHook,
    remote_desktop::RemoteDesktopSideChannelConfig,
    response_sanitization::OutputSanitizerConfig,
    secret_leak::CustomSecretPattern,
    velocity::VelocityConfig,
    AgentVelocityGuard, ComputerUseGuard, EgressAllowlistGuard, ForbiddenPathGuard,
    InputInjectionCapabilityGuard, InternalNetworkGuard, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, PostInvocationPipeline, RemoteDesktopSideChannelGuard, SecretLeakGuard,
    ShellCommandGuard, VelocityGuard,
};

// ---------------------------------------------------------------------------
// Rule-driven guards (1-7 + InternalNetworkGuard)
// ---------------------------------------------------------------------------

pub(super) fn compile_rule_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
    post_invocation: &mut PostInvocationPipeline,
    memory_budget: &chio_kernel::MemoryBudgetConfig,
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
                // Thread the CONFIGURED process memory budget so a lowered
                // `velocity_bucket_cap` tightens this long-lived collection instead
                // of silently using the default.
                builder.add(VelocityGuard::from_memory_budget(cfg, memory_budget));
            }
            if let Some(cfg) = agent_cfg {
                // Thread the CONFIGURED process memory budget so a lowered
                // `velocity_bucket_cap` bounds this guard's agent/session bucket
                // maps too.
                builder.add(AgentVelocityGuard::from_memory_budget(cfg, memory_budget));
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

pub(super) fn compile_computer_use_rule(rule: &ComputerUseRule) -> ComputerUseConfig {
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
    // clipboard / file_transfer / audio / drive_mapping. It does not model
    // session_share, printing, or transfer size, so those stay at the guard's
    // defaults (enabled / no limit).
    RemoteDesktopSideChannelConfig {
        enabled: true,
        clipboard_enabled: rule.clipboard,
        file_transfer_enabled: rule.file_transfer,
        audio_enabled: rule.audio,
        drive_mapping_enabled: rule.drive_mapping,
        ..RemoteDesktopSideChannelConfig::default()
    }
}

pub(super) fn compile_input_injection_rule(
    rule: &InputInjectionRule,
) -> InputInjectionCapabilityConfig {
    InputInjectionCapabilityConfig {
        enabled: true,
        allowed_input_types: rule.allowed_types.clone(),
        require_postcondition_probe: rule.require_postcondition_probe,
        ..InputInjectionCapabilityConfig::default()
    }
}

pub(super) fn compile_browser_automation_rule(
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

pub(super) fn compile_code_execution_rule(
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

fn compile_custom_secret_patterns(rule: &SecretPatternsRule) -> Vec<CustomSecretPattern> {
    rule.patterns
        .iter()
        .map(|pattern| CustomSecretPattern {
            name: pattern.name.clone(),
            pattern: pattern.pattern.clone(),
        })
        .collect()
}

pub(super) fn compile_output_sanitizer_config(rule: &SecretPatternsRule) -> OutputSanitizerConfig {
    let mut config = OutputSanitizerConfig::default();
    config.denylist.patterns = rule
        .patterns
        .iter()
        .map(|pattern| pattern.pattern.clone())
        .collect();
    config
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
