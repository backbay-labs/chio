//! HushSpec policy merge/inheritance.
//!
//! Ported from the HushSpec reference implementation. Merges a child policy
//! into a base policy using one of three strategies: replace, merge, or
//! deep merge (default).

use crate::models::{
    ChioExtension, DetectionExtension, Extensions, HushSpec, JailbreakDetection, MergeStrategy,
    OriginsExtension, PostureExtension, PromptInjectionDetection, ReputationExtension,
    ReputationScoringConfig, ReputationWeights, Rules, ThreatIntelDetection,
};

#[must_use = "merged spec is returned, not applied in place"]
pub fn merge(base: &HushSpec, child: &HushSpec) -> HushSpec {
    let strategy = child.merge_strategy.unwrap_or_default();
    match strategy {
        MergeStrategy::Replace => {
            let mut result = child.clone();
            result.extends = None;
            result
        }
        MergeStrategy::Merge => merge_with_strategy(base, child, false),
        MergeStrategy::DeepMerge => merge_with_strategy(base, child, true),
    }
}

fn merge_with_strategy(base: &HushSpec, child: &HushSpec, deep: bool) -> HushSpec {
    HushSpec {
        hushspec: child.hushspec.clone(),
        name: child.name.clone().or_else(|| base.name.clone()),
        description: child
            .description
            .clone()
            .or_else(|| base.description.clone()),
        extends: None,
        merge_strategy: child.merge_strategy,
        rules: merge_rules(&base.rules, &child.rules),
        extensions: if deep {
            merge_extensions_deep(&base.extensions, &child.extensions)
        } else {
            merge_extensions_merge(&base.extensions, &child.extensions)
        },
        metadata: child.metadata.clone().or_else(|| base.metadata.clone()),
    }
}

fn merge_rules(base: &Option<Rules>, child: &Option<Rules>) -> Option<Rules> {
    match (base, child) {
        (_, Some(child_rules)) => {
            let base_rules = base.as_ref().cloned().unwrap_or_default();
            Some(Rules {
                forbidden_paths: child_rules
                    .forbidden_paths
                    .clone()
                    .or(base_rules.forbidden_paths),
                path_allowlist: child_rules
                    .path_allowlist
                    .clone()
                    .or(base_rules.path_allowlist),
                egress: child_rules.egress.clone().or(base_rules.egress),
                secret_patterns: child_rules
                    .secret_patterns
                    .clone()
                    .or(base_rules.secret_patterns),
                patch_integrity: child_rules
                    .patch_integrity
                    .clone()
                    .or(base_rules.patch_integrity),
                shell_commands: child_rules
                    .shell_commands
                    .clone()
                    .or(base_rules.shell_commands),
                tool_access: child_rules.tool_access.clone().or(base_rules.tool_access),
                computer_use: child_rules.computer_use.clone().or(base_rules.computer_use),
                remote_desktop_channels: child_rules
                    .remote_desktop_channels
                    .clone()
                    .or(base_rules.remote_desktop_channels),
                input_injection: child_rules
                    .input_injection
                    .clone()
                    .or(base_rules.input_injection),
                browser_automation: child_rules
                    .browser_automation
                    .clone()
                    .or(base_rules.browser_automation),
                code_execution: child_rules
                    .code_execution
                    .clone()
                    .or(base_rules.code_execution),
                velocity: child_rules.velocity.clone().or(base_rules.velocity),
                human_in_loop: child_rules
                    .human_in_loop
                    .clone()
                    .or(base_rules.human_in_loop),
            })
        }
        (Some(base_rules), None) => Some(base_rules.clone()),
        (None, None) => None,
    }
}

fn merge_extensions_merge(
    base: &Option<Extensions>,
    child: &Option<Extensions>,
) -> Option<Extensions> {
    match (base, child) {
        (_, Some(child_ext)) => {
            let base_ext = base.as_ref().cloned().unwrap_or_default();
            Some(Extensions {
                posture: child_ext.posture.clone().or(base_ext.posture),
                origins: child_ext.origins.clone().or(base_ext.origins),
                detection: child_ext.detection.clone().or(base_ext.detection),
                reputation: child_ext.reputation.clone().or(base_ext.reputation),
                runtime_assurance: child_ext
                    .runtime_assurance
                    .clone()
                    .or(base_ext.runtime_assurance),
                chio: child_ext.chio.clone().or(base_ext.chio),
            })
        }
        (Some(base_ext), None) => Some(base_ext.clone()),
        (None, None) => None,
    }
}

fn merge_extensions_deep(
    base: &Option<Extensions>,
    child: &Option<Extensions>,
) -> Option<Extensions> {
    match (base, child) {
        (_, Some(child_ext)) => {
            let base_ext = base.as_ref().cloned().unwrap_or_default();
            Some(Extensions {
                posture: merge_posture(&base_ext.posture, &child_ext.posture),
                origins: merge_origins(&base_ext.origins, &child_ext.origins),
                detection: merge_detection(&base_ext.detection, &child_ext.detection),
                reputation: merge_reputation(&base_ext.reputation, &child_ext.reputation),
                runtime_assurance: child_ext
                    .runtime_assurance
                    .clone()
                    .or(base_ext.runtime_assurance),
                chio: merge_chio(&base_ext.chio, &child_ext.chio),
            })
        }
        (Some(base_ext), None) => Some(base_ext.clone()),
        (None, None) => None,
    }
}

fn merge_posture(
    base: &Option<PostureExtension>,
    child: &Option<PostureExtension>,
) -> Option<PostureExtension> {
    match (base, child) {
        (_, Some(child_posture)) => {
            if let Some(base_posture) = base {
                let mut states = base_posture.states.clone();
                for (name, state) in &child_posture.states {
                    states.insert(name.clone(), state.clone());
                }
                Some(PostureExtension {
                    initial: child_posture.initial.clone(),
                    states,
                    transitions: child_posture.transitions.clone(),
                })
            } else {
                Some(child_posture.clone())
            }
        }
        (Some(base_posture), None) => Some(base_posture.clone()),
        (None, None) => None,
    }
}

fn merge_origins(
    base: &Option<OriginsExtension>,
    child: &Option<OriginsExtension>,
) -> Option<OriginsExtension> {
    match (base, child) {
        (_, Some(child_origins)) => {
            if let Some(base_origins) = base {
                let mut merged_profiles = base_origins.profiles.clone();
                for child_profile in &child_origins.profiles {
                    if let Some(pos) = merged_profiles
                        .iter()
                        .position(|profile| profile.id == child_profile.id)
                    {
                        merged_profiles[pos] = child_profile.clone();
                    } else {
                        merged_profiles.push(child_profile.clone());
                    }
                }
                Some(OriginsExtension {
                    default_behavior: child_origins
                        .default_behavior
                        .or(base_origins.default_behavior),
                    profiles: merged_profiles,
                })
            } else {
                Some(child_origins.clone())
            }
        }
        (Some(base_origins), None) => Some(base_origins.clone()),
        (None, None) => None,
    }
}

fn merge_detection(
    base: &Option<DetectionExtension>,
    child: &Option<DetectionExtension>,
) -> Option<DetectionExtension> {
    match (base, child) {
        (_, Some(child_detection)) => {
            if let Some(base_detection) = base {
                Some(DetectionExtension {
                    prompt_injection: merge_prompt_injection(
                        &base_detection.prompt_injection,
                        &child_detection.prompt_injection,
                    ),
                    jailbreak: merge_jailbreak(
                        &base_detection.jailbreak,
                        &child_detection.jailbreak,
                    ),
                    threat_intel: merge_threat_intel(
                        &base_detection.threat_intel,
                        &child_detection.threat_intel,
                    ),
                })
            } else {
                Some(child_detection.clone())
            }
        }
        (Some(base_detection), None) => Some(base_detection.clone()),
        (None, None) => None,
    }
}

fn merge_reputation(
    base: &Option<ReputationExtension>,
    child: &Option<ReputationExtension>,
) -> Option<ReputationExtension> {
    match (base, child) {
        (_, Some(child_reputation)) => {
            if let Some(base_reputation) = base {
                let mut tiers = base_reputation.tiers.clone();
                for (name, tier) in &child_reputation.tiers {
                    tiers.insert(name.clone(), tier.clone());
                }
                Some(ReputationExtension {
                    scoring: merge_reputation_scoring(
                        &base_reputation.scoring,
                        &child_reputation.scoring,
                    ),
                    tiers,
                })
            } else {
                Some(child_reputation.clone())
            }
        }
        (Some(base_reputation), None) => Some(base_reputation.clone()),
        (None, None) => None,
    }
}

fn merge_reputation_scoring(
    base: &Option<ReputationScoringConfig>,
    child: &Option<ReputationScoringConfig>,
) -> Option<ReputationScoringConfig> {
    match (base, child) {
        (_, Some(child_scoring)) => {
            if let Some(base_scoring) = base {
                Some(ReputationScoringConfig {
                    weights: merge_reputation_weights(
                        &base_scoring.weights,
                        &child_scoring.weights,
                    ),
                    temporal_decay_half_life_days: child_scoring
                        .temporal_decay_half_life_days
                        .or(base_scoring.temporal_decay_half_life_days),
                    probationary_receipt_count: child_scoring
                        .probationary_receipt_count
                        .or(base_scoring.probationary_receipt_count),
                    probationary_score_ceiling: child_scoring
                        .probationary_score_ceiling
                        .or(base_scoring.probationary_score_ceiling),
                    probationary_min_days: child_scoring
                        .probationary_min_days
                        .or(base_scoring.probationary_min_days),
                })
            } else {
                Some(child_scoring.clone())
            }
        }
        (Some(base_scoring), None) => Some(base_scoring.clone()),
        (None, None) => None,
    }
}

fn merge_reputation_weights(
    base: &Option<ReputationWeights>,
    child: &Option<ReputationWeights>,
) -> Option<ReputationWeights> {
    match (base, child) {
        (_, Some(child_weights)) => {
            if let Some(base_weights) = base {
                Some(ReputationWeights {
                    boundary_pressure: child_weights
                        .boundary_pressure
                        .or(base_weights.boundary_pressure),
                    resource_stewardship: child_weights
                        .resource_stewardship
                        .or(base_weights.resource_stewardship),
                    least_privilege: child_weights
                        .least_privilege
                        .or(base_weights.least_privilege),
                    history_depth: child_weights.history_depth.or(base_weights.history_depth),
                    tool_diversity: child_weights.tool_diversity.or(base_weights.tool_diversity),
                    delegation_hygiene: child_weights
                        .delegation_hygiene
                        .or(base_weights.delegation_hygiene),
                    reliability: child_weights.reliability.or(base_weights.reliability),
                    incident_correlation: child_weights
                        .incident_correlation
                        .or(base_weights.incident_correlation),
                })
            } else {
                Some(child_weights.clone())
            }
        }
        (Some(base_weights), None) => Some(base_weights.clone()),
        (None, None) => None,
    }
}

fn merge_prompt_injection(
    base: &Option<PromptInjectionDetection>,
    child: &Option<PromptInjectionDetection>,
) -> Option<PromptInjectionDetection> {
    match (base, child) {
        (_, Some(child_prompt)) => {
            if let Some(base_prompt) = base {
                Some(PromptInjectionDetection {
                    enabled: child_prompt.enabled.or(base_prompt.enabled),
                    warn_at_or_above: child_prompt
                        .warn_at_or_above
                        .or(base_prompt.warn_at_or_above),
                    block_at_or_above: child_prompt
                        .block_at_or_above
                        .or(base_prompt.block_at_or_above),
                    max_scan_bytes: child_prompt.max_scan_bytes.or(base_prompt.max_scan_bytes),
                })
            } else {
                Some(child_prompt.clone())
            }
        }
        (Some(base_prompt), None) => Some(base_prompt.clone()),
        (None, None) => None,
    }
}

fn merge_jailbreak(
    base: &Option<JailbreakDetection>,
    child: &Option<JailbreakDetection>,
) -> Option<JailbreakDetection> {
    match (base, child) {
        (_, Some(child_jailbreak)) => {
            if let Some(base_jailbreak) = base {
                Some(JailbreakDetection {
                    enabled: child_jailbreak.enabled.or(base_jailbreak.enabled),
                    block_threshold: child_jailbreak
                        .block_threshold
                        .or(base_jailbreak.block_threshold),
                    warn_threshold: child_jailbreak
                        .warn_threshold
                        .or(base_jailbreak.warn_threshold),
                    max_input_bytes: child_jailbreak
                        .max_input_bytes
                        .or(base_jailbreak.max_input_bytes),
                })
            } else {
                Some(child_jailbreak.clone())
            }
        }
        (Some(base_jailbreak), None) => Some(base_jailbreak.clone()),
        (None, None) => None,
    }
}

fn merge_threat_intel(
    base: &Option<ThreatIntelDetection>,
    child: &Option<ThreatIntelDetection>,
) -> Option<ThreatIntelDetection> {
    match (base, child) {
        (_, Some(child_threat_intel)) => {
            if let Some(base_threat_intel) = base {
                Some(ThreatIntelDetection {
                    enabled: child_threat_intel.enabled.or(base_threat_intel.enabled),
                    pattern_db: child_threat_intel
                        .pattern_db
                        .clone()
                        .or_else(|| base_threat_intel.pattern_db.clone()),
                    similarity_threshold: child_threat_intel
                        .similarity_threshold
                        .or(base_threat_intel.similarity_threshold),
                    top_k: child_threat_intel.top_k.or(base_threat_intel.top_k),
                })
            } else {
                Some(child_threat_intel.clone())
            }
        }
        (Some(base_threat_intel), None) => Some(base_threat_intel.clone()),
        (None, None) => None,
    }
}

fn merge_chio(
    base: &Option<ChioExtension>,
    child: &Option<ChioExtension>,
) -> Option<ChioExtension> {
    match (base, child) {
        (_, Some(child_chio)) => {
            if let Some(base_chio) = base {
                Some(ChioExtension {
                    market_hours: child_chio
                        .market_hours
                        .clone()
                        .or_else(|| base_chio.market_hours.clone()),
                    signing: child_chio
                        .signing
                        .clone()
                        .or_else(|| base_chio.signing.clone()),
                    k8s_namespaces: child_chio
                        .k8s_namespaces
                        .clone()
                        .or_else(|| base_chio.k8s_namespaces.clone()),
                    rollback: child_chio
                        .rollback
                        .clone()
                        .or_else(|| base_chio.rollback.clone()),
                    human_in_loop: child_chio
                        .human_in_loop
                        .clone()
                        .or_else(|| base_chio.human_in_loop.clone()),
                })
            } else {
                Some(child_chio.clone())
            }
        }
        (Some(base_chio), None) => Some(base_chio.clone()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DefaultAction, DetectionLevel, EgressRule, ForbiddenPathsRule, OriginProfile, PostureState,
        PostureTransition, ReputationTier, ReputationTierScope, RuntimeAssuranceExtension,
        RuntimeAssuranceVerifierRule, ToolAccessRule, TransitionTrigger,
    };
    use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
    use std::collections::BTreeMap;

    fn sample_posture_state(label: &str) -> PostureState {
        PostureState {
            description: Some(label.to_string()),
            capabilities: vec![label.to_string()],
            budgets: BTreeMap::new(),
        }
    }

    fn sample_profile(id: &str, explanation: &str) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: None,
            posture: Some(id.to_string()),
            tool_access: None,
            egress: None,
            data: None,
            budgets: None,
            bridge: None,
            explanation: Some(explanation.to_string()),
        }
    }

    fn sample_scope(ttl_seconds: u64) -> ReputationTierScope {
        ReputationTierScope {
            operations: vec!["tool_call".to_string()],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            max_delegation_depth: None,
            ttl_seconds,
            constraints_required: None,
        }
    }

    fn sample_tier(ttl_seconds: u64) -> ReputationTier {
        ReputationTier {
            score_range: [0.0, 1.0],
            max_scope: sample_scope(ttl_seconds),
            promotion: None,
            demotion: None,
        }
    }

    fn sample_verifier(name: &str) -> RuntimeAssuranceVerifierRule {
        RuntimeAssuranceVerifierRule {
            schema: format!("{name}.schema"),
            verifier: name.to_string(),
            effective_tier: RuntimeAssuranceTier::Attested,
            verifier_family: None,
            max_evidence_age_seconds: Some(60),
            allowed_attestation_types: vec!["quote".to_string()],
            required_assertions: BTreeMap::new(),
        }
    }

    #[test]
    fn replace_strategy_discards_base_fields_and_extends() {
        let base = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("base".to_string()),
            description: Some("base description".to_string()),
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                forbidden_paths: Some(ForbiddenPathsRule {
                    enabled: true,
                    patterns: vec!["/etc".to_string()],
                    exceptions: Vec::new(),
                }),
                ..Rules::default()
            }),
            extensions: None,
            metadata: None,
        };
        let child = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("child".to_string()),
            description: None,
            extends: Some("base.yaml".to_string()),
            merge_strategy: Some(MergeStrategy::Replace),
            rules: None,
            extensions: None,
            metadata: None,
        };

        let merged = merge(&base, &child);
        assert_eq!(merged.name.as_deref(), Some("child"));
        assert_eq!(merged.description, None);
        assert_eq!(merged.extends, None);
        assert_eq!(merged.rules, None);
    }

    #[test]
    fn merge_rules_and_slot_level_extensions_preserve_base_fallbacks() {
        let base_rules = Rules {
            forbidden_paths: Some(ForbiddenPathsRule {
                enabled: true,
                patterns: vec!["/etc".to_string()],
                exceptions: Vec::new(),
            }),
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: vec!["mail.send".to_string()],
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Allow,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        };
        let child_rules = Rules {
            egress: Some(EgressRule {
                enabled: true,
                allow: vec!["api.chio.test".to_string()],
                block: Vec::new(),
                default: DefaultAction::Block,
            }),
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: vec!["calendar.read".to_string()],
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Block,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        };

        let merged_rules = merge_rules(&Some(base_rules.clone()), &Some(child_rules.clone()))
            .expect("merged rules");
        assert_eq!(merged_rules.forbidden_paths, base_rules.forbidden_paths);
        assert_eq!(merged_rules.egress, child_rules.egress);
        assert_eq!(merged_rules.tool_access, child_rules.tool_access);
        assert_eq!(
            merge_rules(&Some(base_rules.clone()), &None),
            Some(base_rules)
        );
        assert_eq!(merge_rules(&None, &None), None);

        let base_extensions = Extensions {
            posture: Some(PostureExtension {
                initial: "base".to_string(),
                states: BTreeMap::from([("base".to_string(), sample_posture_state("base"))]),
                transitions: Vec::new(),
            }),
            origins: None,
            detection: Some(DetectionExtension {
                prompt_injection: Some(PromptInjectionDetection {
                    enabled: Some(true),
                    warn_at_or_above: Some(DetectionLevel::Suspicious),
                    block_at_or_above: None,
                    max_scan_bytes: Some(4096),
                }),
                jailbreak: None,
                threat_intel: None,
            }),
            reputation: Some(ReputationExtension {
                scoring: None,
                tiers: BTreeMap::from([("bronze".to_string(), sample_tier(60))]),
            }),
            runtime_assurance: Some(RuntimeAssuranceExtension {
                tiers: BTreeMap::new(),
                trusted_verifiers: BTreeMap::from([("base".to_string(), sample_verifier("base"))]),
            }),
            chio: None,
        };
        let child_extensions = Extensions {
            posture: Some(PostureExtension {
                initial: "child".to_string(),
                states: BTreeMap::from([("child".to_string(), sample_posture_state("child"))]),
                transitions: Vec::new(),
            }),
            origins: Some(OriginsExtension {
                default_behavior: None,
                profiles: vec![sample_profile("child", "child profile")],
            }),
            detection: Some(DetectionExtension {
                prompt_injection: Some(PromptInjectionDetection {
                    enabled: Some(false),
                    warn_at_or_above: None,
                    block_at_or_above: Some(DetectionLevel::Critical),
                    max_scan_bytes: None,
                }),
                jailbreak: Some(JailbreakDetection {
                    enabled: Some(true),
                    block_threshold: Some(4),
                    warn_threshold: None,
                    max_input_bytes: None,
                }),
                threat_intel: None,
            }),
            reputation: None,
            runtime_assurance: None,
            chio: None,
        };

        let merged_extensions = merge_extensions_merge(
            &Some(base_extensions.clone()),
            &Some(child_extensions.clone()),
        )
        .expect("merged extensions");
        assert_eq!(merged_extensions.posture, child_extensions.posture);
        assert_eq!(merged_extensions.origins, child_extensions.origins);
        assert_eq!(merged_extensions.detection, child_extensions.detection);
        assert_eq!(merged_extensions.reputation, base_extensions.reputation);
        assert_eq!(
            merged_extensions.runtime_assurance,
            base_extensions.runtime_assurance
        );
    }

    #[test]
    fn deep_merge_combines_nested_extension_maps_and_profiles() {
        let base_extensions = Extensions {
            posture: Some(PostureExtension {
                initial: "base".to_string(),
                states: BTreeMap::from([("base".to_string(), sample_posture_state("base"))]),
                transitions: vec![PostureTransition {
                    from: "base".to_string(),
                    to: "child".to_string(),
                    on: TransitionTrigger::UserApproval,
                    after: None,
                }],
            }),
            origins: Some(OriginsExtension {
                default_behavior: Some(crate::models::OriginDefaultBehavior::Deny),
                profiles: vec![
                    sample_profile("shared", "base explanation"),
                    sample_profile("base-only", "base only"),
                ],
            }),
            detection: Some(DetectionExtension {
                prompt_injection: Some(PromptInjectionDetection {
                    enabled: Some(true),
                    warn_at_or_above: Some(DetectionLevel::Suspicious),
                    block_at_or_above: None,
                    max_scan_bytes: Some(4096),
                }),
                jailbreak: None,
                threat_intel: Some(ThreatIntelDetection {
                    enabled: Some(true),
                    pattern_db: Some("base.db".to_string()),
                    similarity_threshold: Some(0.7),
                    top_k: None,
                }),
            }),
            reputation: Some(ReputationExtension {
                scoring: Some(ReputationScoringConfig {
                    weights: Some(ReputationWeights {
                        boundary_pressure: Some(0.1),
                        resource_stewardship: None,
                        least_privilege: None,
                        history_depth: None,
                        tool_diversity: None,
                        delegation_hygiene: None,
                        reliability: Some(0.8),
                        incident_correlation: None,
                    }),
                    temporal_decay_half_life_days: Some(30),
                    probationary_receipt_count: None,
                    probationary_score_ceiling: None,
                    probationary_min_days: None,
                }),
                tiers: BTreeMap::from([("bronze".to_string(), sample_tier(60))]),
            }),
            runtime_assurance: Some(RuntimeAssuranceExtension {
                tiers: BTreeMap::new(),
                trusted_verifiers: BTreeMap::from([("base".to_string(), sample_verifier("base"))]),
            }),
            chio: None,
        };
        let child_extensions = Extensions {
            posture: Some(PostureExtension {
                initial: "child".to_string(),
                states: BTreeMap::from([("child".to_string(), sample_posture_state("child"))]),
                transitions: vec![PostureTransition {
                    from: "child".to_string(),
                    to: "review".to_string(),
                    on: TransitionTrigger::Timeout,
                    after: Some("5m".to_string()),
                }],
            }),
            origins: Some(OriginsExtension {
                default_behavior: Some(crate::models::OriginDefaultBehavior::MinimalProfile),
                profiles: vec![
                    sample_profile("shared", "child explanation"),
                    sample_profile("child-only", "child only"),
                ],
            }),
            detection: Some(DetectionExtension {
                prompt_injection: Some(PromptInjectionDetection {
                    enabled: None,
                    warn_at_or_above: None,
                    block_at_or_above: Some(DetectionLevel::Critical),
                    max_scan_bytes: None,
                }),
                jailbreak: Some(JailbreakDetection {
                    enabled: Some(true),
                    block_threshold: Some(4),
                    warn_threshold: Some(2),
                    max_input_bytes: Some(2048),
                }),
                threat_intel: Some(ThreatIntelDetection {
                    enabled: None,
                    pattern_db: None,
                    similarity_threshold: Some(0.9),
                    top_k: Some(5),
                }),
            }),
            reputation: Some(ReputationExtension {
                scoring: Some(ReputationScoringConfig {
                    weights: Some(ReputationWeights {
                        boundary_pressure: None,
                        resource_stewardship: None,
                        least_privilege: Some(0.3),
                        history_depth: None,
                        tool_diversity: None,
                        delegation_hygiene: None,
                        reliability: None,
                        incident_correlation: None,
                    }),
                    temporal_decay_half_life_days: None,
                    probationary_receipt_count: Some(10),
                    probationary_score_ceiling: None,
                    probationary_min_days: Some(7),
                }),
                tiers: BTreeMap::from([
                    ("bronze".to_string(), sample_tier(120)),
                    ("silver".to_string(), sample_tier(300)),
                ]),
            }),
            runtime_assurance: None,
            chio: None,
        };

        let base = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("base".to_string()),
            description: Some("base description".to_string()),
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(base_extensions.clone()),
            metadata: None,
        };
        let child = HushSpec {
            hushspec: "1.0".to_string(),
            name: None,
            description: Some("child description".to_string()),
            extends: Some("base.yaml".to_string()),
            merge_strategy: None,
            rules: None,
            extensions: Some(child_extensions),
            metadata: None,
        };

        let merged = merge(&base, &child);
        assert_eq!(merged.name.as_deref(), Some("base"));
        assert_eq!(merged.description.as_deref(), Some("child description"));
        assert_eq!(merged.extends, None);

        let merged_extensions = merged.extensions.expect("merged extensions");
        let posture = merged_extensions.posture.expect("merged posture");
        assert_eq!(posture.initial, "child");
        assert_eq!(posture.states.len(), 2);
        assert!(posture.states.contains_key("base"));
        assert!(posture.states.contains_key("child"));
        assert_eq!(posture.transitions.len(), 1);
        assert_eq!(posture.transitions[0].from, "child");

        let origins = merged_extensions.origins.expect("merged origins");
        assert_eq!(
            origins.default_behavior,
            Some(crate::models::OriginDefaultBehavior::MinimalProfile)
        );
        assert_eq!(origins.profiles.len(), 3);
        assert_eq!(
            origins
                .profiles
                .iter()
                .find(|profile| profile.id == "shared")
                .and_then(|profile| profile.explanation.as_deref()),
            Some("child explanation")
        );

        let detection = merged_extensions.detection.expect("merged detection");
        let prompt = detection.prompt_injection.expect("merged prompt injection");
        assert_eq!(prompt.enabled, Some(true));
        assert_eq!(prompt.warn_at_or_above, Some(DetectionLevel::Suspicious));
        assert_eq!(prompt.block_at_or_above, Some(DetectionLevel::Critical));
        assert_eq!(prompt.max_scan_bytes, Some(4096));
        assert!(detection.jailbreak.is_some());
        assert_eq!(
            detection
                .threat_intel
                .as_ref()
                .and_then(|threat| threat.pattern_db.as_deref()),
            Some("base.db")
        );
        assert_eq!(
            detection
                .threat_intel
                .as_ref()
                .and_then(|threat| threat.similarity_threshold),
            Some(0.9)
        );

        let reputation = merged_extensions.reputation.expect("merged reputation");
        let scoring = reputation.scoring.expect("merged scoring");
        let weights = scoring.weights.expect("merged weights");
        assert_eq!(weights.boundary_pressure, Some(0.1));
        assert_eq!(weights.least_privilege, Some(0.3));
        assert_eq!(weights.reliability, Some(0.8));
        assert_eq!(scoring.temporal_decay_half_life_days, Some(30));
        assert_eq!(scoring.probationary_receipt_count, Some(10));
        assert_eq!(scoring.probationary_min_days, Some(7));
        assert_eq!(
            reputation
                .tiers
                .get("bronze")
                .map(|tier| tier.max_scope.ttl_seconds),
            Some(120)
        );
        assert!(reputation.tiers.contains_key("silver"));

        assert_eq!(
            merged_extensions.runtime_assurance,
            base_extensions.runtime_assurance
        );
        assert_eq!(
            merge_extensions_deep(&Some(base_extensions.clone()), &None),
            Some(base_extensions)
        );
    }
}
