//! HushSpec policy validation.
//!
//! Validates a parsed policy and returns errors and warnings.

use crate::models::{DetectionLevel, Extensions, HushSpec, Rules, TransitionTrigger};
use crate::regex_safety::{compile_policy_regex, validate_policy_regex_count};
use crate::version;
use chio_core::capability::trust_policy::canonicalize_attestation_verifier;
use std::collections::{BTreeSet, HashSet};

const MAX_POLICY_DENYLIST_PATTERNS: usize = 64;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported hushspec version: {0}")]
    UnsupportedVersion(String),
    #[error("duplicate secret pattern name: {0}")]
    DuplicatePatternName(String),
    #[error("{field}: invalid regex pattern {pattern:?}: {message}")]
    InvalidRegex {
        field: String,
        pattern: String,
        message: String,
    },
    #[error("{0}")]
    Custom(String),
}

#[must_use = "validation result should be checked"]
pub fn validate(spec: &HushSpec) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if !version::is_supported(&spec.hushspec) {
        errors.push(ValidationError::UnsupportedVersion(spec.hushspec.clone()));
    }

    if let Some(rules) = &spec.rules {
        validate_rules(rules, &mut errors);

        if !rules.has_configured_blocks() {
            warnings.push("no rules configured".to_string());
        }
    } else {
        warnings.push("no rules section present".to_string());
    }

    if let Some(ext) = &spec.extensions {
        validate_posture(ext, &mut errors, &mut warnings);
        validate_detection(ext, &mut errors, &mut warnings);
        validate_reputation(ext, &mut errors, &mut warnings);
        validate_runtime_assurance(ext, &mut errors);
    }

    ValidationResult { errors, warnings }
}

fn validate_rules(rules: &Rules, errors: &mut Vec<ValidationError>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        validate_regex_count(
            secret_patterns.patterns.len(),
            "rules.secret_patterns.patterns",
            errors,
        );
        let mut seen = HashSet::new();
        for (index, pattern) in secret_patterns.patterns.iter().enumerate() {
            let name_field = format!("rules.secret_patterns.patterns[{index}].name");
            let trimmed_name = pattern.name.trim();
            if trimmed_name.is_empty() {
                errors.push(ValidationError::Custom(format!(
                    "{name_field} must not be empty"
                )));
            } else if trimmed_name != pattern.name {
                errors.push(ValidationError::Custom(format!(
                    "{name_field} must not have leading or trailing whitespace"
                )));
            }
            if !trimmed_name.is_empty() && !seen.insert(trimmed_name.to_string()) {
                errors.push(ValidationError::DuplicatePatternName(
                    trimmed_name.to_string(),
                ));
            }
            validate_regex(
                &pattern.pattern,
                &format!("rules.secret_patterns.patterns[{index}].pattern"),
                errors,
            );
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        if patch_integrity.max_imbalance_ratio <= 0.0 {
            errors.push(ValidationError::Custom(
                "rules.patch_integrity.max_imbalance_ratio must be > 0".to_string(),
            ));
        }
        validate_regex_count(
            patch_integrity.forbidden_patterns.len(),
            "rules.patch_integrity.forbidden_patterns",
            errors,
        );
        for (index, pattern) in patch_integrity.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.patch_integrity.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        validate_regex_count(
            shell_commands.forbidden_patterns.len(),
            "rules.shell_commands.forbidden_patterns",
            errors,
        );
        for (index, pattern) in shell_commands.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.shell_commands.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        if matches!(tool_access.max_args_size, Some(0)) {
            errors.push(ValidationError::Custom(
                "rules.tool_access.max_args_size must be >= 1".to_string(),
            ));
        }
        if let Some(require_workload_identity) = tool_access.require_workload_identity.as_ref() {
            validate_workload_identity_match(
                require_workload_identity,
                "rules.tool_access.require_workload_identity",
                errors,
            );
        }
        if let Some(prefer_workload_identity) = tool_access.prefer_workload_identity.as_ref() {
            validate_workload_identity_match(
                prefer_workload_identity,
                "rules.tool_access.prefer_workload_identity",
                errors,
            );
        }
    }
}

fn validate_workload_identity_match(
    rule: &crate::models::WorkloadIdentityMatch,
    field: &str,
    errors: &mut Vec<ValidationError>,
) {
    if rule
        .trust_domain
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors.push(ValidationError::Custom(format!(
            "{field}.trust_domain must not be empty when provided"
        )));
    }

    for (index, prefix) in rule.path_prefixes.iter().enumerate() {
        if prefix.trim().is_empty() {
            errors.push(ValidationError::Custom(format!(
                "{field}.path_prefixes[{index}] must not be empty"
            )));
        } else if !prefix.starts_with('/') {
            errors.push(ValidationError::Custom(format!(
                "{field}.path_prefixes[{index}] must start with '/'"
            )));
        } else if prefix.contains("//") {
            errors.push(ValidationError::Custom(format!(
                "{field}.path_prefixes[{index}] must not contain empty path segments"
            )));
        }
    }
}

fn validate_posture(
    ext: &Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(posture) = &ext.posture {
        if posture.states.is_empty() {
            errors.push(ValidationError::Custom(
                "posture.states must define at least one state".to_string(),
            ));
        }

        if !posture.states.contains_key(&posture.initial) {
            errors.push(ValidationError::Custom(format!(
                "posture.initial '{}' does not reference a defined state",
                posture.initial
            )));
        }

        for (state_name, state) in &posture.states {
            for capability in &state.capabilities {
                if !matches!(
                    capability.as_str(),
                    "file_access"
                        | "file_write"
                        | "egress"
                        | "shell"
                        | "tool_call"
                        | "patch"
                        | "custom"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.capabilities includes unknown capability '{capability}'"
                    ));
                }
            }

            for (budget_key, &value) in &state.budgets {
                if value < 0 {
                    errors.push(ValidationError::Custom(format!(
                        "posture.states.{state_name}.budgets.{budget_key} must be non-negative, got {value}"
                    )));
                }
                if !matches!(
                    budget_key.as_str(),
                    "file_writes"
                        | "egress_calls"
                        | "shell_commands"
                        | "tool_calls"
                        | "patches"
                        | "custom_calls"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.budgets uses unknown budget key '{budget_key}'"
                    ));
                }
            }
        }

        for (index, transition) in posture.transitions.iter().enumerate() {
            if transition.from != "*" && !posture.states.contains_key(&transition.from) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].from '{}' does not reference a defined state",
                    transition.from
                )));
            }
            if transition.to == "*" {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to cannot be '*'"
                )));
            } else if !posture.states.contains_key(&transition.to) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to '{}' does not reference a defined state",
                    transition.to
                )));
            }

            if transition.on != TransitionTrigger::Timeout {
                if let Some(after) = &transition.after {
                    if !is_valid_duration(after) {
                        errors.push(ValidationError::Custom(format!(
                            "posture.transitions[{index}].after must be a positive duration matching ^[1-9]\\d*[smhd]$"
                        )));
                    }
                }
            }

            if transition.on == TransitionTrigger::Timeout {
                match transition.after.as_deref() {
                    Some(after) if is_valid_duration(after) => {}
                    Some(_) => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}].after must be a positive duration matching ^[1-9]\\d*[smhd]$"
                    ))),
                    None => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}]: timeout trigger requires 'after' field"
                    ))),
                }
            }
        }
    }
}

fn validate_detection(
    ext: &Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(detection) = &ext.detection {
        if let Some(prompt_injection) = &detection.prompt_injection {
            if matches!(prompt_injection.max_scan_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.prompt_injection.max_scan_bytes must be >= 1".to_string(),
                ));
            }

            let warn_level = prompt_injection
                .warn_at_or_above
                .unwrap_or(DetectionLevel::Suspicious);
            let block_level = prompt_injection
                .block_at_or_above
                .unwrap_or(DetectionLevel::High);
            if block_level < warn_level {
                warnings.push(
                    "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above"
                        .to_string(),
                );
            }
        }

        if let Some(jailbreak) = &detection.jailbreak {
            if matches!(jailbreak.block_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.block_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.warn_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.warn_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.max_input_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.max_input_bytes must be >= 1".to_string(),
                ));
            }

            let block_threshold = jailbreak.block_threshold.unwrap_or(80);
            let warn_threshold = jailbreak.warn_threshold.unwrap_or(50);
            if block_threshold < warn_threshold {
                warnings.push(
                    "detection.jailbreak: block_threshold is lower than warn_threshold".to_string(),
                );
            }
        }

        if let Some(threat_intel) = &detection.threat_intel {
            match threat_intel.pattern_db.as_deref() {
                Some(pattern_db) if pattern_db.trim().is_empty() => {
                    errors.push(ValidationError::Custom(
                        "detection.threat_intel.pattern_db must not be empty".to_string(),
                    ));
                }
                None if threat_intel.enabled.unwrap_or(true) => {
                    errors.push(ValidationError::Custom(
                        "detection.threat_intel.pattern_db is required when enabled".to_string(),
                    ));
                }
                _ => {}
            }
            if let Some(similarity_threshold) = threat_intel.similarity_threshold {
                if !(0.0..=1.0).contains(&similarity_threshold) {
                    errors.push(ValidationError::Custom(
                        "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0"
                            .to_string(),
                    ));
                }
            }
            if matches!(threat_intel.top_k, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.top_k must be >= 1".to_string(),
                ));
            }
        }
    }
}

fn validate_reputation(
    ext: &Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    let Some(reputation) = &ext.reputation else {
        return;
    };

    if reputation.tiers.is_empty() {
        errors.push(ValidationError::Custom(
            "extensions.reputation.tiers must define at least one tier".to_string(),
        ));
    }

    if let Some(scoring) = &reputation.scoring {
        if let Some(days) = scoring.temporal_decay_half_life_days {
            if days == 0 {
                errors.push(ValidationError::Custom(
                    "extensions.reputation.scoring.temporal_decay_half_life_days must be >= 1"
                        .to_string(),
                ));
            }
        }
        if let Some(ceiling) = scoring.probationary_score_ceiling {
            if !(0.0..=1.0).contains(&ceiling) {
                errors.push(ValidationError::Custom(
                    "extensions.reputation.scoring.probationary_score_ceiling must be in [0.0, 1.0]"
                        .to_string(),
                ));
            }
        }
        if let Some(weights) = &scoring.weights {
            validate_weight(
                weights.boundary_pressure,
                "extensions.reputation.scoring.weights.boundary_pressure",
                errors,
            );
            validate_weight(
                weights.resource_stewardship,
                "extensions.reputation.scoring.weights.resource_stewardship",
                errors,
            );
            validate_weight(
                weights.least_privilege,
                "extensions.reputation.scoring.weights.least_privilege",
                errors,
            );
            validate_weight(
                weights.history_depth,
                "extensions.reputation.scoring.weights.history_depth",
                errors,
            );
            validate_weight(
                weights.tool_diversity,
                "extensions.reputation.scoring.weights.tool_diversity",
                errors,
            );
            validate_weight(
                weights.delegation_hygiene,
                "extensions.reputation.scoring.weights.delegation_hygiene",
                errors,
            );
            validate_weight(
                weights.reliability,
                "extensions.reputation.scoring.weights.reliability",
                errors,
            );
            validate_weight(
                weights.incident_correlation,
                "extensions.reputation.scoring.weights.incident_correlation",
                errors,
            );
        }
    }

    for (tier_name, tier) in &reputation.tiers {
        let [min_score, max_score] = tier.score_range;
        if !(0.0..=1.0).contains(&min_score) || !(0.0..=1.0).contains(&max_score) {
            errors.push(ValidationError::Custom(format!(
                "extensions.reputation.tiers.{tier_name}.score_range values must be in [0.0, 1.0]"
            )));
        }
        if min_score > max_score {
            errors.push(ValidationError::Custom(format!(
                "extensions.reputation.tiers.{tier_name}.score_range lower bound exceeds upper bound"
            )));
        }
        if tier.max_scope.ttl_seconds == 0 {
            errors.push(ValidationError::Custom(format!(
                "extensions.reputation.tiers.{tier_name}.max_scope.ttl_seconds must be >= 1"
            )));
        }
        if tier.max_scope.operations.is_empty() {
            warnings.push(format!(
                "extensions.reputation.tiers.{tier_name}.max_scope.operations is empty"
            ));
        }
        for operation in &tier.max_scope.operations {
            if !matches!(
                operation.as_str(),
                "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate"
            ) {
                warnings.push(format!(
                    "extensions.reputation.tiers.{tier_name}.max_scope.operations includes unknown operation '{operation}'"
                ));
            }
        }
    }
}

fn validate_runtime_assurance(ext: &Extensions, errors: &mut Vec<ValidationError>) {
    let Some(runtime_assurance) = ext.runtime_assurance.as_ref() else {
        return;
    };

    if runtime_assurance.tiers.is_empty() {
        errors.push(ValidationError::Custom(
            "extensions.runtime_assurance.tiers must define at least one tier".to_string(),
        ));
        return;
    }

    let mut seen_minimum_tiers = BTreeSet::new();
    let mut seen_trusted_verifiers = BTreeSet::new();
    for (tier_name, tier) in &runtime_assurance.tiers {
        if !seen_minimum_tiers.insert(tier.minimum_attestation_tier) {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.tiers duplicates minimum_attestation_tier {:?}",
                tier.minimum_attestation_tier
            )));
        }
        if tier.max_scope.ttl_seconds == 0 {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.tiers.{tier_name}.max_scope.ttl_seconds must be >= 1"
            )));
        }
        if tier.max_scope.operations.is_empty() {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.tiers.{tier_name}.max_scope.operations is empty"
            )));
        }
    }

    for (rule_name, rule) in &runtime_assurance.trusted_verifiers {
        if rule.schema.trim().is_empty() {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.trusted_verifiers.{rule_name}.schema must not be empty"
            )));
        }
        if rule.verifier.trim().is_empty() {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.trusted_verifiers.{rule_name}.verifier must not be empty"
            )));
        }
        if rule.max_evidence_age_seconds == Some(0) {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.trusted_verifiers.{rule_name}.max_evidence_age_seconds must be >= 1"
            )));
        }
        for (index, attestation_type) in rule.allowed_attestation_types.iter().enumerate() {
            if attestation_type.trim().is_empty() {
                errors.push(ValidationError::Custom(format!(
                    "extensions.runtime_assurance.trusted_verifiers.{rule_name}.allowed_attestation_types[{index}] must not be empty"
                )));
            }
        }
        for (assertion, expected) in &rule.required_assertions {
            if assertion.trim().is_empty() {
                errors.push(ValidationError::Custom(format!(
                    "extensions.runtime_assurance.trusted_verifiers.{rule_name}.required_assertions keys must not be empty"
                )));
            }
            if expected.trim().is_empty() {
                errors.push(ValidationError::Custom(format!(
                    "extensions.runtime_assurance.trusted_verifiers.{rule_name}.required_assertions.{assertion} must not be empty"
                )));
            }
        }

        let canonical_binding = (
            rule.schema.trim().to_string(),
            canonicalize_attestation_verifier(&rule.verifier),
        );
        if !seen_trusted_verifiers.insert(canonical_binding) {
            errors.push(ValidationError::Custom(format!(
                "extensions.runtime_assurance.trusted_verifiers duplicates schema/verifier binding for {} {}",
                rule.schema.trim(),
                rule.verifier.trim()
            )));
        }
    }
}

fn validate_weight(value: Option<f64>, field: &str, errors: &mut Vec<ValidationError>) {
    if let Some(weight) = value {
        if !(0.0..=1.0).contains(&weight) {
            errors.push(ValidationError::Custom(format!(
                "{field} must be in [0.0, 1.0]"
            )));
        }
    }
}

fn validate_regex(pattern: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if let Err(error) = compile_policy_regex(pattern, path) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: error,
        });
    }
}

fn validate_regex_count(count: usize, path: &str, errors: &mut Vec<ValidationError>) {
    if let Err(error) = validate_policy_regex_count(count, path, MAX_POLICY_DENYLIST_PATTERNS) {
        errors.push(ValidationError::Custom(error));
    }
}

fn is_valid_duration(value: &str) -> bool {
    if !matches!(value.as_bytes().last(), Some(b's' | b'm' | b'h' | b'd')) {
        return false;
    }
    let number = &value[..value.len() - 1];
    !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && number.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::models::{
        Extensions, PatchIntegrityRule, SecretPattern, SecretPatternsRule, Severity,
        ShellCommandsRule,
    };

    fn assert_error_contains(result: &ValidationResult, needle: &str) {
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.to_string().contains(needle)),
            "expected error containing {needle:?}, got: {:?}",
            result.errors
        );
    }

    fn assert_warning_contains(result: &ValidationResult, needle: &str) {
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains(needle)),
            "expected warning containing {needle:?}, got: {:?}",
            result.warnings
        );
    }

    fn assert_warning_absent(result: &ValidationResult, needle: &str) {
        assert!(
            result
                .warnings
                .iter()
                .all(|warning| !warning.contains(needle)),
            "expected no warning containing {needle:?}, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn browser_and_code_rules_count_as_configured_rules() {
        let browser_only = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
"#,
        )
        .unwrap();
        let result = validate(&browser_only);
        assert_warning_absent(&result, "no rules configured");

        let code_only = HushSpec::parse(
            r#"
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
"#,
        )
        .unwrap();
        let result = validate(&code_only);
        assert_warning_absent(&result, "no rules configured");
    }

    #[test]
    fn denylist_regex_validation_rejects_unsafe_patterns() {
        let spec = HushSpec {
            hushspec: "0.1.0".to_string(),
            name: Some("regex-validation".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                secret_patterns: Some(SecretPatternsRule {
                    enabled: true,
                    patterns: vec![SecretPattern {
                        name: "broken".to_string(),
                        pattern: "(".to_string(),
                        severity: Severity::Critical,
                        description: None,
                    }],
                    skip_paths: Vec::new(),
                }),
                patch_integrity: Some(PatchIntegrityRule {
                    enabled: true,
                    max_additions: 1000,
                    max_deletions: 500,
                    forbidden_patterns: vec!["a".repeat(513)],
                    require_balance: false,
                    max_imbalance_ratio: 2.0,
                }),
                shell_commands: Some(ShellCommandsRule {
                    enabled: true,
                    forbidden_patterns: vec!["a?".repeat(25); 65],
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions::default()),
            metadata: None,
        };

        let result = validate(&spec);

        assert_error_contains(&result, "rules.secret_patterns.patterns[0].pattern");
        assert_error_contains(&result, "must be at most 512 characters");
        assert_error_contains(
            &result,
            "rules.shell_commands.forbidden_patterns allows at most 64 patterns",
        );
        assert_error_contains(&result, "complexity at most 96");
    }

    #[test]
    fn posture_validation_reports_state_budget_and_transition_issues() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: posture-validation
extensions:
  posture:
    initial: review
    states:
      draft:
        capabilities: ["file_access", "mystery_capability"]
        budgets:
          file_writes: 1
          shadow_budget: 2
      limited:
        budgets:
          tool_calls: -1
    transitions:
      - from: unknown
        to: draft
        on: user_approval
        after: 5x
      - from: draft
        to: "*"
        on: user_denial
      - from: draft
        to: missing
        on: critical_violation
      - from: draft
        to: limited
        on: timeout
      - from: limited
        to: draft
        on: timeout
        after: later
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "posture.initial 'review' does not reference a defined state",
        );
        assert_error_contains(
            &result,
            "posture.states.limited.budgets.tool_calls must be non-negative, got -1",
        );
        assert_error_contains(
            &result,
            "posture.transitions[0].from 'unknown' does not reference a defined state",
        );
        assert_error_contains(
            &result,
            "posture.transitions[0].after must be a positive duration matching ^[1-9]\\d*[smhd]$",
        );
        assert_error_contains(&result, "posture.transitions[1].to cannot be '*'");
        assert_error_contains(
            &result,
            "posture.transitions[2].to 'missing' does not reference a defined state",
        );
        assert_error_contains(
            &result,
            "posture.transitions[3]: timeout trigger requires 'after' field",
        );
        assert_error_contains(
            &result,
            "posture.transitions[4].after must be a positive duration matching ^[1-9]\\d*[smhd]$",
        );
        assert_warning_contains(
            &result,
            "posture.states.draft.capabilities includes unknown capability 'mystery_capability'",
        );
        assert_warning_contains(
            &result,
            "posture.states.draft.budgets uses unknown budget key 'shadow_budget'",
        );
    }

    #[test]
    fn posture_validation_accepts_zero_budgets_and_valid_duration_suffixes() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: posture-validation-boundaries
extensions:
  posture:
    initial: draft
    states:
      draft:
        capabilities: ["tool_call"]
        budgets:
          tool_calls: 0
      review:
        capabilities: ["tool_call"]
    transitions:
      - from: draft
        to: review
        on: timeout
        after: 15m
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);

        assert!(
            result.errors.is_empty(),
            "zero budgets and valid duration suffixes should pass validation: {:?}",
            result.errors
        );
    }

    #[test]
    fn posture_validation_rejects_zero_duration_windows() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: posture-zero-duration
extensions:
  posture:
    initial: draft
    states:
      draft:
        capabilities: ["tool_call"]
      review:
        capabilities: ["tool_call"]
    transitions:
      - from: draft
        to: review
        on: timeout
        after: 0s
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);

        assert_error_contains(
            &result,
            "posture.transitions[0].after must be a positive duration matching ^[1-9]\\d*[smhd]$",
        );
    }

    #[test]
    fn posture_validation_rejects_empty_state_sets() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: empty-posture
extensions:
  posture:
    initial: draft
    states: {}
    transitions: []
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);
        assert_error_contains(&result, "posture.states must define at least one state");
        assert_error_contains(
            &result,
            "posture.initial 'draft' does not reference a defined state",
        );
    }

    #[test]
    fn detection_validation_reports_threshold_errors_and_warning_ordering() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: detection-validation
extensions:
  detection:
    prompt_injection:
      warn_at_or_above: critical
      block_at_or_above: suspicious
      max_scan_bytes: 0
    jailbreak:
      block_threshold: 101
      warn_threshold: 102
      max_input_bytes: 0
    threat_intel:
      similarity_threshold: 1.5
      top_k: 0
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "detection.prompt_injection.max_scan_bytes must be >= 1",
        );
        assert_error_contains(
            &result,
            "detection.jailbreak.block_threshold must be between 0 and 100",
        );
        assert_error_contains(
            &result,
            "detection.jailbreak.warn_threshold must be between 0 and 100",
        );
        assert_error_contains(&result, "detection.jailbreak.max_input_bytes must be >= 1");
        assert_error_contains(
            &result,
            "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0",
        );
        assert_error_contains(&result, "detection.threat_intel.top_k must be >= 1");
        assert_warning_contains(
            &result,
            "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above",
        );
        assert_warning_contains(
            &result,
            "detection.jailbreak: block_threshold is lower than warn_threshold",
        );
    }

    #[test]
    fn detection_validation_requires_threat_intel_pattern_db_when_enabled() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: detection-validation
extensions:
  detection:
    threat_intel:
      enabled: true
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "detection.threat_intel.pattern_db is required when enabled",
        );
    }

    #[test]
    fn reputation_validation_reports_scoring_scope_and_operation_issues() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: reputation-validation
extensions:
  reputation:
    scoring:
      temporal_decay_half_life_days: 0
      probationary_score_ceiling: 1.5
      weights:
        boundary_pressure: -0.1
        resource_stewardship: 1.1
        least_privilege: 0.2
        history_depth: 0.3
        tool_diversity: 0.4
        delegation_hygiene: 0.5
        reliability: 0.6
        incident_correlation: 1.2
    tiers:
      bronze:
        score_range: [0.8, 0.2]
        max_scope:
          operations: []
          ttl_seconds: 0
      silver:
        score_range: [-0.1, 1.2]
        max_scope:
          operations: ["invoke", "escalate"]
          ttl_seconds: 60
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "extensions.reputation.scoring.temporal_decay_half_life_days must be >= 1",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.scoring.probationary_score_ceiling must be in [0.0, 1.0]",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.scoring.weights.boundary_pressure must be in [0.0, 1.0]",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.scoring.weights.resource_stewardship must be in [0.0, 1.0]",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.scoring.weights.incident_correlation must be in [0.0, 1.0]",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.tiers.bronze.score_range lower bound exceeds upper bound",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.tiers.bronze.max_scope.ttl_seconds must be >= 1",
        );
        assert_error_contains(
            &result,
            "extensions.reputation.tiers.silver.score_range values must be in [0.0, 1.0]",
        );
        assert_warning_contains(
            &result,
            "extensions.reputation.tiers.bronze.max_scope.operations is empty",
        );
        assert_warning_contains(
            &result,
            "extensions.reputation.tiers.silver.max_scope.operations includes unknown operation 'escalate'",
        );
    }

    #[test]
    fn reputation_validation_accepts_single_point_score_range() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: reputation-single-point-tier
extensions:
  reputation:
    tiers:
      exact:
        score_range: [0.5, 0.5]
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
"#,
        )
        .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));

        let result = validate(&spec);

        assert!(
            result.errors.is_empty(),
            "equal reputation score_range bounds should be valid: {:?}",
            result.errors
        );
    }

    #[test]
    fn reputation_validation_rejects_empty_tiers() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: empty-reputation
extensions:
  reputation:
    tiers: {}
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "extensions.reputation.tiers must define at least one tier",
        );
    }

    #[test]
    fn runtime_assurance_validation_reports_empty_scope_and_blank_verifiers() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: runtime-assurance-validation
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: []
          ttl_seconds: 0
    trusted_verifiers:
      blank:
        schema: "   "
        verifier: "   "
        effective_tier: verified
        max_evidence_age_seconds: 0
        allowed_attestation_types: [""]
        required_assertions:
          "": "enabled"
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.tiers.baseline.max_scope.ttl_seconds must be >= 1",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.tiers.baseline.max_scope.operations is empty",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.trusted_verifiers.blank.schema must not be empty",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.trusted_verifiers.blank.verifier must not be empty",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.trusted_verifiers.blank.max_evidence_age_seconds must be >= 1",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.trusted_verifiers.blank.allowed_attestation_types[0] must not be empty",
        );
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.trusted_verifiers.blank.required_assertions keys must not be empty",
        );
    }

    #[test]
    fn runtime_assurance_validation_rejects_empty_tiers() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: empty-runtime-assurance
extensions:
  runtime_assurance:
    tiers: {}
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert_error_contains(
            &result,
            "extensions.runtime_assurance.tiers must define at least one tier",
        );
    }

    #[test]
    fn runtime_assurance_validation_rejects_duplicate_minimum_tiers() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: duplicate-runtime-assurance
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      attested_a:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      attested_b:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 120
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.tiers duplicates minimum_attestation_tier Attested"
            )),
            "expected duplicate minimum_attestation_tier error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn runtime_assurance_validation_rejects_invalid_trusted_verifier_rules() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: trusted-verifiers
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
    trusted_verifiers:
      azure_a:
        schema: "chio.runtime-attestation.azure-maa.jwt.v1"
        verifier: "https://maa.contoso.test/"
        effective_tier: verified
        max_evidence_age_seconds: 0
        allowed_attestation_types: ["sgx", ""]
        required_assertions:
          "": "enabled"
          secureBoot: ""
      azure_b:
        schema: "chio.runtime-attestation.azure-maa.jwt.v1"
        verifier: "https://maa.contoso.test"
        effective_tier: verified
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.trusted_verifiers.azure_a.max_evidence_age_seconds must be >= 1"
            )),
            "expected max_evidence_age_seconds error, got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.trusted_verifiers.azure_a.allowed_attestation_types[1] must not be empty"
            )),
            "expected allowed_attestation_types error, got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.trusted_verifiers.azure_a.required_assertions keys must not be empty"
            )),
            "expected required_assertions key error, got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.trusted_verifiers.azure_a.required_assertions.secureBoot must not be empty"
            )),
            "expected required_assertions value error, got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "extensions.runtime_assurance.trusted_verifiers duplicates schema/verifier binding"
            )),
            "expected duplicate trusted verifier binding error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn tool_access_workload_identity_validation_rejects_bad_match_fields() {
        let spec: HushSpec = serde_yml::from_str(
            r#"
hushspec: "0.1.0"
name: workload-identity-validation
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
    require_workload_identity:
      trust_domain: ""
      path_prefixes: ["payments"]
"#,
        )
        .expect("parse policy");

        let result = validate(&spec);
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "rules.tool_access.require_workload_identity.trust_domain must not be empty when provided"
            )),
            "expected trust-domain validation error, got: {:?}",
            result.errors
        );
        assert!(
            result.errors.iter().any(|error| error.to_string().contains(
                "rules.tool_access.require_workload_identity.path_prefixes[0] must start with '/'"
            )),
            "expected path-prefix validation error, got: {:?}",
            result.errors
        );
    }
}
