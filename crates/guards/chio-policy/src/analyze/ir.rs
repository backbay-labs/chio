use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::models::{DefaultAction, HushSpec, Rules, RULE_BLOCK_NAMES};

use super::report::{NotAnalyzed, RuleRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AtomMatcher {
    Glob { pattern: String },
    NumericRange { lo: Option<u64>, hi: Option<u64> },
    BoolFlag { value: bool },
    SetMember { values: BTreeSet<String> },
    Default,
    Opaque { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleAtom {
    pub block: String,
    pub domain: String,
    pub effect: AtomEffect,
    pub matcher: AtomMatcher,
    pub provenance: RuleRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockState {
    Absent,
    Disabled,
    Active,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredBlock {
    pub name: String,
    pub state: BlockState,
    pub atoms: Vec<RuleAtom>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredPolicy {
    pub blocks: Vec<LoweredBlock>,
}

impl LoweredPolicy {
    pub(crate) fn authored_atom_count(&self) -> usize {
        self.blocks
            .iter()
            .flat_map(|block| &block.atoms)
            .filter(|atom| !matches!(atom.matcher, AtomMatcher::Default))
            .count()
    }

    pub(crate) fn not_analyzed(&self) -> Vec<NotAnalyzed> {
        self.blocks
            .iter()
            .filter(|block| block.state == BlockState::Active)
            .flat_map(|block| &block.atoms)
            .filter_map(|atom| match &atom.matcher {
                AtomMatcher::Opaque { reason } => Some(NotAnalyzed {
                    block: atom.block.clone(),
                    field: atom.provenance.field.clone(),
                    reason: reason.clone(),
                }),
                _ => None,
            })
            .collect()
    }
}

fn rule_ref(field: &str, index: usize, pattern: impl Into<String>) -> RuleRef {
    RuleRef {
        field: field.to_string(),
        index,
        pattern: pattern.into(),
    }
}

fn atom(
    block: &str,
    domain: &str,
    effect: AtomEffect,
    matcher: AtomMatcher,
    field: &str,
    index: usize,
    display: impl Into<String>,
) -> RuleAtom {
    RuleAtom {
        block: block.to_string(),
        domain: domain.to_string(),
        effect,
        matcher,
        provenance: rule_ref(field, index, display),
    }
}

fn glob_atoms(
    output: &mut Vec<RuleAtom>,
    block: &str,
    domain: &str,
    effect: AtomEffect,
    field: &str,
    patterns: &[String],
) {
    output.extend(patterns.iter().enumerate().map(|(index, pattern)| {
        atom(
            block,
            domain,
            effect,
            AtomMatcher::Glob {
                pattern: pattern.clone(),
            },
            field,
            index,
            pattern,
        )
    }));
}

fn set_atoms(
    output: &mut Vec<RuleAtom>,
    block: &str,
    domain: &str,
    effect: AtomEffect,
    field: &str,
    values: &[String],
) {
    output.extend(values.iter().enumerate().map(|(index, value)| {
        atom(
            block,
            domain,
            effect,
            AtomMatcher::SetMember {
                values: BTreeSet::from([value.clone()]),
            },
            field,
            index,
            value,
        )
    }));
}

fn opaque(
    output: &mut Vec<RuleAtom>,
    block: &str,
    field: &str,
    index: usize,
    display: impl Into<String>,
    reason: &str,
) {
    output.push(atom(
        block,
        field,
        AtomEffect::Deny,
        AtomMatcher::Opaque {
            reason: reason.to_string(),
        },
        field,
        index,
        display,
    ));
}

fn default_atom(
    output: &mut Vec<RuleAtom>,
    block: &str,
    domain: &str,
    effect: AtomEffect,
    field: &str,
    display: &str,
) {
    output.push(atom(
        block,
        domain,
        effect,
        AtomMatcher::Default,
        field,
        0,
        display,
    ));
}

fn block(name: &str, present: bool, enabled: bool, atoms: Vec<RuleAtom>) -> LoweredBlock {
    LoweredBlock {
        name: name.to_string(),
        state: if !present {
            BlockState::Absent
        } else if enabled {
            BlockState::Active
        } else {
            BlockState::Disabled
        },
        atoms,
    }
}

pub fn lower_policy(spec: &HushSpec) -> LoweredPolicy {
    let empty = Rules::default();
    let rules = spec.rules.as_ref().unwrap_or(&empty);
    let mut blocks = Vec::with_capacity(RULE_BLOCK_NAMES.len());

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.forbidden_paths {
        glob_atoms(
            &mut atoms,
            "forbidden_paths",
            "path",
            AtomEffect::Deny,
            "patterns",
            &rule.patterns,
        );
        glob_atoms(
            &mut atoms,
            "forbidden_paths",
            "path",
            AtomEffect::Allow,
            "exceptions",
            &rule.exceptions,
        );
        default_atom(
            &mut atoms,
            "forbidden_paths",
            "path",
            AtomEffect::Allow,
            "default",
            "allow",
        );
    }
    blocks.push(block(
        "forbidden_paths",
        rules.forbidden_paths.is_some(),
        rules
            .forbidden_paths
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.path_allowlist {
        for (field, patterns) in [
            ("read", &rule.read),
            ("write", &rule.write),
            ("patch", &rule.patch),
        ] {
            glob_atoms(
                &mut atoms,
                "path_allowlist",
                field,
                AtomEffect::Allow,
                field,
                patterns,
            );
            default_atom(
                &mut atoms,
                "path_allowlist",
                field,
                AtomEffect::Deny,
                &format!("{field}_default"),
                "deny",
            );
        }
    }
    blocks.push(block(
        "path_allowlist",
        rules.path_allowlist.is_some(),
        rules
            .path_allowlist
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.egress {
        glob_atoms(
            &mut atoms,
            "egress",
            "host",
            AtomEffect::Allow,
            "allow",
            &rule.allow,
        );
        glob_atoms(
            &mut atoms,
            "egress",
            "host",
            AtomEffect::Deny,
            "block",
            &rule.block,
        );
        default_atom(
            &mut atoms,
            "egress",
            "host",
            if rule.default == DefaultAction::Allow {
                AtomEffect::Allow
            } else {
                AtomEffect::Deny
            },
            "default",
            if rule.default == DefaultAction::Allow {
                "allow"
            } else {
                "block"
            },
        );
    }
    blocks.push(block(
        "egress",
        rules.egress.is_some(),
        rules.egress.as_ref().is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.secret_patterns {
        for (index, pattern) in rule.patterns.iter().enumerate() {
            opaque(
                &mut atoms,
                "secret_patterns",
                "patterns",
                index,
                &pattern.name,
                "regex-valued content predicate",
            );
        }
        glob_atoms(
            &mut atoms,
            "secret_patterns",
            "skip_path",
            AtomEffect::Allow,
            "skip_paths",
            &rule.skip_paths,
        );
    }
    blocks.push(block(
        "secret_patterns",
        rules.secret_patterns.is_some(),
        rules
            .secret_patterns
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.patch_integrity {
        atoms.push(atom(
            "patch_integrity",
            "additions",
            AtomEffect::Deny,
            AtomMatcher::NumericRange {
                lo: u64::try_from(rule.max_additions)
                    .ok()
                    .and_then(|value| value.checked_add(1)),
                hi: None,
            },
            "max_additions",
            0,
            rule.max_additions.to_string(),
        ));
        atoms.push(atom(
            "patch_integrity",
            "deletions",
            AtomEffect::Deny,
            AtomMatcher::NumericRange {
                lo: u64::try_from(rule.max_deletions)
                    .ok()
                    .and_then(|value| value.checked_add(1)),
                hi: None,
            },
            "max_deletions",
            0,
            rule.max_deletions.to_string(),
        ));
        for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
            opaque(
                &mut atoms,
                "patch_integrity",
                "forbidden_patterns",
                index,
                pattern,
                "regex-valued patch predicate",
            );
        }
        if rule.require_balance {
            opaque(
                &mut atoms,
                "patch_integrity",
                "max_imbalance_ratio",
                0,
                rule.max_imbalance_ratio.to_string(),
                "floating-point cross-field ratio",
            );
        }
    }
    blocks.push(block(
        "patch_integrity",
        rules.patch_integrity.is_some(),
        rules
            .patch_integrity
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.shell_commands {
        for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
            opaque(
                &mut atoms,
                "shell_commands",
                "forbidden_patterns",
                index,
                pattern,
                "regex-valued command predicate",
            );
        }
    }
    blocks.push(block(
        "shell_commands",
        rules.shell_commands.is_some(),
        rules
            .shell_commands
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.tool_access {
        glob_atoms(
            &mut atoms,
            "tool_access",
            "tool",
            AtomEffect::Allow,
            "allow",
            &rule.allow,
        );
        glob_atoms(
            &mut atoms,
            "tool_access",
            "tool",
            AtomEffect::Deny,
            "block",
            &rule.block,
        );
        for (index, pattern) in rule.require_confirmation.iter().enumerate() {
            opaque(
                &mut atoms,
                "tool_access",
                "require_confirmation",
                index,
                pattern,
                "advisory confirmation predicate",
            );
        }
        if let Some(maximum) = rule.max_args_size {
            atoms.push(atom(
                "tool_access",
                "args_size",
                AtomEffect::Deny,
                AtomMatcher::NumericRange {
                    lo: u64::try_from(maximum)
                        .ok()
                        .and_then(|value| value.checked_add(1)),
                    hi: None,
                },
                "max_args_size",
                0,
                maximum.to_string(),
            ));
        }
        if rule.require_runtime_assurance_tier.is_some() {
            opaque(
                &mut atoms,
                "tool_access",
                "require_runtime_assurance_tier",
                0,
                "configured",
                "runtime attestation predicate",
            );
        }
        if rule.prefer_runtime_assurance_tier.is_some() {
            opaque(
                &mut atoms,
                "tool_access",
                "prefer_runtime_assurance_tier",
                0,
                "configured",
                "advisory runtime attestation predicate",
            );
        }
        if rule.require_workload_identity.is_some() {
            opaque(
                &mut atoms,
                "tool_access",
                "require_workload_identity",
                0,
                "configured",
                "runtime identity predicate",
            );
        }
        if rule.prefer_workload_identity.is_some() {
            opaque(
                &mut atoms,
                "tool_access",
                "prefer_workload_identity",
                0,
                "configured",
                "advisory runtime identity predicate",
            );
        }
        default_atom(
            &mut atoms,
            "tool_access",
            "tool",
            if rule.default == DefaultAction::Allow {
                AtomEffect::Allow
            } else {
                AtomEffect::Deny
            },
            "default",
            if rule.default == DefaultAction::Allow {
                "allow"
            } else {
                "block"
            },
        );
    }
    blocks.push(block(
        "tool_access",
        rules.tool_access.is_some(),
        rules.tool_access.as_ref().is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.computer_use {
        set_atoms(
            &mut atoms,
            "computer_use",
            "action",
            AtomEffect::Allow,
            "allowed_actions",
            &rule.allowed_actions,
        );
        opaque(
            &mut atoms,
            "computer_use",
            "mode",
            0,
            format!("{:?}", rule.mode).to_lowercase(),
            "warning and default-mode semantics",
        );
    }
    blocks.push(block(
        "computer_use",
        rules.computer_use.is_some(),
        rules.computer_use.as_ref().is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.remote_desktop_channels {
        for (field, value) in [
            ("clipboard", rule.clipboard),
            ("file_transfer", rule.file_transfer),
            ("audio", rule.audio),
            ("drive_mapping", rule.drive_mapping),
        ] {
            atoms.push(atom(
                "remote_desktop_channels",
                field,
                if value {
                    AtomEffect::Allow
                } else {
                    AtomEffect::Deny
                },
                AtomMatcher::BoolFlag { value },
                field,
                0,
                value.to_string(),
            ));
        }
    }
    blocks.push(block(
        "remote_desktop_channels",
        rules.remote_desktop_channels.is_some(),
        rules
            .remote_desktop_channels
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.input_injection {
        set_atoms(
            &mut atoms,
            "input_injection",
            "input_type",
            AtomEffect::Allow,
            "allowed_types",
            &rule.allowed_types,
        );
        if rule.require_postcondition_probe {
            opaque(
                &mut atoms,
                "input_injection",
                "require_postcondition_probe",
                0,
                "true",
                "guard-only postcondition predicate",
            );
        }
    }
    blocks.push(block(
        "input_injection",
        rules.input_injection.is_some(),
        rules
            .input_injection
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.browser_automation {
        opaque(
            &mut atoms,
            "browser_automation",
            "credential_detection",
            0,
            rule.credential_detection.to_string(),
            "guard-only browser predicate",
        );
        for (field, values) in [
            ("allowed_domains", &rule.allowed_domains),
            ("blocked_domains", &rule.blocked_domains),
            ("allowed_verbs", &rule.allowed_verbs),
        ] {
            for (index, value) in values.iter().enumerate() {
                opaque(
                    &mut atoms,
                    "browser_automation",
                    field,
                    index,
                    value,
                    "guard-only browser predicate",
                );
            }
        }
        for (index, value) in rule.extra_credential_patterns.iter().enumerate() {
            opaque(
                &mut atoms,
                "browser_automation",
                "extra_credential_patterns",
                index,
                value,
                "regex-valued browser predicate",
            );
        }
    }
    blocks.push(block(
        "browser_automation",
        rules.browser_automation.is_some(),
        rules
            .browser_automation
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.code_execution {
        opaque(
            &mut atoms,
            "code_execution",
            "network_access",
            0,
            rule.network_access.to_string(),
            "guard-only code predicate",
        );
        for (field, values) in [
            ("language_allowlist", &rule.language_allowlist),
            ("module_denylist", &rule.module_denylist),
        ] {
            for (index, value) in values.iter().enumerate() {
                opaque(
                    &mut atoms,
                    "code_execution",
                    field,
                    index,
                    value,
                    "guard-only code predicate",
                );
            }
        }
        for (field, value) in [
            (
                "max_execution_time_ms",
                rule.max_execution_time_ms.map(|value| value.to_string()),
            ),
            (
                "max_scan_bytes",
                rule.max_scan_bytes.map(|value| value.to_string()),
            ),
        ] {
            if let Some(value) = value {
                opaque(
                    &mut atoms,
                    "code_execution",
                    field,
                    0,
                    value,
                    "guard-only numeric predicate",
                );
            }
        }
    }
    blocks.push(block(
        "code_execution",
        rules.code_execution.is_some(),
        rules
            .code_execution
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.velocity {
        for (field, value) in [
            (
                "max_invocations_per_window",
                rule.max_invocations_per_window.map(u64::from),
            ),
            ("max_spend_per_window", rule.max_spend_per_window),
            (
                "max_requests_per_agent",
                rule.max_requests_per_agent.map(u64::from),
            ),
            (
                "max_requests_per_session",
                rule.max_requests_per_session.map(u64::from),
            ),
        ] {
            if let Some(value) = value {
                atoms.push(atom(
                    "velocity",
                    field,
                    AtomEffect::Deny,
                    AtomMatcher::NumericRange {
                        lo: value.checked_add(1),
                        hi: None,
                    },
                    field,
                    0,
                    value.to_string(),
                ));
            }
        }
        opaque(
            &mut atoms,
            "velocity",
            "window",
            0,
            rule.window_secs.to_string(),
            "stateful rate-window predicate",
        );
        opaque(
            &mut atoms,
            "velocity",
            "burst_factor",
            0,
            rule.burst_factor.to_string(),
            "stateful rate-window predicate",
        );
    }
    blocks.push(block(
        "velocity",
        rules.velocity.is_some(),
        rules.velocity.as_ref().is_some_and(|rule| rule.enabled),
        atoms,
    ));

    let mut atoms = Vec::new();
    if let Some(rule) = &rules.human_in_loop {
        opaque(
            &mut atoms,
            "human_in_loop",
            "on_timeout",
            0,
            format!("{:?}", rule.on_timeout).to_lowercase(),
            "stateful approval timeout",
        );
        for (index, pattern) in rule.require_confirmation.iter().enumerate() {
            opaque(
                &mut atoms,
                "human_in_loop",
                "require_confirmation",
                index,
                pattern,
                "approval workflow predicate",
            );
        }
        if let Some(value) = rule.approve_above {
            atoms.push(atom(
                "human_in_loop",
                "approve_above",
                AtomEffect::Deny,
                AtomMatcher::NumericRange {
                    lo: value.checked_add(1),
                    hi: None,
                },
                "approve_above",
                0,
                value.to_string(),
            ));
        }
        if let Some(value) = &rule.approve_above_currency {
            opaque(
                &mut atoms,
                "human_in_loop",
                "approve_above_currency",
                0,
                value,
                "approval workflow predicate",
            );
        }
        if let Some(value) = rule.timeout_seconds {
            opaque(
                &mut atoms,
                "human_in_loop",
                "timeout_seconds",
                0,
                value.to_string(),
                "stateful approval timeout",
            );
        }
    }
    blocks.push(block(
        "human_in_loop",
        rules.human_in_loop.is_some(),
        rules
            .human_in_loop
            .as_ref()
            .is_some_and(|rule| rule.enabled),
        atoms,
    ));

    debug_assert_eq!(
        blocks
            .iter()
            .map(|block| block.name.as_str())
            .collect::<Vec<_>>(),
        RULE_BLOCK_NAMES
    );
    LoweredPolicy { blocks }
}
