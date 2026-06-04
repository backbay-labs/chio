//! HushSpec policy schema types.
//!
//! Ported from the HushSpec reference implementation. These types define the
//! canonical YAML schema for AI agent security policies.

use std::collections::BTreeMap;

use chio_core::appraisal::AttestationVerifierFamily;
use chio_core::capability::{
    MonetaryAmount, RuntimeAssuranceTier, WorkloadCredentialKind, WorkloadIdentityScheme,
};
use serde::{Deserialize, Serialize};

const MAX_QUOTED_SCALAR_WHITESPACE_RUN: usize = 64;
const MAX_PLAIN_SCALAR_KEY_WHITESPACE_RUN: usize = 5;
const MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN: usize = 64;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    Replace,
    Merge,
    #[default]
    DeepMerge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Error,
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseMode {
    Observe,
    #[default]
    Guardrail,
    FailClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    Timeout,
    BudgetExhausted,
    PatternMatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OriginDefaultBehavior {
    #[default]
    Deny,
    MinimalProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionLevel {
    Safe,
    Suspicious,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Draft,
    Review,
    Approved,
    Deployed,
    Deprecated,
    Archived,
}

// ---------------------------------------------------------------------------
// Top-level spec
// ---------------------------------------------------------------------------

/// A HushSpec policy document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HushSpec {
    pub hushspec: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GovernanceMetadata>,
}

impl HushSpec {
    /// Parse a HushSpec document from a YAML string.
    pub fn parse(yaml: &str) -> Result<Self, serde_yml::Error> {
        if has_non_mapping_document_start(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML policy must start with a mapping",
            ));
        }
        if has_unclosed_double_quoted_value_scalar(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML contains an unterminated double-quoted scalar",
            ));
        }
        if has_libyml_scalar_join_overflow_risk(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML contains an unsupported scalar whitespace run",
            ));
        }

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serde_yml::from_str(yaml)))
            .unwrap_or_else(|_| {
                Err(<serde_yml::Error as serde::de::Error>::custom(
                    "YAML parser panicked while parsing policy",
                ))
            })
    }

    /// Serialize this spec to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yml::Error> {
        serde_yml::to_string(self)
    }
}

fn has_non_mapping_document_start(input: &str) -> bool {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        if trimmed == "---" || trimmed == "..." {
            continue;
        }

        let document_start = trimmed.strip_prefix("---").map(str::trim_start);
        let mut candidate = strip_inline_comment(document_start.unwrap_or(trimmed)).trim();
        candidate = strip_yaml_node_properties(candidate);
        if candidate.is_empty() || candidate.starts_with('#') {
            continue;
        }
        if candidate.starts_with('{')
            || explicit_mapping_key_start(candidate)
            || structural_mapping_colon_index(candidate).is_some()
        {
            return false;
        }
        return true;
    }

    false
}

fn has_unclosed_double_quoted_value_scalar(input: &str) -> bool {
    let mut open_double_quote_indent: Option<usize> = None;
    let mut block_scalar_parent_indent: Option<usize> = None;

    for line in input.lines() {
        let indent = leading_whitespace_len(line);
        let trimmed = line.trim_start();
        if let Some(parent_indent) = block_scalar_parent_indent {
            if trimmed.is_empty() || indent > parent_indent {
                continue;
            }
            block_scalar_parent_indent = None;
        }

        if open_double_quote_indent.is_none() {
            if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
                block_scalar_parent_indent = Some(parent_indent);
                continue;
            }
        }

        let scan_from = if open_double_quote_indent.is_some() {
            0
        } else if let Some(start) = double_quoted_value_start(line) {
            open_double_quote_indent = Some(indent);
            start + 1
        } else {
            continue;
        };

        if double_quote_state_closes_on_line(line, scan_from) {
            open_double_quote_indent = None;
        }
    }

    open_double_quote_indent.is_some()
}

fn has_libyml_scalar_join_overflow_risk(input: &str) -> bool {
    has_libyml_plain_scalar_join_overflow_risk(input)
        || has_libyml_quoted_scalar_join_overflow_risk(input)
}

fn explicit_mapping_key_start(candidate: &str) -> bool {
    let Some(rest) = candidate.strip_prefix('?') else {
        return false;
    };

    rest.is_empty()
        || match rest.chars().next() {
            Some(ch) => ch.is_whitespace(),
            None => true,
        }
}

fn strip_yaml_node_properties(mut candidate: &str) -> &str {
    loop {
        let trimmed = candidate.trim_start();
        let Some(first) = trimmed.chars().next() else {
            return trimmed;
        };
        if first != '&' && first != '!' {
            return trimmed;
        }
        let token_end = trimmed
            .char_indices()
            .find_map(|(index, ch)| ch.is_whitespace().then_some(index))
            .unwrap_or(trimmed.len());
        candidate = &trimmed[token_end..];
    }
}

fn has_libyml_plain_scalar_join_overflow_risk(input: &str) -> bool {
    let mut block_scalar_parent_indent: Option<usize> = None;
    let mut plain_value_parent_indent: Option<usize> = None;

    for line in input.lines() {
        let indent = leading_whitespace_len(line);
        let trimmed = line.trim_start();
        if let Some(parent_indent) = block_scalar_parent_indent {
            if trimmed.is_empty() || indent > parent_indent {
                continue;
            }
            block_scalar_parent_indent = None;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if plain_value_parent_indent.is_some_and(|parent_indent| indent <= parent_indent) {
            plain_value_parent_indent = None;
        }
        if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
            block_scalar_parent_indent = Some(parent_indent);
            plain_value_parent_indent = None;
            continue;
        }

        if let Some(colon_index) = structural_mapping_colon_index(line) {
            plain_value_parent_indent = None;
            if plain_scalar_text_has_join_overflow_risk(&line[..colon_index]) {
                return true;
            }
            let plain_value = strip_inline_comment(&line[colon_index + 1..]);
            if plain_scalar_value_has_join_overflow_risk(plain_value) {
                return true;
            }
            if plain_scalar_can_continue(plain_value) {
                plain_value_parent_indent = Some(indent);
            }
        } else if plain_value_parent_indent.is_some_and(|parent_indent| indent > parent_indent) {
            if plain_scalar_value_has_join_overflow_risk(trimmed) {
                return true;
            }
        } else if plain_scalar_text_has_join_overflow_risk(trimmed) {
            return true;
        }
    }

    false
}

fn plain_scalar_text_has_join_overflow_risk(input: &str) -> bool {
    plain_scalar_text_has_join_overflow_risk_with_limit(
        input,
        MAX_PLAIN_SCALAR_KEY_WHITESPACE_RUN + 1,
    )
}

fn plain_scalar_value_has_join_overflow_risk(input: &str) -> bool {
    plain_scalar_text_has_join_overflow_risk_with_limit(
        input,
        MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1,
    )
}

fn plain_scalar_text_has_join_overflow_risk_with_limit(input: &str, minimum_run: usize) -> bool {
    let trimmed = input.trim();
    if !plain_scalar_can_continue(trimmed) {
        return false;
    }

    has_ascii_whitespace_run(trimmed, minimum_run)
}

fn plain_scalar_can_continue(input: &str) -> bool {
    let trimmed = input.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('"')
        && !trimmed.starts_with('\'')
        && !trimmed.starts_with('[')
        && !trimmed.starts_with('{')
        && !trimmed.starts_with('-')
}

fn has_ascii_whitespace_run(input: &str, minimum_run: usize) -> bool {
    let mut run = 0usize;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            run += 1;
            if run >= minimum_run {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_libyml_quoted_scalar_join_overflow_risk(input: &str) -> bool {
    let mut block_scalar_parent_indent: Option<usize> = None;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut whitespace_run = 0usize;

    let mut lines = input.lines().peekable();
    while let Some(line) = lines.next() {
        if !in_single && !in_double {
            let indent = leading_whitespace_len(line);
            let trimmed = line.trim_start();
            if let Some(parent_indent) = block_scalar_parent_indent {
                if trimmed.is_empty() || indent > parent_indent {
                    continue;
                }
                block_scalar_parent_indent = None;
            }

            if trimmed.starts_with('#') {
                continue;
            }
            if let Some(parent_indent) = block_scalar_parent_indent_start(line) {
                block_scalar_parent_indent = Some(parent_indent);
                continue;
            }
        }

        let mut chars = line.char_indices().peekable();
        let mut previous_is_whitespace = false;
        while let Some((index, ch)) = chars.next() {
            if in_single {
                if ch == '\'' {
                    if matches!(chars.peek(), Some((_, '\''))) {
                        let _ = chars.next();
                        whitespace_run = 0;
                    } else {
                        in_single = false;
                        whitespace_run = 0;
                    }
                } else if ch.is_ascii_whitespace() {
                    whitespace_run += 1;
                    if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                        return true;
                    }
                } else {
                    whitespace_run = 0;
                }
                previous_is_whitespace = false;
                continue;
            }

            if escaped {
                escaped = false;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }

            if in_double {
                match ch {
                    '\\' => {
                        escaped = true;
                        whitespace_run = 0;
                    }
                    '"' => {
                        in_double = false;
                        whitespace_run = 0;
                    }
                    ch if ch.is_ascii_whitespace() => {
                        whitespace_run += 1;
                        if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                            return true;
                        }
                    }
                    _ => {
                        whitespace_run = 0;
                    }
                }
                previous_is_whitespace = false;
                continue;
            }

            if ch == '#' && previous_is_whitespace {
                break;
            }
            if ch == '\'' && quote_starts_yaml_scalar(line, index) {
                in_single = true;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }
            if ch == '"' && quote_starts_yaml_scalar(line, index) {
                in_double = true;
                whitespace_run = 0;
                previous_is_whitespace = false;
                continue;
            }
            previous_is_whitespace = ch.is_ascii_whitespace();
        }

        if in_single || in_double {
            if escaped {
                escaped = false;
            } else if lines.peek().is_some() {
                whitespace_run += 1;
                if whitespace_run > MAX_QUOTED_SCALAR_WHITESPACE_RUN {
                    return true;
                }
            }
        }
    }

    false
}

fn quote_starts_yaml_scalar(line: &str, quote_index: usize) -> bool {
    let before_quote = line[..quote_index].trim_end();
    let Some(previous) = before_quote.chars().last() else {
        return true;
    };

    matches!(previous, ':' | '[' | '{' | ',') || sequence_item_scalar_prefix(before_quote)
}

fn leading_whitespace_len(input: &str) -> usize {
    input
        .chars()
        .take_while(|ch| ch.is_ascii_whitespace() && *ch != '\n')
        .map(char::len_utf8)
        .sum()
}

fn block_scalar_parent_indent_start(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }

    if sequence_block_scalar_start(trimmed) {
        return Some(leading_whitespace_len(line));
    }

    let colon_index = structural_mapping_colon_index(line)?;
    let after_colon = line[colon_index + 1..].trim_start();
    if !(after_colon.starts_with('|') || after_colon.starts_with('>')) {
        return None;
    }

    Some(leading_whitespace_len(line))
}

fn sequence_block_scalar_start(trimmed_line: &str) -> bool {
    let Some(rest) = trimmed_line.strip_prefix('-') else {
        return false;
    };
    let Some(separator) = rest.chars().next() else {
        return false;
    };
    if !separator.is_ascii_whitespace() {
        return false;
    }

    let after_dash = rest.trim_start();
    after_dash.starts_with('|') || after_dash.starts_with('>')
}

fn double_quoted_value_start(line: &str) -> Option<usize> {
    if line.trim_start().starts_with('#') {
        return None;
    }

    if let Some(colon_index) = structural_mapping_colon_index(line) {
        let after_colon = &line[colon_index + 1..];
        let value_offset = after_colon.len() - after_colon.trim_start().len();
        let value_index = colon_index + 1 + value_offset;
        return line[value_index..].starts_with('"').then_some(value_index);
    }

    let quote_index = line.find('"')?;
    let prefix = &line[..quote_index];

    sequence_item_scalar_prefix(prefix).then_some(quote_index)
}

fn sequence_item_scalar_prefix(prefix: &str) -> bool {
    let mut rest = prefix.trim_start();

    loop {
        let Some(after_dash) = rest.strip_prefix('-') else {
            return false;
        };

        let Some(separator) = after_dash.chars().next() else {
            return true;
        };
        if !separator.is_ascii_whitespace() {
            return false;
        }

        rest = after_dash.trim_start();
        if rest.is_empty() {
            return true;
        }
        if !rest.starts_with('-') {
            return false;
        }
    }
}

fn structural_mapping_colon_index(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut chars = line.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if in_single {
            if ch == '\'' {
                if matches!(chars.peek(), Some((_, '\''))) {
                    let _ = chars.next();
                } else {
                    in_single = false;
                }
            }
            continue;
        }

        if in_double {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            ':' if yaml_mapping_separator(chars.peek().map(|(_, next)| *next)) => {
                return Some(index);
            }
            _ => {}
        }
    }

    None
}

fn yaml_mapping_separator(next: Option<char>) -> bool {
    match next {
        Some(ch) => ch.is_whitespace(),
        None => true,
    }
}

fn double_quote_state_closes_on_line(line: &str, mut scan_from: usize) -> bool {
    loop {
        let Some(close_offset) = first_unescaped_double_quote(&line[scan_from..]) else {
            return false;
        };
        let after_close = scan_from + close_offset + 1;
        let rest_before_comment = strip_inline_comment(&line[after_close..]);
        let Some(next_quote_offset) = first_unescaped_double_quote(rest_before_comment) else {
            return true;
        };
        scan_from = after_close + next_quote_offset + 1;
    }
}

fn first_unescaped_double_quote(input: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(index);
        }
    }

    None
}

fn strip_inline_comment(input: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut previous_is_whitespace = false;
    let mut chars = input.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        if in_single {
            if ch == '\'' {
                if matches!(chars.peek(), Some((_, '\''))) {
                    let _ = chars.next();
                } else {
                    in_single = false;
                }
            }
            previous_is_whitespace = false;
            continue;
        }

        if escaped {
            escaped = false;
            previous_is_whitespace = false;
            continue;
        }

        if in_double {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            previous_is_whitespace = false;
            continue;
        }

        if ch == '\'' {
            in_single = true;
            previous_is_whitespace = false;
            continue;
        }
        if ch == '"' {
            in_double = true;
            previous_is_whitespace = false;
            continue;
        }
        if ch == '#' && previous_is_whitespace {
            return &input[..index];
        }
        previous_is_whitespace = ch.is_ascii_whitespace();
    }

    input
}

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

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<OriginsExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<RuntimeAssuranceExtension>,
    /// Chio-specific extension slot. The kernel does not interpret this
    /// block; it is carried verbatim for chio-bridge consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio: Option<ChioExtension>,
}

// ---------------------------------------------------------------------------
// Chio extension
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChioExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_hours: Option<ChioMarketHours>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<ChioSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k8s_namespaces: Option<ChioK8sNamespaces>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<ChioRollback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_in_loop: Option<ChioHumanInLoopAdvanced>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioMarketHours {
    pub tz: String,
    pub open: String,
    pub close: String,
    #[serde(default)]
    pub days: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioSigning {
    pub algo: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioK8sNamespaces {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub human_in_loop: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioRollback {
    #[serde(default)]
    pub on_guard_fail: bool,
    #[serde(default)]
    pub on_timeout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChioHumanInLoopAdvanced {
    #[serde(default)]
    pub approve_when: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvers: Option<ChioApproverSet>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioApproverSet {
    pub n: u32,
    #[serde(default)]
    pub of: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureExtension {
    pub initial: String,
    pub states: BTreeMap<String, PostureState>,
    pub transitions: Vec<PostureTransition>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub budgets: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransition {
    pub from: String,
    pub to: String,
    pub on: TransitionTrigger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginsExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_behavior: Option<OriginDefaultBehavior>,
    #[serde(default)]
    pub profiles: Vec<OriginProfile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    pub id: String,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub match_rules: Option<OriginMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<OriginDataPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<OriginBudgets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginDataPolicy {
    #[serde(default)]
    pub allow_external_sharing: bool,
    #[serde(default)]
    pub redact_before_send: bool,
    #[serde(default)]
    pub block_sensitive_outputs: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginBudgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    #[serde(default)]
    pub allow_cross_origin: bool,
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_injection: Option<PromptInjectionDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jailbreak: Option<JailbreakDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<ThreatIntelDetection>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<ReputationScoringConfig>,
    #[serde(default)]
    pub tiers: BTreeMap<String, ReputationTier>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationScoringConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights: Option<ReputationWeights>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_decay_half_life_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_receipt_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_min_days: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationWeights {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_stewardship: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_depth: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_diversity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_correlation: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTier {
    pub score_range: [f64; 2],
    pub max_scope: ReputationTierScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ReputationPromotion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demotion: Option<ReputationDemotion>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTierScope {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationPromotion {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_receipts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_metrics: Option<ReputationRequiredMetrics>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationRequiredMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure_max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene_min: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationDemotion {
    pub target: String,
    #[serde(default)]
    pub triggers: Vec<ReputationTrigger>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTrigger {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceExtension {
    #[serde(default)]
    pub tiers: BTreeMap<String, RuntimeAssuranceTierRule>,
    #[serde(default)]
    pub trusted_verifiers: BTreeMap<String, RuntimeAssuranceVerifierRule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceTierRule {
    pub minimum_attestation_tier: RuntimeAssuranceTier,
    pub max_scope: ReputationTierScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceVerifierRule {
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default)]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default)]
    pub required_assertions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scan_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
}

// ---------------------------------------------------------------------------
// Governance metadata
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
}

// ---------------------------------------------------------------------------
// Default value helpers
// ---------------------------------------------------------------------------

fn default_1000() -> usize {
    1000
}

fn default_500() -> usize {
    500
}

fn default_allow() -> DefaultAction {
    DefaultAction::Allow
}

fn default_block() -> DefaultAction {
    DefaultAction::Block
}

fn default_guardrail() -> ComputerUseMode {
    ComputerUseMode::Guardrail
}

fn default_imbalance_ratio() -> f64 {
    10.0
}

fn default_true() -> bool {
    true
}

fn default_velocity_window_secs() -> u64 {
    60
}

fn default_burst_factor() -> f64 {
    1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_fuzz_policy_parse_compile_bbaf353() {
        let input = concat!(
            "hushnarrspec: \"0.",
            "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%",
            "scription: Allow a narro     - r      - \"**/.git/*ist_directory\n",
        );

        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn regression_fuzz_policy_parse_compile_2c7fd63() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: block-all\n",
            "description: Deny every tool by default.           currency: \"U\n",
            "    enabled: true\n",
            "    default: block\n",
        );

        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn parse_allows_plain_scalar_with_unpaired_double_quote() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: quoted-description\n",
            "description: A valid plain scalar with a single \" character\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("plain scalar quotes should parse: {err}"),
        };
        assert_eq!(
            spec.description.as_deref(),
            Some("A valid plain scalar with a single \" character")
        );
    }

    #[test]
    fn parse_allows_plain_scalar_continuation_starting_with_quote() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: multiline-description\n",
            "description: first line\n",
            "  \"second line\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("plain scalar continuation quote should parse: {err}"),
        };
        assert_eq!(
            spec.description.as_deref(),
            Some("first line \"second line")
        );
    }

    #[test]
    fn regression_fuzz_policy_parse_compile_67a1282() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: malformed-sequence-quote\n",
            "rules:\n",
            "  forbidden_paths:\n",
            "    enabled: true\n",
            "    patterns:\n",
            "      - \"**.g. cents). Uncomment to rate-limit invocations or spend.\n",
            "  # human_in_loop:\n",
            "  #   require_confirmation: [\"write_*\", \"run_command\"]\n",
        );

        assert!(has_unclosed_double_quoted_value_scalar(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn regression_fuzz_policy_parse_compile_e8a595c() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.{spaces}1.0\"\n\
             name: base\n\n\
             rules:\n\
               shell_commands:\n\
                 enabled: true\n\
               tool_access:\n\
                 enabled: true\n\
                 default: block\n\
                (allow:\n\
                   - read_file\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn parse_allows_single_quoted_scalar_with_double_quote() {
        let spaces = " ".repeat(8);
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             name: single-quoted-description\n\
             description: 'prefix \"{spaces}suffix'\n"
        );

        assert!(!has_libyml_scalar_join_overflow_risk(&input));
        let spec = match HushSpec::parse(&input) {
            Ok(spec) => spec,
            Err(err) => panic!("single quoted scalar should parse: {err}"),
        };
        let expected = format!("prefix \"{spaces}suffix");
        assert_eq!(spec.description.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn parse_rejects_plain_root_scalar_before_libyml() {
        let input = "hushsiption      t\n";

        assert!(has_non_mapping_document_start(input));
        assert!(has_libyml_scalar_join_overflow_risk(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn parse_rejects_plain_root_url_before_libyml() {
        let input = "https://example.com/policy\n";

        assert!(has_non_mapping_document_start(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn parse_rejects_plain_mapping_key_join_before_libyml() {
        let input = concat!("hushspec: \"0.1.0\"\n", "description      min_days: 30\n");

        assert!(!has_non_mapping_document_start(input));
        assert!(has_libyml_scalar_join_overflow_risk(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn parse_rejects_plain_mapping_value_join_before_libyml() {
        let spaces = " ".repeat(MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\nname: value-overflow\nrules:\n  shell_commands:\n    enabled: t{spaces}rue\n"
        );

        assert!(!has_non_mapping_document_start(&input));
        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn parse_allows_plain_mapping_value_with_normal_spacing() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: spaced-description\n",
            "description: hello      world\n",
        );

        assert!(!has_libyml_scalar_join_overflow_risk(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("plain spaced value should parse: {err}"),
        };
        assert_eq!(spec.description.as_deref(), Some("hello      world"));
    }

    #[test]
    fn parse_allows_plain_mapping_value_continuation_with_normal_spacing() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: multiline-spaced-description\n",
            "description: first line\n",
            "  second      line\n",
        );

        assert!(!has_libyml_scalar_join_overflow_risk(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("plain spaced value continuation should parse: {err}"),
        };
        assert_eq!(
            spec.description.as_deref(),
            Some("first line second      line")
        );
    }

    #[test]
    fn rules_block_helpers_cover_conditionable_rule_blocks() {
        let mut rules = Rules::default();
        assert!(!rules.has_configured_blocks());

        rules.tool_access = Some(ToolAccessRule {
            enabled: true,
            allow: Vec::new(),
            block: Vec::new(),
            require_confirmation: Vec::new(),
            default: DefaultAction::Allow,
            max_args_size: None,
            require_runtime_assurance_tier: None,
            prefer_runtime_assurance_tier: None,
            require_workload_identity: None,
            prefer_workload_identity: None,
        });
        assert!(rules.has_configured_blocks());
        assert!(rules.clear_block("tool_access"));
        assert!(!rules.has_configured_blocks());

        assert_eq!(RULE_BLOCK_NAMES.len(), 14);
        for block_name in RULE_BLOCK_NAMES {
            let mut empty_rules = Rules::default();
            assert!(
                empty_rules.clear_block(block_name),
                "missing clear_block arm for {block_name}"
            );
        }

        let mut empty_rules = Rules::default();
        assert!(!empty_rules.clear_block("misspelled_rule_block"));
    }

    #[test]
    fn parse_rejects_plain_mapping_value_continuation_join_before_libyml() {
        let spaces = " ".repeat(MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\nname: value-overflow\n\
             description: first line\n  second{spaces}line\n"
        );

        assert!(!has_non_mapping_document_start(&input));
        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn parse_allows_document_marker_before_mapping() {
        let input = concat!(
            "--- # policy document\n",
            "hushspec: \"0.1.0\"\n",
            "name: document-marker-policy\n"
        );

        assert!(!has_non_mapping_document_start(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("document marker policy should parse: {err}"),
        };
        assert_eq!(spec.name.as_deref(), Some("document-marker-policy"));
    }

    #[test]
    fn parse_allows_document_marker_properties_before_mapping() {
        let input = concat!(
            "--- &base !!map\n",
            "hushspec: \"0.1.0\"\n",
            "name: document-property-policy\n"
        );

        assert!(!has_non_mapping_document_start(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("document properties before mapping should parse: {err}"),
        };
        assert_eq!(spec.name.as_deref(), Some("document-property-policy"));
    }

    #[test]
    fn parse_allows_root_properties_before_mapping() {
        let input = concat!(
            "&base !!map\n",
            "hushspec: \"0.1.0\"\n",
            "name: root-property-policy\n"
        );

        assert!(!has_non_mapping_document_start(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("root properties before mapping should parse: {err}"),
        };
        assert_eq!(spec.name.as_deref(), Some("root-property-policy"));
    }

    #[test]
    fn parse_allows_explicit_key_mapping_start() {
        let input = concat!(
            "? hushspec\n",
            ": \"0.1.0\"\n",
            "name: explicit-key-policy\n",
        );

        assert!(!has_non_mapping_document_start(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("explicit-key mapping should parse: {err}"),
        };
        assert_eq!(spec.name.as_deref(), Some("explicit-key-policy"));
    }

    #[test]
    fn parse_allows_first_mapping_value_with_colon() {
        let input = concat!(
            "description: https://example.com/a:b\n",
            "hushspec: \"0.1.0\"\n",
            "name: url-first-policy\n",
        );

        assert!(!has_non_mapping_document_start(input));
        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("colon-containing mapping value should parse: {err}"),
        };
        assert_eq!(spec.description.as_deref(), Some("https://example.com/a:b"));
    }

    #[test]
    fn document_start_check_keeps_hash_inside_quoted_key() {
        let input = "\"key # name\": value\n";

        assert!(!has_non_mapping_document_start(input));
        assert_eq!(
            strip_inline_comment("\"key # name\": value # trailing"),
            "\"key # name\": value "
        );
    }

    #[test]
    fn parse_allows_block_scalar_with_quoted_long_spaces() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\nname: block-scalar-description\ndescription: |\n  \"prefix{spaces}suffix\"\n"
        );

        assert!(!has_libyml_scalar_join_overflow_risk(&input));
        let spec = match HushSpec::parse(&input) {
            Ok(spec) => spec,
            Err(err) => panic!("block scalar with quoted content should parse: {err}"),
        };
        let expected = format!("\"prefix{spaces}suffix\"\n");
        assert_eq!(spec.description.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn single_quoted_whitespace_overflow_rejected_before_libyml() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             name: single-quoted-description\n\
             description: 'prefix \"{spaces}suffix'\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn quoted_whitespace_overflow_counts_folded_line_break() {
        let left_spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN / 2);
        let right_spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN - left_spaces.len());
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             name: folded-quoted-whitespace\n\
             description: \"prefix{left_spaces}\n{right_spaces}suffix\"\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn quoted_whitespace_overflow_resets_escaped_line_break() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             name: escaped-folded-quoted-whitespace\n\
             description: \"prefix\\\n{spaces}suffix\"\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn overflow_precheck_resumes_after_single_quoted_scalar() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             description: 'has \" inside'\n\
             name: \"bad{spaces}name\"\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn unclosed_double_quote_precheck_detects_nested_sequence_items() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: nested-sequence-quote\n",
            "metadata:\n",
            "  tags:\n",
            "    - - \"unclosed\n",
        );

        assert!(has_unclosed_double_quoted_value_scalar(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn quoted_whitespace_overflow_rejected_in_nested_sequence_item() {
        let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
        let input = format!(
            "hushspec: \"0.1.0\"\n\
             name: nested-sequence-quote\n\
             metadata:\n\
               tags:\n\
                 - - \"prefix{spaces}suffix\"\n"
        );

        assert!(has_libyml_scalar_join_overflow_risk(&input));
        assert!(HushSpec::parse(&input).is_err());
    }

    #[test]
    fn parse_allows_multiline_quoted_scalar_comment_content() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: multiline-quoted-description\n",
            "description: \"first\n",
            "# second\"\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("comment-like quoted continuation should parse: {err}"),
        };
        assert_eq!(spec.description.as_deref(), Some("first # second"));
    }

    #[test]
    fn quote_precheck_scans_after_closed_scalar_on_same_line() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: second-unclosed-quote\n",
            "description: \"closed\" \"unclosed\n",
        );

        assert!(has_unclosed_double_quoted_value_scalar(input));
        assert!(HushSpec::parse(input).is_err());
        assert!(!has_unclosed_double_quoted_value_scalar(
            "description: \"closed\" # \"comment text\n"
        ));
        assert!(has_unclosed_double_quoted_value_scalar(
            "description: \"closed\"#\"unclosed\n"
        ));
    }

    #[test]
    fn quote_precheck_handles_double_quoted_mapping_key() {
        let input = concat!("hushspec: \"0.1.0\"\n", "\"name\": \"unclosed-policy\n",);

        assert!(has_unclosed_double_quoted_value_scalar(input));
        assert!(HushSpec::parse(input).is_err());
    }

    #[test]
    fn parse_allows_hash_inside_double_quoted_scalar() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: quoted-description\n",
            "description: \"A quoted scalar with # as data\"\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("quoted scalar hash should parse: {err}"),
        };
        assert_eq!(
            spec.description.as_deref(),
            Some("A quoted scalar with # as data")
        );
    }

    #[test]
    fn parse_allows_block_scalar_with_unpaired_double_quote() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: block-description\n",
            "description: |\n",
            "  A valid block scalar with a single \" character\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("block scalar quotes should parse: {err}"),
        };
        assert_eq!(
            spec.description.as_deref(),
            Some("A valid block scalar with a single \" character\n")
        );
    }

    #[test]
    fn parse_allows_block_scalar_for_quoted_key_with_colon() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: quoted-key-block-scalar\n",
            "extensions:\n",
            "  runtime_assurance:\n",
            "    trusted_verifiers:\n",
            "      local:\n",
            "        schema: local\n",
            "        verifier: test\n",
            "        effective_tier: verified\n",
            "        required_assertions:\n",
            "          \"a:b\": |\n",
            "            foo: \"bar\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("quoted key block scalar should parse: {err}"),
        };
        let value = spec
            .extensions
            .and_then(|extensions| extensions.runtime_assurance)
            .and_then(|runtime_assurance| runtime_assurance.trusted_verifiers.get("local").cloned())
            .and_then(|verifier| verifier.required_assertions.get("a:b").cloned());
        assert_eq!(value.as_deref(), Some("foo: \"bar\n"));
    }

    #[test]
    fn parse_allows_sequence_block_scalar_with_unpaired_double_quote() {
        let input = concat!(
            "hushspec: \"0.1.0\"\n",
            "name: sequence-block-pattern\n",
            "rules:\n",
            "  shell_commands:\n",
            "    forbidden_patterns:\n",
            "      - |\n",
            "        \"quoted regex text\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("sequence block scalar quotes should parse: {err}"),
        };
        let rules = match spec.rules {
            Some(rules) => rules,
            None => panic!("rules should parse"),
        };
        let shell_commands = match rules.shell_commands {
            Some(shell_commands) => shell_commands,
            None => panic!("shell command rules should parse"),
        };
        assert_eq!(
            shell_commands.forbidden_patterns,
            vec!["\"quoted regex text\n".to_string()]
        );
    }

    #[test]
    fn parse_allows_comment_line_with_unpaired_double_quote() {
        let input = concat!(
            "# note: \"comment-only quote\n",
            "hushspec: \"0.1.0\"\n",
            "name: comment-description\n",
            "description: Valid policy\n",
        );

        let spec = match HushSpec::parse(input) {
            Ok(spec) => spec,
            Err(err) => panic!("comment-only quote should parse: {err}"),
        };
        assert_eq!(spec.name.as_deref(), Some("comment-description"));
    }

    #[test]
    fn block_scalar_detection_uses_last_colon() {
        assert!(block_scalar_parent_indent_start("description: |").is_some());
        assert!(block_scalar_parent_indent_start("\"a:b\": |").is_some());
        assert!(block_scalar_parent_indent_start("'a:b': |").is_some());
        assert!(block_scalar_parent_indent_start("  - |").is_some());
        assert!(block_scalar_parent_indent_start("  - >").is_some());
        assert!(block_scalar_parent_indent_start("  - not-block").is_none());
        assert!(block_scalar_parent_indent_start("# note: |").is_none());
        assert!(block_scalar_parent_indent_start("description: nested: |").is_none());
    }
}
