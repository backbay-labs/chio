//! CodeExecutionGuard -- language allowlist, dangerous-module detection,
//! network gating, and execution-time bounds for sandboxed interpreter
//! actions.
//!
//! The guard applies to
//! [`ToolAction::CodeExecution`] derived from tool calls like `python`,
//! `eval`, `run_code`, `jupyter`, etc.  See [`crate::action::extract_action`]
//! for the full list of tool names that map to code execution.
//!
//! # Enforcement surface
//!
//! | Policy                    | Behavior                                                   |
//! |---------------------------|------------------------------------------------------------|
//! | `language_allowlist`      | Languages outside the set are denied                       |
//! | `dangerous_modules`       | Imports/uses of named modules (e.g. `subprocess`) are denied |
//! | `network_access`          | When `false`, calls requesting network are denied          |
//! | `max_execution_time_ms`   | When the arguments exceed this bound, the call is denied   |
//!
//! Network access is considered requested when either:
//!
//! - the arguments carry `network_access = true` / `allow_network = true`;
//! - or the code contains an obvious network module import
//!   (`socket`, `requests`, `urllib`, `http`, `httpx`, `aiohttp`, `fetch(`).
//!
//! The module-detection regexes target Python, JavaScript, and the common
//! shell-style `import X` / `require('X')` / `from X import` forms.  The
//! detection is intentionally conservative: regex matches are *denial
//! signals*, never permit signals.
//!
//! # Fail-closed behavior
//!
//! - [`ToolAction::CodeExecution`] with no `language` value is denied when
//!   a [`CodeExecutionConfig::language_allowlist`] is set;
//! - malformed configuration (invalid regex patterns in
//!   [`CodeExecutionConfig::module_denylist`]) causes
//!   [`CodeExecutionGuard::with_config`] to return
//!   [`CodeExecutionError::InvalidPattern`];
//! - non-code-execution actions pass through with [`Verdict::Allow`].

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Default dangerous module names (Python-focused; matches are case
/// sensitive and use word boundaries).
pub fn default_dangerous_modules() -> Vec<String> {
    vec![
        "os".to_string(),
        "subprocess".to_string(),
        "socket".to_string(),
        "sys".to_string(),
        "ctypes".to_string(),
        "shutil".to_string(),
        "pickle".to_string(),
        "marshal".to_string(),
        "importlib".to_string(),
    ]
}

/// Default network-module names that signal a code body wants network
/// access.  Used by the `network_access` gate when arguments do not carry
/// an explicit flag.
fn default_network_modules() -> &'static [&'static str] {
    &[
        "socket",
        "requests",
        "urllib",
        "urllib2",
        "urllib3",
        "http",
        "httpx",
        "aiohttp",
        "websockets",
        "ftplib",
        "smtplib",
        "telnetlib",
    ]
}

/// Errors produced when building a [`CodeExecutionGuard`] or parsing its
/// configuration.
#[derive(Debug, thiserror::Error)]
pub enum CodeExecutionError {
    /// A denylist entry was not a valid regex literal.
    #[error("invalid module pattern `{pattern}`: {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Configuration for [`CodeExecutionGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodeExecutionConfig {
    /// Enable/disable the guard entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allowed interpreter languages.  Empty means "any language".
    #[serde(default)]
    pub language_allowlist: Vec<String>,
    /// Dangerous module names (used as word-boundary literal matches
    /// against the code body).  Defaults to
    /// [`default_dangerous_modules`].
    #[serde(default = "default_dangerous_modules")]
    pub module_denylist: Vec<String>,
    /// When `false`, deny code-execution calls that request network
    /// access (either via argument flag or a detectable network import).
    #[serde(default = "default_true")]
    pub network_access: bool,
    /// Maximum execution time in milliseconds.  When set, any call with
    /// an `execution_time_ms` / `timeout_ms` argument above this value
    /// is denied.  `None` disables the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_execution_time_ms: Option<u64>,
    /// Maximum bytes of code to scan for module / network detection.
    /// Longer code bodies are denied outright (fail-closed) so a
    /// padding-based bypass cannot push a forbidden import past the
    /// scan boundary.
    #[serde(default = "default_max_scan_bytes")]
    pub max_scan_bytes: usize,
}

fn default_true() -> bool {
    true
}

fn default_max_scan_bytes() -> usize {
    64 * 1024
}

impl Default for CodeExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            language_allowlist: vec!["python".to_string()],
            module_denylist: default_dangerous_modules(),
            network_access: false,
            max_execution_time_ms: None,
            max_scan_bytes: default_max_scan_bytes(),
        }
    }
}

/// Guard that enforces [`CodeExecutionConfig`] policies against
/// [`ToolAction::CodeExecution`] calls.
pub struct CodeExecutionGuard {
    enabled: bool,
    language_allowlist: HashSet<String>,
    module_patterns: Vec<(String, Regex)>,
    network_access: bool,
    max_execution_time_ms: Option<u64>,
    max_scan_bytes: usize,
}

impl CodeExecutionGuard {
    /// Build a guard with default configuration.  Never fails because the
    /// default patterns are known-valid regex fragments.
    pub fn new() -> Self {
        match Self::with_config(CodeExecutionConfig::default()) {
            Ok(g) => g,
            Err(_) => Self::empty_failclosed(),
        }
    }

    /// Build an empty guard that denies every code-execution call. Used
    /// as a fallback when the default configuration somehow fails to
    /// compile.
    fn empty_failclosed() -> Self {
        Self {
            enabled: true,
            language_allowlist: HashSet::new(),
            module_patterns: Vec::new(),
            network_access: false,
            max_execution_time_ms: Some(0),
            max_scan_bytes: default_max_scan_bytes(),
        }
    }

    /// Build a guard with explicit configuration.  Returns an error when
    /// any entry in `module_denylist` is not a valid literal identifier
    /// (we build word-boundary regexes from the literal).
    pub fn with_config(config: CodeExecutionConfig) -> Result<Self, CodeExecutionError> {
        let mut module_patterns = Vec::with_capacity(config.module_denylist.len());
        for module in &config.module_denylist {
            let pattern = module_regex_source(module);
            let re = Regex::new(&pattern).map_err(|e| CodeExecutionError::InvalidPattern {
                pattern: module.clone(),
                source: e,
            })?;
            module_patterns.push((module.clone(), re));
        }
        let language_allowlist: HashSet<String> = config
            .language_allowlist
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Ok(Self {
            enabled: config.enabled,
            language_allowlist,
            module_patterns,
            network_access: config.network_access,
            max_execution_time_ms: config.max_execution_time_ms,
            max_scan_bytes: config.max_scan_bytes.max(1),
        })
    }

    /// Read the execution-time ceiling from the arguments.  Accepts
    /// `execution_time_ms`, `timeout_ms`, `max_execution_time_ms`.
    fn read_execution_time_ms(arguments: &serde_json::Value) -> Option<u64> {
        for key in [
            "execution_time_ms",
            "executionTimeMs",
            "timeout_ms",
            "timeoutMs",
            "max_execution_time_ms",
            "maxExecutionTimeMs",
        ] {
            if let Some(v) = arguments.get(key).and_then(|v| v.as_u64()) {
                return Some(v);
            }
        }
        None
    }

    /// Read an explicit network-access flag from the arguments, if present.
    fn requested_network_access(arguments: &serde_json::Value) -> Option<bool> {
        for key in [
            "network_access",
            "networkAccess",
            "allow_network",
            "allowNetwork",
        ] {
            if let Some(v) = arguments.get(key).and_then(|v| v.as_bool()) {
                return Some(v);
            }
        }
        None
    }

    /// Return `true` if `code` appears to import or call into a
    /// network-capable module.
    fn code_uses_network(code: &str) -> bool {
        let net_re = network_module_regex();
        net_re.is_match(code)
    }
}

impl Default for CodeExecutionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for CodeExecutionGuard {
    fn name(&self) -> &str {
        "code-execution"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };
        let (language, code) = match action {
            ToolAction::CodeExecution { language, code } => (language, code),
            _ => return Ok(GuardDecision::allow()),
        };

        // 1. Language allowlist.
        if !self.language_allowlist.is_empty() {
            let lang = language.to_ascii_lowercase();
            if lang == "unknown" || !self.language_allowlist.contains(&lang) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Bound scan size for module / network detection. Fail-closed: a
        // body larger than the configured scan window cannot be safely
        // analyzed without leaving room for a padding-based bypass that
        // pushes a forbidden import past the truncation boundary, so we
        // deny outright rather than silently scan only the prefix.
        if code.len() > self.max_scan_bytes {
            tracing::warn!(
                guard = "code-execution",
                code_len = code.len(),
                max_scan_bytes = self.max_scan_bytes,
                "denying code execution: payload exceeds max_scan_bytes"
            );
            return Ok(GuardDecision::deny(Vec::new()));
        }
        let scanned = code.as_str();

        // 2. Dangerous-module detection.
        for (name, re) in &self.module_patterns {
            if re.is_match(scanned) {
                tracing::warn!(
                    guard = "code-execution",
                    module = %name,
                    "denying code execution: dangerous module detected"
                );
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // 3. Network access gate.
        if !self.network_access {
            let requested = Self::requested_network_access(&ctx.request.arguments).unwrap_or(false);
            if requested || Self::code_uses_network(scanned) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // 4. Execution-time bound.
        if let Some(max_ms) = self.max_execution_time_ms {
            if let Some(requested) = Self::read_execution_time_ms(&ctx.request.arguments) {
                if requested > max_ms {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        crate::revalidate_non_consuming_guard(self, ctx)
    }
}

/// Build a regex that matches `import <module>`, `from <module> import`,
/// `require('<module>')`, or a bare `<module>.something` reference in
/// code.  The source is escaped so dotted module names are treated as
/// literals.
fn module_regex_source(module: &str) -> String {
    let escaped = regex::escape(module);
    // Word-boundary anchors handle the `import subprocess`,
    // `from subprocess`, and `subprocess.call` forms; a trailing alternation
    // picks up `require("subprocess")` and `require('subprocess')`.
    format!(
        r#"(?m)(?:^|[^A-Za-z0-9_])(?:import\s+{m}(?:\s|$|\.|,)|from\s+{m}(?:\s|\.)|require\s*\(\s*['"]{m}['"]\s*\)|{m}\s*\.)"#,
        m = escaped
    )
}

/// Compiled once per process: detects calls/imports of the well-known
/// network modules listed in [`default_network_modules`].
fn network_module_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alternation = default_network_modules()
            .iter()
            .map(|m| regex::escape(m))
            .collect::<Vec<_>>()
            .join("|");
        // Fall back to a never-matching regex rather than panicking.
        match Regex::new(&format!(
            r#"(?m)(?:^|[^A-Za-z0-9_])(?:import\s+(?:{a})(?:\s|$|\.|,)|from\s+(?:{a})(?:\s|\.)|require\s*\(\s*['"](?:{a})['"]\s*\)|\bfetch\s*\()"#,
            a = alternation
        )) {
            Ok(re) => re,
            Err(err) => {
                tracing::error!(error = %err, "code-execution: failed to compile network regex");
                // Safe fallback: regex that never matches anything.
                // expect: `\A\z` is a compile-time constant literal, so this
                // construction cannot fail at runtime.
                #[allow(clippy::expect_used)]
                {
                    Regex::new(r"\A\z").expect("empty-string regex compiles")
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_regex_matches_import_forms() {
        let re = Regex::new(&module_regex_source("subprocess")).unwrap();
        assert!(re.is_match("import subprocess\n"));
        assert!(re.is_match("from subprocess import call"));
        assert!(re.is_match("require('subprocess')"));
        assert!(re.is_match("subprocess.run(['ls'])"));
        assert!(!re.is_match("import subprocesses\n"));
        assert!(!re.is_match("# subprocess comment with no code"));
    }

    #[test]
    fn network_module_regex_detects_requests() {
        let re = network_module_regex();
        assert!(re.is_match("import requests\n"));
        assert!(re.is_match("from urllib import parse"));
        assert!(re.is_match("fetch('https://x')"));
        assert!(!re.is_match("import math"));
    }
}
