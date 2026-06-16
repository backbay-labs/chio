//! MemoryGovernanceGuard -- enforce memory store allowlist, retention
//! TTL ceilings, and per-session memory-entry counts on
//! [`ToolAction::MemoryWrite`] and [`ToolAction::MemoryRead`] actions.
//!
//! See `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 3. The guard
//! sources its policy from two places:
//!
//! 1. **Capability constraints** on the matched grant
//!    ([`Constraint::MemoryStoreAllowlist`]): when present, writes and
//!    reads targeting a store outside the allowlist are denied.
//! 2. **Guard configuration** ([`MemoryGovernanceConfig`]): provides
//!    deployment-wide defaults for `max_memory_entries`,
//!    `max_retention_ttl_secs`, and per-store overrides.  Operators can
//!    use these even when the capability grammar does not surface the
//!    equivalent constraints.
//!
//! The guard keeps an in-memory per-session counter of memory writes so
//! it can enforce [`MemoryGovernanceConfig::max_memory_entries`]
//! deterministically without touching shared kernel state.
//!
//! # Fail-closed semantics
//!
//! - memory writes without a parseable store key are denied when the
//!   matched grant carries a non-empty `MemoryStoreAllowlist`;
//! - malformed deny-pattern regex input causes
//!   [`MemoryGovernanceGuard::with_config`] to return
//!   [`MemoryGovernanceError::InvalidPattern`];
//! - writes with an explicit retention TTL above `max_retention_ttl_secs`
//!   are denied;
//! - writes whose total matches / exceeds `max_memory_entries` are
//!   denied (fail-closed on counter mutex poisoning).

use std::collections::HashMap;
use std::sync::Mutex;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use chio_core::capability::scope::Constraint;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Errors produced when building a [`MemoryGovernanceGuard`].
#[derive(Debug, thiserror::Error)]
pub enum MemoryGovernanceError {
    /// A `deny_patterns` entry was not a valid regex.
    #[error("invalid deny pattern `{pattern}`: {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Configuration for [`MemoryGovernanceGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryGovernanceConfig {
    /// Enable/disable the guard entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hard-coded store allowlist applied on top of the capability-level
    /// [`Constraint::MemoryStoreAllowlist`].  Empty means "no additional
    /// allowlist" (capability-level list still applies).
    #[serde(default)]
    pub store_allowlist: Vec<String>,
    /// Maximum memory-entry count per agent + session combination.  When
    /// `Some(n)`, the `n`-th write is denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_entries: Option<u64>,
    /// Maximum retention TTL (seconds) allowed on a single write.  When
    /// `Some(ttl)`, writes requesting a larger TTL -- or indefinite
    /// retention (missing TTL) -- are denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retention_ttl_secs: Option<u64>,
    /// Maximum content size (bytes) for a single memory write.  `None`
    /// disables the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_content_size_bytes: Option<u64>,
    /// Extra regex patterns that deny a write when the content matches.
    #[serde(default)]
    pub deny_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for MemoryGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            store_allowlist: Vec::new(),
            max_memory_entries: None,
            max_retention_ttl_secs: None,
            max_content_size_bytes: None,
            deny_patterns: Vec::new(),
        }
    }
}

/// Session key used for per-session memory-entry counting.
type SessionKey = (String, String); // (agent_id, capability_id)

/// Guard implementing memory governance.
pub struct MemoryGovernanceGuard {
    enabled: bool,
    store_allowlist: Vec<String>,
    max_memory_entries: Option<u64>,
    max_retention_ttl_secs: Option<u64>,
    max_content_size_bytes: Option<u64>,
    deny_patterns: Vec<Regex>,
    counters: Mutex<HashMap<SessionKey, u64>>,
}

impl MemoryGovernanceGuard {
    /// Build a guard with default configuration (no limits).  Non-guard
    /// code paths remain fully permissive until a capability constraint
    /// or config field is supplied.
    pub fn new() -> Self {
        Self::with_config(MemoryGovernanceConfig::default()).unwrap_or_else(|_| Self {
            enabled: true,
            store_allowlist: Vec::new(),
            max_memory_entries: None,
            max_retention_ttl_secs: None,
            max_content_size_bytes: None,
            deny_patterns: Vec::new(),
            counters: Mutex::new(HashMap::new()),
        })
    }

    /// Build a guard with explicit configuration.
    pub fn with_config(config: MemoryGovernanceConfig) -> Result<Self, MemoryGovernanceError> {
        let mut deny_patterns = Vec::with_capacity(config.deny_patterns.len());
        for pat in &config.deny_patterns {
            let re = Regex::new(pat).map_err(|e| MemoryGovernanceError::InvalidPattern {
                pattern: pat.clone(),
                source: e,
            })?;
            deny_patterns.push(re);
        }
        Ok(Self {
            enabled: config.enabled,
            store_allowlist: config.store_allowlist,
            max_memory_entries: config.max_memory_entries,
            max_retention_ttl_secs: config.max_retention_ttl_secs,
            max_content_size_bytes: config.max_content_size_bytes,
            deny_patterns,
            counters: Mutex::new(HashMap::new()),
        })
    }

    /// Current counter value for a session (test / observability helper).
    pub fn session_count(&self, agent_id: &str, capability_id: &str) -> u64 {
        self.counters
            .lock()
            .ok()
            .and_then(|g| {
                g.get(&(agent_id.to_string(), capability_id.to_string()))
                    .copied()
            })
            .unwrap_or(0)
    }

    /// Gather the effective store allowlist from the matched grant plus
    /// the guard-level config.  Returns `None` if neither source supplies
    /// a non-empty allowlist.
    fn effective_store_allowlist<'a>(&'a self, ctx: &'a GuardContext<'a>) -> Option<Vec<String>> {
        let mut combined: Vec<String> = self.store_allowlist.clone();
        if let Some(grant) = ctx
            .matched_grant_index
            .and_then(|i| ctx.scope.grants.get(i))
        {
            for c in &grant.constraints {
                if let Constraint::MemoryStoreAllowlist(list) = c {
                    combined.extend(list.iter().cloned());
                }
            }
        }
        if combined.is_empty() {
            None
        } else {
            Some(combined)
        }
    }

    /// Increment the per-session write counter and return the new value.
    /// Fails closed (treats poisoning as "over limit") on mutex poisoning.
    fn bump_counter(&self, key: SessionKey) -> Result<u64, KernelError> {
        let mut guard = self.counters.lock().map_err(|_| {
            KernelError::Internal("memory-governance guard counter mutex poisoned".to_string())
        })?;
        let entry = guard.entry(key).or_insert(0);
        *entry = entry.saturating_add(1);
        Ok(*entry)
    }
}

impl Default for MemoryGovernanceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for MemoryGovernanceGuard {
    fn name(&self) -> &str {
        "memory-governance"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        match action {
            ToolAction::MemoryWrite { store, .. } => self.evaluate_write(ctx, &store),
            ToolAction::MemoryRead { store, .. } => self.evaluate_read(ctx, &store),
            _ => Ok(GuardDecision::allow()),
        }
    }
}

impl MemoryGovernanceGuard {
    fn evaluate_write(
        &self,
        ctx: &GuardContext,
        store: &str,
    ) -> Result<GuardDecision, KernelError> {
        // 1. Store allowlist (capability + guard config).
        if let Some(allow) = self.effective_store_allowlist(ctx) {
            if !allow.iter().any(|s| store_matches(s, store)) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // 2. Retention TTL ceiling.
        if let Some(max_ttl) = self.max_retention_ttl_secs {
            let requested = extract_retention_ttl(&ctx.request.arguments);
            match requested {
                None => {
                    // Missing TTL with a configured ceiling is treated
                    // as a request for indefinite retention and denied.
                    return Ok(GuardDecision::deny(Vec::new()));
                }
                Some(ttl) if ttl > max_ttl => {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
                Some(_) => {}
            }
        }

        // 3. Content size.
        if let Some(max_bytes) = self.max_content_size_bytes {
            match extract_content_size_bytes(&ctx.request.arguments) {
                Some(size) => {
                    if size > max_bytes {
                        return Ok(GuardDecision::deny(Vec::new()));
                    }
                }
                None => {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        // 4. Deny patterns on content.
        if !self.deny_patterns.is_empty() {
            if let Some(content) = extract_content_text(&ctx.request.arguments) {
                for re in &self.deny_patterns {
                    if re.is_match(&content) {
                        return Ok(GuardDecision::deny(Vec::new()));
                    }
                }
            }
        }

        // 5. Per-session entry limit.  We bump the counter only after
        //    the previous gates pass; denials do not consume quota.
        if let Some(max_entries) = self.max_memory_entries {
            let key = (ctx.agent_id.to_string(), ctx.request.capability.id.clone());
            let count = self.bump_counter(key)?;
            if count > max_entries {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        Ok(GuardDecision::allow())
    }

    fn evaluate_read(&self, ctx: &GuardContext, store: &str) -> Result<GuardDecision, KernelError> {
        // Reads respect the store allowlist so an agent cannot read from
        // a forbidden store even when the write path is blocked.
        if let Some(allow) = self.effective_store_allowlist(ctx) {
            if !allow.iter().any(|s| store_matches(s, store)) {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }
        Ok(GuardDecision::allow())
    }
}

/// Store allowlist match: supports exact match and `*` wildcard.
fn store_matches(pattern: &str, store: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return store.starts_with(prefix);
    }
    pattern == store
}

/// Read an explicit retention TTL (seconds) from the arguments.
fn extract_retention_ttl(arguments: &Value) -> Option<u64> {
    for key in [
        "retention_ttl",
        "retentionTtl",
        "retention_ttl_secs",
        "retentionTtlSecs",
        "ttl",
        "ttl_secs",
        "expires_in",
        "expiresIn",
    ] {
        if let Some(v) = arguments.get(key).and_then(|v| v.as_u64()) {
            return Some(v);
        }
    }
    None
}

/// Read an explicit content byte size from the arguments, falling back
/// to the length of the `content` / `text` string when present.
fn extract_content_size_bytes(arguments: &Value) -> Option<u64> {
    for key in ["content_size", "contentSize", "content_bytes", "size"] {
        if let Some(v) = arguments.get(key).and_then(|v| v.as_u64()) {
            return Some(v);
        }
    }
    extract_content_text(arguments).map(|s| s.len() as u64)
}

/// Extract the text body of a memory write for regex / size checks.
fn extract_content_text(arguments: &Value) -> Option<String> {
    for key in ["content", "text", "value", "vector_text", "payload"] {
        if let Some(v) = arguments.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_matches_wildcards() {
        assert!(store_matches("*", "anything"));
        assert!(store_matches("agent-*", "agent-notes"));
        assert!(!store_matches("agent-*", "other"));
        assert!(store_matches("agent-notes", "agent-notes"));
    }

    #[test]
    fn extract_retention_ttl_reads_common_keys() {
        let args = serde_json::json!({"ttl": 600});
        assert_eq!(extract_retention_ttl(&args), Some(600));
        let camel = serde_json::json!({"retentionTtl": 120});
        assert_eq!(extract_retention_ttl(&camel), Some(120));
        let none = serde_json::json!({});
        assert_eq!(extract_retention_ttl(&none), None);
    }

    #[test]
    fn content_size_falls_back_to_text_length() {
        let args = serde_json::json!({"content": "hello"});
        assert_eq!(extract_content_size_bytes(&args), Some(5));
    }
}
