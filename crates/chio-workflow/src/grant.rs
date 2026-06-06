//! SkillGrant -- extends the capability model for multi-step skill composition.
//!
//! A `SkillGrant` authorizes an agent to execute a named skill, which is a
//! declared sequence of tool invocations. Unlike individual `ToolGrant`s, a
//! skill grant binds the entire sequence under a single authorization with
//! a shared budget envelope.

use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

/// Schema identifier for skill grants.
pub const SKILL_GRANT_SCHEMA: &str = "chio.skill-grant.v1";

/// A capability grant for a multi-step skill.
///
/// This extends the standard Chio capability model by authorizing an ordered
/// sequence of tool invocations rather than individual tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillGrant {
    /// Schema version.
    pub schema: String,

    /// Unique skill identifier (e.g. "search-and-summarize").
    pub skill_id: String,

    /// Version of the skill manifest this grant authorizes.
    pub skill_version: String,

    /// Tool steps authorized by this grant, in declared order.
    /// Each entry is "server_id:tool_name".
    pub authorized_steps: Vec<String>,

    /// Maximum number of complete skill executions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_executions: Option<u32>,

    /// Budget envelope for the entire skill execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_envelope: Option<MonetaryAmount>,

    /// Maximum wall-clock duration for a single skill execution (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,

    /// Whether steps must execute in declared order.
    /// Defaults to true (strict ordering).
    #[serde(default = "default_strict_ordering")]
    pub strict_ordering: bool,
}

fn default_strict_ordering() -> bool {
    true
}

impl SkillGrant {
    /// Create a new skill grant.
    pub fn new(skill_id: String, skill_version: String, authorized_steps: Vec<String>) -> Self {
        Self {
            schema: SKILL_GRANT_SCHEMA.to_string(),
            skill_id,
            skill_version,
            authorized_steps,
            max_executions: None,
            budget_envelope: None,
            max_duration_secs: None,
            strict_ordering: true,
        }
    }

    /// Check whether a tool step is authorized by this grant.
    #[must_use]
    pub fn authorizes_step(&self, server_id: &str, tool_name: &str) -> bool {
        let key = format!("{server_id}:{tool_name}");
        self.authorized_steps.contains(&key)
    }

    /// Check whether a step index is valid for strict ordering.
    ///
    /// `completed_steps` is the number of steps already completed.
    /// Returns true if the proposed step at the given index follows
    /// the expected order.
    #[must_use]
    pub fn is_step_in_order(&self, step_index: usize, completed_steps: usize) -> bool {
        if !self.strict_ordering {
            return true;
        }
        step_index == completed_steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_grant_roundtrip() {
        let grant = SkillGrant::new(
            "search-and-summarize".to_string(),
            "1.0.0".to_string(),
            vec![
                "search-server:search".to_string(),
                "llm-server:summarize".to_string(),
            ],
        );

        let json = serde_json::to_string(&grant).unwrap();
        let deserialized: SkillGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.skill_id, "search-and-summarize");
        assert_eq!(deserialized.authorized_steps.len(), 2);
        assert!(deserialized.strict_ordering);
    }

    #[test]
    fn authorizes_step() {
        let grant = SkillGrant::new(
            "s1".to_string(),
            "1.0".to_string(),
            vec!["srv:tool_a".to_string(), "srv:tool_b".to_string()],
        );
        assert!(grant.authorizes_step("srv", "tool_a"));
        assert!(grant.authorizes_step("srv", "tool_b"));
        assert!(!grant.authorizes_step("srv", "tool_c"));
    }

    #[test]
    fn strict_ordering() {
        let grant = SkillGrant::new(
            "s1".to_string(),
            "1.0".to_string(),
            vec!["a:t1".to_string(), "a:t2".to_string()],
        );
        assert!(grant.is_step_in_order(0, 0)); // first step ok
        assert!(grant.is_step_in_order(1, 1)); // second step ok
        assert!(!grant.is_step_in_order(1, 0)); // skipping step 0
    }

    #[test]
    fn relaxed_ordering() {
        let mut grant = SkillGrant::new(
            "s1".to_string(),
            "1.0".to_string(),
            vec!["a:t1".to_string(), "a:t2".to_string()],
        );
        grant.strict_ordering = false;
        assert!(grant.is_step_in_order(1, 0)); // out of order ok
    }
}
