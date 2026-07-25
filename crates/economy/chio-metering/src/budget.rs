//! Monetary budget enforcement with denominated currency.
//!
//! Budget policies define spending limits per session, agent, or tool.
//! The enforcer tracks cumulative spending and rejects invocations that
//! would exceed the configured budget. Cross-currency enforcement uses
//! the chio-link oracle for conversion.

use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::cost::CostMetadata;

/// A budget policy defining spending limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicy {
    /// Maximum total spending across all dimensions.
    pub max_total: MonetaryAmount,

    /// Optional per-session spending limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_session: Option<MonetaryAmount>,

    /// Optional per-agent spending limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_agent: Option<MonetaryAmount>,

    /// Optional per-tool spending limit (key format: "server:tool").
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub max_per_tool: HashMap<String, MonetaryAmount>,

    /// Currency for budget enforcement. Costs in other currencies require
    /// oracle conversion.
    pub currency: String,
}

/// A budget violation describes why a cost was rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum BudgetViolation {
    /// Total budget exceeded.
    Total {
        limit_units: u64,
        current_units: u64,
        requested_units: u64,
        currency: String,
    },
    /// Per-session budget exceeded.
    Session {
        session_id: String,
        limit_units: u64,
        current_units: u64,
        requested_units: u64,
        currency: String,
    },
    /// Per-agent budget exceeded.
    Agent {
        agent_id: String,
        limit_units: u64,
        current_units: u64,
        requested_units: u64,
        currency: String,
    },
    /// Per-tool budget exceeded.
    Tool {
        tool_key: String,
        limit_units: u64,
        current_units: u64,
        requested_units: u64,
        currency: String,
    },
}

/// Budget enforcer that tracks cumulative spending and enforces policies.
///
/// Thread-safe usage requires external synchronization (the kernel already
/// serializes guard evaluation per-request).
///
/// WARNING: counters are process-local and reset to zero on restart, reopening
/// the full budget. Use the kernel's durable `BudgetStore` for cross-restart
/// continuity.
#[deprecated(note = "process-local counters reset on restart; use chio-kernel BudgetStore")]
#[derive(Debug, Clone)]
pub struct BudgetEnforcer {
    policy: BudgetPolicy,
    /// Total spending tracked.
    total_spent: u64,
    /// Per-session spending.
    session_spent: HashMap<String, u64>,
    /// Per-agent spending.
    agent_spent: HashMap<String, u64>,
    /// Per-tool spending.
    tool_spent: HashMap<String, u64>,
}

#[allow(deprecated)]
impl BudgetEnforcer {
    /// Create a new budget enforcer with the given policy.
    pub fn new(policy: BudgetPolicy) -> Self {
        Self {
            policy,
            total_spent: 0,
            session_spent: HashMap::new(),
            agent_spent: HashMap::new(),
            tool_spent: HashMap::new(),
        }
    }

    /// Check whether a proposed cost would violate the budget.
    ///
    /// Returns `Ok(())` if the cost is within budget, or `Err(BudgetViolation)`
    /// describing which limit would be exceeded.
    ///
    /// The `cost_units` must already be denominated in the policy currency.
    /// Use chio-link oracle to convert cross-currency costs before calling this.
    pub fn check(&self, meta: &CostMetadata, cost_units: u64) -> Result<(), BudgetViolation> {
        if self.total_spent.saturating_add(cost_units) > self.policy.max_total.units {
            return Err(BudgetViolation::Total {
                limit_units: self.policy.max_total.units,
                current_units: self.total_spent,
                requested_units: cost_units,
                currency: self.policy.currency.clone(),
            });
        }

        if let (Some(ref limit), Some(ref sid)) = (&self.policy.max_per_session, &meta.session_id) {
            let current = self.session_spent.get(sid).copied().unwrap_or(0);
            if current.saturating_add(cost_units) > limit.units {
                return Err(BudgetViolation::Session {
                    session_id: sid.clone(),
                    limit_units: limit.units,
                    current_units: current,
                    requested_units: cost_units,
                    currency: self.policy.currency.clone(),
                });
            }
        }

        if let Some(ref limit) = self.policy.max_per_agent {
            let current = self.agent_spent.get(&meta.agent_id).copied().unwrap_or(0);
            if current.saturating_add(cost_units) > limit.units {
                return Err(BudgetViolation::Agent {
                    agent_id: meta.agent_id.clone(),
                    limit_units: limit.units,
                    current_units: current,
                    requested_units: cost_units,
                    currency: self.policy.currency.clone(),
                });
            }
        }

        let tool_key = format!("{}:{}", meta.tool_server, meta.tool_name);
        if let Some(limit) = self.policy.max_per_tool.get(&tool_key) {
            let current = self.tool_spent.get(&tool_key).copied().unwrap_or(0);
            if current.saturating_add(cost_units) > limit.units {
                return Err(BudgetViolation::Tool {
                    tool_key,
                    limit_units: limit.units,
                    current_units: current,
                    requested_units: cost_units,
                    currency: self.policy.currency.clone(),
                });
            }
        }

        Ok(())
    }

    /// Record a cost that has been approved and executed.
    ///
    /// This updates all tracking counters. Call this after the tool invocation
    /// succeeds and the receipt is signed.
    pub fn record(&mut self, meta: &CostMetadata, cost_units: u64) {
        self.total_spent = self.total_spent.saturating_add(cost_units);

        if let Some(ref sid) = meta.session_id {
            let entry = self.session_spent.entry(sid.clone()).or_insert(0);
            *entry = entry.saturating_add(cost_units);
        }

        let agent_entry = self.agent_spent.entry(meta.agent_id.clone()).or_insert(0);
        *agent_entry = agent_entry.saturating_add(cost_units);

        let tool_key = format!("{}:{}", meta.tool_server, meta.tool_name);
        let tool_entry = self.tool_spent.entry(tool_key).or_insert(0);
        *tool_entry = tool_entry.saturating_add(cost_units);
    }

    /// Return the total amount spent so far.
    #[must_use]
    pub fn total_spent(&self) -> u64 {
        self.total_spent
    }

    /// Return the remaining budget in policy currency units.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.policy.max_total.units.saturating_sub(self.total_spent)
    }

    /// Return a reference to the active policy.
    #[must_use]
    pub fn policy(&self) -> &BudgetPolicy {
        &self.policy
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::cost::CostMetadata;

    fn make_policy() -> BudgetPolicy {
        let mut per_tool = HashMap::new();
        per_tool.insert(
            "s1:expensive".to_string(),
            MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
        );

        BudgetPolicy {
            max_total: MonetaryAmount {
                units: 10000,
                currency: "USD".to_string(),
            },
            max_per_session: Some(MonetaryAmount {
                units: 5000,
                currency: "USD".to_string(),
            }),
            max_per_agent: Some(MonetaryAmount {
                units: 3000,
                currency: "USD".to_string(),
            }),
            max_per_tool: per_tool,
            currency: "USD".to_string(),
        }
    }

    fn make_meta(agent: &str, server: &str, tool: &str) -> CostMetadata {
        let mut m = CostMetadata::new(
            "r1".to_string(),
            1000,
            agent.to_string(),
            server.to_string(),
            tool.to_string(),
        );
        m.session_id = Some("sess-1".to_string());
        m
    }

    #[test]
    fn within_budget() {
        let enforcer = BudgetEnforcer::new(make_policy());
        let meta = make_meta("a1", "s1", "t1");
        assert!(enforcer.check(&meta, 100).is_ok());
    }

    #[test]
    fn total_budget_exceeded() {
        let mut enforcer = BudgetEnforcer::new(make_policy());
        let meta = make_meta("a1", "s1", "t1");
        enforcer.record(&meta, 9900);
        let result = enforcer.check(&meta, 200);
        assert!(matches!(result, Err(BudgetViolation::Total { .. })));
    }

    #[test]
    fn per_agent_budget_exceeded() {
        let mut enforcer = BudgetEnforcer::new(make_policy());
        let meta = make_meta("a1", "s1", "t1");
        enforcer.record(&meta, 2900);
        let result = enforcer.check(&meta, 200);
        assert!(matches!(result, Err(BudgetViolation::Agent { .. })));
    }

    #[test]
    fn per_session_budget_exceeded() {
        // Use a policy where the session limit triggers before the agent limit.
        let policy = BudgetPolicy {
            max_total: MonetaryAmount {
                units: 100000,
                currency: "USD".to_string(),
            },
            max_per_session: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            max_per_agent: None,
            max_per_tool: HashMap::new(),
            currency: "USD".to_string(),
        };
        let mut enforcer = BudgetEnforcer::new(policy);
        let meta = make_meta("a1", "s1", "t1");
        enforcer.record(&meta, 900);
        let result = enforcer.check(&meta, 200);
        assert!(matches!(result, Err(BudgetViolation::Session { .. })));
    }

    #[test]
    fn per_tool_budget_exceeded() {
        let mut enforcer = BudgetEnforcer::new(make_policy());
        let meta = make_meta("a1", "s1", "expensive");
        enforcer.record(&meta, 400);
        let result = enforcer.check(&meta, 200);
        assert!(matches!(result, Err(BudgetViolation::Tool { .. })));
    }

    #[test]
    fn zero_cost_always_passes() {
        let enforcer = BudgetEnforcer::new(make_policy());
        let meta = make_meta("a1", "s1", "t1");
        assert!(enforcer.check(&meta, 0).is_ok());
    }

    #[test]
    fn record_with_very_large_numbers_saturates() {
        let policy = BudgetPolicy {
            max_total: MonetaryAmount {
                units: u64::MAX,
                currency: "USD".to_string(),
            },
            max_per_session: None,
            max_per_agent: None,
            max_per_tool: HashMap::new(),
            currency: "USD".to_string(),
        };
        let mut enforcer = BudgetEnforcer::new(policy);
        let meta = make_meta("a1", "s1", "t1");
        enforcer.record(&meta, u64::MAX - 10);
        enforcer.record(&meta, 20);
        // Should saturate at u64::MAX, not overflow
        assert_eq!(enforcer.total_spent(), u64::MAX);
    }

    #[test]
    fn remaining_when_overspent_returns_zero() {
        let policy = BudgetPolicy {
            max_total: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            max_per_session: None,
            max_per_agent: None,
            max_per_tool: HashMap::new(),
            currency: "USD".to_string(),
        };
        let mut enforcer = BudgetEnforcer::new(policy);
        let meta = make_meta("a1", "s1", "t1");
        // record() does not enforce budget; it just tracks spending
        enforcer.record(&meta, 150);
        // remaining() should saturate to 0
        assert_eq!(enforcer.remaining(), 0);
    }

    #[test]
    fn budget_violation_serde_roundtrip() {
        let violation = BudgetViolation::Total {
            limit_units: 1000,
            current_units: 900,
            requested_units: 200,
            currency: "USD".to_string(),
        };
        let json = serde_json::to_string(&violation).unwrap();
        let back: BudgetViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, violation);
    }

    #[test]
    fn remaining_budget() {
        let mut enforcer = BudgetEnforcer::new(make_policy());
        assert_eq!(enforcer.remaining(), 10000);
        let meta = make_meta("a1", "s1", "t1");
        enforcer.record(&meta, 3000);
        assert_eq!(enforcer.remaining(), 7000);
        assert_eq!(enforcer.total_spent(), 3000);
    }
}
