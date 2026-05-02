//! Executable reference specification for Chio scope subsumption.
//!
//! This model intentionally reimplements the shipped subset logic without
//! calling into `chio_core`, so differential tests can detect spec/runtime drift.

/// Mirrors `chio_core::capability::Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpecOperation {
    Invoke,
    ReadResult,
    Read,
    Subscribe,
    Get,
    Delegate,
}

/// Mirrors `chio_core::capability::RuntimeAssuranceTier`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpecRuntimeAssuranceTier {
    None,
    Basic,
    Attested,
    Verified,
}

/// Mirrors `chio_core::capability::MonetaryAmount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecMonetaryAmount {
    pub units: u64,
    pub currency: String,
}

/// Mirrors `chio_core::capability::Constraint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecConstraint {
    PathPrefix(String),
    DomainExact(String),
    DomainGlob(String),
    RegexMatch(String),
    MaxLength(usize),
    MaxArgsSize(usize),
    GovernedIntentRequired,
    RequireApprovalAbove { threshold_units: u64 },
    SellerExact(String),
    MinimumRuntimeAssurance(SpecRuntimeAssuranceTier),
    Custom(String, String),
}

/// Mirrors `chio_core::capability::ToolGrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<SpecOperation>,
    pub constraints: Vec<SpecConstraint>,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<SpecMonetaryAmount>,
    pub max_total_cost: Option<SpecMonetaryAmount>,
    pub dpop_required: Option<bool>,
}

impl SpecToolGrant {
    /// Reference implementation of `ToolGrant::is_subset_of`.
    ///
    /// Written for clarity rather than performance. Mirrors the current
    /// shipped Rust implementation.
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecToolGrant) -> bool {
        if parent.server_id != "*" && self.server_id != parent.server_id {
            return false;
        }

        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        for op in &self.operations {
            if !parent.operations.contains(op) {
                return false;
            }
        }

        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                _ => return false,
            }
        }

        for pc in &parent.constraints {
            if !self.constraints.contains(pc) {
                return false;
            }
        }

        if !monetary_cap_is_subset(
            self.max_cost_per_invocation.as_ref(),
            parent.max_cost_per_invocation.as_ref(),
        ) {
            return false;
        }

        if !monetary_cap_is_subset(self.max_total_cost.as_ref(), parent.max_total_cost.as_ref()) {
            return false;
        }

        if parent.dpop_required == Some(true) && self.dpop_required != Some(true) {
            return false;
        }

        true
    }
}

/// Mirrors `chio_core::capability::ResourceGrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecResourceGrant {
    pub uri_pattern: String,
    pub operations: Vec<SpecOperation>,
}

impl SpecResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecResourceGrant) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Mirrors `chio_core::capability::PromptGrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecPromptGrant {
    pub prompt_name: String,
    pub operations: Vec<SpecOperation>,
}

impl SpecPromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecPromptGrant) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Mirrors `chio_core::capability::ChioScope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecChioScope {
    pub grants: Vec<SpecToolGrant>,
    pub resource_grants: Vec<SpecResourceGrant>,
    pub prompt_grants: Vec<SpecPromptGrant>,
}

impl SpecChioScope {
    /// Reference implementation of `ChioScope::is_subset_of`.
    ///
    /// Every grant in `self` must be covered by some grant in `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &SpecChioScope) -> bool {
        self.grants
            .iter()
            .all(|cg| parent.grants.iter().any(|pg| cg.is_subset_of(pg)))
            && self
                .resource_grants
                .iter()
                .all(|cg| parent.resource_grants.iter().any(|pg| cg.is_subset_of(pg)))
            && self
                .prompt_grants
                .iter()
                .all(|cg| parent.prompt_grants.iter().any(|pg| cg.is_subset_of(pg)))
    }
}

fn pattern_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }

    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }

    parent == child
}

fn monetary_cap_is_subset(
    child: Option<&SpecMonetaryAmount>,
    parent: Option<&SpecMonetaryAmount>,
) -> bool {
    match parent {
        None => true,
        Some(parent_cap) => matches!(
            child,
            Some(child_cap)
                if child_cap.currency == parent_cap.currency
                    && child_cap.units <= parent_cap.units
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(server: &str, tool: &str, ops: Vec<SpecOperation>) -> SpecToolGrant {
        SpecToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: ops,
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn scope(grants: Vec<SpecToolGrant>) -> SpecChioScope {
        SpecChioScope {
            grants,
            resource_grants: vec![],
            prompt_grants: vec![],
        }
    }

    #[test]
    fn empty_scope_is_subset_of_anything() {
        let parent = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        let child = scope(vec![]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn same_scope_is_subset() {
        let s = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(s.is_subset_of(&s));
    }

    #[test]
    fn fewer_grants_is_subset() {
        let parent = scope(vec![
            grant("a", "t1", vec![SpecOperation::Invoke]),
            grant("a", "t2", vec![SpecOperation::Invoke]),
        ]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn fewer_operations_is_subset() {
        let parent = scope(vec![grant(
            "a",
            "t1",
            vec![SpecOperation::Invoke, SpecOperation::ReadResult],
        )]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn different_server_not_subset() {
        let parent = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        let child = scope(vec![grant("b", "t1", vec![SpecOperation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn wildcard_tool_subsumes() {
        let parent = scope(vec![grant("a", "*", vec![SpecOperation::Invoke])]);
        let child = scope(vec![grant("a", "t1", vec![SpecOperation::Invoke])]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn budget_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_ok = SpecToolGrant {
            max_invocations: Some(5),
            ..parent.clone()
        };
        let child_exceed = SpecToolGrant {
            max_invocations: Some(20),
            ..parent.clone()
        };
        let child_none = SpecToolGrant {
            max_invocations: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_exceed.is_subset_of(&parent));
        assert!(!child_none.is_subset_of(&parent));
    }

    #[test]
    fn monetary_budget_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(SpecMonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(SpecMonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        };
        let child_ok = SpecToolGrant {
            max_cost_per_invocation: Some(SpecMonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(SpecMonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            ..parent.clone()
        };
        let child_bad_currency = SpecToolGrant {
            max_cost_per_invocation: Some(SpecMonetaryAmount {
                units: 50,
                currency: "EUR".to_string(),
            }),
            max_total_cost: parent.max_total_cost.clone(),
            ..parent.clone()
        };
        let child_bad_total = SpecToolGrant {
            max_cost_per_invocation: parent.max_cost_per_invocation.clone(),
            max_total_cost: Some(SpecMonetaryAmount {
                units: 999,
                currency: "USD".to_string(),
            }),
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_bad_currency.is_subset_of(&parent));
        assert!(!child_bad_total.is_subset_of(&parent));
    }

    #[test]
    fn dpop_requirement_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        };
        let child_ok = SpecToolGrant {
            dpop_required: Some(true),
            ..parent.clone()
        };
        let child_bad = SpecToolGrant {
            dpop_required: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_bad.is_subset_of(&parent));
    }

    #[test]
    fn constraint_superset_check() {
        let parent = SpecToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![SpecConstraint::PathPrefix("/app".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_ok = SpecToolGrant {
            constraints: vec![
                SpecConstraint::PathPrefix("/app".to_string()),
                SpecConstraint::MaxLength(1024),
            ],
            ..parent.clone()
        };
        let child_bad = SpecToolGrant {
            constraints: vec![SpecConstraint::MaxLength(1024)],
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_bad.is_subset_of(&parent));
    }

    #[test]
    fn governed_constraint_equality_check() {
        let parent = SpecToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![
                SpecConstraint::GovernedIntentRequired,
                SpecConstraint::RequireApprovalAbove {
                    threshold_units: 500,
                },
                SpecConstraint::MinimumRuntimeAssurance(SpecRuntimeAssuranceTier::Attested),
            ],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_ok = SpecToolGrant {
            constraints: vec![
                SpecConstraint::GovernedIntentRequired,
                SpecConstraint::RequireApprovalAbove {
                    threshold_units: 500,
                },
                SpecConstraint::MinimumRuntimeAssurance(SpecRuntimeAssuranceTier::Attested),
                SpecConstraint::SellerExact("seller.chio".to_string()),
            ],
            ..parent.clone()
        };
        let child_bad = SpecToolGrant {
            constraints: vec![
                SpecConstraint::GovernedIntentRequired,
                SpecConstraint::RequireApprovalAbove {
                    threshold_units: 500,
                },
                SpecConstraint::MinimumRuntimeAssurance(SpecRuntimeAssuranceTier::Basic),
            ],
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_bad.is_subset_of(&parent));
    }

    #[test]
    fn resource_pattern_prefix_subsumes() {
        let parent = SpecResourceGrant {
            uri_pattern: "chio://receipts/*".to_string(),
            operations: vec![SpecOperation::Read],
        };
        let child = SpecResourceGrant {
            uri_pattern: "chio://receipts/abc".to_string(),
            operations: vec![SpecOperation::Read],
        };

        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn prompt_wildcard_subsumes() {
        let parent = SpecPromptGrant {
            prompt_name: "*".to_string(),
            operations: vec![SpecOperation::Get],
        };
        let child = SpecPromptGrant {
            prompt_name: "triage".to_string(),
            operations: vec![SpecOperation::Get],
        };

        assert!(child.is_subset_of(&parent));
    }
}
