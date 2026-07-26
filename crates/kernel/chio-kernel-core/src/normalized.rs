//! Proof-facing normalized types for the bounded verified core.
//!
//! These types deliberately carve out the pure authorization subset the
//! executable spec and future Lean refinement work can talk about without
//! depending on the full runtime object graph.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;

use chio_core_types::capability::{
    runtime_attestation::RuntimeAssuranceTier,
    scope::{
        ChioScope, Constraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant,
    },
    token::CapabilityToken,
};
use serde::{Deserialize, Serialize};

use crate::capability_verify::VerifiedCapability;
use crate::evaluate::EvaluationVerdict;
#[cfg(not(kani))]
use crate::formal_core::monetary_cap_is_subset_by_parts;
use crate::formal_core::{
    exact_or_wildcard_covers, optional_u32_cap_is_subset, prefix_wildcard_or_exact_covers,
    required_true_is_preserved,
};
use crate::guard::PortableToolCallRequest;
use crate::Verdict;

/// Errors raised while projecting runtime objects into the normalized
/// proof-facing surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationError {
    /// The current bounded proof lane does not model this constraint yet.
    UnsupportedConstraint { kind: String },
}

/// Proof-facing monetary cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedMonetaryAmount {
    pub units: u64,
    pub currency: String,
}

/// Proof-facing runtime assurance tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedRuntimeAssuranceTier {
    None,
    Basic,
    Attested,
    Verified,
}

/// Proof-facing operation enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedOperation {
    Invoke,
    ReadResult,
    Read,
    Subscribe,
    Get,
    Delegate,
}

/// Constraint subset currently admitted into the normalized proof-facing AST.
///
/// Unsupported runtime-only constraints remain outside this boundary and cause
/// normalization to fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum NormalizedConstraint {
    PathPrefix(String),
    DomainExact(String),
    DomainGlob(String),
    RegexMatch(String),
    MaxLength(usize),
    MaxArgsSize(usize),
    GovernedIntentRequired,
    RequireApprovalAbove { threshold_units: u64 },
    SellerExact(String),
    MinimumRuntimeAssurance(NormalizedRuntimeAssuranceTier),
    Custom(String, String),
}

/// Proof-facing tool grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<NormalizedOperation>,
    pub constraints: Vec<NormalizedConstraint>,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<NormalizedMonetaryAmount>,
    pub max_total_cost: Option<NormalizedMonetaryAmount>,
    pub dpop_required: Option<bool>,
}

impl NormalizedToolGrant {
    /// Mirrors `ToolGrant::is_subset_of` over the normalized proof-facing AST.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        #[cfg(kani)]
        {
            return self.is_subset_of_bounded_kani(parent);
        }

        #[cfg(not(kani))]
        {
            if !exact_or_wildcard_covers(&parent.server_id, &self.server_id) {
                return false;
            }
            if !exact_or_wildcard_covers(&parent.tool_name, &self.tool_name) {
                return false;
            }

            if !self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
            {
                return false;
            }

            if !optional_u32_cap_is_subset(
                self.max_invocations.is_some(),
                self.max_invocations.unwrap_or(0),
                parent.max_invocations.is_some(),
                parent.max_invocations.unwrap_or(0),
            ) {
                return false;
            }

            if !parent
                .constraints
                .iter()
                .all(|constraint| self.constraints.contains(constraint))
            {
                return false;
            }

            if !monetary_cap_is_subset(
                self.max_cost_per_invocation.as_ref(),
                parent.max_cost_per_invocation.as_ref(),
            ) {
                return false;
            }

            if !monetary_cap_is_subset(self.max_total_cost.as_ref(), parent.max_total_cost.as_ref())
            {
                return false;
            }

            if !required_true_is_preserved(
                parent.dpop_required == Some(true),
                self.dpop_required == Some(true),
            ) {
                return false;
            }

            true
        }
    }

    #[cfg(kani)]
    fn is_subset_of_bounded_kani(&self, parent: &Self) -> bool {
        if !exact_or_wildcard_covers(&parent.server_id, &self.server_id) {
            return false;
        }
        if !exact_or_wildcard_covers(&parent.tool_name, &self.tool_name) {
            return false;
        }
        if !normalized_operations_subset_bounded_kani(&self.operations, &parent.operations) {
            return false;
        }
        if !optional_u32_cap_is_subset(
            self.max_invocations.is_some(),
            self.max_invocations.unwrap_or(0),
            parent.max_invocations.is_some(),
            parent.max_invocations.unwrap_or(0),
        ) {
            return false;
        }
        if !normalized_constraints_subset_bounded_kani(&self.constraints, &parent.constraints) {
            return false;
        }
        if !monetary_cap_is_subset_bounded_kani(
            self.max_cost_per_invocation.as_ref(),
            parent.max_cost_per_invocation.as_ref(),
        ) {
            return false;
        }
        if !monetary_cap_is_subset_bounded_kani(
            self.max_total_cost.as_ref(),
            parent.max_total_cost.as_ref(),
        ) {
            return false;
        }
        if !required_true_is_preserved(
            parent.dpop_required == Some(true),
            self.dpop_required == Some(true),
        ) {
            return false;
        }

        true
    }
}

/// Proof-facing resource grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedResourceGrant {
    pub uri_pattern: String,
    pub operations: Vec<NormalizedOperation>,
}

impl NormalizedResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Proof-facing prompt grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedPromptGrant {
    pub prompt_name: String,
    pub operations: Vec<NormalizedOperation>,
}

impl NormalizedPromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Proof-facing scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedScope {
    pub grants: Vec<NormalizedToolGrant>,
    pub resource_grants: Vec<NormalizedResourceGrant>,
    pub prompt_grants: Vec<NormalizedPromptGrant>,
}

impl NormalizedScope {
    /// Mirrors `ChioScope::is_subset_of` over the normalized proof-facing AST.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        #[cfg(kani)]
        {
            if !self.resource_grants.is_empty()
                || !parent.resource_grants.is_empty()
                || !self.prompt_grants.is_empty()
                || !parent.prompt_grants.is_empty()
            {
                return false;
            }
            if self.grants.is_empty() {
                return true;
            }
            if self.grants.len() == 1 && parent.grants.len() == 1 {
                return self.grants[0].is_subset_of(&parent.grants[0]);
            }
            return false;
        }

        #[cfg(not(kani))]
        {
            self.grants.iter().all(|grant| {
                parent
                    .grants
                    .iter()
                    .any(|candidate| grant.is_subset_of(candidate))
            }) && self.resource_grants.iter().all(|grant| {
                parent
                    .resource_grants
                    .iter()
                    .any(|candidate| grant.is_subset_of(candidate))
            }) && self.prompt_grants.iter().all(|grant| {
                parent
                    .prompt_grants
                    .iter()
                    .any(|candidate| grant.is_subset_of(candidate))
            })
        }
    }
}

/// Proof-facing capability token projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedCapability {
    pub id: String,
    pub issuer_hex: String,
    pub subject_hex: String,
    pub scope: NormalizedScope,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Proof-facing verified-capability output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedVerifiedCapability {
    pub capability: NormalizedCapability,
    pub evaluated_at: u64,
}

/// Proof-facing request shape for the current evaluated tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRequest {
    pub request_id: String,
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
}

/// Proof-facing verdict enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedVerdict {
    Allow,
    Deny,
    PendingApproval,
}

/// Proof-facing evaluation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedEvaluationVerdict {
    pub request: NormalizedRequest,
    pub verdict: NormalizedVerdict,
    pub reason: Option<String>,
    pub matched_grant_index: Option<usize>,
    pub verified: Option<NormalizedVerifiedCapability>,
}

impl TryFrom<&CapabilityToken> for NormalizedCapability {
    type Error = NormalizationError;

    fn try_from(capability: &CapabilityToken) -> Result<Self, Self::Error> {
        Ok(Self {
            id: capability.id.clone(),
            issuer_hex: capability.issuer.to_hex(),
            subject_hex: capability.subject.to_hex(),
            scope: NormalizedScope::try_from(&capability.scope)?,
            issued_at: capability.issued_at,
            expires_at: capability.expires_at,
        })
    }
}

impl TryFrom<&VerifiedCapability> for NormalizedVerifiedCapability {
    type Error = NormalizationError;

    fn try_from(verified: &VerifiedCapability) -> Result<Self, Self::Error> {
        Ok(Self {
            capability: NormalizedCapability {
                id: verified.id.clone(),
                issuer_hex: verified.issuer_hex.clone(),
                subject_hex: verified.subject_hex.clone(),
                scope: NormalizedScope::try_from(&verified.scope)?,
                issued_at: verified.issued_at,
                expires_at: verified.expires_at,
            },
            evaluated_at: verified.evaluated_at,
        })
    }
}

impl From<&PortableToolCallRequest> for NormalizedRequest {
    fn from(request: &PortableToolCallRequest) -> Self {
        Self {
            request_id: request.request_id.clone(),
            tool_name: request.tool_name.clone(),
            server_id: request.server_id.clone(),
            agent_id: request.agent_id.clone(),
            arguments: request.arguments.clone(),
        }
    }
}

impl NormalizedEvaluationVerdict {
    pub fn try_from_evaluation(
        request: &PortableToolCallRequest,
        verdict: &EvaluationVerdict,
    ) -> Result<Self, NormalizationError> {
        Ok(Self {
            request: NormalizedRequest::from(request),
            verdict: NormalizedVerdict::from(verdict.verdict),
            reason: verdict.reason.clone(),
            matched_grant_index: verdict.matched_grant_index,
            verified: verdict
                .verified
                .as_ref()
                .map(NormalizedVerifiedCapability::try_from)
                .transpose()?,
        })
    }
}

impl From<Verdict> for NormalizedVerdict {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            Verdict::Deny => Self::Deny,
            Verdict::PendingApproval => Self::PendingApproval,
        }
    }
}

impl TryFrom<&ChioScope> for NormalizedScope {
    type Error = NormalizationError;

    fn try_from(scope: &ChioScope) -> Result<Self, Self::Error> {
        Ok(Self {
            grants: scope
                .grants
                .iter()
                .map(NormalizedToolGrant::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            resource_grants: scope
                .resource_grants
                .iter()
                .map(NormalizedResourceGrant::from)
                .collect(),
            prompt_grants: scope
                .prompt_grants
                .iter()
                .map(NormalizedPromptGrant::from)
                .collect(),
        })
    }
}

impl TryFrom<&ToolGrant> for NormalizedToolGrant {
    type Error = NormalizationError;

    fn try_from(grant: &ToolGrant) -> Result<Self, Self::Error> {
        Ok(Self {
            server_id: grant.server_id.clone(),
            tool_name: grant.tool_name.clone(),
            operations: grant
                .operations
                .iter()
                .cloned()
                .map(NormalizedOperation::from)
                .collect(),
            constraints: grant
                .constraints
                .iter()
                .map(NormalizedConstraint::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            max_invocations: grant.max_invocations,
            max_cost_per_invocation: grant
                .max_cost_per_invocation
                .as_ref()
                .map(NormalizedMonetaryAmount::from),
            max_total_cost: grant
                .max_total_cost
                .as_ref()
                .map(NormalizedMonetaryAmount::from),
            dpop_required: grant.dpop_required,
        })
    }
}

impl From<&ResourceGrant> for NormalizedResourceGrant {
    fn from(grant: &ResourceGrant) -> Self {
        Self {
            uri_pattern: grant.uri_pattern.clone(),
            operations: grant
                .operations
                .iter()
                .cloned()
                .map(NormalizedOperation::from)
                .collect(),
        }
    }
}

impl From<&PromptGrant> for NormalizedPromptGrant {
    fn from(grant: &PromptGrant) -> Self {
        Self {
            prompt_name: grant.prompt_name.clone(),
            operations: grant
                .operations
                .iter()
                .cloned()
                .map(NormalizedOperation::from)
                .collect(),
        }
    }
}

impl From<&MonetaryAmount> for NormalizedMonetaryAmount {
    fn from(amount: &MonetaryAmount) -> Self {
        Self {
            units: amount.units,
            currency: amount.currency.clone(),
        }
    }
}

impl From<Operation> for NormalizedOperation {
    fn from(operation: Operation) -> Self {
        match operation {
            Operation::Invoke => Self::Invoke,
            Operation::ReadResult => Self::ReadResult,
            Operation::Read => Self::Read,
            Operation::Subscribe => Self::Subscribe,
            Operation::Get => Self::Get,
            Operation::Delegate => Self::Delegate,
        }
    }
}

impl From<RuntimeAssuranceTier> for NormalizedRuntimeAssuranceTier {
    fn from(tier: RuntimeAssuranceTier) -> Self {
        match tier {
            RuntimeAssuranceTier::None => Self::None,
            RuntimeAssuranceTier::Basic => Self::Basic,
            RuntimeAssuranceTier::Attested => Self::Attested,
            RuntimeAssuranceTier::Verified => Self::Verified,
        }
    }
}

impl TryFrom<&Constraint> for NormalizedConstraint {
    type Error = NormalizationError;

    fn try_from(constraint: &Constraint) -> Result<Self, Self::Error> {
        match constraint {
            Constraint::PathPrefix(value) => Ok(Self::PathPrefix(value.clone())),
            Constraint::DomainExact(value) => Ok(Self::DomainExact(value.clone())),
            Constraint::DomainGlob(value) => Ok(Self::DomainGlob(value.clone())),
            Constraint::RegexMatch(value) => Ok(Self::RegexMatch(value.clone())),
            Constraint::MaxLength(value) => Ok(Self::MaxLength(*value)),
            Constraint::MaxArgsSize(value) => Ok(Self::MaxArgsSize(*value)),
            Constraint::GovernedIntentRequired => Ok(Self::GovernedIntentRequired),
            Constraint::RequireApprovalAbove { threshold_units } => {
                Ok(Self::RequireApprovalAbove {
                    threshold_units: *threshold_units,
                })
            }
            Constraint::SellerExact(value) => Ok(Self::SellerExact(value.clone())),
            Constraint::MinimumRuntimeAssurance(tier) => {
                Ok(Self::MinimumRuntimeAssurance((*tier).into()))
            }
            Constraint::Custom(key, value) => Ok(Self::Custom(key.clone(), value.clone())),
            unsupported => Err(NormalizationError::UnsupportedConstraint {
                kind: unsupported_constraint_name(unsupported).to_string(),
            }),
        }
    }
}

#[cfg(not(kani))]
fn monetary_cap_is_subset(
    child: Option<&NormalizedMonetaryAmount>,
    parent: Option<&NormalizedMonetaryAmount>,
) -> bool {
    let child_units = child.map(|cap| cap.units).unwrap_or(0);
    let parent_units = parent.map(|cap| cap.units).unwrap_or(0);
    let currency_matches = match (child, parent) {
        (Some(child_cap), Some(parent_cap)) => child_cap.currency == parent_cap.currency,
        _ => false,
    };
    monetary_cap_is_subset_by_parts(
        child.is_some(),
        child_units,
        parent.is_some(),
        parent_units,
        currency_matches,
    )
}

#[cfg(kani)]
fn normalized_operations_subset_bounded_kani(
    child: &[NormalizedOperation],
    parent: &[NormalizedOperation],
) -> bool {
    if child.is_empty() {
        return true;
    }
    if child.len() == 1 && parent.len() == 1 {
        return child[0] == parent[0];
    }
    false
}

#[cfg(kani)]
fn normalized_constraints_subset_bounded_kani(
    _child: &[NormalizedConstraint],
    parent: &[NormalizedConstraint],
) -> bool {
    parent.is_empty()
}

#[cfg(kani)]
fn monetary_cap_is_subset_bounded_kani(
    child: Option<&NormalizedMonetaryAmount>,
    parent: Option<&NormalizedMonetaryAmount>,
) -> bool {
    match (child, parent) {
        (None, None) | (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(child_cap), Some(parent_cap)) => {
            child_cap.units <= parent_cap.units && child_cap.currency == parent_cap.currency
        }
    }
}

fn pattern_covers(parent: &str, child: &str) -> bool {
    prefix_wildcard_or_exact_covers(parent, child)
}

fn unsupported_constraint_name(constraint: &Constraint) -> &'static str {
    match constraint {
        Constraint::PathPrefix(_) => "path_prefix",
        Constraint::DomainExact(_) => "domain_exact",
        Constraint::DomainGlob(_) => "domain_glob",
        Constraint::RegexMatch(_) => "regex_match",
        Constraint::MaxLength(_) => "max_length",
        Constraint::MaxArgsSize(_) => "max_args_size",
        Constraint::GovernedIntentRequired => "governed_intent_required",
        Constraint::RequireApprovalAbove { .. } => "require_approval_above",
        Constraint::RequireCumulativeApprovalAbove { .. } => "require_cumulative_approval_above",
        Constraint::SellerExact(_) => "seller_exact",
        Constraint::MinimumRuntimeAssurance(_) => "minimum_runtime_assurance",
        Constraint::MinimumAutonomyTier(_) => "minimum_autonomy_tier",
        Constraint::Custom(_, _) => "custom",
        Constraint::TableAllowlist(_) => "table_allowlist",
        Constraint::ColumnDenylist(_) => "column_denylist",
        Constraint::MaxRowsReturned(_) => "max_rows_returned",
        Constraint::OperationClass(_) => "operation_class",
        Constraint::AudienceAllowlist(_) => "audience_allowlist",
        Constraint::ContentReviewTier(_) => "content_review_tier",
        Constraint::MaxTransactionAmountUsd(_) => "max_transaction_amount_usd",
        Constraint::RequireDualApproval(_) => "require_dual_approval",
        Constraint::ModelConstraint { .. } => "model_constraint",
        Constraint::MemoryStoreAllowlist(_) => "memory_store_allowlist",
        Constraint::MemoryWriteDenyPatterns(_) => "memory_write_deny_patterns",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn grant(constraints: Vec<Constraint>) -> ToolGrant {
        ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "tool-a".to_string(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: Some(4),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            max_total_cost: None,
            dpop_required: Some(true),
        }
    }

    #[test]
    fn normalized_scope_preserves_subset_logic_for_supported_surface() {
        let parent = ChioScope {
            grants: vec![grant(vec![Constraint::PathPrefix("/tmp".to_string())])],
            resource_grants: vec![ResourceGrant {
                uri_pattern: "chio://receipts/*".to_string(),
                operations: vec![Operation::Read],
            }],
            prompt_grants: vec![PromptGrant {
                prompt_name: "*".to_string(),
                operations: vec![Operation::Get],
            }],
        };
        let child = ChioScope {
            grants: vec![grant(vec![
                Constraint::PathPrefix("/tmp".to_string()),
                Constraint::MaxLength(32),
            ])],
            resource_grants: vec![ResourceGrant {
                uri_pattern: "chio://receipts/session/*".to_string(),
                operations: vec![Operation::Read],
            }],
            prompt_grants: vec![PromptGrant {
                prompt_name: "risk_*".to_string(),
                operations: vec![Operation::Get],
            }],
        };

        let normalized_parent = NormalizedScope::try_from(&parent).expect("parent normalizes");
        let normalized_child = NormalizedScope::try_from(&child).expect("child normalizes");

        assert!(normalized_child.is_subset_of(&normalized_parent));
    }

    #[test]
    fn normalized_scope_rejects_unsupported_constraint() {
        let scope = ChioScope {
            grants: vec![grant(vec![Constraint::TableAllowlist(vec![
                "users".to_string()
            ])])],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        let error = NormalizedScope::try_from(&scope).expect_err("unsupported constraint fails");
        assert_eq!(
            error,
            NormalizationError::UnsupportedConstraint {
                kind: "table_allowlist".to_string(),
            }
        );
    }

    #[test]
    fn normalized_scope_rejects_cumulative_approval_until_enforced() {
        let scope = ChioScope {
            grants: vec![grant(vec![Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 10,
                    currency: "USD".to_string(),
                },
                approval_budget_id: "budget-1".to_string(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            }])],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        let error = NormalizedScope::try_from(&scope)
            .expect_err("cumulative approval requires atomic enforcement");
        assert_eq!(
            error,
            NormalizationError::UnsupportedConstraint {
                kind: "require_cumulative_approval_above".to_string(),
            }
        );
    }

    #[test]
    fn normalized_evaluation_captures_verified_projection() {
        let request = PortableToolCallRequest {
            request_id: "req-1".to_string(),
            tool_name: "tool-a".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({"path":"/tmp/demo.txt"}),
        };
        let verified = VerifiedCapability {
            id: "cap-1".to_string(),
            subject_hex: "agent-1".to_string(),
            issuer_hex: "issuer-1".to_string(),
            scope: ChioScope {
                grants: vec![grant(vec![Constraint::PathPrefix("/tmp".to_string())])],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 10,
            expires_at: 20,
            evaluated_at: 15,
        };
        let verdict = EvaluationVerdict {
            verdict: Verdict::Allow,
            reason: None,
            matched_grant_index: Some(0),
            verified: Some(verified),
        };

        let normalized = NormalizedEvaluationVerdict::try_from_evaluation(&request, &verdict)
            .expect("evaluation normalizes");

        assert_eq!(normalized.request.request_id, "req-1");
        assert_eq!(normalized.verdict, NormalizedVerdict::Allow);
        assert_eq!(
            normalized
                .verified
                .as_ref()
                .expect("verified projection present")
                .capability
                .id,
            "cap-1"
        );
    }
}
