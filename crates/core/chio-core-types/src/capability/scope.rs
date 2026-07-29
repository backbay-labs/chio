use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::cumulative_approval::CumulativeApprovalRootBinding;
use super::governance::{GovernedAutonomyTier, ProvenanceEvidenceClass};
use super::runtime_attestation::RuntimeAssuranceTier;

/// What a capability token authorizes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChioScope {
    /// Individual tool grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<ToolGrant>,

    /// Individual resource grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_grants: Vec<ResourceGrant>,

    /// Individual prompt grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_grants: Vec<PromptGrant>,
}

impl ChioScope {
    /// Whether any grant authorizes delegation.
    #[must_use]
    pub fn authorizes_delegation(&self) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate))
            || self
                .resource_grants
                .iter()
                .any(|grant| grant.operations.contains(&Operation::Delegate))
            || self
                .prompt_grants
                .iter()
                .any(|grant| grant.operations.contains(&Operation::Delegate))
    }

    /// Whether this scope carries negotiated cumulative-approval semantics.
    #[must_use]
    pub fn has_cumulative_approval(&self) -> bool {
        self.grants.iter().any(|grant| {
            grant
                .constraints
                .iter()
                .any(Constraint::is_cumulative_approval)
        })
    }

    /// Returns true if `self` is a subset of `other` -- that is, every grant
    /// in `self` is covered by some grant in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &ChioScope) -> bool {
        self.grants.iter().all(|child_grant| {
            other
                .grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.resource_grants.iter().all(|child_grant| {
            other
                .resource_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.prompt_grants.iter().all(|child_grant| {
            other
                .prompt_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        })
    }
}

/// A monetary amount with currency denomination.
///
/// Uses minor-unit integers to avoid floating-point precision issues.
/// For USD, 1 dollar = 100 units (cents). For JPY, 1 yen = 1 unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. cents for USD).
    pub units: u64,
    /// ISO 4217 currency code. Examples: "USD", "EUR", "JPY".
    pub currency: String,
}

/// Authorization for a single tool on a single server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolGrant {
    /// Which tool server (by server_id from the manifest).
    pub server_id: String,
    /// Which tool on that server.
    pub tool_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
    /// Parameter constraints that narrow the tool's input space.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// Maximum number of invocations allowed under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    /// Maximum monetary cost per single invocation under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    /// Maximum aggregate monetary cost across all invocations under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    /// If Some(true), the kernel requires a valid DPoP proof for every invocation.
    /// None and Some(false) both mean DPoP is not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_required: Option<bool>,
}

impl ToolGrant {
    /// Returns true if `self` is a subset of `parent`.
    ///
    /// A child grant is a subset when:
    /// - It targets the same server and tool, unless the parent uses `*`.
    /// - Its operations are a subset of the parent's.
    /// - Its max_invocations is no greater than the parent's (if set).
    /// - Its constraints are at least as restrictive (superset of constraints).
    #[must_use]
    pub fn is_subset_of(&self, parent: &ToolGrant) -> bool {
        // Must target the same server + tool (or parent grants all via "*")
        if parent.server_id != "*" && self.server_id != parent.server_id {
            return false;
        }
        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        // Child operations must be a subset of parent operations
        let ops_ok = self
            .operations
            .iter()
            .all(|op| parent.operations.contains(op));
        if !ops_ok {
            return false;
        }

        // If parent has an invocation cap, child must too and it must be <= parent
        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                None => return false, // child is uncapped but parent is capped
                Some(_) => return false, // child exceeds parent
            }
        }

        // Child must have at least as many constraints (more restrictive).
        // Each parent constraint must appear in the child's constraint list.
        let constraints_ok = parent.constraints.iter().all(|parent_constraint| {
            self.constraints
                .iter()
                .any(|child_constraint| parent_constraint.is_preserved_by(child_constraint))
        }) && self
            .constraints
            .iter()
            .filter(|constraint| constraint.is_cumulative_approval())
            .all(|child_constraint| {
                parent
                    .constraints
                    .iter()
                    .any(|parent_constraint| parent_constraint.is_preserved_by(child_constraint))
            });
        if !constraints_ok {
            return false;
        }

        // If parent has a per-invocation cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_cost_per_invocation {
            match &self.max_cost_per_invocation {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent has a total cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_total_cost {
            match &self.max_total_cost {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent requires DPoP, child must also require DPoP.
        // If parent does not require DPoP (None or Some(false)), child may do anything.
        if parent.dpop_required == Some(true) && self.dpop_required != Some(true) {
            return false;
        }

        true
    }
}

/// Authorization for reading or subscribing to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGrant {
    /// URI pattern identifying which resources are in scope.
    pub uri_pattern: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl ResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &ResourceGrant) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Authorization for retrieving a prompt by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGrant {
    /// Prompt name pattern.
    pub prompt_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl PromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &PromptGrant) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
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

/// An operation that can be performed under a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Invoke the tool (execute it).
    Invoke,
    /// Read the result of a previous invocation.
    ReadResult,
    /// Read a resource.
    Read,
    /// Subscribe to resource updates.
    Subscribe,
    /// Retrieve a prompt.
    Get,
    /// Delegate this grant to another agent.
    Delegate,
}

/// Operation class for data-layer tool calls (SQL, document DB, etc.).
///
/// Used by `Constraint::OperationClass` to restrict a grant to read-only,
/// read-write, or administrative operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOperationClass {
    /// SELECT and other read-only statements only.
    ReadOnly,
    /// Read and write (INSERT, UPDATE, DELETE) but no schema changes.
    ReadWrite,
    /// Schema-altering or privilege-altering operations.
    Admin,
}

/// Content review tier for outbound communication constraints.
///
/// Used by `Constraint::ContentReviewTier` to indicate the level of
/// content review that downstream guards should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentReviewTier {
    /// No content review required.
    None,
    /// Basic heuristic review (e.g. keyword filters).
    Basic,
    /// Strict review (e.g. model-based review or human approval).
    Strict,
}

/// Safety tier for model-routing constraints.
///
/// Used by `Constraint::ModelConstraint` to express a minimum safety
/// floor for the model executing a tool-bearing agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSafetyTier {
    /// Low assurance: unfiltered or permissive models.
    Low,
    /// Standard assurance: baseline safety filters.
    Standard,
    /// High assurance: stricter safety filters and evaluations.
    High,
    /// Restricted: only models meeting restricted-use criteria.
    Restricted,
}

/// A constraint on tool parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Constraint {
    /// File path parameter must start with this prefix.
    PathPrefix(String),
    /// Network domain must match exactly.
    DomainExact(String),
    /// Network domain must match a glob pattern.
    DomainGlob(String),
    /// Parameter must match a regular expression.
    RegexMatch(String),
    /// String parameter must not exceed this length.
    MaxLength(usize),
    /// Serialized argument payload must not exceed this many bytes.
    MaxArgsSize(usize),
    /// Requests must carry a governed transaction intent.
    GovernedIntentRequired,
    /// Requests at or above this threshold require a valid approval token.
    RequireApprovalAbove { threshold_units: u64 },
    /// Cumulative authorized spend at or above this threshold requires approval.
    RequireCumulativeApprovalAbove {
        threshold: MonetaryAmount,
        approval_budget_id: String,
        approval_budget_epoch: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cumulative_approval_root_binding: Option<Box<CumulativeApprovalRootBinding>>,
    },
    /// Requests must carry commerce approval context for this exact seller.
    SellerExact(String),
    /// Governed requests must carry valid runtime attestation at or above this tier.
    MinimumRuntimeAssurance(RuntimeAssuranceTier),
    /// Governed requests at or above this autonomy tier must carry autonomy context and pass bond gating.
    MinimumAutonomyTier(GovernedAutonomyTier),
    /// Extensibility: arbitrary key-value constraint.
    Custom(String, String),

    // The variants below carry data-layer, communication, financial,
    // model-routing, and memory-governance policy. They serialize through
    // the same tagged serde envelope as the variants above
    // (`#[serde(tag = "type", content = "value", rename_all = "snake_case")]`).
    /// Data layer: database tables the grant may reference.
    ///
    /// Evaluated against parsed SQL by `chio-data-guards`; the kernel
    /// records the constraint and leaves enforcement to that guard.
    TableAllowlist(Vec<String>),
    /// Data layer: forbidden columns, formatted as `"table.column"`.
    ///
    /// Evaluated by `chio-data-guards`; kernel treats it as an advisory
    /// constraint and does not reject at the request-matching stage.
    ColumnDenylist(Vec<String>),
    /// Data layer: maximum number of rows a query may return.
    ///
    /// Enforced post-invocation by downstream result-shaping guards.
    MaxRowsReturned(u64),
    /// Data layer: operation class the grant authorises.
    OperationClass(SqlOperationClass),
    /// Communication: allowed recipient channels or IDs.
    AudienceAllowlist(Vec<String>),
    /// Communication: content review tier demanded of downstream guards.
    ContentReviewTier(ContentReviewTier),
    /// Financial: maximum transaction amount in USD.
    ///
    /// The value is a decimal string (e.g. `"100.00"`) because
    /// `rust_decimal` is not in the workspace.
    MaxTransactionAmountUsd(String),
    /// Financial: whether the grant requires dual approval before execution.
    RequireDualApproval(bool),
    /// Model routing: constrain the models this grant may execute under.
    ModelConstraint {
        /// Explicit allowlist of model identifiers. Empty means no allowlist.
        allowed_model_ids: Vec<String>,
        /// Minimum acceptable model safety tier, if any.
        min_safety_tier: Option<ModelSafetyTier>,
    },
    /// Memory governance: memory stores the grant may write to.
    MemoryStoreAllowlist(Vec<String>),
    /// Memory governance: regex patterns that block writes.
    ///
    /// Patterns are compiled lazily during kernel evaluation so invalid
    /// regexes do not break construction or round-trip serialization.
    MemoryWriteDenyPatterns(Vec<String>),
    /// Delivery: an Allow for this grant is valid only if the final
    /// post-transform output content hash equals this expected digest,
    /// otherwise the request is denied before any irreversible money
    /// movement.
    ///
    /// The value is a canonical lowercase 64-character hex SHA-256 digest.
    /// Unlike the argument-side constraints above, this is enforced at the
    /// output-aware durable terminal, not at request matching; the request
    /// matcher only admits the carrier. Every surface that cannot prove
    /// the output-aware terminal ordering rejects the constraint before it
    /// mutates budget or payment.
    OutputDigestSha256(String),
    /// Delivery: this grant authorizes exactly one purchased finding
    /// reveal. The provider-signed marker names the exact finding and
    /// listing being sold and closes over the settlement rail, so omitted
    /// purchase context can never downgrade into a generic
    /// digest-constrained call.
    ///
    /// Admission requires the request to name the same finding, a verified
    /// purchase context, and the settlement profile the selector admits.
    /// Surfaces without purchase-aware admission reject the marker before
    /// any budget or payment mutation.
    RequireFindingPurchase(Box<FindingPurchaseMarkerV1>),
}

/// Closed settlement selector for a purchased finding reveal.
///
/// The selector is signed into the grant by the provider, so a purchase
/// admitted for one rail cannot be replayed against another by omitting
/// its companion evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingSettlementSelector {
    /// Single-operator settlement over a local reversible hold: authorize
    /// before dispatch, capture only after the delivered output passes the
    /// digest and media checks, release on any failure.
    LocalReversibleHold,
    /// Cross-organization escrow settlement. The digest pins the exact
    /// settlement-profile envelope the escrow witness must satisfy.
    /// Registered for wire compatibility; admission rejects it until an
    /// escrow witness lane exists.
    CrossOrgEscrow {
        /// Canonical lowercase 64-hex SHA-256 digest of the signed
        /// settlement-profile envelope.
        settlement_profile_sha256: String,
    },
}

/// Provider-signed purchase binding carried by
/// [`Constraint::RequireFindingPurchase`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPurchaseMarkerV1 {
    /// Content-addressed id of the finding being sold.
    pub finding_id: String,
    /// Listing the sale was admitted under.
    pub listing_id: String,
    /// Closed settlement rail selector for this sale.
    pub settlement: FindingSettlementSelector,
}

impl Constraint {
    #[must_use]
    pub fn is_cumulative_approval(&self) -> bool {
        matches!(self, Self::RequireCumulativeApprovalAbove { .. })
    }

    #[must_use]
    pub fn cumulative_approval_root_binding(&self) -> Option<&CumulativeApprovalRootBinding> {
        match self {
            Self::RequireCumulativeApprovalAbove {
                cumulative_approval_root_binding,
                ..
            } => cumulative_approval_root_binding.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn set_cumulative_approval_root_binding(
        &mut self,
        binding: Option<CumulativeApprovalRootBinding>,
    ) -> Result<()> {
        match self {
            Self::RequireCumulativeApprovalAbove {
                cumulative_approval_root_binding,
                ..
            } => {
                *cumulative_approval_root_binding = binding.map(Box::new);
                Ok(())
            }
            _ => Err(Error::AttenuationViolation {
                reason: "constraint is not cumulative approval".into(),
            }),
        }
    }

    pub(crate) fn clear_cumulative_approval_root_binding(&mut self) {
        if let Self::RequireCumulativeApprovalAbove {
            cumulative_approval_root_binding,
            ..
        } = self
        {
            *cumulative_approval_root_binding = None;
        }
    }

    fn is_preserved_by(&self, child: &Self) -> bool {
        match (self, child) {
            (
                Self::RequireCumulativeApprovalAbove {
                    threshold: parent_threshold,
                    approval_budget_id: parent_budget_id,
                    approval_budget_epoch: parent_budget_epoch,
                    cumulative_approval_root_binding: parent_binding,
                },
                Self::RequireCumulativeApprovalAbove {
                    threshold: child_threshold,
                    approval_budget_id: child_budget_id,
                    approval_budget_epoch: child_budget_epoch,
                    cumulative_approval_root_binding: child_binding,
                },
            ) => {
                parent_budget_id == child_budget_id
                    && parent_budget_epoch == child_budget_epoch
                    && parent_threshold.currency == child_threshold.currency
                    && child_threshold.units <= parent_threshold.units
                    && match (parent_binding, child_binding) {
                        (Some(parent), Some(child)) => parent.canonical_eq(child),
                        (None, None) => true,
                        _ => false,
                    }
            }
            // A delivery digest is preserved only by an identical digest:
            // a child cannot loosen or drop the expected output.
            (Self::OutputDigestSha256(parent), Self::OutputDigestSha256(child)) => parent == child,
            // A purchase marker is preserved only by an identical marker:
            // delegation cannot retarget the finding, listing, or rail.
            (Self::RequireFindingPurchase(parent), Self::RequireFindingPurchase(child)) => {
                parent == child
            }
            _ => self == child,
        }
    }
}

/// Metadata describing the model executing a tool-bearing agent.
///
/// Carried on `ToolCallRequest` so the kernel can evaluate
/// `Constraint::ModelConstraint` against the calling model's identity
/// and safety tier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ModelMetadata {
    /// Model identifier (e.g. `"claude-opus-4"`, `"gpt-5"`).
    pub model_id: String,
    /// Declared safety tier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<ModelSafetyTier>,
    /// Optional provider label (e.g. `"anthropic"`, `"openai"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Provenance class describing how Chio learned this model identity.
    /// Defaults to `asserted`.
    #[serde(
        default,
        skip_serializing_if = "is_default_model_metadata_provenance_class"
    )]
    pub provenance_class: ProvenanceEvidenceClass,
}

fn is_default_model_metadata_provenance_class(class: &ProvenanceEvidenceClass) -> bool {
    *class == ProvenanceEvidenceClass::Asserted
}

impl ModelMetadata {
    #[must_use]
    pub fn with_provenance_class(mut self, provenance_class: ProvenanceEvidenceClass) -> Self {
        self.provenance_class = provenance_class;
        self
    }
}
