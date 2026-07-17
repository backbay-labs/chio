//! Hierarchical budget governance for enterprise fleet management.
//!
//! A tree-structured budget policy model that sits above the flat
//! [`crate::budget::BudgetPolicy`]. Parents cap children at
//! every level -- organization, department, team, agent -- and draft spend
//! is evaluated against every ancestor node. A tree is authoritative over
//! the shape and limits of budgets; it is storage-agnostic. Callers supply
//! a [`SpendSnapshot`] that represents current spend per node per window,
//! and the tree renders a fail-closed [`BudgetDecision`].
//!
//! # Relationship to [`crate::budget`]
//!
//! The flat [`crate::budget::BudgetEnforcer`] evaluates a single policy
//! scoped per-session, per-agent, or per-tool. Hierarchical governance
//! does not replace it. Instead, a [`BudgetTree`] expresses organizational
//! structure (org -> department -> team -> agent) where each node has its
//! own caps and window. The two coexist: the flat enforcer is per-grant,
//! while the tree is per-organization.
//!
//! # Persistence boundary
//!
//! This module does not own storage. Callers read a [`SpendSnapshot`] from
//! whatever backing store they use (SQLite, Redis, in-memory) and pass it
//! to [`BudgetTree::evaluate`]. The tree itself can be serialized to JSON
//! for configuration-as-data (`serialize` / `deserialize`). A downstream
//! SQLite-backed snapshot store is explicitly out of scope for this crate.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Identifier for a node in a budget tree.
///
/// Conventionally formatted as `scope/name`, e.g. `org/acme`,
/// `dept/acme/research`, `agent/alice`. No validation is enforced on the
/// string shape; the tree only requires unique IDs and acyclic parent
/// references.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BudgetNodeId(pub String);

impl BudgetNodeId {
    /// Construct a new node identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Return the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for BudgetNodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for BudgetNodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for BudgetNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Windowed budget period. Windows determine which spend bucket a draft
/// charges against and when counters roll over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetWindow {
    /// Calendar day boundaries (Unix epoch, 86400s).
    Daily,
    /// Calendar month boundaries in days (approximated as 30d). Callers
    /// needing precise calendar months should advance the snapshot window
    /// key externally.
    Monthly,
    /// Rolling window of the given duration in seconds.
    Rolling {
        /// Window length in seconds.
        seconds: u64,
    },
}

impl BudgetWindow {
    /// Return the window length in seconds. Monthly approximates to 30 days.
    #[must_use]
    pub fn duration_seconds(&self) -> u64 {
        match self {
            Self::Daily => 86_400,
            Self::Monthly => 86_400 * 30,
            Self::Rolling { seconds } => *seconds,
        }
    }

    /// Compute the window bucket key for a given timestamp. For fixed
    /// windows (Daily, Monthly) this is the bucket start; for Rolling
    /// windows, a caller-controlled snapshot key is appropriate and this
    /// function returns the window start that contains `ts`.
    #[must_use]
    pub fn bucket_start(&self, ts: u64) -> u64 {
        let d = self.duration_seconds();
        if d == 0 {
            return 0;
        }
        ts - (ts % d)
    }
}

/// Per-dimension spending caps for a node. All fields are optional so
/// partial policies compose cleanly (a node may cap only tokens, only
/// dollars, etc.).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimits {
    /// Maximum spend in minor currency units (e.g. cents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_spend_units: Option<u64>,

    /// ISO 4217 currency code for `max_spend_units`. Required if
    /// `max_spend_units` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Maximum number of tokens consumed within the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,

    /// Maximum number of tool-invocation requests within the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,

    /// Maximum warehouse-style data volume in bytes within the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_warehouse_bytes: Option<u64>,
}

/// A single node in a budget tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetNode {
    /// Unique identifier for this node.
    pub id: BudgetNodeId,

    /// Parent node identifier, if any. `None` marks a root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<BudgetNodeId>,

    /// Per-dimension limits applied at this node.
    #[serde(default)]
    pub limits: BudgetLimits,

    /// Window that limits apply to.
    pub window: BudgetWindow,

    /// When `false`, the node denies all draft spend with
    /// [`BudgetDenyReason::NodeDisabled`].
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl BudgetNode {
    /// Construct a new enabled node with default (empty) limits and the
    /// given window.
    #[must_use]
    pub fn new(id: impl Into<BudgetNodeId>, window: BudgetWindow) -> Self {
        Self {
            id: id.into(),
            parent: None,
            limits: BudgetLimits::default(),
            window,
            enabled: true,
        }
    }

    /// Builder: set the parent node.
    #[must_use]
    pub fn with_parent(mut self, parent: impl Into<BudgetNodeId>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Builder: set the per-dimension limits.
    #[must_use]
    pub fn with_limits(mut self, limits: BudgetLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Builder: disable the node.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// A draft spend that a caller wants to check against the tree. Every
/// dimension is optional: a request that only consumes tokens sets only
/// `tokens`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSpend {
    /// Spend in minor currency units.
    #[serde(default)]
    pub spend_units: u64,

    /// Currency code associated with `spend_units`. A positive spend
    /// whose currency does not match the checked node's spend-cap
    /// currency fails closed: the cap denies it rather than skipping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Tokens consumed.
    #[serde(default)]
    pub tokens: u64,

    /// Number of requests. Commonly 1 per invocation.
    #[serde(default)]
    pub requests: u64,

    /// Warehouse bytes consumed.
    #[serde(default)]
    pub warehouse_bytes: u64,
}

impl AggregateSpend {
    /// Construct from a spend amount in minor units of `currency`.
    #[must_use]
    pub fn with_spend(units: u64, currency: impl Into<String>) -> Self {
        Self {
            spend_units: units,
            currency: Some(currency.into()),
            ..Self::default()
        }
    }

    /// Construct from a token count.
    #[must_use]
    pub fn with_tokens(tokens: u64) -> Self {
        Self {
            tokens,
            ..Self::default()
        }
    }

    /// Construct from a request count.
    #[must_use]
    pub fn with_requests(requests: u64) -> Self {
        Self {
            requests,
            ..Self::default()
        }
    }

    /// Construct from a warehouse byte count.
    #[must_use]
    pub fn with_warehouse_bytes(bytes: u64) -> Self {
        Self {
            warehouse_bytes: bytes,
            ..Self::default()
        }
    }

    fn saturating_add(&self, other: &Self) -> Self {
        Self {
            spend_units: self.spend_units.saturating_add(other.spend_units),
            currency: self.currency.clone().or_else(|| other.currency.clone()),
            tokens: self.tokens.saturating_add(other.tokens),
            requests: self.requests.saturating_add(other.requests),
            warehouse_bytes: self.warehouse_bytes.saturating_add(other.warehouse_bytes),
        }
    }
}

/// Current spend for a single window bucket of a single node.
///
/// A node with a rolling window may have many buckets open; consumers
/// track whichever window key they use for accounting. The evaluation
/// logic here only consults the bucket identified by the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerWindowSpend {
    /// Window-start timestamp (seconds since the Unix epoch). Rolling
    /// windows use the caller's start-of-window marker.
    #[serde(default)]
    pub window_start: u64,

    /// Current spend within the window.
    #[serde(default)]
    pub current: AggregateSpend,
}

/// Snapshot of current spend for every node involved in an evaluation.
///
/// Callers read this from their persistence layer (SQLite, Redis, etc.)
/// before calling [`BudgetTree::evaluate`]. Nodes absent from the map are
/// treated as having zero current spend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSnapshot {
    /// Current spend keyed by node id.
    #[serde(default)]
    pub per_node: HashMap<BudgetNodeId, PerWindowSpend>,
}

impl SpendSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite the current spend for a node.
    pub fn set(&mut self, id: BudgetNodeId, spend: PerWindowSpend) {
        self.per_node.insert(id, spend);
    }

    /// Look up the current spend for a node.
    #[must_use]
    pub fn get(&self, id: &BudgetNodeId) -> Option<&PerWindowSpend> {
        self.per_node.get(id)
    }
}

/// Why a draft spend was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum BudgetDenyReason {
    /// The node or one of its ancestors is disabled.
    NodeDisabled {
        /// The disabled node.
        node: BudgetNodeId,
    },
    /// A per-dimension cap would be exceeded at `node`.
    DimensionExceeded {
        /// The node whose cap was hit.
        node: BudgetNodeId,
        /// Dimension name. Stable identifiers:
        /// `"spend"`, `"tokens"`, `"requests"`, `"warehouse_bytes"`.
        dimension: String,
        /// Cap value formatted as a decimal string (with currency suffix
        /// for spend caps).
        cap: String,
        /// The projected post-charge value, formatted as a decimal string.
        would_reach: String,
    },
    /// The caller-supplied snapshot's window is older than allowed for
    /// this node's window. Callers should refresh the snapshot.
    WindowExpired {
        /// The node whose window has expired.
        node: BudgetNodeId,
    },
    /// The evaluated leaf id is not in the tree.
    UnknownNode {
        /// The node id that was looked up.
        node: BudgetNodeId,
    },
    /// A draft carrying positive spend hit a spend cap whose currency is
    /// absent or differs from the draft's. An uncomparable spend cap denies
    /// rather than being silently skipped, so a cross-currency draft can
    /// never walk through a cap it was meant to honor. Zero-spend drafts do
    /// not trigger this: they move no money, so the cap has nothing to
    /// prove against them.
    CurrencyMismatch {
        /// The spend-capped node whose currency could not be compared.
        node: BudgetNodeId,
        /// The node's declared currency, if any.
        node_currency: Option<String>,
        /// The draft's currency, if any.
        draft_currency: Option<String>,
    },
    /// The current spend plus the draft cannot be represented in `u64` for
    /// a checked dimension. A cap can never be soundly compared against an
    /// overflowed projection, so this denies rather than silently
    /// saturating to a value the cap would wrongly appear to permit.
    ProjectionOverflow {
        /// The node whose projection overflowed.
        node: BudgetNodeId,
        /// Dimension whose projection overflowed. Stable identifier:
        /// `"spend"`.
        dimension: String,
    },
}

/// Outcome of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BudgetDecision {
    /// The draft spend is within every ancestor's cap.
    Allow,
    /// The draft spend would exceed a cap, or the leaf is unknown.
    Deny {
        /// Cause of the denial. The tree deny path returns the
        /// closest-to-root offender so operators see the most restrictive
        /// scope first.
        reason: BudgetDenyReason,
    },
}

/// Errors from tree construction and serialization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    /// A node contains internally inconsistent limits.
    #[error("invalid limits for node `{node}`: {message}")]
    InvalidLimits {
        /// The node whose limits are invalid.
        node: BudgetNodeId,
        /// Human-readable validation message.
        message: String,
    },
    /// Insertion would create a cycle; the parent chain already includes
    /// the inserted node.
    #[error("cycle detected while inserting node `{node}` (conflicts with ancestor)")]
    Cycle {
        /// The node whose insertion would have created the cycle.
        node: BudgetNodeId,
    },
    /// Parent referenced by a node is missing from the tree.
    #[error("parent `{parent}` of node `{node}` is not present in the tree")]
    MissingParent {
        /// The node referencing a missing parent.
        node: BudgetNodeId,
        /// The missing parent id.
        parent: BudgetNodeId,
    },
    /// Attempted to insert a node whose id already exists.
    #[error("duplicate node id `{node}`")]
    Duplicate {
        /// The id that was already present.
        node: BudgetNodeId,
    },
    /// The supplied JSON value is not a valid tree representation.
    #[error("invalid serialized tree: {0}")]
    InvalidSerialization(String),
}

/// A tree of budget nodes supporting parent-capped evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetTree {
    nodes: HashMap<BudgetNodeId, BudgetNode>,
    children: HashMap<BudgetNodeId, Vec<BudgetNodeId>>,
}

impl BudgetTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Look up a node by id.
    #[must_use]
    pub fn get(&self, id: &BudgetNodeId) -> Option<&BudgetNode> {
        self.nodes.get(id)
    }

    /// Insert a node into the tree.
    ///
    /// Returns [`BudgetError::Duplicate`] if `node.id` already exists,
    /// [`BudgetError::MissingParent`] if the node references a parent that
    /// is not present, and [`BudgetError::Cycle`] if the new parent edge
    /// would make `node.id` its own ancestor.
    pub fn insert(&mut self, node: BudgetNode) -> Result<(), BudgetError> {
        if self.nodes.contains_key(&node.id) {
            return Err(BudgetError::Duplicate {
                node: node.id.clone(),
            });
        }
        validate_limits(&node)?;
        if let Some(parent) = &node.parent {
            if !self.nodes.contains_key(parent) {
                return Err(BudgetError::MissingParent {
                    node: node.id.clone(),
                    parent: parent.clone(),
                });
            }
            // Cycle check: walk from parent upward; if we ever land on
            // node.id, reject.
            let mut cursor: Option<BudgetNodeId> = Some(parent.clone());
            let mut visited: HashSet<BudgetNodeId> = HashSet::new();
            while let Some(current) = cursor {
                if current == node.id {
                    return Err(BudgetError::Cycle {
                        node: node.id.clone(),
                    });
                }
                if !visited.insert(current.clone()) {
                    // A pre-existing cycle in the stored tree: reject rather
                    // than loop forever.
                    return Err(BudgetError::Cycle {
                        node: node.id.clone(),
                    });
                }
                cursor = self.nodes.get(&current).and_then(|n| n.parent.clone());
            }
        }

        if let Some(parent) = &node.parent {
            self.children
                .entry(parent.clone())
                .or_default()
                .push(node.id.clone());
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Validate the tree: every referenced parent must exist and the
    /// parent graph must be acyclic.
    pub fn validate(&self) -> Result<(), BudgetError> {
        for node in self.nodes.values() {
            validate_limits(node)?;
            if let Some(parent) = &node.parent {
                if !self.nodes.contains_key(parent) {
                    return Err(BudgetError::MissingParent {
                        node: node.id.clone(),
                        parent: parent.clone(),
                    });
                }
            }
        }
        // Acyclicity check from every node.
        for id in self.nodes.keys() {
            let mut visited: HashSet<BudgetNodeId> = HashSet::new();
            let mut cursor = Some(id.clone());
            while let Some(current) = cursor {
                if !visited.insert(current.clone()) {
                    return Err(BudgetError::Cycle { node: id.clone() });
                }
                cursor = self.nodes.get(&current).and_then(|n| n.parent.clone());
            }
        }
        Ok(())
    }

    /// Return ancestors of `id` in leaf-to-root order including `id` at
    /// position 0. If `id` is absent, returns an empty vector.
    #[must_use]
    pub fn ancestors(&self, id: &BudgetNodeId) -> Vec<BudgetNodeId> {
        let mut out = Vec::new();
        let mut visited: HashSet<BudgetNodeId> = HashSet::new();
        let mut cursor: Option<BudgetNodeId> = if self.nodes.contains_key(id) {
            Some(id.clone())
        } else {
            None
        };
        while let Some(current) = cursor {
            if !visited.insert(current.clone()) {
                break;
            }
            let next = self.nodes.get(&current).and_then(|n| n.parent.clone());
            out.push(current);
            cursor = next;
        }
        out
    }

    /// Return every descendant of `id` (not including `id` itself).
    /// Order is breadth-first starting from direct children.
    #[must_use]
    pub fn descendants(&self, id: &BudgetNodeId) -> Vec<BudgetNodeId> {
        let mut out = Vec::new();
        if !self.nodes.contains_key(id) {
            return out;
        }
        let mut queue: Vec<BudgetNodeId> = self.children.get(id).cloned().unwrap_or_default();
        let mut visited: HashSet<BudgetNodeId> = HashSet::new();
        while let Some(current) = queue.first().cloned() {
            queue.remove(0);
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(next) = self.children.get(&current) {
                for c in next {
                    queue.push(c.clone());
                }
            }
            out.push(current);
        }
        out
    }

    /// Evaluate whether `draft` may be charged to node `id`.
    ///
    /// The decision walks from the leaf up to the root and denies if any
    /// node is disabled or any cap would be exceeded. The reason field
    /// references the node closest to the root among the offenders so
    /// that broad policy boundaries surface first.
    #[must_use]
    pub fn evaluate(
        &self,
        id: &BudgetNodeId,
        draft: AggregateSpend,
        current: &SpendSnapshot,
    ) -> BudgetDecision {
        if !self.nodes.contains_key(id) {
            return BudgetDecision::Deny {
                reason: BudgetDenyReason::UnknownNode { node: id.clone() },
            };
        }

        let ancestors = self.ancestors(id);
        let mut offender: Option<(usize, BudgetDenyReason)> = None;
        for (idx, node_id) in ancestors.iter().enumerate() {
            let Some(node) = self.nodes.get(node_id) else {
                continue;
            };
            if !node.enabled {
                let candidate = BudgetDenyReason::NodeDisabled {
                    node: node_id.clone(),
                };
                offender = Some((idx, candidate));
                continue;
            }
            let zero = PerWindowSpend::default();
            let current_spend = current.per_node.get(node_id).unwrap_or(&zero);
            let projected = current_spend.current.saturating_add(&draft);
            let limits = &node.limits;

            if let Some(cap) = limits.max_spend_units {
                // A capped node always carries a currency (enforced at
                // insert). The cap is denominated in that currency and this
                // layer does not convert: cross-currency conversion is the
                // caller's responsibility and must run before evaluation.
                match (&limits.currency, &draft.currency) {
                    (Some(node_currency), Some(draft_currency))
                        if node_currency == draft_currency =>
                    {
                        match current_spend
                            .current
                            .spend_units
                            .checked_add(draft.spend_units)
                        {
                            Some(projected_spend_units) => {
                                if projected_spend_units > cap {
                                    let cap_str = format!("{cap} {node_currency}");
                                    let reach_str = format!(
                                        "{projected_spend_units} {}",
                                        projected.currency.clone().unwrap_or_default()
                                    );
                                    let candidate = BudgetDenyReason::DimensionExceeded {
                                        node: node_id.clone(),
                                        dimension: "spend".to_string(),
                                        cap: cap_str,
                                        would_reach: reach_str,
                                    };
                                    offender = Some((idx, candidate));
                                }
                            }
                            None => {
                                // The checked add overflowed u64: saturating
                                // here would compare the cap against a value
                                // that understates the true projected spend,
                                // so this denies instead.
                                let candidate = BudgetDenyReason::ProjectionOverflow {
                                    node: node_id.clone(),
                                    dimension: "spend".to_string(),
                                };
                                offender = Some((idx, candidate));
                            }
                        }
                    }
                    _ if draft.spend_units > 0 => {
                        // Fail closed: a positive spend whose currency is
                        // absent or differs from the node's cannot be proven
                        // within the cap, so it is denied rather than
                        // silently skipped.
                        let candidate = BudgetDenyReason::CurrencyMismatch {
                            node: node_id.clone(),
                            node_currency: limits.currency.clone(),
                            draft_currency: draft.currency.clone(),
                        };
                        offender = Some((idx, candidate));
                    }
                    _ => {
                        // A zero-spend draft moves no money and cannot
                        // breach a spend cap; the remaining dimensions
                        // still evaluate.
                    }
                }
            }

            if let Some(cap) = limits.max_tokens {
                if projected.tokens > cap {
                    let candidate = BudgetDenyReason::DimensionExceeded {
                        node: node_id.clone(),
                        dimension: "tokens".to_string(),
                        cap: cap.to_string(),
                        would_reach: projected.tokens.to_string(),
                    };
                    offender = Some((idx, candidate));
                }
            }

            if let Some(cap) = limits.max_requests {
                if projected.requests > cap {
                    let candidate = BudgetDenyReason::DimensionExceeded {
                        node: node_id.clone(),
                        dimension: "requests".to_string(),
                        cap: cap.to_string(),
                        would_reach: projected.requests.to_string(),
                    };
                    offender = Some((idx, candidate));
                }
            }

            if let Some(cap) = limits.max_warehouse_bytes {
                if projected.warehouse_bytes > cap {
                    let candidate = BudgetDenyReason::DimensionExceeded {
                        node: node_id.clone(),
                        dimension: "warehouse_bytes".to_string(),
                        cap: cap.to_string(),
                        would_reach: projected.warehouse_bytes.to_string(),
                    };
                    offender = Some((idx, candidate));
                }
            }
        }

        match offender {
            None => BudgetDecision::Allow,
            Some((_, reason)) => BudgetDecision::Deny { reason },
        }
    }

    /// Serialize the tree to a stable JSON representation. Nodes are
    /// emitted sorted by id so the encoding is deterministic.
    #[must_use]
    pub fn serialize(&self) -> serde_json::Value {
        let mut ids: Vec<&BudgetNodeId> = self.nodes.keys().collect();
        ids.sort();
        let nodes: Vec<&BudgetNode> = ids.iter().filter_map(|id| self.nodes.get(id)).collect();
        serde_json::json!({
            "version": 1,
            "nodes": nodes,
        })
    }

    /// Deserialize a tree from its JSON encoding. Validates structure on
    /// the way in so the returned tree is guaranteed cycle-free with
    /// every referenced parent present.
    pub fn deserialize(v: serde_json::Value) -> Result<Self, BudgetError> {
        #[derive(Deserialize)]
        struct Encoded {
            #[serde(default)]
            nodes: Vec<BudgetNode>,
        }
        let enc: Encoded = serde_json::from_value(v)
            .map_err(|e| BudgetError::InvalidSerialization(format!("{e}")))?;

        // Insert roots first, then children whose parents are already
        // present. This lets the cycle/missing-parent checks run as each
        // node is added.
        let mut tree = Self::new();
        let mut remaining: Vec<BudgetNode> = enc.nodes;
        loop {
            let before = remaining.len();
            let mut next: Vec<BudgetNode> = Vec::new();
            for node in remaining {
                let parent_ready = match &node.parent {
                    None => true,
                    Some(p) => tree.nodes.contains_key(p),
                };
                if parent_ready {
                    tree.insert(node)?;
                } else {
                    next.push(node);
                }
            }
            if next.is_empty() {
                break;
            }
            if next.len() == before {
                // Forward progress stalled; remaining nodes point at
                // missing parents or form a cycle among themselves.
                let first = next.into_iter().next();
                if let Some(node) = first {
                    let parent = node.parent.clone().unwrap_or_else(|| BudgetNodeId::new(""));
                    return Err(BudgetError::MissingParent {
                        node: node.id,
                        parent,
                    });
                }
                break;
            }
            remaining = next;
        }

        tree.validate()?;
        Ok(tree)
    }
}

fn validate_limits(node: &BudgetNode) -> Result<(), BudgetError> {
    if node.limits.max_spend_units.is_some() {
        let valid_currency = node
            .limits
            .currency
            .as_deref()
            .is_some_and(|currency| !currency.trim().is_empty());
        if !valid_currency {
            return Err(BudgetError::InvalidLimits {
                node: node.id.clone(),
                message: "max_spend_units requires non-empty currency".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(
        id: &str,
        parent: Option<&str>,
        limits: BudgetLimits,
        window: BudgetWindow,
    ) -> BudgetNode {
        let mut n = BudgetNode::new(id, window).with_limits(limits);
        if let Some(p) = parent {
            n = n.with_parent(p);
        }
        n
    }

    #[test]
    fn duplicate_insert_is_rejected() {
        let mut tree = BudgetTree::new();
        tree.insert(leaf(
            "org/acme",
            None,
            BudgetLimits::default(),
            BudgetWindow::Daily,
        ))
        .expect("insert");
        let err = tree
            .insert(leaf(
                "org/acme",
                None,
                BudgetLimits::default(),
                BudgetWindow::Daily,
            ))
            .unwrap_err();
        assert!(matches!(err, BudgetError::Duplicate { .. }));
    }

    #[test]
    fn missing_parent_is_rejected() {
        let mut tree = BudgetTree::new();
        let err = tree
            .insert(leaf(
                "team/x",
                Some("dept/missing"),
                BudgetLimits::default(),
                BudgetWindow::Daily,
            ))
            .unwrap_err();
        assert!(matches!(err, BudgetError::MissingParent { .. }));
    }

    #[test]
    fn spend_limits_require_currency_at_insert() {
        let mut tree = BudgetTree::new();
        let result = tree.insert(leaf(
            "org/no-currency",
            None,
            BudgetLimits {
                max_spend_units: Some(100),
                currency: None,
                ..BudgetLimits::default()
            },
            BudgetWindow::Daily,
        ));

        assert!(matches!(
            result,
            Err(BudgetError::InvalidLimits { ref node, .. }) if node.as_str() == "org/no-currency"
        ));

        let mut blank = BudgetTree::new();
        let result = blank.insert(leaf(
            "org/blank-currency",
            None,
            BudgetLimits {
                max_spend_units: Some(100),
                currency: Some(" \t".to_string()),
                ..BudgetLimits::default()
            },
            BudgetWindow::Daily,
        ));

        assert!(matches!(
            result,
            Err(BudgetError::InvalidLimits { ref node, .. }) if node.as_str() == "org/blank-currency"
        ));
    }

    #[test]
    fn deserialize_rejects_spend_limit_without_currency() {
        let encoded = serde_json::json!({
            "version": 1,
            "nodes": [{
                "id": "org/no-currency",
                "limits": {
                    "max_spend_units": 100
                },
                "window": {
                    "kind": "daily"
                },
                "enabled": true
            }]
        });

        let result = BudgetTree::deserialize(encoded);

        assert!(matches!(
            result,
            Err(BudgetError::InvalidLimits { ref node, .. }) if node.as_str() == "org/no-currency"
        ));
    }

    #[test]
    fn bucket_start_is_window_aligned() {
        assert_eq!(BudgetWindow::Daily.bucket_start(0), 0);
        assert_eq!(BudgetWindow::Daily.bucket_start(86_399), 0);
        assert_eq!(BudgetWindow::Daily.bucket_start(86_400), 86_400);
        assert_eq!(
            BudgetWindow::Rolling { seconds: 3600 }.bucket_start(7_200 + 5),
            7_200
        );
    }

    #[test]
    fn spend_cap_denies_on_currency_mismatch_and_absence() {
        let limits = BudgetLimits {
            max_spend_units: Some(100),
            currency: Some("USD".to_string()),
            ..BudgetLimits::default()
        };
        let mut tree = BudgetTree::new();
        tree.insert(leaf("root", None, limits, BudgetWindow::Daily))
            .expect("insert");
        let id = BudgetNodeId::from("root");
        let snapshot = SpendSnapshot::new();

        // A draft in a different currency is under the numeric cap but cannot
        // be compared against it; the uncomparable cap denies instead of
        // being silently skipped.
        match tree.evaluate(&id, AggregateSpend::with_spend(10, "EUR"), &snapshot) {
            BudgetDecision::Deny {
                reason:
                    BudgetDenyReason::CurrencyMismatch {
                        node_currency,
                        draft_currency,
                        ..
                    },
            } => {
                assert_eq!(node_currency.as_deref(), Some("USD"));
                assert_eq!(draft_currency.as_deref(), Some("EUR"));
            }
            other => panic!("EUR draft was not denied: {other:?}"),
        }

        // A draft carrying no currency at all is equally uncomparable.
        let no_currency = AggregateSpend {
            spend_units: 10,
            ..AggregateSpend::default()
        };
        match tree.evaluate(&id, no_currency, &snapshot) {
            BudgetDecision::Deny {
                reason: BudgetDenyReason::CurrencyMismatch { .. },
            } => {}
            other => panic!("currency-absent draft was not denied: {other:?}"),
        }

        // A matching-currency draft under the cap still allows.
        assert!(matches!(
            tree.evaluate(&id, AggregateSpend::with_spend(10, "USD"), &snapshot),
            BudgetDecision::Allow
        ));

        // A matching-currency draft over the cap keeps the existing reason.
        match tree.evaluate(&id, AggregateSpend::with_spend(500, "USD"), &snapshot) {
            BudgetDecision::Deny {
                reason: BudgetDenyReason::DimensionExceeded { dimension, .. },
            } => assert_eq!(dimension, "spend"),
            other => panic!("USD over-cap draft got {other:?}"),
        }
    }
}
