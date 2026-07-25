//! Vector database guard.
//!
//! `VectorDbGuard` inspects tool calls that target a vector database --
//! Pinecone, Weaviate, Qdrant, Chroma, or any database the operator
//! configures as vector-flavored -- and enforces four categories of
//! policy that the SQL guard cannot:
//!
//! 1. **Collection allowlist.** A query to a collection that is not on the
//!    operator's allowlist is denied.
//! 2. **Namespace scoping.** A query whose `namespace` field falls
//!    outside the configured namespace allowlist is denied. Missing
//!    namespaces deny when namespace enforcement is configured.
//! 3. **Operation class.** Upsert, delete, or index-mutation verbs are
//!    denied when the active grant carries
//!    [`SqlOperationClass::ReadOnly`](chio_core::capability::scope::SqlOperationClass::ReadOnly).
//!    The reuse of `SqlOperationClass` is deliberate so a single
//!    constraint enum covers every database-shaped grant.
//! 4. **`top_k` ceiling.** A query whose `top_k` exceeds the grant's
//!    [`Constraint::MaxRowsReturned`](chio_core::capability::scope::Constraint::MaxRowsReturned)
//!    is denied.  The guard fails closed when `top_k` is missing from the
//!    arguments and a ceiling is configured.
//!
//! # Fail-closed rules
//!
//! Like every other guard in this crate, the vector guard is fail-closed:
//!
//! - JSON parse errors in the arguments deny.
//! - Missing required fields (collection when the allowlist is non-empty,
//!   namespace when a namespace is configured, `top_k` when a ceiling is
//!   configured) deny.
//! - An empty collection allowlist denies every request (no collection is
//!   implicitly allowed).  Operators can opt into an open configuration
//!   via [`VectorGuardConfig::allow_all`].
//!
//! # Action detection
//!
//! `chio-guards` already categorises some vector flows as
//! [`ToolAction::MemoryRead`]/[`ToolAction::MemoryWrite`]; this guard
//! primarily drives off [`ToolAction::DatabaseQuery`] with a
//! vector-flavored `database` (or a tool name that matches a configured
//! vendor substring) so it can enforce the same policy against bespoke
//! vendor-adapted SDK tools as well.  The memory-read/write actions are
//! handled as a second pass -- they carry the store and optional key but
//! no `top_k` or `operation` hint, so the guard lifts those from the raw
//! arguments JSON.
//!
//! # Tool argument schema
//!
//! The guard extracts four fields from the tool arguments by JSON path:
//!
//! | field         | default arg keys                        |
//! |---------------|-----------------------------------------|
//! | collection    | `collection`, `index`, `class`, `store` |
//! | namespace     | `namespace`, `tenant`, `partition`      |
//! | operation     | `operation`, `op`, `action`             |
//! | top_k         | `top_k`, `topK`, `k`, `limit`           |
//!
//! All paths are configurable via [`VectorGuardConfig::field_paths`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use chio_core::capability::scope::{ChioScope, Constraint, SqlOperationClass, ToolGrant};
use chio_guards::{extract_action_checked, ToolAction};
use chio_kernel::{GuardContext, GuardDecision, KernelError};
use thiserror::Error;

/// Structured reason for a [`VectorDbGuard`] denial.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VectorGuardDenyReason {
    /// The tool action is not a database/memory style access the guard
    /// can reason about, but policy requires one.  Emitted only in tests;
    /// the guard passes through unknown actions at runtime.
    #[error("tool action is not a vector-database access")]
    NotAVectorAccess,

    /// The request does not target a vector database according to the
    /// configured vendor substrings and `allow_all` is disabled.
    #[error("database '{database}' is not flagged as vector-shaped")]
    NotVectorFlavored {
        /// The database identifier reported by the tool call.
        database: String,
    },

    /// A referenced collection is not on the operator's allowlist.
    #[error("collection '{collection}' is not in the allowlist")]
    CollectionNotAllowed {
        /// The offending collection name.
        collection: String,
    },

    /// The collection allowlist is empty and `allow_all` is false.
    #[error("vector guard has no configured collection allowlist and allow_all is false")]
    NoConfig,

    /// The request targets a namespace that is not permitted by the
    /// configured namespace allowlist.
    #[error("namespace '{namespace}' is not in the allowlist")]
    NamespaceNotAllowed {
        /// The offending namespace name.
        namespace: String,
    },

    /// The operation verb was denied (for example an `upsert` under a
    /// read-only grant).
    #[error("operation '{operation}' is not allowed by the active operation class")]
    OperationNotAllowed {
        /// The offending operation verb.
        operation: String,
    },

    /// A `top_k` (or equivalent) value exceeds the configured ceiling.
    #[error("top_k {requested} exceeds max_rows_returned {max}")]
    TopKExceedsLimit {
        /// The requested top-k value.
        requested: u64,
        /// The configured ceiling.
        max: u64,
    },

    /// The arguments could not be parsed.
    #[error("vector guard argument parse error: {error}")]
    ParseError {
        /// Human readable error message.
        error: String,
    },
}

impl VectorGuardDenyReason {
    /// Short stable tag suitable for metrics labels.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAVectorAccess => "not_a_vector_access",
            Self::NotVectorFlavored { .. } => "not_vector_flavored",
            Self::CollectionNotAllowed { .. } => "collection_not_allowed",
            Self::NoConfig => "no_config",
            Self::NamespaceNotAllowed { .. } => "namespace_not_allowed",
            Self::OperationNotAllowed { .. } => "operation_not_allowed",
            Self::TopKExceedsLimit { .. } => "top_k_exceeds_limit",
            Self::ParseError { .. } => "parse_error",
        }
    }
}

/// Configurable JSON field paths for the argument extractor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorFieldPaths {
    /// Keys scanned in order for the collection/index name.
    pub collection: Vec<String>,
    /// Keys scanned in order for the namespace.
    pub namespace: Vec<String>,
    /// Keys scanned in order for the operation verb.
    pub operation: Vec<String>,
    /// Keys scanned in order for the top-k value.
    pub top_k: Vec<String>,
}

impl Default for VectorFieldPaths {
    fn default() -> Self {
        Self {
            collection: vec![
                "collection".into(),
                "index".into(),
                "class".into(),
                "store".into(),
            ],
            namespace: vec!["namespace".into(), "tenant".into(), "partition".into()],
            operation: vec!["operation".into(), "op".into(), "action".into()],
            top_k: vec!["top_k".into(), "topK".into(), "k".into(), "limit".into()],
        }
    }
}

/// Configuration for [`VectorDbGuard`].
///
/// The guard is fail-closed by default: an empty `collection_allowlist`
/// denies every call unless `allow_all` is set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorGuardConfig {
    /// Substrings that mark a database identifier (or tool name) as
    /// vector-flavored.  Defaults to the four supported vendors plus the
    /// generic `"vector"` sentinel.
    #[serde(default = "default_vendor_markers")]
    pub vendor_markers: Vec<String>,

    /// Collections the grant may touch.  Case-insensitive.
    #[serde(default)]
    pub collection_allowlist: Vec<String>,

    /// Optional namespace allowlist.  `None` disables namespace
    /// enforcement; `Some(empty)` denies every namespaced request.
    #[serde(default)]
    pub namespace_allowlist: Option<Vec<String>>,

    /// Operation verbs that are always denied regardless of the active
    /// operation class (for example: `"drop_index"`).  Case-insensitive.
    #[serde(default)]
    pub denied_operations: Vec<String>,

    /// Operation verbs considered "mutating" for the purposes of
    /// [`SqlOperationClass::ReadOnly`] enforcement.  Case-insensitive.
    #[serde(default = "default_mutating_operations")]
    pub mutating_operations: Vec<String>,

    /// JSON field path overrides.
    #[serde(default)]
    pub field_paths: VectorFieldPaths,

    /// Allow every request that passes field-path parsing, ignoring the
    /// allowlists.  Parse errors still deny.
    #[serde(default)]
    pub allow_all: bool,
}

fn default_vendor_markers() -> Vec<String> {
    vec![
        "vector".into(),
        "pinecone".into(),
        "weaviate".into(),
        "qdrant".into(),
        "chroma".into(),
        "milvus".into(),
    ]
}

fn default_mutating_operations() -> Vec<String> {
    vec![
        "upsert".into(),
        "insert".into(),
        "update".into(),
        "delete".into(),
        "write".into(),
        "index".into(),
        "reindex".into(),
        "drop".into(),
        "drop_index".into(),
        "create_collection".into(),
        "delete_collection".into(),
    ]
}

impl Default for VectorGuardConfig {
    fn default() -> Self {
        Self {
            vendor_markers: default_vendor_markers(),
            collection_allowlist: Vec::new(),
            namespace_allowlist: None,
            denied_operations: Vec::new(),
            mutating_operations: default_mutating_operations(),
            field_paths: VectorFieldPaths::default(),
            allow_all: false,
        }
    }
}

impl VectorGuardConfig {
    /// Returns true when the operator has not configured any allowlist.
    pub fn is_empty(&self) -> bool {
        self.collection_allowlist.is_empty()
            && self
                .namespace_allowlist
                .as_ref()
                .map(|v| v.is_empty())
                .unwrap_or(true)
            && self.denied_operations.is_empty()
    }

    /// Case-insensitive collection match.
    pub fn collection_allowed(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.collection_allowlist
            .iter()
            .any(|c| c.to_ascii_lowercase() == lower)
    }

    /// Case-insensitive namespace match.  Returns `true` when namespace
    /// enforcement is disabled.
    pub fn namespace_allowed(&self, name: &str) -> bool {
        match &self.namespace_allowlist {
            None => true,
            Some(list) => {
                let lower = name.to_ascii_lowercase();
                list.iter().any(|c| c.to_ascii_lowercase() == lower)
            }
        }
    }

    /// Returns true when the tool name or database identifier matches any
    /// configured vendor substring (case-insensitive).
    pub fn looks_like_vector(&self, database: &str, tool: &str) -> bool {
        let db = database.to_ascii_lowercase();
        let tl = tool.to_ascii_lowercase();
        self.vendor_markers.iter().any(|m| {
            !m.is_empty()
                && (db.contains(&m.to_ascii_lowercase()) || tl.contains(&m.to_ascii_lowercase()))
        })
    }
}

/// The parsed view of a vector-database tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorCall {
    /// Normalised collection name (lowercased).
    pub collection: String,
    /// Optional namespace string from the arguments.
    pub namespace: Option<String>,
    /// Optional operation verb from the arguments.
    pub operation: Option<String>,
    /// Optional `top_k` ceiling from the arguments.
    pub top_k: Option<u64>,
}

/// Vector database guard.
pub struct VectorDbGuard {
    config: VectorGuardConfig,
}

impl VectorDbGuard {
    /// Construct a new guard with the given configuration.
    pub fn new(config: VectorGuardConfig) -> Self {
        if config.allow_all {
            warn!(
                target: "chio.data-guards.vector",
                "vector-db-guard constructed with allow_all=true; fail-closed default disabled"
            );
        }
        Self { config }
    }

    /// Read-only access to the configuration.
    pub fn config(&self) -> &VectorGuardConfig {
        &self.config
    }

    /// Evaluate an already-extracted [`VectorCall`] against the configured
    /// policy and the active capability scope.
    ///
    /// Returns `Ok(())` to allow; `Err(VectorGuardDenyReason)` to deny.
    pub fn check(&self, call: &VectorCall, scope: &ChioScope) -> Result<(), VectorGuardDenyReason> {
        self.check_with_matched_grant(call, scope, None)
    }

    fn check_with_matched_grant(
        &self,
        call: &VectorCall,
        scope: &ChioScope,
        matched_grant_index: Option<usize>,
    ) -> Result<(), VectorGuardDenyReason> {
        if self.config.allow_all {
            return Ok(());
        }

        if self.config.is_empty() {
            return Err(VectorGuardDenyReason::NoConfig);
        }

        // Collection allowlist.
        if !self.config.collection_allowlist.is_empty()
            && !self.config.collection_allowed(&call.collection)
        {
            return Err(VectorGuardDenyReason::CollectionNotAllowed {
                collection: call.collection.clone(),
            });
        }

        // Namespace allowlist.
        if let Some(ns) = &call.namespace {
            if !self.config.namespace_allowed(ns) {
                return Err(VectorGuardDenyReason::NamespaceNotAllowed {
                    namespace: ns.clone(),
                });
            }
        } else if self
            .config
            .namespace_allowlist
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            // Namespaces are being enforced but the call did not provide
            // one: fail-closed.
            return Err(VectorGuardDenyReason::NamespaceNotAllowed {
                namespace: String::new(),
            });
        }

        // Operation verb handling.
        if let Some(op) = &call.operation {
            let op_lower = op.to_ascii_lowercase();

            // Hard denylist always wins.
            if self
                .config
                .denied_operations
                .iter()
                .any(|d| d.to_ascii_lowercase() == op_lower)
            {
                return Err(VectorGuardDenyReason::OperationNotAllowed {
                    operation: op.clone(),
                });
            }

            // Inspect the active grant's operation class.
            let class = operation_class_for_request(scope, matched_grant_index);
            if let Some(class) = class {
                let is_mutation = self
                    .config
                    .mutating_operations
                    .iter()
                    .any(|m| m.to_ascii_lowercase() == op_lower);

                match (class, is_mutation) {
                    (SqlOperationClass::ReadOnly, true) => {
                        return Err(VectorGuardDenyReason::OperationNotAllowed {
                            operation: op.clone(),
                        })
                    }
                    (SqlOperationClass::ReadWrite, _) if op_lower == "drop_index" => {
                        // DDL-ish verbs even under read-write need Admin.
                        return Err(VectorGuardDenyReason::OperationNotAllowed {
                            operation: op.clone(),
                        });
                    }
                    _ => {}
                }
            }
        } else if let Some(class) = operation_class_for_request(scope, matched_grant_index) {
            // No explicit operation verb was provided, but the active grant
            // narrows to a specific OperationClass. Fail closed: a ReadOnly
            // scope must not allow a call that could be a write, and any
            // OperationClass stricter than Admin requires knowing the verb
            // to make an allow decision. This closes the vector-write bypass
            // where a MemoryWrite-shaped call omits `operation` and would
            // otherwise skip the mutation gate entirely.
            if matches!(
                class,
                SqlOperationClass::ReadOnly | SqlOperationClass::ReadWrite
            ) {
                return Err(VectorGuardDenyReason::OperationNotAllowed {
                    operation: String::new(),
                });
            }
        }

        // top_k ceiling.
        if let Some(max) = max_rows_for_request(scope, matched_grant_index) {
            match call.top_k {
                Some(k) if k > max => {
                    return Err(VectorGuardDenyReason::TopKExceedsLimit { requested: k, max });
                }
                None => {
                    // A ceiling is set but the call did not declare top_k.
                    // Fail-closed.
                    return Err(VectorGuardDenyReason::TopKExceedsLimit {
                        requested: u64::MAX,
                        max,
                    });
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Extract a [`VectorCall`] from the tool arguments value.
    pub fn extract_call(&self, arguments: &Value) -> Result<VectorCall, VectorGuardDenyReason> {
        if !arguments.is_object() && !arguments.is_null() {
            return Err(VectorGuardDenyReason::ParseError {
                error: "arguments must be a JSON object".into(),
            });
        }
        let collection = pick_string(arguments, &self.config.field_paths.collection)
            .map(|s| s.to_ascii_lowercase())
            .ok_or(VectorGuardDenyReason::ParseError {
                error: "missing collection/index field".into(),
            })?;
        let namespace = pick_string(arguments, &self.config.field_paths.namespace);
        let operation = pick_string(arguments, &self.config.field_paths.operation);
        let top_k = pick_number(arguments, &self.config.field_paths.top_k);

        Ok(VectorCall {
            collection,
            namespace,
            operation,
            top_k,
        })
    }
}

impl chio_kernel::Guard for VectorDbGuard {
    fn name(&self) -> &str {
        "vector-db"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let tool = &ctx.request.tool_name;
        let args = &ctx.request.arguments;
        let action = match extract_action_checked(tool, args) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let database = match &action {
            ToolAction::DatabaseQuery { database, .. } => database.clone(),
            ToolAction::MemoryRead { store, .. } | ToolAction::MemoryWrite { store, .. } => {
                store.clone()
            }
            // Fall back to inspecting the tool name directly: not every
            // bespoke vector SDK tool is wired up in `extract_action`.
            _ => tool.clone(),
        };

        // Non-vector traffic always short-circuits to Allow regardless of
        // `allow_all`. This is by design: a domain-scoped guard returns
        // Allow for traffic outside its concern, and the deny-by-default
        // contract is enforced by the composing authority layer, not here.
        // `allow_all` only governs whether vector policy is enforced on
        // vector-shaped requests; it must not force non-vector calls
        // through `extract_call`, which would deny any call lacking
        // vector-specific fields.
        if !self.config.looks_like_vector(&database, tool) {
            return Ok(GuardDecision::allow());
        }
        let call = match self.extract_call(args) {
            Ok(c) => c,
            Err(reason) => {
                warn!(
                    target: "chio.data-guards.vector",
                    code = reason.code(),
                    reason = %reason,
                    database = %database,
                    "vector-db-guard denied: parse failed"
                );
                return Ok(GuardDecision::deny(Vec::new()));
            }
        };

        if self.config.allow_all {
            // Dry-run/debug mode still validates vector call shape so
            // malformed payloads fail closed, but skips allowlist and
            // scope enforcement once parsing succeeds.
            return Ok(GuardDecision::allow());
        }

        match self.check_with_matched_grant(&call, ctx.scope, ctx.matched_grant_index) {
            Ok(()) => Ok(GuardDecision::allow()),
            Err(reason) => {
                warn!(
                    target: "chio.data-guards.vector",
                    code = reason.code(),
                    reason = %reason,
                    database = %database,
                    collection = %call.collection,
                    "vector-db-guard denied"
                );
                Ok(GuardDecision::deny(Vec::new()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn active_grant(scope: &ChioScope, matched_grant_index: Option<usize>) -> Option<&ToolGrant> {
    matched_grant_index.and_then(|index| scope.grants.get(index))
}

fn operation_class_for_constraints(constraints: &[Constraint]) -> Option<SqlOperationClass> {
    let mut strongest: Option<SqlOperationClass> = None;
    for c in constraints {
        if let Constraint::OperationClass(class) = c {
            strongest = Some(match (strongest, *class) {
                (None, new) => new,
                (Some(SqlOperationClass::ReadOnly), _) => SqlOperationClass::ReadOnly,
                (_, SqlOperationClass::ReadOnly) => SqlOperationClass::ReadOnly,
                (Some(SqlOperationClass::ReadWrite), _) => SqlOperationClass::ReadWrite,
                (_, SqlOperationClass::ReadWrite) => SqlOperationClass::ReadWrite,
                (Some(SqlOperationClass::Admin), SqlOperationClass::Admin) => {
                    SqlOperationClass::Admin
                }
            });
        }
    }
    strongest
}

/// Return the strictest [`SqlOperationClass`] for the matched grant when
/// available, or across the full scope as a conservative fallback for
/// direct callers that do not supply grant attribution.
fn operation_class_for_request(
    scope: &ChioScope,
    matched_grant_index: Option<usize>,
) -> Option<SqlOperationClass> {
    if let Some(grant) = active_grant(scope, matched_grant_index) {
        return operation_class_for_constraints(&grant.constraints);
    }

    let mut strongest: Option<SqlOperationClass> = None;
    for grant in &scope.grants {
        strongest = match (
            strongest,
            operation_class_for_constraints(&grant.constraints),
        ) {
            (Some(SqlOperationClass::ReadOnly), _) => Some(SqlOperationClass::ReadOnly),
            (_, Some(SqlOperationClass::ReadOnly)) => Some(SqlOperationClass::ReadOnly),
            (Some(SqlOperationClass::ReadWrite), _) => Some(SqlOperationClass::ReadWrite),
            (_, Some(SqlOperationClass::ReadWrite)) => Some(SqlOperationClass::ReadWrite),
            (None, Some(class)) => Some(class),
            (current, None) => current,
            (Some(SqlOperationClass::Admin), Some(SqlOperationClass::Admin)) => {
                Some(SqlOperationClass::Admin)
            }
        };
    }
    strongest
}

fn max_rows_for_constraints(constraints: &[Constraint]) -> Option<u64> {
    let mut min: Option<u64> = None;
    for c in constraints {
        if let Constraint::MaxRowsReturned(n) = c {
            min = Some(min.map_or(*n, |m| m.min(*n)));
        }
    }
    min
}

/// Return the lowest `MaxRowsReturned` from the matched grant when
/// available, or across the full scope as a conservative fallback for
/// direct callers that do not supply grant attribution.
fn max_rows_for_request(scope: &ChioScope, matched_grant_index: Option<usize>) -> Option<u64> {
    if let Some(grant) = active_grant(scope, matched_grant_index) {
        return max_rows_for_constraints(&grant.constraints);
    }

    let mut min: Option<u64> = None;
    for grant in &scope.grants {
        if let Some(grant_min) = max_rows_for_constraints(&grant.constraints) {
            min = Some(min.map_or(grant_min, |current| current.min(grant_min)));
        }
    }
    min
}

/// Walk `keys` over `value` and return the first string we find.
fn pick_string(value: &Value, keys: &[String]) -> Option<String> {
    for key in keys {
        if let Some(s) = lookup_path(value, key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Walk `keys` over `value` and return the first unsigned integer.
fn pick_number(value: &Value, keys: &[String]) -> Option<u64> {
    for key in keys {
        if let Some(n) = lookup_path(value, key).and_then(|v| v.as_u64()) {
            return Some(n);
        }
        // Accept stringified numbers too for SDKs that over-quote.
        if let Some(s) = lookup_path(value, key).and_then(|v| v.as_str()) {
            if let Ok(n) = s.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return None;
    }

    if let Some(exact) = value.get(path) {
        return Some(exact);
    }

    let mut cursor = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

/// Convenience: turn a hash-set style vec into a normalised lower-case set
/// for callers that need to build their own filters.
#[doc(hidden)]
pub fn lowercase_set<I, S>(items: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    items
        .into_iter()
        .map(|s| s.as_ref().to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::{
        scope::{Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

    fn grant_with_constraints(constraints: Vec<Constraint>) -> ToolGrant {
        ToolGrant {
            server_id: "srv".into(),
            tool_name: "*".into(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn scope_with(constraints: Vec<Constraint>) -> ChioScope {
        ChioScope {
            grants: vec![grant_with_constraints(constraints)],
            resource_grants: vec![],
            prompt_grants: vec![],
        }
    }

    fn test_capability() -> CapabilityToken {
        let kp = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-vector-guard".into(),
                issuer: kp.public_key(),
                subject: kp.public_key(),
                scope: ChioScope::default(),
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &kp,
        )
        .unwrap()
    }

    fn base_cfg() -> VectorGuardConfig {
        VectorGuardConfig {
            collection_allowlist: vec!["docs".into()],
            ..Default::default()
        }
    }

    #[test]
    fn deny_collection_not_in_allowlist() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "secrets".into(),
            namespace: None,
            operation: Some("query".into()),
            top_k: Some(10),
        };
        let err = g.check(&call, &ChioScope::default()).unwrap_err();
        assert!(matches!(
            err,
            VectorGuardDenyReason::CollectionNotAllowed { .. }
        ));
    }

    #[test]
    fn allow_collection_in_allowlist() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: Some("query".into()),
            top_k: Some(5),
        };
        g.check(&call, &ChioScope::default()).unwrap();
    }

    #[test]
    fn deny_cross_namespace() {
        let cfg = VectorGuardConfig {
            collection_allowlist: vec!["docs".into()],
            namespace_allowlist: Some(vec!["tenant-a".into()]),
            ..Default::default()
        };
        let g = VectorDbGuard::new(cfg);
        let call = VectorCall {
            collection: "docs".into(),
            namespace: Some("tenant-b".into()),
            operation: None,
            top_k: None,
        };
        let err = g.check(&call, &ChioScope::default()).unwrap_err();
        assert!(matches!(
            err,
            VectorGuardDenyReason::NamespaceNotAllowed { .. }
        ));
    }

    #[test]
    fn deny_upsert_under_readonly() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: Some("upsert".into()),
            top_k: None,
        };
        let scope = scope_with(vec![Constraint::OperationClass(
            SqlOperationClass::ReadOnly,
        )]);
        let err = g.check(&call, &scope).unwrap_err();
        assert!(matches!(
            err,
            VectorGuardDenyReason::OperationNotAllowed { .. }
        ));
    }

    #[test]
    fn allow_query_under_readonly() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: Some("query".into()),
            top_k: Some(1),
        };
        let scope = scope_with(vec![
            Constraint::OperationClass(SqlOperationClass::ReadOnly),
            Constraint::MaxRowsReturned(50),
        ]);
        g.check(&call, &scope).unwrap();
    }

    #[test]
    fn deny_top_k_over_max_rows() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: Some("query".into()),
            top_k: Some(500),
        };
        let scope = scope_with(vec![Constraint::MaxRowsReturned(50)]);
        let err = g.check(&call, &scope).unwrap_err();
        match err {
            VectorGuardDenyReason::TopKExceedsLimit { requested, max } => {
                assert_eq!(requested, 500);
                assert_eq!(max, 50);
            }
            other => panic!("unexpected reason: {other:?}"),
        }
    }

    #[test]
    fn deny_missing_top_k_when_ceiling_set() {
        let g = VectorDbGuard::new(base_cfg());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: Some("query".into()),
            top_k: None,
        };
        let scope = scope_with(vec![Constraint::MaxRowsReturned(50)]);
        let err = g.check(&call, &scope).unwrap_err();
        assert!(matches!(
            err,
            VectorGuardDenyReason::TopKExceedsLimit { .. }
        ));
    }

    #[test]
    fn empty_config_denies() {
        let g = VectorDbGuard::new(VectorGuardConfig::default());
        let call = VectorCall {
            collection: "docs".into(),
            namespace: None,
            operation: None,
            top_k: None,
        };
        let err = g.check(&call, &ChioScope::default()).unwrap_err();
        assert!(matches!(err, VectorGuardDenyReason::NoConfig));
    }

    #[test]
    fn allow_all_skips_allowlists() {
        let g = VectorDbGuard::new(VectorGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let call = VectorCall {
            collection: "anything".into(),
            namespace: Some("anywhere".into()),
            operation: Some("upsert".into()),
            top_k: Some(10_000),
        };
        g.check(&call, &ChioScope::default()).unwrap();
    }

    #[test]
    fn allow_all_still_denies_parse_errors() {
        let guard = VectorDbGuard::new(VectorGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let request = ToolCallRequest {
            request_id: "req-vector-allow-all-parse".to_string(),
            capability: test_capability(),
            tool_name: "pinecone_query".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            arguments: serde_json::json!({"namespace": "tenant-a"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let scope = ChioScope::default();
        let agent_id = String::from("agent");
        let server_id = String::from("srv");
        let verdict = guard
            .evaluate(&GuardContext {
                request: &request,
                scope: &scope,
                agent_id: &agent_id,
                server_id: &server_id,
                session_filesystem_roots: None,
                matched_grant_index: None,
            })
            .unwrap();
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn evaluate_denies_malformed_vector_action_arguments() {
        let guard = VectorDbGuard::new(VectorGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let request = ToolCallRequest {
            request_id: "req-vector-malformed-action".to_string(),
            capability: test_capability(),
            tool_name: "vector_query".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            arguments: serde_json::json!({"collection": ["docs"], "top_k": 5}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let scope = ChioScope::default();
        let agent_id = String::from("agent");
        let server_id = String::from("srv");
        let verdict = guard
            .evaluate(&GuardContext {
                request: &request,
                scope: &scope,
                agent_id: &agent_id,
                server_id: &server_id,
                session_filesystem_roots: None,
                matched_grant_index: None,
            })
            .unwrap();
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn extract_call_parses_defaults() {
        let g = VectorDbGuard::new(base_cfg());
        let args = serde_json::json!({
            "collection": "docs",
            "namespace": "tenant-a",
            "operation": "query",
            "top_k": 42
        });
        let call = g.extract_call(&args).unwrap();
        assert_eq!(call.collection, "docs");
        assert_eq!(call.namespace.as_deref(), Some("tenant-a"));
        assert_eq!(call.operation.as_deref(), Some("query"));
        assert_eq!(call.top_k, Some(42));
    }

    #[test]
    fn extract_call_parses_nested_custom_field_paths() {
        let g = VectorDbGuard::new(VectorGuardConfig {
            collection_allowlist: vec!["docs".into()],
            field_paths: VectorFieldPaths {
                collection: vec!["request.index".into()],
                namespace: vec!["request.routing.tenant".into()],
                operation: vec!["request.operation".into()],
                top_k: vec!["request.options.limit".into()],
            },
            ..Default::default()
        });
        let args = serde_json::json!({
            "request": {
                "index": "Docs",
                "routing": {"tenant": "tenant-a"},
                "operation": "query",
                "options": {"limit": "42"}
            }
        });
        let call = g.extract_call(&args).unwrap();
        assert_eq!(call.collection, "docs");
        assert_eq!(call.namespace.as_deref(), Some("tenant-a"));
        assert_eq!(call.operation.as_deref(), Some("query"));
        assert_eq!(call.top_k, Some(42));
    }

    #[test]
    fn extract_call_missing_collection_errors() {
        let g = VectorDbGuard::new(base_cfg());
        let args = serde_json::json!({"namespace": "tenant-a"});
        let err = g.extract_call(&args).unwrap_err();
        assert!(matches!(err, VectorGuardDenyReason::ParseError { .. }));
    }

    #[test]
    fn lookup_path_prefers_exact_top_level_key() {
        let args = serde_json::json!({
            "request.index": "flat",
            "request": {"index": "nested"}
        });
        assert_eq!(
            lookup_path(&args, "request.index"),
            Some(&serde_json::json!("flat"))
        );
        assert!(lookup_path(&args, "request..index").is_none());
    }

    #[test]
    fn looks_like_vector_matches_vendor_substring() {
        let cfg = VectorGuardConfig::default();
        assert!(cfg.looks_like_vector("pinecone-prod", "query"));
        assert!(cfg.looks_like_vector("main", "weaviate_search"));
        assert!(cfg.looks_like_vector("vector-store", "query"));
        assert!(!cfg.looks_like_vector("postgres", "sql"));
    }

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(VectorGuardDenyReason::NoConfig.code(), "no_config");
        assert_eq!(
            VectorGuardDenyReason::CollectionNotAllowed {
                collection: "x".into(),
            }
            .code(),
            "collection_not_allowed"
        );
        assert_eq!(
            VectorGuardDenyReason::TopKExceedsLimit {
                requested: 1,
                max: 0,
            }
            .code(),
            "top_k_exceeds_limit"
        );
    }

    #[test]
    fn lowercase_set_normalises() {
        let s = lowercase_set(["Foo", "BAR"]);
        assert!(s.contains("foo"));
        assert!(s.contains("bar"));
    }
}
