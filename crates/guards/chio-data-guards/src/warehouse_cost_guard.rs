//! Warehouse cost guard.
//!
//! `WarehouseCostGuard` enforces *pre-execution* cost limits on queries
//! sent to large-scale analytical warehouses (BigQuery, Snowflake,
//! Redshift, Athena, and friends).  The guard does not itself contact a
//! warehouse to estimate cost: instead it reads a dry-run estimate that
//! the tool server (or an upstream dry-run gate) has already attached to
//! the tool call arguments.  Typical paths:
//!
//! ```jsonc
//! // BigQuery / Snowflake-style dry-run metadata carried on the call:
//! {
//!   "query": "SELECT ...",
//!   "dry_run": {
//!     "bytes_scanned": 53687091200,  // 50 GiB
//!     "estimated_cost_usd": "0.25"
//!   }
//! }
//! ```
//!
//! The guard enforces two operator-configured ceilings:
//!
//! - [`WarehouseCostGuardConfig::max_bytes_scanned`] -- a hard upper bound
//!   on the warehouse's reported scan volume.
//! - [`WarehouseCostGuardConfig::max_cost_per_query_usd`] -- a hard upper
//!   bound on the dry-run's estimated monetary cost.
//!
//! Both limits sit on the guard config rather than on the capability
//! scope. Kernel integrations populate the guard config from
//! `Constraint::Custom("max_bytes_scanned", ...)` /
//! `Constraint::Custom("max_cost_per_query_usd", ...)`.
//!
//! The guard emits a [`CostDimension::WarehouseQuery`] on every *allowed*
//! query via [`WarehouseCostGuard::record_cost`] so callers can attach
//! the dimension to the outgoing receipt.  Emission is not automatic
//! inside the kernel's `Guard::evaluate` path -- the kernel does not
//! thread mutable receipts through guards -- but the helper keeps the
//! mapping in one place.
//!
//! # Fail-closed rules
//!
//! - Parse errors in the dry-run metadata deny.
//! - Missing dry-run metadata with a configured ceiling denies.
//! - Non-decimal strings in `estimated_cost_usd` deny.
//! - Negative byte or cost values deny (decoded as invalid via a safe
//!   parser that rejects the minus sign).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::warn;

use chio_guards::{extract_action_checked, ToolAction};
use chio_kernel::{GuardContext, GuardDecision, KernelError};
use chio_metering::CostDimension;

// ---------------------------------------------------------------------------
// Reason codes
// ---------------------------------------------------------------------------

/// Structured reason for a [`WarehouseCostGuard`] denial.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WarehouseCostDenyReason {
    /// The tool call did not carry the expected dry-run metadata.
    #[error("missing dry-run metadata at `{path}`")]
    MissingEstimate {
        /// The configured argument path.
        path: String,
    },

    /// The dry-run metadata contained a field of the wrong shape or an
    /// unparseable decimal string.
    #[error("dry-run metadata parse error: {error}")]
    ParseError {
        /// Human-readable cause.
        error: String,
    },

    /// Reported scan volume exceeds the configured limit.
    #[error("bytes_scanned {bytes_scanned} exceeds limit {limit}")]
    BytesExceedsLimit {
        /// Reported bytes-scanned value.
        bytes_scanned: u64,
        /// Configured limit.
        limit: u64,
    },

    /// Estimated cost exceeds the configured limit.
    #[error("estimated_cost_usd {estimated_cost_usd} exceeds limit {limit_usd}")]
    CostExceedsLimit {
        /// Reported decimal string.
        estimated_cost_usd: String,
        /// Configured limit as a decimal string.
        limit_usd: String,
    },

    /// The guard has neither a byte limit nor a cost limit and
    /// `allow_all` is false.  Fail-closed default.
    #[error("warehouse guard has no configured limits and allow_all is false")]
    NoConfig,
}

impl WarehouseCostDenyReason {
    /// Short stable tag suitable for metrics labels.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingEstimate { .. } => "missing_estimate",
            Self::ParseError { .. } => "parse_error",
            Self::BytesExceedsLimit { .. } => "bytes_exceeds_limit",
            Self::CostExceedsLimit { .. } => "cost_exceeds_limit",
            Self::NoConfig => "no_config",
        }
    }
}

// ---------------------------------------------------------------------------
// Argument paths
// ---------------------------------------------------------------------------

/// JSON argument paths configurable per deployment.
///
/// Each path is a dot-separated sequence of object keys; arrays are not
/// traversed.  Example: `"dry_run.bytes_scanned"`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarehouseCostFieldPaths {
    /// Path to the bytes-scanned value.
    pub bytes_scanned: String,
    /// Path to the estimated-cost decimal string.
    pub estimated_cost_usd: String,
}

impl Default for WarehouseCostFieldPaths {
    fn default() -> Self {
        Self {
            bytes_scanned: "dry_run.bytes_scanned".to_string(),
            estimated_cost_usd: "dry_run.estimated_cost_usd".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Operator configuration for [`WarehouseCostGuard`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarehouseCostGuardConfig {
    /// Maximum bytes the warehouse may scan to satisfy a single query.
    /// `None` disables byte-based enforcement.
    #[serde(default)]
    pub max_bytes_scanned: Option<u64>,

    /// Maximum estimated cost per query in USD, as a decimal string.
    /// `None` disables cost-based enforcement.
    #[serde(default)]
    pub max_cost_per_query_usd: Option<String>,

    /// Substrings that identify a request as targeting an analytical
    /// warehouse (case-insensitive).  Matched against the database
    /// identifier *and* the tool name.
    #[serde(default = "default_warehouse_markers")]
    pub warehouse_markers: Vec<String>,

    /// JSON paths for extracting dry-run metadata.
    #[serde(default)]
    pub field_paths: WarehouseCostFieldPaths,

    /// Bypass: allow every warehouse call that parses successfully.
    /// Parse errors still deny.
    #[serde(default)]
    pub allow_all: bool,
}

impl Default for WarehouseCostGuardConfig {
    fn default() -> Self {
        Self {
            max_bytes_scanned: None,
            max_cost_per_query_usd: None,
            warehouse_markers: default_warehouse_markers(),
            field_paths: WarehouseCostFieldPaths::default(),
            allow_all: false,
        }
    }
}

fn default_warehouse_markers() -> Vec<String> {
    vec![
        "bigquery".into(),
        "snowflake".into(),
        "redshift".into(),
        "athena".into(),
        "databricks".into(),
        "presto".into(),
        "trino".into(),
    ]
}

impl WarehouseCostGuardConfig {
    /// Returns true when no ceiling is configured.
    pub fn is_empty(&self) -> bool {
        self.max_bytes_scanned.is_none() && self.max_cost_per_query_usd.is_none()
    }

    /// Case-insensitive match against the configured warehouse markers.
    pub fn looks_like_warehouse(&self, database: &str, tool: &str) -> bool {
        let db = database.to_ascii_lowercase();
        let tl = tool.to_ascii_lowercase();
        self.warehouse_markers.iter().any(|m| {
            !m.is_empty()
                && (db.contains(&m.to_ascii_lowercase()) || tl.contains(&m.to_ascii_lowercase()))
        })
    }
}

// ---------------------------------------------------------------------------
// Dry-run estimate
// ---------------------------------------------------------------------------

/// Parsed dry-run estimate extracted from a tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRunEstimate {
    /// Reported scan size in bytes.
    pub bytes_scanned: u64,
    /// Reported estimated cost in USD, as a decimal string verbatim.
    pub estimated_cost_usd: String,
}

impl DryRunEstimate {
    /// Convert this estimate into a [`CostDimension::WarehouseQuery`] for
    /// downstream receipt emission.
    pub fn to_cost_dimension(&self) -> CostDimension {
        CostDimension::WarehouseQuery {
            bytes_scanned: self.bytes_scanned,
            estimated_cost_usd: self.estimated_cost_usd.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

/// Warehouse cost guard.
pub struct WarehouseCostGuard {
    config: WarehouseCostGuardConfig,
}

impl WarehouseCostGuard {
    /// Construct a new guard with the given configuration.
    pub fn new(config: WarehouseCostGuardConfig) -> Self {
        if config.allow_all {
            warn!(
                target: "chio.data-guards.warehouse",
                "warehouse-cost-guard constructed with allow_all=true; fail-closed default disabled"
            );
        }
        Self { config }
    }

    /// Read-only access to the configuration.
    pub fn config(&self) -> &WarehouseCostGuardConfig {
        &self.config
    }

    /// Extract a [`DryRunEstimate`] from the tool call arguments.
    pub fn extract_estimate(
        &self,
        arguments: &Value,
    ) -> Result<DryRunEstimate, WarehouseCostDenyReason> {
        let bytes_path = self.config.field_paths.bytes_scanned.clone();
        let cost_path = self.config.field_paths.estimated_cost_usd.clone();

        let bytes_raw = lookup_path(arguments, &bytes_path).ok_or(
            WarehouseCostDenyReason::MissingEstimate {
                path: bytes_path.clone(),
            },
        )?;
        let cost_raw =
            lookup_path(arguments, &cost_path).ok_or(WarehouseCostDenyReason::MissingEstimate {
                path: cost_path.clone(),
            })?;

        let bytes_scanned =
            coerce_u64(bytes_raw).ok_or_else(|| WarehouseCostDenyReason::ParseError {
                error: format!("{bytes_path} is not a non-negative integer"),
            })?;

        let estimated_cost_usd =
            coerce_decimal_string(cost_raw).ok_or_else(|| WarehouseCostDenyReason::ParseError {
                error: format!("{cost_path} is not a non-negative decimal string"),
            })?;

        Ok(DryRunEstimate {
            bytes_scanned,
            estimated_cost_usd,
        })
    }

    /// Evaluate an estimate against the configured policy.  Returns
    /// `Ok(())` to allow, `Err(...)` to deny.
    pub fn check(&self, estimate: &DryRunEstimate) -> Result<(), WarehouseCostDenyReason> {
        if self.config.allow_all {
            return Ok(());
        }

        if self.config.is_empty() {
            return Err(WarehouseCostDenyReason::NoConfig);
        }

        if let Some(limit) = self.config.max_bytes_scanned {
            if estimate.bytes_scanned > limit {
                return Err(WarehouseCostDenyReason::BytesExceedsLimit {
                    bytes_scanned: estimate.bytes_scanned,
                    limit,
                });
            }
        }

        if let Some(limit) = self.config.max_cost_per_query_usd.as_ref() {
            if decimal_string_gt(&estimate.estimated_cost_usd, limit) {
                return Err(WarehouseCostDenyReason::CostExceedsLimit {
                    estimated_cost_usd: estimate.estimated_cost_usd.clone(),
                    limit_usd: limit.clone(),
                });
            }
        }

        Ok(())
    }

    /// Produce the receipt cost dimension for an estimate.
    ///
    /// Callers that wire the guard into the kernel can collect the
    /// dimension via this helper on the allow path and attach it to the
    /// outgoing receipt.  The dimension is emitted regardless of whether
    /// the guard has any ceiling configured, so observability is uniform.
    pub fn record_cost(estimate: &DryRunEstimate) -> CostDimension {
        estimate.to_cost_dimension()
    }
}

impl chio_kernel::Guard for WarehouseCostGuard {
    fn name(&self) -> &str {
        "warehouse-cost"
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
            _ => tool.clone(),
        };

        // Non-warehouse traffic always short-circuits to Allow regardless of
        // `allow_all`; `allow_all` only disables enforcement on the warehouse
        // path.
        if !self.config.looks_like_warehouse(&database, tool) {
            return Ok(GuardDecision::allow());
        }
        let estimate = match self.extract_estimate(args) {
            Ok(e) => e,
            Err(reason) => {
                warn!(
                    target: "chio.data-guards.warehouse",
                    code = reason.code(),
                    reason = %reason,
                    database = %database,
                    "warehouse-cost-guard denied: missing or invalid estimate"
                );
                return Ok(GuardDecision::deny(Vec::new()));
            }
        };

        if self.config.allow_all {
            // Dry-run/debug mode still validates the dry-run payload so
            // malformed estimates fail closed, but skips limit checks
            // once parsing succeeds.
            return Ok(GuardDecision::allow());
        }

        match self.check(&estimate) {
            Ok(()) => Ok(GuardDecision::allow()),
            Err(reason) => {
                warn!(
                    target: "chio.data-guards.warehouse",
                    code = reason.code(),
                    reason = %reason,
                    database = %database,
                    "warehouse-cost-guard denied"
                );
                Ok(GuardDecision::deny(Vec::new()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON path / numeric helpers
// ---------------------------------------------------------------------------

fn lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        // Reject explicit negatives, scientific notation, or decimals --
        // dry-run bytes are always integer.
        if s.starts_with('-') || s.contains('.') || s.contains('e') || s.contains('E') {
            return None;
        }
        return s.parse::<u64>().ok();
    }
    None
}

/// Accept decimal strings and JSON numbers.  The return value is the
/// verbatim string representation (for receipt preservation) after a
/// canonical parse that rejects malformed input.
fn coerce_decimal_string(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return valid_non_negative_decimal(s).then(|| s.to_string());
    }
    // Check integer before floating: serde_json surfaces `100` as both
    // as_u64 and as_f64, and we want the narrower integer form so the
    // receipt shows exactly what the caller sent.
    if let Some(n) = v.as_u64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_i64() {
        if n < 0 {
            return None;
        }
        return Some(n.to_string());
    }
    if let Some(n) = v.as_f64() {
        if n.is_sign_negative() || !n.is_finite() {
            return None;
        }
        return Some(format_decimal_full_precision(n));
    }
    None
}

fn valid_non_negative_decimal(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') || s.starts_with('+') {
        return false;
    }
    // At most one dot; digits only otherwise.
    let mut seen_dot = false;
    for c in s.chars() {
        if c == '.' {
            if seen_dot {
                return false;
            }
            seen_dot = true;
        } else if !c.is_ascii_digit() {
            return false;
        }
    }
    // Must contain at least one digit.
    s.chars().any(|c| c.is_ascii_digit())
}

/// Render a non-negative `f64` as a decimal string without rounding
/// away sub-cent precision. `format!("{n:.2}")` would coerce
/// `0.0049` to `"0.00"` before policy comparison, understating tight
/// limits on small queries. We instead use Rust's default `Display`
/// for `f64` which emits the shortest round-trippable representation
/// (so `0.0049` stays `0.0049`), then normalize integer-ish values
/// (`100.0`) to `"100"` so `valid_non_negative_decimal` accepts them
/// and comparisons against operator-supplied limits do not depend on
/// trailing `.0`.
fn format_decimal_full_precision(n: f64) -> String {
    // Rust's `Display` for f64 already emits the shortest
    // round-trippable decimal. Trim a trailing ".0" when the value is
    // an integer so limit strings like "100" still compare equal.
    let s = format!("{n}");
    if let Some(stripped) = s.strip_suffix(".0") {
        return stripped.to_string();
    }
    s
}

/// Compare two non-negative decimal strings without allocating a big-
/// decimal dependency.  Returns `true` when `a > b`.
///
/// Both inputs must already be validated by [`valid_non_negative_decimal`]
/// (or generated by [`format_decimal_full_precision`]); on bad input we err on the side
/// of strictly greater so the guard denies.
fn decimal_string_gt(a: &str, b: &str) -> bool {
    if !valid_non_negative_decimal(a) || !valid_non_negative_decimal(b) {
        return true;
    }
    let (a_int, a_frac) = split_decimal(a);
    let (b_int, b_frac) = split_decimal(b);

    // Compare integer parts numerically, ignoring leading zeros.
    let a_int_trimmed = a_int.trim_start_matches('0');
    let b_int_trimmed = b_int.trim_start_matches('0');
    let a_digits = if a_int_trimmed.is_empty() {
        "0"
    } else {
        a_int_trimmed
    };
    let b_digits = if b_int_trimmed.is_empty() {
        "0"
    } else {
        b_int_trimmed
    };

    if a_digits.len() != b_digits.len() {
        return a_digits.len() > b_digits.len();
    }
    if a_digits != b_digits {
        return a_digits > b_digits;
    }

    // Integer parts equal: compare fractional parts lexicographically
    // after padding to equal length.
    let max_len = a_frac.len().max(b_frac.len());
    let a_padded = pad_right(a_frac, max_len);
    let b_padded = pad_right(b_frac, max_len);
    a_padded > b_padded
}

fn split_decimal(s: &str) -> (&str, &str) {
    match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    }
}

fn pad_right(s: &str, len: usize) -> String {
    let mut out = s.to_string();
    while out.len() < len {
        out.push('0');
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

    fn cfg_1gb_5usd() -> WarehouseCostGuardConfig {
        WarehouseCostGuardConfig {
            max_bytes_scanned: Some(1024 * 1024 * 1024),
            max_cost_per_query_usd: Some("5.00".into()),
            ..Default::default()
        }
    }

    fn test_capability() -> CapabilityToken {
        let kp = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-warehouse-guard".into(),
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

    #[test]
    fn decimal_comparison_basics() {
        assert!(decimal_string_gt("10.00", "5.00"));
        assert!(!decimal_string_gt("0.25", "5.00"));
        assert!(decimal_string_gt("1.10", "1.09"));
        assert!(!decimal_string_gt("1.10", "1.10"));
        assert!(!decimal_string_gt("001.10", "1.10"));
        assert!(decimal_string_gt("100", "99.99"));
        assert!(decimal_string_gt("5.001", "5"));
    }

    #[test]
    fn decimal_comparison_rejects_bad_input() {
        // Malformed inputs fail conservatively (treated as greater).
        assert!(decimal_string_gt("-1.00", "0.25"));
        assert!(decimal_string_gt("abc", "0.25"));
        assert!(decimal_string_gt("1.2.3", "0.25"));
    }

    #[test]
    fn lookup_path_basic() {
        let v = serde_json::json!({
            "dry_run": {"bytes_scanned": 1024, "estimated_cost_usd": "0.01"}
        });
        assert_eq!(
            lookup_path(&v, "dry_run.bytes_scanned"),
            Some(&serde_json::json!(1024))
        );
        assert_eq!(
            lookup_path(&v, "dry_run.estimated_cost_usd"),
            Some(&serde_json::json!("0.01"))
        );
        assert!(lookup_path(&v, "dry_run.missing").is_none());
        assert!(lookup_path(&v, "dry_run..bytes").is_none());
    }

    #[test]
    fn coerce_u64_handles_string_and_number() {
        assert_eq!(coerce_u64(&serde_json::json!(123)), Some(123));
        assert_eq!(coerce_u64(&serde_json::json!("123")), Some(123));
        assert!(coerce_u64(&serde_json::json!("-1")).is_none());
        assert!(coerce_u64(&serde_json::json!("1.0")).is_none());
        assert!(coerce_u64(&serde_json::json!("1e9")).is_none());
    }

    #[test]
    fn coerce_decimal_string_variants() {
        assert_eq!(
            coerce_decimal_string(&serde_json::json!("0.25")),
            Some("0.25".into())
        );
        assert_eq!(
            coerce_decimal_string(&serde_json::json!(100)),
            Some("100".into())
        );
        assert_eq!(
            coerce_decimal_string(&serde_json::json!(0.25)).as_deref(),
            Some("0.25")
        );
        assert!(coerce_decimal_string(&serde_json::json!("-1.00")).is_none());
        assert!(coerce_decimal_string(&serde_json::json!("abc")).is_none());
    }

    #[test]
    fn deny_bytes_over_limit() {
        let g = WarehouseCostGuard::new(cfg_1gb_5usd());
        // 50 GiB
        let estimate = DryRunEstimate {
            bytes_scanned: 50u64 * 1024 * 1024 * 1024,
            estimated_cost_usd: "0.25".into(),
        };
        let err = g.check(&estimate).unwrap_err();
        match err {
            WarehouseCostDenyReason::BytesExceedsLimit { .. } => {}
            other => panic!("expected BytesExceedsLimit, got {other:?}"),
        }
    }

    #[test]
    fn allow_small_query_under_both_limits() {
        let g = WarehouseCostGuard::new(cfg_1gb_5usd());
        let estimate = DryRunEstimate {
            bytes_scanned: 1024,
            estimated_cost_usd: "0.25".into(),
        };
        g.check(&estimate).unwrap();
    }

    #[test]
    fn deny_cost_over_limit() {
        let g = WarehouseCostGuard::new(WarehouseCostGuardConfig {
            max_cost_per_query_usd: Some("1.00".into()),
            ..Default::default()
        });
        let estimate = DryRunEstimate {
            bytes_scanned: 0,
            estimated_cost_usd: "5.00".into(),
        };
        let err = g.check(&estimate).unwrap_err();
        assert!(matches!(
            err,
            WarehouseCostDenyReason::CostExceedsLimit { .. }
        ));
    }

    #[test]
    fn empty_config_denies() {
        let g = WarehouseCostGuard::new(WarehouseCostGuardConfig::default());
        let estimate = DryRunEstimate {
            bytes_scanned: 0,
            estimated_cost_usd: "0.0".into(),
        };
        let err = g.check(&estimate).unwrap_err();
        assert!(matches!(err, WarehouseCostDenyReason::NoConfig));
    }

    #[test]
    fn allow_all_skips_limits() {
        let g = WarehouseCostGuard::new(WarehouseCostGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let estimate = DryRunEstimate {
            bytes_scanned: u64::MAX,
            estimated_cost_usd: "9999999.99".into(),
        };
        g.check(&estimate).unwrap();
    }

    #[test]
    fn allow_all_still_denies_parse_errors() {
        let guard = WarehouseCostGuard::new(WarehouseCostGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let request = ToolCallRequest {
            request_id: "req-warehouse-allow-all-parse".to_string(),
            capability: test_capability(),
            tool_name: "bigquery".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            arguments: serde_json::json!({"query": "SELECT 1"}),
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
    fn evaluate_denies_malformed_warehouse_action_arguments() {
        let guard = WarehouseCostGuard::new(WarehouseCostGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let request = ToolCallRequest {
            request_id: "req-warehouse-malformed-action".to_string(),
            capability: test_capability(),
            tool_name: "bigquery".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            arguments: serde_json::json!({
                "query": ["SELECT 1"],
                "dry_run": {
                    "bytes_scanned": 1024,
                    "estimated_cost_usd": "0.01"
                }
            }),
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
    fn extract_estimate_default_paths() {
        let g = WarehouseCostGuard::new(cfg_1gb_5usd());
        let args = serde_json::json!({
            "query": "SELECT 1",
            "dry_run": {
                "bytes_scanned": 1024,
                "estimated_cost_usd": "0.01"
            }
        });
        let e = g.extract_estimate(&args).unwrap();
        assert_eq!(e.bytes_scanned, 1024);
        assert_eq!(e.estimated_cost_usd, "0.01");
    }

    #[test]
    fn extract_estimate_custom_paths() {
        let g = WarehouseCostGuard::new(WarehouseCostGuardConfig {
            field_paths: WarehouseCostFieldPaths {
                bytes_scanned: "bq.stats.bytes".into(),
                estimated_cost_usd: "bq.stats.usd".into(),
            },
            max_bytes_scanned: Some(2048),
            ..Default::default()
        });
        let args = serde_json::json!({
            "bq": {"stats": {"bytes": 1024, "usd": "0.10"}}
        });
        let e = g.extract_estimate(&args).unwrap();
        assert_eq!(e.bytes_scanned, 1024);
        assert_eq!(e.estimated_cost_usd, "0.10");
    }

    #[test]
    fn extract_estimate_missing_path_errors() {
        let g = WarehouseCostGuard::new(cfg_1gb_5usd());
        let args = serde_json::json!({"query": "SELECT 1"});
        let err = g.extract_estimate(&args).unwrap_err();
        assert!(matches!(
            err,
            WarehouseCostDenyReason::MissingEstimate { .. }
        ));
    }

    #[test]
    fn record_cost_produces_warehouse_query_dimension() {
        let estimate = DryRunEstimate {
            bytes_scanned: 123,
            estimated_cost_usd: "0.05".into(),
        };
        match WarehouseCostGuard::record_cost(&estimate) {
            CostDimension::WarehouseQuery {
                bytes_scanned,
                estimated_cost_usd,
            } => {
                assert_eq!(bytes_scanned, 123);
                assert_eq!(estimated_cost_usd, "0.05");
            }
            other => panic!("unexpected cost dimension: {other:?}"),
        }
    }

    #[test]
    fn looks_like_warehouse_matches_vendor_substring() {
        let cfg = WarehouseCostGuardConfig::default();
        assert!(cfg.looks_like_warehouse("bigquery-prod", "query"));
        assert!(cfg.looks_like_warehouse("main", "snowflake"));
        assert!(!cfg.looks_like_warehouse("postgres", "sql"));
    }
}
