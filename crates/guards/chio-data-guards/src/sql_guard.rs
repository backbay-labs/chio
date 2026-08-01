//! The `SqlQueryGuard` implementation.
//!
//! The guard listens for `ToolAction::DatabaseQuery { database, query }` via
//! [`chio_guards::extract_action_checked`] and enforces four knobs defined by
//! [`SqlGuardConfig`]: operation allowlist, table allowlist, per-table
//! column allowlist, and regex predicate denylist.  Failures route through
//! [`SqlGuardDenyReason`](crate::error::SqlGuardDenyReason) so downstream
//! callers can match on structured reasons.
//!
//! Fail-closed semantics:
//!
//! - parse errors deny (even when `allow_all` is set);
//! - empty configurations deny unless `allow_all` is set;
//! - any check that fails short-circuits to `Verdict::Deny`;
//! - the guard passes non-`DatabaseQuery` actions through with
//!   `Verdict::Allow` (guards are additive).

use regex::{Regex, RegexBuilder};
use tracing::warn;

use chio_guards::{extract_action_checked, ToolAction};
use chio_kernel::{GuardContext, GuardDecision, KernelError};

use crate::config::{SqlGuardConfig, SqlOperation};
use crate::error::SqlGuardDenyReason;
use crate::sql_parser::{self, SqlAnalysis};

/// Built-in SQL query guard.
pub struct SqlQueryGuard {
    config: SqlGuardConfig,
    denylist_regex: Vec<(String, Regex)>,
}

const MAX_DENYLISTED_PREDICATES: usize = 64;
const MAX_DENYLISTED_PREDICATE_LEN: usize = 512;
const MAX_DENYLISTED_PREDICATE_COMPLEXITY: usize = 96;
const DENYLISTED_PREDICATE_REGEX_SIZE_LIMIT: usize = 1 << 20;
const DENYLISTED_PREDICATE_DFA_SIZE_LIMIT: usize = 1 << 20;

impl SqlQueryGuard {
    /// Construct a new guard with the given configuration.
    ///
    /// Invalid or over-broad `denylisted_predicates` produce a guard that
    /// denies every SQL query. Use [`Self::try_new`] when policy loading should
    /// reject invalid configurations directly.
    pub fn new(config: SqlGuardConfig) -> Self {
        match Self::try_new(config) {
            Ok(guard) => guard,
            Err(error) => {
                warn!(
                    target: "chio.data-guards.sql",
                    error = %error,
                    "invalid sql-query-guard config; constructing fail-closed deny-all guard"
                );
                Self {
                    config: SqlGuardConfig::default(),
                    denylist_regex: Vec::new(),
                }
            }
        }
    }

    /// Construct a new guard or reject invalid user-supplied regex patterns.
    pub fn try_new(config: SqlGuardConfig) -> Result<Self, String> {
        if config.allow_all {
            warn!(
                target: "chio.data-guards.sql",
                "sql-query-guard constructed with allow_all=true; fail-closed default disabled"
            );
        }

        if config.denylisted_predicates.len() > MAX_DENYLISTED_PREDICATES {
            return Err(format!(
                "sql_query.denylisted_predicates allows at most {MAX_DENYLISTED_PREDICATES} patterns"
            ));
        }
        let mut denylist_regex = Vec::with_capacity(config.denylisted_predicates.len());
        for pattern in &config.denylisted_predicates {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err("sql_query.denylisted_predicates cannot contain empty patterns".into());
            }
            if trimmed.len() > MAX_DENYLISTED_PREDICATE_LEN {
                return Err(format!(
                    "sql_query.denylisted_predicates entries must be at most {MAX_DENYLISTED_PREDICATE_LEN} characters"
                ));
            }
            let complexity = predicate_pattern_complexity(trimmed);
            if complexity > MAX_DENYLISTED_PREDICATE_COMPLEXITY {
                return Err(format!(
                    "sql_query.denylisted_predicates entries must have complexity at most {MAX_DENYLISTED_PREDICATE_COMPLEXITY}"
                ));
            }
            let re = RegexBuilder::new(trimmed)
                .case_insensitive(true)
                .size_limit(DENYLISTED_PREDICATE_REGEX_SIZE_LIMIT)
                .dfa_size_limit(DENYLISTED_PREDICATE_DFA_SIZE_LIMIT)
                .build()
                .map_err(|error| {
                    format!("invalid sql_query.denylisted_predicates entry `{trimmed}`: {error}")
                })?;
            denylist_regex.push((trimmed.to_string(), re));
        }

        Ok(Self {
            config,
            denylist_regex,
        })
    }

    /// Read-only access to the configuration (useful for tests and
    /// observability).
    pub fn config(&self) -> &SqlGuardConfig {
        &self.config
    }

    /// Evaluate a raw SQL query string against the configured policy.
    ///
    /// Returns `Ok(())` to allow, `Err(SqlGuardDenyReason)` to deny.  This
    /// is the primary testing and integration entry point; the
    /// [`chio_kernel::Guard`] impl is a thin wrapper that maps this result
    /// to [`Verdict`].
    pub fn analyze(&self, query: &str) -> Result<SqlAnalysis, SqlGuardDenyReason> {
        // Fail-closed on parse error, even when allow_all is set.
        let analysis = sql_parser::parse(query, self.config.dialect)
            .map_err(|e| SqlGuardDenyReason::ParseError { error: e })?;

        if self.config.allow_all {
            return Ok(analysis);
        }

        if self.config.is_empty() {
            return Err(SqlGuardDenyReason::NoConfig);
        }

        self.enforce_operation(&analysis)?;
        self.enforce_tables(&analysis)?;
        self.enforce_columns(&analysis)?;
        self.enforce_predicate_denylist(&analysis)?;
        self.enforce_where_for_mutations(&analysis)?;

        Ok(analysis)
    }

    fn enforce_operation(&self, analysis: &SqlAnalysis) -> Result<(), SqlGuardDenyReason> {
        if self.config.operation_allowlist.is_empty() {
            // If no operation allowlist was set but other lists are, we
            // conservatively require an explicit allowlist: fail-closed.
            return Err(SqlGuardDenyReason::OperationNotAllowed {
                operation: analysis.operation.as_str().to_string(),
            });
        }
        if !self
            .config
            .operation_allowlist
            .contains(&analysis.operation)
        {
            return Err(SqlGuardDenyReason::OperationNotAllowed {
                operation: analysis.operation.as_str().to_string(),
            });
        }
        Ok(())
    }

    fn enforce_tables(&self, analysis: &SqlAnalysis) -> Result<(), SqlGuardDenyReason> {
        if self.config.table_allowlist.is_empty() {
            return Err(SqlGuardDenyReason::TableNotAllowed {
                table: analysis
                    .tables
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "<none>".to_string()),
            });
        }
        for table in &analysis.tables {
            if !self.config.table_allowed(table) {
                return Err(SqlGuardDenyReason::TableNotAllowed {
                    table: table.clone(),
                });
            }
        }
        Ok(())
    }

    fn enforce_columns(&self, analysis: &SqlAnalysis) -> Result<(), SqlGuardDenyReason> {
        if analysis.operation != SqlOperation::Select {
            return Ok(());
        }
        let Some(_) = self.config.column_allowlist.as_ref() else {
            return Ok(());
        };

        for (table, column) in &analysis.projected_columns {
            // Wildcard projection: deny whenever the table has an
            // explicit column allowlist.  We cannot prove the expansion
            // is inside the allowed set.
            if column == "*" {
                if self.config.table_has_column_allowlist(table) {
                    return Err(SqlGuardDenyReason::SelectStarDenied {
                        table: table.clone(),
                    });
                }
                continue;
            }

            // Computed/opaque projections (`"?"` from the parser, e.g.
            // `SELECT lower(ssn) FROM users`) or JOINs where the source
            // table cannot be resolved (parser emits `table == "?"` too).
            // A per-table allowlist check is not enough: the computed
            // expression could read any column from any joined table,
            // and for JOINs `table == "?"` never matches a real
            // allowlist entry, letting sensitive columns leak through
            // expressions like `lower(users.ssn)`.
            //
            // We reach this branch only after the early return at the
            // top of `enforce_columns` proved that SOME column allowlist
            // is configured, so fail closed uniformly on any `"?"`
            // projection: the guard cannot prove the expression stays
            // inside the allowed set without evaluating it.
            if column == "?" {
                return Err(SqlGuardDenyReason::ColumnNotAllowed {
                    table: table.clone(),
                    column: "?".to_string(),
                });
            }

            // Apply the column allowlist for this table if configured.
            match self.config.column_allowed(table, column) {
                Some(true) => {}
                Some(false) => {
                    return Err(SqlGuardDenyReason::ColumnNotAllowed {
                        table: table.clone(),
                        column: column.clone(),
                    })
                }
                None => {
                    // Table has no column allowlist entry: allow.
                }
            }
        }
        Ok(())
    }

    fn enforce_predicate_denylist(&self, analysis: &SqlAnalysis) -> Result<(), SqlGuardDenyReason> {
        if self.denylist_regex.is_empty() {
            return Ok(());
        }
        if analysis.where_canonical.is_empty() {
            return Ok(());
        }
        for (pattern, re) in &self.denylist_regex {
            if re.is_match(&analysis.where_canonical) {
                return Err(SqlGuardDenyReason::PredicateDenylisted {
                    pattern: pattern.clone(),
                });
            }
        }
        Ok(())
    }

    fn enforce_where_for_mutations(
        &self,
        analysis: &SqlAnalysis,
    ) -> Result<(), SqlGuardDenyReason> {
        if !self.config.require_where_for_mutations {
            return Ok(());
        }
        let needs_where = matches!(
            analysis.operation,
            SqlOperation::Update | SqlOperation::Delete
        );
        if needs_where && !analysis.has_where {
            return Err(SqlGuardDenyReason::MissingWhereClause {
                operation: analysis.operation.as_str().to_string(),
            });
        }
        Ok(())
    }
}

fn predicate_pattern_complexity(pattern: &str) -> usize {
    let mut score = 0usize;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' | '*' | '+' | '?' => score = score.saturating_add(4),
            '{' | '[' | '(' => score = score.saturating_add(2),
            _ => {}
        }
    }
    score
}

impl chio_kernel::Guard for SqlQueryGuard {
    fn name(&self) -> &str {
        "sql-query"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };
        let (database, query) = match &action {
            ToolAction::DatabaseQuery { database, query } => (database.as_str(), query.as_str()),
            _ => return Ok(GuardDecision::allow()),
        };

        match self.analyze(query) {
            Ok(_) => Ok(GuardDecision::allow()),
            Err(reason) => {
                warn!(
                    target: "chio.data-guards.sql",
                    database = %database,
                    code = reason.code(),
                    reason = %reason,
                    "sql-query-guard denied query"
                );
                Ok(GuardDecision::deny(Vec::new()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use chio_core::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{Guard, ToolCallRequest, Verdict};

    use crate::config::{SqlDialect, SqlGuardConfig, SqlOperation};

    fn test_capability() -> CapabilityToken {
        let kp = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-sql-guard".into(),
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

    fn cfg_select_orders() -> SqlGuardConfig {
        SqlGuardConfig {
            dialect: SqlDialect::Generic,
            operation_allowlist: vec![SqlOperation::Select],
            table_allowlist: vec!["orders".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn allow_select_from_allowed_table() {
        let g = SqlQueryGuard::new(cfg_select_orders());
        g.analyze("SELECT id FROM orders").expect("allowed");
    }

    #[test]
    fn evaluate_denies_malformed_database_query_arguments() {
        let guard = SqlQueryGuard::new(SqlGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let request = ToolCallRequest {
            request_id: "req-sql-malformed-action".to_string(),
            capability: test_capability(),
            tool_name: "sql".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            arguments: serde_json::json!({"query": ["SELECT id FROM orders"]}),
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
        assert_eq!(verdict.verdict, Verdict::Deny);
    }

    #[test]
    fn deny_select_from_unlisted_table() {
        let g = SqlQueryGuard::new(cfg_select_orders());
        let err = g.analyze("SELECT * FROM users").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::TableNotAllowed { .. }));
    }

    #[test]
    fn deny_drop_when_ddl_not_allowed() {
        let g = SqlQueryGuard::new(cfg_select_orders());
        let err = g.analyze("DROP TABLE orders").expect_err("denied");
        assert!(matches!(
            err,
            SqlGuardDenyReason::OperationNotAllowed { .. }
        ));
    }

    #[test]
    fn deny_update_when_only_select_allowed() {
        let g = SqlQueryGuard::new(cfg_select_orders());
        let err = g
            .analyze("UPDATE orders SET foo=1 WHERE id=1")
            .expect_err("denied");
        assert!(matches!(
            err,
            SqlGuardDenyReason::OperationNotAllowed { .. }
        ));
    }

    #[test]
    fn deny_malformed_sql() {
        let g = SqlQueryGuard::new(cfg_select_orders());
        let err = g.analyze("SELEKT oops").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::ParseError { .. }));
    }

    #[test]
    fn empty_config_denies() {
        let g = SqlQueryGuard::new(SqlGuardConfig::default());
        let err = g.analyze("SELECT 1").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::NoConfig));
    }

    #[test]
    fn allow_all_still_denies_parse_errors() {
        let g = SqlQueryGuard::new(SqlGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        let err = g.analyze("NOT SQL AT ALL ;;;;").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::ParseError { .. }));
    }

    #[test]
    fn allow_all_permits_well_formed_query() {
        let g = SqlQueryGuard::new(SqlGuardConfig {
            allow_all: true,
            ..Default::default()
        });
        g.analyze("SELECT id FROM whatever").expect("allowed");
    }

    #[test]
    fn column_allowlist_denies_unlisted_column() {
        let mut map = HashMap::new();
        map.insert(
            "orders".to_string(),
            vec!["id".to_string(), "total".to_string()],
        );
        let cfg = SqlGuardConfig {
            operation_allowlist: vec![SqlOperation::Select],
            table_allowlist: vec!["orders".into()],
            column_allowlist: Some(map),
            ..Default::default()
        };
        let g = SqlQueryGuard::new(cfg);
        g.analyze("SELECT id, total FROM orders").expect("allowed");
        let err = g
            .analyze("SELECT id, email FROM orders")
            .expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::ColumnNotAllowed { .. }));
    }

    #[test]
    fn select_star_denied_when_column_allowlist_active() {
        let mut map = HashMap::new();
        map.insert("orders".to_string(), vec!["id".to_string()]);
        let cfg = SqlGuardConfig {
            operation_allowlist: vec![SqlOperation::Select],
            table_allowlist: vec!["orders".into()],
            column_allowlist: Some(map),
            ..Default::default()
        };
        let g = SqlQueryGuard::new(cfg);
        let err = g.analyze("SELECT * FROM orders").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::SelectStarDenied { .. }));
    }

    #[test]
    fn predicate_denylist_blocks_or_1_equals_1() {
        let cfg = SqlGuardConfig {
            operation_allowlist: vec![SqlOperation::Select],
            table_allowlist: vec!["orders".into()],
            denylisted_predicates: vec![r"\bor\s+1\s*=\s*1\b".to_string()],
            ..Default::default()
        };
        let g = SqlQueryGuard::new(cfg);
        let err = g
            .analyze("SELECT id FROM orders WHERE id = 1 OR 1=1")
            .expect_err("denied");
        assert!(matches!(
            err,
            SqlGuardDenyReason::PredicateDenylisted { .. }
        ));
    }

    #[test]
    fn mutation_without_where_is_denied() {
        let cfg = SqlGuardConfig {
            operation_allowlist: vec![SqlOperation::Delete],
            table_allowlist: vec!["orders".into()],
            ..Default::default()
        };
        let g = SqlQueryGuard::new(cfg);
        let err = g.analyze("DELETE FROM orders").expect_err("denied");
        assert!(matches!(err, SqlGuardDenyReason::MissingWhereClause { .. }));
    }

    #[test]
    fn mutation_where_optional_when_disabled() {
        let cfg = SqlGuardConfig {
            operation_allowlist: vec![SqlOperation::Delete],
            table_allowlist: vec!["orders".into()],
            require_where_for_mutations: false,
            ..Default::default()
        };
        let g = SqlQueryGuard::new(cfg);
        g.analyze("DELETE FROM orders").expect("allowed");
    }
}
