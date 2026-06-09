//! Error types for the Chio data layer guards.
//!
//! Data layer guards return [`Verdict::Deny`](chio_kernel::Verdict::Deny) on
//! failure and emit a structured denial reason via tracing.  The reason types
//! are exposed here so downstream integrations (for example the kernel's
//! receipt builder or a policy test harness) can match on them structurally
//! rather than string-parsing log lines.

use thiserror::Error;

/// Structured reason for a [`SqlQueryGuard`](crate::sql_guard::SqlQueryGuard)
/// denial.
///
/// Every denial path in the SQL guard produces one of these variants.  The
/// guard logs the reason via `tracing::warn!` and returns
/// `Ok(Verdict::Deny)`; callers that need the reason programmatically can use
/// [`SqlQueryGuard::analyze`](crate::sql_guard::SqlQueryGuard::analyze) which
/// returns the reason alongside the verdict.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SqlGuardDenyReason {
    /// The parsed operation class is not present in the guard's
    /// `operation_allowlist` (fail-closed default).
    #[error("sql operation '{operation}' is not allowed")]
    OperationNotAllowed {
        /// The parsed operation class (for example `SELECT`, `DROP`).
        operation: String,
    },

    /// A referenced table is not present in the guard's `table_allowlist`.
    #[error("table '{table}' is not in the allowlist")]
    TableNotAllowed {
        /// The offending table name, as parsed (case preserved for logs).
        table: String,
    },

    /// A projected column is not present in the guard's `column_allowlist`
    /// for the given table.
    #[error("column '{column}' on table '{table}' is not in the allowlist")]
    ColumnNotAllowed {
        /// The table owning the column.
        table: String,
        /// The offending column name.
        column: String,
    },

    /// The canonicalized WHERE/predicate text matched a denylist regex.
    #[error("predicate matched denylist pattern '{pattern}'")]
    PredicateDenylisted {
        /// The regex pattern source that matched.
        pattern: String,
    },

    /// A mutation (UPDATE, DELETE) lacked a WHERE clause.
    #[error("{operation} without WHERE clause is not allowed")]
    MissingWhereClause {
        /// The mutation operation kind.
        operation: String,
    },

    /// `sqlparser` could not parse the query.  Fail-closed.
    #[error("sql parse error: {error}")]
    ParseError {
        /// Human readable parser error message.
        error: String,
    },

    /// The guard config has no allowlists at all and `allow_all` is false.
    /// Fail-closed default: an unconfigured guard denies every query.
    #[error("sql guard has no configured allowlists and allow_all is false")]
    NoConfig,

    /// `SELECT *` attempted while a column allowlist is active.
    #[error("SELECT * on table '{table}' is denied when a column allowlist is active")]
    SelectStarDenied {
        /// The offending table name.
        table: String,
    },
}

impl SqlGuardDenyReason {
    /// Short stable tag suitable for metrics labels.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OperationNotAllowed { .. } => "operation_not_allowed",
            Self::TableNotAllowed { .. } => "table_not_allowed",
            Self::ColumnNotAllowed { .. } => "column_not_allowed",
            Self::PredicateDenylisted { .. } => "predicate_denylisted",
            Self::MissingWhereClause { .. } => "missing_where_clause",
            Self::ParseError { .. } => "parse_error",
            Self::NoConfig => "no_config",
            Self::SelectStarDenied { .. } => "select_star_denied",
        }
    }
}
