//! Configuration types for the SQL query guard.
//!
//! [`SqlGuardConfig`] captures the four enforcement knobs:
//!
//! - `operation_allowlist`: which SQL operations are permitted
//!   (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, DDL, other).
//! - `table_allowlist`: which tables may be referenced (case-insensitive).
//! - `column_allowlist`: optional per-table restriction on projected columns.
//! - `denylisted_predicates`: regex patterns matched against canonicalized
//!   WHERE clauses (for example to block `OR 1=1` style injections).
//!
//! The guard is fail-closed by default: an empty config denies every query.
//! Operators can opt into an open configuration via [`SqlGuardConfig::allow_all`],
//! which the guard logs as a warning on construction.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// SQL dialect selector for [`sqlparser`].
///
/// We keep our own enum rather than re-exporting [`sqlparser::dialect::Dialect`]
/// so the public config type is `Deserialize` and does not leak the parser
/// crate's trait objects into every caller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlDialect {
    /// Generic ANSI-ish dialect.  The default.
    #[default]
    Generic,
    /// PostgreSQL.
    Postgres,
    /// MySQL.
    MySql,
    /// SQLite.
    Sqlite,
    /// Microsoft SQL Server (T-SQL).
    MsSql,
    /// Snowflake.
    Snowflake,
    /// BigQuery.
    BigQuery,
}

/// Normalized SQL operation class tracked by the guard.
///
/// This is a coarser classification than [`sqlparser::ast::Statement`]: every
/// statement maps to exactly one of these variants.  Guards compare against
/// this enum so callers can write dialect-independent policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOperation {
    /// `SELECT`, `WITH ... SELECT`, and other read-only queries.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`, `TRUNCATE`.
    Delete,
    /// DDL: `CREATE`, `DROP`, `ALTER`, `RENAME`, `COMMENT`.
    Ddl,
    /// Anything that does not fit a category above (for example `EXPLAIN`,
    /// `SET`, `SHOW`).  Fail-closed: allowlist must explicitly include
    /// [`SqlOperation::Other`] for these.
    Other,
}

impl SqlOperation {
    /// Stable string tag used by logs and denial reasons.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Ddl => "DDL",
            Self::Other => "OTHER",
        }
    }
}

/// Guard configuration for [`SqlQueryGuard`](crate::sql_guard::SqlQueryGuard).
///
/// The guard is fail-closed: when every list is empty and `allow_all` is
/// false, the guard denies every SQL query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqlGuardConfig {
    /// SQL dialect used by the parser.  Defaults to [`SqlDialect::Generic`].
    #[serde(default)]
    pub dialect: SqlDialect,

    /// Operations that are permitted.  A query whose parsed
    /// [`SqlOperation`] is not in this list is denied.
    #[serde(default)]
    pub operation_allowlist: Vec<SqlOperation>,

    /// Tables that may be referenced in `FROM`, `JOIN`, `INSERT INTO`,
    /// `UPDATE`, and `DELETE FROM`.  Comparisons are case-insensitive.
    #[serde(default)]
    pub table_allowlist: Vec<String>,

    /// Optional per-table projected-column allowlist.  When set, every
    /// column projected in a `SELECT` on the table must appear here.  A
    /// table that does not appear as a key is treated as having no column
    /// restriction.  `SELECT *` is denied whenever the referenced table has
    /// a column allowlist entry.
    #[serde(default)]
    pub column_allowlist: Option<HashMap<String, Vec<String>>>,

    /// Regex patterns matched against the canonicalized WHERE clause text
    /// of each query.  A match denies the query.
    #[serde(default)]
    pub denylisted_predicates: Vec<String>,

    /// Deny mutations (`UPDATE`, `DELETE`) that lack a `WHERE` clause.
    /// Defaults to `true`.
    #[serde(default = "default_require_where_for_mutations")]
    pub require_where_for_mutations: bool,

    /// Escape hatch: allow every query that parses successfully.
    ///
    /// This overrides the fail-closed default.  The guard logs a warning
    /// on construction when `allow_all` is true so operators can find the
    /// escape hatch in observability.  Malformed SQL is still denied: the
    /// parse error wins over `allow_all`.
    #[serde(default)]
    pub allow_all: bool,
}

fn default_require_where_for_mutations() -> bool {
    true
}

impl Default for SqlGuardConfig {
    fn default() -> Self {
        Self {
            dialect: SqlDialect::default(),
            operation_allowlist: Vec::new(),
            table_allowlist: Vec::new(),
            column_allowlist: None,
            denylisted_predicates: Vec::new(),
            require_where_for_mutations: default_require_where_for_mutations(),
            allow_all: false,
        }
    }
}

impl SqlGuardConfig {
    /// Returns true when every allowlist is empty.  The guard treats this
    /// as "no config" and denies every query unless `allow_all` is set.
    pub fn is_empty(&self) -> bool {
        self.operation_allowlist.is_empty()
            && self.table_allowlist.is_empty()
            && self
                .column_allowlist
                .as_ref()
                .map(|m| m.is_empty())
                .unwrap_or(true)
            && self.denylisted_predicates.is_empty()
    }

    /// Case-insensitive lookup of a table in the allowlist.
    pub fn table_allowed(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.table_allowlist
            .iter()
            .any(|entry| entry.to_ascii_lowercase() == lower)
    }

    /// Case-insensitive lookup of a column on the given table.  Returns
    /// `None` when no column allowlist is configured, `Some(true)` when the
    /// column is allowed, and `Some(false)` when it is denied.
    pub fn column_allowed(&self, table: &str, column: &str) -> Option<bool> {
        let map = self.column_allowlist.as_ref()?;
        let lower_table = table.to_ascii_lowercase();
        let lower_column = column.to_ascii_lowercase();
        for (tbl, cols) in map {
            if tbl.to_ascii_lowercase() == lower_table {
                let allowed = cols
                    .iter()
                    .any(|c| c.to_ascii_lowercase() == lower_column || c == "*");
                return Some(allowed);
            }
        }
        None
    }

    /// Returns true when the table has an explicit column allowlist entry.
    /// Used to decide whether `SELECT *` should be denied.
    pub fn table_has_column_allowlist(&self, table: &str) -> bool {
        let Some(map) = self.column_allowlist.as_ref() else {
            return false;
        };
        let lower = table.to_ascii_lowercase();
        map.keys().any(|k| k.to_ascii_lowercase() == lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_detected() {
        let cfg = SqlGuardConfig::default();
        assert!(cfg.is_empty());
    }

    #[test]
    fn table_allowlist_is_case_insensitive() {
        let cfg = SqlGuardConfig {
            table_allowlist: vec!["Orders".to_string()],
            ..Default::default()
        };
        assert!(cfg.table_allowed("orders"));
        assert!(cfg.table_allowed("ORDERS"));
        assert!(!cfg.table_allowed("users"));
    }

    #[test]
    fn column_allowlist_returns_none_when_unset() {
        let cfg = SqlGuardConfig::default();
        assert!(cfg.column_allowed("orders", "id").is_none());
    }

    #[test]
    fn column_allowlist_hit_and_miss() {
        let mut map = HashMap::new();
        map.insert("orders".to_string(), vec!["id".to_string(), "total".into()]);
        let cfg = SqlGuardConfig {
            column_allowlist: Some(map),
            ..Default::default()
        };
        assert_eq!(cfg.column_allowed("orders", "id"), Some(true));
        assert_eq!(cfg.column_allowed("ORDERS", "TOTAL"), Some(true));
        assert_eq!(cfg.column_allowed("orders", "email"), Some(false));
        assert!(cfg.column_allowed("other_table", "id").is_none());
    }

    #[test]
    fn wildcard_column_allows_everything_on_that_table() {
        let mut map = HashMap::new();
        map.insert("orders".to_string(), vec!["*".to_string()]);
        let cfg = SqlGuardConfig {
            column_allowlist: Some(map),
            ..Default::default()
        };
        assert_eq!(cfg.column_allowed("orders", "anything"), Some(true));
    }

    #[test]
    fn table_has_column_allowlist_checks_keys() {
        let mut map = HashMap::new();
        map.insert("Orders".to_string(), vec!["id".into()]);
        let cfg = SqlGuardConfig {
            column_allowlist: Some(map),
            ..Default::default()
        };
        assert!(cfg.table_has_column_allowlist("orders"));
        assert!(!cfg.table_has_column_allowlist("users"));
    }
}
