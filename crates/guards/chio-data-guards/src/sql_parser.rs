//! Thin wrapper over the `sqlparser` crate that produces a normalized
//! [`SqlAnalysis`] for the guard to evaluate.
//!
//! Goals:
//!
//! - Keep [`sqlparser`] types out of the guard surface.  Everything the
//!   guard consumes is a plain `String`, `Vec<String>`, or an
//!   [`SqlOperation`].
//! - Extract the four things the guard cares about: the operation class,
//!   the referenced tables, the projected columns per table (for `SELECT`
//!   only), and whether a `WHERE` clause is present.
//! - Fail-closed on parse errors: returning an [`Err`] causes the guard
//!   to deny.

use sqlparser::ast::{
    Delete, FromTable, Insert, ObjectName, ObjectNamePart, Query, Select, SelectItem, SetExpr,
    Statement, TableFactor, TableObject, Update, UpdateTableFromKind,
};
use sqlparser::dialect::{
    BigQueryDialect, Dialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect,
    SQLiteDialect, SnowflakeDialect,
};
use sqlparser::parser::Parser;

use crate::config::{SqlDialect, SqlOperation};

/// Normalized view of a parsed SQL statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlAnalysis {
    /// Operation class.
    pub operation: SqlOperation,
    /// All tables referenced anywhere in the statement.  Names are left as
    /// the parser produced them (case preserved); case-insensitive compare
    /// happens in the config layer.
    pub tables: Vec<String>,
    /// Projected columns per source table, for `SELECT` queries only.
    ///
    /// Each entry is `(table, column)`.  `column == "*"` means the query
    /// uses a wildcard projection.  The table is the source table as
    /// resolved from the `FROM` list (aliases are resolved back to the
    /// underlying table).  When the projection cannot be resolved to a
    /// specific table, the special sentinel `"?"` is used so the guard
    /// can conservatively apply column checks across every referenced
    /// table.
    pub projected_columns: Vec<(String, String)>,
    /// Whether the statement contains a `WHERE` clause.  Applies to
    /// `SELECT`, `UPDATE`, `DELETE`.  `INSERT` always reports `false`.
    pub has_where: bool,
    /// Canonicalized WHERE text, lower-cased and whitespace-collapsed, or
    /// an empty string when absent.  Used against the predicate denylist.
    pub where_canonical: String,
}

/// Parse `query` and return a normalized analysis.  Parse errors are
/// returned as [`Err(String)`] so the guard can build a
/// [`SqlGuardDenyReason::ParseError`](crate::error::SqlGuardDenyReason::ParseError)
/// from them.
pub fn parse(query: &str, dialect: SqlDialect) -> Result<SqlAnalysis, String> {
    let dialect_obj = dialect_for(dialect);
    let statements = Parser::parse_sql(dialect_obj.as_ref(), query).map_err(|e| e.to_string())?;
    // Reject multi-statement queries fail-closed. Analyzing only the first
    // statement would let a payload like `SELECT ...; DROP TABLE ...` sail
    // past scope checks because the guard classifies the SELECT while the
    // destructive DROP hides behind it. Drivers like mysql-connector or
    // postgres that support `multi_statements` would then execute both.
    // Operators who legitimately need a batch can split and evaluate each
    // statement independently.
    if statements.len() > 1 {
        return Err(format!(
            "multi-statement SQL not supported by guard (found {} statements); split into separate evaluations",
            statements.len()
        ));
    }
    let Some(statement) = statements.into_iter().next() else {
        return Err("empty statement".to_string());
    };

    Ok(analyze(&statement))
}

fn dialect_for(dialect: SqlDialect) -> Box<dyn Dialect + Send + Sync> {
    match dialect {
        SqlDialect::Generic => Box::new(GenericDialect {}),
        SqlDialect::Postgres => Box::new(PostgreSqlDialect {}),
        SqlDialect::MySql => Box::new(MySqlDialect {}),
        SqlDialect::Sqlite => Box::new(SQLiteDialect {}),
        SqlDialect::MsSql => Box::new(MsSqlDialect {}),
        SqlDialect::Snowflake => Box::new(SnowflakeDialect {}),
        SqlDialect::BigQuery => Box::new(BigQueryDialect {}),
    }
}

fn analyze(stmt: &Statement) -> SqlAnalysis {
    let mut analysis = SqlAnalysis {
        operation: classify(stmt),
        tables: Vec::new(),
        projected_columns: Vec::new(),
        has_where: false,
        where_canonical: String::new(),
    };

    match stmt {
        Statement::Query(query) => analyze_query(query, &mut analysis),
        Statement::Insert(insert) => analyze_insert(insert, &mut analysis),
        Statement::Update(update) => analyze_update(update, &mut analysis),
        Statement::Delete(Delete {
            from, selection, ..
        }) => {
            let twj_list = match from {
                FromTable::WithFromKeyword(list) | FromTable::WithoutKeyword(list) => list,
            };
            for twj in twj_list {
                collect_table_factor(&twj.relation, &mut analysis.tables, &mut Vec::new());
            }
            if let Some(expr) = selection {
                analysis.has_where = true;
                analysis.where_canonical = canonicalize(&expr_to_string(expr));
            }
        }
        Statement::Truncate(truncate) => {
            for truncate_target in &truncate.table_names {
                analysis
                    .tables
                    .push(object_name_to_string(&truncate_target.name));
            }
        }
        Statement::CreateTable(ct) => analysis.tables.push(object_name_to_string(&ct.name)),
        Statement::Drop { names, .. } => {
            for name in names {
                analysis.tables.push(object_name_to_string(name));
            }
        }
        Statement::AlterTable(alter) => analysis.tables.push(object_name_to_string(&alter.name)),
        _ => {}
    }

    dedupe(&mut analysis.tables);
    analysis
}

fn classify(stmt: &Statement) -> SqlOperation {
    match stmt {
        Statement::Query(_) => SqlOperation::Select,
        Statement::Insert(_) => SqlOperation::Insert,
        Statement::Update(_) => SqlOperation::Update,
        Statement::Delete(_) | Statement::Truncate(_) => SqlOperation::Delete,
        Statement::CreateTable(_)
        | Statement::CreateView { .. }
        | Statement::CreateIndex(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateTrigger { .. }
        | Statement::Drop { .. }
        | Statement::AlterTable(_)
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::RenameTable(_)
        | Statement::Comment { .. } => SqlOperation::Ddl,
        _ => SqlOperation::Other,
    }
}

fn analyze_query(query: &Query, analysis: &mut SqlAnalysis) {
    match query.body.as_ref() {
        SetExpr::Select(select) => analyze_select(select, analysis),
        SetExpr::Query(inner) => analyze_query(inner, analysis),
        SetExpr::SetOperation { left, right, .. } => {
            analyze_set_expr(left, analysis);
            analyze_set_expr(right, analysis);
        }
        _ => {}
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            analyze_query(&cte.query, analysis);
        }
    }
}

fn analyze_set_expr(expr: &SetExpr, analysis: &mut SqlAnalysis) {
    match expr {
        SetExpr::Select(select) => analyze_select(select, analysis),
        SetExpr::Query(inner) => analyze_query(inner, analysis),
        SetExpr::SetOperation { left, right, .. } => {
            analyze_set_expr(left, analysis);
            analyze_set_expr(right, analysis);
        }
        _ => {}
    }
}

fn analyze_select(select: &Select, analysis: &mut SqlAnalysis) {
    if let Some(into) = &select.into {
        analysis.operation = SqlOperation::Ddl;
        analysis.tables.push(object_name_to_string(&into.name));
    }

    // Resolve FROM/JOIN table list and build an alias -> table map so
    // qualified projections (`u.id`) can be attributed to their source
    // table.
    let mut aliases: Vec<(String, String)> = Vec::new();
    for twj in &select.from {
        collect_table_factor(&twj.relation, &mut analysis.tables, &mut aliases);
        for join in &twj.joins {
            collect_table_factor(&join.relation, &mut analysis.tables, &mut aliases);
        }
    }

    // Determine the "primary" source table for unqualified projections.
    // If there is exactly one source table, use it; otherwise mark "?".
    let primary_table: String = if analysis.tables.len() == 1 {
        analysis.tables[0].clone()
    } else {
        "?".to_string()
    };

    for item in &select.projection {
        match item {
            SelectItem::Wildcard(_) => {
                if analysis.tables.is_empty() {
                    analysis.projected_columns.push(("?".into(), "*".into()));
                } else {
                    for tbl in &analysis.tables {
                        analysis.projected_columns.push((tbl.clone(), "*".into()));
                    }
                }
            }
            SelectItem::QualifiedWildcard(kind, _) => {
                let object_name = match kind {
                    sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name) => name,
                    sqlparser::ast::SelectItemQualifiedWildcardKind::Expr(_) => {
                        analysis.projected_columns.push(("?".into(), "*".into()));
                        continue;
                    }
                };
                let qualifier = object_name_to_string(object_name);
                let resolved = resolve_alias(&qualifier, &aliases).unwrap_or(qualifier);
                analysis.projected_columns.push((resolved, "*".into()));
            }
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                let (table, column) = resolve_projected_expr(expr, &primary_table, &aliases);
                analysis.projected_columns.push((table, column));
            }
        }
    }

    if let Some(expr) = &select.selection {
        analysis.has_where = true;
        analysis.where_canonical = canonicalize(&expr_to_string(expr));
    }
}

fn expr_to_string(expr: &sqlparser::ast::Expr) -> String {
    format!("{expr}")
}

fn collect_table_factor(
    factor: &TableFactor,
    tables: &mut Vec<String>,
    aliases: &mut Vec<(String, String)>,
) {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            let full = object_name_to_string(name);
            tables.push(full.clone());
            if let Some(a) = alias {
                aliases.push((a.name.value.clone(), full));
            }
        }
        TableFactor::Derived {
            subquery, alias, ..
        } => {
            let mut nested = SqlAnalysis {
                operation: SqlOperation::Select,
                tables: Vec::new(),
                projected_columns: Vec::new(),
                has_where: false,
                where_canonical: String::new(),
            };
            analyze_query(subquery, &mut nested);
            for t in nested.tables {
                tables.push(t.clone());
                if let Some(a) = alias {
                    aliases.push((a.name.value.clone(), t));
                }
            }
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            collect_table_factor(&table_with_joins.relation, tables, aliases);
            for join in &table_with_joins.joins {
                collect_table_factor(&join.relation, tables, aliases);
            }
        }
        _ => {}
    }
}

fn resolve_projected_expr(
    expr: &sqlparser::ast::Expr,
    primary_table: &str,
    aliases: &[(String, String)],
) -> (String, String) {
    use sqlparser::ast::Expr;
    match expr {
        Expr::Identifier(ident) => (primary_table.to_string(), ident.value.clone()),
        Expr::CompoundIdentifier(parts) => {
            if parts.len() >= 2 {
                let qualifier = parts[parts.len() - 2].value.clone();
                let column = parts[parts.len() - 1].value.clone();
                let resolved = resolve_alias(&qualifier, aliases).unwrap_or(qualifier);
                (resolved, column)
            } else if let Some(single) = parts.first() {
                (primary_table.to_string(), single.value.clone())
            } else {
                ("?".into(), "?".into())
            }
        }
        // Any other expression (function call, literal, arithmetic) does
        // not project a single identified column; we mark it with "?" so
        // the guard will neither allow nor deny on column grounds.  The
        // guard falls back to table-allowlist enforcement for these.
        _ => (primary_table.to_string(), "?".to_string()),
    }
}

fn resolve_alias(qualifier: &str, aliases: &[(String, String)]) -> Option<String> {
    let lower = qualifier.to_ascii_lowercase();
    aliases
        .iter()
        .find(|(a, _)| a.to_ascii_lowercase() == lower)
        .map(|(_, t)| t.clone())
}

fn analyze_insert(insert: &Insert, analysis: &mut SqlAnalysis) {
    match &insert.table {
        TableObject::TableName(name) => analysis.tables.push(object_name_to_string(name)),
        TableObject::TableFunction(_) => {}
    }
    if let Some(source) = &insert.source {
        analyze_query(source, analysis);
    }
}

fn analyze_update(update: &Update, analysis: &mut SqlAnalysis) {
    collect_table_factor(
        &update.table.relation,
        &mut analysis.tables,
        &mut Vec::new(),
    );
    for join in &update.table.joins {
        collect_table_factor(&join.relation, &mut analysis.tables, &mut Vec::new());
    }
    if let Some(UpdateTableFromKind::BeforeSet(from_list))
    | Some(UpdateTableFromKind::AfterSet(from_list)) = &update.from
    {
        for twj in from_list {
            collect_table_factor(&twj.relation, &mut analysis.tables, &mut Vec::new());
        }
    }
    if let Some(expr) = &update.selection {
        analysis.has_where = true;
        analysis.where_canonical = canonicalize(&expr_to_string(expr));
    }
}

fn object_name_to_string(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|part| match part {
            ObjectNamePart::Identifier(i) => i.value.clone(),
            ObjectNamePart::Function(f) => f.name.value.clone(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn canonicalize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_ws = false;
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

fn dedupe(items: &mut Vec<String>) {
    let mut seen: Vec<String> = Vec::new();
    items.retain(|item| {
        let lower = item.to_ascii_lowercase();
        if seen.contains(&lower) {
            false
        } else {
            seen.push(lower);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_select() {
        let a = parse("SELECT id, name FROM orders", SqlDialect::Generic).expect("parse");
        assert_eq!(a.operation, SqlOperation::Select);
        assert_eq!(a.tables, vec!["orders".to_string()]);
        assert_eq!(
            a.projected_columns,
            vec![
                ("orders".to_string(), "id".to_string()),
                ("orders".to_string(), "name".to_string()),
            ]
        );
        assert!(!a.has_where);
    }

    #[test]
    fn parses_select_star() {
        let a = parse("SELECT * FROM users", SqlDialect::Generic).expect("parse");
        assert_eq!(a.operation, SqlOperation::Select);
        assert_eq!(a.tables, vec!["users".to_string()]);
        assert_eq!(
            a.projected_columns,
            vec![("users".to_string(), "*".to_string())]
        );
    }

    #[test]
    fn classifies_drop_as_ddl() {
        let a = parse("DROP TABLE orders", SqlDialect::Generic).expect("parse");
        assert_eq!(a.operation, SqlOperation::Ddl);
        assert_eq!(a.tables, vec!["orders".to_string()]);
    }

    #[test]
    fn classifies_update_with_where() {
        let a = parse(
            "UPDATE orders SET total = 0 WHERE id = 1",
            SqlDialect::Generic,
        )
        .expect("parse");
        assert_eq!(a.operation, SqlOperation::Update);
        assert!(a.has_where);
        assert!(a.where_canonical.contains("id = 1"));
    }

    #[test]
    fn classifies_delete_without_where() {
        let a = parse("DELETE FROM orders", SqlDialect::Generic).expect("parse");
        assert_eq!(a.operation, SqlOperation::Delete);
        assert!(!a.has_where);
    }

    #[test]
    fn resolves_alias_in_projection() {
        let a = parse(
            "SELECT o.id FROM orders o JOIN users u ON o.user_id = u.id",
            SqlDialect::Generic,
        )
        .expect("parse");
        assert_eq!(a.operation, SqlOperation::Select);
        // orders should be resolved through alias "o"
        assert!(a
            .projected_columns
            .iter()
            .any(|(t, c)| t == "orders" && c == "id"));
    }

    #[test]
    fn parses_postgres_dialect() {
        let a = parse(
            "SELECT id FROM orders WHERE created_at > NOW() - INTERVAL '1 day'",
            SqlDialect::Postgres,
        )
        .expect("parse");
        assert_eq!(a.operation, SqlOperation::Select);
    }

    #[test]
    fn parses_mysql_dialect() {
        let a = parse(
            "SELECT `id` FROM `orders` WHERE `name` = 'x'",
            SqlDialect::MySql,
        )
        .expect("parse");
        assert_eq!(a.operation, SqlOperation::Select);
        assert_eq!(a.tables, vec!["orders".to_string()]);
    }

    #[test]
    fn parse_error_is_surfaced() {
        let err = parse("SELEKT * FRUM", SqlDialect::Generic).expect_err("should fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn canonicalize_normalizes_whitespace_and_case() {
        assert_eq!(canonicalize("  ID  =  1  "), "id = 1");
        assert_eq!(canonicalize("A\n\tOR\n1=1"), "a or 1=1");
    }

    #[test]
    fn truncate_is_delete() {
        let a = parse("TRUNCATE TABLE orders", SqlDialect::Generic).expect("parse");
        assert_eq!(a.operation, SqlOperation::Delete);
    }

    #[test]
    fn select_into_is_treated_as_write_ddl() {
        let a = parse("SELECT id INTO archive FROM orders", SqlDialect::MsSql).expect("parse");
        assert_eq!(a.operation, SqlOperation::Ddl);
        assert!(a.tables.contains(&"archive".to_string()));
        assert!(a.tables.contains(&"orders".to_string()));
    }
}
