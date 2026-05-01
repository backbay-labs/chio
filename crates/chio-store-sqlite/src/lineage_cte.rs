//! Recursive-CTE lineage queries.
//!
//! Provides forward and reverse recursive-CTE walks atop the receipt
//! and capability lineage tables. Behind the `lineage` cargo feature so
//! the receipt store keeps byte-equivalent behaviour when the feature
//! is off.
//!
//! Depth and row caps are enforced inside SQL with
//! `WHERE depth < ?N` and an explicit `LIMIT`; on overflow the caller
//! receives a truncation marker matching the schema in
//! `chio-lineage::schema::TruncationMarker`.

use rusqlite::Connection;

/// Default depth bound. Mirrors [`chio_lineage::query::DEFAULT_DEPTH_LIMIT`].
pub const DEFAULT_DEPTH_LIMIT: u32 = 20;

/// Result of a recursive walk: receipt ids and a truncation flag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkResult {
    pub receipt_ids: Vec<String>,
    pub depth_reached: u32,
    pub truncated: bool,
    pub limit: u32,
}

/// Forward walk over `receipt_lineage_statements`: starting at
/// `parent_receipt_id`, follow signed receipt-lineage edges to children.
/// The CTE caps recursion at `depth_limit` and total rows at `row_limit`.
pub fn forward_receipt_lineage(
    conn: &Connection,
    parent_receipt_id: &str,
    depth_limit: u32,
    row_limit: u32,
) -> rusqlite::Result<WalkResult> {
    let sql = "
        WITH RECURSIVE downstream(receipt_id, parent_receipt_id, depth) AS (
            SELECT receipt_id, parent_receipt_id, 0 AS depth
            FROM receipt_lineage_statements
            WHERE parent_receipt_id = ?1
            UNION ALL
            SELECT s.receipt_id, s.parent_receipt_id, d.depth + 1
            FROM receipt_lineage_statements s
            JOIN downstream d ON s.parent_receipt_id = d.receipt_id
            WHERE d.depth + 1 < ?2
        )
        SELECT receipt_id, depth FROM downstream
        ORDER BY depth, receipt_id
        LIMIT ?3
    ";
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(rusqlite::params![
        parent_receipt_id,
        depth_limit as i64,
        row_limit as i64,
    ])?;
    let mut ids = Vec::new();
    let mut deepest = 0u32;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let depth: i64 = row.get(1)?;
        deepest = deepest.max(depth as u32);
        ids.push(id);
    }
    let truncated = ids.len() as u32 >= row_limit || deepest + 1 >= depth_limit;
    Ok(WalkResult {
        receipt_ids: ids,
        depth_reached: deepest,
        truncated,
        limit: depth_limit,
    })
}

/// Reverse walk: given a receipt id, walk upstream through signed
/// receipt-lineage statements to discover ancestor receipts.
pub fn reverse_receipt_lineage(
    conn: &Connection,
    child_receipt_id: &str,
    depth_limit: u32,
    row_limit: u32,
) -> rusqlite::Result<WalkResult> {
    let sql = "
        WITH RECURSIVE upstream(receipt_id, parent_receipt_id, depth) AS (
            SELECT receipt_id, parent_receipt_id, 0 AS depth
            FROM receipt_lineage_statements
            WHERE receipt_id = ?1
            UNION ALL
            SELECT s.receipt_id, s.parent_receipt_id, u.depth + 1
            FROM receipt_lineage_statements s
            JOIN upstream u ON s.receipt_id = u.parent_receipt_id
            WHERE u.depth + 1 < ?2
        )
        SELECT parent_receipt_id, depth FROM upstream
        WHERE parent_receipt_id IS NOT NULL
        ORDER BY depth, parent_receipt_id
        LIMIT ?3
    ";
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(rusqlite::params![
        child_receipt_id,
        depth_limit as i64,
        row_limit as i64,
    ])?;
    let mut ids = Vec::new();
    let mut deepest = 0u32;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let depth: i64 = row.get(1)?;
        deepest = deepest.max(depth as u32);
        ids.push(id);
    }
    let truncated = ids.len() as u32 >= row_limit || deepest + 1 >= depth_limit;
    Ok(WalkResult {
        receipt_ids: ids,
        depth_reached: deepest,
        truncated,
        limit: depth_limit,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE receipt_lineage_statements (
                receipt_id TEXT NOT NULL,
                parent_receipt_id TEXT,
                PRIMARY KEY (receipt_id, parent_receipt_id)
            );",
        )
        .unwrap();
        conn
    }

    fn add_edge(conn: &Connection, child: &str, parent: &str) {
        conn.execute(
            "INSERT INTO receipt_lineage_statements (receipt_id, parent_receipt_id) VALUES (?1, ?2)",
            rusqlite::params![child, parent],
        )
        .unwrap();
    }

    #[test]
    fn forward_walks_descendants() {
        let conn = fresh_conn();
        add_edge(&conn, "b", "a");
        add_edge(&conn, "c", "b");
        let r = forward_receipt_lineage(&conn, "a", 20, 100).unwrap();
        assert!(r.receipt_ids.contains(&"b".to_string()));
        assert!(r.receipt_ids.contains(&"c".to_string()));
    }

    #[test]
    fn reverse_walks_ancestors() {
        let conn = fresh_conn();
        add_edge(&conn, "b", "a");
        add_edge(&conn, "c", "b");
        let r = reverse_receipt_lineage(&conn, "c", 20, 100).unwrap();
        assert!(r.receipt_ids.contains(&"b".to_string()));
        // The CTE chains upward via the parent linkage; both ancestors land.
        assert!(r.receipt_ids.contains(&"a".to_string()));
    }

    #[test]
    fn depth_limit_bounds_results() {
        let conn = fresh_conn();
        for i in 0..10 {
            add_edge(&conn, &format!("r{}", i + 1), &format!("r{}", i));
        }
        let r = forward_receipt_lineage(&conn, "r0", 3, 100).unwrap();
        // depth 0..2 fit, depth 3 is excluded; row count <= 3.
        assert!(r.receipt_ids.len() <= 3);
    }
}
