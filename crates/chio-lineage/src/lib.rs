//! Chio lineage and provenance DAG (M09 wave-opener skeleton).
//!
//! This crate is the M09 lineage substrate. Phase 0 lands only the crate
//! genesis: workspace registration, the schema-name constant, and the
//! placeholder error type. Subsequent M09 phases (P5.T1 through P5.T9) ship
//! the DAG schema, OTEL ingest path, M04 corpus ingest path, recursive-CTE
//! query layer, differential mode, and CLI surface.
//!
//! Source of truth: `.planning/trajectory-2/09-economic-layer-and-lineage.md`.

#![forbid(unsafe_code)]

/// JSON Schema name reserved for the lineage DAG. The schema artifact lands
/// at `crates/chio-lineage/schemas/lineage-graph.v1.json` in M09 P5.T1.
pub const LINEAGE_GRAPH_SCHEMA: &str = "chio.lineage.graph/v1";

/// Errors surfaced by the lineage indexer. Phase 0 lands the variant skeleton
/// so downstream callers compile against the public type without churn.
#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    /// The OTEL ingest path or M04 corpus ingest path has not been
    /// implemented yet. M09 P5.T2 and P5.T3 land the real paths.
    #[error("lineage ingest path not yet implemented")]
    NotYetImplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_name_is_versioned() {
        assert_eq!(LINEAGE_GRAPH_SCHEMA, "chio.lineage.graph/v1");
    }

    #[test]
    fn not_yet_implemented_renders() {
        let err = LineageError::NotYetImplemented;
        assert_eq!(err.to_string(), "lineage ingest path not yet implemented");
    }
}
