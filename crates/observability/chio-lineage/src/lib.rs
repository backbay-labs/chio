//! Chio lineage and provenance DAG.
//!
//! Indexes signed receipts, capability lineage, and signed
//! receipt-lineage statements into a provenance DAG. Source feeds are
//! the OTEL receipt exporter NDJSON stream and the deterministic replay
//! corpus.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod diff;
pub mod ingest_otel;
pub mod ingest_replay_corpus;
pub mod query;
pub mod schema;

/// JSON Schema name reserved for the lineage DAG. Schema artifact lives at
/// `crates/chio-lineage/schemas/lineage-graph.v1.json`.
pub const LINEAGE_GRAPH_SCHEMA: &str = "chio.lineage.graph/v1";

/// Errors surfaced by the lineage indexer.
#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    #[error("OTEL ingest failed: {0}")]
    OtelIngest(#[from] ingest_otel::OtelIngestError),
    #[error("replay corpus ingest failed: {0}")]
    CorpusIngest(#[from] ingest_replay_corpus::CorpusIngestError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_name_is_versioned() {
        assert_eq!(LINEAGE_GRAPH_SCHEMA, "chio.lineage.graph/v1");
    }
}
