//! Lineage DAG schema.
//!
//! Defines the node and edge types projected from the receipt store,
//! capability lineage, and signed receipt-lineage statements. The schema
//! is the source of truth for the JSON artifact at
//! `crates/observability/chio-lineage/schemas/lineage-graph.v1.json`.
//!
//! Evidence-class preservation rules:
//!
//! - `Asserted`: caller-supplied call-chain attributes, OTEL ingest fields
//!   that are not signed independently.
//! - `Observed`: local runtime kernel truth (request lineage, capability
//!   lineage, kernel-emitted receipts that have been written to this store).
//! - `Verified`: signed session anchors, signed receipt-lineage statements,
//!   verified continuation tokens, and checkpoint or anchor proofs after
//!   verification.

use serde::{Deserialize, Serialize};

/// Provenance evidence class. Mirrors the values defined by
/// `spec/PROTOCOL.md` for caller-supplied vs locally-observed vs
/// independently-verified facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Caller-supplied or imported attributes that have not been signed or
    /// independently verified by this kernel.
    Asserted,
    /// Local kernel runtime truth (rows in this store written by the
    /// kernel itself).
    Observed,
    /// Independently signed or proof-checked.
    Verified,
}

/// Lineage node kinds. Every node in the graph belongs to exactly one of
/// these kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Prompt,
    Capability,
    GuardVerdict,
    ToolCall,
    Receipt,
}

/// Lineage edge kinds, typed by the relation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    PromptToCapability,
    CapabilityParent,
    CapabilityToGuard,
    GuardToToolCall,
    ToolCallToReceipt,
    ReceiptToChildRequest,
    RequestToRequest,
    ReceiptLineageParent,
    /// A governed memory-write receipt depends on the verified Finding
    /// delivery receipt whose content it ingested. Direction is dependent
    /// write -> source delivery so reverse traversal from the source reports
    /// the complete bounded blast radius.
    FindingMemoryWriteToDelivery,
}

/// A graph node. Stable id, kind, evidence class, and optional projection
/// metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageNode {
    pub id: String,
    pub kind: NodeKind,
    pub evidence_class: EvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

/// A graph edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub evidence_class: EvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<i64>,
}

/// Truncation marker emitted when bounded query results exceed the
/// documented depth or row cap. Its shape is pinned to bound the
/// recursive-CTE traversal risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationMarker {
    pub truncated: bool,
    pub depth_reached: u32,
    pub limit: u32,
}

impl TruncationMarker {
    /// Produce the canonical "depth reached the cap" marker.
    pub fn at_depth(depth_reached: u32, limit: u32) -> Self {
        Self {
            truncated: true,
            depth_reached,
            limit,
        }
    }
}

/// Top-level lineage graph projection. A complete graph or a query-bounded
/// subgraph (with optional truncation marker).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageGraph {
    pub schema_version: String,
    pub nodes: Vec<LineageNode>,
    pub edges: Vec<LineageEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<TruncationMarker>,
}

impl LineageGraph {
    /// Construct an empty graph stamped with the current schema version.
    pub fn empty() -> Self {
        Self {
            schema_version: crate::LINEAGE_GRAPH_SCHEMA.to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            truncated: None,
        }
    }

    /// Mark this projection as truncated at the documented depth bound.
    pub fn with_truncation(mut self, depth_reached: u32, limit: u32) -> Self {
        self.truncated = Some(TruncationMarker::at_depth(depth_reached, limit));
        self
    }

    /// Return true if any node or edge carries the requested evidence class.
    pub fn contains_evidence(&self, class: EvidenceClass) -> bool {
        self.nodes.iter().any(|n| n.evidence_class == class)
            || self.edges.iter().any(|e| e.evidence_class == class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_marker_shape_is_pinned() {
        let marker = TruncationMarker::at_depth(20, 20);
        let json = serde_json::to_value(marker).unwrap_or(serde_json::Value::Null);
        assert_eq!(json["truncated"], serde_json::json!(true));
        assert_eq!(json["depth_reached"], serde_json::json!(20));
        assert_eq!(json["limit"], serde_json::json!(20));
    }

    #[test]
    fn empty_graph_carries_schema_version() {
        let g = LineageGraph::empty();
        assert_eq!(g.schema_version, crate::LINEAGE_GRAPH_SCHEMA);
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        assert!(g.truncated.is_none());
    }

    #[test]
    fn evidence_class_round_trips_snake_case() {
        let v = serde_json::to_value(EvidenceClass::Asserted).unwrap_or(serde_json::Value::Null);
        assert_eq!(v, serde_json::json!("asserted"));
        let v = serde_json::to_value(EvidenceClass::Observed).unwrap_or(serde_json::Value::Null);
        assert_eq!(v, serde_json::json!("observed"));
        let v = serde_json::to_value(EvidenceClass::Verified).unwrap_or(serde_json::Value::Null);
        assert_eq!(v, serde_json::json!("verified"));
    }

    #[test]
    fn schema_artifact_exists_and_pins_marker_shape() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/schemas/lineage-graph.v1.json");
        let bytes = std::fs::read(path).unwrap_or_default();
        assert!(!bytes.is_empty(), "schema artifact must exist");
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        let marker = &v["definitions"]["TruncationMarker"]["properties"];
        assert!(marker.get("truncated").is_some());
        assert!(marker.get("depth_reached").is_some());
        assert!(marker.get("limit").is_some());
        let edge_kinds = v["definitions"]["EdgeKind"]["enum"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(edge_kinds.iter().any(|kind| {
            kind == &serde_json::Value::String("finding_memory_write_to_delivery".to_owned())
        }));
    }

    #[test]
    fn contains_evidence_walks_nodes_and_edges() {
        let mut g = LineageGraph::empty();
        g.nodes.push(LineageNode {
            id: "n1".into(),
            kind: NodeKind::Receipt,
            evidence_class: EvidenceClass::Observed,
            tenant_id: None,
            recorded_at: None,
            label: None,
            source_table: None,
            source_id: None,
        });
        assert!(g.contains_evidence(EvidenceClass::Observed));
        assert!(!g.contains_evidence(EvidenceClass::Verified));
    }
}
