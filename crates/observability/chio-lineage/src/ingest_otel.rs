//! OTEL receipt-stream ingest.
//!
//! Folds NDJSON frames produced by the OTEL receipt exporter
//! (`crates/chio-otel-receipt-exporter/src/sink.rs`) into the lineage
//! DAG. Idempotent on re-ingest: edges and nodes carry stable natural
//! keys derived from the source receipt id and OTEL trace/span ids.
//!
//! Schema-version gate: frames declare `otel.schema = otlp.grpc.trace.v1`;
//! unknown versions reject fail-closed via [`OtelIngestError::SchemaMismatch`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::schema::{EdgeKind, EvidenceClass, LineageEdge, LineageGraph, LineageNode, NodeKind};

/// Pinned ingest schema. The exporter writes frames stamped with this value
/// in the `otel.schema` attribute.
pub const OTEL_INGEST_SCHEMA: &str = "otlp.grpc.trace.v1";

/// One NDJSON frame from the OTEL receipt exporter sink. Only the fields
/// the lineage indexer needs are typed; unknown fields are tolerated to
/// keep ingest forward-compatible inside the same major schema version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelReceiptFrame {
    pub schema_version: String,
    pub receipt_id: String,
    pub trace_id: String,
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub recorded_at: Option<i64>,
    /// Optional: the local Chio receipt id this OTEL span correlates to.
    /// When present, the ingest path emits a `tool_call_to_receipt` edge
    /// upgraded to `Observed` evidence class (the kernel wrote the receipt
    /// itself); without it, the edge stays `Asserted`.
    #[serde(default)]
    pub correlation_source_chio_receipt_id: Option<String>,
}

/// Ingest errors.
#[derive(Debug, thiserror::Error)]
pub enum OtelIngestError {
    /// The frame was malformed JSON.
    #[error("invalid OTEL NDJSON frame: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// Frame schema version is not recognised. Fail-closed.
    #[error("unsupported OTEL ingest schema: expected {expected}, got {actual}")]
    SchemaMismatch { expected: String, actual: String },
    /// A required natural-key field was empty or whitespace-padded.
    #[error("invalid required OTEL field: {field}")]
    InvalidRequiredField { field: &'static str },
}

/// In-memory ingest. Folds frames into a [`LineageGraph`], deduplicating
/// nodes and edges by their natural keys.
#[derive(Debug, Default)]
pub struct OtelIngest {
    graph: LineageGraph,
    seen_nodes: HashSet<String>,
    seen_edges: HashSet<(String, String, EdgeKind)>,
}

impl OtelIngest {
    pub fn new() -> Self {
        Self {
            graph: LineageGraph::empty(),
            seen_nodes: HashSet::new(),
            seen_edges: HashSet::new(),
        }
    }

    /// Parse and ingest a single NDJSON frame line.
    pub fn ingest_line(&mut self, line: &str) -> Result<(), OtelIngestError> {
        let frame: OtelReceiptFrame = serde_json::from_str(line)?;
        self.ingest_frame(frame)
    }

    /// Ingest a fully-typed frame.
    pub fn ingest_frame(&mut self, frame: OtelReceiptFrame) -> Result<(), OtelIngestError> {
        if frame.schema_version != OTEL_INGEST_SCHEMA {
            return Err(OtelIngestError::SchemaMismatch {
                expected: OTEL_INGEST_SCHEMA.to_string(),
                actual: frame.schema_version,
            });
        }
        validate_required_field(&frame.receipt_id, "receipt_id")?;
        validate_required_field(&frame.trace_id, "trace_id")?;
        validate_required_field(&frame.span_id, "span_id")?;

        // Tool call node. OTEL is caller-asserted until correlated.
        let tool_id = format!("tool:{}:{}", frame.trace_id, frame.span_id);
        self.add_node(LineageNode {
            id: tool_id.clone(),
            kind: NodeKind::ToolCall,
            evidence_class: EvidenceClass::Asserted,
            tenant_id: frame.tenant_id.clone(),
            recorded_at: frame.recorded_at,
            label: frame.tool_name.clone(),
            source_table: Some("otel.span".to_string()),
            source_id: Some(frame.span_id.clone()),
        });

        // Capability node, when known.
        if let Some(cap) = frame.capability_id.as_deref() {
            let cap_id = format!("cap:{cap}");
            self.add_node(LineageNode {
                id: cap_id.clone(),
                kind: NodeKind::Capability,
                evidence_class: EvidenceClass::Asserted,
                tenant_id: frame.tenant_id.clone(),
                recorded_at: frame.recorded_at,
                label: Some(cap.to_string()),
                source_table: Some("otel.span".to_string()),
                source_id: Some(frame.span_id.clone()),
            });
            self.add_edge(LineageEdge {
                from: cap_id,
                to: tool_id.clone(),
                kind: EdgeKind::CapabilityToGuard,
                evidence_class: EvidenceClass::Asserted,
                source_table: Some("otel.span".to_string()),
                source_id: Some(frame.span_id.clone()),
                tenant_id: frame.tenant_id.clone(),
                recorded_at: frame.recorded_at,
            });
        }

        // Receipt node + edge. Observed only if the frame carries the
        // local Chio receipt correlation; otherwise asserted.
        let (receipt_id, evidence) = match frame.correlation_source_chio_receipt_id.as_deref() {
            Some(local) => (format!("rcpt:{local}"), EvidenceClass::Observed),
            None => (
                format!("rcpt:otel:{}", frame.receipt_id),
                EvidenceClass::Asserted,
            ),
        };
        self.add_node(LineageNode {
            id: receipt_id.clone(),
            kind: NodeKind::Receipt,
            evidence_class: evidence,
            tenant_id: frame.tenant_id.clone(),
            recorded_at: frame.recorded_at,
            label: Some(frame.receipt_id.clone()),
            source_table: Some("otel.receipt".to_string()),
            source_id: Some(frame.receipt_id.clone()),
        });
        self.add_edge(LineageEdge {
            from: tool_id,
            to: receipt_id,
            kind: EdgeKind::ToolCallToReceipt,
            evidence_class: evidence,
            source_table: Some("otel.span".to_string()),
            source_id: Some(frame.span_id.clone()),
            tenant_id: frame.tenant_id,
            recorded_at: frame.recorded_at,
        });

        Ok(())
    }

    fn add_node(&mut self, node: LineageNode) {
        if self.seen_nodes.insert(node.id.clone()) {
            self.graph.nodes.push(node);
        }
    }

    fn add_edge(&mut self, edge: LineageEdge) {
        let key = (edge.from.clone(), edge.to.clone(), edge.kind);
        if self.seen_edges.insert(key) {
            self.graph.edges.push(edge);
        }
    }

    /// Consume the ingest state and return the accumulated graph.
    pub fn into_graph(self) -> LineageGraph {
        self.graph
    }

    /// Borrow the current graph state without consuming.
    pub fn graph(&self) -> &LineageGraph {
        &self.graph
    }
}

fn validate_required_field(value: &str, field: &'static str) -> Result<(), OtelIngestError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(OtelIngestError::InvalidRequiredField { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> OtelReceiptFrame {
        OtelReceiptFrame {
            schema_version: OTEL_INGEST_SCHEMA.to_string(),
            receipt_id: "r1".into(),
            trace_id: "t1".into(),
            span_id: "s1".into(),
            parent_span_id: None,
            capability_id: Some("cap.read".into()),
            tool_name: Some("fs.read".into()),
            tenant_id: Some("tenant-a".into()),
            recorded_at: Some(1700000000),
            correlation_source_chio_receipt_id: None,
        }
    }

    #[test]
    fn ingest_is_idempotent() {
        let mut ingest = OtelIngest::new();
        ingest.ingest_frame(frame()).unwrap_or_default();
        let nodes_after_first = ingest.graph().nodes.len();
        let edges_after_first = ingest.graph().edges.len();
        ingest.ingest_frame(frame()).unwrap_or_default();
        assert_eq!(ingest.graph().nodes.len(), nodes_after_first);
        assert_eq!(ingest.graph().edges.len(), edges_after_first);
    }

    #[test]
    fn schema_mismatch_rejects_fail_closed() {
        let mut bad = frame();
        bad.schema_version = "otlp.future.v9".into();
        let mut ingest = OtelIngest::new();
        let res = ingest.ingest_frame(bad);
        assert!(matches!(res, Err(OtelIngestError::SchemaMismatch { .. })));
        // Nothing was ingested.
        assert!(ingest.graph().nodes.is_empty());
        assert!(ingest.graph().edges.is_empty());
    }

    #[test]
    fn required_frame_ids_must_be_non_empty_and_unpadded() {
        fn assert_rejected(field: &str, configure: impl FnOnce(&mut OtelReceiptFrame)) {
            let mut bad = frame();
            configure(&mut bad);
            let mut ingest = OtelIngest::new();
            let res = ingest.ingest_frame(bad);

            assert!(matches!(
                res,
                Err(OtelIngestError::InvalidRequiredField { field: actual }) if actual == field
            ));
            assert!(ingest.graph().nodes.is_empty());
            assert!(ingest.graph().edges.is_empty());
        }

        assert_rejected("receipt_id", |frame| {
            frame.receipt_id = " ".into();
        });
        assert_rejected("trace_id", |frame| {
            frame.trace_id = " t1".into();
        });
        assert_rejected("span_id", |frame| {
            frame.span_id = "s1 ".into();
        });
        assert_rejected("receipt_id", |frame| {
            frame.receipt_id = "receipt\nbad".into();
        });
        assert_rejected("span_id", |frame| {
            frame.span_id = "span\0bad".into();
        });
    }

    #[test]
    fn correlation_upgrades_to_observed() {
        let mut f = frame();
        f.correlation_source_chio_receipt_id = Some("local-r-42".into());
        let mut ingest = OtelIngest::new();
        ingest.ingest_frame(f).unwrap_or_default();
        let g = ingest.into_graph();
        let receipt = g.nodes.iter().find(|n| n.kind == NodeKind::Receipt);
        assert!(receipt.is_some());
        if let Some(n) = receipt {
            assert_eq!(n.evidence_class, EvidenceClass::Observed);
        }
    }

    #[test]
    fn missing_correlation_stays_asserted() {
        let mut ingest = OtelIngest::new();
        ingest.ingest_frame(frame()).unwrap_or_default();
        let g = ingest.into_graph();
        let receipt = g.nodes.iter().find(|n| n.kind == NodeKind::Receipt);
        assert!(receipt.is_some());
        if let Some(n) = receipt {
            assert_eq!(n.evidence_class, EvidenceClass::Asserted);
        }
    }

    #[test]
    fn ndjson_line_round_trips() {
        let line = serde_json::to_string(&frame()).unwrap_or_default();
        let mut ingest = OtelIngest::new();
        ingest.ingest_line(&line).unwrap_or_default();
        assert_eq!(ingest.graph().nodes.len(), 3);
    }
}
