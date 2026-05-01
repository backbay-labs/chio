//! Deterministic replay-corpus ingest.
//!
//! Reads replay corpus fixtures and reconstructs the same DAG shape as
//! the OTEL ingest path so that an offline ground truth is available to
//! the recursive-CTE query layer and the differential mode. Receipts
//! read from the corpus carry `Observed` evidence class because the
//! corpus is the canonical kernel-emitted ground truth; signed receipt-
//! lineage statements observed in the corpus upgrade to `Verified`.
//!
//! Corpus rows are not mutated by ingest; this module only projects.

use serde::{Deserialize, Serialize};

use crate::schema::{EdgeKind, EvidenceClass, LineageEdge, LineageGraph, LineageNode, NodeKind};

/// One M04 corpus receipt row in the lineage-projection shape. Real M04
/// corpus rows carry many more fields; only the lineage-relevant subset is
/// typed here. Unknown fields are tolerated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusReceiptRow {
    pub receipt_id: String,
    #[serde(default)]
    pub parent_receipt_id: Option<String>,
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub parent_capability_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub recorded_at: Option<i64>,
    /// True when the corpus row carries a signed receipt-lineage
    /// statement linking parent_receipt_id to receipt_id.
    #[serde(default)]
    pub has_signed_lineage_statement: bool,
}

/// Ingest errors.
#[derive(Debug, thiserror::Error)]
pub enum CorpusIngestError {
    #[error("invalid corpus row JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Project a corpus row set into a lineage graph. Deterministic in row
/// order; idempotent on duplicate rows (graph dedups by node and edge keys).
pub fn ingest_corpus(rows: &[CorpusReceiptRow]) -> LineageGraph {
    let mut graph = LineageGraph::empty();
    let mut seen_nodes = std::collections::HashSet::new();
    let mut seen_edges = std::collections::HashSet::new();

    let mut push_node = |g: &mut LineageGraph, n: LineageNode| {
        if seen_nodes.insert(n.id.clone()) {
            g.nodes.push(n);
        }
    };
    let mut push_edge = |g: &mut LineageGraph, e: LineageEdge| {
        let key = (e.from.clone(), e.to.clone(), e.kind);
        if seen_edges.insert(key) {
            g.edges.push(e);
        }
    };

    for row in rows {
        let receipt_id = format!("rcpt:{}", row.receipt_id);
        push_node(
            &mut graph,
            LineageNode {
                id: receipt_id.clone(),
                kind: NodeKind::Receipt,
                evidence_class: EvidenceClass::Observed,
                tenant_id: row.tenant_id.clone(),
                recorded_at: row.recorded_at,
                label: Some(row.receipt_id.clone()),
                source_table: Some("m04.corpus".to_string()),
                source_id: Some(row.receipt_id.clone()),
            },
        );

        if let Some(cap) = &row.capability_id {
            let cap_id = format!("cap:{cap}");
            push_node(
                &mut graph,
                LineageNode {
                    id: cap_id.clone(),
                    kind: NodeKind::Capability,
                    evidence_class: EvidenceClass::Observed,
                    tenant_id: row.tenant_id.clone(),
                    recorded_at: row.recorded_at,
                    label: Some(cap.clone()),
                    source_table: Some("m04.corpus".to_string()),
                    source_id: Some(row.receipt_id.clone()),
                },
            );
            if let Some(parent_cap) = &row.parent_capability_id {
                let parent_id = format!("cap:{parent_cap}");
                push_node(
                    &mut graph,
                    LineageNode {
                        id: parent_id.clone(),
                        kind: NodeKind::Capability,
                        evidence_class: EvidenceClass::Observed,
                        tenant_id: row.tenant_id.clone(),
                        recorded_at: row.recorded_at,
                        label: Some(parent_cap.clone()),
                        source_table: Some("m04.corpus".to_string()),
                        source_id: Some(row.receipt_id.clone()),
                    },
                );
                push_edge(
                    &mut graph,
                    LineageEdge {
                        from: parent_id,
                        to: cap_id.clone(),
                        kind: EdgeKind::CapabilityParent,
                        evidence_class: EvidenceClass::Observed,
                        source_table: Some("m04.corpus".to_string()),
                        source_id: Some(row.receipt_id.clone()),
                        tenant_id: row.tenant_id.clone(),
                        recorded_at: row.recorded_at,
                    },
                );
            }
            if let Some(tool) = &row.tool_name {
                let tool_id = format!("tool:{}:{}", row.receipt_id, tool);
                push_node(
                    &mut graph,
                    LineageNode {
                        id: tool_id.clone(),
                        kind: NodeKind::ToolCall,
                        evidence_class: EvidenceClass::Observed,
                        tenant_id: row.tenant_id.clone(),
                        recorded_at: row.recorded_at,
                        label: Some(tool.clone()),
                        source_table: Some("m04.corpus".to_string()),
                        source_id: Some(row.receipt_id.clone()),
                    },
                );
                push_edge(
                    &mut graph,
                    LineageEdge {
                        from: cap_id,
                        to: tool_id.clone(),
                        kind: EdgeKind::CapabilityToGuard,
                        evidence_class: EvidenceClass::Observed,
                        source_table: Some("m04.corpus".to_string()),
                        source_id: Some(row.receipt_id.clone()),
                        tenant_id: row.tenant_id.clone(),
                        recorded_at: row.recorded_at,
                    },
                );
                push_edge(
                    &mut graph,
                    LineageEdge {
                        from: tool_id,
                        to: receipt_id.clone(),
                        kind: EdgeKind::ToolCallToReceipt,
                        evidence_class: EvidenceClass::Observed,
                        source_table: Some("m04.corpus".to_string()),
                        source_id: Some(row.receipt_id.clone()),
                        tenant_id: row.tenant_id.clone(),
                        recorded_at: row.recorded_at,
                    },
                );
            }
        }

        if let Some(parent) = &row.parent_receipt_id {
            let parent_node = format!("rcpt:{parent}");
            push_node(
                &mut graph,
                LineageNode {
                    id: parent_node.clone(),
                    kind: NodeKind::Receipt,
                    evidence_class: EvidenceClass::Observed,
                    tenant_id: row.tenant_id.clone(),
                    recorded_at: row.recorded_at,
                    label: Some(parent.clone()),
                    source_table: Some("m04.corpus".to_string()),
                    source_id: Some(parent.clone()),
                },
            );
            // Verified only when the corpus row attests to a signed
            // receipt-lineage statement. Otherwise observed.
            let evidence = if row.has_signed_lineage_statement {
                EvidenceClass::Verified
            } else {
                EvidenceClass::Observed
            };
            push_edge(
                &mut graph,
                LineageEdge {
                    from: parent_node,
                    to: receipt_id,
                    kind: EdgeKind::ReceiptLineageParent,
                    evidence_class: evidence,
                    source_table: Some("m04.corpus".to_string()),
                    source_id: Some(row.receipt_id.clone()),
                    tenant_id: row.tenant_id.clone(),
                    recorded_at: row.recorded_at,
                },
            );
        }
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_corpus_yields_empty_graph() {
        let g = ingest_corpus(&[]);
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
    }

    #[test]
    fn signed_lineage_statement_upgrades_to_verified() {
        let rows = vec![CorpusReceiptRow {
            receipt_id: "child".into(),
            parent_receipt_id: Some("parent".into()),
            capability_id: None,
            parent_capability_id: None,
            tool_name: None,
            tenant_id: None,
            recorded_at: None,
            has_signed_lineage_statement: true,
        }];
        let g = ingest_corpus(&rows);
        let edge = g
            .edges
            .iter()
            .find(|e| e.kind == EdgeKind::ReceiptLineageParent);
        assert!(edge.is_some());
        if let Some(e) = edge {
            assert_eq!(e.evidence_class, EvidenceClass::Verified);
        }
    }

    #[test]
    fn ingest_is_deterministic_and_idempotent() {
        let row = CorpusReceiptRow {
            receipt_id: "r1".into(),
            parent_receipt_id: None,
            capability_id: Some("cap.x".into()),
            parent_capability_id: Some("cap.root".into()),
            tool_name: Some("tool.run".into()),
            tenant_id: Some("t".into()),
            recorded_at: Some(1),
            has_signed_lineage_statement: false,
        };
        let rows = vec![row.clone(), row.clone(), row];
        let g = ingest_corpus(&rows);
        // Three rows but every fact is the same, so dedup applies.
        // Expected: 1 receipt + 2 capabilities (x and root) + 1 tool call = 4 nodes.
        assert_eq!(g.nodes.len(), 4);
        assert!(g.nodes.iter().any(|n| n.kind == NodeKind::Receipt));
        assert_eq!(
            g.nodes
                .iter()
                .filter(|n| n.kind == NodeKind::Capability)
                .count(),
            2
        );
        assert_eq!(
            g.nodes
                .iter()
                .filter(|n| n.kind == NodeKind::ToolCall)
                .count(),
            1
        );
    }
}
