//! Deterministic replay-corpus ingest.
//!
//! Reads replay corpus fixtures and reconstructs the same DAG shape as
//! the OTEL ingest path so that an offline ground truth is available to
//! the recursive-CTE query layer and the differential mode. Receipts
//! read from the corpus carry `Observed` evidence class because the
//! corpus is the canonical kernel-emitted ground truth; signed receipt-
//! lineage statements upgrade to `Verified` only after signature and
//! parent/child binding verification.
//!
//! Corpus rows are not mutated by ingest; this module only projects.

use serde::{Deserialize, Serialize};

use chio_core_types::capability::governance::ProvenanceEvidenceClass;
use chio_core_types::receipt::lineage::ReceiptLineageStatement;

use crate::schema::{EdgeKind, EvidenceClass, LineageEdge, LineageGraph, LineageNode, NodeKind};

/// One replay-corpus receipt row in the lineage-projection shape. Real
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
    /// Signed receipt-lineage statement linking parent_receipt_id to
    /// receipt_id. This is the only field that can upgrade replay-corpus
    /// receipt lineage from observed to verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_lineage_statement: Option<ReceiptLineageStatement>,
}

/// Ingest errors.
#[derive(Debug, thiserror::Error)]
pub enum CorpusIngestError {
    #[error("invalid corpus row JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid corpus field at row {row_index}: {field}")]
    InvalidField {
        row_index: usize,
        field: &'static str,
    },
}

/// Project a corpus row set into a lineage graph. Deterministic in row
/// order; idempotent on duplicate rows (graph dedups by node and edge keys).
pub fn ingest_corpus(rows: &[CorpusReceiptRow]) -> Result<LineageGraph, CorpusIngestError> {
    for (row_index, row) in rows.iter().enumerate() {
        validate_row(row, row_index)?;
    }

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
                source_table: Some("replay.corpus".to_string()),
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
                    source_table: Some("replay.corpus".to_string()),
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
                        source_table: Some("replay.corpus".to_string()),
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
                        source_table: Some("replay.corpus".to_string()),
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
                        source_table: Some("replay.corpus".to_string()),
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
                        source_table: Some("replay.corpus".to_string()),
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
                        source_table: Some("replay.corpus".to_string()),
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
                    source_table: Some("replay.corpus".to_string()),
                    source_id: Some(parent.clone()),
                },
            );
            let evidence = if signed_lineage_statement_verifies(row, parent) {
                EvidenceClass::Verified
            } else {
                EvidenceClass::Observed
            };
            let finding_dependency = row.signed_lineage_statement.as_ref().is_some_and(
                |statement| {
                    statement.relation_kind
                        == chio_core_types::receipt::lineage::ReceiptLineageRelationKind::FindingMemoryWriteToDelivery
                        && signed_lineage_statement_verifies(row, parent)
                },
            );
            let (from, to, kind) = if finding_dependency {
                (
                    receipt_id.clone(),
                    parent_node.clone(),
                    EdgeKind::FindingMemoryWriteToDelivery,
                )
            } else {
                (
                    parent_node.clone(),
                    receipt_id.clone(),
                    EdgeKind::ReceiptLineageParent,
                )
            };
            push_edge(
                &mut graph,
                LineageEdge {
                    from,
                    to,
                    kind,
                    evidence_class: evidence,
                    source_table: Some("replay.corpus".to_string()),
                    source_id: Some(row.receipt_id.clone()),
                    tenant_id: row.tenant_id.clone(),
                    recorded_at: row.recorded_at,
                },
            );
        }
    }

    Ok(graph)
}

fn signed_lineage_statement_verifies(row: &CorpusReceiptRow, parent: &str) -> bool {
    let Some(statement) = row.signed_lineage_statement.as_ref() else {
        return false;
    };
    statement.parent_receipt_id == parent
        && statement.child_receipt_id == row.receipt_id
        && statement.evidence_class == ProvenanceEvidenceClass::Verified
        && matches!(statement.verify_signature(), Ok(true))
}

fn validate_row(row: &CorpusReceiptRow, row_index: usize) -> Result<(), CorpusIngestError> {
    validate_required_field(&row.receipt_id, row_index, "receipt_id")?;
    validate_optional_field(
        row.parent_receipt_id.as_deref(),
        row_index,
        "parent_receipt_id",
    )?;
    validate_optional_field(row.capability_id.as_deref(), row_index, "capability_id")?;
    validate_optional_field(
        row.parent_capability_id.as_deref(),
        row_index,
        "parent_capability_id",
    )?;
    validate_optional_field(row.tool_name.as_deref(), row_index, "tool_name")?;
    validate_optional_field(row.tenant_id.as_deref(), row_index, "tenant_id")?;
    Ok(())
}

fn validate_required_field(
    value: &str,
    row_index: usize,
    field: &'static str,
) -> Result<(), CorpusIngestError> {
    if value.is_empty() || value.trim() != value {
        return Err(CorpusIngestError::InvalidField { row_index, field });
    }
    Ok(())
}

fn validate_optional_field(
    value: Option<&str>,
    row_index: usize,
    field: &'static str,
) -> Result<(), CorpusIngestError> {
    if let Some(value) = value {
        validate_required_field(value, row_index, field)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_corpus_yields_empty_graph() -> Result<(), CorpusIngestError> {
        let g = ingest_corpus(&[])?;
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        Ok(())
    }

    #[test]
    fn corpus_rows_reject_blank_or_padded_natural_keys() {
        fn row() -> CorpusReceiptRow {
            CorpusReceiptRow {
                receipt_id: "child".into(),
                parent_receipt_id: Some("parent".into()),
                capability_id: Some("cap.child".into()),
                parent_capability_id: Some("cap.parent".into()),
                tool_name: Some("tool.run".into()),
                tenant_id: Some("tenant-a".into()),
                recorded_at: None,
                signed_lineage_statement: None,
            }
        }

        fn assert_rejected(field: &'static str, configure: impl FnOnce(&mut CorpusReceiptRow)) {
            let mut bad = row();
            configure(&mut bad);
            let result = ingest_corpus(&[bad]);

            assert!(matches!(
                result,
                Err(CorpusIngestError::InvalidField { field: actual, .. }) if actual == field
            ));
        }

        assert_rejected("receipt_id", |row| {
            row.receipt_id = " ".into();
        });
        assert_rejected("parent_receipt_id", |row| {
            row.parent_receipt_id = Some(" parent".into());
        });
        assert_rejected("capability_id", |row| {
            row.capability_id = Some("cap.child ".into());
        });
        assert_rejected("parent_capability_id", |row| {
            row.parent_capability_id = Some("\t".into());
        });
        assert_rejected("tool_name", |row| {
            row.tool_name = Some(" tool.run".into());
        });
        assert_rejected("tenant_id", |row| {
            row.tenant_id = Some("tenant-a ".into());
        });
    }

    #[test]
    fn boolean_lineage_hint_does_not_upgrade_to_verified() -> Result<(), CorpusIngestError> {
        let rows = vec![CorpusReceiptRow {
            receipt_id: "child".into(),
            parent_receipt_id: Some("parent".into()),
            capability_id: None,
            parent_capability_id: None,
            tool_name: None,
            tenant_id: None,
            recorded_at: None,
            signed_lineage_statement: None,
        }];
        let g = ingest_corpus(&rows)?;
        let edge = g
            .edges
            .iter()
            .find(|e| e.kind == EdgeKind::ReceiptLineageParent);
        assert!(edge.is_some());
        if let Some(e) = edge {
            assert_eq!(e.evidence_class, EvidenceClass::Observed);
        }
        Ok(())
    }

    #[test]
    fn signed_lineage_statement_upgrades_to_verified() -> Result<(), Box<dyn std::error::Error>> {
        use chio_core_types::crypto::Keypair;
        use chio_core_types::receipt::{
            lineage::ReceiptLineageEndpoints, lineage::ReceiptLineageRelationKind,
            lineage::ReceiptLineageStatementBody,
        };
        use chio_core_types::session::{RequestId, SessionAnchorReference};

        let keypair = Keypair::generate();
        let statement = ReceiptLineageStatement::sign(
            ReceiptLineageStatementBody::new(
                "stmt-1",
                ReceiptLineageEndpoints::new(
                    "parent",
                    "child",
                    RequestId::new("parent-request"),
                    RequestId::new("child-request"),
                    SessionAnchorReference::new("parent-anchor", "parent-hash"),
                    SessionAnchorReference::new("child-anchor", "child-hash"),
                ),
                ReceiptLineageRelationKind::LocalChild,
                1,
                keypair.public_key(),
            ),
            &keypair,
        )?;
        let rows = vec![CorpusReceiptRow {
            receipt_id: "child".into(),
            parent_receipt_id: Some("parent".into()),
            capability_id: None,
            parent_capability_id: None,
            tool_name: None,
            tenant_id: None,
            recorded_at: None,
            signed_lineage_statement: Some(statement),
        }];
        let g = ingest_corpus(&rows)?;
        let edge = g
            .edges
            .iter()
            .find(|e| e.kind == EdgeKind::ReceiptLineageParent);
        assert!(edge.is_some());
        if let Some(e) = edge {
            assert_eq!(e.evidence_class, EvidenceClass::Verified);
        }
        Ok(())
    }

    #[test]
    fn finding_memory_dependency_keeps_its_typed_child_to_parent_direction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use chio_core_types::crypto::Keypair;
        use chio_core_types::receipt::{
            lineage::ReceiptLineageEndpoints, lineage::ReceiptLineageRelationKind,
            lineage::ReceiptLineageStatementBody,
        };
        use chio_core_types::session::{RequestId, SessionAnchorReference};

        let keypair = Keypair::generate();
        let statement = ReceiptLineageStatement::sign(
            ReceiptLineageStatementBody::new(
                "stmt-finding-memory",
                ReceiptLineageEndpoints::new(
                    "delivery",
                    "memory-write",
                    RequestId::new("delivery-request"),
                    RequestId::new("memory-request"),
                    SessionAnchorReference::new("delivery-anchor", "delivery-hash"),
                    SessionAnchorReference::new("memory-anchor", "memory-hash"),
                ),
                ReceiptLineageRelationKind::FindingMemoryWriteToDelivery,
                1,
                keypair.public_key(),
            ),
            &keypair,
        )?;
        let graph = ingest_corpus(&[CorpusReceiptRow {
            receipt_id: "memory-write".into(),
            parent_receipt_id: Some("delivery".into()),
            capability_id: None,
            parent_capability_id: None,
            tool_name: None,
            tenant_id: None,
            recorded_at: None,
            signed_lineage_statement: Some(statement),
        }])?;
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::FindingMemoryWriteToDelivery)
            .ok_or("typed Finding memory edge missing")?;
        assert_eq!(edge.from, "rcpt:memory-write");
        assert_eq!(edge.to, "rcpt:delivery");
        assert_eq!(edge.evidence_class, EvidenceClass::Verified);
        Ok(())
    }

    #[test]
    fn signed_lineage_statement_with_wrong_child_stays_observed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use chio_core_types::crypto::Keypair;
        use chio_core_types::receipt::{
            lineage::ReceiptLineageEndpoints, lineage::ReceiptLineageRelationKind,
            lineage::ReceiptLineageStatementBody,
        };
        use chio_core_types::session::{RequestId, SessionAnchorReference};

        let keypair = Keypair::generate();
        let statement = ReceiptLineageStatement::sign(
            ReceiptLineageStatementBody::new(
                "stmt-1",
                ReceiptLineageEndpoints::new(
                    "parent",
                    "other-child",
                    RequestId::new("parent-request"),
                    RequestId::new("child-request"),
                    SessionAnchorReference::new("parent-anchor", "parent-hash"),
                    SessionAnchorReference::new("child-anchor", "child-hash"),
                ),
                ReceiptLineageRelationKind::LocalChild,
                1,
                keypair.public_key(),
            ),
            &keypair,
        )?;
        let rows = vec![CorpusReceiptRow {
            receipt_id: "child".into(),
            parent_receipt_id: Some("parent".into()),
            capability_id: None,
            parent_capability_id: None,
            tool_name: None,
            tenant_id: None,
            recorded_at: None,
            signed_lineage_statement: Some(statement),
        }];
        let g = ingest_corpus(&rows)?;
        let edge = g
            .edges
            .iter()
            .find(|e| e.kind == EdgeKind::ReceiptLineageParent)
            .ok_or_else(|| std::io::Error::other("lineage edge present"))?;
        assert_eq!(edge.evidence_class, EvidenceClass::Observed);
        Ok(())
    }

    #[test]
    fn ingest_is_deterministic_and_idempotent() -> Result<(), CorpusIngestError> {
        let row = CorpusReceiptRow {
            receipt_id: "r1".into(),
            parent_receipt_id: None,
            capability_id: Some("cap.x".into()),
            parent_capability_id: Some("cap.root".into()),
            tool_name: Some("tool.run".into()),
            tenant_id: Some("t".into()),
            recorded_at: Some(1),
            signed_lineage_statement: None,
        };
        let rows = vec![row.clone(), row.clone(), row];
        let g = ingest_corpus(&rows)?;
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
        Ok(())
    }
}
