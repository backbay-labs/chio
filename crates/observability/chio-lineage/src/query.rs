//! Lineage query layer.
//!
//! Forward queries walk downstream edges from a seed (capability +
//! optional tenant + time window) to receipt nodes. Reverse queries walk
//! upstream from a revoked credential or capability to every tool call
//! and receipt that transitively depended on it.
//!
//! The persistent backing is `chio-store-sqlite` via the `lineage` cargo
//! feature (see `crates/platform/chio-store-sqlite/src/lineage_cte.rs`); this module
//! provides the in-memory graph window used during a single query, with
//! depth and row caps that emit the canonical truncation marker on
//! overflow.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::schema::{LineageEdge, LineageGraph, LineageNode, NodeKind, TruncationMarker};

/// Default recursion depth bound. Matches the bound used by the
/// `capability_lineage::get_delegation_chain` recursive CTE so operators
/// reason about a single cap across the in-memory and SQLite query paths.
pub const DEFAULT_DEPTH_LIMIT: u32 = 20;

/// Query bounds.
#[derive(Debug, Clone, Copy)]
pub struct QueryBounds {
    pub depth_limit: u32,
    pub row_limit: u32,
}

impl Default for QueryBounds {
    fn default() -> Self {
        Self {
            depth_limit: DEFAULT_DEPTH_LIMIT,
            row_limit: 10_000,
        }
    }
}

/// Result of a graph query: a subgraph plus an optional truncation marker.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub graph: LineageGraph,
    pub truncated: Option<TruncationMarker>,
}

/// Forward query. Walk downstream edges starting from any node id in
/// `seeds`, returning the reachable subgraph bounded by `bounds`.
pub fn forward(graph: &LineageGraph, seeds: &[&str], bounds: QueryBounds) -> QueryResult {
    let adjacency = build_outgoing(&graph.edges);
    walk(graph, seeds, &adjacency, bounds)
}

/// Reverse query. Walk upstream edges (treating each edge as `to -> from`)
/// from `seeds`. Useful for "show every tool call whose capability
/// transitively depended on credential X revoked at T".
pub fn reverse(graph: &LineageGraph, seeds: &[&str], bounds: QueryBounds) -> QueryResult {
    let adjacency = build_incoming(&graph.edges);
    walk(graph, seeds, &adjacency, bounds)
}

/// Reverse-resolve governed memory writes that depend on one verified Finding
/// delivery receipt. Only the typed M6 relation participates, so an unrelated
/// generic receipt parent cannot be promoted into Finding provenance.
pub fn finding_memory_dependents(
    graph: &LineageGraph,
    delivery_receipt_id: &str,
    bounds: QueryBounds,
) -> QueryResult {
    let edges: Vec<LineageEdge> = graph
        .edges
        .iter()
        .filter(|edge| {
            edge.kind == crate::schema::EdgeKind::FindingMemoryWriteToDelivery
                && edge.evidence_class == crate::schema::EvidenceClass::Verified
        })
        .cloned()
        .collect();
    let typed = LineageGraph {
        schema_version: graph.schema_version.clone(),
        nodes: graph.nodes.clone(),
        edges,
        truncated: None,
    };
    reverse(&typed, &[delivery_receipt_id], bounds)
}

fn build_outgoing(edges: &[LineageEdge]) -> HashMap<String, Vec<usize>> {
    let mut adj: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in edges.iter().enumerate() {
        adj.entry(e.from.clone()).or_default().push(i);
    }
    adj
}

fn build_incoming(edges: &[LineageEdge]) -> HashMap<String, Vec<usize>> {
    let mut adj: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in edges.iter().enumerate() {
        adj.entry(e.to.clone()).or_default().push(i);
    }
    adj
}

fn walk(
    graph: &LineageGraph,
    seeds: &[&str],
    adjacency: &HashMap<String, Vec<usize>>,
    bounds: QueryBounds,
) -> QueryResult {
    let node_index: HashMap<&str, &LineageNode> =
        graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<(String, u32)> = VecDeque::new();
    for seed in seeds {
        if node_index.contains_key(*seed) {
            frontier.push_back(((*seed).to_string(), 0));
        }
    }

    let mut out_nodes: Vec<LineageNode> = Vec::new();
    let mut out_edges: Vec<LineageEdge> = Vec::new();
    let mut deepest: u32 = 0;
    let mut truncated_depth = false;
    let mut truncated_rows = false;

    while let Some((node_id, depth)) = frontier.pop_front() {
        if !visited.insert(node_id.clone()) {
            continue;
        }
        deepest = deepest.max(depth);
        if let Some(n) = node_index.get(node_id.as_str()) {
            out_nodes.push((*n).clone());
        }
        if out_nodes.len() as u32 >= bounds.row_limit {
            truncated_rows = true;
            break;
        }
        if depth >= bounds.depth_limit {
            truncated_depth = true;
            continue;
        }
        let next_depth = depth.saturating_add(1);
        if let Some(idxs) = adjacency.get(&node_id) {
            for idx in idxs {
                let edge = &graph.edges[*idx];
                out_edges.push(edge.clone());
                let next = if edge.from == node_id {
                    &edge.to
                } else {
                    &edge.from
                };
                if !visited.contains(next) {
                    frontier.push_back((next.clone(), next_depth));
                }
            }
        }
    }

    let mut result = LineageGraph {
        schema_version: graph.schema_version.clone(),
        nodes: out_nodes,
        edges: out_edges,
        truncated: None,
    };
    let marker = if truncated_depth || truncated_rows {
        let limit = if truncated_rows {
            bounds.row_limit
        } else {
            bounds.depth_limit
        };
        let marker = TruncationMarker::at_depth(deepest, limit);
        result.truncated = Some(marker);
        Some(marker)
    } else {
        None
    };
    QueryResult {
        graph: result,
        truncated: marker,
    }
}

/// Filter helper: receipts only.
pub fn receipt_nodes(graph: &LineageGraph) -> Vec<&LineageNode> {
    graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Receipt)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EdgeKind, EvidenceClass, NodeKind};

    fn graph() -> LineageGraph {
        let mut g = LineageGraph::empty();
        for id in ["cap:x", "tool:t1", "rcpt:r1", "rcpt:r2"] {
            let kind = if id.starts_with("cap:") {
                NodeKind::Capability
            } else if id.starts_with("tool:") {
                NodeKind::ToolCall
            } else {
                NodeKind::Receipt
            };
            g.nodes.push(LineageNode {
                id: id.into(),
                kind,
                evidence_class: EvidenceClass::Observed,
                tenant_id: None,
                recorded_at: None,
                label: None,
                source_table: None,
                source_id: None,
            });
        }
        let mk_edge = |from: &str, to: &str, k: EdgeKind| LineageEdge {
            from: from.into(),
            to: to.into(),
            kind: k,
            evidence_class: EvidenceClass::Observed,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        };
        g.edges
            .push(mk_edge("cap:x", "tool:t1", EdgeKind::CapabilityToGuard));
        g.edges
            .push(mk_edge("tool:t1", "rcpt:r1", EdgeKind::ToolCallToReceipt));
        g.edges.push(mk_edge(
            "rcpt:r1",
            "rcpt:r2",
            EdgeKind::ReceiptLineageParent,
        ));
        g
    }

    #[test]
    fn forward_from_capability_reaches_receipts() {
        let g = graph();
        let res = forward(&g, &["cap:x"], QueryBounds::default());
        let receipts: Vec<_> = res
            .graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Receipt)
            .collect();
        assert_eq!(receipts.len(), 2);
        assert!(res.truncated.is_none());
    }

    #[test]
    fn reverse_from_receipt_reaches_capability() {
        let g = graph();
        let res = reverse(&g, &["rcpt:r2"], QueryBounds::default());
        let caps: Vec<_> = res
            .graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Capability)
            .collect();
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn finding_delivery_reverse_query_returns_only_typed_memory_dependents() {
        let mut g = LineageGraph::empty();
        for id in [
            "rcpt:delivery",
            "rcpt:memory",
            "rcpt:generic",
            "rcpt:asserted-memory",
        ] {
            g.nodes.push(LineageNode {
                id: id.to_owned(),
                kind: NodeKind::Receipt,
                evidence_class: EvidenceClass::Verified,
                tenant_id: None,
                recorded_at: None,
                label: None,
                source_table: None,
                source_id: None,
            });
        }
        g.edges.push(LineageEdge {
            from: "rcpt:memory".to_owned(),
            to: "rcpt:delivery".to_owned(),
            kind: EdgeKind::FindingMemoryWriteToDelivery,
            evidence_class: EvidenceClass::Verified,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        });
        g.edges.push(LineageEdge {
            from: "rcpt:asserted-memory".to_owned(),
            to: "rcpt:delivery".to_owned(),
            kind: EdgeKind::FindingMemoryWriteToDelivery,
            evidence_class: EvidenceClass::Asserted,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        });
        g.edges.push(LineageEdge {
            from: "rcpt:generic".to_owned(),
            to: "rcpt:delivery".to_owned(),
            kind: EdgeKind::ReceiptLineageParent,
            evidence_class: EvidenceClass::Verified,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        });

        let result = finding_memory_dependents(
            &g,
            "rcpt:delivery",
            QueryBounds {
                depth_limit: 4,
                row_limit: 10,
            },
        );
        let ids: HashSet<_> = result
            .graph
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect();
        assert!(ids.contains("rcpt:delivery"));
        assert!(ids.contains("rcpt:memory"));
        assert!(!ids.contains("rcpt:generic"));
        assert!(!ids.contains("rcpt:asserted-memory"));
        assert!(result.truncated.is_none());
    }

    #[test]
    fn depth_bound_emits_truncation_marker() {
        let g = graph();
        let bounds = QueryBounds {
            depth_limit: 1,
            row_limit: 10_000,
        };
        let res = forward(&g, &["cap:x"], bounds);
        assert!(res.truncated.is_some());
        if let Some(m) = res.truncated {
            assert!(m.truncated);
            assert_eq!(m.limit, 1);
        }
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        let mut g = graph();
        g.edges.push(LineageEdge {
            from: "rcpt:r2".into(),
            to: "cap:x".into(),
            kind: EdgeKind::ReceiptLineageParent,
            evidence_class: EvidenceClass::Observed,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        });
        let res = forward(&g, &["cap:x"], QueryBounds::default());
        // Cycle should not blow up; we still see all 4 nodes.
        assert!(res.graph.nodes.len() >= 3);
    }
}
