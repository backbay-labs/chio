//! Differential mode.
//!
//! Compare lineage graphs across two guard versions (typically derived
//! from running the same deterministic replay corpus through two guard
//! manifests). The diff is the symmetric difference of edges keyed by
//! `(from, to, kind)`, plus an evidence-class summary so downstream
//! reviewers can see when an edge was upgraded or downgraded across
//! versions.
//!
//! Output is stable: ordering is by `(from, to, kind)` text comparison
//! so JSON dumps and text summaries are byte-stable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::schema::{EdgeKind, EvidenceClass, LineageEdge, LineageGraph};

/// One side of a symmetric edge diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub evidence_class: EvidenceClass,
}

impl From<&LineageEdge> for DiffEdge {
    fn from(e: &LineageEdge) -> Self {
        Self {
            from: e.from.clone(),
            to: e.to.clone(),
            kind: e.kind,
            evidence_class: e.evidence_class,
        }
    }
}

/// Symmetric diff of two lineage graphs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageDiff {
    pub left_label: String,
    pub right_label: String,
    /// Edges present only on the left side.
    pub only_left: Vec<DiffEdge>,
    /// Edges present only on the right side.
    pub only_right: Vec<DiffEdge>,
    /// Edges present on both sides but with a changed evidence class.
    pub evidence_changed: Vec<EvidenceChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceChange {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub left: EvidenceClass,
    pub right: EvidenceClass,
}

fn edge_key(e: &LineageEdge) -> (String, String, EdgeKind) {
    (e.from.clone(), e.to.clone(), e.kind)
}

/// Compute the symmetric edge diff between two lineage graphs.
pub fn diff(
    left_label: impl Into<String>,
    left: &LineageGraph,
    right_label: impl Into<String>,
    right: &LineageGraph,
) -> LineageDiff {
    let left_map: BTreeMap<_, _> = left.edges.iter().map(|e| (edge_key(e), e)).collect();
    let right_map: BTreeMap<_, _> = right.edges.iter().map(|e| (edge_key(e), e)).collect();

    let mut only_left = Vec::new();
    let mut only_right = Vec::new();
    let mut evidence_changed = Vec::new();

    for (key, edge) in &left_map {
        match right_map.get(key) {
            None => only_left.push(DiffEdge::from(*edge)),
            Some(right_edge) if right_edge.evidence_class != edge.evidence_class => {
                evidence_changed.push(EvidenceChange {
                    from: edge.from.clone(),
                    to: edge.to.clone(),
                    kind: edge.kind,
                    left: edge.evidence_class,
                    right: right_edge.evidence_class,
                });
            }
            _ => {}
        }
    }
    for (key, edge) in &right_map {
        if !left_map.contains_key(key) {
            only_right.push(DiffEdge::from(*edge));
        }
    }

    only_left.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    only_right.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    evidence_changed.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));

    LineageDiff {
        left_label: left_label.into(),
        right_label: right_label.into(),
        only_left,
        only_right,
        evidence_changed,
    }
}

/// Render the diff as a stable Cypher-ish text summary.
pub fn render_text(diff: &LineageDiff) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "lineage diff: left={} right={}\n",
        diff.left_label, diff.right_label
    ));
    out.push_str(&format!("only-left: {}\n", diff.only_left.len()));
    for e in &diff.only_left {
        out.push_str(&format!("  - ({})-[{:?}]->({})\n", e.from, e.kind, e.to));
    }
    out.push_str(&format!("only-right: {}\n", diff.only_right.len()));
    for e in &diff.only_right {
        out.push_str(&format!("  + ({})-[{:?}]->({})\n", e.from, e.kind, e.to));
    }
    out.push_str(&format!(
        "evidence-changed: {}\n",
        diff.evidence_changed.len()
    ));
    for c in &diff.evidence_changed {
        out.push_str(&format!(
            "  ~ ({})-[{:?}]->({}) {:?} -> {:?}\n",
            c.from, c.kind, c.to, c.left, c.right
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{LineageNode, NodeKind};

    fn n(id: &str) -> LineageNode {
        LineageNode {
            id: id.into(),
            kind: NodeKind::Receipt,
            evidence_class: EvidenceClass::Observed,
            tenant_id: None,
            recorded_at: None,
            label: None,
            source_table: None,
            source_id: None,
        }
    }

    fn e(from: &str, to: &str, ev: EvidenceClass) -> LineageEdge {
        LineageEdge {
            from: from.into(),
            to: to.into(),
            kind: EdgeKind::ToolCallToReceipt,
            evidence_class: ev,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        }
    }

    #[test]
    fn empty_graphs_have_empty_diff() {
        let l = LineageGraph::empty();
        let r = LineageGraph::empty();
        let d = diff("v1", &l, "v2", &r);
        assert!(d.only_left.is_empty());
        assert!(d.only_right.is_empty());
    }

    #[test]
    fn finds_only_left_only_right_and_evidence_change() {
        let mut l = LineageGraph::empty();
        l.nodes.push(n("a"));
        l.nodes.push(n("b"));
        l.edges.push(e("a", "b", EvidenceClass::Observed));
        l.edges.push(e("a", "c", EvidenceClass::Asserted));
        let mut r = LineageGraph::empty();
        r.nodes.push(n("a"));
        r.nodes.push(n("b"));
        r.edges.push(e("a", "b", EvidenceClass::Verified));
        r.edges.push(e("a", "d", EvidenceClass::Observed));

        let d = diff("v1", &l, "v2", &r);
        assert_eq!(d.only_left.len(), 1);
        assert_eq!(d.only_right.len(), 1);
        assert_eq!(d.evidence_changed.len(), 1);
        assert_eq!(d.evidence_changed[0].left, EvidenceClass::Observed);
        assert_eq!(d.evidence_changed[0].right, EvidenceClass::Verified);
    }

    #[test]
    fn diff_is_stable_serialization() {
        let mut l = LineageGraph::empty();
        l.edges.push(e("z", "y", EvidenceClass::Observed));
        l.edges.push(e("a", "b", EvidenceClass::Observed));
        let r = LineageGraph::empty();
        let d = diff("v1", &l, "v2", &r);
        // Sorted: a-b before z-y.
        assert_eq!(d.only_left[0].from, "a");
        assert_eq!(d.only_left[1].from, "z");
        let txt = render_text(&d);
        assert!(txt.contains("only-left: 2"));
    }
}
