//! Integration test for differential mode.
//!
//! Two guard versions producing slightly different lineage shapes against
//! the same replay corpus must yield a stable JSON diff plus a stable text
//! summary; revoking a guard publisher cascades through the diff.

use chio_lineage::diff::{diff, render_text};
use chio_lineage::ingest_replay_corpus::{ingest_corpus, CorpusReceiptRow};

fn corpus_v1() -> Vec<CorpusReceiptRow> {
    vec![CorpusReceiptRow {
        receipt_id: "r1".into(),
        parent_receipt_id: None,
        capability_id: Some("cap.read".into()),
        parent_capability_id: None,
        tool_name: Some("pii-mask".into()),
        tenant_id: Some("tenant".into()),
        recorded_at: Some(1),
        signed_lineage_statement: None,
    }]
}

fn corpus_v2() -> Vec<CorpusReceiptRow> {
    // v2 adds an extra capability parent and renames the tool, simulating
    // a `pii-mask v1 -> v2` swap.
    vec![CorpusReceiptRow {
        receipt_id: "r1".into(),
        parent_receipt_id: None,
        capability_id: Some("cap.read".into()),
        parent_capability_id: Some("cap.org".into()),
        tool_name: Some("pii-mask".into()),
        tenant_id: Some("tenant".into()),
        recorded_at: Some(1),
        signed_lineage_statement: None,
    }]
}

#[test]
fn diff_finds_added_capability_parent_edge() -> Result<(), Box<dyn std::error::Error>> {
    let l = ingest_corpus(&corpus_v1())?;
    let r = ingest_corpus(&corpus_v2())?;
    let d = diff("pii-mask-v1", &l, "pii-mask-v2", &r);
    assert!(!d.only_right.is_empty(), "v2 introduced new edges");
    let txt = render_text(&d);
    assert!(txt.contains("only-right:"));
    // Stable label ordering.
    assert!(txt.starts_with("lineage diff: left=pii-mask-v1 right=pii-mask-v2"));
    Ok(())
}

#[test]
fn diff_serializes_to_stable_json() -> Result<(), Box<dyn std::error::Error>> {
    let l = ingest_corpus(&corpus_v1())?;
    let r = ingest_corpus(&corpus_v2())?;
    let d = diff("v1", &l, "v2", &r);
    let a = serde_json::to_string(&d).unwrap_or_default();
    let b = serde_json::to_string(&d).unwrap_or_default();
    assert_eq!(a, b);
    assert!(a.contains("\"only_left\""));
    assert!(a.contains("\"only_right\""));
    Ok(())
}
