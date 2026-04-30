//! Integration test for M09 P5.T6 anchor pinning.

use chio_lineage::anchor::{frontier_digest, pin_frontier, CanonicalSource, SigningState};
use chio_lineage::ingest_replay_corpus::{ingest_corpus, CorpusReceiptRow};

fn fixture_graph() -> chio_lineage::schema::LineageGraph {
    ingest_corpus(&[CorpusReceiptRow {
        receipt_id: "r1".into(),
        parent_receipt_id: None,
        capability_id: Some("cap.read".into()),
        parent_capability_id: None,
        tool_name: Some("fs.read".into()),
        tenant_id: None,
        recorded_at: Some(1),
        has_signed_lineage_statement: true,
    }])
}

#[test]
fn deterministic_frontier_hash_through_canonical_bytes() {
    let g = fixture_graph();
    let a = frontier_digest(&g);
    let b = frontier_digest(&g);
    assert_eq!(a.hex, b.hex);
    assert_eq!(a.algo, "sha256");
}

#[test]
fn missing_m03_signer_records_unsigned_state_and_exits_cleanly() {
    let g = fixture_graph();
    let pinned = pin_frontier(&g, None);
    assert!(matches!(
        pinned.signing,
        SigningState::UnsignedSoftDepAbsent
    ));
    // Equivalence shim is the documented soft-dep fallback for M06.
    assert!(matches!(
        pinned.canonical_source,
        CanonicalSource::EquivalenceShim
    ));
    assert_eq!(pinned.node_count, g.nodes.len());
    assert_eq!(pinned.edge_count, g.edges.len());
}

#[test]
fn signer_hint_is_recorded_for_m10_consumption() {
    let g = fixture_graph();
    let pinned = pin_frontier(&g, Some("hybrid-ed25519-mldsa65"));
    if let SigningState::Signed { algorithm, .. } = pinned.signing {
        assert_eq!(algorithm, "hybrid-ed25519-mldsa65");
    } else {
        panic!("signer hint should produce Signed state");
    }
}
