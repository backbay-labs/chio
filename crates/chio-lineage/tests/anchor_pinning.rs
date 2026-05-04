//! Integration test for M09 P5.T6 anchor pinning.

use chio_lineage::anchor::{
    frontier_digest, pin_frontier, pin_frontier_signed, CanonicalSource, SigningState,
};
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
fn signer_hint_without_signature_is_unsigned_stub() {
    // A signer hint without an actual signature payload must NOT promote
    // the artifact to `Signed`. Verifiers checking `is_signed()` would
    // otherwise be tricked into trusting an unsigned anchor (lineage
    // tamper, fail-closed contract).
    let g = fixture_graph();
    let pinned = pin_frontier(&g, Some("hybrid-ed25519-mldsa65"));
    if let SigningState::UnsignedSignerStubbed { algorithm } = &pinned.signing {
        assert_eq!(algorithm, "hybrid-ed25519-mldsa65");
    } else {
        panic!("signer hint without signature should produce UnsignedSignerStubbed state");
    }
    assert!(!pinned.is_signed());
}

#[test]
fn pin_frontier_signed_with_real_payload_is_signed() {
    let g = fixture_graph();
    let pinned = pin_frontier_signed(&g, "hybrid-ed25519-mldsa65", "deadbeef")
        .unwrap_or_else(|_| panic!("signed pin should succeed with valid payload"));
    if let SigningState::Signed {
        algorithm,
        signature_hex,
    } = &pinned.signing
    {
        assert_eq!(algorithm, "hybrid-ed25519-mldsa65");
        assert_eq!(signature_hex, "deadbeef");
    } else {
        panic!("real payload should produce Signed state");
    }
    assert!(pinned.is_signed());
}
