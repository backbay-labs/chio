//! Integration test for anchor pinning.

use chio_core_types::crypto::Keypair;
use chio_lineage::anchor::{
    frontier_digest, frontier_signature_message, pin_frontier, pin_frontier_signed,
    verify_frontier_signature, CanonicalSource, SigningState,
};
use chio_lineage::ingest_replay_corpus::{ingest_corpus, CorpusIngestError, CorpusReceiptRow};

fn fixture_graph() -> Result<chio_lineage::schema::LineageGraph, CorpusIngestError> {
    ingest_corpus(&[CorpusReceiptRow {
        receipt_id: "r1".into(),
        parent_receipt_id: None,
        capability_id: Some("cap.read".into()),
        parent_capability_id: None,
        tool_name: Some("fs.read".into()),
        tenant_id: None,
        recorded_at: Some(1),
        signed_lineage_statement: None,
    }])
}

#[test]
fn deterministic_frontier_hash_through_canonical_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let g = fixture_graph()?;
    let a = frontier_digest(&g);
    let b = frontier_digest(&g);
    assert_eq!(a.hex, b.hex);
    assert_eq!(a.algo, "sha256");
    Ok(())
}

#[test]
fn missing_hybrid_signer_records_unsigned_state_and_exits_cleanly(
) -> Result<(), Box<dyn std::error::Error>> {
    let g = fixture_graph()?;
    let pinned = pin_frontier(&g, None);
    assert!(matches!(
        pinned.signing,
        SigningState::UnsignedSoftDepAbsent
    ));
    // Equivalence shim is the documented soft-dep fallback for canonical bytes.
    assert!(matches!(
        pinned.canonical_source,
        CanonicalSource::EquivalenceShim
    ));
    assert_eq!(pinned.node_count, g.nodes.len());
    assert_eq!(pinned.edge_count, g.edges.len());
    Ok(())
}

#[test]
fn signer_hint_without_signature_is_unsigned_stub() -> Result<(), Box<dyn std::error::Error>> {
    // A signer hint without an actual signature payload must NOT promote
    // the artifact to `Signed`. Verifiers checking `is_signed()` would
    // otherwise be tricked into trusting an unsigned anchor (lineage
    // tamper, fail-closed contract).
    let g = fixture_graph()?;
    let pinned = pin_frontier(&g, Some("hybrid-ed25519-mldsa65"));
    if let SigningState::UnsignedSignerStubbed { algorithm } = &pinned.signing {
        assert_eq!(algorithm, "hybrid-ed25519-mldsa65");
    } else {
        panic!("signer hint without signature should produce UnsignedSignerStubbed state");
    }
    assert!(!pinned.is_signed());
    Ok(())
}

#[test]
fn pin_frontier_signed_with_unverified_payload_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let g = fixture_graph()?;
    let keypair = Keypair::from_seed(&[7_u8; 32]);
    let err = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), "deadbeef")
        .err()
        .unwrap_or_else(|| panic!("unverified payload must fail closed"));
    assert!(format!("{err}").contains("signature payload is invalid"));
    Ok(())
}

#[test]
fn pin_frontier_signed_verifies_with_trusted_key() -> Result<(), Box<dyn std::error::Error>> {
    let g = fixture_graph()?;
    let keypair = Keypair::from_seed(&[7_u8; 32]);
    let signature = keypair.sign(&frontier_signature_message(&g));
    let pinned = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), &signature.to_hex())
        .unwrap_or_else(|error| panic!("signed pin should verify: {error}"));

    assert!(!pinned.is_signed());
    assert!(pinned.is_signed_by(&g, &keypair.public_key()));
    assert!(verify_frontier_signature(&pinned, &g, &keypair.public_key()).is_ok());
    Ok(())
}
