use super::super::*;
use super::support::*;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::CapabilitySnapshotProvenance;

fn signed_token(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 1_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_unwrap()
}

fn signed_snapshot(
    token: &CapabilityToken,
    federated_parent_capability_id: Option<String>,
) -> CapabilitySnapshot {
    CapabilitySnapshot {
        capability_id: token.id.clone(),
        subject_key: token.subject.to_hex(),
        issuer_key: token.issuer.to_hex(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        grants_json: serde_json::to_string(&token.scope).test_unwrap(),
        delegation_depth: 0,
        parent_capability_id: None,
        federated_parent_capability_id,
        provenance: CapabilitySnapshotProvenance::SignedToken,
        signed_capability: Some(token.clone()),
    }
}

fn synthetic_anchor(label: &str, federated_parent: Option<String>) -> CapabilitySnapshot {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    CapabilitySnapshot {
        capability_id: format!("fed-del-{}", sha256_hex(label.as_bytes())),
        subject_key: subject.public_key().to_hex(),
        issuer_key: issuer.public_key().to_hex(),
        issued_at: 100,
        expires_at: 1_000,
        grants_json: serde_json::to_string(&ChioScope::default()).test_unwrap(),
        delegation_depth: 0,
        parent_capability_id: None,
        federated_parent_capability_id: federated_parent,
        provenance: CapabilitySnapshotProvenance::SyntheticAnchor,
        signed_capability: None,
    }
}

fn share_import(share_id: &str, snapshot: CapabilitySnapshot) -> FederatedEvidenceShareImport {
    FederatedEvidenceShareImport {
        share_id: share_id.to_string(),
        manifest_hash: format!("manifest-{share_id}"),
        exported_at: 500,
        issuer: "remote".to_string(),
        partner: "local".to_string(),
        signer_public_key: snapshot.issuer_key.clone(),
        require_proofs: true,
        query_json: "{}".to_string(),
        tool_receipts: Vec::new(),
        capability_lineage: vec![snapshot],
    }
}

#[test]
fn federation_bridge_is_immutable_and_preserves_signed_parent() {
    let path = unique_db_path("federated-bridge-immutable");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer = Keypair::generate();
    let child = signed_token("bridge-child", &Keypair::generate(), &issuer);
    let parent = signed_token("bridge-parent", &Keypair::generate(), &issuer);
    let other_parent = signed_token("bridge-other-parent", &Keypair::generate(), &issuer);
    store.record_capability_snapshot(&child, None).test_unwrap();
    store
        .record_capability_snapshot(&parent, None)
        .test_unwrap();
    store
        .record_capability_snapshot(&other_parent, None)
        .test_unwrap();
    let cursor_before_bridge = store.max_lineage_seq().test_unwrap();

    store
        .record_federated_lineage_bridge(&child.id, &parent.id, None)
        .test_unwrap();
    store
        .record_federated_lineage_bridge(&child.id, &parent.id, None)
        .test_unwrap();
    assert!(store
        .record_federated_lineage_bridge(&child.id, &other_parent.id, None)
        .is_err());

    let child_snapshot = store
        .get_combined_lineage(&child.id)
        .test_unwrap()
        .test_expect("child lineage");
    assert!(child_snapshot.parent_capability_id.is_none());
    assert_eq!(
        child_snapshot.federated_parent_capability_id.as_deref(),
        Some(parent.id.as_str())
    );
    assert!(store.max_lineage_seq().test_unwrap() > cursor_before_bridge);
    let chain = store.get_combined_delegation_chain(&child.id).test_unwrap();
    assert_eq!(
        chain
            .iter()
            .map(|snapshot| snapshot.capability_id.as_str())
            .collect::<Vec<_>>(),
        vec![parent.id.as_str(), child.id.as_str()]
    );

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn combined_delegation_chain_rejects_partial_and_cyclic_federated_lineage() {
    let path = unique_db_path("federated-chain-integrity");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer = Keypair::generate();
    let missing_parent = signed_snapshot(
        &signed_token("missing-parent-child", &Keypair::generate(), &issuer),
        Some("missing-parent".to_string()),
    );
    store
        .import_federated_evidence_share(&share_import("missing-parent", missing_parent.clone()))
        .test_unwrap();
    assert!(matches!(
        store.get_combined_delegation_chain(&missing_parent.capability_id),
        Err(ReceiptStoreError::Conflict(message))
            if message.contains("missing parent")
    ));

    let first = synthetic_anchor("cycle-first", None);
    let second = synthetic_anchor("cycle-second", Some(first.capability_id.clone()));
    let mut first = first;
    first.federated_parent_capability_id = Some(second.capability_id.clone());
    let mut import = share_import("cycle", first.clone());
    import.capability_lineage.push(second);
    store.import_federated_evidence_share(&import).test_unwrap();
    assert!(matches!(
        store.get_combined_delegation_chain(&first.capability_id),
        Err(ReceiptStoreError::Conflict(message)) if message.contains("cycle")
    ));

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn federated_import_rejects_legacy_and_cross_share_divergence() {
    let path = unique_db_path("federated-cross-share-conflict");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer = Keypair::generate();
    let token = signed_token("shared-capability", &Keypair::generate(), &issuer);
    let snapshot = signed_snapshot(&token, None);

    let mut legacy = snapshot.clone();
    legacy.provenance = CapabilitySnapshotProvenance::LegacyProjection;
    legacy.signed_capability = None;
    assert!(store
        .import_federated_evidence_share(&share_import("legacy", legacy))
        .is_err());

    store
        .import_federated_evidence_share(&share_import("share-a", snapshot.clone()))
        .test_unwrap();
    store
        .import_federated_evidence_share(&share_import("share-b", snapshot.clone()))
        .test_unwrap();

    let divergent = signed_token("shared-capability", &Keypair::generate(), &issuer);
    assert!(store
        .import_federated_evidence_share(&share_import(
            "share-conflict",
            signed_snapshot(&divergent, None),
        ))
        .is_err());
    let connection = store.connection().test_unwrap();
    let shares: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM federated_evidence_shares",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(shares, 2);
    drop(connection);

    assert!(
        chio_kernel::ReceiptStore::get_capability_snapshot(&store, &token.id)
            .test_unwrap()
            .is_none()
    );
    let resolved = store
        .get_combined_lineage(&token.id)
        .test_unwrap()
        .test_expect("imported signed reporting lineage");
    assert_eq!(
        resolved.provenance,
        CapabilitySnapshotProvenance::SignedToken
    );
    assert_eq!(
        resolved
            .signed_capability
            .as_ref()
            .map(|token| token.id.as_str()),
        Some(token.id.as_str())
    );

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn federated_reimport_upgrades_only_the_matching_legacy_share_row() {
    let path = unique_db_path("federated-legacy-reimport");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let token = signed_token(
        "legacy-reimport-capability",
        &Keypair::generate(),
        &Keypair::generate(),
    );
    let snapshot = signed_snapshot(&token, None);
    for share_id in ["share-a", "share-b"] {
        store
            .import_federated_evidence_share(&share_import(share_id, snapshot.clone()))
            .test_unwrap();
    }
    store
        .connection()
        .test_unwrap()
        .execute(
            "UPDATE federated_share_capability_lineage \
             SET provenance = 'legacy_projection', signed_capability_json = NULL \
             WHERE capability_id = ?1",
            params![token.id],
        )
        .test_unwrap();

    store
        .import_federated_evidence_share(&share_import("share-a", snapshot))
        .test_unwrap();

    let connection = store.connection().test_unwrap();
    let share_a: (String, Option<String>) = connection
        .query_row(
            "SELECT provenance, signed_capability_json \
             FROM federated_share_capability_lineage \
             WHERE share_id = 'share-a' AND capability_id = ?1",
            params![token.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .test_unwrap();
    let share_b: (String, Option<String>) = connection
        .query_row(
            "SELECT provenance, signed_capability_json \
             FROM federated_share_capability_lineage \
             WHERE share_id = 'share-b' AND capability_id = ?1",
            params![token.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .test_unwrap();
    assert_eq!(share_a.0, "signed_token");
    assert!(share_a.1.is_some());
    assert_eq!(share_b, ("legacy_projection".to_string(), None));

    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn federated_row_decode_rejects_negative_synthetic_timestamp() {
    let path = unique_db_path("federated-negative-timestamp");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let anchor = synthetic_anchor("negative-timestamp", None);
    store
        .import_federated_evidence_share(&share_import("share-negative", anchor.clone()))
        .test_unwrap();
    store
        .connection()
        .test_unwrap()
        .execute(
            "UPDATE federated_share_capability_lineage SET issued_at = -1 \
             WHERE share_id = 'share-negative' AND capability_id = ?1",
            params![anchor.capability_id],
        )
        .test_unwrap();

    assert!(store
        .get_federated_share_for_capability(&anchor.capability_id)
        .is_err());

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn atomic_federated_lineage_is_idempotent_and_concurrent() {
    let path = unique_db_path("federated-lineage-concurrent");
    let store_a = SqliteReceiptStore::open(&path).test_unwrap();
    let store_b = SqliteReceiptStore::open(&path).test_unwrap();
    let anchor = synthetic_anchor("concurrent", None);
    let child_token = signed_token(
        "federated-child",
        &Keypair::generate(),
        &Keypair::generate(),
    );
    let child = signed_snapshot(&child_token, Some(anchor.capability_id.clone()));
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for mut store in [store_a, store_b] {
        let barrier = Arc::clone(&barrier);
        let anchor = anchor.clone();
        let child = child.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store.persist_federated_delegation_lineage(&anchor, None, &child)
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().test_unwrap().test_unwrap();
    }

    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .persist_federated_delegation_lineage(&anchor, None, &child)
        .test_unwrap();
    assert!(
        chio_kernel::ReceiptStore::get_capability_snapshot(&store, &anchor.capability_id)
            .test_unwrap()
            .is_none()
    );
    assert!(chio_kernel::ReceiptStore::get_capability_delegation_chain(
        &store,
        &anchor.capability_id
    )
    .test_unwrap()
    .is_empty());
    assert!(
        chio_kernel::ReceiptStore::get_capability_snapshot(&store, &child.capability_id)
            .test_unwrap()
            .is_some()
    );
    let chain = store
        .get_combined_delegation_chain(&child.capability_id)
        .test_unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].capability_id, anchor.capability_id);
    assert_eq!(chain[1].capability_id, child.capability_id);

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn atomic_federated_lineage_rolls_back_on_child_conflict() {
    let path = unique_db_path("federated-lineage-rollback");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let existing = signed_token(
        "conflicting-federated-child",
        &Keypair::generate(),
        &Keypair::generate(),
    );
    store
        .record_capability_snapshot(&existing, None)
        .test_unwrap();

    let anchor = synthetic_anchor("rollback", None);
    let incoming = signed_token(
        "conflicting-federated-child",
        &Keypair::generate(),
        &Keypair::generate(),
    );
    let child = signed_snapshot(&incoming, Some(anchor.capability_id.clone()));
    assert!(store
        .persist_federated_delegation_lineage(&anchor, None, &child)
        .is_err());
    assert!(store
        .get_combined_lineage(&anchor.capability_id)
        .test_unwrap()
        .is_none());
    let bridge_count: i64 = store
        .connection()
        .test_unwrap()
        .query_row(
            "SELECT COUNT(*) FROM federated_lineage_bridges WHERE local_capability_id = ?1",
            params![incoming.id],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(bridge_count, 0);

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn atomic_federated_lineage_rolls_back_on_sqlite_integer_overflow() {
    let path = unique_db_path("federated-lineage-overflow");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let anchor = synthetic_anchor("overflow", None);
    let issuer = Keypair::generate();
    let child_token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "overflow-federated-child".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope::default(),
            issued_at: i64::MAX as u64 + 1,
            expires_at: i64::MAX as u64 + 2,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .test_unwrap();
    let child = signed_snapshot(&child_token, Some(anchor.capability_id.clone()));

    assert!(store
        .persist_federated_delegation_lineage(&anchor, None, &child)
        .is_err());
    assert!(store
        .get_combined_lineage(&anchor.capability_id)
        .test_unwrap()
        .is_none());
    assert!(store
        .get_combined_lineage(&child.capability_id)
        .test_unwrap()
        .is_none());

    drop(store);
    let _ = fs::remove_file(path);
}
