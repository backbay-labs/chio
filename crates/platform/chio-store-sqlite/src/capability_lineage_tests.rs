use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel::CapabilitySnapshotProvenance;
use rusqlite::{params, Connection};

use crate::receipt_store::SqliteReceiptStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

/// Build a test CapabilityToken with the given ID and subject/issuer keypairs.
fn make_token(
    id: &str,
    subject_kp: &Keypair,
    issuer_kp: &Keypair,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "shell".to_string(),
                tool_name: "bash".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at,
        expires_at,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer_kp).expect("sign failed")
}

fn make_delegated_token(
    id: &str,
    subject_kp: &Keypair,
    delegator_kp: &Keypair,
    parent: &CapabilityToken,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let mut body = make_token(id, subject_kp, delegator_kp, issued_at, expires_at).body();
    body.delegation_chain = parent.delegation_chain.clone();
    body.delegation_chain.push(
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: delegator_kp.public_key(),
                delegatee: subject_kp.public_key(),
                attenuations: Vec::new(),
                timestamp: issued_at,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            delegator_kp,
        )
        .expect("sign delegation link"),
    );
    CapabilityToken::sign(body, delegator_kp).expect("sign delegated capability")
}

#[test]
fn record_and_get_lineage_returns_matching_fields() {
    let path = unique_db_path("cl-persist");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let token = make_token("cap-001", &subject_kp, &issuer_kp, 1000, 2000);

    store.record_capability_snapshot(&token, None).unwrap();

    let snap = store.get_lineage("cap-001").unwrap().unwrap();
    assert_eq!(snap.capability_id, "cap-001");
    assert_eq!(snap.subject_key, subject_kp.public_key().to_hex());
    assert_eq!(snap.issuer_key, issuer_kp.public_key().to_hex());
    assert_eq!(snap.issued_at, 1000);
    assert_eq!(snap.expires_at, 2000);
    assert_eq!(snap.delegation_depth, 0);
    assert!(snap.parent_capability_id.is_none());

    let _ = fs::remove_file(path);
}

#[test]
fn delegated_bounded_snapshot_reads_parent_depth_inside_the_writer_job() {
    // The parent-depth lookup for a delegated capability must run on the
    // writer connection inside the bounded job, not on a reader-pool
    // connection ahead of it. With every reader-pool connection checked
    // out, a delegated bounded snapshot must still resolve the parent depth
    // and persist quickly, proving the read no longer sits unbounded on the
    // pre-dispatch hot path where an exhausted pool would stall it.
    let path = unique_db_path("cl-bounded-parent-read");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let kp_root = Keypair::generate();
    let kp_child = Keypair::generate();
    let root = make_token("cap-root-bounded", &kp_root, &kp_root, 1000, 9000);
    let child = make_delegated_token("cap-child-bounded", &kp_child, &kp_root, &root, 1100, 8000);

    store.record_capability_snapshot(&root, None).unwrap();

    // Exhaust the reader pool: hold every reader connection so any
    // reader-pool checkout on the hot path would block.
    let mut held = Vec::new();
    for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
        held.push(store.connection().unwrap());
    }

    let start = std::time::Instant::now();
    store
        .record_capability_snapshot_with_timeout(
            &child,
            Some("cap-root-bounded"),
            std::time::Duration::from_millis(500),
        )
        .unwrap();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "delegated bounded snapshot must not wait on the exhausted reader pool"
    );

    // Release the reader pool so the read-back can observe the persisted row.
    drop(held);

    let snap = store.get_lineage("cap-child-bounded").unwrap().unwrap();
    assert_eq!(
        snap.delegation_depth, 1,
        "child depth must be resolved from the parent inside the bounded job"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn record_capability_snapshot_is_idempotent() {
    let path = unique_db_path("cl-idempotent");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let token = make_token("cap-idem-001", &subject_kp, &issuer_kp, 1000, 2000);

    // Insert twice -- must not panic or error.
    store.record_capability_snapshot(&token, None).unwrap();
    store.record_capability_snapshot(&token, None).unwrap();

    // Only one row should exist.
    let connection = store.connection().unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM capability_lineage WHERE capability_id = ?1",
            params!["cap-idem-001"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    let _ = fs::remove_file(path);
}

#[test]
fn grants_json_round_trips_without_field_loss() {
    let path = unique_db_path("cl-json-rt");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let token = make_token("cap-json-001", &subject_kp, &issuer_kp, 1000, 2000);

    store.record_capability_snapshot(&token, None).unwrap();

    let snap = store.get_lineage("cap-json-001").unwrap().unwrap();
    let round_tripped: ChioScope = serde_json::from_str(&snap.grants_json).unwrap();

    assert_eq!(round_tripped.grants.len(), token.scope.grants.len());
    assert_eq!(round_tripped.grants[0].server_id, "shell");
    assert_eq!(round_tripped.grants[0].tool_name, "bash");

    let _ = fs::remove_file(path);
}

#[test]
fn signed_capability_round_trips_through_replication() -> Result<(), Box<dyn std::error::Error>> {
    let source_path = unique_db_path("cl-signed-source");
    let destination_path = unique_db_path("cl-signed-destination");
    let source = SqliteReceiptStore::open(&source_path)?;
    let mut destination = SqliteReceiptStore::open(&destination_path)?;
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let token = make_token("cap-signed", &subject, &issuer, 1000, 2000);

    source.record_capability_snapshot(&token, None)?;
    let stored = source
        .list_capability_snapshots_after_seq(0, 1)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other("signed snapshot missing"))?;
    let persisted = stored
        .snapshot
        .signed_capability
        .as_ref()
        .ok_or_else(|| std::io::Error::other("signed token missing"))?;
    assert_eq!(persisted.id, token.id);
    assert_eq!(persisted.signature.to_hex(), token.signature.to_hex());

    destination.upsert_capability_snapshot(&stored.snapshot)?;
    let replicated = destination
        .get_lineage(&token.id)?
        .ok_or_else(|| std::io::Error::other("replicated snapshot missing"))?;
    assert_eq!(
        replicated
            .signed_capability
            .as_ref()
            .map(|capability| capability.signature.to_hex()),
        Some(token.signature.to_hex())
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(destination_path);
    Ok(())
}

#[test]
fn lineage_delta_rejects_cursor_and_limit_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("cl-delta-overflow");
    let store = SqliteReceiptStore::open(&path)?;

    assert!(store
        .list_capability_snapshots_after_seq(u64::MAX, 1)
        .is_err());
    if usize::BITS > 63 {
        assert!(store
            .list_capability_snapshots_after_seq(0, usize::MAX)
            .is_err());
    }

    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn signed_capability_upgrade_advances_replication_cursor() -> Result<(), Box<dyn std::error::Error>>
{
    let source_path = unique_db_path("cl-signed-upgrade-source");
    let destination_path = unique_db_path("cl-signed-upgrade-destination");
    let source = SqliteReceiptStore::open(&source_path)?;
    let mut destination = SqliteReceiptStore::open(&destination_path)?;
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let token = make_token("cap-signed-upgrade", &subject, &issuer, 1000, 2000);

    source.record_capability_snapshot(&token, None)?;
    source.writer_handle().run_write({
        let capability_id = token.id.clone();
        move |connection| {
            connection.execute(
                "UPDATE capability_lineage \
                     SET signed_capability_json = NULL, provenance = 'legacy_projection' \
                     WHERE capability_id = ?1",
                params![capability_id],
            )?;
            Ok(())
        }
    })?;
    let unsigned_seq: u64 = source.connection()?.query_row(
        "SELECT rowid FROM capability_lineage WHERE capability_id = ?1",
        params![token.id],
        |row| row.get::<_, i64>(0).map(|seq| seq.max(0) as u64),
    )?;
    assert!(source.list_capability_snapshots_after_seq(0, 1).is_err());

    source.record_capability_snapshot(&token, None)?;
    let delta = source.list_capability_snapshots_after_seq(unsigned_seq, 10)?;
    assert_eq!(delta.len(), 1);
    assert!(delta[0].seq > unsigned_seq);
    assert!(delta[0].snapshot.signed_capability.is_some());
    assert_eq!(source.max_lineage_seq()?, delta[0].seq);

    destination.upsert_capability_snapshot(&delta[0].snapshot)?;
    assert!(destination
        .get_lineage(&token.id)?
        .and_then(|snapshot| snapshot.signed_capability)
        .is_some());

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(destination_path);
    Ok(())
}

#[test]
fn reopen_does_not_normalize_synthetic_anchor_with_signed_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("cl-corrupt-synthetic-signed");
    let store = SqliteReceiptStore::open(&path)?;
    let token = make_token(
        "cap-corrupt-synthetic",
        &Keypair::generate(),
        &Keypair::generate(),
        1_000,
        2_000,
    );
    store.record_capability_snapshot(&token, None)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE capability_lineage SET provenance = 'synthetic_anchor' WHERE capability_id = ?1",
        params![token.id],
    )?;
    drop(connection);

    let reopened = SqliteReceiptStore::open(&path)?;
    assert!(reopened.get_lineage(&token.id).is_err());
    let provenance: String = reopened.connection()?.query_row(
        "SELECT provenance FROM capability_lineage WHERE capability_id = ?1",
        params![token.id],
        |row| row.get(0),
    )?;
    assert_eq!(provenance, "synthetic_anchor");

    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn legacy_null_signed_capability_migrates_without_reconstruction(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("cl-signed-legacy");
    let store = SqliteReceiptStore::open(&path)?;
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let token = make_token("cap-legacy", &subject, &issuer, 1000, 2000);
    store.record_capability_snapshot(&token, None)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute("DROP INDEX idx_capability_lineage_federated_parent", [])?;
    for table in ["capability_lineage", "federated_share_capability_lineage"] {
        for column in [
            "provenance",
            "federated_parent_capability_id",
            "signed_capability_json",
        ] {
            connection.execute(&format!("ALTER TABLE {table} DROP COLUMN {column}"), [])?;
        }
    }
    crate::stamp_schema_version(&connection, "receipt", 0)?;
    drop(connection);

    let migrated = SqliteReceiptStore::open(&path)?;
    let snapshot = migrated
        .get_lineage(&token.id)?
        .ok_or_else(|| std::io::Error::other("migrated snapshot missing"))?;
    assert!(snapshot.signed_capability.is_none());
    assert_eq!(
        snapshot.provenance,
        CapabilitySnapshotProvenance::LegacyProjection
    );
    assert!(chio_kernel::ReceiptStore::get_capability_snapshot(&migrated, &token.id)?.is_none());
    assert!(
        chio_kernel::ReceiptStore::get_capability_delegation_chain(&migrated, &token.id)?
            .is_empty()
    );
    let signed_json: Option<String> = migrated.connection()?.query_row(
        "SELECT signed_capability_json FROM capability_lineage WHERE capability_id = ?1",
        params![token.id],
        |row| row.get(0),
    )?;
    assert!(signed_json.is_none());

    migrated.record_capability_snapshot(&token, None)?;
    let upgraded = migrated
        .get_lineage(&token.id)?
        .ok_or_else(|| std::io::Error::other("upgraded snapshot missing"))?;
    assert!(upgraded.signed_capability.is_some());
    assert_eq!(
        upgraded.provenance,
        CapabilitySnapshotProvenance::SignedToken
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn record_rechecks_conflicts_after_waiting_for_an_external_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("cl-cross-process-conflict");
    let waiting_store = SqliteReceiptStore::open(&path)?;
    let observer = SqliteReceiptStore::open(&path)?;
    let issuer = Keypair::generate();
    let incoming_subject = Keypair::generate();
    let persisted_subject = Keypair::generate();
    let incoming = make_token("cap-race", &incoming_subject, &issuer, 1000, 2000);
    let persisted = make_token("cap-race", &persisted_subject, &issuer, 1000, 2000);

    let mut external = Connection::open(&path)?;
    let transaction =
        external.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let started = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_started = std::sync::Arc::clone(&started);
    let write = std::thread::spawn(move || {
        writer_started.wait();
        waiting_store.record_capability_snapshot(&incoming, None)
    });
    started.wait();
    std::thread::sleep(std::time::Duration::from_millis(100));

    transaction.execute(
        r#"
            INSERT INTO capability_lineage (
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id,
                provenance,
                signed_capability_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, 'signed_token', ?7)
            "#,
        params![
            persisted.id,
            persisted.subject.to_hex(),
            persisted.issuer.to_hex(),
            persisted.issued_at as i64,
            persisted.expires_at as i64,
            serde_json::to_string(&persisted.scope)?,
            serde_json::to_string(&persisted)?,
        ],
    )?;
    transaction.commit()?;

    let result = write
        .join()
        .map_err(|_| std::io::Error::other("lineage writer panicked"))?;
    assert!(result.is_err());
    let snapshot = observer
        .get_lineage("cap-race")?
        .ok_or_else(|| std::io::Error::other("persisted winner missing"))?;
    assert_eq!(
        snapshot.subject_key,
        persisted_subject.public_key().to_hex()
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn replication_rejects_signed_capability_downgrade_conflict_and_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("cl-signed-conflicts");
    let mut store = SqliteReceiptStore::open(&path)?;
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let token = make_token("cap-conflict", &subject, &issuer, 1000, 2000);
    store.record_capability_snapshot(&token, None)?;
    let persisted = store
        .get_lineage(&token.id)?
        .ok_or_else(|| std::io::Error::other("persisted snapshot missing"))?;

    let mut downgrade = persisted.clone();
    downgrade.signed_capability = None;
    assert!(store.upsert_capability_snapshot(&downgrade).is_err());

    let mut conflicting_body = token.body();
    conflicting_body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 2,
        root_binding: None,
    });
    let conflicting_token = CapabilityToken::sign(conflicting_body, &issuer)?;
    let mut conflicting = persisted.clone();
    conflicting.signed_capability = Some(conflicting_token);
    assert!(store.upsert_capability_snapshot(&conflicting).is_err());

    let mut mismatched = persisted;
    mismatched.expires_at = mismatched.expires_at.saturating_add(1);
    assert!(store.upsert_capability_snapshot(&mismatched).is_err());
    let unchanged = store
        .get_lineage(&token.id)?
        .ok_or_else(|| std::io::Error::other("snapshot removed after conflict"))?;
    assert_eq!(unchanged.expires_at, token.expires_at);
    assert!(unchanged.signed_capability.is_some());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn record_rejects_parent_that_disagrees_with_signed_token() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("cl-signed-parent-mismatch");
    let store = SqliteReceiptStore::open(&path)?;
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let token = make_token("cap-direct", &subject, &issuer, 1000, 2000);

    assert!(store
        .record_capability_snapshot(&token, Some("unexpected-parent"))
        .is_err());
    assert!(store.get_lineage(&token.id)?.is_none());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn get_lineage_returns_none_for_missing_capability() {
    let path = unique_db_path("cl-missing");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let result = store.get_lineage("nonexistent-cap").unwrap();
    assert!(result.is_none());

    let _ = fs::remove_file(path);
}

#[test]
fn get_lineage_rejects_negative_persisted_unsigned_fields() {
    let path = unique_db_path("cl-corrupt-read");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let connection = store.connection().unwrap();
    connection
        .execute(
            r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
            params![
                "cap-corrupt-read",
                "subject",
                "issuer",
                -1_i64,
                2_000_i64,
                "{}",
                0_i64
            ],
        )
        .unwrap();
    drop(connection);

    let error = store.get_lineage("cap-corrupt-read").unwrap_err();
    assert!(error.to_string().contains("issued_at"));

    let _ = fs::remove_file(path);
}

#[test]
fn record_child_snapshot_rejects_negative_parent_depth() {
    let path = unique_db_path("cl-corrupt-parent");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let connection = store.connection().unwrap();
    connection
        .execute(
            r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
            params![
                "cap-corrupt-parent",
                "subject",
                "issuer",
                1_000_i64,
                2_000_i64,
                "{}",
                -1_i64
            ],
        )
        .unwrap();
    drop(connection);

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let corrupt_parent = make_token("cap-corrupt-parent", &issuer_kp, &issuer_kp, 1_000, 2_000);
    let child = make_delegated_token(
        "cap-child-from-corrupt",
        &subject_kp,
        &issuer_kp,
        &corrupt_parent,
        1_100,
        1_900,
    );
    let error = store
        .record_capability_snapshot(&child, Some("cap-corrupt-parent"))
        .unwrap_err();
    assert!(error.to_string().contains("delegation_depth"));

    let _ = fs::remove_file(path);
}

#[test]
fn lineage_replication_rejects_negative_snapshot_fields() {
    let path = unique_db_path("cl-corrupt-repl");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let connection = store.connection().unwrap();
    connection
        .execute(
            r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
            params![
                "cap-corrupt-repl",
                "subject",
                "issuer",
                1_000_i64,
                -2_000_i64,
                "{}",
                0_i64
            ],
        )
        .unwrap();
    drop(connection);

    let error = store
        .list_capability_snapshots_after_seq(0, 10)
        .unwrap_err();
    assert!(error.to_string().contains("expires_at"));

    let _ = fs::remove_file(path);
}

#[test]
fn get_delegation_chain_returns_root_first_for_three_level_chain() {
    let path = unique_db_path("cl-chain-3");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let kp_root = Keypair::generate();
    let kp_mid = Keypair::generate();
    let kp_leaf = Keypair::generate();

    // root -> parent -> child
    let root = make_token("cap-root", &kp_root, &kp_root, 1000, 9000);
    let parent = make_delegated_token("cap-parent", &kp_mid, &kp_root, &root, 1100, 8000);
    let child = make_delegated_token("cap-child", &kp_leaf, &kp_mid, &parent, 1200, 7000);

    store.record_capability_snapshot(&root, None).unwrap();
    store
        .record_capability_snapshot(&parent, Some("cap-root"))
        .unwrap();
    store
        .record_capability_snapshot(&child, Some("cap-parent"))
        .unwrap();

    // Walking the chain from child should return root, parent, child (root-first).
    let chain = store.get_delegation_chain("cap-child").unwrap();
    assert_eq!(chain.len(), 3, "should have 3 entries in chain");
    assert_eq!(chain[0].capability_id, "cap-root", "root should be first");
    assert_eq!(
        chain[1].capability_id, "cap-parent",
        "parent should be second"
    );
    assert_eq!(chain[2].capability_id, "cap-child", "child should be last");

    let _ = fs::remove_file(path);
}

#[test]
fn get_delegation_chain_returns_single_entry_for_root_capability() {
    let path = unique_db_path("cl-chain-root");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let kp = Keypair::generate();
    let root = make_token("cap-solo", &kp, &kp, 1000, 9000);

    store.record_capability_snapshot(&root, None).unwrap();

    let chain = store.get_delegation_chain("cap-solo").unwrap();
    assert_eq!(chain.len(), 1, "root has no parent -- only itself in chain");
    assert_eq!(chain[0].capability_id, "cap-solo");

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_store_authority_chain_rejects_missing_signed_ancestor() {
    let path = unique_db_path("cl-missing-signed-ancestor");
    let store = SqliteReceiptStore::open(&path).unwrap();
    let delegator = Keypair::generate();
    let subject = Keypair::generate();
    let missing_parent = make_token("cap-missing-parent", &delegator, &delegator, 1_000, 9_000);
    let child = make_delegated_token(
        "cap-orphan-child",
        &subject,
        &delegator,
        &missing_parent,
        1_100,
        8_000,
    );
    store
        .record_capability_snapshot(&missing_parent, None)
        .unwrap();
    store
        .record_capability_snapshot(&child, Some(&missing_parent.id))
        .unwrap();
    let external = Connection::open(&path).unwrap();
    external.pragma_update(None, "foreign_keys", "OFF").unwrap();
    external
        .execute(
            "DELETE FROM capability_lineage WHERE capability_id = ?1",
            params![missing_parent.id],
        )
        .unwrap();

    assert_eq!(store.get_delegation_chain(&child.id).unwrap().len(), 1);
    assert!(
        chio_kernel::ReceiptStore::get_capability_delegation_chain(&store, &child.id)
            .unwrap()
            .is_empty()
    );

    let _ = fs::remove_file(path);
}

#[test]
fn get_delegation_chain_enforces_max_depth_guard() {
    let path = unique_db_path("cl-depth-guard");
    let store = SqliteReceiptStore::open(&path).unwrap();

    // Build a chain of 25 entries (exceeds the level < 20 guard).
    let kp = Keypair::generate();
    let mut prev_id: Option<String> = None;
    let mut prev_token: Option<CapabilityToken> = None;
    for i in 0..25usize {
        let id = format!("cap-depth-{i:03}");
        let token = match prev_token.as_ref() {
            Some(parent) => make_delegated_token(&id, &kp, &kp, parent, 1000 + i as u64, 9000),
            None => make_token(&id, &kp, &kp, 1000 + i as u64, 9000),
        };
        store
            .record_capability_snapshot(&token, prev_id.as_deref())
            .unwrap();
        prev_id = Some(id);
        prev_token = Some(token);
    }

    // Walking the chain from the deepest node should be capped at 21 entries (depth guard).
    let chain = store.get_delegation_chain("cap-depth-024").unwrap();
    // With level < 20, the recursion visits at most 21 distinct rows.
    assert!(
        chain.len() <= 21,
        "chain length {} exceeds max depth guard of 21",
        chain.len()
    );

    let _ = fs::remove_file(path);
}

#[test]
fn capability_lineage_table_created_by_open() {
    let path = unique_db_path("cl-table-exists");
    let store = SqliteReceiptStore::open(&path).unwrap();

    // Query the table to verify it exists; COUNT(*) fails if the table is absent.
    let connection = store.connection().unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM capability_lineage", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0, "table should exist and be empty");

    let _ = fs::remove_file(path);
}

#[test]
fn subject_key_index_exists() {
    let path = unique_db_path("cl-index-check");
    let store = SqliteReceiptStore::open(&path).unwrap();

    // PRAGMA index_list returns rows for each index on the table.
    let connection = store.connection().unwrap();
    let mut stmt = connection
        .prepare("PRAGMA index_list(capability_lineage)")
        .unwrap();
    let index_names: Vec<String> = stmt
        .query_map([], |row: &rusqlite::Row<'_>| row.get::<_, String>(1))
        .unwrap()
        .filter_map(|r: Result<String, _>| r.ok())
        .collect();

    assert!(
        index_names
            .iter()
            .any(|n| n == "idx_capability_lineage_subject"),
        "subject_key index not found; found: {index_names:?}"
    );

    let _ = fs::remove_file(path);
}
