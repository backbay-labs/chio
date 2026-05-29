use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::BudgetEventAuthority;
use chio_kernel::{BudgetStore, RevocationRecord};
use chio_store_sqlite::{SqliteBudgetStore, SqliteCapabilityAuthority, SqliteRevocationStore};

use chio_test_support::prelude::*;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn cleanup_sqlite_files(path: &std::path::Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

fn authority(authority_id: &str, lease_id: &str, lease_epoch: u64) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority_id.to_string(),
        lease_id: lease_id.to_string(),
        lease_epoch,
    }
}

#[test]
fn sqlite_capability_authority_rotates_and_applies_newer_snapshot() {
    let primary_path = unique_db_path("chio-authority-primary");
    let replica_path = unique_db_path("chio-authority-replica");
    let primary =
        SqliteCapabilityAuthority::open(&primary_path).test_expect("open primary authority");
    let replica =
        SqliteCapabilityAuthority::open(&replica_path).test_expect("open replica authority");
    let primary_local_key_before = primary
        .current_keypair()
        .test_expect("read primary local signing key")
        .public_key();

    let rotated = replica.rotate().test_expect("rotate replica authority");
    let snapshot = replica.snapshot().test_expect("snapshot replica authority");
    let replaced = primary
        .apply_snapshot(&snapshot)
        .test_expect("apply newer replica snapshot");
    let status = primary.status().test_expect("read primary status");

    assert!(replaced);
    assert_eq!(snapshot.public_key_hex, rotated.public_key.to_hex());
    assert_eq!(status.generation, rotated.generation);
    assert_eq!(status.public_key.to_hex(), snapshot.public_key_hex);
    assert_eq!(
        primary
            .local_keypair()
            .test_expect("read primary local signing custody after snapshot")
            .public_key(),
        primary_local_key_before
    );
    let current_keypair_error = match primary.current_keypair() {
        Ok(_) => panic!("replicated authority snapshot must fence stale local signing custody"),
        Err(error) => error,
    };
    assert!(current_keypair_error
        .to_string()
        .contains("does not match replicated authority public key"));
    assert!(status
        .trusted_public_keys
        .iter()
        .any(|key| key.to_hex() == snapshot.public_key_hex));

    cleanup_sqlite_files(&primary_path);
    cleanup_sqlite_files(&replica_path);
}

#[test]
fn sqlite_capability_authority_rejects_snapshot_with_invalid_public_key() {
    let path = unique_db_path("chio-authority-invalid-snapshot");
    let authority = SqliteCapabilityAuthority::open(&path).test_expect("open authority");
    let mut snapshot = authority.snapshot().test_expect("snapshot authority");
    snapshot.public_key_hex = "deadbeef".to_string();

    let error = authority
        .apply_snapshot(&snapshot)
        .test_expect_err("invalid public key should fail closed");
    assert!(error.to_string().contains("invalid public key"));

    cleanup_sqlite_files(&path);
}

#[test]
fn sqlite_budget_and_revocation_paths_cover_limits_and_ordering() {
    let budget_path = unique_db_path("chio-budget-store");
    let revocation_path = unique_db_path("chio-revocation-store");
    let budget_store = SqliteBudgetStore::open(&budget_path).test_expect("open budget store");
    let revocation_store =
        SqliteRevocationStore::open(&revocation_path).test_expect("open revocation store");

    assert!(budget_store
        .try_charge_cost("cap-1", 0, Some(2), 5, Some(10), Some(10))
        .test_expect("charge within limits"));
    assert!(!budget_store
        .try_charge_cost("cap-1", 0, Some(2), 6, Some(5), Some(10))
        .test_expect("per-invocation cap should fail closed"));

    let charged = budget_store
        .get_usage("cap-1", 0)
        .test_expect("load charged usage")
        .test_expect("charged usage exists");
    assert_eq!(charged.invocation_count, 1);
    assert_eq!(
        charged
            .committed_cost_units()
            .test_expect("derive charged total"),
        5
    );

    budget_store
        .reduce_charge_cost("cap-1", 0, 3)
        .test_expect("reduce charged budget");
    let reduced = budget_store
        .get_usage("cap-1", 0)
        .test_expect("reload reduced usage")
        .test_expect("reduced usage exists");
    assert_eq!(
        reduced
            .committed_cost_units()
            .test_expect("derive reduced total"),
        2
    );
    assert_eq!(
        budget_store
            .list_usages_after(10, Some(0))
            .test_expect("list replicated budgets")
            .len(),
        1
    );

    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-1".to_string(),
            revoked_at: 100,
        })
        .test_expect("insert first revocation");
    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-2".to_string(),
            revoked_at: 100,
        })
        .test_expect("insert second revocation");
    revocation_store
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-3".to_string(),
            revoked_at: 101,
        })
        .test_expect("insert third revocation");

    let after = revocation_store
        .list_revocations_after(10, Some(100), Some("cap-1"))
        .test_expect("list revocations after cursor");
    let capability_ids = after
        .iter()
        .map(|record| record.capability_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(capability_ids, vec!["cap-2", "cap-3"]);

    cleanup_sqlite_files(&budget_path);
    cleanup_sqlite_files(&revocation_path);
}

#[test]
fn sqlite_budget_hold_authority_metadata_persists_across_reopen() {
    let path = unique_db_path("chio-budget-authority-lease");
    let hold_id = "hold-cap-lease-0";
    let authorize_event_id = "hold-cap-lease-0:authorize";
    let release_event_id = "hold-cap-lease-0:release";
    let initial = authority("budget-primary", "lease-7", 7);
    let advanced = authority("budget-primary", "lease-7", 8);

    {
        let store = SqliteBudgetStore::open(&path).test_expect("open budget store");
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
                Some(&initial),
            )
            .test_expect("authorize hold with lease metadata"));
    }

    {
        let store = SqliteBudgetStore::open(&path).test_expect("reopen budget store");
        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .test_expect("load events after reopen");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].authority.as_ref(), Some(&initial));

        let error = store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some("hold-cap-lease-0:release-missing"),
                None,
            )
            .test_expect_err("missing lease metadata should fail closed");
        assert!(error
            .to_string()
            .contains("requires authority lease metadata"));

        let advanced_error = store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some(release_event_id),
                Some(&advanced),
            )
            .test_expect_err("advanced lease metadata should fail closed");
        assert!(advanced_error
            .to_string()
            .contains("advanced beyond the open lease"));

        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some(release_event_id),
                Some(&initial),
            )
            .test_expect("release hold with matching lease metadata");

        let usage = store
            .get_usage("cap-lease", 0)
            .test_expect("reload usage")
            .test_expect("usage exists");
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 75);
        assert_eq!(usage.total_cost_realized_spend, 0);

        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .test_expect("reload events after release");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].authority.as_ref(), Some(&initial));
    }

    cleanup_sqlite_files(&path);
}

#[test]
fn sqlite_budget_authorize_idempotency_persists_across_reopen() {
    let path = unique_db_path("chio-budget-authority-idempotent");
    let hold_id = "hold-cap-idempotent-0";
    let authorize_event_id = "hold-cap-idempotent-0:authorize";
    let authority = authority("budget-primary", "lease-12", 12);

    {
        let store = SqliteBudgetStore::open(&path).test_expect("open budget store");
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-idempotent",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
                Some(&authority),
            )
            .test_expect("authorize hold before reopen"));
    }

    {
        let store = SqliteBudgetStore::open(&path).test_expect("reopen budget store");
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-idempotent",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
                Some(&authority),
            )
            .test_expect("replay identical authorize after reopen"));

        let usage = store
            .get_usage("cap-idempotent", 0)
            .test_expect("reload usage")
            .test_expect("usage exists");
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
        assert_eq!(usage.total_cost_realized_spend, 0);

        let events = store
            .list_mutation_events(10, Some("cap-idempotent"), Some(0))
            .test_expect("reload events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, authorize_event_id);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
    }

    cleanup_sqlite_files(&path);
}
