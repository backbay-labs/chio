use super::*;

#[test]
fn a_transient_lock_root_failure_does_not_wedge_provisioning() {
    let (_temp, database, lock_root) = fixture();
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o500))
        .expect("make lock root read only");
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
        .expect("restore lock root mode");

    // The failed attempt cleans up after itself, so the store provisions normally
    // once the transient condition clears instead of wedging as a partial provision.
    SqliteAuthorityStore::provision(&database, &lock_root).expect("reprovision");
    SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
}

#[test]
fn partial_provision_fails_closed() {
    let (_temp, database, lock_root) = fixture();
    drop(SqliteBudgetStore::open(&database).expect("initialize authority schemas"));
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure database mode");
    // An owner table carrying no owner row is what an interrupted provision leaves
    // behind when its outcome is unknown and the artifacts are kept for inspection.
    let connection = Connection::open(&database).expect("open database");
    connection
        .execute_batch(SERVING_OWNER_SCHEMA)
        .expect("owner table");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(SqliteBudgetStore::open(&database).is_err());
    assert!(SqliteRevocationStore::open(&database).is_err());
}
