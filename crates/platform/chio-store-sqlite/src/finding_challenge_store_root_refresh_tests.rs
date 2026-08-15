#[test]
fn v12_schema_adds_append_only_effect_root_refreshes() {
    let mut connection = Connection::open_in_memory().expect("open previous database");
    connection
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .expect("install current challenge schema");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER effect_root_bindings_refreshes_valid;
            DROP TRIGGER effect_root_bindings_refreshes_immutable;
            DROP TRIGGER effect_root_bindings_refreshes_no_delete;
            DROP TABLE effect_root_bindings_refreshes;
            "#,
        )
        .expect("rewind root refresh schema objects");
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 12)
        .expect("stamp previous schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate revision twelve");

    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read migrated version");
    assert_eq!(version, FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION);
    assert!(connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'effect_root_bindings_refreshes')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("inspect root refresh table"));
    verify_finding_challenge_invariants(&connection).expect("verify canonical schema");
}
