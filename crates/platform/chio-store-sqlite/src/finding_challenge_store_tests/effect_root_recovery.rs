#[test]
fn legacy_anchor_binding_reconciliation_is_exact_and_idempotent() {
    let fixture = fixture();
    let head = Liability::new("legacy-anchor-binding", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let intent_key = digest("legacy-anchor-intent");
    let intent_digest = digest("legacy-anchor-commitment");
    let merkle_root = chain_hash("legacy-anchor-root");
    let evidence_hash = chain_hash("legacy-anchor-evidence");
    fixture
        .store
        .record_effect_intent(
            &intent_key,
            FindingEffectIntentKind::RootIntent,
            &intent_digest,
            Some(&head.liability_key),
            false,
            NOW,
        )
        .expect("record legacy anchor intent");

    assert_eq!(
        fixture
            .store
            .reconcile_anchor_effect_root_binding(
                &intent_key,
                &head.liability_key,
                &intent_digest,
                &merkle_root,
                &evidence_hash,
                NOW + 1,
            )
            .expect("reconstruct exact legacy binding"),
        FindingChallengeWriteOutcome::Inserted
    );
    fixture
        .store
        .advance_effect_intent(
            &intent_key,
            FindingEffectIntentState::Dispatched,
            NOW + 2,
        )
        .expect("dispatch reconstructed anchor");
    fixture
        .store
        .confirm_effect_root(&intent_key, &merkle_root, &evidence_hash, NOW + 3)
        .expect("confirm reconstructed anchor");
    assert_eq!(
        fixture
            .store
            .reconcile_anchor_effect_root_binding(
                &intent_key,
                &head.liability_key,
                &intent_digest,
                &merkle_root,
                &evidence_hash,
                NOW + 4,
            )
            .expect("replay exact recovered binding"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(matches!(
        fixture.store.reconcile_anchor_effect_root_binding(
            &intent_key,
            &head.liability_key,
            &digest("different-legacy-anchor-commitment"),
            &merkle_root,
            &evidence_hash,
            NOW + 5,
        ),
        Err(FindingChallengeStoreError::Conflict(_))
    ));
}

#[test]
fn v9_schema_migrates_the_legacy_anchor_recovery_trigger() {
    let mut connection = Connection::open_in_memory().expect("open previous database");
    connection
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .expect("install current challenge schema");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER effect_root_bindings_valid_intent;
            CREATE TRIGGER effect_root_bindings_valid_intent
            BEFORE INSERT ON effect_root_bindings
            WHEN NOT EXISTS (
                SELECT 1 FROM effect_intents
                WHERE intent_key = NEW.intent_key
                  AND liability_key = NEW.liability_key
                  AND kind = 'root_intent'
                  AND state = 'pending'
                  AND attempt_count = 0
            )
            BEGIN
                SELECT RAISE(ABORT, 'effect root binding requires its pending root intent');
            END;
            "#,
        )
        .expect("restore revision nine trigger");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt previous database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 9)
        .expect("stamp previous schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate revision nine");
    assert_eq!(
        connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
                [FINDING_CHALLENGE_SCHEMA_KEY],
                |row| row.get::<_, i32>(0),
            )
            .expect("read migrated version"),
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION
    );
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("isolate trigger regression from fixture foreign keys");

    let intent_key = digest("confirmed-legacy-anchor");
    let liability_key = digest("confirmed-legacy-liability");
    connection
        .execute(
            r#"
            INSERT INTO effect_intents (
                intent_key, liability_key, kind, intent_digest,
                settlement_required, state, attempt_count, recorded_at, updated_at
            ) VALUES (?1, ?2, 'root_intent', ?3, 0, 'confirmed', 1, ?4, ?4)
            "#,
            params![
                intent_key,
                liability_key,
                digest("confirmed-legacy-digest"),
                sqlite_i64(NOW, "now").expect("fixture time fits SQLite"),
            ],
        )
        .expect("install confirmed legacy anchor intent");
    connection
        .execute(
            r#"
            INSERT INTO effect_root_bindings (
                intent_key, liability_key, merkle_root, evidence_hash, bound_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                intent_key,
                liability_key,
                chain_hash("confirmed-legacy-root"),
                chain_hash("confirmed-legacy-evidence"),
                sqlite_i64(NOW + 1, "bound_at").expect("fixture time fits SQLite"),
            ],
        )
        .expect("new trigger accepts exact legacy anchor recovery state");
}
