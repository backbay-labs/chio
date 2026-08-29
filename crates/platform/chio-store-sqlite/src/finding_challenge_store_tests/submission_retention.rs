use super::*;

#[test]
fn submit_challenge_inserts_replays_and_rejects_conflicts() {
    let fixture = fixture();
    let challenge = Challenge::buyer("alpha");
    assert_eq!(
        submit(&fixture, &challenge),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .get_challenge(&challenge.challenge_id)
            .expect("get challenge")
            .expect("challenge present"),
        FindingChallengeRecord {
            challenge_id: challenge.challenge_id.clone(),
            finding_id: challenge.finding_id.clone(),
            listing_id: LISTING_ID.to_string(),
            challenge_envelope_sha256: challenge.envelope_sha256.clone(),
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(hex64('b')),
            state: FindingChallengeState::Submitted,
            retry_count: 0,
            retry_deadline: None,
            outcome_envelope_sha256: None,
            submitted_at: NOW,
            updated_at: NOW,
        },
        "every challenge column must round-trip, so a column-index swap fails here"
    );
    assert_eq!(
        fixture
            .store
            .get_challenge_submission(&challenge.challenge_id)
            .expect("get retained challenge submission")
            .expect("retained challenge submission present"),
        FindingChallengeSubmissionEnvelopeRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_envelope_sha256: challenge.envelope_sha256.clone(),
            challenge_envelope_json: challenge.envelope_json.clone(),
            recorded_at: NOW,
        },
        "the exact canonical signed filing must survive the submission commit"
    );

    assert_eq!(
        submit(&fixture, &challenge),
        FindingChallengeWriteOutcome::ExistingSame,
        "an identical replay must not open a second adjudication"
    );

    // A retry carries the clock it retries from, so the submission time
    // must not decide whether it is the same challenge.
    let mut later = challenge.input();
    later.submitted_at = NOW + 30;
    assert_eq!(
        fixture
            .store
            .submit_challenge(&later)
            .expect("replay from a later clock"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        fixture
            .store
            .get_challenge(&challenge.challenge_id)
            .expect("get challenge")
            .expect("challenge present")
            .submitted_at,
        NOW,
        "a replay never moves the submission time the first call committed"
    );

    let mut conflicting = challenge.input();
    conflicting.evidence_class = FindingChallengeEvidenceClass::DigestMismatch;
    assert!(
        matches!(
            fixture.store.submit_challenge(&conflicting),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "conflicting parameters under an existing challenge id must reject"
    );

    let mut duplicate_envelope = Challenge::buyer("beta");
    duplicate_envelope
        .envelope_sha256
        .clone_from(&challenge.envelope_sha256);
    duplicate_envelope
        .envelope_json
        .clone_from(&challenge.envelope_json);
    assert!(
        matches!(
            fixture.store.submit_challenge(&duplicate_envelope.input()),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one signed challenge envelope cannot open two adjudications"
    );

    let mut audit_with_challenger = Challenge::audit("gamma");
    audit_with_challenger.challenger_hex = Some(hex64('b'));
    assert!(
        matches!(
            fixture
                .store
                .submit_challenge(&audit_with_challenger.input()),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a venue audit must not name a challenger"
    );
    let mut buyer_without_challenger = Challenge::buyer("delta");
    buyer_without_challenger.challenger_hex = None;
    assert!(
        matches!(
            fixture
                .store
                .submit_challenge(&buyer_without_challenger.input()),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a buyer submission must name its challenger"
    );

    let audit = Challenge::audit("epsilon").in_class(FindingChallengeEvidenceClass::DigestMismatch);
    assert_eq!(
        submit(&fixture, &audit),
        FindingChallengeWriteOutcome::Inserted
    );
    let listed = fixture
        .store
        .list_challenges(&hex64('a'), LISTING_ID)
        .expect("list challenges");
    assert_eq!(listed.len(), 2);
    assert!(fixture
        .store
        .get_challenge("challenge-absent")
        .expect("absent challenge lookup")
        .is_none());
}

#[test]
fn challenge_submission_rejects_noncanonical_or_mismatched_bytes_atomically() {
    let fixture = fixture();
    let mut noncanonical = Challenge::buyer("noncanonical");
    noncanonical.envelope_json = br#"{ "tag": "noncanonical" }"#.to_vec();
    noncanonical.envelope_sha256 = sha256_hex(&noncanonical.envelope_json);
    assert!(matches!(
        fixture.store.submit_challenge(&noncanonical.input()),
        Err(FindingChallengeStoreError::Invariant(_))
    ));
    assert!(fixture
        .store
        .get_challenge(&noncanonical.challenge_id)
        .expect("read rejected noncanonical challenge")
        .is_none());

    let mut mismatched = Challenge::buyer("mismatched");
    mismatched.envelope_sha256 = hex64('f');
    assert!(matches!(
        fixture.store.submit_challenge(&mismatched.input()),
        Err(FindingChallengeStoreError::Invariant(_))
    ));
    assert!(fixture
        .store
        .get_challenge(&mismatched.challenge_id)
        .expect("read rejected digest-mismatched challenge")
        .is_none());
}

#[test]
fn v13_schema_adds_exact_challenge_submission_retention() {
    let mut connection = Connection::open_in_memory().expect("open previous database");
    connection
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .expect("install current challenge schema");
    connection
        .pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)
        .expect("stamp Chio application id");
    connection
        .execute_batch("DROP TABLE finding_challenge_submissions;")
        .expect("rewind challenge-submission retention schema object");
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 13)
        .expect("stamp previous schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate revision thirteen");

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
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'finding_challenge_submissions')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("inspect challenge-submission retention table"));
    verify_finding_challenge_invariants(&connection).expect("verify canonical schema");
}

#[test]
fn v13_schema_with_a_challenge_fails_closed_without_exact_submission_bytes() {
    let mut connection = Connection::open_in_memory().expect("open previous database");
    connection
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .expect("install current challenge schema");
    connection
        .pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)
        .expect("stamp Chio application id");
    connection
        .execute(
            r#"
            INSERT INTO challenges (
                challenge_id, finding_id, listing_id,
                challenge_envelope_sha256, authorization_branch,
                evidence_class, challenger_hex, state, retry_count,
                retry_deadline, outcome_envelope_sha256, submitted_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, 'buyer_submission',
                      'evidence_invalid', ?5, 'submitted', 0,
                      NULL, NULL, ?6, ?6)
            "#,
            params![
                "challenge-legacy",
                hex64('a'),
                LISTING_ID,
                hex64('c'),
                hex64('b'),
                i64::try_from(NOW).expect("test time fits sqlite"),
            ],
        )
        .expect("insert legacy challenge");
    connection
        .execute_batch("DROP TABLE finding_challenge_submissions;")
        .expect("rewind challenge-submission retention schema object");
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 13)
        .expect("stamp previous schema");

    assert!(matches!(
        initialize_finding_challenge_schema(&mut connection),
        Err(FindingChallengeStoreError::Invariant(detail))
            if detail == "challenge row has no exact retained signed submission"
    ));

    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read retained legacy version");
    assert_eq!(
        version, 13,
        "failed migration must not stamp revision fourteen"
    );
    assert!(!connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'finding_challenge_submissions')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("inspect rolled-back schema"));
}

#[test]
fn current_schema_rejects_a_challenge_missing_its_submission() {
    let fixture = fixture();
    let challenge = Challenge::buyer("missing-retention");
    submit(&fixture, &challenge);
    {
        let connection = fixture
            .store
            .connection
            .lock()
            .expect("lock fixture database");
        connection
            .execute(
                "DELETE FROM finding_challenge_submissions WHERE challenge_id = ?1",
                [&challenge.challenge_id],
            )
            .expect("simulate retention corruption");
        assert!(matches!(
            verify_finding_challenge_invariants(&connection),
            Err(FindingChallengeStoreError::Invariant(detail))
                if detail == "challenge row has no exact retained signed submission"
        ));
    }
}

#[test]
fn offline_repair_atomically_restores_v13_exact_submission_bytes() {
    let temp = tempfile::tempdir().expect("create repair directory");
    secure_temp_directory(temp.path());
    let database = temp.path().join("challenge-repair.sqlite3");
    let envelope = br#"{"challenge":"legacy"}"#;
    let envelope_sha256 = sha256_hex(envelope);
    {
        let connection = Connection::open(&database).expect("open repair fixture");
        connection
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .expect("install current challenge schema");
        connection
            .pragma_update(None, "application_id", crate::CHIO_SQLITE_APPLICATION_ID)
            .expect("stamp Chio application id");
        connection
            .execute(
                r#"
                INSERT INTO challenges (
                    challenge_id, finding_id, listing_id,
                    challenge_envelope_sha256, authorization_branch,
                    evidence_class, challenger_hex, state, retry_count,
                    retry_deadline, outcome_envelope_sha256, submitted_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, 'buyer_submission',
                          'evidence_invalid', ?5, 'submitted', 0,
                          NULL, NULL, ?6, ?6)
                "#,
                params![
                    "challenge-legacy",
                    hex64('a'),
                    LISTING_ID,
                    envelope_sha256,
                    hex64('b'),
                    i64::try_from(NOW).expect("test time fits sqlite"),
                ],
            )
            .expect("insert legacy challenge");
        connection
            .execute_batch("DROP TABLE finding_challenge_submissions;")
            .expect("rewind challenge-submission retention schema object");
        crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 13)
            .expect("stamp previous schema");
    }

    let input = FindingChallengeSubmissionRepairInput {
        challenge_id: "challenge-legacy",
        challenge_envelope_sha256: &envelope_sha256,
        challenge_envelope_json: envelope,
    };
    let report = SqliteFindingChallengeStore::repair_challenge_submissions(
        &database,
        std::slice::from_ref(&input),
    )
    .expect("repair missing exact filing");
    assert_eq!(report.inserted, 1);
    assert_eq!(report.exact_replays, 0);
    assert_eq!(
        report.schema_version,
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION
    );

    let replay = SqliteFindingChallengeStore::repair_challenge_submissions(
        &database,
        std::slice::from_ref(&input),
    )
    .expect("replay exact repair");
    assert_eq!(replay.inserted, 0);
    assert_eq!(replay.exact_replays, 1);
    let connection = Connection::open(&database).expect("reopen repaired database");
    verify_finding_challenge_invariants(&connection).expect("verify repaired database");
}
