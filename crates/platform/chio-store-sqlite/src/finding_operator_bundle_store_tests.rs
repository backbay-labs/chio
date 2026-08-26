use super::*;

fn finding_id() -> String {
    "a".repeat(64)
}

#[test]
fn canonical_bundle_survives_restart_and_replays_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator.db");
    let bundle = br#"{"schema":"chio.finding.operator-bundle.v1"}"#;
    let store = SqliteFindingOperatorBundleStore::open(&path).unwrap();
    assert_eq!(
        store.put(&finding_id(), bundle).unwrap(),
        FindingOperatorBundleWriteOutcome::Inserted
    );
    drop(store);
    let reopened = SqliteFindingOperatorBundleStore::open(&path).unwrap();
    assert_eq!(
        reopened.put(&finding_id(), bundle).unwrap(),
        FindingOperatorBundleWriteOutcome::ExactReplay
    );
    assert_eq!(reopened.get(&finding_id()).unwrap().bundle_json, bundle);
}

#[test]
fn every_pooled_connection_has_busy_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteFindingOperatorBundleStore::open(dir.path().join("operator.db")).unwrap();
    let first = store.pool.get().unwrap();
    let second = store.pool.get().unwrap();

    for connection in [&first, &second] {
        let busy_timeout = connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
            .unwrap();
        assert!(busy_timeout >= 5_000);
    }
}

#[test]
fn artifact_lookup_does_not_read_unrelated_bundles() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let unrelated_id = "0".repeat(64);
    let legacy_id = "1".repeat(64);
    let indexed_id = "f".repeat(64);
    let unrelated = br#"{"bundle":"unrelated"}"#;
    let legacy = br#"{"bundle":"legacy"}"#;
    let indexed = br#"{"bundle":"indexed"}"#;
    let envelope_sha256 = "a".repeat(64);
    store.put(&unrelated_id, unrelated).unwrap();
    store
        .put_with_artifact_indexes(
            &legacy_id,
            legacy,
            &[FindingOperatorBundleArtifactIndex {
                kind: FindingOperatorBundleArtifactKind::Admission,
                envelope_sha256: envelope_sha256.clone(),
                authority_policy_json: None,
            }],
        )
        .unwrap();
    store
        .put_with_artifact_indexes(
            &indexed_id,
            indexed,
            &[FindingOperatorBundleArtifactIndex {
                kind: FindingOperatorBundleArtifactKind::Admission,
                envelope_sha256: envelope_sha256.clone(),
                authority_policy_json: Some(br#"{"authority":"old"}"#.to_vec()),
            }],
        )
        .unwrap();
    store
        .pool
        .get()
        .unwrap()
        .execute(
            "UPDATE chio_finding_operator_bundles SET bundle_json = '{}' WHERE finding_id = ?1",
            [&unrelated_id],
        )
        .unwrap();

    let resolved = store
        .get_by_artifact(
            FindingOperatorBundleArtifactKind::Admission,
            &envelope_sha256,
        )
        .unwrap();
    assert_eq!(resolved.finding_id, indexed_id);
    assert_eq!(resolved.bundle_json, indexed);
    assert_eq!(
        resolved.authority_policy_json.as_deref(),
        Some(br#"{"authority":"old"}"#.as_slice())
    );
    assert_eq!(
        resolved.authority_policy_sha256.as_deref(),
        Some(sha256_hex(br#"{"authority":"old"}"#).as_str())
    );

    assert!(matches!(
        store.put_with_artifact_indexes(
            &"e".repeat(64),
            br#"{"bundle":"conflicting-policy"}"#,
            &[FindingOperatorBundleArtifactIndex {
                kind: FindingOperatorBundleArtifactKind::Admission,
                envelope_sha256,
                authority_policy_json: Some(br#"{"authority":"new"}"#.to_vec()),
            }],
        ),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));

    store
        .pool
        .get()
        .unwrap()
        .execute(
            "UPDATE chio_finding_operator_artifact_authority_policies SET policy_json = ?1 WHERE artifact_kind = 'admission' AND envelope_sha256 = ?2",
            params![b"{}".as_slice(), "a".repeat(64)],
        )
        .unwrap();
    assert!(matches!(
        store.get_by_artifact(
            FindingOperatorBundleArtifactKind::Admission,
            &"a".repeat(64),
        ),
        Err(FindingOperatorBundleStoreError::DigestMismatch)
    ));
}

#[test]
fn complete_artifact_indexes_are_not_backfilled_again() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let bundle = br#"{"bundle":"indexed"}"#;
    let indexes = [
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::FeeSchedule,
            envelope_sha256: "1".repeat(64),
            authority_policy_json: None,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::Admission,
            envelope_sha256: "2".repeat(64),
            authority_policy_json: None,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::VerifierProfile,
            envelope_sha256: "3".repeat(64),
            authority_policy_json: None,
        },
        FindingOperatorBundleArtifactIndex {
            kind: FindingOperatorBundleArtifactKind::MarketTerms,
            envelope_sha256: "4".repeat(64),
            authority_policy_json: None,
        },
    ];
    store
        .put_with_artifact_indexes(&finding_id(), bundle, &indexes)
        .unwrap();
    assert!(store
        .list_without_complete_artifact_index(10_000)
        .unwrap()
        .is_empty());
}

#[test]
fn changed_or_noncanonical_bundle_is_rejected() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let first = br#"{"a":1}"#;
    store.put(&finding_id(), first).unwrap();
    assert!(matches!(
        store.put(&finding_id(), br#"{"a":2}"#),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));
    assert!(matches!(
        store.put(&"b".repeat(64), b"{ \"a\": 1 }"),
        Err(FindingOperatorBundleStoreError::Invalid("bundle_json"))
    ));
}

#[test]
fn admission_capacity_matches_the_complete_resolver_scan() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let bundle = br#"{"a":1}"#;
    let digest = sha256_hex(bundle);
    {
        let mut conn = store.pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..MAX_RETAINED_BUNDLES {
            tx.execute(
                "INSERT INTO chio_finding_operator_bundles (finding_id, bundle_sha256, bundle_json, created_at) VALUES (?1, ?2, ?3, 1)",
                params![format!("{index:064x}"), digest, bundle],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        store.list(MAX_RETAINED_BUNDLES as u64).unwrap().len(),
        10_000
    );
    assert!(matches!(
        store.put(&"f".repeat(64), bundle),
        Err(FindingOperatorBundleStoreError::Capacity)
    ));
    assert_eq!(
        store.put(&format!("{:064x}", 1), bundle).unwrap(),
        FindingOperatorBundleWriteOutcome::ExactReplay
    );
}

#[test]
fn bundle_lookup_stops_at_the_first_streamed_match() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    for index in 0..4 {
        store
            .put(
                &format!("{index:064x}"),
                format!(r#"{{"index":{index}}}"#).as_bytes(),
            )
            .unwrap();
    }
    let mut inspected = 0usize;
    let found = store
        .find_bundle(|_| {
            inspected += 1;
            inspected == 2
        })
        .unwrap()
        .unwrap();
    assert_eq!(inspected, 2);
    assert_eq!(found.finding_id, format!("{:064x}", 1));
}

#[test]
fn public_proof_survives_restart_and_replays_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operator.db");
    let proof = br#"{"schema":"chio.finding.operator-proof-bundle.v1"}"#;
    let store = SqliteFindingOperatorBundleStore::open(&path).unwrap();
    assert_eq!(
        store.put_proof(&finding_id(), proof).unwrap(),
        FindingOperatorBundleWriteOutcome::Inserted
    );
    assert_eq!(store.proof_count().unwrap(), 1);
    drop(store);

    let reopened = SqliteFindingOperatorBundleStore::open(&path).unwrap();
    assert_eq!(
        reopened.put_proof(&finding_id(), proof).unwrap(),
        FindingOperatorBundleWriteOutcome::ExactReplay
    );
    let record = reopened.get_proof(&finding_id()).unwrap();
    assert_eq!(record.proof_json, proof);
    assert_eq!(record.proof_sha256, sha256_hex(proof));
    assert!(matches!(
        reopened.put_proof(&finding_id(), br#"{"schema":"changed"}"#),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));
}

#[test]
fn purchase_job_precedes_and_survives_terminal_state() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let request_id = "e".repeat(64);
    let request_sha256 = "f".repeat(64);
    let job = br#"{"schema":"chio.finding.operator-purchase-job.v1"}"#;
    assert_eq!(
        store
            .put_purchase_job(&request_id, "buyer-1", &request_sha256, job)
            .unwrap(),
        FindingOperatorBundleWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_purchase_job(&request_id, "buyer-1", &request_sha256, job)
            .unwrap(),
        FindingOperatorBundleWriteOutcome::ExactReplay
    );
    let record = store.get_purchase_job(&request_id).unwrap().unwrap();
    assert_eq!(record.job_json, job);
    assert_eq!(store.purchase_job_count().unwrap(), 1);
    assert!(matches!(
        store.put_purchase_job(&request_id, "buyer-2", &request_sha256, job),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));
}

#[test]
fn purchase_job_capacity_preserves_exact_replay() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let job = br#"{"schema":"chio.finding.operator-purchase-job.v1"}"#;
    let job_sha256 = sha256_hex(job);
    let request_sha256 = "f".repeat(64);
    {
        let mut conn = store.pool.get().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..MAX_RETAINED_PURCHASE_JOBS {
            let request_id = format!("{index:064x}");
            tx.execute(
                "INSERT INTO chio_finding_operator_purchase_jobs (request_id, principal_id, request_sha256, job_sha256, job_json, created_at) VALUES (?1, 'buyer-1', ?2, ?3, ?4, 1)",
                params![request_id, request_sha256, job_sha256, job],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        store.purchase_job_count().unwrap(),
        MAX_RETAINED_PURCHASE_JOBS as u64
    );
    assert!(matches!(
        store.put_purchase_job(&"e".repeat(64), "buyer-1", &request_sha256, job),
        Err(FindingOperatorBundleStoreError::PurchaseJobCapacity)
    ));
    assert_eq!(
        store
            .put_purchase_job(&format!("{:064x}", 1), "buyer-1", &request_sha256, job)
            .unwrap(),
        FindingOperatorBundleWriteOutcome::ExactReplay
    );
}

#[test]
fn terminal_replay_is_principal_and_request_bound() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let request_id = "c".repeat(64);
    let request_sha256 = "d".repeat(64);
    let result = br#"{"schema":"chio.finding.purchase-result.v1"}"#;
    assert_eq!(
        store
            .reserve_terminal_capacity(&request_id, "buyer-1", &request_sha256)
            .unwrap(),
        FindingOperatorTerminalCapacityOutcome::Reserved
    );
    assert_eq!(
        store
            .put_terminal(&request_id, "buyer-1", &request_sha256, result)
            .unwrap(),
        FindingOperatorTerminalWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_terminal(&request_id, "buyer-1", &request_sha256, result)
            .unwrap(),
        FindingOperatorTerminalWriteOutcome::ExactReplay
    );
    assert_eq!(
        store
            .get_terminal(&request_id)
            .unwrap()
            .unwrap()
            .result_json,
        result
    );
    assert!(matches!(
        store.put_terminal(&request_id, "buyer-2", &request_sha256, result),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));
}

#[test]
fn terminal_byte_capacity_preserves_exact_replay() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let first_request_id = "a".repeat(64);
    let second_request_id = "b".repeat(64);
    let request_sha256 = "c".repeat(64);
    let first = br#"{"payload":"first"}"#;
    let second = br#"{"payload":"second"}"#;
    let capacity = i64::try_from(first.len() + second.len() - 1).unwrap();
    assert_eq!(
        store
            .reserve_terminal_capacity_with_limit(
                &first_request_id,
                "buyer-1",
                &request_sha256,
                i64::try_from(first.len()).unwrap(),
                capacity,
            )
            .unwrap(),
        FindingOperatorTerminalCapacityOutcome::Reserved
    );
    assert_eq!(
        store
            .reserve_terminal_capacity_with_limit(
                &first_request_id,
                "buyer-1",
                &request_sha256,
                i64::try_from(first.len()).unwrap(),
                capacity,
            )
            .unwrap(),
        FindingOperatorTerminalCapacityOutcome::ExactReplay
    );
    assert!(matches!(
        store.reserve_terminal_capacity_with_limit(
            &second_request_id,
            "buyer-1",
            &request_sha256,
            i64::try_from(second.len()).unwrap(),
            capacity,
        ),
        Err(FindingOperatorBundleStoreError::TerminalCapacity)
    ));
    assert_eq!(
        store
            .put_terminal(&first_request_id, "buyer-1", &request_sha256, first,)
            .unwrap(),
        FindingOperatorTerminalWriteOutcome::Inserted
    );
    assert_eq!(
        store
            .put_terminal(&first_request_id, "buyer-1", &request_sha256, first)
            .unwrap(),
        FindingOperatorTerminalWriteOutcome::ExactReplay
    );
    assert_eq!(store.terminal_count().unwrap(), 1);
}

#[test]
fn terminal_capacity_release_is_bound_and_idempotent() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let request_id = "e".repeat(64);
    let request_sha256 = "f".repeat(64);
    store
        .reserve_terminal_capacity(&request_id, "buyer-1", &request_sha256)
        .unwrap();
    assert!(matches!(
        store.release_terminal_capacity(&request_id, "buyer-2", &request_sha256),
        Err(FindingOperatorBundleStoreError::Conflict)
    ));
    assert!(store
        .release_terminal_capacity(&request_id, "buyer-1", &request_sha256)
        .unwrap());
    assert!(!store
        .release_terminal_capacity(&request_id, "buyer-1", &request_sha256)
        .unwrap());
}

#[test]
fn terminal_capacity_claims_are_listed_with_exact_bindings() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    let request_id = "a".repeat(64);
    let request_sha256 = "b".repeat(64);
    store
        .reserve_terminal_capacity(&request_id, "buyer-1", &request_sha256)
        .unwrap();

    assert_eq!(
        store.terminal_capacity_claims().unwrap(),
        vec![FindingOperatorTerminalCapacityRecord {
            request_id,
            principal_id: "buyer-1".to_owned(),
            request_sha256,
            reserved_bytes: u64::try_from(MAX_TERMINAL_BYTES).unwrap(),
        }]
    );
}

#[test]
fn seller_artifact_capacity_bounds_database_and_file_storage() {
    let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
    {
        let conn = store.pool.get().unwrap();
        conn.execute_batch(
            "CREATE TABLE chio_finding_payloads (finding_id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)",
        )
        .unwrap();
    }
    let database_bytes = {
        let conn = store.pool.get().unwrap();
        seller_database_bytes(&conn).unwrap()
    };
    let first_request = "1".repeat(64);
    let second_request = "2".repeat(64);
    let third_request = "3".repeat(64);
    let request_sha256 = "4".repeat(64);
    let maximum_bytes = database_bytes + 250;

    assert_eq!(
        store
            .reserve_seller_artifact_capacity_with_limits(
                &first_request,
                "seller-1",
                &request_sha256,
                40,
                10,
                100,
                maximum_bytes,
            )
            .unwrap(),
        FindingOperatorSellerArtifactCapacityOutcome::Reserved
    );
    assert_eq!(
        store
            .reserve_seller_artifact_capacity_with_limits(
                &first_request,
                "seller-1",
                &request_sha256,
                40,
                10,
                100,
                maximum_bytes,
            )
            .unwrap(),
        FindingOperatorSellerArtifactCapacityOutcome::ExactReplay
    );
    assert_eq!(
        store
            .reserve_seller_artifact_capacity_with_limits(
                &second_request,
                "seller-1",
                &request_sha256,
                40,
                10,
                100,
                maximum_bytes,
            )
            .unwrap(),
        FindingOperatorSellerArtifactCapacityOutcome::Reserved
    );
    assert!(matches!(
        store.reserve_seller_artifact_capacity_with_limits(
            &third_request,
            "seller-1",
            &request_sha256,
            40,
            10,
            100,
            maximum_bytes,
        ),
        Err(FindingOperatorBundleStoreError::SellerArtifactCapacity)
    ));

    let finding_id = "5".repeat(64);
    {
        let conn = store.pool.get().unwrap();
        conn.execute(
            "INSERT INTO chio_finding_payloads (finding_id, ciphertext) VALUES (?1, ?2)",
            params![finding_id, vec![0u8; 20]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chio_finding_operator_bundles (finding_id, bundle_sha256, bundle_json, created_at) VALUES (?1, ?2, ?3, 1)",
            params![finding_id, "6".repeat(64), vec![0u8; 20]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chio_finding_operator_proofs (finding_id, proof_sha256, proof_json, created_at) VALUES (?1, ?2, ?3, 1)",
            params![finding_id, "7".repeat(64), vec![0u8; 20]],
        )
        .unwrap();
    }
    assert_eq!(
        store
            .commit_seller_artifact_capacity(
                &first_request,
                "seller-1",
                &request_sha256,
                &finding_id,
            )
            .unwrap(),
        FindingOperatorSellerArtifactCapacityOutcome::Committed
    );
    assert_eq!(
        store
            .commit_seller_artifact_capacity(
                &first_request,
                "seller-1",
                &request_sha256,
                &finding_id,
            )
            .unwrap(),
        FindingOperatorSellerArtifactCapacityOutcome::ExactReplay
    );
    assert!(!store
        .release_seller_artifact_capacity(&first_request, "seller-1", &request_sha256,)
        .unwrap());
    assert!(matches!(
        store.commit_seller_artifact_capacity(
            &second_request,
            "seller-1",
            &request_sha256,
            &"8".repeat(64),
        ),
        Err(FindingOperatorBundleStoreError::NotFound)
    ));
    assert!(store
        .release_seller_artifact_capacity(&second_request, "seller-1", &request_sha256,)
        .unwrap());
    assert!(!store
        .release_seller_artifact_capacity(&second_request, "seller-1", &request_sha256,)
        .unwrap());
}
