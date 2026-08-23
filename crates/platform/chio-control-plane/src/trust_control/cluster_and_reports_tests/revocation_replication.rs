use super::*;

#[tokio::test]
async fn revocation_delta_endpoint_negotiates_legacy_and_sequence_cursors() {
    let revocation_db = unique_temp_path("revocation-delta-upgrade", "sqlite3");
    let state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        Some(revocation_db),
        None,
    );
    let store = state.revocation_store().test_unwrap();
    for capability_id in ["cap-b", "cap-a"] {
        store
            .upsert_revocation(&RevocationRecord {
                capability_id: capability_id.to_string(),
                revoked_at: 10,
            })
            .test_unwrap();
    }
    let stream_id = store.revocation_stream_id().test_unwrap();

    let issued_at = unix_timestamp_now() as i64;
    let signature = cluster_peer_auth_signature(
        &state.config.service_token,
        "http://node-b",
        INTERNAL_REVOCATIONS_DELTA_PATH,
        issued_at,
        None,
    )
    .test_unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        CLUSTER_NODE_ID_HEADER,
        HeaderValue::from_static("http://node-b"),
    );
    headers.insert(
        CLUSTER_AUTH_ISSUED_AT_HEADER,
        HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
    );
    headers.insert(
        CLUSTER_AUTH_SIGNATURE_HEADER,
        HeaderValue::from_str(&signature).test_unwrap(),
    );

    // An old client sends only the tuple cursor. The upgraded server must
    // preserve that pagination and omit every sequence-cursor field.
    let legacy = handle_internal_revocations_delta(
        State(state.clone()),
        Query(RevocationDeltaQuery {
            cursor_version: None,
            stream_id: None,
            after_seq: None,
            after_revoked_at: Some(10),
            after_capability_id: Some("cap-a".to_string()),
            limit: Some(MAX_LIST_LIMIT),
        }),
        headers.clone(),
    )
    .await;
    assert_eq!(legacy.status(), StatusCode::OK);
    let legacy: Value =
        serde_json::from_slice(&to_bytes(legacy.into_body(), usize::MAX).await.test_unwrap())
            .test_unwrap();
    assert!(legacy.get("cursorVersion").is_none());
    assert_eq!(
        legacy["records"],
        json!([{"capabilityId": "cap-b", "revokedAt": 10}])
    );

    // A new client explicitly negotiates version 4 with the durable stream
    // identity and gets the insertion sequence, including same-second backfills.
    let sequence = handle_internal_revocations_delta(
        State(state.clone()),
        Query(RevocationDeltaQuery {
            cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            stream_id: Some(stream_id.clone()),
            after_seq: Some(0),
            after_revoked_at: Some(10),
            after_capability_id: Some("cap-z".to_string()),
            limit: Some(MAX_LIST_LIMIT),
        }),
        headers.clone(),
    )
    .await;
    assert_eq!(sequence.status(), StatusCode::OK);
    let sequence: Value = serde_json::from_slice(
        &to_bytes(sequence.into_body(), usize::MAX)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(
        sequence["cursorVersion"],
        REVOCATION_SEQUENCE_CURSOR_VERSION
    );
    assert_eq!(sequence["streamId"], stream_id);
    assert_eq!(sequence["headSeq"], 2);
    assert_eq!(sequence["records"][0]["seq"], 1);
    assert_eq!(sequence["records"][0]["capabilityId"], "cap-b");
    assert_eq!(sequence["records"][1]["seq"], 2);
    assert_eq!(sequence["records"][1]["capabilityId"], "cap-a");

    let wrong_stream = handle_internal_revocations_delta(
        State(state.clone()),
        Query(RevocationDeltaQuery {
            cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            stream_id: Some("01991bb4-e2f7-7e21-b75d-a59be8fbc442".to_string()),
            ..RevocationDeltaQuery::default()
        }),
        headers.clone(),
    )
    .await;
    assert_eq!(wrong_stream.status(), StatusCode::CONFLICT);

    let retired = handle_internal_revocations_delta(
        State(state.clone()),
        Query(RevocationDeltaQuery {
            cursor_version: Some(2),
            ..RevocationDeltaQuery::default()
        }),
        headers.clone(),
    )
    .await;
    assert_eq!(retired.status(), StatusCode::BAD_REQUEST);

    let unsupported = handle_internal_revocations_delta(
        State(state),
        Query(RevocationDeltaQuery {
            cursor_version: Some(99),
            ..RevocationDeltaQuery::default()
        }),
        headers,
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn revocation_snapshot_is_projection_bounded_and_epoch_bound() {
    let source_revocation_db = unique_temp_path("cluster-source-revocation-snapshot", "sqlite3");
    let target_revocation_db = unique_temp_path("cluster-target-revocation-snapshot", "sqlite3");
    let source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        Some(source_revocation_db.clone()),
        None,
    );
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        Some(target_revocation_db.clone()),
        None,
    );
    let source_store = SqliteRevocationStore::open(&source_revocation_db).test_unwrap();
    for revoked_at in 1..=32 {
        source_store
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-one".to_string(),
                revoked_at,
            })
            .test_unwrap();
    }

    let mut snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    assert_eq!(snapshot.revocations.len(), 1);
    assert_eq!(snapshot.revocations[0].revoked_at, 32);
    let cursor = snapshot
        .replication
        .revocation_cursor
        .as_ref()
        .test_unwrap();
    assert_eq!(
        cursor.cursor_version,
        Some(REVOCATION_SEQUENCE_CURSOR_VERSION)
    );
    assert_eq!(cursor.seq, Some(32));

    snapshot.replication.revocation_cursor_version = Some(2);
    snapshot
        .replication
        .revocation_cursor
        .as_mut()
        .test_unwrap()
        .cursor_version = Some(2);
    let error = apply_cluster_snapshot(&target_state, "http://node-a", snapshot)
        .test_unwrap_err()
        .to_string();
    assert!(error.contains("unsupported revocation cursor version 2"));
    assert!(SqliteRevocationStore::open(&target_revocation_db)
        .test_unwrap()
        .list_revocations_after(MAX_LIST_LIMIT, None, None)
        .test_unwrap()
        .is_empty());
    assert_eq!(
        with_peer_state(&target_state, "http://node-a", |peer| peer
            .snapshot_applied_count),
        Some(0)
    );

    let _ = std::fs::remove_file(source_revocation_db);
    let _ = std::fs::remove_file(target_revocation_db);
}

#[test]
fn legacy_revocation_snapshot_recovers_projection_without_reusing_tuple_cursor() {
    let source_revocation_db =
        unique_temp_path("cluster-source-legacy-revocation-snapshot", "sqlite3");
    let target_revocation_db =
        unique_temp_path("cluster-target-legacy-revocation-snapshot", "sqlite3");
    let source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        Some(source_revocation_db.clone()),
        None,
    );
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        Some(target_revocation_db.clone()),
        None,
    );
    SqliteRevocationStore::open(&source_revocation_db)
        .test_unwrap()
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-legacy-origin".to_string(),
            revoked_at: 55,
        })
        .test_unwrap();

    let current = build_cluster_state_snapshot(&source_state).test_unwrap();
    let mut legacy_json = serde_json::to_value(current).test_unwrap();
    let replication = legacy_json["replication"].as_object_mut().test_unwrap();
    replication.remove("revocationCursorVersion");
    replication.remove("revocationStreamId");
    let cursor = replication["revocationCursor"]
        .as_object_mut()
        .test_unwrap();
    cursor.insert("cursorVersion".to_string(), serde_json::json!(3));
    cursor.remove("streamId");
    let legacy: ClusterStateSnapshotResponse = serde_json::from_value(legacy_json).test_unwrap();

    apply_cluster_snapshot(&target_state, "http://node-a", legacy).test_unwrap();
    assert!(SqliteRevocationStore::open(&target_revocation_db)
        .test_unwrap()
        .is_revoked("cap-legacy-origin")
        .test_unwrap());
    assert!(peer_revocation_cursor(&target_state, "http://node-a").is_none());

    let _ = std::fs::remove_file(source_revocation_db);
    let _ = std::fs::remove_file(target_revocation_db);
}
