use super::*;

fn temp_receipt_db() -> (tempfile::TempDir, String) {
    let temp_dir = tempfile::tempdir().test_unwrap();
    let path = temp_dir.path().join("receipts.sqlite3");
    (temp_dir, path.to_string_lossy().into_owned())
}

#[tokio::test]
async fn live_route_reports_process_healthy_without_consulting_dependencies() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("GET")
        .uri("/chio/live")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);
}

#[tokio::test]
async fn health_route_reports_ready_when_the_receipt_store_is_reachable() {
    let (temp_dir, db_path) = temp_receipt_db();
    let state =
        test_state_with_receipt_db(Vec::new(), "http://127.0.0.1:1".to_string(), Some(&db_path));
    let request = Request::builder()
        .method("GET")
        .uri("/chio/health")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);

    drop(state);
    temp_dir.close().test_unwrap();
}

#[tokio::test]
async fn readiness_consults_the_store_reachability_signal() {
    // With no store there is no dependency to fail, so readiness is healthy. The
    // reachability signal it consults is true for a working store; a store whose
    // connection could no longer answer this query drives readiness to unhealthy.
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    assert_eq!(state.readiness_status().await, SidecarStatus::Healthy);

    let (temp_dir, db_path) = temp_receipt_db();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );

    drop(store);
    temp_dir.close().test_unwrap();
}

#[tokio::test]
async fn reachability_probe_touches_the_write_path_and_persists_nothing() {
    let (temp_dir, db_path) = temp_receipt_db();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();

    // A healthy store probes reachable, and the probe rolls back: exercising the
    // write path must not leave a durable receipt behind.
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );
    assert!(
        store.load_receipts().test_unwrap().is_empty(),
        "the readiness probe must not persist a receipt"
    );

    // Drop the receipt table out of band, as a bad migration or schema corruption
    // would. A bare connection check would still answer here; the write-path probe
    // must not, so an instance that can no longer persist receipts leaves rotation.
    let side = rusqlite::Connection::open(&db_path).test_unwrap();
    side.execute("DROP TABLE http_receipts", []).test_unwrap();
    drop(side);

    assert!(
        !store.is_reachable(),
        "a store that can no longer persist receipts must fail readiness"
    );

    drop(store);
    temp_dir.close().test_unwrap();
}
