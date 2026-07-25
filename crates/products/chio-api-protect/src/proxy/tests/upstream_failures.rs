use super::*;

impl MockUpstreamServer {
    fn spawn_unresponsive() -> Option<Self> {
        let listener = Self::bind_mock_upstream_listener()?;
        let address = listener.local_addr().test_unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_http_request(&mut stream);
                request_log.lock().test_unwrap().push(request);
                let mut sink = [0_u8; 256];
                while let Ok(read) = stream.read(&mut sink) {
                    if read == 0 {
                        break;
                    }
                }
            }
        });
        Some(Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        })
    }
}

fn test_state_with_client_timeout(
    routes: Vec<RouteEntry>,
    upstream: String,
    timeout: std::time::Duration,
) -> Arc<ProxyState> {
    let mut state = test_state(routes, upstream);
    let http_client = client_builder_with_contract(&state.egress_contract)
        .timeout(timeout)
        .build()
        .test_unwrap();
    Arc::get_mut(&mut state).test_unwrap().http_client = http_client;
    state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_surfaces_upstream_failures_after_allowing_request() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let text = String::from_utf8(body.to_vec()).test_unwrap();
    assert!(text.contains("upstream error:"));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].response_status, 502);
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_records_receipt_when_upstream_times_out() {
    let Some(server) = MockUpstreamServer::spawn_unresponsive() else {
        return;
    };
    let state = test_state_with_client_timeout(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        server.base_url(),
        std::time::Duration::from_millis(150),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        proxy_handler(State(Arc::clone(&state)), request),
    )
    .await
    .test_unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 502);
}
